import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const cli = new URL('../cli.js', import.meta.url);

function run(args, input) {
  return spawnSync(process.execPath, [cli.pathname, ...args], { encoding: 'utf8', input });
}

test('CLI exits 1 when a critical finding reaches the default threshold', () => {
  const result = run([], 'create table public.exposed (id bigint);');
  assert.equal(result.status, 1);
  assert.match(result.stdout, /RLS-001/);
});

test('CLI accepts safe SQL from stdin', () => {
  const result = run([], `
    create table public.notes (id bigint, user_id uuid);
    alter table public.notes enable row level security;
    create policy owner_reads on public.notes for select to authenticated
      using ((select auth.uid()) = user_id);
  `);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /No rule-based risks found/);
});

test('CLI combines migration files in argument order and emits JSON', () => {
  const directory = mkdtempSync(join(tmpdir(), 'rls-guard-'));
  const first = join(directory, '001.sql');
  const second = join(directory, '002.sql');
  writeFileSync(first, 'create table public.notes (id bigint, user_id uuid);');
  writeFileSync(second, `
    alter table public.notes enable row level security;
    create policy owner_reads on public.notes for select to authenticated
      using ((select auth.uid()) = user_id);
  `);
  const result = run(['--json', first, second]);
  assert.equal(result.status, 0);
  const report = JSON.parse(result.stdout);
  assert.equal(report.summary.tables, 1);
  assert.equal(report.findings.length, 0);
});

test('CLI supports stricter severity thresholds and validates options', () => {
  const medium = run(['--fail-on', 'medium'], `
    create table public.locked (id bigint);
    alter table public.locked enable row level security;
  `);
  assert.equal(medium.status, 1);
  assert.match(medium.stdout, /RLS-002/);

  const invalid = run(['--fail-on', 'urgent'], 'select 1;');
  assert.equal(invalid.status, 2);
  assert.match(invalid.stderr, /critical, high, medium, or low/);
});

test('CLI emits a Markdown audit report with actionable checkboxes', () => {
  const result = run(['--format', 'markdown'], 'create table public.exposed (id bigint);');
  assert.equal(result.status, 1);
  assert.match(result.stdout, /# RLS Guard Security Report/);
  assert.match(result.stdout, /\[CRITICAL\] RLS-001/);
  assert.match(result.stdout, /- \[ \] Verified with role-based tests/);
  assert.match(result.stdout, /```sql[\s\S]*ENABLE ROW LEVEL SECURITY/);
});

test('CLI writes reports to --output without printing the report', () => {
  const directory = mkdtempSync(join(tmpdir(), 'rls-guard-output-'));
  const output = join(directory, 'report.md');
  const result = run(['--format', 'markdown', '--output', output], `
    create table public.notes (id bigint, user_id uuid);
    alter table public.notes enable row level security;
    create policy owner_reads on public.notes for select to authenticated
      using ((select auth.uid()) = user_id);
  `);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, '');
  assert.match(readFileSync(output, 'utf8'), /No rule-based risks found/);
});

test('CLI emits valid SARIF with mapped levels and remediation metadata', () => {
  const result = run(['--format', 'sarif'], 'create table public.exposed (id bigint);');
  assert.equal(result.status, 1);
  const sarif = JSON.parse(result.stdout);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].tool.driver.name, 'RLS Guard');
  assert.equal(sarif.runs[0].tool.driver.version, '0.6.0');
  assert.equal(sarif.runs[0].results[0].ruleId, 'RLS-001');
  assert.equal(sarif.runs[0].results[0].level, 'error');
  assert.match(sarif.runs[0].results[0].properties.remediation, /ENABLE ROW LEVEL SECURITY/);
});

test('CLI writes an empty SARIF result set for safe SQL', () => {
  const result = run(['--format', 'sarif'], `
    create table public.notes (id bigint, user_id uuid);
    alter table public.notes enable row level security;
    create policy owner_reads on public.notes for select to authenticated
      using ((select auth.uid()) = user_id);
  `);
  assert.equal(result.status, 0);
  const sarif = JSON.parse(result.stdout);
  assert.deepEqual(sarif.runs[0].results, []);
  assert.deepEqual(sarif.runs[0].tool.driver.rules, []);
});

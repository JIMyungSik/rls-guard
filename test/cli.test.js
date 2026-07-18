import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
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

import test from 'node:test';
import assert from 'node:assert/strict';
import { scanSql } from '../scanner.js';

const ids = (sql) => scanSql(sql).findings.map((item) => item.ruleId);

test('reconstructs final state after dropped policies and tables', () => {
  const result = scanSql(`
    create table public.notes (id bigint, user_id uuid);
    alter table public.notes enable row level security;
    create policy "old open policy" on public.notes for select using (true);
    drop policy "old open policy" on public.notes;
    create policy "owner reads" on public.notes for select to authenticated
      using ((select auth.uid()) = user_id);
    create table public.temporary_data (id bigint);
    drop table public.temporary_data;
  `);
  assert.deepEqual(result.findings, []);
  assert.equal(result.summary.tables, 1);
  assert.equal(result.summary.policies, 1);
});

test('ignores DDL in comments but preserves comment markers in strings', () => {
  const result = scanSql(`
    -- create table public.comment_only (id bigint);
    /* create table public.block_comment_only (id bigint); */
    create table private.audit_log (message text default '--still a string');
  `);
  assert.equal(result.summary.tables, 1);
  assert.equal(result.findings.length, 0);
});

test('detects a policy that omits every condition', () => {
  const findings = ids(`
    create table public.profiles (id uuid primary key);
    alter table public.profiles enable row level security;
    create policy open_profiles on public.profiles for select to anon;
  `);
  assert.ok(findings.includes('RLS-007'));
});

test('reconstructs a policy hardened by ALTER POLICY', () => {
  const result = scanSql(`
    create table public.documents (id bigint, user_id uuid);
    alter table public.documents enable row level security;
    create policy document_access on public.documents for all;
    alter policy document_access on public.documents to authenticated
      using ((select auth.uid()) = user_id)
      with check ((select auth.uid()) = user_id);
  `);
  assert.deepEqual(result.findings, []);
});

test('tracks policy renames before later alterations', () => {
  const result = scanSql(`
    create table public.documents (id bigint, user_id uuid);
    alter table public.documents enable row level security;
    create policy old_name on public.documents for select using (true);
    alter policy old_name on public.documents rename to owner_reads;
    alter policy owner_reads on public.documents to authenticated
      using ((select auth.uid()) = user_id);
  `);
  assert.deepEqual(result.findings, []);
  assert.equal(result.summary.policies, 1);
});

test('does not report an anonymous grant after it is revoked', () => {
  const findings = ids(`
    grant insert, update on table public.notes to anon;
    revoke insert, update on table public.notes from anon;
  `);
  assert.ok(!findings.includes('GRANT-001'));
});

test('keeps unrevoked privileges and roles in the final grant state', () => {
  const result = scanSql(`
    grant insert, update on table public.notes to anon, authenticated;
    revoke insert on table public.notes from anon;
  `);
  const grantFindings = result.findings.filter((item) => item.ruleId === 'GRANT-001');
  assert.equal(grantFindings.length, 1);
  assert.match(grantFindings[0].evidence, /update/i);
  assert.doesNotMatch(grantFindings[0].evidence, /insert/i);
});

test('detects and reconstructs role-level RLS bypass state', () => {
  const unsafe = scanSql(`alter role app_worker with bypassrls;`);
  const finding = unsafe.findings.find((item) => item.ruleId === 'ROLE-001');
  assert.equal(finding?.severity, 'critical');
  assert.equal(finding?.target, 'app_worker');

  const hardened = ids(`
    create role app_worker bypassrls;
    alter role app_worker with nobypassrls;
  `);
  assert.ok(!hardened.includes('ROLE-001'));

  const dropped = ids(`
    create user temporary_worker with bypassrls;
    drop user if exists temporary_worker;
  `);
  assert.ok(!dropped.includes('ROLE-001'));
});

test('tracks SUPERUSER independently from BYPASSRLS', () => {
  const result = scanSql(`
    create role app_admin superuser nobypassrls;
    alter role app_admin bypassrls;
    alter role app_admin nosuperuser;
  `);
  const finding = result.findings.find((item) => item.ruleId === 'ROLE-001');
  assert.match(finding?.evidence || '', /BYPASSRLS/);
  assert.doesNotMatch(finding?.evidence || '', /SUPERUSER/);

  const hardened = ids(`
    alter user app_admin with superuser bypassrls;
    alter user app_admin with nosuperuser nobypassrls;
  `);
  assert.ok(!hardened.includes('ROLE-001'));
});

test('detects storage writes that are not bucket scoped', () => {
  const findings = ids(`
    create policy upload_any_bucket on storage.objects for insert to authenticated
      with check ((select auth.uid())::text = owner_id);
  `);
  assert.ok(findings.includes('STORAGE-001'));
});

test('accepts bucket-scoped storage writes', () => {
  const findings = ids(`
    create policy upload_avatars on storage.objects for insert to authenticated
      with check (bucket_id = 'avatars' and (select auth.uid())::text = owner_id);
  `);
  assert.ok(!findings.includes('STORAGE-001'));
  assert.ok(!findings.includes('RLS-007'));
});

test('accepts both supported search_path assignment forms', () => {
  for (const assignment of ['=', 'to']) {
    const findings = ids(`
      create function public.secure_fn() returns void language sql security definer
      set search_path ${assignment} pg_catalog, public as $$ select null; $$;
    `);
    assert.ok(!findings.includes('FUNC-001'));
  }
});

test('reconstructs function replacement and later security changes', () => {
  const replaced = ids(`
    create function public.audit_event() returns void language sql security definer
      as $$ select null; $$;
    create or replace function public.audit_event() returns void language sql security definer
      set search_path = pg_catalog, public as $$ select null; $$;
  `);
  assert.ok(!replaced.includes('FUNC-001'));

  const altered = ids(`
    create function public.audit_event() returns void language sql security definer
      as $$ select null; $$;
    alter function public.audit_event() set search_path to pg_catalog, public;
  `);
  assert.ok(!altered.includes('FUNC-001'));
});

test('preserves a function schema when it is renamed', () => {
  const result = scanSql(`
    create function internal.audit_event() returns void language sql security definer
      as $$ select null; $$;
    alter function internal.audit_event() rename to record_event;
  `);
  const finding = result.findings.find((item) => item.ruleId === 'FUNC-001');
  assert.equal(finding?.target, 'internal.record_event');
});

test('does not report a security definer function after it is dropped', () => {
  const findings = ids(`
    create function public.temporary_fn() returns void language sql security definer
      as $$ select null; $$;
    drop function if exists public.temporary_fn();
  `);
  assert.ok(!findings.includes('FUNC-001'));
});

test('reconstructs view security options, rename, and drop', () => {
  const altered = scanSql(`
    create view public.profile_names as select 'name'::text as name;
    alter view public.profile_names set (security_invoker = true);
    alter view public.profile_names rename to safe_profile_names;
  `);
  assert.ok(!altered.findings.some((item) => item.ruleId === 'VIEW-001'));

  const dropped = ids(`
    create view public.temporary_view as select 1 as id;
    drop view if exists public.temporary_view;
  `);
  assert.ok(!dropped.includes('VIEW-001'));

  const renamedPrivate = scanSql(`
    create view internal.audit_summary as select 1 as total;
    alter view internal.audit_summary rename to activity_summary;
  `);
  assert.ok(!renamedPrivate.findings.some((item) => item.ruleId === 'VIEW-001'));
});

test('does not flag views outside Supabase exposed schemas', () => {
  const findings = ids(`create view private.audit_summary as select 1 as total;`);
  assert.ok(!findings.includes('VIEW-001'));
});

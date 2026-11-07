import { afterAll, describe, expect, it } from 'vitest';
import { splitSql } from '../src/rules/supabase-rls';
import { audit, cleanupTempDirs, copyNamedFixture, makeTempDir, writeFiles } from './helpers';

afterAll(cleanupTempDirs);

async function findingsFor(files: Record<string, string>) {
  const root = makeTempDir();
  writeFiles(root, files);
  return (await audit(root)).findings.filter((f) => f.ruleId === 'supabase-rls');
}

describe('fixtures/supabase-rls', () => {
  it('reports tables without RLS and open policies, replaying migrations in order', async () => {
    const result = await audit(copyNamedFixture('supabase-rls'));
    const got = result.findings.map((f) =>
      `${f.severity} ${f.messageId} ${f.params.table} ${f.params.command ?? ''}`.trim(),
    );
    expect(got).toEqual([
      'critical supabase.noRls orders',
      'critical supabase.noRls Invoices',
      'critical supabase.noRls audit_log',
      'high supabase.openWritePolicy todos UPDATE',
      'high supabase.openWritePolicy todos DELETE',
      'medium supabase.openInsertPolicy todos INSERT',
      'low supabase.openReadPolicy todos SELECT',
    ]);
    const disabled = result.findings.find((f) => f.params.table === 'audit_log');
    expect(disabled).toMatchObject({ file: 'supabase/migrations/20240201000000_regression.sql', line: 2 });
  });
});

describe('supabase-rls false positives', () => {
  it('ignores SQL outside a supabase/ folder', async () => {
    expect(await findingsFor({ 'db/schema.sql': 'create table users (id int);' })).toEqual([]);
  });

  it('ignores comments, strings and function bodies', async () => {
    const sql = [
      '-- create table public.a (id int);',
      '/* create table public.b (id int); */',
      "insert into public.s (v) values ('create table public.c (id int); x');",
      "create function f() returns void language plpgsql as $x$ begin execute 'create table public.d (id int)'; end; $x$;",
      'create function g() returns void language sql as $$ create table public.e (id int); $$;',
    ].join('\n');
    expect(await findingsFor({ 'supabase/migrations/1.sql': sql })).toEqual([]);
  });

  it('accepts RLS enabled in a later migration, quoted or unqualified names, ALTER ... ONLY', async () => {
    expect(
      await findingsFor({
        'supabase/migrations/1_a.sql':
          'create table public.a (id int);\ncreate table "Mixed" (id int);\ncreate table c (id int);',
        'supabase/migrations/2_b.sql': [
          'ALTER TABLE a ENABLE ROW LEVEL SECURITY;',
          'alter table public."Mixed" enable row level security;',
          'alter table only public.c enable row level security, force row level security;',
        ].join('\n'),
      }),
    ).toEqual([]);
  });

  it('ignores temp tables, other schemas, revoked tables, dropped and renamed tables', async () => {
    expect(
      await findingsFor({
        'supabase/migrations/1.sql': [
          'create temporary table t (id int);',
          'create table private.p (id int);',
          'create table public.r (id int);',
          'revoke all on public.r from anon, authenticated;',
          'create table public.gone (id int);',
          'drop table if exists public.gone;',
          'create table public.old_name (id int);',
          'alter table public.old_name rename to new_name;',
          'alter table public.new_name enable row level security;',
        ].join('\n'),
      }),
    ).toEqual([]);
  });

  it('ignores safe, restrictive, admin-only, dropped and altered policies', async () => {
    const sql = [
      'create table public.t (id int, user_id uuid);',
      'alter table public.t enable row level security;',
      'create policy "own" on public.t for all using (auth.uid() = user_id);',
      'create policy "true-ish" on public.t for update using (is_admin() or true_flag);',
      'create policy "r" on public.t as restrictive for all using (true);',
      'create policy "svc" on public.t for all to service_role using (true);',
      'create policy "tmp" on public.t for delete using (true);',
      'drop policy "tmp" on public.t;',
      'create policy "alt" on public.t for update using (true);',
      'alter policy "alt" on public.t using (auth.uid() = user_id);',
      'create policy "chk" on public.t for update using (auth.uid() = user_id) with check (true);',
    ].join('\n');
    expect(await findingsFor({ 'supabase/migrations/1.sql': sql })).toEqual([]);
  });
});

describe('splitSql', () => {
  it('keeps offsets and splits on top-level semicolons only', () => {
    const src = 'create policy "a;b" on t using (true);\n-- x;\nselect 1';
    const st = splitSql(src);
    expect(st).toHaveLength(2);
    expect(st[0]?.sql).toContain('"a;b"');
    expect(src.slice(st[1]?.index ?? 0)).toBe('select 1');
  });
});

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

describe('supabase-rls detection is not bypassed', () => {
  const noRls = async (sql: string) =>
    (await findingsFor({ 'supabase/migrations/1.sql': sql }))
      .filter((f) => f.messageId === 'supabase.noRls')
      .map((f) => f.params.table);

  it('reports unlogged tables (they are exposed like any other)', async () => {
    expect(await noRls('create unlogged table public.events (id int);')).toEqual(['events']);
  });

  it('needs every privilege revoked from both anon and authenticated', async () => {
    const sql = [
      'create table public.e (id int);',
      'revoke all on all tables in schema public from anon, authenticated;',
      'grant all on public.e to public;',
      'create table public.a (id int);',
      'revoke all on public.a from anon;',
      'create table public.b (id int);',
      'revoke all on public.b from public;',
      'create table public.c (id int);',
      'revoke select on public.c from anon, authenticated;',
      'create table public.d (id int);',
      'revoke all on table public.d from anon, authenticated;',
      'grant select on public.d to authenticated;',
      'create table public.f (id int);',
      'revoke grant option for all on public.f from anon, authenticated;',
      'create table public.g (id int, email text);',
      'revoke select (email), insert (email), update (email), delete on public.g from anon, authenticated;',
      'create table public.h (id int);',
      'revoke all on public.h from anon, authenticated;',
      'grant select (id) on public.h to group anon;',
      'create table public.i (id int);',
      'revoke all on public.i from anon, authenticated;',
      'alter table public.i owner to authenticated;',
      'create table public.j (id int);',
      'revoke all on public.j from anon, authenticated;',
      'alter table public.j owner to "anon";',
      'create table public.k (id int);',
      'revoke all on public.k from anon, authenticated;',
      'alter table public.k owner to app_user;',
    ].join('\n');
    expect((await noRls(sql)).sort()).toEqual(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k']);
  });

  it('reopens every table on REASSIGN OWNED to a non-admin role, not to postgres', async () => {
    const base = 'create table public.a (id int);\nrevoke all on public.a from anon, authenticated;\n';
    expect(await noRls(`${base}reassign owned by app to authenticated;`)).toEqual(['a']);
    expect(await noRls(`${base}reassign owned by app to postgres;`)).toEqual([]);
    expect(await noRls(`${base}reassign owned by "x to postgres" to anon;`)).toEqual(['a']);
    expect(await noRls(`${base}reassign owned by app to postgres garbage;`)).toEqual(['a']);
    expect(await noRls(`${base}alter table public.a owner to postgres, owner to anon;`)).toEqual(['a']);
  });

  it('closes a table when the schema-wide revoke covers it', async () => {
    const sql = 'create table public.a (id int);\nrevoke all on all tables in schema public from anon, authenticated;';
    expect(await noRls(sql)).toEqual([]);
  });

  it('is not blinded by E-strings, $ in identifiers or unterminated quotes', async () => {
    expect(await noRls("insert into t values (E'it\\'s; create table public.x (id int);');")).toEqual([]);
    expect(await noRls('select a$b$ from t;\ncreate table public.y (id int);')).toEqual(['y']);
    expect(await noRls("select 'oops;\ncreate table public.z (id int);")).toEqual(['z']);
    expect(await noRls('select $$ never closed;\ncreate table public.w (id int);')).toEqual(['w']);
  });
});

describe('supabase-rls with several projects', () => {
  it('replays the migrations of each project separately', async () => {
    const found = await findingsFor({
      'a/supabase/migrations/1.sql': 'create table public.t (id int);\nalter table public.t enable row level security;',
      'b/supabase/migrations/1.sql': 'create table public.t (id int);',
      'b/supabase/migrations/2.sql': 'create table public.u (id int);',
      'a/supabase/migrations/3.sql': 'alter table public.u enable row level security;',
    });
    expect(found.map((f) => `${f.file} ${f.params.table}`).sort()).toEqual([
      'b/supabase/migrations/1.sql t',
      'b/supabase/migrations/2.sql u',
    ]);
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

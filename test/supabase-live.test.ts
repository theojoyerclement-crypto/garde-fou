import { afterAll, describe, expect, it } from 'vitest';
import { fakeSupabaseAnonKey, fakeSupabaseServiceRoleKey } from '../scripts/fake-keys';
import { renderReport } from '../src/report';
import {
  createSupabaseLiveClient,
  keyKind,
  resolveTarget,
  type FetchGet,
  type LiveReadResult,
  type SupabaseLiveClient,
} from '../src/supabase-live';
import type { OsvClient, ScannedFile } from '../src/types';
import { audit, cleanupTempDirs, makeTempDir, writeFiles } from './helpers';

afterAll(cleanupTempDirs);

const REF = 'abcdefghijklmnopqrst';
/** OSV stand-in: the test helper turns the network off without one. */
const noOsv: OsvClient = { query: async (p) => p.map(() => []) };
const URL_ = `https://${REF}.supabase.co`;
const refOf = (key: string) =>
  (JSON.parse(Buffer.from(key.split('.')[1] ?? '', 'base64url').toString()) as { ref: string }).ref;
/** Anon key whose JWT names the project REF. */
function anonKeyFor(ref: string): string {
  for (;;) {
    const k = fakeSupabaseAnonKey();
    const [h, p, s] = k.split('.');
    const payload = JSON.parse(Buffer.from(p ?? '', 'base64url').toString()) as Record<string, unknown>;
    payload.ref = ref;
    const out = [h, Buffer.from(JSON.stringify(payload)).toString('base64url'), s].join('.');
    if (refOf(out) === ref) return out;
  }
}

const file = (rel: string, content: string): ScannedFile => ({ abs: rel, rel, content, gitignored: false });

/** Fake client: records every call, answers from a table → result map. Never any network. */
function fakeClient(answers: Record<string, LiveReadResult>, apiTables: string[] | null = null) {
  const calls: string[] = [];
  const client: SupabaseLiveClient = {
    async listTables(t) {
      calls.push(`list ${t.url}`);
      return apiTables;
    },
    async selectOne(t, table) {
      calls.push(`select ${table} ${t.url}`);
      return answers[table] ?? 'denied';
    },
  };
  return { client, calls };
}

function project(anon: string) {
  const root = makeTempDir();
  writeFiles(root, {
    '.env': `NEXT_PUBLIC_SUPABASE_URL=${URL_}\nNEXT_PUBLIC_SUPABASE_ANON_KEY=${anon}\n`,
    '.gitignore': '.env\n',
    'supabase/migrations/001_init.sql': [
      'create table public.profiles (id uuid primary key, email text);',
      'create table public.posts (id bigint primary key, body text);',
      'alter table public.posts enable row level security;',
      'create table private.secrets (id int);',
      'create table public.old (id int);',
      'drop table public.old;',
    ].join('\n'),
  });
  return root;
}

describe('--supabase-live', () => {
  it('reports readable tables as critical, without any data, after confirmation', async () => {
    const anon = anonKeyFor(REF);
    const { client, calls } = fakeClient({ profiles: 'rows', posts: 'empty', comments: 'rows' }, ['comments', 'profiles', 'rpc/x']);
    const asked: string[] = [];
    const result = await audit(project(anon), {
      osv: noOsv,
      supabaseLive: { client, confirm: async ({ host }) => (asked.push(host), true) },
    });
    expect(asked).toEqual([`${REF}.supabase.co`]);
    // Tables from the migrations (public, not dropped) and from the API; one select each, nothing else.
    expect(calls).toEqual([
      `list ${URL_}`,
      `select comments ${URL_}`,
      `select posts ${URL_}`,
      `select profiles ${URL_}`,
    ]);
    const live = result.findings.filter((f) => f.ruleId === 'supabase-live');
    expect(live.map((f) => ({ severity: f.severity, messageId: f.messageId, ...f.params }))).toEqual([
      { severity: 'critical', messageId: 'supabase.liveReadable', table: 'comments', host: `${REF}.supabase.co` },
      { severity: 'critical', messageId: 'supabase.liveReadable', table: 'profiles', host: `${REF}.supabase.co` },
    ]);
    expect(result.notes).toContain('supabase.liveChecked');
    const text = renderReport(result, { lang: 'fr', color: false });
    expect(text).toContain('Table profiles : ses données sont lisibles par n\'importe qui (test en direct)');
    expect(text).not.toContain(anon);
  });

  it('sends nothing when the user does not confirm', async () => {
    const { client, calls } = fakeClient({ profiles: 'rows' });
    const result = await audit(project(anonKeyFor(REF)), { osv: noOsv, supabaseLive: { client, confirm: async () => false } });
    expect(calls).toEqual([]);
    expect(result.notes).toContain('supabase.liveDeclined');
    expect(result.findings.filter((f) => f.ruleId === 'supabase-live')).toEqual([]);
  });

  it('never runs with --offline', async () => {
    const { client, calls } = fakeClient({ profiles: 'rows' });
    await audit(project(anonKeyFor(REF)), { offline: true, supabaseLive: { client, confirm: async () => true } });
    expect(calls).toEqual([]);
  });

  it('refuses a service_role or secret key, even given by the user, before asking anything', async () => {
    const { client, calls } = fakeClient({});
    let asked = false;
    const confirm = async () => ((asked = true), true);
    const root = project(anonKeyFor(REF));
    const result = await audit(root, { osv: noOsv, supabaseLive: { client, confirm, key: fakeSupabaseServiceRoleKey() } });
    expect(result.notes).toContain('supabase.liveBadKey');
    const secret = ['sb', 'secret', 'x'.repeat(30)].join('_');
    expect((await audit(root, { osv: noOsv, supabaseLive: { client, confirm, key: secret } })).notes).toContain('supabase.liveBadKey');
    expect(asked).toBe(false);
    expect(calls).toEqual([]);
  });

  it('never picks a service_role key found in the project', () => {
    const r = resolveTarget([file('.env', `SUPABASE_URL=${URL_}\nSUPABASE_SERVICE_ROLE_KEY=${fakeSupabaseServiceRoleKey()}\n`)]);
    expect(r).toEqual({ ok: false, problem: 'notFound' });
  });

  it('pairs URL and key without guessing', () => {
    const anon = anonKeyFor(REF);
    const other = 'zyxwvutsrqponmlkjihg';
    expect(resolveTarget([file('a.ts', `${URL_} ${anon}`)])).toEqual({ ok: true, target: { url: URL_, key: anon } });
    // Two projects, the JWT names one of them: that pair.
    expect(resolveTarget([file('a.ts', `${URL_} https://${other}.supabase.co ${anon}`)])).toEqual({
      ok: true,
      target: { url: URL_, key: anon },
    });
    // Two projects, two keys naming nothing: ambiguous.
    const pub1 = ['sb', 'publishable', 'a'.repeat(30)].join('_');
    const pub2 = ['sb', 'publishable', 'b'.repeat(30)].join('_');
    expect(resolveTarget([file('a.ts', `${URL_} ${pub1} ${pub2}`)])).toEqual({ ok: false, problem: 'ambiguous' });
    // Templates are not used.
    expect(resolveTarget([file('.env.example', `${URL_} ${anon}`)])).toEqual({ ok: false, problem: 'notFound' });
    // User-given values win; http only for a local instance.
    expect(resolveTarget([], { url: 'http://localhost:54321/', key: pub1 })).toEqual({
      ok: true,
      target: { url: 'http://localhost:54321', key: pub1 },
    });
    expect(resolveTarget([], { url: 'http://example.com', key: pub1 })).toEqual({ ok: false, problem: 'badUrl' });
  });

  it('classifies keys', () => {
    expect(keyKind(anonKeyFor(REF))).toBe('anon');
    expect(keyKind(fakeSupabaseServiceRoleKey())).toBe('forbidden');
    expect(keyKind(['sb', 'publishable', 'a'.repeat(30)].join('_'))).toBe('publishable');
    expect(keyKind('hello')).toBe('unknown');
  });
});

describe('Supabase live HTTP client', () => {
  it('only sends GET select=*&limit=1 with the anon key, and returns no data', async () => {
    const seen: { url: string; method: string; headers: Record<string, string> }[] = [];
    const fetch: FetchGet = async (url, init) => {
      seen.push({ url, method: init.method, headers: init.headers });
      if (url.endsWith('/rest/v1/')) return { ok: true, status: 200, json: async () => ({ paths: { '/': {}, '/todos': {}, '/rpc/f': {}, '/bad name': {} } }) };
      if (url.includes('/todos?')) return { ok: true, status: 200, json: async () => [{ email: 'someone@example.com' }] };
      if (url.includes('/empty?')) return { ok: true, status: 200, json: async () => [] };
      if (url.includes('/locked?')) return { ok: false, status: 401, json: async () => ({}) };
      return { ok: false, status: 500, json: async () => ({}) };
    };
    const t = { url: URL_, key: 'anon-key' };
    const c = createSupabaseLiveClient({ fetch });
    expect(await c.listTables(t)).toEqual(['todos']);
    expect(await c.selectOne(t, 'todos')).toBe('rows');
    expect(await c.selectOne(t, 'empty')).toBe('empty');
    expect(await c.selectOne(t, 'locked')).toBe('denied');
    expect(await c.selectOne(t, 'broken')).toBe('error');
    expect(await c.selectOne(t, 'x;drop')).toBe('error');
    expect(seen.every((s) => s.method === 'GET')).toBe(true);
    expect(seen.map((s) => s.url)).toEqual([
      `${URL_}/rest/v1/`,
      `${URL_}/rest/v1/todos?select=*&limit=1`,
      `${URL_}/rest/v1/empty?select=*&limit=1`,
      `${URL_}/rest/v1/locked?select=*&limit=1`,
      `${URL_}/rest/v1/broken?select=*&limit=1`,
    ]);
    expect(seen[1]?.headers).toMatchObject({ apikey: 'anon-key', Authorization: 'Bearer anon-key' });
  });
});

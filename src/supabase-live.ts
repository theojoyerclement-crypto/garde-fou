/**
 * --supabase-live: checks, against the real Supabase project, whether the
 * public (anon) key can read table rows.
 *
 * Safety rules (see CLAUDE.md):
 * - only the anon / publishable key, found in the scanned project or given by
 *   the user; a service_role / secret key is refused (it bypasses RLS);
 * - strictly read-only: GET requests only, `select=*&limit=1` per table, plus
 *   the PostgREST OpenAPI root to list exposed tables;
 * - row contents are never returned, printed or stored: only "rows / empty /
 *   denied / error" leaves the client;
 * - runs only after an explicit confirmation (or --yes).
 */
import { basenameOf, isEnvTemplate } from './patterns';
import { publicTables } from './rules/supabase-rls';
import type { Finding, ScannedFile } from './types';

export interface SupabaseTarget {
  /** Origin of the project, e.g. https://abcdefghijklmnopqrst.supabase.co */
  url: string;
  key: string;
}

export type LiveReadResult = 'rows' | 'empty' | 'denied' | 'error';

export interface SupabaseLiveClient {
  /** Tables exposed by PostgREST (OpenAPI root), or null if not available. */
  listTables(target: SupabaseTarget): Promise<string[] | null>;
  /** GET /rest/v1/<table>?select=*&limit=1. Never returns the data. */
  selectOne(target: SupabaseTarget, table: string): Promise<LiveReadResult>;
}

export type FetchGet = (
  url: string,
  init: { method: 'GET'; headers: Record<string, string>; signal?: AbortSignal },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/** Postgres identifier that is safe to put in a URL path as is. */
const TABLE_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;
const MAX_TABLES = 200;
const TIMEOUT_MS = 10_000;

export function createSupabaseLiveClient(opts: { fetch?: FetchGet } = {}): SupabaseLiveClient {
  const fetchGet: FetchGet = opts.fetch ?? ((url, init) => fetch(url, init));
  const headers = (t: SupabaseTarget) => ({ apikey: t.key, Authorization: `Bearer ${t.key}`, Accept: 'application/json' });
  const get = (url: string, t: SupabaseTarget) =>
    fetchGet(url, { method: 'GET', headers: headers(t), signal: AbortSignal.timeout(TIMEOUT_MS) });
  return {
    async listTables(t) {
      try {
        const res = await get(`${t.url}/rest/v1/`, t);
        if (!res.ok) return null;
        const spec = (await res.json()) as { paths?: Record<string, unknown> } | null;
        if (!spec || typeof spec.paths !== 'object' || spec.paths === null) return null;
        return Object.keys(spec.paths)
          .map((p) => p.replace(/^\//, ''))
          .filter((p) => TABLE_NAME.test(p));
      } catch {
        return null;
      }
    },
    async selectOne(t, table) {
      if (!TABLE_NAME.test(table)) return 'error';
      try {
        const res = await get(`${t.url}/rest/v1/${table}?select=*&limit=1`, t);
        if (res.status === 401 || res.status === 403 || res.status === 404) return 'denied';
        if (!res.ok) return 'error';
        const body = await res.json();
        // Only the shape is looked at; the rows are dropped right here.
        return Array.isArray(body) ? (body.length > 0 ? 'rows' : 'empty') : 'error';
      } catch {
        return 'error';
      }
    },
  };
}

export type KeyKind = 'anon' | 'publishable' | 'forbidden' | 'unknown';

function jwtPayload(key: string): Record<string, unknown> | null {
  const parts = key.split('.');
  if (parts.length !== 3 || !parts[0]?.startsWith('eyJ')) return null;
  try {
    const p: unknown = JSON.parse(Buffer.from(parts[1] ?? '', 'base64url').toString('utf8'));
    return typeof p === 'object' && p !== null ? (p as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Only anon / publishable keys may be used: they are public by design and RLS applies to them. */
export function keyKind(key: string): KeyKind {
  if (/^sb_publishable_[A-Za-z0-9_-]{20,}$/.test(key)) return 'publishable';
  if (key.startsWith('sb_secret_')) return 'forbidden';
  const payload = jwtPayload(key);
  if (!payload) return 'unknown';
  if (payload.role === 'anon') return 'anon';
  return 'forbidden';
}

/** https origin of a Supabase URL (http only for a local instance), or null. */
export function normalizeSupabaseUrl(raw: string): string | null {
  try {
    const u = new URL(raw.trim());
    const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1';
    if (u.protocol !== 'https:' && !(local && u.protocol === 'http:')) return null;
    if (u.username || u.password) return null;
    return u.origin;
  } catch {
    return null;
  }
}

const URL_RE = /https:\/\/([a-z0-9]{20})\.supabase\.co(?![\w.-])/g;
const JWT_RE = /(?<![\w-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}(?![\w-])/g;
const PUBLISHABLE_RE = /(?<![\w-])sb_publishable_[A-Za-z0-9_-]{20,}(?![\w-])/g;

export type TargetResolution =
  | { ok: true; target: SupabaseTarget }
  | { ok: false; problem: 'notFound' | 'ambiguous' | 'badKey' | 'badUrl' };

/**
 * URL + anon key: user-given values win; the rest comes from the project
 * (.env files included, templates excluded). Ambiguity is never guessed.
 */
export function resolveTarget(
  files: readonly ScannedFile[],
  given: { url?: string; key?: string } = {},
): TargetResolution {
  if (given.key !== undefined && keyKind(given.key) !== 'anon' && keyKind(given.key) !== 'publishable') {
    return { ok: false, problem: 'badKey' };
  }
  let givenUrl: string | undefined;
  if (given.url !== undefined) {
    const u = normalizeSupabaseUrl(given.url);
    if (!u) return { ok: false, problem: 'badUrl' };
    givenUrl = u;
  }
  if (givenUrl && given.key) return { ok: true, target: { url: givenUrl, key: given.key } };

  const refs = new Set<string>();
  const anon = new Map<string, string>(); // key → project ref (from the JWT), '' if none
  for (const f of files) {
    if (isEnvTemplate(basenameOf(f.rel))) continue;
    for (const m of f.content.matchAll(URL_RE)) if (m[1]) refs.add(m[1]);
    for (const m of f.content.matchAll(JWT_RE)) if (keyKind(m[0]) === 'anon') anon.set(m[0], keyRef(m[0]));
    for (const m of f.content.matchAll(PUBLISHABLE_RE)) anon.set(m[0], '');
  }

  const urls = givenUrl ? [givenUrl] : [...refs].map((r) => `https://${r}.supabase.co`);
  const keys: [string, string][] = given.key ? [[given.key, keyRef(given.key)]] : [...anon];
  const refOf = (url: string) => /^https:\/\/([a-z0-9]{20})\.supabase\.co$/.exec(url)?.[1];
  // A key fits a URL when it names no project, or names this one.
  const pairs = urls.flatMap((url) =>
    keys.filter(([, r]) => r === '' || refOf(url) === undefined || r === refOf(url)).map(([key, r]) => ({ url, key, exact: r !== '' && r === refOf(url) })),
  );
  const exact = pairs.filter((p) => p.exact);
  const chosen = exact.length === 1 ? exact : pairs;
  const only = chosen.length === 1 ? chosen[0] : undefined;
  if (only) return { ok: true, target: { url: only.url, key: only.key } };
  return { ok: false, problem: chosen.length === 0 ? 'notFound' : 'ambiguous' };
}

function keyRef(key: string): string {
  const ref = jwtPayload(key)?.ref;
  return typeof ref === 'string' ? ref : '';
}

export interface LiveCheckResult {
  findings: Finding[];
  tested: number;
  errors: number;
}

/** Tables from the migrations and from the OpenAPI root, one read-only select each. */
export async function checkSupabaseLive(
  files: readonly ScannedFile[],
  target: SupabaseTarget,
  client: SupabaseLiveClient,
): Promise<LiveCheckResult> {
  const fromApi = (await client.listTables(target)) ?? [];
  const tables = [...new Set([...publicTables(files), ...fromApi])]
    .filter((t) => TABLE_NAME.test(t))
    .sort()
    .slice(0, MAX_TABLES);
  const host = new URL(target.url).host;
  const findings: Finding[] = [];
  let errors = 0;
  for (const table of tables) {
    const r = await client.selectOne(target, table);
    if (r === 'error') errors++;
    if (r !== 'rows') continue;
    findings.push({
      ruleId: 'supabase-live',
      severity: 'critical',
      messageId: 'supabase.liveReadable',
      params: { table, host },
    });
  }
  return { findings, tested: tables.length, errors };
}

/**
 * OSV.dev client: the ONLY network access of Garde-Fou, disabled by --offline.
 * Only package names and versions from the lockfile are sent, never code.
 */
import type { OsvClient, OsvPackage, OsvVuln, Severity } from './types';

export const OSV_API = 'https://api.osv.dev/v1';
const BATCH_SIZE = 1000;
const DETAIL_CONCURRENCY = 8;
const DEFAULT_TIMEOUT_MS = 15_000;

/** The subset of `fetch` the client needs (tests inject a fake one). */
export type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

interface OsvRecord {
  id?: unknown;
  withdrawn?: unknown;
  database_specific?: { severity?: unknown };
  affected?: {
    package?: { name?: unknown; ecosystem?: unknown };
    ranges?: { type?: unknown; events?: OsvEvent[] }[];
    database_specific?: { severity?: unknown };
    ecosystem_specific?: { severity?: unknown };
  }[];
}

/** OSV ids end up in URLs and in the report: accept only their documented shape. */
export function isOsvId(id: unknown): id is string {
  return typeof id === 'string' && /^[A-Za-z][A-Za-z0-9._:-]{2,80}$/.test(id);
}

const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

/** Semver comparison; NaN when either side is not a plain semver version. */
export function compareSemver(a: string, b: string): number {
  const pa = SEMVER.exec(a.trim());
  const pb = SEMVER.exec(b.trim());
  if (!pa || !pb) return Number.NaN;
  for (let i = 1; i <= 3; i++) {
    const d = Number(pa[i]) - Number(pb[i]);
    if (d !== 0) return Math.sign(d);
  }
  const ra = pa[4];
  const rb = pb[4];
  if (ra === rb) return 0;
  if (ra === undefined) return 1; // 1.0.0 > 1.0.0-beta
  if (rb === undefined) return -1;
  const ia = ra.split('.');
  const ib = rb.split('.');
  for (let i = 0; i < Math.max(ia.length, ib.length); i++) {
    const x = ia[i];
    const y = ib[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny) {
      const d = Number(x) - Number(y);
      if (d !== 0) return Math.sign(d);
    } else if (nx !== ny) {
      return nx ? -1 : 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

function toSeverity(v: unknown): Severity | null {
  if (typeof v !== 'string') return null;
  switch (v.toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MODERATE':
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    default:
      return null;
  }
}

function severityOf(r: OsvRecord): Severity | null {
  const top = toSeverity(r.database_specific?.severity);
  if (top) return top;
  for (const a of r.affected ?? []) {
    const s = toSeverity(a.database_specific?.severity) ?? toSeverity(a.ecosystem_specific?.severity);
    if (s) return s;
  }
  return null;
}

/** Smallest `fixed` version of a range that contains `pkg.version`. */
function fixedVersion(r: OsvRecord, pkg: OsvPackage): string | null {
  const candidates: string[] = [];
  for (const a of r.affected ?? []) {
    if (a.package?.ecosystem !== 'npm' || a.package?.name !== pkg.name) continue;
    for (const range of a.ranges ?? []) {
      if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;
      let introduced: string | null = null;
      for (const ev of range.events ?? []) {
        if (typeof ev.introduced === 'string') {
          introduced = ev.introduced;
        } else if (typeof ev.fixed === 'string' && introduced !== null) {
          const after = introduced === '0' || compareSemver(introduced, pkg.version) <= 0;
          if (after && compareSemver(pkg.version, ev.fixed) < 0) candidates.push(ev.fixed);
          introduced = null;
        } else if (typeof ev.last_affected === 'string') {
          introduced = null;
        }
      }
    }
  }
  candidates.sort(compareSemver);
  return candidates[0] ?? null;
}

/** OSV record → what the report needs. Null for withdrawn or malformed records. */
export function toVuln(raw: unknown, pkg: OsvPackage): OsvVuln | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as OsvRecord;
  if (!isOsvId(r.id) || r.withdrawn) return null;
  const fixed = fixedVersion(r, pkg);
  return { id: r.id, severity: severityOf(r), fixed: fixed && SEMVER.test(fixed) ? fixed : null };
}

export function createOsvClient(opts: { fetch?: FetchLike; timeoutMs?: number } = {}): OsvClient {
  const doFetch = opts.fetch ?? (globalThis.fetch as unknown as FetchLike);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const call = async (url: string, init?: Parameters<FetchLike>[1]): Promise<unknown> => {
    const res = await doFetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) throw new Error(`OSV HTTP ${res.status}`);
    return res.json();
  };

  return {
    async query(pkgs: readonly OsvPackage[]): Promise<OsvVuln[][]> {
      const ids: string[][] = [];
      for (let i = 0; i < pkgs.length; i += BATCH_SIZE) {
        const chunk = pkgs.slice(i, i + BATCH_SIZE);
        const body = JSON.stringify({
          queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: 'npm' }, version: p.version })),
        });
        const res = (await call(`${OSV_API}/querybatch`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body,
        })) as { results?: { vulns?: { id?: unknown }[] }[] };
        for (let k = 0; k < chunk.length; k++) {
          ids.push((res.results?.[k]?.vulns ?? []).map((v) => v.id).filter(isOsvId));
        }
      }

      const unique = [...new Set(ids.flat())].sort();
      const details = new Map<string, unknown>();
      let next = 0;
      const worker = async () => {
        while (next < unique.length) {
          const id = unique[next++] as string;
          details.set(id, await call(`${OSV_API}/vulns/${encodeURIComponent(id)}`));
        }
      };
      await Promise.all(Array.from({ length: Math.min(DETAIL_CONCURRENCY, unique.length) }, worker));

      return pkgs.map((p, i) =>
        (ids[i] ?? []).map((id) => toVuln(details.get(id), p)).filter((v): v is OsvVuln => v !== null),
      );
    },
  };
}

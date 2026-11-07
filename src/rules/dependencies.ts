import { compareSemver } from '../osv';
import { basenameOf, lineOf } from '../patterns';
import { SEVERITY_ORDER, type Finding, type OsvPackage, type OsvVuln, type Rule, type ScanContext, type Severity } from '../types';

/**
 * Production dependencies with published vulnerabilities, looked up on
 * OSV.dev from the exact versions of `package-lock.json` /
 * `npm-shrinkwrap.json`. The only rule that uses the network; skipped with
 * --offline (the report header says so).
 *
 * Not reported (no false positives): dev dependencies (never shipped),
 * linked / workspace packages, versions that are not plain semver (git, file,
 * tarball), withdrawn advisories. package.json ranges alone are never guessed.
 */

export const LOCKFILES = new Set(['package-lock.json', 'npm-shrinkwrap.json']);

const PLAIN_SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
/** npm package names (scoped or not). Anything else is not sent to OSV. */
const NPM_NAME = /^(?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*$/i;

interface LockEntry {
  version?: unknown;
  dev?: unknown;
  devOptional?: unknown;
  link?: unknown;
  dependencies?: Record<string, LockEntry>;
}

function keep(name: string, e: LockEntry): e is LockEntry & { version: string } {
  return (
    NPM_NAME.test(name) &&
    typeof e.version === 'string' &&
    PLAIN_SEMVER.test(e.version) &&
    e.dev !== true &&
    e.devOptional !== true &&
    e.link !== true
  );
}

/** Production packages of an npm lockfile (v1, v2 or v3). Null if unreadable. */
export function parsePackageLock(text: string): OsvPackage[] | null {
  let json: { packages?: Record<string, LockEntry>; dependencies?: Record<string, LockEntry> };
  try {
    json = JSON.parse(text);
  } catch {
    return null;
  }
  if (!json || typeof json !== 'object') return null;

  const out = new Map<string, OsvPackage>();
  const add = (name: string, version: string) => out.set(`${name}@${version}`, { name, version });

  if (json.packages && typeof json.packages === 'object') {
    for (const [key, entry] of Object.entries(json.packages)) {
      const at = key.lastIndexOf('node_modules/');
      if (at < 0 || !entry || typeof entry !== 'object') continue; // root or workspace
      const name = key.slice(at + 'node_modules/'.length);
      if (keep(name, entry)) add(name, entry.version);
    }
  } else if (json.dependencies && typeof json.dependencies === 'object') {
    const walk = (deps: Record<string, LockEntry>) => {
      for (const [name, entry] of Object.entries(deps)) {
        if (!entry || typeof entry !== 'object') continue;
        if (keep(name, entry)) add(name, entry.version);
        if (entry.dependencies && entry.dev !== true) walk(entry.dependencies);
      }
    };
    walk(json.dependencies);
  }
  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name) || compareSemver(a.version, b.version));
}

function worst(vulns: readonly OsvVuln[]): Severity {
  // Unknown severity counts as medium: the advisory exists, its weight is unknown.
  return vulns
    .map((v) => v.severity ?? 'medium')
    .reduce((a, b) => (SEVERITY_ORDER.indexOf(b) < SEVERITY_ORDER.indexOf(a) ? b : a), 'low' as Severity);
}

function lineOfPackage(content: string, name: string): number | undefined {
  const i = content.indexOf(`node_modules/${name}"`);
  return i < 0 ? undefined : lineOf(content, i);
}

export const dependenciesRule: Rule = {
  id: 'dependencies',
  async run(ctx: ScanContext): Promise<Finding[]> {
    const locks = ctx.files.filter((f) => !f.gitignored && LOCKFILES.has(basenameOf(f.rel)));
    if (locks.length === 0) return [];
    if (!ctx.osv) {
      ctx.notes.add('osv.offline');
      return [];
    }

    const perLock = locks.map((f) => ({ f, deps: parsePackageLock(f.content) ?? [] }));
    const unique = new Map<string, OsvPackage>();
    for (const { deps } of perLock) for (const d of deps) unique.set(`${d.name}@${d.version}`, d);
    const queries = [...unique.values()];

    const vulnsByKey = new Map<string, OsvVuln[]>();
    if (queries.length > 0) {
      let results: OsvVuln[][];
      try {
        results = await ctx.osv.query(queries);
      } catch {
        ctx.notes.add('osv.error');
        return [];
      }
      queries.forEach((q, i) => vulnsByKey.set(`${q.name}@${q.version}`, results[i] ?? []));
    }
    ctx.notes.add('osv.checked');

    const findings: Finding[] = [];
    for (const { f, deps } of perLock) {
      for (const d of deps) {
        const vulns = [...(vulnsByKey.get(`${d.name}@${d.version}`) ?? [])].sort((a, b) => a.id.localeCompare(b.id));
        if (vulns.length === 0) continue;
        const ids = vulns.map((v) => v.id);
        const fixes = vulns.map((v) => v.fixed).filter((x): x is string => x !== null).sort(compareSemver);
        findings.push({
          ruleId: 'dependencies',
          severity: worst(vulns),
          messageId: 'deps.vulnerable',
          params: {
            pkg: d.name,
            version: d.version,
            count: String(vulns.length),
            id: ids[0] ?? '',
            ids: ids.length > 3 ? `${ids.slice(0, 3).join(', ')} +${ids.length - 3}` : ids.join(', '),
            // Highest fix: the first version that fixes every advisory with a known fix.
            fixed: fixes[fixes.length - 1] ?? '',
          },
          file: f.rel,
          line: lineOfPackage(f.content, d.name),
        });
      }
    }
    return findings;
  },
};

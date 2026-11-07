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
 *
 * With a v2/v3 lockfile the dependency tree is rebuilt (npm resolution rules)
 * from the `dependencies` of package.json:
 * - packages reachable only through a build toolchain (`BUILD_TOOLCHAIN`, e.g.
 *   expo > @expo/cli) run on the developer's machine, never in the app: skipped;
 * - packages reachable only through a dev tool listed in `dependencies` by
 *   mistake (`DEV_TOOLS`, e.g. jest) give one low "dev tool in production"
 *   finding per tool, not one finding per advisory;
 * - an indirect dependency names the direct dependency that installs it (`via`),
 *   and `major` flags a fix that needs a new major version.
 * A v1 lockfile keeps the flat list (no tree, no `via`).
 */

export const LOCKFILES = new Set(['package-lock.json', 'npm-shrinkwrap.json']);

const PLAIN_SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
/** npm package names (scoped or not). Anything else is not sent to OSV. */
const NPM_NAME = /^(?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*$/i;

/**
 * Build-time packages: CLIs, bundlers and config loaders that run on the
 * developer's machine or the build server and are never shipped in the app,
 * even when a runtime package (e.g. `expo`) lists them in its dependencies.
 * Nothing below them is reported.
 */
export const BUILD_TOOLCHAIN = new Set([
  '@expo/cli',
  '@expo/config',
  '@expo/config-plugins',
  '@expo/fingerprint',
  '@expo/metro',
  '@expo/metro-config',
  '@expo/prebuild-config',
  '@react-native-community/cli',
  '@react-native/community-cli-plugin',
  '@react-native/metro-config',
  'metro',
]);

/** Test runners, linters and formatters: their place is devDependencies. */
const DEV_TOOLS = new Set([
  '@playwright/test',
  'ava',
  'babel-jest',
  'cypress',
  'eslint',
  'husky',
  'jasmine',
  'jest',
  'jest-expo',
  'lint-staged',
  'mocha',
  'nodemon',
  'prettier',
  'ts-jest',
  'vitest',
]);
const DEV_TOOL_SCOPES = ['@storybook/', '@testing-library/'];

export function isDevTool(name: string): boolean {
  return DEV_TOOLS.has(name) || DEV_TOOL_SCOPES.some((s) => name.startsWith(s));
}

interface LockEntry {
  version?: unknown;
  dev?: unknown;
  devOptional?: unknown;
  link?: unknown;
  resolved?: unknown;
  dependencies?: Record<string, LockEntry>;
  optionalDependencies?: unknown;
  peerDependencies?: unknown;
  devDependencies?: unknown;
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

function nameOfKey(key: string): string {
  const at = key.lastIndexOf('node_modules/');
  return at < 0 ? '' : key.slice(at + 'node_modules/'.length);
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
      const name = nameOfKey(key);
      if (!name || !entry || typeof entry !== 'object') continue; // root or workspace
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

/** One production package (name@version) and how the app reaches it. */
export interface ProdPackage extends OsvPackage {
  /** Listed in the `dependencies` of package.json. */
  direct: boolean;
  /** Direct dependencies that install it (empty when direct, or with a v1 lockfile). */
  via: string[];
  /** Reached only through these dev tools listed in `dependencies`. */
  devTools: string[];
}

function names(v: unknown): string[] {
  return v && typeof v === 'object' ? Object.keys(v).filter((n) => NPM_NAME.test(n)) : [];
}

/**
 * Production packages of a lockfile with the direct dependencies that bring
 * them in. Null if unreadable. Without a `packages` tree (v1) or a root entry,
 * returns the flat list of parsePackageLock().
 */
export function analyzePackageLock(text: string): ProdPackage[] | null {
  const flat = parsePackageLock(text);
  if (!flat) return null;
  const json = JSON.parse(text) as { packages?: Record<string, LockEntry> };
  const pkgs = json.packages && typeof json.packages === 'object' ? json.packages : null;
  const root = pkgs && Object.hasOwn(pkgs, '') ? pkgs[''] : undefined;
  if (
    !pkgs ||
    !root ||
    typeof root !== 'object' ||
    (root.dependencies === undefined && root.devDependencies === undefined && root.optionalDependencies === undefined)
  ) {
    return flat.map((p) => ({ ...p, direct: false, via: [], devTools: [] }));
  }

  const entry = (key: string): LockEntry | undefined => {
    const e = Object.hasOwn(pkgs, key) ? pkgs[key] : undefined;
    return e && typeof e === 'object' ? e : undefined;
  };
  /** npm resolution: the closest node_modules/<name>, going up from `from`. */
  const resolve = (from: string, name: string): string | undefined => {
    let base = from;
    for (;;) {
      const key = `${base ? `${base}/` : ''}node_modules/${name}`;
      const e = entry(key);
      if (e) {
        // Workspace link: continue from the linked folder.
        if (e.link === true) return typeof e.resolved === 'string' && entry(e.resolved) ? e.resolved : undefined;
        return key;
      }
      if (!base) return undefined;
      const i = base.lastIndexOf('/node_modules/');
      base = i < 0 ? '' : base.slice(0, i);
    }
  };
  const childrenOf = (key: string, e: LockEntry): string[] =>
    [...names(e.dependencies), ...names(e.optionalDependencies), ...names(e.peerDependencies)]
      .map((n) => resolve(key, n))
      .filter((k): k is string => k !== undefined);

  /** Every lock key reachable from `start`, without entering the build toolchain. */
  const reach = (start: string): Set<string> => {
    const seen = new Set<string>();
    const stack = [start];
    while (stack.length > 0) {
      const key = stack.pop() as string;
      if (seen.has(key) || BUILD_TOOLCHAIN.has(nameOfKey(key))) continue;
      seen.add(key);
      const e = entry(key);
      if (e) stack.push(...childrenOf(key, e));
    }
    return seen;
  };

  const directNames = [
    ...new Set([...names(root.dependencies), ...names(root.optionalDependencies), ...names(root.peerDependencies)]),
  ].sort();
  const runtimeVia = new Map<string, Set<string>>(); // lock key → direct dependencies reaching it
  const devToolVia = new Map<string, Set<string>>();
  const directKeys = new Set<string>();
  for (const name of directNames) {
    const start = resolve('', name);
    if (!start) continue;
    const tool = isDevTool(name);
    if (!tool) directKeys.add(start);
    const target = tool ? devToolVia : runtimeVia;
    for (const key of reach(start)) {
      const set = target.get(key) ?? new Set<string>();
      set.add(name);
      target.set(key, set);
    }
  }

  const out = new Map<string, ProdPackage>();
  for (const [key, e] of Object.entries(pkgs)) {
    const name = nameOfKey(key);
    if (!name || !e || typeof e !== 'object' || !keep(name, e)) continue;
    const runtime = runtimeVia.get(key);
    const tools = devToolVia.get(key);
    if (!runtime && !tools) continue; // build toolchain only, or not installed by the app
    const id = `${name}@${e.version}`;
    const p = out.get(id) ?? { name, version: e.version, direct: false, via: [], devTools: [] };
    if (runtime) {
      if (directKeys.has(key)) p.direct = true;
      p.via = [...new Set([...p.via, ...[...runtime].filter((n) => n !== name)])].sort();
    } else if (tools) {
      p.devTools = [...new Set([...p.devTools, ...tools])].sort();
    }
    out.set(id, p);
  }
  for (const p of out.values()) {
    // Also reachable at runtime: the dev tool is not the only way in.
    if (p.direct || p.via.length > 0) p.devTools = [];
    if (p.direct) p.via = [];
  }
  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name) || compareSemver(a.version, b.version));
}

function majorOf(v: string): number {
  return Number.parseInt(v, 10);
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

/** Line of `name` in the `dependencies` block of package.json. */
function lineOfDependency(content: string, name: string): number | undefined {
  const block = content.indexOf('"dependencies"');
  const i = block < 0 ? -1 : content.indexOf(`"${name}"`, block);
  return i < 0 ? undefined : lineOf(content, i);
}

function listOf(items: readonly string[]): string {
  return items.length > 3 ? `${items.slice(0, 3).join(', ')} +${items.length - 3}` : items.join(', ');
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

    const perLock = locks.map((f) => ({ f, deps: analyzePackageLock(f.content) ?? [] }));
    const unique = new Map<string, OsvPackage>();
    for (const { deps } of perLock) for (const d of deps) unique.set(`${d.name}@${d.version}`, { name: d.name, version: d.version });
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
      const dir = f.rel.includes('/') ? f.rel.slice(0, f.rel.lastIndexOf('/') + 1) : '';
      const manifest = ctx.files.find((m) => m.rel === `${dir}package.json`);
      const byTool = new Map<string, string[]>();
      for (const d of deps) {
        const vulns = [...(vulnsByKey.get(`${d.name}@${d.version}`) ?? [])].sort((a, b) => a.id.localeCompare(b.id));
        if (vulns.length === 0) continue;
        if (d.devTools.length > 0) {
          // Only installed because a dev tool sits in `dependencies`: one finding per tool, below.
          for (const t of d.devTools) byTool.set(t, [...(byTool.get(t) ?? []), d.name]);
          continue;
        }
        const ids = vulns.map((v) => v.id);
        const fixes = vulns.map((v) => v.fixed).filter((x): x is string => x !== null).sort(compareSemver);
        // Highest fix: the first version that fixes every advisory with a known fix.
        const fixed = fixes[fixes.length - 1] ?? '';
        findings.push({
          ruleId: 'dependencies',
          severity: worst(vulns),
          messageId: 'deps.vulnerable',
          params: {
            pkg: d.name,
            version: d.version,
            count: String(vulns.length),
            id: ids[0] ?? '',
            ids: listOf(ids),
            fixed,
            via: listOf(d.via),
            viaCmd: d.via.slice(0, 3).join(' '),
            major: fixed && majorOf(fixed) > majorOf(d.version) ? '1' : '',
          },
          file: f.rel,
          line: lineOfPackage(f.content, d.name),
        });
      }
      for (const [tool, pkgs] of [...byTool].sort(([a], [b]) => a.localeCompare(b))) {
        const vulnerable = [...new Set(pkgs)].sort();
        findings.push({
          ruleId: 'dependencies',
          severity: 'low',
          messageId: 'deps.devToolInProd',
          params: { pkg: tool, count: String(vulnerable.length), pkgs: listOf(vulnerable) },
          file: manifest ? manifest.rel : f.rel,
          line: manifest ? lineOfDependency(manifest.content, tool) : lineOfPackage(f.content, tool),
        });
      }
    }
    return findings;
  },
};

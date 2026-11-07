import { afterAll, describe, expect, it } from 'vitest';
import { compareSemver, createOsvClient, toVuln, type FetchLike } from '../src/osv';
import { renderHtml } from '../src/html';
import { localizeFinding, renderReport } from '../src/report';
import { analyzePackageLock, parsePackageLock } from '../src/rules/dependencies';
import type { OsvClient, OsvPackage, OsvVuln } from '../src/types';
import { audit, cleanupTempDirs, copyNamedFixture, makeTempDir, writeFiles } from './helpers';

afterAll(cleanupTempDirs);

/** Tiny offline stand-in for OSV: package → advisories affecting versions below `fixed`. */
const FAKE_DB: Record<string, { id: string; severity: OsvVuln['severity']; fixed: string }[]> = {
  lodash: [
    { id: 'GHSA-35jh-r3h4-6jhm', severity: 'high', fixed: '4.17.21' },
    { id: 'GHSA-29mw-wpgm-hmr9', severity: 'medium', fixed: '4.17.21' },
  ],
  minimist: [{ id: 'GHSA-xvch-5gv4-984h', severity: 'critical', fixed: '1.2.6' }],
  semver: [{ id: 'GHSA-c2qf-rxjj-qqgw', severity: 'high', fixed: '5.7.2' }],
  ms: [{ id: 'GHSA-w9mr-4mfr-499f', severity: null, fixed: '2.0.0' }],
  // Cases seen on a real Expo app (fixtures/dependencies-expo, fixtures/dependencies-devtool).
  zod: [{ id: 'GHSA-mrhx-c7xc-m3w5', severity: 'high', fixed: '4.6.6' }],
  glob: [{ id: 'GHSA-3g3m-2fjr-6pw4', severity: 'medium', fixed: '14.0.2' }],
  minimatch: [{ id: 'GHSA-g3hv-75wg-m249', severity: 'medium', fixed: '11.0.1' }],
  deepmerge: [{ id: 'GHSA-gcqx-w48m-w2h4', severity: 'low', fixed: '4.3.2' }],
  nanoid: [{ id: 'GHSA-mwcw-c2x4-8c55', severity: 'medium', fixed: '3.3.8' }],
  picomatch: [{ id: 'GHSA-fake-picomatch', severity: 'medium', fixed: '2.3.2' }],
};

function fakeOsv(log: OsvPackage[][] = []): OsvClient {
  return {
    async query(pkgs) {
      log.push([...pkgs]);
      return pkgs.map((p) =>
        (FAKE_DB[p.name] ?? [])
          .filter((v) => compareSemver(p.version, v.fixed) < 0)
          .map((v) => ({ id: v.id, severity: v.severity, fixed: v.fixed })),
      );
    },
  };
}

describe('fixtures/dependencies', () => {
  it('reports vulnerable production dependencies with their fix, never dev ones', async () => {
    const queried: OsvPackage[][] = [];
    const result = await audit(copyNamedFixture('dependencies'), { osv: fakeOsv(queried) });
    expect(result.notes).toEqual(['osv.checked']);
    expect(queried.flat().map((p) => `${p.name}@${p.version}`)).toEqual([
      'lodash@4.17.20',
      'minimist@1.2.5',
      'mkdirp-legacy@1.0.0',
      // dev dependency: checked only to list its advisories among the ignored ones, never a finding.
      'semver@5.7.1',
    ]);
    expect(result.findings.map((f) => ({ severity: f.severity, line: f.line, ...f.params }))).toEqual([
      {
        severity: 'critical',
        line: 30,
        pkg: 'minimist',
        version: '1.2.5',
        count: '1',
        id: 'GHSA-xvch-5gv4-984h',
        ids: 'GHSA-xvch-5gv4-984h',
        fixed: '1.2.6',
        via: 'mkdirp-legacy',
        viaCmd: 'mkdirp-legacy',
        major: '',
      },
      {
        severity: 'high',
        line: 18,
        pkg: 'lodash',
        version: '4.17.20',
        count: '2',
        id: 'GHSA-29mw-wpgm-hmr9',
        ids: 'GHSA-29mw-wpgm-hmr9, GHSA-35jh-r3h4-6jhm',
        fixed: '4.17.21',
        via: '',
        viaCmd: '',
        major: '',
      },
    ]);
  });

  it('does not touch the network with --offline and says so', async () => {
    const result = await audit(copyNamedFixture('dependencies'), { offline: true, osv: fakeOsv() });
    expect(result.findings).toEqual([]);
    expect(result.notes).toEqual(['osv.offline']);
  });

  it('reports OSV failures as a note, not as findings', async () => {
    const broken: OsvClient = { query: () => Promise.reject(new Error('ECONNREFUSED')) };
    const result = await audit(copyNamedFixture('dependencies'), { osv: broken });
    expect(result.findings).toEqual([]);
    expect(result.notes).toEqual(['osv.error']);
  });

  it('stays silent (no query, no note) without a lockfile', async () => {
    const root = makeTempDir();
    writeFiles(root, { 'package.json': '{"dependencies":{"lodash":"4.17.20"}}' });
    const queried: OsvPackage[][] = [];
    const result = await audit(root, { osv: fakeOsv(queried) });
    expect(queried).toEqual([]);
    expect(result.notes).toEqual([]);
  });
});

describe('fixtures/dependencies-expo (build toolchain, dev tools, indirect dependencies)', () => {
  it('skips what only the build toolchain or devDependencies install, names the parent of indirect ones', async () => {
    const result = await audit(copyNamedFixture('dependencies-expo'), { osv: fakeOsv() });
    // zod 3.25.76, glob, minimatch (expo > @expo/cli, @expo/config) and deepmerge (@expo/config) never run
    // in the app; jest's glob / minimatch are dev: no finding, but listed as ignored with their advisories.
    expect(result.findings.map((f) => ({ severity: f.severity, ...f.params }))).toEqual([
      {
        severity: 'high',
        pkg: 'zod',
        version: '3.22.0',
        count: '1',
        id: 'GHSA-mrhx-c7xc-m3w5',
        ids: 'GHSA-mrhx-c7xc-m3w5',
        fixed: '4.6.6',
        via: 'form-kit',
        viaCmd: 'form-kit',
        major: '1',
      },
      {
        severity: 'medium',
        pkg: 'nanoid',
        version: '3.3.6',
        count: '1',
        id: 'GHSA-mwcw-c2x4-8c55',
        ids: 'GHSA-mwcw-c2x4-8c55',
        fixed: '3.3.8',
        via: 'form-kit',
        viaCmd: 'form-kit',
        major: '',
      },
    ]);
  });

  it('lists every ignored dependency with its reason, what installs it and its advisories', async () => {
    const queried: OsvPackage[][] = [];
    const result = await audit(copyNamedFixture('dependencies-expo'), { osv: fakeOsv(queried) });
    const file = 'package-lock.json';
    expect(result.ignoredDeps).toEqual([
      { file, name: '@expo/cli', version: '58.0.0', reason: 'build', via: ['@expo/cli'], vulns: [] },
      { file, name: '@expo/config', version: '58.0.0', reason: 'build', via: ['@expo/config'], vulns: [] },
      { file, name: 'deepmerge', version: '4.3.1', reason: 'build', via: ['@expo/config'], vulns: ['GHSA-gcqx-w48m-w2h4'] },
      { file, name: 'glob', version: '13.0.6', reason: 'build', via: ['@expo/cli', '@expo/config'], vulns: ['GHSA-3g3m-2fjr-6pw4'] },
      { file, name: 'jest', version: '30.5.2', reason: 'dev', via: ['jest'], vulns: [] },
      { file, name: 'minimatch', version: '10.2.6', reason: 'build', via: ['@expo/cli', '@expo/config'], vulns: ['GHSA-g3hv-75wg-m249'] },
      { file, name: 'zod', version: '3.25.76', reason: 'build', via: ['@expo/cli'], vulns: ['GHSA-mrhx-c7xc-m3w5'] },
    ]);
    // Ignored packages are checked on OSV too (names and versions only), to show their advisories.
    expect(queried.flat().map((p) => `${p.name}@${p.version}`).sort()).toEqual([
      '@expo/cli@58.0.0',
      '@expo/config@58.0.0',
      'deepmerge@4.3.1',
      'expo@58.0.0',
      'form-kit@1.0.0',
      'glob@13.0.6',
      'jest@30.5.2',
      'minimatch@10.2.6',
      'nanoid@3.3.6',
      'zod@3.22.0',
      'zod@3.25.76',
    ]);
  });

  it.each(['fr', 'en'] as const)('%s: one summary line, the full list with --verbose', async (lang) => {
    const result = await audit(copyNamedFixture('dependencies-expo'), { osv: fakeOsv() });
    const short = renderReport(result, { lang, color: false });
    expect(short).toContain(
      lang === 'fr'
        ? '6 dépendances de build ignorées, 1 dépendance de dev ignorée, dont 4 avec failles connues (détail : --verbose)'
        : '6 build dependencies ignored, 1 dev dependency ignored, 4 with known vulnerabilities (details: --verbose)',
    );
    expect(short).not.toContain('zod@3.25.76');
    const long = renderReport(result, { lang, color: false, verbose: true });
    expect(long).not.toContain('--verbose');
    expect(long).toContain(lang === 'fr' ? 'Dépendances ignorées (hors score)' : 'Ignored dependencies (not scored)');
    expect(long).toContain('zod@3.25.76 via @expo/cli ⚠ GHSA-mrhx-c7xc-m3w5');
    expect(long).toContain('jest@30.5.2');
    // Packages with advisories come first in their group.
    expect(long.indexOf('deepmerge@4.3.1')).toBeLessThan(long.indexOf('@expo/cli@58.0.0'));
  });

  it('still counts ignored dependencies with --offline, without claiming anything about advisories', async () => {
    const result = await audit(copyNamedFixture('dependencies-expo'), { offline: true });
    expect(result.ignoredDeps.every((d) => d.vulns.length === 0)).toBe(true);
    const text = renderReport(result, { lang: 'fr', color: false });
    expect(text).toContain('6 dépendances de build ignorées, 1 dépendance de dev ignorée (détail : --verbose)');
  });

  it('shows the summary and a collapsed, escaped list in the HTML report', async () => {
    const result = await audit(copyNamedFixture('dependencies-expo'), { osv: fakeOsv() });
    const html = renderHtml(result, { lang: 'en', date: new Date('2026-11-07T12:00:00Z') });
    expect(html).toContain('6 build dependencies ignored, 1 dev dependency ignored, 4 with known vulnerabilities</p>');
    expect(html).toContain('<details class="ignored">\n<summary>Ignored dependencies (not scored)</summary>');
    expect(html).toContain('<li>zod@3.25.76 via @expo/cli ⚠ GHSA-mrhx-c7xc-m3w5</li>');
  });

  it.each(['fr', 'en'] as const)('%s: an indirect fix targets the parent; a major jump forbids overrides', async (lang) => {
    const result = await audit(copyNamedFixture('dependencies-expo'), { osv: fakeOsv() });
    const [zod, nanoid] = result.findings.map((f) => localizeFinding(f, lang));
    for (const t of [zod, nanoid]) {
      expect(t?.fix).toContain('npm update form-kit');
      expect(t?.prompt).toContain('form-kit');
    }
    expect(zod?.fix).toContain('3.22.0 → 4.6.6');
    expect(zod?.fix).toMatch(lang === 'fr' ? /Ne la forcez pas avec « overrides »/ : /Do not force it with "overrides"/);
    expect(zod?.prompt).toMatch(lang === 'fr' ? /n'ajoute pas d'overrides/ : /do not add an overrides entry/);
    expect(nanoid?.fix).toMatch(lang === 'fr' ? /ajoutez un « overrides » vers 3\.3\.8/ : /add an "overrides" entry for 3\.3\.8/);
  });
});

describe('fixtures/dependencies-devtool (jest in dependencies by mistake)', () => {
  it('gives one low finding for the tool instead of one per advisory, keeps what the app itself uses', async () => {
    const result = await audit(copyNamedFixture('dependencies-devtool'), { osv: fakeOsv() });
    expect(
      result.findings.map((f) => ({ severity: f.severity, messageId: f.messageId, file: f.file, line: f.line, ...f.params })),
    ).toEqual([
      // picomatch is also installed by react: a runtime dependency, reported normally.
      expect.objectContaining({ severity: 'medium', messageId: 'deps.vulnerable', pkg: 'picomatch', via: 'react' }),
      {
        severity: 'low',
        messageId: 'deps.devToolInProd',
        file: 'package.json',
        line: 10, // the dependencies entry, not "test": "jest" in scripts
        pkg: 'jest',
        count: '2',
        pkgs: 'glob, minimatch',
      },
    ]);
    const tool = result.findings[1];
    if (!tool) throw new Error('missing finding');
    for (const lang of ['fr', 'en'] as const) {
      const t = localizeFinding(tool, lang);
      expect(t.title).toContain('jest');
      expect(t.fix).toContain('devDependencies');
      expect(t.why).toContain('glob, minimatch');
    }
  });

  it('says nothing about the dev tool when it brings no vulnerable package', async () => {
    const clean: OsvClient = { query: async (pkgs) => pkgs.map(() => []) };
    const result = await audit(copyNamedFixture('dependencies-devtool'), { osv: clean });
    expect(result.findings).toEqual([]);
    // Still visible: what only jest installs.
    expect(result.ignoredDeps.map((d) => `${d.reason}:${d.name}:${d.via.join('+')}`)).toEqual([
      'devTool:glob:jest',
      'devTool:jest:jest',
      'devTool:minimatch:jest',
    ]);
  });
});

describe('analyzePackageLock', () => {
  it('follows workspace links and peer dependencies, and keeps v1 lockfiles flat', () => {
    const v3 = JSON.stringify({
      packages: {
        '': { dependencies: { app: '*' } },
        'node_modules/app': { resolved: 'packages/app', link: true },
        'packages/app': { dependencies: { a: '1' }, peerDependencies: { p: '1' } },
        'node_modules/a': { version: '1.0.0' },
        'node_modules/p': { version: '2.0.0' },
        'node_modules/orphan': { version: '3.0.0' },
      },
    });
    expect(analyzePackageLock(v3)).toEqual({
      packages: [
        { name: 'a', version: '1.0.0', direct: false, via: ['app'], devTools: [] },
        { name: 'p', version: '2.0.0', direct: false, via: ['app'], devTools: [] },
      ],
      // Installed by nothing package.json declares: not checked, but not hidden either.
      skipped: [{ name: 'orphan', version: '3.0.0', reason: 'unused', via: [] }],
    });
    const v1 = JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        a: { version: '1.0.0' },
        t: { version: '2.0.0', dev: true, dependencies: { u: { version: '1.0.0' } } },
        g: { version: 'github:x/y#abc' },
      },
    });
    expect(analyzePackageLock(v1)).toEqual({
      packages: [{ name: 'a', version: '1.0.0', direct: false, via: [], devTools: [] }],
      skipped: [
        { name: 'g', version: 'github:x/y#abc', reason: 'unverifiable', via: [] },
        { name: 't', version: '2.0.0', reason: 'dev', via: [] },
        { name: 'u', version: '1.0.0', reason: 'dev', via: [] },
      ],
    });
    expect(analyzePackageLock('nope')).toBeNull();
  });

  it('lists non-semver versions as unverifiable, never workspace links', async () => {
    const result = await audit(copyNamedFixture('dependencies'), { osv: fakeOsv() });
    expect(result.ignoredDeps.map((d) => `${d.reason}:${d.name}`)).toEqual(['unverifiable:from-git', 'dev:semver']);
    expect(result.ignoredDeps.find((d) => d.name === 'semver')?.vulns).toEqual(['GHSA-c2qf-rxjj-qqgw']);
  });

  it('never enters the build toolchain, even when a runtime package depends on it', () => {
    const v3 = JSON.stringify({
      packages: {
        '': { dependencies: { 'expo-constants': '1', '@expo/config': '1' } },
        'node_modules/expo-constants': { version: '1.0.0', dependencies: { '@expo/config': '1' } },
        'node_modules/@expo/config': { version: '1.0.0', dependencies: { deepmerge: '4' } },
        'node_modules/deepmerge': { version: '4.3.1' },
      },
    });
    const a = analyzePackageLock(v3);
    expect(a?.packages.map((p) => p.name)).toEqual(['expo-constants']);
    expect(a?.skipped.map((p) => `${p.reason}:${p.name}`)).toEqual(['build:@expo/config', 'build:deepmerge']);
  });
});

describe('parsePackageLock', () => {
  it('reads v1 lockfiles and skips dev, non-semver and malformed entries', () => {
    const v1 = JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        a: { version: '1.0.0', dependencies: { b: { version: '2.0.0' } } },
        devtool: { version: '3.0.0', dev: true, dependencies: { c: { version: '4.0.0' } } },
        gitdep: { version: 'github:x/y#abc' },
        'bad name!': { version: '1.0.0' },
      },
    });
    expect(parsePackageLock(v1)).toEqual([
      { name: 'a', version: '1.0.0' },
      { name: 'b', version: '2.0.0' },
    ]);
    expect(parsePackageLock('not json')).toBeNull();
  });

  it('handles scoped packages and dedupes', () => {
    const v3 = JSON.stringify({
      packages: {
        '': { name: 'root' },
        'node_modules/@scope/pkg': { version: '1.2.3' },
        'node_modules/x/node_modules/@scope/pkg': { version: '1.2.3' },
        'packages/workspace': { version: '0.0.1' },
        'node_modules/opt': { version: '1.0.0', devOptional: true },
      },
    });
    expect(parsePackageLock(v3)).toEqual([{ name: '@scope/pkg', version: '1.2.3' }]);
  });
});

describe('OSV client', () => {
  const lodash = { name: 'lodash', version: '4.17.20' };
  const record = {
    id: 'GHSA-35jh-r3h4-6jhm',
    database_specific: { severity: 'HIGH' },
    affected: [
      {
        package: { ecosystem: 'npm', name: 'lodash' },
        ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
      },
    ],
  };

  it('maps severity and the fixing version of the range containing the version', () => {
    expect(toVuln(record, lodash)).toEqual({ id: 'GHSA-35jh-r3h4-6jhm', severity: 'high', fixed: '4.17.21' });
    const twoRanges = {
      ...record,
      database_specific: { severity: 'MODERATE' },
      affected: [
        {
          package: { ecosystem: 'npm', name: 'lodash' },
          ranges: [{ type: 'SEMVER', events: [{ introduced: '3.0.0' }, { fixed: '3.10.2' }, { introduced: '4.0.0' }, { fixed: '4.17.21' }] }],
        },
      ],
    };
    expect(toVuln(twoRanges, lodash)).toMatchObject({ severity: 'medium', fixed: '4.17.21' });
    expect(toVuln({ ...record, database_specific: {} }, lodash)?.severity).toBeNull();
  });

  it('drops withdrawn and malformed records', () => {
    expect(toVuln({ ...record, withdrawn: '2024-01-01T00:00:00Z' }, lodash)).toBeNull();
    expect(toVuln({ ...record, id: '../../etc/passwd' }, lodash)).toBeNull();
    expect(toVuln(null, lodash)).toBeNull();
  });

  it('batches queries, fetches details once per id and sends only names and versions', async () => {
    const calls: { url: string; body?: string }[] = [];
    const fetch: FetchLike = async (url, init) => {
      calls.push({ url, body: init?.body });
      const json = url.endsWith('/querybatch')
        ? { results: [{ vulns: [{ id: record.id }] }, {}, { vulns: [{ id: record.id }, { id: 'bad id' }] }] }
        : record;
      return { ok: true, status: 200, json: async () => json };
    };
    const client = createOsvClient({ fetch });
    const res = await client.query([lodash, { name: 'ms', version: '2.1.3' }, { name: 'lodash', version: '4.17.19' }]);
    expect(res.map((r) => r.map((v) => v.id))).toEqual([[record.id], [], [record.id]]);
    expect(calls.map((c) => c.url)).toEqual([
      'https://api.osv.dev/v1/querybatch',
      'https://api.osv.dev/v1/vulns/GHSA-35jh-r3h4-6jhm',
    ]);
    expect(JSON.parse(calls[0]?.body ?? '{}')).toEqual({
      queries: [
        { package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20' },
        { package: { name: 'ms', ecosystem: 'npm' }, version: '2.1.3' },
        { package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.19' },
      ],
    });
  });

  it('fails on HTTP errors (the rule turns it into a note)', async () => {
    const fetch: FetchLike = async () => ({ ok: false, status: 503, json: async () => ({}) });
    await expect(createOsvClient({ fetch }).query([lodash])).rejects.toThrow('OSV HTTP 503');
  });
});

describe('compareSemver', () => {
  it('orders versions and prereleases', () => {
    expect(compareSemver('1.2.10', '1.2.9')).toBe(1);
    expect(compareSemver('1.0.0-beta', '1.0.0')).toBe(-1);
    expect(compareSemver('1.0.0-alpha.2', '1.0.0-alpha.10')).toBe(-1);
    expect(compareSemver('1.0.0', 'v1.0.0')).toBe(0);
    expect(compareSemver('1.0', '1.0.0')).toBeNaN();
  });
});

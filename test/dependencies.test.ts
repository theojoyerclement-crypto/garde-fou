import { afterAll, describe, expect, it } from 'vitest';
import { compareSemver, createOsvClient, toVuln, type FetchLike } from '../src/osv';
import { parsePackageLock } from '../src/rules/dependencies';
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

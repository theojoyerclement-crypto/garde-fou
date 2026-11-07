import { afterAll, describe, expect, it } from 'vitest';
import { renderReport } from '../src/report';
import { compareSemver } from '../src/osv';
import type { OsvClient } from '../src/types';
import { audit, cleanupTempDirs, copyNamedFixture } from './helpers';

afterAll(cleanupTempDirs);

/** Same advisories as the vulnerable fixture: the clean app's versions are past every fix. */
const fakeOsv: OsvClient = {
  async query(pkgs) {
    const db: Record<string, string> = { lodash: '4.17.21', minimist: '1.2.6', ms: '2.0.0', semver: '5.7.2' };
    return pkgs.map((p) => {
      const fixed = db[p.name];
      return fixed && compareSemver(p.version, fixed) < 0 ? [{ id: `GHSA-fake-${p.name}`, severity: 'high', fixed }] : [];
    });
  },
};

describe('fixtures/clean-app (secure lookalike of every check)', () => {
  it('has 0 finding with every rule enabled, OSV included', async () => {
    const result = await audit(copyNamedFixture('clean-app'), { osv: fakeOsv });
    expect(result.findings).toEqual([]);
    expect(result.score).toBe(100);
    expect(result.notes).toEqual(['osv.checked']);
    expect(renderReport(result, { lang: 'fr', color: false })).toContain('Aucun problème détecté.');
  });
});

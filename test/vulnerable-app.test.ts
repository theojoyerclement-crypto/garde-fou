import { rmSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runAudit, type AuditResult } from '../src/audit';
import { renderReport } from '../src/report';
import { fakeAnthropicKey, generateFixtureSecrets, type GeneratedSecrets } from '../scripts/fake-keys';
import { cleanupTempDirs, commitAll, copyFixture, git, makeTempDir, writeFiles } from './helpers';
import type { Finding } from '../src/types';

afterAll(cleanupTempDirs);

function byMessage(result: AuditResult, id: Finding['messageId']): Finding[] {
  return result.findings.filter((f) => f.messageId === id);
}

describe('fixtures/vulnerable-app inside a git repository', () => {
  let root: string;
  let secrets: GeneratedSecrets;
  let removedKey: string;
  let result: AuditResult;

  beforeAll(() => {
    root = path.join(makeTempDir(), 'vulnerable-app');
    copyFixture(root);
    secrets = generateFixtureSecrets();
    writeFiles(root, secrets.files);

    // Commit 1: everything, including .env and a .env.production + a key in an old file.
    removedKey = fakeAnthropicKey();
    writeFiles(root, {
      '.env.production': 'DATABASE_URL=postgres://localhost/prod\n',
      'src/old-config.ts': `export const KEY = '${removedKey}';\n`,
    });
    git(root, 'init', '-q');
    commitAll(root, 'initial commit');

    // Commit 2: the AI "cleans up" — the files disappear, the history keeps them.
    rmSync(path.join(root, '.env.production'));
    rmSync(path.join(root, 'src/old-config.ts'));
    commitAll(root, 'remove secrets');

    result = runAudit(root);
  });

  it('reads git and its history', () => {
    expect(result.gitAvailable).toBe(true);
    expect(result.historyScanned).toBe(true);
  });

  it('finds every hard-coded key, in the files where it lives', () => {
    const found = byMessage(result, 'secret.file').map((f) => `${f.params.provider} @ ${f.file}`);
    expect(found).toEqual(
      expect.arrayContaining([
        'OpenAI @ src/lib/ai.generated.ts',
        'Anthropic @ src/lib/ai.generated.ts',
        'Stripe (live) @ src/lib/payments.generated.ts',
        'Supabase service_role @ src/lib/payments.generated.ts',
        // .env is tracked: its keys are leaked too.
        'OpenAI @ .env',
        'Supabase service_role @ .env',
        'Stripe (live) @ .env',
      ]),
    );
    expect(found).toHaveLength(7);
    for (const f of byMessage(result, 'secret.file')) {
      expect(f.severity).toBe('critical');
      expect(f.line).toBeGreaterThan(0);
    }
  });

  it('finds a key that only survives in git history', () => {
    const hist = byMessage(result, 'secret.history');
    expect(hist).toHaveLength(1);
    expect(hist[0]).toMatchObject({
      severity: 'critical',
      file: 'src/old-config.ts',
      params: { provider: 'Anthropic' },
    });
    expect(hist[0]?.commit).toMatch(/^[0-9a-f]{7}$/);
  });

  it('reports the committed .env and the .env found in history', () => {
    expect(byMessage(result, 'env.tracked')).toEqual([
      expect.objectContaining({ severity: 'high', file: '.env' }),
    ]);
    expect(byMessage(result, 'env.history')).toEqual([
      expect.objectContaining({ severity: 'high', file: '.env.production' }),
    ]);
    expect(byMessage(result, 'env.notIgnored')).toEqual([]);
  });

  it('reports secrets exposed through NEXT_PUBLIC_* / VITE_*', () => {
    expect(byMessage(result, 'env.publicSecretValue')).toEqual([
      expect.objectContaining({
        severity: 'critical',
        file: '.env',
        params: expect.objectContaining({ name: 'NEXT_PUBLIC_STRIPE_SECRET_KEY' }),
      }),
    ]);
    const sensitive = byMessage(result, 'env.publicSensitive').map((f) => `${f.params.name} @ ${f.file}`);
    expect(sensitive.sort()).toEqual(
      [
        'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY @ .env.example',
        'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY @ src/lib/supabase-admin.ts',
        'VITE_OPENAI_API_KEY @ src/legacy/chat.ts',
      ].sort(),
    );
  });

  it('produces no false positive', () => {
    const files = new Set(result.findings.map((f) => f.file));
    expect(files.has('src/lib/safe.ts')).toBe(false);
    expect(files.has('README.md')).toBe(false);
    expect(files.has('package.json')).toBe(false);
    const names = result.findings.map((f) => f.params.name).filter(Boolean);
    for (const n of ['NEXT_PUBLIC_SUPABASE_ANON_KEY', 'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY', 'VITE_OPENAI_MODEL', 'NEXT_PUBLIC_SUPABASE_URL']) {
      expect(names).not.toContain(n);
    }
    // Only the 2 live keys in payments.generated.ts, not the test / placeholder ones.
    expect(result.findings.filter((f) => f.file === 'src/lib/payments.generated.ts')).toHaveLength(2);
  });

  it('sorts by severity and scores the project', () => {
    const order = ['critical', 'high', 'medium', 'low'];
    const ranks = result.findings.map((f) => order.indexOf(f.severity));
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
    expect(result.score).toBe(0);
  });

  it('never prints a raw secret', () => {
    const all = [secrets.openai, secrets.anthropic, secrets.stripe, secrets.supabaseServiceRole, removedKey];
    const outputs = [
      JSON.stringify(result),
      renderReport(result, { lang: 'fr', color: false }),
      renderReport(result, { lang: 'en', color: false }),
    ];
    for (const out of outputs) for (const s of all) expect(out).not.toContain(s);
  });

  it('renders a French and an English report', () => {
    const fr = renderReport(result, { lang: 'fr', color: false });
    expect(fr).toContain('CRITIQUE (');
    expect(fr).toContain('ÉLEVÉ (');
    expect(fr).toContain('Score : 0/100');
    expect(fr).toContain('Pourquoi :');
    expect(fr).toContain('Variable sensible exposée au navigateur : VITE_OPENAI_API_KEY');

    const en = renderReport(result, { lang: 'en', color: false });
    expect(en).toContain('CRITICAL (');
    expect(en).toContain('Score : 0/100');
    expect(en).toContain('Sensitive variable exposed to the browser: VITE_OPENAI_API_KEY');
  });
});

describe('fixtures/vulnerable-app without git', () => {
  it('flags the unprotected .env without reporting its keys twice', () => {
    const root = path.join(makeTempDir(), 'vulnerable-app');
    copyFixture(root);
    writeFiles(root, generateFixtureSecrets().files);

    const result = runAudit(root);
    expect(result.gitAvailable).toBe(false);
    expect(byMessage(result, 'env.notIgnored')).toEqual([
      expect.objectContaining({ severity: 'high', file: '.env' }),
    ]);
    expect(byMessage(result, 'secret.file').some((f) => f.file === '.env')).toBe(false);
    expect(byMessage(result, 'secret.file')).toHaveLength(4);
  });
});

describe('a clean project', () => {
  it('gets 100/100 and no findings', () => {
    const root = makeTempDir();
    const keys = generateFixtureSecrets();
    writeFiles(root, {
      '.gitignore': 'node_modules/\n.env*\n!.env.example\n',
      // Secrets where they belong: in a gitignored .env, server-side names.
      '.env': `STRIPE_SECRET_KEY=${keys.stripe}\nOPENAI_API_KEY=${keys.openai}\n`,
      '.env.example': 'STRIPE_SECRET_KEY=\nOPENAI_API_KEY=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\n',
      'src/server.ts': 'export const key = process.env.STRIPE_SECRET_KEY;\n',
      // Never scanned.
      'node_modules/lib/index.js': `module.exports = '${keys.anthropic}';\n`,
      'fixtures/demo.ts': `export const k = '${keys.stripe}';\n`,
    });
    git(root, 'init', '-q');
    commitAll(root, 'init');

    const result = runAudit(root);
    expect(result.findings).toEqual([]);
    expect(result.score).toBe(100);
    expect(renderReport(result, { lang: 'fr', color: false })).toContain('Aucun problème détecté.');
  });
});

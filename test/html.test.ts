import { createHash } from 'node:crypto';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import type { AuditResult } from '../src/audit';
import { escapeHtml, falsePositiveUrl, renderHtml } from '../src/html';
import { localizeFinding } from '../src/report';
import type { Finding } from '../src/types';
import { generateFixtureSecrets } from '../scripts/fake-keys';
import { audit, cleanupTempDirs, commitAll, copyFixture, copyNamedFixture, git, makeTempDir, writeFiles } from './helpers';

afterAll(cleanupTempDirs);

const DATE = new Date('2026-11-07T12:00:00Z');
const XSS = '<script>alert(1)</script>"><img src=x onerror=alert(2)>\'`';

function fakeResult(findings: Finding[], target = 'demo'): AuditResult {
  return {
    target,
    root: '/tmp/demo',
    filesScanned: 3,
    gitAvailable: false,
    historyScanned: false,
    notes: [],
    findings,
    score: 55,
  };
}

/** Text content of every <script> and <style> element. */
function inline(html: string, tag: 'script' | 'style'): string[] {
  return [...html.matchAll(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, 'g'))].map((m) => m[1] ?? '');
}

describe('escapeHtml', () => {
  it('escapes the five HTML special characters', () => {
    expect(escapeHtml(`<a href="x" title='y'>&</a>`)).toBe('&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;');
  });
});

describe('renderHtml escapes everything that comes from the project or the AI', () => {
  const evil: Finding[] = [
    {
      ruleId: 'supabase-rls',
      severity: 'high',
      messageId: 'supabase.openWritePolicy',
      params: { table: XSS, policy: XSS, command: 'UPDATE', roles: XSS },
      file: `supabase/migrations/${XSS}.sql`,
      line: 3,
      ai: { explanation: XSS, fix: `</pre><script>alert(3)</script>` },
    },
    {
      ruleId: 'api-auth',
      severity: 'critical',
      messageId: 'api.noAuthAI',
      params: { framework: 'Next.js', route: `/api/${XSS}` },
      file: 'app/api/x/route.ts',
      line: 1,
    },
  ];
  const html = renderHtml(fakeResult(evil, `</title>${XSS}`), { lang: 'fr', date: DATE });

  it('contains no injected markup', () => {
    expect(html.match(/<script/g)).toHaveLength(1); // our own copy-button script
    expect(html).not.toContain('<img');
    expect(html).not.toContain('alert(3)</script>');
    expect(html.match(/<\/title>/g)).toHaveLength(1);
    expect(html.match(/<\/pre>/g)?.length).toBe(html.match(/<pre[ >]/g)?.length);
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('ships a strict CSP whose hashes match the only inline style and script', () => {
    const csp = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html)?.[1] ?? '';
    expect(csp).toContain("default-src 'none'");
    const [script] = inline(html, 'script');
    const [style] = inline(html, 'style');
    const hash = (s: string) => `'sha256-${createHash('sha256').update(s, 'utf8').digest('base64')}'`;
    expect(csp).toContain(`script-src ${hash(script ?? '')}`);
    expect(csp).toContain(`style-src ${hash(style ?? '')}`);
    expect(html).not.toMatch(/<[^>]*\son[a-z]+\s*=/i); // no inline event handler in any real tag
    expect(html).not.toMatch(/<[^>]*\sstyle\s*=/i); // no style attribute (blocked by the CSP anyway)
  });
});

describe('renderHtml on the fixtures', () => {
  const cases = ['supabase-rls', 'firebase', 'api-auth', 'dependencies', 'clean-app'] as const;

  it.each(cases)('%s: standalone page, FR and EN, score, disclaimer, one copy button per finding', async (name) => {
    const result = await audit(copyNamedFixture(name));
    for (const lang of ['fr', 'en'] as const) {
      const html = renderHtml(result, { lang, date: DATE });
      expect(html.startsWith('<!doctype html>')).toBe(true);
      expect(html).toContain(`<html lang="${lang}">`);
      expect(html).toContain('<meta name="viewport" content="width=device-width, initial-scale=1">');
      expect(html).toContain(`${result.score}<small>/100</small>`);
      expect(html).toContain(lang === 'fr' ? 'Aide à la vérification, pas une certification' : 'A review aid, not a security certification');
      // No external resource: no src/href to another origin except the issue links, no <link>, no @import.
      expect(html).not.toMatch(/<link|@import|\ssrc=|url\(/i);
      const hrefs = [...html.matchAll(/href="([^"]*)"/g)].map((m) => m[1] ?? '');
      for (const h of hrefs) expect(h.startsWith('https://github.com/theojoyerclement-crypto/garde-fou/issues/new?')).toBe(true);
      expect(html.match(/data-copy="/g)?.length ?? 0).toBe(result.findings.length);
      expect(hrefs).toHaveLength(result.findings.length);
      for (const f of result.findings) expect(html).toContain(escapeHtml(localizeFinding(f, lang).title));
      if (name === 'clean-app') expect(html).toContain(lang === 'fr' ? 'Aucun problème détecté.' : 'No issues found.');
    }
  });

  it('sorts findings by severity', async () => {
    const html = renderHtml(await audit(copyNamedFixture('supabase-rls')), { lang: 'en', date: DATE });
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => html.indexOf(`>${s} (`));
    expect(order.every((i) => i > 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
  });
});

describe('false-positive issue link', () => {
  it('is pre-filled but never contains a secret, a masked value, a path or code', async () => {
    const root = path.join(makeTempDir(), 'vulnerable-app');
    copyFixture(root);
    const secrets = generateFixtureSecrets();
    writeFiles(root, secrets.files);
    git(root, 'init', '-q');
    commitAll(root, 'init');
    const result = await audit(root);
    expect(result.findings.length).toBeGreaterThan(5);

    for (const f of result.findings) {
      const url = falsePositiveUrl(f, 'fr');
      const q = new URL(url).searchParams;
      const text = `${q.get('title')}\n${q.get('body')}`;
      expect(q.get('title')).toContain(f.messageId);
      expect(q.get('labels')).toBe('false-positive');
      for (const s of [secrets.openai, secrets.anthropic, secrets.stripe, secrets.supabaseServiceRole]) {
        expect(text).not.toContain(s);
        expect(text).not.toContain(s.slice(-4));
      }
      if (f.params.masked) expect(text).not.toContain(f.params.masked);
      if (f.file && f.file.includes('/')) expect(text).not.toContain(f.file);
      expect(text).toContain('Ne collez JAMAIS de clé');
    }
  });
});

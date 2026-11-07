import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AuditResult } from '../src/audit';
import { addAiAdvice, cleanAiText, excerptFor, explainFindings, parseAdvice } from '../src/ai/explain';
import {
  claudeProvider,
  isLoopbackUrl,
  ollamaProvider,
  openaiProvider,
  resolveProvider,
  type AiProvider,
  type AiRequest,
  type ClaudeClientLike,
} from '../src/ai/providers';
import { isRedacted, redactSecrets } from '../src/ai/redact';
import type { FetchLike } from '../src/osv';
import { renderReport } from '../src/report';
import {
  fakeAnthropicKey,
  fakeOpenAIKey,
  fakeStripeLiveKey,
  fakeSupabaseAnonKey,
  fakeSupabaseServiceRoleKey,
  generateFixtureSecrets,
  type GeneratedSecrets,
} from '../scripts/fake-keys';
import { audit, cleanupTempDirs, commitAll, copyFixture, git, makeTempDir, writeFiles } from './helpers';

afterAll(cleanupTempDirs);

const ADVICE = JSON.stringify({ explanation: 'Because the key ships to the browser.', fix: 'Move it to a server route.' });

/** Fake provider that records every request it would have sent. */
function recorder(answer: (req: AiRequest) => Promise<string> = async () => ADVICE) {
  const sent: AiRequest[] = [];
  const provider: AiProvider = {
    id: 'claude',
    model: 'fake',
    complete: async (req) => {
      sent.push(req);
      return answer(req);
    },
  };
  return { provider, sent };
}

function strip(result: AuditResult) {
  return result.findings.map(({ ai: _ai, ...rest }) => rest);
}

describe('redactSecrets', () => {
  it('removes every provider key, JWT, private key, URL password and sensitive assignment', () => {
    const keys = [fakeOpenAIKey(), fakeAnthropicKey(), fakeStripeLiveKey(), fakeSupabaseServiceRoleKey(), fakeSupabaseAnonKey()];
    const pem = ['-----BEGIN', 'PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----'].join(' ');
    const text = [
      ...keys.map((k, i) => `const k${i} = "${k}";`),
      pem,
      'DATABASE_URL=postgres://admin:S3cr3tPassw0rd@db.example.com:5432/app',
      'const password = "hunter2-but-longer";',
      '{ "client_secret": "abcdEFGH1234" }',
      'webhookSecret: whsec_9f8e7d6c5b4a',
      'const token = Xy9-Qw8_Er7Ty6Ui5Op4As3Df2Gh1Jk0;',
    ].join('\n');

    const out = redactSecrets(text);
    for (const k of keys) expect(out).not.toContain(k);
    for (const s of ['MIIEvQIBADANBgkqhkiG9w0BAQEFAASC', 'S3cr3tPassw0rd', 'hunter2-but-longer', 'abcdEFGH1234', 'whsec_9f8e7d6c5b4a', 'Xy9-Qw8_Er7Ty6Ui5Op4As3Df2Gh1Jk0']) {
      expect(out).not.toContain(s);
    }
    expect(isRedacted(out)).toBe(true);
    expect(out).toContain('postgres://admin:[REDACTED]@db.example.com');
  });

  it('masks every value of a .env file and keeps code readable', () => {
    expect(redactSecrets('PLAIN=hello\nexport OTHER = world', { envFile: true })).toBe('PLAIN=[REDACTED]\nexport OTHER =[REDACTED]');
    const code = 'const apiKey = process.env.OPENAI_API_KEY;\nconst model = "gpt-4o-mini";';
    expect(redactSecrets(code)).toBe(code);
  });
});

describe('--ai on fixtures/vulnerable-app (secrets masked BEFORE sending)', () => {
  let root: string;
  let secrets: GeneratedSecrets;
  let removedKey: string;

  beforeAll(() => {
    root = path.join(makeTempDir(), 'vulnerable-app');
    copyFixture(root);
    secrets = generateFixtureSecrets();
    writeFiles(root, secrets.files);
    removedKey = fakeAnthropicKey();
    writeFiles(root, { 'src/old.ts': `export const K = '${removedKey}';\n` });
    git(root, 'init', '-q');
    commitAll(root, 'init');
  });

  it('never sends a secret, only short redacted excerpts', async () => {
    const result = await audit(root);
    const { provider, sent } = recorder();
    await explainFindings(result, { provider, lang: 'fr', maxFindings: 50 });

    expect(sent.length).toBe(result.findings.length);
    const envValues = secrets.files['.env']
      ?.split('\n')
      .map((l) => l.split('=').slice(1).join('='))
      .filter((v) => v.length > 8) ?? [];
    const all = [secrets.openai, secrets.anthropic, secrets.stripe, secrets.supabaseServiceRole, removedKey, ...envValues];
    for (const req of sent) {
      const payload = req.system + req.user;
      for (const s of all) expect(payload).not.toContain(s);
      expect(isRedacted(payload)).toBe(true);
      const excerpt = /<excerpt>\n([\s\S]*)\n<\/excerpt>/.exec(req.user)?.[1];
      if (excerpt) expect(excerpt.split('\n').length).toBeLessThanOrEqual(13);
    }
    expect(sent.some((r) => r.user.includes('[REDACTED'))).toBe(true);
    expect(sent.some((r) => r.user.includes('<excerpt>'))).toBe(true);
  });

  it('adds advice without touching findings, severities or score', async () => {
    const before = await audit(root);
    const after = await audit(root);
    await explainFindings(after, { provider: recorder().provider, lang: 'en' });
    expect(strip(after)).toEqual(strip(before));
    expect(after.score).toBe(before.score);
    expect(after.notes).toContain('ai.used');
    expect(after.findings.filter((f) => f.ai)).toHaveLength(Math.min(10, after.findings.length));
    const text = renderReport(after, { lang: 'en', color: false });
    expect(text).toContain('AI explanation (double-check it) :');
    expect(text).toContain('Move it to a server route.');
  });
});

describe('fallback without AI', () => {
  async function sample() {
    const root = makeTempDir();
    writeFiles(root, { 'firestore.rules': "service cloud.firestore { match /databases/{d}/documents { match /x/{id} { allow write; } } }" });
    return audit(root);
  }

  it('without a key: same report, a note, no crash', async () => {
    const result = await sample();
    const before = JSON.stringify(result.findings);
    await addAiAdvice(result, 'auto', { lang: 'fr', offline: false, env: {} });
    expect(JSON.stringify(result.findings)).toBe(before);
    expect(result.notes).toEqual(['ai.noKey']);
  });

  it('with --offline: remote providers are refused, Ollama only on loopback', async () => {
    const result = await sample();
    await addAiAdvice(result, 'claude', { lang: 'fr', offline: true, env: { ANTHROPIC_API_KEY: 'x' } });
    expect(result.notes).toEqual(['ai.offline']);
    expect(resolveProvider('ollama', { OLLAMA_HOST: 'gpu.example.com:11434' }, { offline: true }).provider).toBeNull();
    expect(resolveProvider('ollama', {}, { offline: true }).provider?.id).toBe('ollama');
  });

  it.each([
    ['a network error', () => Promise.reject(new Error('ECONNRESET'))],
    ['an unusable answer', () => Promise.resolve('Sorry, I cannot help.')],
    ['a wrong JSON shape', () => Promise.resolve('{"explanation": 42}')],
    ['a timeout', () => new Promise<string>(() => {})],
  ])('on %s: findings unchanged, note ai.error', async (_label, answer) => {
    const result = await sample();
    const before = JSON.stringify(result.findings);
    await explainFindings(result, { provider: recorder(answer).provider, lang: 'fr', timeoutMs: 50 });
    expect(JSON.stringify(result.findings)).toBe(before);
    expect(result.notes).toEqual(['ai.error']);
  });
});

describe('AI output is untrusted', () => {
  it('drops control and bidi characters, bounds length, redacts keys it might echo', () => {
    const key = fakeOpenAIKey();
    const advice = parseAdvice(
      JSON.stringify({ explanation: `ok\u001b[31m red\u202e ${key}`, fix: 'x'.repeat(10_000) }),
    );
    expect(advice?.explanation).not.toMatch(/[\u001b\u202e]/);
    expect(advice?.explanation).not.toContain(key);
    expect(advice?.fix.length).toBeLessThanOrEqual(2500);
    expect(cleanAiText('a\n\n\n\nb', 100)).toBe('a\n\nb');
  });

  it('only reads excerpts inside the audited folder', () => {
    const root = makeTempDir();
    writeFiles(root, { 'a.ts': 'x' });
    const f = { ruleId: 'x', severity: 'low', messageId: 'env.tracked', params: {}, file: '../outside.ts', line: 1 } as const;
    expect(excerptFor(root, { ...f })).toBeNull();
    expect(excerptFor(root, { ...f, file: 'a.ts', commit: 'abc1234' })).toBeNull();
  });
});

describe('providers', () => {
  const req = { system: 'S', user: 'U' };
  const signal = new AbortController().signal;

  it('Claude: official SDK, claude-opus-5-5, structured output, server-side fallback', async () => {
    const calls: Record<string, unknown>[] = [];
    const client: ClaudeClientLike = {
      beta: {
        messages: {
          create: async (params) => {
            calls.push(params);
            return { stop_reason: 'end_turn', content: [{ type: 'thinking' }, { type: 'text', text: ADVICE }] };
          },
        },
      },
    };
    const p = claudeProvider('k', undefined, async () => client);
    expect(await p.complete(req, signal)).toBe(ADVICE);
    expect(calls[0]).toMatchObject({
      model: 'claude-opus-5-5',
      betas: ['server-side-fallback-2026-07-01'],
      fallbacks: 'default',
      system: 'S',
      messages: [{ role: 'user', content: 'U' }],
      output_config: { effort: 'low', format: { type: 'json_schema' } },
    });
    const refusing = claudeProvider('k', undefined, async () => ({
      beta: { messages: { create: async () => ({ stop_reason: 'refusal', content: [] }) } },
    }));
    await expect(refusing.complete(req, signal)).rejects.toThrow('declined');
  });

  it('OpenAI and Ollama: HTTP shapes', async () => {
    const seen: { url: string; headers?: Record<string, string>; body?: string }[] = [];
    const fetch: FetchLike = async (url, init) => {
      seen.push({ url, headers: init?.headers, body: init?.body });
      const json = url.includes('openai') ? { choices: [{ message: { content: ADVICE } }] } : { message: { content: ADVICE } };
      return { ok: true, status: 200, json: async () => json };
    };
    expect(await openaiProvider('sk-test', undefined, fetch).complete(req, signal)).toBe(ADVICE);
    expect(await ollamaProvider('localhost:11434', undefined, fetch).complete(req, signal)).toBe(ADVICE);
    expect(seen[0]?.url).toBe('https://api.openai.com/v1/chat/completions');
    expect(seen[0]?.headers?.authorization).toBe('Bearer sk-test');
    expect(seen[1]?.url).toBe('http://localhost:11434/api/chat');
    expect(seen[1]?.headers?.authorization).toBeUndefined();
    const failing: FetchLike = async () => ({ ok: false, status: 401, json: async () => ({}) });
    await expect(openaiProvider('k', undefined, failing).complete(req, signal)).rejects.toThrow('401');
  });

  it('auto picks Claude, then OpenAI, and honours GARDEFOU_AI_MODEL', () => {
    expect(resolveProvider('auto', {}).provider).toBeNull();
    expect(resolveProvider('auto', { OPENAI_API_KEY: 'o' }).provider?.id).toBe('openai');
    expect(resolveProvider('auto', { OPENAI_API_KEY: 'o', ANTHROPIC_API_KEY: 'a' }).provider?.id).toBe('claude');
    expect(resolveProvider('openai', { ANTHROPIC_API_KEY: 'a' }).provider).toBeNull();
    expect(resolveProvider('claude', { ANTHROPIC_API_KEY: 'a', GARDEFOU_AI_MODEL: 'claude-sonnet-5-5' }).provider?.model).toBe('claude-sonnet-5-5');
    expect(isLoopbackUrl('http://127.0.0.1:11434')).toBe(true);
    expect(isLoopbackUrl('http://10.0.0.2:11434')).toBe(false);
  });
});

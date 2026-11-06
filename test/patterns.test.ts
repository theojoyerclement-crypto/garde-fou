import { describe, expect, it } from 'vitest';
import {
  detectSecrets,
  isEnvFile,
  isEnvTemplate,
  lineOf,
  maskSecret,
  shannonEntropy,
} from '../src/patterns';
import {
  fakeAnthropicKey,
  fakeOpenAIKey,
  fakeStripeLiveKey,
  fakeStripePublishableKey,
  fakeStripeTestKey,
  fakeSupabaseAnonKey,
  fakeSupabaseServiceRoleKey,
  placeholderStripeKey,
} from '../scripts/fake-keys';

describe('detectSecrets — true positives', () => {
  it.each([
    ['openai', fakeOpenAIKey],
    ['anthropic', fakeAnthropicKey],
    ['stripe', fakeStripeLiveKey],
    ['supabaseServiceRole', fakeSupabaseServiceRoleKey],
  ] as const)('detects a %s key', (provider, make) => {
    // Several samples: the check must not depend on luck.
    for (let i = 0; i < 20; i++) {
      const key = make();
      const found = detectSecrets(`const k = "${key}";`);
      expect(found).toHaveLength(1);
      expect(found[0]?.provider).toBe(provider);
      expect(found[0]?.value).toBe(key);
    }
  });

  it('detects a legacy OpenAI key (T3BlbkFJ marker)', () => {
    const body = (n: number) => fakeStripeLiveKey().slice(8, 8 + n);
    const key = ['sk', `${body(20)}T3BlbkFJ${body(20)}`].join('-');
    expect(detectSecrets(key).map((m) => m.provider)).toEqual(['openai']);
  });

  it('detects a Supabase sb_secret_ key', () => {
    const key = ['sb', 'secret', fakeStripeLiveKey().slice(8, 48)].join('_');
    expect(detectSecrets(`KEY=${key}`).map((m) => m.provider)).toEqual(['supabaseSecret']);
  });

  it('finds several keys and reports their position', () => {
    const a = fakeAnthropicKey();
    const s = fakeStripeLiveKey();
    const text = `line1\nA=${a}\nS=${s}\n`;
    const found = detectSecrets(text);
    expect(found.map((f) => f.provider)).toEqual(['anthropic', 'stripe']);
    expect(found.map((f) => lineOf(text, f.index))).toEqual([2, 3]);
  });
});

describe('detectSecrets — no false positives', () => {
  it.each([
    ['Supabase anon key', fakeSupabaseAnonKey()],
    ['Stripe test key', fakeStripeTestKey()],
    ['Stripe publishable key', fakeStripePublishableKey()],
    ['low-entropy placeholder', placeholderStripeKey()],
    ['documentation ellipsis', 'OPENAI_API_KEY=sk-proj-... STRIPE=sk_live_...'],
    ['your-key placeholder', ['sk', 'ant', 'api03', `your-api-key-here-${'a'.repeat(80)}`].join('-')],
    ['a random JWT without role', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'],
    ['a key glued to other characters', `x${fakeStripeLiveKey()}`],
    ['plain prose', 'This file talks about sk_live keys and service_role tokens.'],
  ])('ignores %s', (_label, text) => {
    expect(detectSecrets(text)).toEqual([]);
  });
});

describe('helpers', () => {
  it('computes Shannon entropy', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
    expect(shannonEntropy('abcd')).toBe(2);
  });

  it('masks secrets without revealing them', () => {
    const key = fakeStripeLiveKey();
    const masked = maskSecret(key);
    expect(masked.startsWith(key.slice(0, 10))).toBe(true);
    expect(masked.length).toBeLessThan(20);
    expect(masked).not.toContain(key.slice(10, -4));
  });

  it('recognises .env files and templates', () => {
    expect(isEnvFile('.env')).toBe(true);
    expect(isEnvFile('.env.local')).toBe(true);
    expect(isEnvFile('env.ts')).toBe(false);
    expect(isEnvFile('.envrc')).toBe(false);
    expect(isEnvTemplate('.env.example')).toBe(true);
    expect(isEnvTemplate('.env.production')).toBe(false);
  });
});

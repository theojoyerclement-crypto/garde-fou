/**
 * Deterministic secret detectors shared by the rules.
 *
 * Every detector = a strict provider-specific regex + a validation step
 * (Shannon entropy and placeholder filter, or JWT payload decoding).
 * Precision first: when in doubt, a candidate is dropped.
 */

export type SecretProvider =
  | 'openai'
  | 'anthropic'
  | 'stripe'
  | 'supabaseServiceRole'
  | 'supabaseSecret';

export const PROVIDER_LABELS: Record<SecretProvider, string> = {
  openai: 'OpenAI',
  anthropic: 'Anthropic',
  stripe: 'Stripe (live)',
  supabaseServiceRole: 'Supabase service_role',
  supabaseSecret: 'Supabase secret',
};

export interface SecretMatch {
  provider: SecretProvider;
  value: string;
  index: number;
}

interface Detector {
  provider: SecretProvider;
  /** Must be global. Group 1 = full secret, group 2 = part checked by `validate`. */
  regex: RegExp;
  validate: (body: string) => boolean;
}

/** Minimum Shannon entropy (bits/char) of the random part of a key. */
export const MIN_ENTROPY = 3.5;

const PLACEHOLDER =
  /(x{5,}|\*{4,}|0{6,}|\.{3}|<|>|example|placeholder|dummy|redacted|your[_-]?(api[_-]?)?key|replace[_-]?me|changeme|insert[_-]?here)/i;

export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function looksRandom(body: string): boolean {
  return shannonEntropy(body) >= MIN_ENTROPY && !PLACEHOLDER.test(body);
}

function decodeBase64Url(s: string): string | null {
  try {
    return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  } catch {
    return null;
  }
}

function isSupabaseServiceRoleJwt(payloadB64: string): boolean {
  const json = decodeBase64Url(payloadB64);
  if (!json) return false;
  try {
    const payload: unknown = JSON.parse(json);
    return (
      typeof payload === 'object' &&
      payload !== null &&
      (payload as Record<string, unknown>).role === 'service_role'
    );
  } catch {
    return false;
  }
}

// `(?<![\w-])` / `(?![\w-])`: the key must not be glued to other key-like characters.
const DETECTORS: Detector[] = [
  {
    provider: 'anthropic',
    regex: /(?<![\w-])(sk-ant-(?:api|admin)\d{2}-([A-Za-z0-9_-]{80,}))(?![\w-])/g,
    validate: looksRandom,
  },
  {
    // Project / service-account / admin keys.
    provider: 'openai',
    regex: /(?<![\w-])(sk-(?:proj|svcacct|admin)-([A-Za-z0-9_-]{40,}))(?![\w-])/g,
    validate: looksRandom,
  },
  {
    // Legacy user keys always embed "T3BlbkFJ" (base64 of "OpenAI").
    provider: 'openai',
    regex: /(?<![\w-])(sk-([A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}))(?![\w-])/g,
    validate: looksRandom,
  },
  {
    // Secret (sk_) and restricted (rk_) LIVE keys only. Test keys are harmless.
    provider: 'stripe',
    regex: /(?<![\w-])((?:sk|rk)_live_([A-Za-z0-9]{24,}))(?![\w-])/g,
    validate: looksRandom,
  },
  {
    provider: 'supabaseSecret',
    regex: /(?<![\w-])(sb_secret_([A-Za-z0-9_-]{20,}))(?![\w-])/g,
    validate: looksRandom,
  },
  {
    // A JWT whose payload says role=service_role. The anon key (role=anon) is public by design.
    provider: 'supabaseServiceRole',
    regex: /(?<![\w-])(eyJ[A-Za-z0-9_-]{8,}\.(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{16,})(?![\w-])/g,
    validate: isSupabaseServiceRoleJwt,
  },
];

export function detectSecrets(text: string): SecretMatch[] {
  const out: SecretMatch[] = [];
  for (const d of DETECTORS) {
    d.regex.lastIndex = 0;
    for (const m of text.matchAll(d.regex)) {
      const value = m[1];
      const body = m[2];
      if (value === undefined || body === undefined) continue;
      if (!d.validate(body)) continue;
      out.push({ provider: d.provider, value, index: m.index ?? 0 });
    }
  }
  return out.sort((a, b) => a.index - b.index);
}

/** Shows enough to recognise a key, never enough to use it. */
export function maskSecret(value: string): string {
  if (value.length <= 16) return `${value.slice(0, 4)}…`;
  return `${value.slice(0, 10)}…${value.slice(-4)}`;
}

/** 1-based line number of `index` in `text`. */
export function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

const ENV_FILE = /^\.env(\..+)?$/;
const ENV_TEMPLATE = /\.(example|sample|template|dist|defaults?)$/i;

export function isEnvFile(basename: string): boolean {
  return ENV_FILE.test(basename);
}

/** `.env.example` & co. are meant to be committed. */
export function isEnvTemplate(basename: string): boolean {
  return isEnvFile(basename) && ENV_TEMPLATE.test(basename);
}

export function basenameOf(relPath: string): string {
  const i = relPath.lastIndexOf('/');
  return i === -1 ? relPath : relPath.slice(i + 1);
}

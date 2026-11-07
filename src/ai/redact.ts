/**
 * Secret redaction applied to EVERYTHING sent to an AI provider, before it
 * leaves the machine. Deliberately greedy: over-masking only costs a little
 * context, under-masking leaks a key.
 */
import { MIN_ENTROPY, detectSecrets, shannonEntropy } from '../patterns';

export const REDACTED = '[REDACTED]';

/** Words that make a variable / key / field name sensitive. */
const SENSITIVE_NAME =
  /(?:key|secret|token|passw(?:or)?d|pwd|private|credential|auth|cookie|session|signature|salt|dsn)/i;

/** `NAME = value`, `"name": "value"`, `name: 'value'` (value up to a delimiter). */
const ASSIGNMENT =
  /(\b[A-Za-z_$][\w$.-]*["']?\s*(?:=|:)\s*)(["'`]?)([^\s"'`,;)}\]]{3,})\2/g;

const PEM = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g;
const JWT = /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.?[A-Za-z0-9_-]*/g;
const URL_CREDENTIALS = /(\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@'"`]+:)[^\s@'"`]+@/gi;
const LONG_TOKEN = /[A-Za-z0-9+/_=.-]{20,}/g;
const ENV_LINE = /^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=).*$/gm;

function looksRandom(tok: string): boolean {
  return /\d/.test(tok) && /[A-Za-z]/.test(tok) && shannonEntropy(tok) >= MIN_ENTROPY;
}

export function redactSecrets(text: string, opts: { envFile?: boolean } = {}): string {
  let out = text;

  // 1. Provider keys found by the deterministic detectors.
  for (const m of detectSecrets(out)) out = out.split(m.value).join(`[REDACTED:${m.provider}]`);

  // 2. .env files: every value goes.
  if (opts.envFile) out = out.replace(ENV_LINE, `$1${REDACTED}`);

  // 3. Private keys, JWTs (even "public" anon keys), credentials inside URLs.
  out = out.replace(PEM, '[REDACTED:private key]');
  out = out.replace(JWT, '[REDACTED:jwt]');
  out = out.replace(URL_CREDENTIALS, `$1${REDACTED}@`);

  // 4. Values assigned to sensitive names, whatever they look like.
  out = out.replace(ASSIGNMENT, (all, lhs: string, q: string, value: string) => {
    if (!SENSITIVE_NAME.test(lhs) || value.startsWith('[REDACTED')) return all;
    // Keep code references readable: process.env.X, import.meta.env.X, Deno.env.get(…).
    if (/^(?:process\.env|import\.meta\.env|Deno\.env)\b/.test(value)) return all;
    return `${lhs}${q}${REDACTED}${q}`;
  });

  // 5. Any long random-looking token left.
  out = out.replace(LONG_TOKEN, (tok) => (looksRandom(tok) ? REDACTED : tok));

  return out;
}

/** True when nothing that the detectors recognise as a secret is left. */
export function isRedacted(text: string): boolean {
  return (
    detectSecrets(text).length === 0 && !new RegExp(PEM.source).test(text) && !new RegExp(JWT.source).test(text)
  );
}

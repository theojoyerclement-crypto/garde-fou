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

/** `NAME =`, `"name":`, `name:` — the value is read by `valueEnd()`, not by the regex. */
const ASSIGNMENT_LHS = /\b([A-Za-z_$][\w$.-]*)["']?\s*(?:=|:)[ \t]*/g;
/** Values that are references, not secrets: keep code readable. */
const ENV_REFERENCE = /^(?:process\.env|import\.meta\.env|Deno\.env)\b/;

/**
 * End of the value starting at `start`: up to the matching closing quote
 * (whatever is inside, spaces included), or to the end of the line.
 */
function valueEnd(text: string, start: number): number {
  const q = text[start];
  if (q === '"' || q === "'" || q === '`') {
    for (let i = start + 1; i < text.length; i++) {
      if (text[i] === '\\') {
        i++;
        continue;
      }
      if (text[i] === q) {
        // Anything but a terminator after the closing quote (concatenation,
        // another literal…) may still be secret: mask to the end of the line.
        const eol = text.indexOf('\n', i);
        const rest = text.slice(i + 1, eol < 0 ? text.length : eol);
        return /^[\s;,)\]}]*$/.test(rest) ? i + 1 : eol < 0 ? text.length : eol;
      }
      if (text[i] === '\n' && q !== '`') break;
    }
  }
  const eol = text.indexOf('\n', start);
  return eol < 0 ? text.length : eol;
}

interface Assignment {
  start: number;
  end: number;
  value: string;
}

/**
 * Every value assigned to a sensitive name, unless it is empty or an env
 * reference. The value may start on a following line. Ranges never overlap:
 * scanning resumes after each value, so a name inside a value is part of it.
 */
function sensitiveAssignments(text: string): Assignment[] {
  const out: Assignment[] = [];
  const re = new RegExp(ASSIGNMENT_LHS.source, 'g');
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    if (!SENSITIVE_NAME.test(m[1] ?? '')) continue;
    let start = m.index + m[0].length;
    while (start < text.length && /\s/.test(text[start] ?? '')) start++;
    if (start >= text.length) break;
    const end = valueEnd(text, start);
    re.lastIndex = Math.max(re.lastIndex, end);
    const value = text.slice(start, end);
    const inner = value.replace(/^["'`]|["'`]$/g, '').trim();
    if (!inner || ENV_REFERENCE.test(inner)) continue;
    out.push({ start, end, value });
  }
  return out;
}

function isMasked(value: string): boolean {
  return /^["'`]?\[REDACTED[^\]]*\]["'`]?$/.test(value.trim());
}

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

  // 4. Values assigned to sensitive names, whatever they look like: the whole
  //    quoted string (spaces included) or the rest of the line.
  for (const a of sensitiveAssignments(out).reverse()) {
    if (isMasked(a.value)) continue;
    const q = /^["'`]/.test(a.value) && a.value.length > 1 && a.value.endsWith(a.value[0] ?? '') ? (a.value[0] ?? '') : '';
    out = `${out.slice(0, a.start)}${q}${REDACTED}${q}${out.slice(a.end)}`;
  }

  // 5. Any long random-looking token left.
  out = out.replace(LONG_TOKEN, (tok) => (looksRandom(tok) ? REDACTED : tok));

  return out;
}

/**
 * Fail-closed check before sending: no detectable secret, no private key or
 * JWT, and every value assigned to a sensitive name is masked.
 */
export function isRedacted(text: string): boolean {
  return (
    detectSecrets(text).length === 0 &&
    !new RegExp(PEM.source).test(text) &&
    !new RegExp(JWT.source).test(text) &&
    sensitiveAssignments(text).every((a) => isMasked(a.value))
  );
}

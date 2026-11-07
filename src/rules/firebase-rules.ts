import { basenameOf, lineOf } from '../patterns';
import type { Finding, Rule, ScanContext, ScannedFile } from '../types';

/**
 * Firebase security rules left open:
 *
 * - Firestore / Cloud Storage (`*.rules`): `allow write` (or create / update /
 *   delete) with no condition or `if true`, anywhere; `allow read` the same way
 *   on the catch-all path `{document=**}`; the "test mode" rule
 *   `if request.time < timestamp.date(…)`, open to everyone until that date.
 * - Realtime Database (`database.rules.json`): `".write": true` anywhere,
 *   `".read": true` at the root.
 *
 * Not reported (no false positives): public reads on a specific collection or
 * path (public catalogue, blog posts…), any condition other than `true`.
 */

type Service = 'Firestore' | 'Cloud Storage' | 'Realtime Database';

const WRITE_METHODS = new Set(['write', 'create', 'update', 'delete']);
const READ_METHODS = new Set(['read', 'get', 'list']);

const RE_TOKEN =
  /\bmatch\s+((?:\/(?:\{[^}\s]*\}|[^\s/{}]+))+)\s*\{|\{|\}|\ballow\s+([a-z,\s]+?)\s*(?::\s*if\b([^;]*))?;/g;
const RE_TEST_MODE = /^request\.time<timestamp\.date\(\d+,\d+,\d+\)$/;
const RE_CATCH_ALL =
  /^(?:\/databases\/\{[^}]+\}\/documents|\/b\/\{[^}]+\}\/o)?\/\{[^}=]+=\*\*\}$/;

/** Blanks out comments and string contents, keeping offsets. */
export function maskRules(src: string): string {
  const chars = src.split('');
  const blank = (from: number, to: number) => {
    for (let k = from; k < to && k < chars.length; k++) if (chars[k] !== '\n') chars[k] = ' ';
  };
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    if (ch === '/' && src[i + 1] === '/') {
      const end = src.indexOf('\n', i);
      const j = end < 0 ? src.length : end;
      blank(i, j);
      i = j;
    } else if (ch === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      const j = end < 0 ? src.length : end + 2;
      blank(i, j);
      i = j;
    } else if (ch === '"' || ch === "'") {
      let j = i + 1;
      while (j < src.length && src[j] !== ch && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
      blank(i + 1, j);
      i = j + 1;
    } else {
      i++;
    }
  }
  return chars.join('');
}

function serviceOf(f: ScannedFile): Service | null {
  const name = basenameOf(f.rel);
  if (!name.endsWith('.rules')) return null;
  if (/\bservice\s+firebase\.storage\b/.test(f.content)) return 'Cloud Storage';
  if (/\bservice\s+cloud\.firestore\b/.test(f.content)) return 'Firestore';
  return null;
}

function normalizeCondition(cond: string): string {
  let c = cond.replace(/\s+/g, '');
  while (c.startsWith('(') && c.endsWith(')')) c = c.slice(1, -1);
  return c;
}

/** `/databases/{database}/documents/users/{id}` → `/users/{id}` (what users recognise). */
function displayPath(full: string): string {
  return full.replace(/^\/databases\/\{[^}]+\}\/documents|^\/b\/\{[^}]+\}\/o/, '') || '/';
}

export function scanSecurityRules(f: ScannedFile, service: Service): Finding[] {
  const findings: Finding[] = [];
  const masked = maskRules(f.content);
  /** One frame per `{`: a match path, or null for any other block. */
  const stack: (string | null)[] = [];

  for (const m of masked.matchAll(RE_TOKEN)) {
    const tok = m[0];
    if (m[1] !== undefined) {
      stack.push(m[1]);
      continue;
    }
    if (tok === '{') {
      stack.push(null);
      continue;
    }
    if (tok === '}') {
      stack.pop();
      continue;
    }

    const methods = (m[2] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    if (methods.length === 0 || methods.some((x) => !WRITE_METHODS.has(x) && !READ_METHODS.has(x))) {
      continue; // not an allow statement we understand: never guess
    }
    const cond = m[3] === undefined ? 'true' : normalizeCondition(m[3]);
    const testMode = RE_TEST_MODE.test(cond);
    if (cond !== 'true' && !testMode) continue;

    const full = stack.filter((s): s is string => s !== null).join('');
    if (!full) continue;
    const path = displayPath(full);
    const base = {
      ruleId: 'firebase-rules',
      file: f.rel,
      line: lineOf(f.content, m.index ?? 0),
    };
    const writes = methods.some((x) => WRITE_METHODS.has(x));

    if (testMode) {
      findings.push({ ...base, severity: 'high', messageId: 'firebase.testMode', params: { service, path } });
    } else if (writes) {
      findings.push({ ...base, severity: 'critical', messageId: 'firebase.openWrite', params: { service, path } });
    } else if (RE_CATCH_ALL.test(full)) {
      findings.push({ ...base, severity: 'high', messageId: 'firebase.openRead', params: { service, path } });
    }
  }
  return findings;
}

function isOpen(v: unknown): boolean {
  return v === true || (typeof v === 'string' && normalizeCondition(v) === 'true');
}

/** Line of the n-th `"<key>": true` in the file (JSON keeps document order). */
function nthKeyLine(content: string, key: '.read' | '.write', n: number): number | undefined {
  const re = new RegExp(String.raw`"\.${key.slice(1)}"\s*:\s*(?:true|"\s*true\s*")`, 'g');
  let i = 0;
  for (const m of content.matchAll(re)) if (i++ === n) return lineOf(content, m.index ?? 0);
  return undefined;
}

export function scanRealtimeRules(f: ScannedFile): Finding[] {
  let json: unknown;
  try {
    json = JSON.parse(f.content);
  } catch {
    return [];
  }
  const rules = (json as { rules?: unknown } | null)?.rules;
  if (!rules || typeof rules !== 'object') return [];

  const findings: Finding[] = [];
  const counters = { '.read': 0, '.write': 0 };
  const service: Service = 'Realtime Database';

  const walk = (node: Record<string, unknown>, path: string) => {
    for (const [k, v] of Object.entries(node)) {
      if (k === '.read' || k === '.write') {
        if (!isOpen(v)) continue;
        const line = nthKeyLine(f.content, k, counters[k]++);
        const base = { ruleId: 'firebase-rules', file: f.rel, line, params: { service, path } };
        if (k === '.write') findings.push({ ...base, severity: 'critical', messageId: 'firebase.openWrite' });
        else if (path === '/') findings.push({ ...base, severity: 'high', messageId: 'firebase.openRead' });
      } else if (v && typeof v === 'object' && !Array.isArray(v)) {
        walk(v as Record<string, unknown>, `${path === '/' ? '' : path}/${k}`);
      }
    }
  };
  walk(rules as Record<string, unknown>, '/');
  return findings;
}

export const firebaseRulesRule: Rule = {
  id: 'firebase-rules',
  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    for (const f of ctx.files) {
      if (f.gitignored) continue;
      if (basenameOf(f.rel) === 'database.rules.json') {
        findings.push(...scanRealtimeRules(f));
        continue;
      }
      const service = serviceOf(f);
      if (service) findings.push(...scanSecurityRules(f, service));
    }
    return findings;
  },
};

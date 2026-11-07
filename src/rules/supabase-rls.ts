import { lineOf } from '../patterns';
import type { Finding, Rule, ScanContext, ScannedFile } from '../types';

/**
 * Supabase migrations (`supabase/**.sql`), replayed in file-name order:
 *
 * - table of the `public` schema whose row level security is never enabled
 *   (or disabled afterwards): anyone holding the public anon key can read and
 *   change every row through the auto-generated API;
 * - permissive policy whose condition is literally `true`.
 *
 * Not reported (no false positives): tables of other schemas, temporary tables,
 * tables on which every privilege is revoked from both `anon` and
 * `authenticated` (and not granted back), policies dropped or
 * altered later, restrictive policies, policies limited to admin roles.
 */

const ID = String.raw`(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)`;
const QNAME = String.raw`${ID}(?:\s*\.\s*${ID})?`;
const QNAME_LIST = String.raw`${QNAME}(?:\s*,\s*${QNAME})*`;

/** Unlogged tables are regular tables for the API: only temporary ones are skipped. */
const RE_CREATE_TABLE = new RegExp(
  String.raw`^create\s+(?:(?:global|local)\s+)?((?:temp|temporary)\s+)?(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?(${QNAME})`,
  'i',
);
const IDENT_CHAR = /[A-Za-z0-9_$]/;
const RE_ALTER_TABLE = new RegExp(
  String.raw`^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(${QNAME})\s+([\s\S]*)$`,
  'i',
);
const RE_DROP_TABLE = new RegExp(String.raw`^drop\s+table\s+(?:if\s+exists\s+)?(${QNAME_LIST})`, 'i');
const RE_CREATE_POLICY = new RegExp(
  String.raw`^create\s+policy\s+(${ID})\s+on\s+(${QNAME})([\s\S]*)$`,
  'i',
);
const RE_DROP_OR_ALTER_POLICY = new RegExp(
  String.raw`^(?:drop|alter)\s+policy\s+(?:if\s+exists\s+)?(${ID})\s+on\s+(${QNAME})`,
  'i',
);
/** `revoke <privileges> on <target> from <roles>` / `grant <privileges> on <target> to <roles>`. */
const RE_GRANT_OR_REVOKE = new RegExp(
  String.raw`^(revoke|grant)\s+(?:grant\s+option\s+for\s+)?([\s\S]+?)\s+on\s+(?:table\s+)?(${QNAME_LIST}|all\s+tables\s+in\s+schema\s+${ID})\s+(?:from|to)\s+([\s\S]+)$`,
  'i',
);
/** Roles the Supabase API uses. A table is closed only when both lose every privilege. */
const API_ROLES = ['anon', 'authenticated'] as const;
const TABLE_PRIVILEGES = ['select', 'insert', 'update', 'delete'] as const;

/** Roles that bypass or administer RLS: an open policy for them only changes nothing. */
const ADMIN_ROLES = new Set([
  'service_role',
  'postgres',
  'supabase_admin',
  'supabase_auth_admin',
  'supabase_storage_admin',
]);

export interface SqlStatement {
  /** Offset of the first non-blank character in the original text. */
  index: number;
  /** Statement with comments and string / dollar-quoted contents blanked out. */
  sql: string;
}

/**
 * Splits SQL into statements. Comments, string literals and dollar-quoted
 * bodies (functions) are replaced by spaces so offsets stay valid.
 */
export function splitSql(src: string): SqlStatement[] {
  const chars = src.split('');
  const blank = (from: number, to: number) => {
    for (let k = from; k < to && k < chars.length; k++) if (chars[k] !== '\n') chars[k] = ' ';
  };
  let i = 0;
  while (i < src.length) {
    const ch = src[i];
    const next = src[i + 1];
    if (ch === '-' && next === '-') {
      const end = src.indexOf('\n', i);
      const j = end < 0 ? src.length : end;
      blank(i, j);
      i = j;
    } else if (ch === '/' && next === '*') {
      // Unterminated constructs are left visible: PostgreSQL would reject the
      // file anyway, and hiding the rest of it could hide real statements.
      const end = src.indexOf('*/', i + 2);
      if (end < 0) {
        i += 2;
        continue;
      }
      blank(i, end + 2);
      i = end + 2;
    } else if (ch === "'") {
      // E'…' strings use backslash escapes.
      const escapes = /[eE]/.test(src[i - 1] ?? '') && !IDENT_CHAR.test(src[i - 2] ?? '');
      let j = i + 1;
      let closed = false;
      while (j < src.length) {
        if (escapes && src[j] === '\\') {
          j += 2;
          continue;
        }
        if (src[j] === "'") {
          if (src[j + 1] === "'") {
            j += 2;
            continue;
          }
          closed = true;
          break;
        }
        j++;
      }
      if (!closed) {
        i++;
        continue;
      }
      blank(i + 1, j);
      i = j + 1;
    } else if (ch === '"') {
      const end = src.indexOf('"', i + 1);
      i = end < 0 ? i + 1 : end + 1;
    } else if (ch === '$' && !IDENT_CHAR.test(src[i - 1] ?? '')) {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(src.slice(i, i + 64));
      const end = m ? src.indexOf(m[0], i + m[0].length) : -1;
      if (!m || end < 0) {
        i++;
        continue;
      }
      blank(i, end + m[0].length);
      i = end + m[0].length;
    } else {
      i++;
    }
  }

  const masked = chars.join('');
  const out: SqlStatement[] = [];
  let start = 0;
  let inQuote = false;
  const push = (end: number) => {
    const raw = masked.slice(start, end);
    const lead = raw.length - raw.trimStart().length;
    const sql = raw.trim();
    if (sql) out.push({ index: start + lead, sql });
  };
  for (let k = 0; k < masked.length; k++) {
    if (masked[k] === '"') inQuote = !inQuote;
    else if (masked[k] === ';' && !inQuote) {
      push(k);
      start = k + 1;
    }
  }
  push(masked.length);
  return out;
}

function normalizeIdent(raw: string): string {
  return raw.startsWith('"') ? raw.slice(1, -1).replace(/""/g, '"') : raw.toLowerCase();
}

/** `public.users`, `"Users"`, `users` → { schema, name }. */
function parseQName(raw: string): { schema: string; name: string } {
  const parts = [...raw.matchAll(new RegExp(ID, 'g'))].map((m) => normalizeIdent(m[0]));
  return parts.length > 1
    ? { schema: parts[0] ?? 'public', name: parts[1] ?? '' }
    : { schema: 'public', name: parts[0] ?? '' };
}

function splitQNames(list: string): string[] {
  return [...list.matchAll(new RegExp(QNAME, 'g'))].map((m) => tableKey(m[0]));
}

function tableKey(raw: string): string {
  const { schema, name } = parseQName(raw);
  return `${schema}.${name}`;
}

function displayTable(key: string): string {
  return key.startsWith('public.') ? key.slice('public.'.length) : key;
}

/** Inner text of the parenthesis opened right after `keyword`, or null. */
function parenAfter(text: string, keyword: RegExp): string | null {
  const m = keyword.exec(text);
  if (!m) return null;
  let i = m.index + m[0].length - 1; // on the '('
  const open = i;
  let depth = 0;
  for (; i < text.length; i++) {
    if (text[i] === '(') depth++;
    else if (text[i] === ')' && --depth === 0) return text.slice(open + 1, i);
  }
  return null;
}

function isLiteralTrue(expr: string | null): boolean {
  if (expr == null) return false;
  let e = expr.replace(/\s+/g, '').toLowerCase();
  while (e.startsWith('(') && e.endsWith(')')) e = e.slice(1, -1);
  return e === 'true';
}

interface Loc {
  file: string;
  line: number;
}

interface TableState {
  rls: boolean;
  /** Where the table becomes unprotected (creation or `disable row level security`). */
  loc: Loc | null;
  /** API role → privileges revoked from it on this table. */
  revoked: Map<string, Set<string>>;
}

function newTable(rls: boolean, loc: Loc | null): TableState {
  return { rls, loc, revoked: new Map() };
}

/** True when neither anon nor authenticated keeps any privilege on the table. */
function isClosedToApi(t: TableState): boolean {
  return API_ROLES.every((r) => TABLE_PRIVILEGES.every((p) => t.revoked.get(r)?.has(p)));
}

interface OpenPolicy {
  table: string;
  policy: string;
  command: string;
  roles: string[];
  loc: Loc;
}

export function isSupabaseSql(rel: string): boolean {
  return /(^|\/)supabase\/.+\.sql$/i.test(rel);
}

export const supabaseRlsRule: Rule = {
  id: 'supabase-rls',
  run(ctx: ScanContext): Finding[] {
    const sqlFiles = ctx.files
      .filter((f) => !f.gitignored && isSupabaseSql(f.rel))
      .sort((a, b) => a.rel.localeCompare(b.rel));
    if (sqlFiles.length === 0) return [];

    const tables = new Map<string, TableState>();
    const policies = new Map<string, OpenPolicy>();

    for (const f of sqlFiles) replay(f, tables, policies);

    const findings: Finding[] = [];
    for (const [key, t] of tables) {
      if (t.rls || !t.loc) continue;
      if (!key.startsWith('public.')) continue;
      if (isClosedToApi(t)) continue;
      findings.push({
        ruleId: 'supabase-rls',
        severity: 'critical',
        messageId: 'supabase.noRls',
        params: { table: displayTable(key) },
        file: t.loc.file,
        line: t.loc.line,
      });
    }

    for (const p of policies.values()) {
      const t = tables.get(p.table);
      if (t && !t.rls && t.loc) continue; // the table itself is already reported
      const params = {
        table: displayTable(p.table),
        policy: p.policy,
        command: p.command.toUpperCase(),
        roles: p.roles.join(', '),
      };
      const base = { ruleId: 'supabase-rls', params, file: p.loc.file, line: p.loc.line };
      if (p.command === 'select') {
        findings.push({ ...base, severity: 'low', messageId: 'supabase.openReadPolicy' });
      } else if (p.command === 'insert') {
        findings.push({ ...base, severity: 'medium', messageId: 'supabase.openInsertPolicy' });
      } else {
        findings.push({ ...base, severity: 'high', messageId: 'supabase.openWritePolicy' });
      }
    }
    return findings;
  },
};

function replay(
  f: ScannedFile,
  tables: Map<string, TableState>,
  policies: Map<string, OpenPolicy>,
): void {
  for (const st of splitSql(f.content)) {
    const s = st.sql;
    const loc = (): Loc => ({ file: f.rel, line: lineOf(f.content, st.index) });
    let m: RegExpExecArray | null;

    if ((m = RE_CREATE_TABLE.exec(s))) {
      if (m[1]) continue; // temporary tables are not exposed by the API
      const key = tableKey(m[2] ?? '');
      const t = tables.get(key);
      if (t) t.loc ??= loc();
      else tables.set(key, newTable(false, loc()));
      continue;
    }

    if ((m = RE_ALTER_TABLE.exec(s))) {
      const key = tableKey(m[1] ?? '');
      const actions = m[2] ?? '';
      const rename = new RegExp(String.raw`^rename\s+to\s+(${ID})`, 'i').exec(actions.trim());
      if (rename) {
        const t = tables.get(key);
        const newKey = `${key.split('.')[0]}.${normalizeIdent(rename[1] ?? '')}`;
        if (t) {
          tables.delete(key);
          tables.set(newKey, t);
        }
        for (const [pk, p] of [...policies]) {
          if (p.table !== key) continue;
          policies.delete(pk);
          policies.set(`${newKey}|${p.policy}`, { ...p, table: newKey });
        }
        continue;
      }
      const rls = /\b(enable|disable)\s+row\s+level\s+security\b/i.exec(actions);
      if (!rls) continue;
      const enabled = rls[1]?.toLowerCase() === 'enable';
      const t = tables.get(key);
      if (t) {
        t.rls = enabled;
        if (!enabled) t.loc = loc();
      } else {
        tables.set(key, newTable(enabled, enabled ? null : loc()));
      }
      continue;
    }

    if ((m = RE_DROP_TABLE.exec(s))) {
      for (const key of splitQNames(m[1] ?? '')) {
        tables.delete(key);
        for (const [pk, p] of [...policies]) if (p.table === key) policies.delete(pk);
      }
      continue;
    }

    if ((m = RE_CREATE_POLICY.exec(s))) {
      const policy = normalizeIdent(m[1] ?? '');
      const table = tableKey(m[2] ?? '');
      const rest = m[3] ?? '';
      const pk = `${table}|${policy}`;
      policies.delete(pk);
      if (/\bas\s+restrictive\b/i.test(rest)) continue;
      const command = (/\bfor\s+(all|select|insert|update|delete)\b/i.exec(rest)?.[1] ?? 'all').toLowerCase();
      const rolesText = /\bto\s+([\s\S]+?)(?=\busing\b|\bwith\s+check\b|$)/i.exec(rest)?.[1];
      const roles = rolesText
        ? rolesText.split(',').map((r) => normalizeIdent(r.trim())).filter(Boolean)
        : ['public'];
      if (roles.every((r) => ADMIN_ROLES.has(r))) continue;
      const using = parenAfter(rest, /\busing\s*\(/i);
      const check = parenAfter(rest, /\bwith\s+check\s*\(/i);
      const open = command === 'insert' ? isLiteralTrue(check) : isLiteralTrue(using);
      if (open) policies.set(pk, { table, policy, command, roles, loc: loc() });
      continue;
    }

    if ((m = RE_DROP_OR_ALTER_POLICY.exec(s))) {
      // An altered policy may no longer be open: never guess, forget it.
      policies.delete(`${tableKey(m[2] ?? '')}|${normalizeIdent(m[1] ?? '')}`);
      continue;
    }

    if ((m = RE_GRANT_OR_REVOKE.exec(s))) {
      if (/^revoke\s+grant\s+option\s+for\b/i.test(s)) continue; // privileges stay
      const revoke = m[1]?.toLowerCase() === 'revoke';
      const privText = (m[2] ?? '').toLowerCase();
      const privileges = /\ball\b/.test(privText)
        ? [...TABLE_PRIVILEGES]
        : TABLE_PRIVILEGES.filter((p) => new RegExp(String.raw`\b${p}\b`).test(privText));
      const named = (m[4] ?? '')
        .split(',')
        .map((r) => normalizeIdent(r.trim().split(/\s+/)[0] ?? ''));
      // Granting to PUBLIC reopens access for everyone; revoking from PUBLIC
      // does not touch the privileges Supabase grants to anon / authenticated.
      const roles = API_ROLES.filter((r) => named.includes(r) || (!revoke && named.includes('public')));
      if (privileges.length === 0 || roles.length === 0) continue;

      const target = (m[3] ?? '').trim();
      const schema = new RegExp(String.raw`^all\s+tables\s+in\s+schema\s+(${ID})$`, 'i').exec(target);
      const keys = schema
        ? [...tables.keys()].filter((k) => k.startsWith(`${normalizeIdent(schema[1] ?? '')}.`))
        : splitQNames(target);
      for (const key of keys) {
        let t = tables.get(key);
        if (!t) tables.set(key, (t = newTable(false, null)));
        for (const role of roles) {
          let set = t.revoked.get(role);
          if (!set) t.revoked.set(role, (set = new Set()));
          for (const p of privileges) {
            if (revoke) set.add(p);
            else set.delete(p);
          }
        }
      }
    }
  }
}

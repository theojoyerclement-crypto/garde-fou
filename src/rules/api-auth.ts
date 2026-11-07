import { basenameOf, lineOf } from '../patterns';
import type { Finding, Rule, ScanContext, ScannedFile } from '../types';

/**
 * Server routes reachable by anyone that do something costly or privileged
 * without checking who is calling:
 *
 * - Next.js route handlers (`app/**\/route.ts`) and API routes (`pages/api/**`),
 * - Express routes (`app.post('/x', …)`),
 * - Supabase Edge Functions (`supabase/functions/<name>/index.ts`).
 *
 * A route is reported only when BOTH hold:
 * 1. it uses a privileged capability: Supabase service_role key, Firebase
 *    Admin SDK, database writes (Prisma, Drizzle, Mongo/Mongoose), or a paid
 *    AI API (OpenAI, Anthropic, Vercel AI SDK, Gemini, Mistral, Groq…);
 * 2. the file contains no authentication marker at all (session, getUser,
 *    Authorization header, JWT verification, webhook signature, shared secret…).
 *
 * Not reported (no false positives): routes whose path says they are meant to
 * be public (auth, login, signup, webhook, callback, cron, health), Next.js
 * projects with a middleware / proxy (it may enforce auth), Express apps that
 * mount an auth middleware with `.use(…)`, and anything with an auth marker.
 */

type Framework = 'Next.js' | 'Express' | 'Supabase Edge Function';

const CODE_FILE = /\.(?:[cm]?[jt]sx?)$/i;
const NEXT_APP_ROUTE = /(?:^|\/)app\/(?:(.+)\/)?route\.(?:[cm]?[jt]s)$/i;
const NEXT_PAGES_API = /(?:^|\/)pages\/(api(?:\/.+)?)\.(?:[cm]?[jt]sx?)$/i;
const EDGE_FUNCTION = /(?:^|\/)supabase\/functions\/([^/_][^/]*)\/index\.(?:[cm]?[jt]s)$/i;
/** `<app dir>/middleware.ts`, `<app dir>/src/proxy.ts`… → group 1 = app dir ('' or 'apps/web/'). */
const NEXT_MIDDLEWARE_ANYWHERE = /^((?:[^/]+\/)*?)(?:src\/)?(?:middleware|proxy)\.(?:[cm]?[jt]s)$/i;

/** Directory of the Next.js app a route file belongs to ('' or 'apps/web/'). */
export function nextAppDir(rel: string): string {
  const m = /^((?:[^/]+\/)*?)(?:src\/)?(?:app|pages)\//.exec(rel);
  return m?.[1] ?? '';
}

/** Directories holding a package.json, deepest first ('' = scan root). */
export function projectRoots(rels: readonly string[]): string[] {
  const dirs = rels
    .filter((r) => basenameOf(r) === 'package.json')
    .map((r) => r.slice(0, r.length - 'package.json'.length));
  return [...new Set(['', ...dirs])].sort((a, b) => b.length - a.length);
}

export function projectOf(rel: string, roots: readonly string[]): string {
  return roots.find((r) => rel.startsWith(r)) ?? '';
}

/** Path segments of routes that are public by design. */
const PUBLIC_BY_DESIGN =
  /(?:^|[/_.\-[(])(?:webhooks?|auth|login|logout|signin|signout|signup|sign-in|sign-out|sign-up|register|callback|oauth|cron|health|healthz|status|og)(?:$|[/_.\-\])])/i;

const AUTH_MARKER = new RegExp(
  [
    // `supabase.auth.admin.*` is the privileged admin API, not a check of the caller.
    String.raw`\bauth\b(?!\s*\.\s*admin\b)`,
    'getServerSession',
    'getSession',
    'getUser',
    'getClaims',
    'currentUser',
    'requireAuth',
    'requireUser',
    'withAuth',
    'isAuthenticated',
    'ensureAuth',
    'verifyIdToken',
    String.raw`jwt\.verify`,
    'jwtVerify',
    String.raw`\bjose\b`,
    'authorization',
    String.raw`\bbearer\b`,
    'x-api-key',
    String.raw`\bsession\b`,
    'clerk',
    'kinde',
    'passport',
    'next-auth',
    'lucia',
    'better-auth',
    String.raw`_SECRET\b`,
    String.raw`\bcookies\s*\(`,
    'constructEvent',
    'signature',
  ].join('|'),
  'i',
);

const PRIVILEGED = [
  /SERVICE_ROLE|service_role/,
  /['"](?:npm:)?firebase-admin(?:\/[\w-]+)?(?:@[^'"]*)?['"]/,
  /\bprisma\s*\.\s*\w+\s*\.\s*(?:create|createMany|update|updateMany|upsert|delete|deleteMany)\s*\(/,
  /\bdb\s*\.\s*(?:insert|update|delete)\s*\(/,
  /\.(?:insertOne|insertMany|updateOne|updateMany|deleteOne|deleteMany|findByIdAndUpdate|findByIdAndDelete|findOneAndUpdate|findOneAndDelete)\s*\(/,
];

const AI = [
  /['"](?:npm:|https:\/\/esm\.sh\/)?(?:openai|@anthropic-ai\/sdk|@ai-sdk\/[\w-]+|@google\/generative-ai|@google\/genai|groq-sdk|@mistralai\/mistralai|replicate|cohere-ai)(?:@[^'"/]*)?(?:\/[^'"]*)?['"]/,
  /\bapi\.openai\.com\b|\bapi\.anthropic\.com\b|\bgenerativelanguage\.googleapis\.com\b|\bopenrouter\.ai\/api\b|\bai\.gateway\.lovable\.dev\b|\bapi\.mistral\.ai\b|\bapi\.groq\.com\b/,
];

const EXPRESS_IMPORT = /(?:from\s+|require\s*\(\s*)['"](?:npm:)?express(?:@[^'"]*)?['"]/;
const EXPRESS_ROUTE =
  /\b(?:app|router|api|server|routes?)\s*\.\s*(?:get|post|put|patch|delete|all)\s*\(\s*(['"`])([^'"`]+)\1/g;
const EXPRESS_AUTH_USE = new RegExp(String.raw`\.use\s*\([^)\n]*(?:${AUTH_MARKER.source})`, 'i');

const NEXT_APP_HANDLER =
  /export\s+(?:async\s+)?(?:function\s+|const\s+|let\s+)(?:GET|POST|PUT|PATCH|DELETE)\b|export\s*\{[^}]*\bas\s+(?:GET|POST|PUT|PATCH|DELETE)\b/;
const DEFAULT_EXPORT = /export\s+default\b/;
const EDGE_SERVE = /\b(?:Deno\.)?serve\s*\(/;

/** Removes // and /* *\/ comments, keeping strings (and offsets) intact. */
export function stripJsComments(src: string): string {
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
    } else if (ch === '"' || ch === "'" || ch === '`') {
      let j = i + 1;
      while (j < src.length && src[j] !== ch && (ch === '`' || src[j] !== '\n')) j += src[j] === '\\' ? 2 : 1;
      i = j + 1;
    } else {
      i++;
    }
  }
  return chars.join('');
}

interface Route {
  framework: Framework;
  route: string;
  /** Offset of the handler (export, serve call or first route registration). */
  index: number;
}

function nextAppRoute(rel: string, code: string): Route | null {
  const m = NEXT_APP_ROUTE.exec(rel);
  if (!m) return null;
  const h = NEXT_APP_HANDLER.exec(code);
  if (!h) return null;
  const segs = (m[1] ?? '').split('/').filter((s) => s && !/^\(.*\)$/.test(s) && !s.startsWith('@'));
  return { framework: 'Next.js', route: `/${segs.join('/')}`, index: h.index };
}

function nextPagesRoute(rel: string, code: string): Route | null {
  const m = NEXT_PAGES_API.exec(rel);
  if (!m) return null;
  const h = DEFAULT_EXPORT.exec(code);
  if (!h) return null;
  return { framework: 'Next.js', route: `/${(m[1] ?? '').replace(/\/index$/, '')}`, index: h.index };
}

function edgeRoute(rel: string, code: string): Route | null {
  const m = EDGE_FUNCTION.exec(rel);
  if (!m) return null;
  const h = EDGE_SERVE.exec(code);
  return { framework: 'Supabase Edge Function', route: `/functions/v1/${m[1] ?? ''}`, index: h?.index ?? 0 };
}

function expressRoute(code: string): Route | null {
  if (!EXPRESS_IMPORT.test(code)) return null;
  const m = new RegExp(EXPRESS_ROUTE.source).exec(code);
  if (!m) return null;
  return { framework: 'Express', route: m[2] ?? '', index: m.index };
}

export const apiAuthRule: Rule = {
  id: 'api-auth',
  run(ctx: ScanContext): Finding[] {
    const code = new Map<ScannedFile, string>();
    const codeOf = (f: ScannedFile) => {
      let c = code.get(f);
      if (c === undefined) code.set(f, (c = stripJsComments(f.content)));
      return c;
    };
    const sources = ctx.files.filter((f) => !f.gitignored && CODE_FILE.test(basenameOf(f.rel)));

    // Middlewares only protect their own app: a scan may cover several projects
    // (monorepo, parent folder), so everything is scoped by directory.
    const projects = projectRoots(ctx.files.map((f) => f.rel));
    const middlewareDirs = new Set<string>();
    const expressAuthProjects = new Set<string>();
    for (const f of sources) {
      const mw = NEXT_MIDDLEWARE_ANYWHERE.exec(f.rel);
      if (mw) middlewareDirs.add(mw[1] ?? '');
      if (/\.use\s*\(/.test(f.content) && EXPRESS_AUTH_USE.test(codeOf(f))) {
        expressAuthProjects.add(projectOf(f.rel, projects));
      }
    }

    const findings: Finding[] = [];
    for (const f of sources) {
      if (/(?:^|\/)(?:test|tests|__tests__|e2e)\//.test(f.rel) || /\.(?:test|spec)\./.test(f.rel)) continue;
      const c = codeOf(f);

      const route =
        nextAppRoute(f.rel, c) ??
        nextPagesRoute(f.rel, c) ??
        edgeRoute(f.rel, c) ??
        (NEXT_APP_ROUTE.test(f.rel) || NEXT_PAGES_API.test(f.rel) ? null : expressRoute(c));
      if (!route) continue;
      if (route.framework === 'Next.js' && middlewareDirs.has(nextAppDir(f.rel))) continue;
      if (route.framework === 'Express' && expressAuthProjects.has(projectOf(f.rel, projects))) continue;
      // Public by design: judged on the route and the file name, never on the
      // folders above (a project folder named "api-auth" says nothing).
      if (PUBLIC_BY_DESIGN.test(route.route) || PUBLIC_BY_DESIGN.test(basenameOf(f.rel))) continue;
      if (AUTH_MARKER.test(c)) continue;

      const privileged = PRIVILEGED.some((re) => re.test(c));
      const ai = !privileged && AI.some((re) => re.test(c));
      if (!privileged && !ai) continue;

      findings.push({
        ruleId: 'api-auth',
        severity: 'high',
        messageId: privileged ? 'api.noAuthPrivileged' : 'api.noAuthAI',
        params: { framework: route.framework, route: route.route },
        file: f.rel,
        line: lineOf(f.content, route.index),
      });
    }
    return findings;
  },
};

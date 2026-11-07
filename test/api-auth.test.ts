import { cpSync } from 'node:fs';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { audit, cleanupTempDirs, copyNamedFixture, fixturesDir, makeTempDir, writeFiles } from './helpers';

afterAll(cleanupTempDirs);

async function findingsFor(files: Record<string, string>) {
  const root = makeTempDir();
  writeFiles(root, files);
  return (await audit(root)).findings.filter((f) => f.ruleId === 'api-auth');
}

const AI_ROUTE = "import OpenAI from 'openai';\nexport async function POST() { return Response.json(await new OpenAI().models.list()); }\n";
const ADMIN_ROUTE =
  "const k = process.env.SUPABASE_SERVICE_ROLE_KEY;\nexport async function POST() { return new Response(k ? 'x' : 'y'); }\n";

describe('fixtures/api-auth', () => {
  it('reports unauthenticated privileged and AI routes for Next.js, Express and Edge Functions', async () => {
    const result = await audit(copyNamedFixture('api-auth'));
    const got = result.findings.map((f) => `${f.messageId} ${f.params.framework} ${f.params.route} @ ${f.file}:${f.line}`);
    expect(got.sort()).toEqual(
      [
        'api.noAuthAI Express /api/summarize @ server/index.js:8',
        'api.noAuthAI Next.js /api/chat @ app/api/chat/route.ts:6',
        'api.noAuthAI Next.js /api/generate @ pages/api/generate.ts:6',
        'api.noAuthPrivileged Next.js /api/admin/delete-user @ app/api/admin/delete-user/route.ts:6',
        'api.noAuthPrivileged Next.js /api/notes @ app/(dashboard)/api/notes/route.ts:3',
        'api.noAuthPrivileged Supabase Edge Function /functions/v1/delete-account @ supabase/functions/delete-account/index.ts:3',
      ].sort(),
    );
    for (const f of result.findings) expect(f.severity).toBe('high');
  });
});

describe('api-auth false positives', () => {
  it('ignores routes with an auth check', async () => {
    const checks = [
      "import { auth } from '@/auth';\nconst s = await auth();",
      'const { data } = await supabase.auth.getUser(token);',
      "const h = req.headers.get('authorization');",
      'const session = await getServerSession(authOptions);',
      "if (req.headers.get('x-cron-key') !== process.env.CRON_SECRET) throw 1;",
      "import { currentUser } from '@clerk/nextjs/server';",
    ];
    for (const check of checks) {
      expect(await findingsFor({ 'app/api/x/route.ts': `${check}\n${AI_ROUTE}` })).toEqual([]);
    }
  });

  it('ignores routes that are public by design', async () => {
    for (const p of ['webhook', 'stripe-webhook', 'auth/[...nextauth]', 'login', 'sign-up', 'cron/cleanup', 'og']) {
      expect(await findingsFor({ [`app/api/${p}/route.ts`]: ADMIN_ROUTE })).toEqual([]);
    }
  });

  it('ignores routes without a privileged capability (anon client, reads, plain logic)', async () => {
    expect(
      await findingsFor({
        'app/api/products/route.ts':
          "const s = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY);\nexport async function POST() { await s.from('w').insert({}); return new Response(); }",
        'app/api/list/route.ts': 'export async function GET() { return Response.json(await prisma.user.findMany()); }',
        'pages/api/hello.ts': "export default function h(req, res) { res.json({ ok: true }); }",
      }),
    ).toEqual([]);
  });

  it('does not count comments as code, nor as auth', async () => {
    expect(await findingsFor({ 'app/api/x/route.ts': "// import OpenAI from 'openai'\nexport async function POST() {}" })).toEqual([]);
    const flagged = await findingsFor({ 'app/api/x/route.ts': `// TODO: check auth and session\n${AI_ROUTE}` });
    expect(flagged).toHaveLength(1);
  });

  it('trusts a Next.js middleware / proxy and Express auth middleware', async () => {
    expect(await findingsFor({ 'middleware.ts': 'export function middleware() {}', 'app/api/x/route.ts': AI_ROUTE })).toEqual([]);
    expect(await findingsFor({ 'src/proxy.ts': 'export function proxy() {}', 'src/app/api/x/route.ts': AI_ROUTE })).toEqual([]);
    expect(
      await findingsFor({
        'server/app.js': "const express = require('express');\napp.use(passport.authenticate('jwt'));",
        'server/ai.js':
          "const express = require('express');\nconst OpenAI = require('openai');\nrouter.post('/ask', async (req, res) => res.json(await new OpenAI().models.list()));",
      }),
    ).toEqual([]);
  });

  it('ignores non-route files, tests and shared edge helpers', async () => {
    expect(
      await findingsFor({
        'src/lib/ai.ts': AI_ROUTE,
        'app/api/x/route.test.ts': AI_ROUTE,
        'supabase/functions/_shared/admin.ts': ADMIN_ROUTE,
        'scripts/seed.js': "const express = require('express');\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY;",
      }),
    ).toEqual([]);
  });
});

describe('api-auth when several projects are scanned at once', () => {
  it('detects its fixture when the whole fixtures/ folder is scanned', async () => {
    const parent = makeTempDir();
    for (const n of ['api-auth', 'clean-app', 'supabase-rls', 'firebase', 'dependencies']) {
      cpSync(path.join(fixturesDir, n), path.join(parent, n), { recursive: true });
    }
    const found = (await audit(parent)).findings.filter((f) => f.ruleId === 'api-auth');
    expect(found).toHaveLength(6);
    for (const f of found) expect(f.file?.startsWith('api-auth/')).toBe(true);
  });

  it('judges "public by design" on the route and file name, not on parent folders', async () => {
    const flagged = await findingsFor({
      'auth-service/app/api/chat/route.ts': AI_ROUTE,
      'packages/webhooks-ui/app/api/ask/route.ts': AI_ROUTE,
    });
    expect(flagged.map((f) => f.file).sort()).toEqual([
      'auth-service/app/api/chat/route.ts',
      'packages/webhooks-ui/app/api/ask/route.ts',
    ]);
    expect(await findingsFor({ 'pages/api/stripe-webhook.ts': "import OpenAI from 'openai';\nexport default async function h() { await new OpenAI().models.list(); }" })).toEqual([]);
  });

  it('a Next.js middleware only protects its own app', async () => {
    const found = await findingsFor({
      'apps/a/middleware.ts': 'export function middleware() {}',
      'apps/a/app/api/x/route.ts': AI_ROUTE,
      'apps/b/app/api/x/route.ts': AI_ROUTE,
      'apps/c/src/middleware.ts': 'export function middleware() {}',
      'apps/c/src/app/api/x/route.ts': AI_ROUTE,
    });
    expect(found.map((f) => f.file)).toEqual(['apps/b/app/api/x/route.ts']);
  });

  it('an Express auth middleware only protects its own project', async () => {
    const route =
      "const express = require('express');\nconst OpenAI = require('openai');\nrouter.post('/ask', async (req, res) => res.json(await new OpenAI().models.list()));";
    const found = await findingsFor({
      'svc-a/package.json': '{}',
      'svc-a/app.js': "const express = require('express');\napp.use(requireAuth);",
      'svc-a/routes.js': route,
      'svc-b/package.json': '{}',
      'svc-b/routes.js': route,
    });
    expect(found.map((f) => f.file)).toEqual(['svc-b/routes.js']);
  });
});

/**
 * `gardefou mcp` (`npx @gardefou/cli mcp`): Model Context Protocol server over stdio (newline-delimited
 * JSON-RPC 2.0), so an AI agent (Claude Code, Cursor…) can run the audit.
 *
 * Read-only by construction: it calls runAudit() (the same scanner as the CLI)
 * and the localized messages, nothing that writes files. No --ai, no
 * --supabase-live (they need an explicit human decision). stdout carries the
 * protocol only.
 */
import { existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { createInterface } from 'node:readline';
import type { Readable, Writable } from 'node:stream';
import { runAudit, type AuditOptions, type AuditResult } from './audit';
import { detectLang, isLang, messages, type Lang } from './i18n';
import { countBySeverity, ignoredSummary, localizeFinding } from './report';
import type { Finding, MessageId } from './types';
import { VERSION } from './version';

export const MCP_PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'] as const;

export interface McpDeps {
  audit?: (dir: string, opts: AuditOptions) => Promise<AuditResult>;
  /** Default language when a call gives none. */
  lang?: Lang;
}

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };
interface JsonRpcRequest {
  jsonrpc?: unknown;
  id?: unknown;
  method?: unknown;
  params?: unknown;
}

const LANG_SCHEMA = { type: 'string', enum: ['fr', 'en'], description: 'Language of the texts (fr / en).' };

export const MCP_TOOLS = [
  {
    name: 'scan_project',
    description:
      'Audits a local project for typical AI-generated security mistakes (exposed API keys, committed .env, Supabase without RLS, open Firebase rules, unauthenticated API routes, vulnerable dependencies). Read-only: never modifies files. Returns the findings (secrets masked) and a score out of 100.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Directory to audit (absolute, or relative to the server working directory).' },
        lang: LANG_SCHEMA,
        history: { type: 'boolean', description: 'Also scan the git history (default true).' },
        offline: { type: 'boolean', description: 'No network: skip the OSV dependency check (default false).' },
      },
      required: ['path'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: 'explain_finding',
    description:
      'Explains one finding returned by scan_project: plain-language risk, fix, and a ready-to-paste fix prompt. Pass the finding (messageId, params, file, line) as returned.',
    inputSchema: {
      type: 'object',
      properties: {
        messageId: { type: 'string', description: 'messageId of the finding.' },
        params: { type: 'object', additionalProperties: { type: 'string' }, description: 'params of the finding.' },
        file: { type: 'string' },
        line: { type: 'integer' },
        lang: LANG_SCHEMA,
      },
      required: ['messageId'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
] as const;

class ToolInputError extends Error {}

function obj(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function langOf(v: unknown, fallback: Lang): Lang {
  if (v === undefined) return fallback;
  if (typeof v === 'string' && isLang(v)) return v;
  throw new ToolInputError('lang must be "fr" or "en"');
}

function textResult(data: Json): Json {
  return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }], structuredContent: data };
}

function errorResult(message: string): Json {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function findingJson(f: Finding, lang: Lang): Json {
  const t = localizeFinding(f, lang);
  return {
    ruleId: f.ruleId,
    severity: f.severity,
    messageId: f.messageId,
    params: f.params,
    ...(f.file !== undefined ? { file: f.file } : {}),
    ...(f.line !== undefined ? { line: f.line } : {}),
    ...(f.commit !== undefined ? { commit: f.commit } : {}),
    title: t.title,
    why: t.why,
    fix: t.fix,
    prompt: t.prompt,
  };
}

export function createMcpHandler(deps: McpDeps = {}) {
  const audit = deps.audit ?? runAudit;
  const defaultLang = deps.lang ?? detectLang();

  async function scanProject(args: Record<string, unknown>): Promise<Json> {
    const lang = langOf(args.lang, defaultLang);
    if (typeof args.path !== 'string' || args.path.trim() === '') throw new ToolInputError('path is required');
    for (const k of ['history', 'offline'] as const) {
      if (args[k] !== undefined && typeof args[k] !== 'boolean') throw new ToolInputError(`${k} must be a boolean`);
    }
    const dir = path.resolve(args.path);
    if (!existsSync(dir) || !statSync(dir).isDirectory()) return errorResult(messages(lang).ui.targetNotFound(args.path));
    const result = await audit(dir, {
      history: (args.history as boolean | undefined) ?? true,
      offline: (args.offline as boolean | undefined) ?? false,
    });
    const m = messages(lang);
    return textResult({
      target: result.root,
      score: result.score,
      verdict: m.ui.verdict(result.score),
      counts: countBySeverity(result.findings),
      filesScanned: result.filesScanned,
      notes: result.notes.map((n) => m.ui.notes[n]),
      ignoredDependencies: ignoredSummary(result, lang, true) ?? '',
      findings: result.findings.map((f) => findingJson(f, lang)),
    });
  }

  function explainFinding(args: Record<string, unknown>): Json {
    const lang = langOf(args.lang, defaultLang);
    const id = args.messageId;
    if (typeof id !== 'string' || !Object.hasOwn(messages(lang).findings, id)) {
      throw new ToolInputError('unknown messageId (use one returned by scan_project)');
    }
    const params: Record<string, string> = {};
    for (const [k, v] of Object.entries(obj(args.params))) {
      if (typeof v === 'string' || typeof v === 'number') params[k] = String(v);
    }
    const f: Finding = {
      ruleId: 'mcp',
      severity: 'low',
      messageId: id as MessageId,
      params,
      ...(typeof args.file === 'string' ? { file: args.file } : {}),
      ...(Number.isInteger(args.line) ? { line: args.line as number } : {}),
    };
    const t = localizeFinding(f, lang);
    return textResult({ messageId: id, title: t.title, why: t.why, fix: t.fix, prompt: t.prompt });
  }

  /** One JSON-RPC message in, the response out (null for notifications). */
  return async function handle(msg: unknown): Promise<Json | null> {
    const req = obj(msg) as JsonRpcRequest;
    const isNotification = !('id' in obj(msg));
    const id = (typeof req.id === 'string' || typeof req.id === 'number' ? req.id : null) as Json;
    const reply = (result: Json): Json => ({ jsonrpc: '2.0', id, result });
    const fail = (code: number, message: string): Json => ({ jsonrpc: '2.0', id, error: { code, message } });

    if (req.jsonrpc !== '2.0' || typeof req.method !== 'string') return isNotification ? null : fail(-32600, 'Invalid Request');
    if (isNotification) return null; // notifications/initialized, cancelled…

    const params = obj(req.params);
    switch (req.method) {
      case 'initialize': {
        const asked = params.protocolVersion;
        const version = (MCP_PROTOCOL_VERSIONS as readonly unknown[]).includes(asked) ? asked : MCP_PROTOCOL_VERSIONS[0];
        return reply({
          protocolVersion: version as string,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: 'gardefou', version: VERSION },
          instructions:
            'Garde-Fou audits a local project for security mistakes. Call scan_project with a directory, then explain_finding on a finding to get its fix prompt. Read-only.',
        });
      }
      case 'ping':
        return reply({});
      case 'tools/list':
        return reply({ tools: MCP_TOOLS as unknown as Json });
      case 'tools/call': {
        const name = params.name;
        const args = obj(params.arguments);
        try {
          if (name === 'scan_project') return reply(await scanProject(args));
          if (name === 'explain_finding') return reply(explainFinding(args));
          return fail(-32602, `Unknown tool: ${String(name)}`);
        } catch (err) {
          if (err instanceof ToolInputError) return reply(errorResult(err.message));
          return reply(errorResult('Garde-Fou failed on this project.'));
        }
      }
      default:
        return fail(-32601, 'Method not found');
    }
  };
}

/** Serves MCP on a stream pair until the input ends. */
export async function serveMcp(input: Readable, output: Writable, deps: McpDeps = {}): Promise<void> {
  const handle = createMcpHandler(deps);
  const rl = createInterface({ input, crlfDelay: Number.POSITIVE_INFINITY });
  const pending: Promise<void>[] = [];
  for await (const line of rl) {
    if (line.trim() === '') continue;
    pending.push(
      (async () => {
        let msg: unknown;
        try {
          msg = JSON.parse(line);
        } catch {
          output.write(`${JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } })}\n`);
          return;
        }
        const res = await handle(msg);
        if (res !== null) output.write(`${JSON.stringify(res)}\n`);
      })(),
    );
  }
  await Promise.all(pending);
}

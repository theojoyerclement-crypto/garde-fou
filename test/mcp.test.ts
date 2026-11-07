import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { afterAll, describe, expect, it } from 'vitest';
import { fakeOpenAIKey } from '../scripts/fake-keys';
import { maskSecret } from '../src/patterns';
import { MCP_TOOLS, createMcpHandler, serveMcp } from '../src/mcp';
import { audit, cleanupTempDirs, copyNamedFixture, makeTempDir, writeFiles } from './helpers';

afterAll(cleanupTempDirs);

/** Offline audit: tests never touch the network. */
const handle = createMcpHandler({ audit: (dir, opts) => audit(dir, { ...opts, offline: true }), lang: 'en' });

const call = (id: number, name: string, args: Record<string, unknown>) =>
  handle({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });

function treeHash(dir: string): string {
  const h = createHash('sha256');
  const walk = (d: string) => {
    for (const name of readdirSync(d).sort()) {
      const abs = path.join(d, name);
      h.update(path.relative(dir, abs));
      if (statSync(abs).isDirectory()) walk(abs);
      else h.update(readFileSync(abs));
    }
  };
  walk(dir);
  return h.digest('hex');
}

type ToolResult = { content: { type: string; text: string }[]; structuredContent?: Record<string, unknown>; isError?: boolean };
const resultOf = (res: unknown) => (res as { result: ToolResult }).result;

describe('MCP server', () => {
  it('initializes, negotiates the protocol version and lists two read-only tools', async () => {
    const init = await handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26' } });
    expect(init).toMatchObject({
      id: 1,
      result: { protocolVersion: '2025-03-26', capabilities: { tools: {} }, serverInfo: { name: 'gardefou' } },
    });
    const unknown = await handle({ jsonrpc: '2.0', id: 2, method: 'initialize', params: { protocolVersion: '1999-01-01' } });
    expect(unknown).toMatchObject({ result: { protocolVersion: '2025-06-18' } });
    expect(await handle({ jsonrpc: '2.0', method: 'notifications/initialized' })).toBeNull();

    const list = (await handle({ jsonrpc: '2.0', id: 3, method: 'tools/list' })) as unknown as { result: { tools: typeof MCP_TOOLS } };
    expect(list.result.tools.map((t) => t.name)).toEqual(['scan_project', 'explain_finding']);
    for (const t of list.result.tools) expect(t.annotations.readOnlyHint).toBe(true);
  });

  it('scan_project returns findings and score, secrets masked, without modifying the project', async () => {
    const root = copyNamedFixture('supabase-rls');
    const key = fakeOpenAIKey();
    writeFiles(root, { 'lib/ai.ts': `export const client = new OpenAI({ apiKey: "${key}" });\n` });
    const before = treeHash(root);

    const res = resultOf(await call(4, 'scan_project', { path: root, history: false }));
    expect(res.isError).toBeUndefined();
    const data = res.structuredContent as { score: number; counts: Record<string, number>; findings: Record<string, unknown>[] };
    expect(JSON.parse(res.content[0]?.text ?? '{}')).toEqual(data);
    expect(data.score).toBeLessThan(100);
    expect(data.counts.critical).toBeGreaterThan(0);
    const secret = data.findings.find((f) => f.messageId === 'secret.file');
    expect(secret).toMatchObject({ severity: 'critical', file: 'lib/ai.ts', line: 1 });
    expect(secret?.title).toContain(maskSecret(key));
    expect(typeof secret?.prompt).toBe('string');
    expect(JSON.stringify(res)).not.toContain(key);
    expect(treeHash(root)).toBe(before);
  });

  it('explain_finding gives the localized texts of a finding returned by scan_project', async () => {
    const scan = resultOf(await call(5, 'scan_project', { path: copyNamedFixture('firebase'), history: false, lang: 'fr' }));
    const f = (scan.structuredContent as { findings: { messageId: string; params: Record<string, string>; file: string; line: number; title: string }[] }).findings[0];
    if (!f) throw new Error('no finding');
    const res = resultOf(await call(6, 'explain_finding', { messageId: f.messageId, params: f.params, file: f.file, line: f.line, lang: 'fr' }));
    expect(res.structuredContent).toMatchObject({ messageId: f.messageId, title: f.title });
    expect(Object.keys(res.structuredContent ?? {})).toEqual(['messageId', 'title', 'why', 'fix', 'prompt']);
  });

  it('reports bad input as tool errors, unknown methods as JSON-RPC errors', async () => {
    expect(resultOf(await call(7, 'scan_project', { path: path.join(makeTempDir(), 'missing') }))).toMatchObject({ isError: true });
    expect(resultOf(await call(8, 'scan_project', {}))).toMatchObject({ isError: true });
    expect(resultOf(await call(9, 'scan_project', { path: '.', lang: 'de' }))).toMatchObject({ isError: true });
    expect(resultOf(await call(10, 'explain_finding', { messageId: '__proto__' }))).toMatchObject({ isError: true });
    expect(await call(11, 'write_file', {})).toMatchObject({ error: { code: -32602 } });
    expect(await handle({ jsonrpc: '2.0', id: 12, method: 'resources/list' })).toMatchObject({ error: { code: -32601 } });
    expect(await handle({ id: 13, method: 'ping' })).toMatchObject({ error: { code: -32600 } });
    expect(await handle({ jsonrpc: '2.0', id: 14, method: 'ping' })).toEqual({ jsonrpc: '2.0', id: 14, result: {} });
  });

  it('speaks newline-delimited JSON-RPC over streams, stdout carries responses only', async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    const chunks: string[] = [];
    output.on('data', (c: Buffer) => chunks.push(c.toString('utf8')));
    const done = serveMcp(input, output, { audit: (dir, opts) => audit(dir, { ...opts, offline: true }), lang: 'en' });
    input.write('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}\n');
    input.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n');
    input.write('not json\n');
    input.write(`${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'scan_project', arguments: { path: copyNamedFixture('clean-app'), history: false } } })}\n`);
    input.end();
    await done;
    const lines = chunks.join('').trim().split('\n').map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(lines).toHaveLength(3);
    expect(lines.find((l) => l.id === 1)).toMatchObject({ result: { serverInfo: { name: 'gardefou' } } });
    expect(lines.find((l) => l.id === null)).toMatchObject({ error: { code: -32700 } });
    expect(lines.find((l) => l.id === 2)).toMatchObject({ result: { structuredContent: { score: 100, findings: [] } } });
  });
});

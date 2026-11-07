import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { fakeOpenAIKey } from '../scripts/fake-keys';
import { maskSecret } from '../src/patterns';
import { renderMarkdownSummary, exceedsFailOn } from '../src/ci';
import { audit, cleanupTempDirs, copyNamedFixture, makeTempDir, repoRoot, writeFiles } from './helpers';

afterAll(cleanupTempDirs);

const ACTION = readFileSync(path.join(repoRoot, 'action.yml'), 'utf8');

/** `run: |` blocks of action.yml, by step name (tiny parser: enough for this file). */
function runBlocks(yml: string): Map<string, string> {
  const lines = yml.split(/\r?\n/);
  const out = new Map<string, string>();
  let step = '';
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    const name = /^\s*- name:\s*(.+)$/.exec(line);
    if (name?.[1]) step = name[1].trim();
    const run = /^(\s*)run: \|\s*$/.exec(line);
    if (!run) continue;
    const indent = (run[1] ?? '').length;
    const body: string[] = [];
    for (i++; i < lines.length; i++) {
      const l = lines[i] ?? '';
      if (l.trim() !== '' && l.length - l.trimStart().length <= indent) break;
      body.push(l.slice(indent + 2));
    }
    i--;
    out.set(step, body.join('\n'));
  }
  return out;
}

function findBash(): string | null {
  if (process.platform !== 'win32') return 'bash';
  const git = 'C:\\Program Files\\Git\\bin\\bash.exe';
  return existsSync(git) ? git : null;
}

const posix = (p: string) => p.replace(/\\/g, '/');

/** Runs the real "Scan" step of action.yml with GitHub's env, the CLI loaded from src/ through tsx. */
function simulateScan(inputs: { path: string; failOn?: string; lang?: string }) {
  const bash = findBash();
  if (!bash) throw new Error('bash not found');
  const temp = makeTempDir();
  const shim = path.join(temp, 'cli-shim.mjs');
  const tsxApi = createRequire(path.join(repoRoot, 'package.json')).resolve('tsx/esm/api');
  writeFileSync(
    shim,
    `import { register } from ${JSON.stringify(pathToFileURL(tsxApi).href)};\nregister();\nawait import(${JSON.stringify(pathToFileURL(path.join(repoRoot, 'src', 'cli.ts')).href)});\n`,
  );
  const summary = path.join(temp, 'step-summary.md');
  const output = path.join(temp, 'github-output');
  writeFileSync(summary, '');
  writeFileSync(output, '');
  const res = spawnSync(bash, ['-c', runBlocks(ACTION).get('Scan') ?? 'exit 99'], {
    encoding: 'utf8',
    env: {
      ...process.env,
      RUNNER_TEMP: posix(temp),
      GITHUB_STEP_SUMMARY: posix(summary),
      GITHUB_OUTPUT: posix(output),
      GF_PATH: posix(inputs.path),
      GF_FAIL_ON: inputs.failOn ?? 'critical',
      GF_LANG: inputs.lang ?? 'en',
      GF_OFFLINE: 'true',
      GF_HISTORY: 'false',
      GF_CLI: posix(shim),
    },
  });
  const outputs = Object.fromEntries(
    readFileSync(output, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((l) => l.split('=') as [string, string]),
  );
  return { res, log: `${res.stdout}\n${res.stderr}`, summary: readFileSync(summary, 'utf8'), outputs, temp };
}

function vulnerableProject() {
  const root = makeTempDir();
  const key = fakeOpenAIKey();
  writeFiles(root, {
    'lib/ai.ts': `export const openai = new OpenAI({ apiKey: "${key}" });\n`,
    'supabase/migrations/001.sql': 'create table public.notes (id int);\n',
  });
  return { root, key };
}

const canRun = findBash() !== null;

describe('action.yml', () => {
  it('declares the inputs, fails on critical by default, never interpolates inputs into scripts', () => {
    expect(ACTION).toMatch(/fail-on:\n\s+description:[^\n]*\n\s+default: critical/);
    for (const input of ['path', 'fail-on', 'lang', 'offline', 'history', 'report-name']) expect(ACTION).toContain(`  ${input}:`);
    for (const [step, body] of runBlocks(ACTION)) expect(body, step).not.toContain('${{');
    expect(ACTION).toContain('actions/upload-artifact@v4');
  });

  it.skipIf(!canRun)('fails the job on a critical problem, summary without secret, HTML report kept', () => {
    const { root, key } = vulnerableProject();
    const run = simulateScan({ path: root });
    expect(run.res.status).toBe(0); // the step itself succeeds; "Apply fail-on" reads exit-code
    expect(run.outputs['exit-code']).toBe('1');
    expect(Number(run.outputs.score)).toBeLessThan(100);
    expect(run.summary).toContain('## Garde-Fou — ');
    expect(run.summary).toContain('| Severity | Problem | Location |');
    expect(run.summary).toContain('lib/ai.ts:1');
    expect(run.summary).toContain('Failed: at least one problem of severity "CRITICAL" or above.');
    // Nothing of the key in the logs or the summary, not even its masked form.
    for (const text of [run.log, run.summary]) {
      expect(text).not.toContain(key);
      expect(text).not.toContain(maskSecret(key));
      expect(text).not.toContain(key.slice(-4));
    }
    // The HTML artifact is written (masked keys only); the JSON with findings is removed.
    const html = readFileSync(path.join(run.temp, 'garde-fou-report.html'), 'utf8');
    expect(html).not.toContain(key);
    expect(existsSync(path.join(run.temp, 'garde-fou.json'))).toBe(false);
  }, 60_000);

  it.skipIf(!canRun)('passes below the threshold, and with fail-on none', () => {
    const clean = simulateScan({ path: copyNamedFixture('clean-app') });
    expect(clean.outputs['exit-code']).toBe('0');
    expect(clean.summary).toContain('No issues found.');
    const { root } = vulnerableProject();
    expect(simulateScan({ path: root, failOn: 'none' }).outputs['exit-code']).toBe('0');
  }, 60_000);

  it.skipIf(!canRun)('reports a missing directory as an error (exit code 2)', () => {
    const run = simulateScan({ path: path.join(makeTempDir(), 'missing') });
    expect(run.outputs['exit-code']).toBe('2');
    expect(run.log).toContain('::error title=Garde-Fou::');
  }, 60_000);
});

describe('Markdown summary and fail-on', () => {
  it('neutralises Markdown / HTML in titles and paths', async () => {
    const root = makeTempDir();
    writeFiles(root, { 'supabase/migrations/001.sql': 'create table public."a|<img src=x>" (id int);\n' });
    const md = renderMarkdownSummary(await audit(root), 'en');
    expect(md).not.toContain('<img');
    expect(md).toContain('&lt;img src=x&gt;');
    expect(md).toContain('a\\|');
  });

  it('compares severities', () => {
    const f = (severity: 'critical' | 'high' | 'medium' | 'low') => ({ ruleId: 'x', severity, messageId: 'env.tracked' as const, params: {} });
    expect(exceedsFailOn([f('high')], 'critical')).toBe(false);
    expect(exceedsFailOn([f('high')], 'high')).toBe(true);
    expect(exceedsFailOn([f('low')], 'medium')).toBe(false);
    expect(exceedsFailOn([f('critical')], 'none')).toBe(false);
  });
});

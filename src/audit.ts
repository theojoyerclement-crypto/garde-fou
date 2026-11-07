import { existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { readGitInfo } from './git';
import { createOsvClient } from './osv';
import { computeScore, sortFindings } from './report';
import { rules as defaultRules } from './rules';
import { scanFiles } from './scanner';
import { checkSupabaseLive, createSupabaseLiveClient, resolveTarget, type SupabaseLiveClient } from './supabase-live';
import type { Finding, IgnoredDep, NoteId, OsvClient, Rule, ScanContext } from './types';

export interface AuditOptions {
  /** Scan the git history too (default: true). */
  history?: boolean;
  /** No network at all: dependencies are not checked against OSV (default: false). */
  offline?: boolean;
  /** OSV client to use (tests inject a fake one). */
  osv?: OsvClient;
  rules?: readonly Rule[];
  /** --supabase-live: read-only test against the real project (never with `offline`). */
  supabaseLive?: SupabaseLiveOptions;
}

export interface SupabaseLiveOptions {
  client?: SupabaseLiveClient;
  /** User-given URL / anon key; the rest is looked up in the project. */
  url?: string;
  key?: string;
  /** Asked once the target is known; nothing is sent before it returns true. */
  confirm: (info: { host: string }) => Promise<boolean>;
}

export interface AuditResult {
  /** Target as given by the user (for display). */
  target: string;
  root: string;
  filesScanned: number;
  gitAvailable: boolean;
  historyScanned: boolean;
  notes: NoteId[];
  /** Dependencies left out of the findings (build tools, dev…), with their advisories. */
  ignoredDeps: IgnoredDep[];
  findings: Finding[];
  score: number;
}

export class TargetNotFoundError extends Error {
  constructor(public readonly target: string) {
    super(`Directory not found: ${target}`);
  }
}

export async function runAudit(target: string, opts: AuditOptions = {}): Promise<AuditResult> {
  const root = path.resolve(target);
  if (!existsSync(root) || !statSync(root).isDirectory()) throw new TargetNotFoundError(target);

  const history = opts.history ?? true;
  const files = scanFiles(root);
  const git = readGitInfo(root, { history });
  const ctx: ScanContext = {
    root,
    files,
    git,
    osv: opts.offline ? null : (opts.osv ?? createOsvClient()),
    notes: new Set(),
    ignoredDeps: [],
  };

  const perRule = await Promise.all((opts.rules ?? defaultRules).map((r) => r.run(ctx)));
  const all = perRule.flat();
  if (opts.supabaseLive && !opts.offline) all.push(...(await runSupabaseLive(files, opts.supabaseLive, ctx.notes)));
  const findings = sortFindings(all);

  return {
    target,
    root,
    filesScanned: files.filter((f) => !f.gitignored).length,
    gitAvailable: git !== null,
    historyScanned: git?.history != null,
    notes: [...ctx.notes].sort(),
    ignoredDeps: ctx.ignoredDeps,
    findings,
    score: computeScore(findings),
  };
}

const LIVE_PROBLEM_NOTES = {
  notFound: 'supabase.liveNotFound',
  ambiguous: 'supabase.liveAmbiguous',
  badKey: 'supabase.liveBadKey',
  badUrl: 'supabase.liveBadUrl',
} as const satisfies Record<string, NoteId>;

async function runSupabaseLive(
  files: ScanContext['files'],
  opts: SupabaseLiveOptions,
  notes: Set<NoteId>,
): Promise<Finding[]> {
  const resolved = resolveTarget(files, { url: opts.url, key: opts.key });
  if (!resolved.ok) {
    notes.add(LIVE_PROBLEM_NOTES[resolved.problem]);
    return [];
  }
  if (!(await opts.confirm({ host: new URL(resolved.target.url).host }))) {
    notes.add('supabase.liveDeclined');
    return [];
  }
  const res = await checkSupabaseLive(files, resolved.target, opts.client ?? createSupabaseLiveClient());
  notes.add('supabase.liveChecked');
  if (res.errors > 0) notes.add('supabase.liveErrors');
  return res.findings;
}

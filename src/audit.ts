import { existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { readGitInfo } from './git';
import { createOsvClient } from './osv';
import { computeScore, sortFindings } from './report';
import { rules as defaultRules } from './rules';
import { scanFiles } from './scanner';
import type { Finding, IgnoredDep, NoteId, OsvClient, Rule, ScanContext } from './types';

export interface AuditOptions {
  /** Scan the git history too (default: true). */
  history?: boolean;
  /** No network at all: dependencies are not checked against OSV (default: false). */
  offline?: boolean;
  /** OSV client to use (tests inject a fake one). */
  osv?: OsvClient;
  rules?: readonly Rule[];
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
  const findings = sortFindings(perRule.flat());

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

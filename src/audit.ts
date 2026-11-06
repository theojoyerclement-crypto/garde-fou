import { existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { readGitInfo } from './git';
import { computeScore, sortFindings } from './report';
import { rules as defaultRules } from './rules';
import { scanFiles } from './scanner';
import type { Finding, Rule } from './types';

export interface AuditOptions {
  /** Scan the git history too (default: true). */
  history?: boolean;
  rules?: readonly Rule[];
}

export interface AuditResult {
  /** Target as given by the user (for display). */
  target: string;
  root: string;
  filesScanned: number;
  gitAvailable: boolean;
  historyScanned: boolean;
  findings: Finding[];
  score: number;
}

export class TargetNotFoundError extends Error {
  constructor(public readonly target: string) {
    super(`Directory not found: ${target}`);
  }
}

export function runAudit(target: string, opts: AuditOptions = {}): AuditResult {
  const root = path.resolve(target);
  if (!existsSync(root) || !statSync(root).isDirectory()) throw new TargetNotFoundError(target);

  const history = opts.history ?? true;
  const files = scanFiles(root);
  const git = readGitInfo(root, { history });
  const ctx = { root, files, git };

  const findings = sortFindings((opts.rules ?? defaultRules).flatMap((r) => r.run(ctx)));

  return {
    target,
    root,
    filesScanned: files.filter((f) => !f.gitignored).length,
    gitAvailable: git !== null,
    historyScanned: git?.history != null,
    findings,
    score: computeScore(findings),
  };
}

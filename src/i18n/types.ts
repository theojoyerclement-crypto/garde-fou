import type { MessageId, NoteId, Severity } from '../types';

type P = Record<string, string>;

export interface FindingText {
  title: (p: P) => string;
  /** Plain-language explanation of the risk, for non-experts. */
  why: (p: P) => string;
  /** Concrete fix. */
  fix: (p: P) => string;
  /**
   * Ready-to-paste prompt for an AI coding tool (Lovable, Cursor, Claude Code…).
   * `p.location` is always set ("file:line", "file" or "").
   */
  prompt: (p: P) => string;
}

export interface Messages {
  severity: Record<Severity, string>;
  findings: Record<MessageId, FindingText>;
  ui: {
    title: (target: string) => string;
    filesScanned: (n: number) => string;
    gitHistoryScanned: string;
    gitHistorySkipped: string;
    noGit: string;
    noIssues: string;
    why: string;
    fix: string;
    prompt: string;
    notes: Record<NoteId, string>;
    inHistory: (commit: string) => string;
    score: string;
    summary: (counts: Record<Severity, number>) => string;
    verdict: (score: number) => string;
    targetNotFound: (target: string) => string;
  };
}

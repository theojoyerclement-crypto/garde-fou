import type { IgnoredReason, MessageId, NoteId, Severity } from '../types';

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
    aiExplanation: string;
    aiFix: string;
    aiInvalid: (choice: string) => string;
    htmlWritten: (file: string) => string;
    htmlError: (file: string) => string;
    ignored: {
      /** One line for the header. `vulnerable` is null when OSV was not queried. */
      summary: (counts: Record<IgnoredReason, number>, vulnerable: number | null, verbose: boolean) => string;
      /** Title of the --verbose / HTML detail. */
      title: string;
      reasons: Record<IgnoredReason, string>;
      via: (list: string) => string;
    };
  };
  html: {
    pageTitle: (target: string) => string;
    disclaimer: string;
    copy: string;
    copied: string;
    falsePositive: string;
    details: string;
    locations: (n: number) => string;
    generated: (version: string, date: string) => string;
    issueTitle: (messageId: string) => string;
    issueBody: (f: IssueFields) => string;
  };
}

/** What a false-positive issue may contain: no secret, no path, no code. */
export interface IssueFields {
  ruleId: string;
  messageId: string;
  severity: string;
  version: string;
  fileType: string;
  details: string;
}

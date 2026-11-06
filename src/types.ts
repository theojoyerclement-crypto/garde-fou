export type Severity = 'critical' | 'high' | 'medium' | 'low';

export const SEVERITY_ORDER: readonly Severity[] = ['critical', 'high', 'medium', 'low'];

/** Identifiers of every message a rule can emit. Texts live in src/i18n/. */
export type MessageId =
  | 'secret.file'
  | 'secret.history'
  | 'env.tracked'
  | 'env.history'
  | 'env.notIgnored'
  | 'env.publicSensitive'
  | 'env.publicSecretValue';

export interface Finding {
  ruleId: string;
  severity: Severity;
  messageId: MessageId;
  /** Values interpolated into the localized message. Never contains a raw secret. */
  params: Record<string, string>;
  /** Path relative to the scanned root, POSIX separators. */
  file?: string;
  line?: number;
  /** Short commit hash, for findings coming from git history. */
  commit?: string;
}

export interface ScannedFile {
  abs: string;
  /** Path relative to the scanned root, POSIX separators. */
  rel: string;
  content: string;
  /**
   * True when the file is matched by a .gitignore. Only `.env*` files are kept
   * in that case (the env rule needs them); everything else ignored is skipped.
   */
  gitignored: boolean;
}

export interface HistoryLine {
  commit: string;
  /** Path relative to the scanned root, POSIX separators. */
  file: string;
  text: string;
}

export interface GitInfo {
  /** Files tracked in the index, relative to the scanned root. */
  tracked: Set<string>;
  /** Lines added across all commits of all refs. Null when history was not read. */
  history: HistoryLine[] | null;
  /** Every file that appears in at least one commit → most recent commit touching it. */
  filesInHistory: Map<string, string>;
}

export interface ScanContext {
  root: string;
  files: ScannedFile[];
  git: GitInfo | null;
}

export interface Rule {
  id: string;
  run(ctx: ScanContext): Finding[];
}

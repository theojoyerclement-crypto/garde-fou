import pc from 'picocolors';
import { messages, type Lang } from './i18n';
import { SEVERITY_ORDER, type Finding, type Severity } from './types';
import type { AuditResult } from './audit';

/** Points removed from 100 for each finding of a given severity. */
export const SEVERITY_PENALTY: Record<Severity, number> = {
  critical: 30,
  high: 15,
  medium: 5,
  low: 2,
};

export function computeScore(findings: readonly Finding[]): number {
  const penalty = findings.reduce((sum, f) => sum + SEVERITY_PENALTY[f.severity], 0);
  return Math.max(0, 100 - penalty);
}

export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      (a.file ?? '').localeCompare(b.file ?? '') ||
      (a.line ?? 0) - (b.line ?? 0),
  );
}

export function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

/** Where a finding lives, as shown to the user ("file:line", "file" or ""). */
export function locationOf(f: Finding): string {
  if (!f.file) return '';
  return f.line ? `${f.file}:${f.line}` : f.file;
}

export interface LocalizedText {
  title: string;
  why: string;
  fix: string;
  prompt: string;
}

export function localizeFinding(f: Finding, lang: Lang): LocalizedText {
  const t = messages(lang).findings[f.messageId];
  const p = { location: locationOf(f), ...f.params };
  return { title: t.title(p), why: t.why(p), fix: t.fix(p), prompt: t.prompt(p) };
}

export interface RenderOptions {
  lang: Lang;
  color: boolean;
}

export function renderReport(result: AuditResult, opts: RenderOptions): string {
  const m = messages(opts.lang);
  const c = pc.createColors(opts.color);
  const sevColor: Record<Severity, (s: string) => string> = {
    critical: (s) => c.bold(c.red(s)),
    high: (s) => c.red(s),
    medium: (s) => c.yellow(s),
    low: (s) => c.cyan(s),
  };
  const icon: Record<Severity, string> = { critical: '✖', high: '✖', medium: '▲', low: '•' };

  const out: string[] = [];
  out.push('', c.bold(m.ui.title(result.target)));
  const gitState = !result.gitAvailable
    ? m.ui.noGit
    : result.historyScanned
      ? m.ui.gitHistoryScanned
      : m.ui.gitHistorySkipped;
  const header = [m.ui.filesScanned(result.filesScanned), gitState, ...result.notes.map((n) => m.ui.notes[n])];
  out.push(c.dim(header.join(' · ')), '');

  if (result.findings.length === 0) {
    out.push(c.green(`✔ ${m.ui.noIssues}`), '');
  }

  for (const sev of SEVERITY_ORDER) {
    const group = result.findings.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    out.push(sevColor[sev](`${m.severity[sev]} (${group.length})`));
    for (const f of group) {
      const text = localizeFinding(f, opts.lang);
      out.push(`  ${sevColor[sev](icon[sev])} ${c.bold(text.title)}`);
      const where = f.commit ? `${f.file ?? ''} (${m.ui.inHistory(f.commit)})` : locationOf(f);
      if (where.trim()) out.push(`    ${c.dim(where)}`);
      out.push(`    ${c.dim(`${m.ui.why} :`)} ${text.why}`);
      out.push(`    ${c.dim(`${m.ui.fix} :`)} ${text.fix}`);
      out.push(`    ${c.dim(`${m.ui.prompt} :`)}`);
      out.push(`    ${c.cyan(text.prompt)}`);
      out.push('');
    }
  }

  const score = result.score;
  const scoreColor = score >= 90 ? c.green : score >= 60 ? c.yellow : c.red;
  out.push(
    `${c.bold(`${m.ui.score} : `)}${c.bold(scoreColor(`${score}/100`))}  ${c.dim(
      m.ui.summary(countBySeverity(result.findings)),
    )}`,
  );
  out.push(scoreColor(m.ui.verdict(score)), '');
  return out.join('\n');
}

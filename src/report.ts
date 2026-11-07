import pc from 'picocolors';
import { messages, type Lang } from './i18n';
import { SEVERITY_ORDER, type Finding, type IgnoredReason, type Severity } from './types';
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

/** C0/C1 controls (incl. ESC), zero-width and bidi override characters. */
const UNSAFE_CHARS = new RegExp(
  '[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2069\ufeff]',
  'g',
);
const MAX_PARAM_LENGTH = 120;

/**
 * Params come from the audited project (file names, policy names, routes…),
 * i.e. untrusted input: no terminal escape sequences, no line breaks, bounded length.
 */
export function cleanParam(value: string): string {
  const s = value.replace(UNSAFE_CHARS, ' ').replace(/\s+/g, ' ').trim();
  return s.length > MAX_PARAM_LENGTH ? `${s.slice(0, MAX_PARAM_LENGTH - 1)}…` : s;
}

/**
 * Stricter cleaning for text pasted into an AI agent: only characters found in
 * paths, identifiers and route patterns survive, so a crafted name cannot carry
 * shell syntax ($, `, ;, |, &, quotes, <, >) into a command the agent writes.
 */
export function promptParam(value: string): string {
  return cleanParam(value).replace(/[^\p{L}\p{N} ._/@+\-:,()[\]{}*=#]/gu, '_');
}

function mapParams(p: Record<string, string>, fn: (v: string) => string): Record<string, string> {
  return Object.fromEntries(Object.entries(p).map(([k, v]) => [k, fn(v)]));
}

/** `location` overrides where the finding is (e.g. several files for one grouped issue). */
export function localizeFinding(f: Finding, lang: Lang, location?: string): LocalizedText {
  const t = messages(lang).findings[f.messageId];
  const raw = { location: location ?? locationOf(f), ...f.params };
  const p = mapParams(raw, cleanParam);
  const pp = mapParams(raw, promptParam);
  return { title: t.title(p), why: t.why(p), fix: t.fix(p), prompt: t.prompt(pp) };
}

export interface RenderOptions {
  lang: Lang;
  color: boolean;
  /** List every ignored dependency (default: a one-line count). */
  verbose?: boolean;
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
  out.push(c.dim(header.join(' · ')));
  const ignored = ignoredSummary(result, opts.lang, opts.verbose ?? false);
  if (ignored) out.push(c.dim(ignored));
  out.push('');

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
      const where = cleanParam(f.commit ? `${f.file ?? ''} (${m.ui.inHistory(f.commit)})` : locationOf(f));
      if (where.trim()) out.push(`    ${c.dim(where)}`);
      out.push(`    ${c.dim(`${m.ui.why} :`)} ${text.why}`);
      out.push(`    ${c.dim(`${m.ui.fix} :`)} ${text.fix}`);
      if (f.ai) {
        const indent = (s: string) => s.split(/\r?\n/).map((l) => `      ${l}`);
        out.push(`    ${c.magenta(`${m.ui.aiExplanation} :`)}`, ...indent(f.ai.explanation));
        out.push(`    ${c.magenta(`${m.ui.aiFix} :`)}`, ...indent(f.ai.fix));
      }
      out.push(`    ${c.dim(`${m.ui.prompt} :`)}`);
      out.push(`    ${c.cyan(text.prompt)}`);
      out.push('');
    }
  }

  if (opts.verbose && result.ignoredDeps.length > 0) {
    out.push(c.bold(m.ui.ignored.title));
    for (const g of ignoredGroups(result, opts.lang)) {
      out.push(`  ${g.label} (${g.lines.length})`);
      for (const l of g.lines) out.push(`    ${l.vulnerable ? c.yellow(l.text) : c.dim(l.text)}`);
    }
    out.push('');
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

const IGNORED_ORDER: readonly IgnoredReason[] = ['build', 'devTool', 'dev', 'unused', 'unverifiable'];

/** One-line count of the ignored dependencies, or null when there are none. */
export function ignoredSummary(result: AuditResult, lang: Lang, verbose: boolean): string | null {
  if (result.ignoredDeps.length === 0) return null;
  const counts = Object.fromEntries(IGNORED_ORDER.map((r) => [r, 0])) as Record<IgnoredReason, number>;
  for (const d of result.ignoredDeps) counts[d.reason]++;
  const vulnerable = result.notes.includes('osv.checked') ? result.ignoredDeps.filter((d) => d.vulns.length > 0).length : null;
  return messages(lang).ui.ignored.summary(counts, vulnerable, verbose);
}

export interface IgnoredGroup {
  reason: IgnoredReason;
  label: string;
  /** "name@version (file) via x, y  ⚠ GHSA-…", cleaned; packages with advisories first. */
  lines: { text: string; vulnerable: boolean }[];
}

/** Ignored dependencies grouped by reason, for --verbose and the HTML report. */
export function ignoredGroups(result: AuditResult, lang: Lang): IgnoredGroup[] {
  const m = messages(lang).ui.ignored;
  const manyLocks = new Set(result.ignoredDeps.map((d) => d.file)).size > 1;
  return IGNORED_ORDER.map((reason) => {
    const deps = result.ignoredDeps
      .filter((d) => d.reason === reason)
      .sort((a, b) => Number(b.vulns.length > 0) - Number(a.vulns.length > 0) || a.name.localeCompare(b.name));
    const lines = deps.map((d) => {
      const via = d.via.filter((v) => v !== d.name);
      const parts = [
        `${d.name}@${d.version}`,
        manyLocks ? `(${d.file})` : '',
        via.length > 0 ? m.via(via.length > 3 ? `${via.slice(0, 3).join(', ')} +${via.length - 3}` : via.join(', ')) : '',
        d.vulns.length > 0 ? `⚠ ${d.vulns.join(', ')}` : '',
      ];
      return { text: cleanParam(parts.filter(Boolean).join('  ')), vulnerable: d.vulns.length > 0 };
    });
    return { reason, label: m.reasons[reason], lines };
  }).filter((g) => g.lines.length > 0);
}

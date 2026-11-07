/**
 * CI helpers (GitHub Action): Markdown job summary and --fail-on.
 *
 * The summary is meant for logs and PR pages: it never contains a secret,
 * not even masked (the `masked` param is replaced), nor prompts or code.
 */
import { redactSecrets } from './ai/redact';
import type { AuditResult } from './audit';
import { messages, type Lang } from './i18n';
import { countBySeverity, ignoredSummary, localizeFinding, locationOf, cleanParam } from './report';
import { SEVERITY_ORDER, type Finding, type Severity } from './types';

export type FailOn = Severity | 'none';
export const FAIL_ON_VALUES: readonly FailOn[] = [...SEVERITY_ORDER, 'none'];

export function isFailOn(v: string): v is FailOn {
  return (FAIL_ON_VALUES as readonly string[]).includes(v);
}

/** True when a finding is at `level` or more severe. */
export function exceedsFailOn(findings: readonly Finding[], level: FailOn): boolean {
  if (level === 'none') return false;
  const max = SEVERITY_ORDER.indexOf(level);
  return findings.some((f) => SEVERITY_ORDER.indexOf(f.severity) <= max);
}

const MAX_ROWS = 50;

/** Markdown and HTML are both rendered by GitHub: neutralise both. */
function mdCell(s: string): string {
  return cleanParam(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\|/g, '\\|')
    .replace(/[`*_[\]]/g, (c) => `\\${c}`);
}

/** Same finding with no trace of the secret value, for public logs. */
function withoutSecret(f: Finding): Finding {
  return 'masked' in f.params ? { ...f, params: { ...f.params, masked: '•••' } } : f;
}

export function renderMarkdownSummary(result: AuditResult, lang: Lang, failOn: FailOn = 'none'): string {
  const m = messages(lang);
  const out: string[] = [];
  out.push(`## Garde-Fou — ${result.score}/100`, '');
  out.push(`${mdCell(m.ui.verdict(result.score))} ${mdCell(m.ui.summary(countBySeverity(result.findings)))}`, '');
  if (exceedsFailOn(result.findings, failOn)) out.push(`**${mdCell(m.ui.markdown.failed(m.severity[failOn as Severity]))}**`, '');

  if (result.findings.length === 0) {
    out.push(`✔ ${mdCell(m.ui.noIssues)}`, '');
  } else {
    out.push(`| ${m.ui.markdown.severity} | ${m.ui.markdown.problem} | ${m.ui.markdown.location} |`, '| --- | --- | --- |');
    for (const f of result.findings.slice(0, MAX_ROWS)) {
      const t = localizeFinding(withoutSecret(f), lang);
      const where = f.commit ? `${f.file ?? ''} (${m.ui.inHistory(f.commit)})` : locationOf(f);
      out.push(`| ${mdCell(m.severity[f.severity])} | ${mdCell(t.title)} | ${mdCell(where)} |`);
    }
    if (result.findings.length > MAX_ROWS) out.push('', mdCell(m.ui.markdown.more(result.findings.length - MAX_ROWS)));
    out.push('');
  }
  const ignored = ignoredSummary(result, lang, true);
  const notes = result.notes.map((n) => m.ui.notes[n]);
  const footer = [...notes, ...(ignored ? [ignored] : [])];
  if (footer.length > 0) out.push(`<sub>${footer.map(mdCell).join(' · ')}</sub>`, '');
  // Belt and braces: nothing key-shaped ever reaches a public log.
  return redactSecrets(out.join('\n'));
}

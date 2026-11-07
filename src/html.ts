/**
 * --html: one self-contained page (no external resource), FR/EN, mobile
 * friendly. Everything that comes from the audited project or from the AI is
 * HTML-escaped; a strict CSP (hash of our own inline style and script) blocks
 * any script that would slip through anyway.
 */
import { createHash } from 'node:crypto';
import type { AuditResult } from './audit';
import { redactSecrets } from './ai/redact';
import { messages, type Lang } from './i18n';
import { basenameOf, isEnvFile } from './patterns';
import {
  cleanParam,
  countBySeverity,
  ignoredGroups,
  ignoredSummary,
  localizeFinding,
  locationOf,
  promptParam,
} from './report';
import { SEVERITY_ORDER, type Finding, type Severity } from './types';
import { ISSUES_NEW_URL, VERSION } from './version';

const HTML_ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

/** Escapes text for HTML content AND quoted attribute values. */
export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => HTML_ESCAPES[c] ?? c);
}

/** Params safe to put in a public issue: no path, route, table, policy or masked value. */
const ISSUE_SAFE_PARAMS = ['provider', 'prefix', 'name', 'service', 'framework', 'command', 'pkg', 'version', 'id'];

function fileTypeOf(file: string | undefined): string {
  if (!file) return 'n/a';
  const base = basenameOf(file);
  if (isEnvFile(base)) return '.env';
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(dot).toLowerCase() : 'n/a';
}

/** Pre-filled GitHub issue for a false positive. Contains no secret, path or code. */
export function falsePositiveUrl(f: Finding, lang: Lang): string {
  const m = messages(lang).html;
  const details =
    ISSUE_SAFE_PARAMS.filter((k) => f.params[k])
      .map((k) => `${k}=${promptParam(f.params[k] ?? '')}`)
      .join(', ') || 'n/a';
  const body = redactSecrets(
    m.issueBody({
      ruleId: f.ruleId,
      messageId: f.messageId,
      severity: f.severity,
      version: VERSION,
      fileType: promptParam(fileTypeOf(f.file)),
      details,
    }),
  );
  const q = new URLSearchParams({ title: m.issueTitle(f.messageId), body, labels: 'false-positive' });
  return `${ISSUES_NEW_URL}?${q.toString()}`;
}

const STYLE = `
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--text:#1b1f24;--muted:#5b6470;--border:#dde1e6;
--critical:#b42318;--high:#d92d20;--medium:#b54708;--low:#175cd3;--ok:#067647;--code:#f1f3f5;--accent:#344054}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--text:#e6e8eb;--muted:#9aa4b2;--border:#2a2f3a;
--critical:#ff6b5f;--high:#ff8a7a;--medium:#f5b54a;--low:#7cb2ff;--ok:#4cd39b;--code:#11141a;--accent:#cfd4dc}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:1.5rem;margin:0 0 4px}
h2{font-size:1.1rem;margin:32px 0 12px}
h3{font-size:1rem;margin:0 0 8px;overflow-wrap:anywhere}
.target{color:var(--muted);margin:0 0 16px;overflow-wrap:anywhere}
.disclaimer{border:1px solid var(--border);border-left:4px solid var(--medium);background:var(--card);padding:12px 14px;border-radius:8px;margin:0 0 20px}
.summary{display:flex;flex-wrap:wrap;gap:16px;align-items:center;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px}
.score{font-size:2.6rem;font-weight:700;line-height:1}
.score small{font-size:1rem;color:var(--muted);font-weight:400}
.score.good{color:var(--ok)}.score.warn{color:var(--medium)}.score.bad{color:var(--critical)}
.counts{display:flex;flex-wrap:wrap;gap:8px;margin:0;padding:0;list-style:none}
.pill{border-radius:999px;padding:2px 10px;font-size:.85rem;border:1px solid currentColor}
.notes{color:var(--muted);font-size:.9rem;margin:8px 0 0;flex-basis:100%}
.finding{background:var(--card);border:1px solid var(--border);border-left:4px solid var(--accent);border-radius:10px;padding:14px 16px;margin:0 0 14px}
.sev-critical{color:var(--critical)}.sev-high{color:var(--high)}.sev-medium{color:var(--medium)}.sev-low{color:var(--low)}
.finding.critical{border-left-color:var(--critical)}.finding.high{border-left-color:var(--high)}
.finding.medium{border-left-color:var(--medium)}.finding.low{border-left-color:var(--low)}
.loc{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.85rem;color:var(--muted);margin:0 0 8px;overflow-wrap:anywhere}
.finding p{margin:6px 0;overflow-wrap:anywhere}
.label{font-weight:600}
.ai{border-top:1px dashed var(--border);margin-top:10px;padding-top:8px}
.ai pre{font:inherit}
.prompt{margin-top:12px;border:1px solid var(--border);border-radius:8px;overflow:hidden}
.prompt-head{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:6px 10px;background:var(--code);font-size:.9rem}
pre{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}
.prompt pre{padding:10px;font:.9rem/1.5 ui-monospace,SFMono-Regular,Consolas,monospace}
button,.fp{font:inherit;font-size:.9rem;cursor:pointer;border-radius:6px;border:1px solid var(--border);background:var(--card);color:var(--text);padding:6px 12px;min-height:36px}
.fp{display:inline-block;margin-top:10px;text-decoration:none;color:var(--muted)}
button:focus-visible,.fp:focus-visible{outline:2px solid var(--low);outline-offset:2px}
.count{margin:0 0 4px;font-size:.85rem;color:var(--muted)}
.locs{margin:0 0 8px;padding-left:18px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.85rem;color:var(--muted)}
.locs li{overflow-wrap:anywhere}
details{border-top:1px solid var(--border);margin-top:8px;padding-top:6px}
summary{cursor:pointer;font-weight:600;padding:6px 0;min-height:36px}
summary:focus-visible{outline:2px solid var(--low);outline-offset:2px}
.empty{color:var(--ok);font-weight:600}
footer{color:var(--muted);font-size:.85rem;margin-top:32px}
`.trim();

const SCRIPT = `
document.addEventListener('click',function(e){
var b=e.target&&e.target.closest?e.target.closest('button[data-copy]'):null;if(!b)return;
var el=document.getElementById(b.getAttribute('data-copy'));if(!el)return;var t=el.textContent||'';
function done(){var o=b.getAttribute('data-label');b.textContent=b.getAttribute('data-done');setTimeout(function(){b.textContent=o},1500)}
function fallback(){var a=document.createElement('textarea');a.value=t;a.setAttribute('readonly','');a.style.position='fixed';a.style.opacity='0';document.body.appendChild(a);a.select();try{document.execCommand('copy');done()}catch(_){}document.body.removeChild(a)}
if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(done,fallback)}else{fallback()}
});
`.trim();

export function cspHash(source: string): string {
  return `'sha256-${createHash('sha256').update(source, 'utf8').digest('base64')}'`;
}

export const CSP = [
  "default-src 'none'",
  `style-src ${cspHash(STYLE)}`,
  `script-src ${cspHash(SCRIPT)}`,
  "img-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

/** Locations named in a grouped prompt; the card itself lists them all. */
export const MAX_PROMPT_LOCATIONS = 8;

export interface FindingGroup {
  items: Finding[];
}

/**
 * Same problem (rule, message, severity, params) found in several places →
 * one group, in first-seen order. Different params (another key, another
 * table…) stay separate.
 */
export function groupFindings(findings: readonly Finding[]): FindingGroup[] {
  const groups = new Map<string, FindingGroup>();
  for (const f of findings) {
    const params = Object.keys(f.params)
      .sort()
      .map((k) => [k, f.params[k]]);
    const key = JSON.stringify([f.ruleId, f.messageId, f.severity, params]);
    const g = groups.get(key);
    if (g) g.items.push(f);
    else groups.set(key, { items: [f] });
  }
  return [...groups.values()];
}

function whereOf(f: Finding, lang: Lang): string {
  return cleanParam(f.commit ? `${f.file ?? ''} (${messages(lang).ui.inHistory(f.commit)})` : locationOf(f));
}

export interface HtmlOptions {
  lang: Lang;
  /** Defaults to now; tests pass a fixed date. */
  date?: Date;
}

function multiline(text: string): string {
  return `<pre>${escapeHtml(text)}</pre>`;
}

export function renderHtml(result: AuditResult, opts: HtmlOptions): string {
  const m = messages(opts.lang);
  const e = (s: string) => escapeHtml(s);
  const date = (opts.date ?? new Date()).toISOString().slice(0, 10);
  const counts = countBySeverity(result.findings);
  const scoreClass = result.score >= 90 ? 'good' : result.score >= 60 ? 'warn' : 'bad';
  const target = cleanParam(result.target);
  const gitState = !result.gitAvailable
    ? m.ui.noGit
    : result.historyScanned
      ? m.ui.gitHistoryScanned
      : m.ui.gitHistorySkipped;
  const notes = [m.ui.filesScanned(result.filesScanned), gitState, ...result.notes.map((n) => m.ui.notes[n])];
  // The detail is in the page (collapsed section below): no --verbose hint.
  const ignored = ignoredSummary(result, opts.lang, true);

  const out: string[] = [];
  out.push(
    '<!doctype html>',
    `<html lang="${opts.lang}">`,
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<meta http-equiv="Content-Security-Policy" content="${CSP}">`,
    '<meta name="referrer" content="no-referrer">',
    '<meta name="robots" content="noindex">',
    `<title>${e(m.html.pageTitle(target))}</title>`,
    `<style>${STYLE}</style>`,
    '</head>',
    '<body>',
    '<div class="wrap">',
    '<header>',
    '<h1>Garde-Fou</h1>',
    `<p class="target">${e(target)}</p>`,
    `<p class="disclaimer" role="note"><strong>⚠ ${e(m.html.disclaimer)}</strong></p>`,
    '<section class="summary" aria-label="score">',
    `<div class="score ${scoreClass}">${result.score}<small>/100</small></div>`,
    `<div><div>${e(m.ui.verdict(result.score))}</div>`,
    '<ul class="counts">',
    ...SEVERITY_ORDER.map(
      (s) => `<li class="pill sev-${s}">${e(m.severity[s])} · ${counts[s]}</li>`,
    ),
    '</ul></div>',
    `<p class="notes">${e(notes.join(' · '))}</p>`,
    ...(ignored ? [`<p class="notes">${e(ignored)}</p>`] : []),
    '</section>',
    '</header>',
    '<main>',
  );

  if (result.findings.length === 0) out.push(`<p class="empty">✔ ${e(m.ui.noIssues)}</p>`);

  let n = 0;
  for (const sev of SEVERITY_ORDER) {
    const findings = result.findings.filter((f) => f.severity === sev);
    if (findings.length === 0) continue;
    out.push(`<h2 class="sev-${sev}">${e(m.severity[sev as Severity])} (${findings.length})</h2>`);
    for (const g of groupFindings(findings)) {
      const f = g.items[0] as Finding;
      const id = `p${n++}`;
      const wheres = g.items.map((x) => whereOf(x, opts.lang)).filter(Boolean);
      // The prompt names every location (capped) so one paste fixes them all.
      const shown = wheres.slice(0, MAX_PROMPT_LOCATIONS).join(', ');
      const more = wheres.length > MAX_PROMPT_LOCATIONS ? ` +${wheres.length - MAX_PROMPT_LOCATIONS}` : '';
      const t = localizeFinding(f, opts.lang, g.items.length > 1 ? `${shown}${more}` : undefined);
      const ai = g.items.find((x) => x.ai)?.ai;

      out.push(`<article class="finding ${sev}">`, `<h3>${e(t.title)}</h3>`);
      if (wheres.length > 1) out.push(`<p class="count">${e(m.html.locations(wheres.length))}</p>`);
      if (wheres.length > 0) out.push(`<ul class="locs">${wheres.map((w) => `<li>${e(w)}</li>`).join('')}</ul>`);
      out.push(
        '<details>',
        `<summary>${e(m.html.details)}</summary>`,
        `<p><span class="label">${e(m.ui.why)} :</span> ${e(t.why)}</p>`,
        `<p><span class="label">${e(m.ui.fix)} :</span> ${e(t.fix)}</p>`,
      );
      if (ai) {
        out.push(
          '<div class="ai">',
          `<p class="label">${e(m.ui.aiExplanation)}</p>`,
          multiline(ai.explanation),
          `<p class="label">${e(m.ui.aiFix)}</p>`,
          multiline(ai.fix),
          '</div>',
        );
      }
      out.push(
        '<div class="prompt">',
        `<div class="prompt-head"><span>${e(m.ui.prompt)}</span>` +
          `<button type="button" data-copy="${id}" data-label="${e(m.html.copy)}" data-done="${e(m.html.copied)}">${e(m.html.copy)}</button></div>`,
        `<pre id="${id}">${e(t.prompt)}</pre>`,
        '</div>',
        '</details>',
        `<a class="fp" href="${e(falsePositiveUrl(f, opts.lang))}" target="_blank" rel="noopener noreferrer">${e(m.html.falsePositive)}</a>`,
        '</article>',
      );
    }
  }

  const groups = ignoredGroups(result, opts.lang);
  if (groups.length > 0) {
    out.push('<details class="ignored">', `<summary>${e(m.ui.ignored.title)}</summary>`);
    for (const g of groups) {
      out.push(
        `<p class="label">${e(g.label)} (${g.lines.length})</p>`,
        `<ul class="locs">${g.lines.map((l) => `<li>${e(l.text)}</li>`).join('')}</ul>`,
      );
    }
    out.push('</details>');
  }

  out.push(
    '</main>',
    `<footer><p>${e(m.html.generated(VERSION, date))}</p><p>${e(m.html.disclaimer)}</p></footer>`,
    '</div>',
    `<script>${SCRIPT}</script>`,
    '</body>',
    '</html>',
    '',
  );
  return out.join('\n');
}

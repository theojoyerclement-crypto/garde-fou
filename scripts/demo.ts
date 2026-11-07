/**
 * `npm run demo`: renders the README images from a real scan of
 * fixtures/vulnerable-app (copied to a temp dir with freshly generated FAKE
 * keys, committed to a throwaway git repo, offline).
 *
 * Writes docs/demo-{fr,en}.svg (animated terminal: the command is typed, then
 * the report appears line by line) and docs/report-{fr,en}.svg (same report,
 * static). Only masked keys can appear, as in the real report.
 */
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAudit, type AuditResult } from '../src/audit';
import { messages, type Lang } from '../src/i18n';
import { localizeFinding, locationOf } from '../src/report';
import { SEVERITY_ORDER, type Severity } from '../src/types';
import { generateFixtureSecrets } from './fake-keys';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const COLS = 96;
const CHAR_W = 8.4;
const LINE_H = 21;
const PAD = 22;
const TOP = 48;

const COLORS = {
  text: '#e6edf3',
  dim: '#8b949e',
  green: '#3fb950',
  prompt: '#79c0ff',
  critical: '#ff7b72',
  high: '#f0883e',
  medium: '#d29922',
  low: '#39c5cf',
};
const SEV_COLOR: Record<Severity, string> = {
  critical: COLORS.critical,
  high: COLORS.high,
  medium: COLORS.medium,
  low: COLORS.low,
};
const ICON: Record<Severity, string> = { critical: '✖', high: '✖', medium: '▲', low: '•' };

interface Seg {
  text: string;
  color: string;
  bold?: boolean;
}
type Line = Seg[];

function wrap(text: string, width: number, indent: string): string[] {
  const words = text.split(' ');
  const out: string[] = [];
  let cur = '';
  for (const w of words) {
    if (cur && (cur.length + 1 + w.length) > width) {
      out.push(cur);
      cur = indent + w;
    } else cur = cur ? `${cur} ${w}` : w;
  }
  if (cur) out.push(cur);
  return out;
}

const DEMO_TARGET: Record<Lang, string> = { fr: 'mon-app', en: 'my-app' };
const HINT: Record<Lang, string> = {
  fr: 'Chaque problème : pourquoi c’est grave, comment corriger, et un prompt à coller dans votre outil IA.',
  en: 'Every problem: why it matters, how to fix it, and a prompt to paste into your AI tool.',
};

function reportLines(result: AuditResult, lang: Lang): Line[] {
  const m = messages(lang);
  const target = DEMO_TARGET[lang];
  const lines: Line[] = [];
  lines.push([{ text: `$ npx gardefou ${target}`, color: COLORS.prompt }]);
  lines.push([]);
  lines.push([{ text: m.ui.title(target), color: COLORS.text, bold: true }]);
  lines.push([{ text: [m.ui.filesScanned(result.filesScanned), m.ui.gitHistoryScanned].join(' · '), color: COLORS.dim }]);
  lines.push([]);
  for (const sev of SEVERITY_ORDER) {
    const group = result.findings.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    lines.push([{ text: `${m.severity[sev]} (${group.length})`, color: SEV_COLOR[sev], bold: sev === 'critical' }]);
    for (const f of group) {
      const t = localizeFinding(f, lang);
      const where = f.commit ? `${f.file ?? ''} (${m.ui.inHistory(f.commit)})` : locationOf(f);
      const [first, ...rest] = wrap(t.title, COLS - 4, '    ');
      lines.push([
        { text: `  ${ICON[sev]} `, color: SEV_COLOR[sev] },
        { text: first ?? '', color: COLORS.text, bold: true },
      ]);
      for (const r of rest) lines.push([{ text: r, color: COLORS.text, bold: true }]);
      if (where) lines.push([{ text: `    ${where}`, color: COLORS.dim }]);
    }
    lines.push([]);
  }
  const c = result.findings.reduce((acc, f) => ({ ...acc, [f.severity]: acc[f.severity] + 1 }), {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  } as Record<Severity, number>);
  lines.push([
    { text: `${m.ui.score} : `.replace(' :', lang === 'fr' ? ' :' : ':'), color: COLORS.text, bold: true },
    { text: `${result.score}/100`, color: result.score >= 90 ? COLORS.green : result.score >= 60 ? COLORS.medium : COLORS.critical, bold: true },
    { text: `  ${m.ui.summary(c)}`, color: COLORS.dim },
  ]);
  lines.push([{ text: m.ui.verdict(result.score), color: result.score >= 60 ? COLORS.medium : COLORS.critical }]);
  lines.push([]);
  for (const h of wrap(HINT[lang], COLS, '')) lines.push([{ text: h, color: COLORS.green }]);
  return lines;
}

const xml = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function svg(lines: Line[], lang: Lang, animated: boolean): string {
  const width = Math.round(PAD * 2 + COLS * CHAR_W);
  const height = TOP + lines.length * LINE_H + PAD;
  const cmd = lines[0]?.[0]?.text ?? '';
  const typeSteps = cmd.length;
  const typeEnd = 0.4 + typeSteps * 0.06;
  const title = lang === 'fr' ? 'Garde-Fou : démo d’un audit' : 'Garde-Fou: audit demo';
  const style = [
    `text{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;font-size:14px;white-space:pre}`,
    `.b{font-weight:700}`,
    animated
      ? [
          `.l{opacity:0;animation:show .01s linear forwards}`,
          `@keyframes show{to{opacity:1}}`,
          `.type{transform:scaleX(0);transform-box:fill-box;transform-origin:left;animation:type ${(typeSteps * 0.06).toFixed(2)}s steps(${typeSteps}) .4s forwards}`,
          `@keyframes type{to{transform:scaleX(1)}}`,
          `.cur{animation:blink 1s step-end infinite}`,
          `@keyframes blink{50%{opacity:0}}`,
        ].join('')
      : '',
  ].join('');

  const out: string[] = [];
  out.push(
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="${xml(title)}">`,
    `<title>${xml(title)}</title>`,
    `<style>${style}</style>`,
    `<rect width="${width}" height="${height}" rx="10" fill="#0d1117"/>`,
    `<rect width="${width}" height="34" rx="10" fill="#161b22"/><rect y="24" width="${width}" height="10" fill="#161b22"/>`,
    `<circle cx="20" cy="17" r="6" fill="#ff5f57"/><circle cx="40" cy="17" r="6" fill="#febc2e"/><circle cx="60" cy="17" r="6" fill="#28c840"/>`,
    `<text x="${width / 2}" y="22" fill="${COLORS.dim}" text-anchor="middle">gardefou</text>`,
  );
  if (animated) {
    out.push(
      `<defs><clipPath id="c"><rect class="type" x="${PAD}" y="${TOP - 16}" width="${(cmd.length + 1) * CHAR_W}" height="${LINE_H}"/></clipPath></defs>`,
    );
  }
  lines.forEach((line, i) => {
    const y = TOP + i * LINE_H;
    const tspans = line
      .map((s) => `<tspan fill="${s.color}"${s.bold ? ' class="b"' : ''}>${xml(s.text)}</tspan>`)
      .join('');
    if (i === 0 && animated) {
      out.push(`<text x="${PAD}" y="${y}" clip-path="url(#c)">${tspans}</text>`);
      return;
    }
    if (!animated) {
      out.push(`<text x="${PAD}" y="${y}">${tspans}</text>`);
      return;
    }
    const delay = (typeEnd + 0.5 + (i - 1) * 0.09).toFixed(2);
    out.push(`<text class="l" style="animation-delay:${delay}s" x="${PAD}" y="${y}">${tspans}</text>`);
  });
  if (animated) {
    const y = TOP + lines.length * LINE_H - LINE_H;
    const delay = (typeEnd + 0.5 + lines.length * 0.09).toFixed(2);
    out.push(
      `<g class="l" style="animation-delay:${delay}s"><rect class="cur" x="${PAD + (lines.at(-1)?.reduce((n, s) => n + s.text.length, 0) ?? 0) * CHAR_W + 4}" y="${y - 14}" width="8" height="17" fill="${COLORS.text}"/></g>`,
    );
  }
  out.push('</svg>', '');
  return out.join('\n');
}

async function main() {
  const tmp = mkdtempSync(path.join(os.tmpdir(), 'garde-fou-demo-'));
  try {
    const root = path.join(tmp, 'app');
    cpSync(path.join(repoRoot, 'fixtures', 'vulnerable-app'), root, {
      recursive: true,
      filter: (src) => path.basename(src) !== '.env' && !path.basename(src).includes('.generated.'),
    });
    for (const [rel, content] of Object.entries(generateFixtureSecrets().files)) {
      const abs = path.join(root, rel);
      mkdirSync(path.dirname(abs), { recursive: true });
      writeFileSync(abs, content);
    }
    const git = (...args: string[]) =>
      execFileSync('git', ['-c', 'user.name=demo', '-c', 'user.email=demo@example.invalid', '-c', 'commit.gpgsign=false', ...args], {
        cwd: root,
        stdio: 'ignore',
      });
    git('init', '-q');
    git('add', '-A');
    git('commit', '-q', '--no-verify', '-m', 'init');

    const result = await runAudit(root, { offline: true });
    const docs = path.join(repoRoot, 'docs');
    mkdirSync(docs, { recursive: true });
    for (const lang of ['fr', 'en'] as const) {
      const lines = reportLines(result, lang);
      writeFileSync(path.join(docs, `demo-${lang}.svg`), svg(lines, lang, true));
      writeFileSync(path.join(docs, `report-${lang}.svg`), svg(lines, lang, false));
    }
    process.stdout.write(`${result.findings.length} findings, score ${result.score}: docs/demo-{fr,en}.svg, docs/report-{fr,en}.svg\n`);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

await main();

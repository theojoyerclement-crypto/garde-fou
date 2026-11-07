#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { createInterface } from 'node:readline/promises';
import { Command, Option } from 'commander';
import pc from 'picocolors';
import { addAiAdvice } from './ai/explain';
import { AI_PROVIDERS, type AiProviderId } from './ai/providers';
import { TargetNotFoundError, runAudit, type SupabaseLiveOptions } from './audit';
import { exceedsFailOn, isFailOn, renderMarkdownSummary, type FailOn } from './ci';
import { renderHtml } from './html';
import { detectLang, isLang, messages, type Lang } from './i18n';
import { serveMcp } from './mcp';
import { localizeFinding, renderReport } from './report';
import { VERSION } from './version';

export const DEFAULT_HTML_FILE = 'garde-fou-report.html';

interface CliOptions {
  lang?: string;
  json?: boolean;
  history: boolean;
  offline?: boolean;
  color: boolean;
  ai?: string | boolean;
  html?: string | boolean;
  verbose?: boolean;
  failOn?: string;
  markdown?: string;
  supabaseLive?: boolean;
  supabaseUrl?: string;
  supabaseKey?: string;
  yes?: boolean;
}

/** Asks for the explicit "this is my project" answer on the terminal (prompt on stderr). */
async function askLiveConfirmation(lang: Lang, host: string): Promise<boolean> {
  const m = messages(lang).ui.live;
  if (!process.stdin.isTTY) {
    process.stderr.write(`${m.needsYes}\n`);
    return false;
  }
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = (await rl.question(m.confirm(host))).trim().toLowerCase();
    return m.phrases.some((p) => p.toLowerCase() === answer);
  } finally {
    rl.close();
  }
}

const program = new Command();

program
  .name('gardefou')
  .description(
    'Garde-Fou : audit de sécurité local pour projets générés par IA / local security audit for AI-generated projects',
  )
  .version(VERSION)
  .argument('[dir]', 'dossier à auditer / directory to audit', '.')
  .addOption(new Option('--lang <lang>', 'langue / language').choices(['fr', 'en']))
  .option('--json', 'sortie JSON / JSON output')
  .option('--html [file]', `rapport HTML autonome / standalone HTML report (${DEFAULT_HTML_FILE})`)
  .option('--markdown <file>', 'résumé Markdown sans secret (CI) / Markdown summary without secrets (CI)')
  .option(
    '--fail-on <severity>',
    'code 1 dès cette gravité : critical | high | medium | low | none (défaut : high) / exit 1 from this severity',
  )
  .option(
    '--ai [provider]',
    'explications IA optionnelles : claude | openai | ollama (clé via ANTHROPIC_API_KEY / OPENAI_API_KEY) / optional AI explanations',
  )
  .option(
    '--supabase-live',
    'teste en direct (lecture seule, clé anon) si les tables Supabase sont lisibles / live read-only check of Supabase tables',
  )
  .option('--supabase-url <url>', 'URL du projet Supabase pour --supabase-live / Supabase URL')
  .option('--supabase-key <key>', 'clé anon / publishable pour --supabase-live / anon key')
  .option('-y, --yes', 'confirme --supabase-live sans question / confirm --supabase-live')
  .option('--no-history', "ne pas analyser l'historique git / skip git history")
  .option(
    '--offline',
    'aucun accès réseau : ni OSV, ni IA distante, ni Supabase / no network at all',
  )
  .option('--no-color', 'désactiver les couleurs / disable colors')
  .option('--verbose', 'lister les dépendances ignorées / list ignored dependencies')
  .action(async (dir: string, opts: CliOptions) => {
    const lang: Lang = opts.lang && isLang(opts.lang) ? opts.lang : detectLang();
    const m = messages(lang);

    let aiChoice: 'auto' | AiProviderId | null = null;
    if (opts.ai !== undefined && opts.ai !== false) {
      if (opts.ai === true) aiChoice = 'auto';
      else if ((AI_PROVIDERS as readonly string[]).includes(opts.ai)) aiChoice = opts.ai as AiProviderId;
      else {
        process.stderr.write(`${m.ui.aiInvalid(opts.ai)}\n`);
        process.exitCode = 2;
        return;
      }
    }

    let failOn: FailOn = 'high';
    if (opts.failOn !== undefined) {
      if (!isFailOn(opts.failOn)) {
        process.stderr.write(`${m.ui.failOnInvalid(opts.failOn)}\n`);
        process.exitCode = 2;
        return;
      }
      failOn = opts.failOn;
    }

    const offline = opts.offline ?? false;
    let supabaseLive: SupabaseLiveOptions | undefined;
    if (opts.supabaseLive) {
      if (offline) {
        process.stderr.write(`${m.ui.live.offline}\n`);
        process.exitCode = 2;
        return;
      }
      supabaseLive = {
        url: opts.supabaseUrl,
        key: opts.supabaseKey,
        confirm: async ({ host }) => (opts.yes ? true : askLiveConfirmation(lang, host)),
      };
    }

    try {
      const result = await runAudit(dir, { history: opts.history, offline, supabaseLive });
      if (aiChoice) await addAiAdvice(result, aiChoice, { lang, offline, env: process.env });

      if (opts.json) {
        const findings = result.findings.map((f) => ({ ...f, ...localizeFinding(f, lang) }));
        process.stdout.write(`${JSON.stringify({ ...result, lang, findings }, null, 2)}\n`);
      } else {
        process.stdout.write(
          `${renderReport(result, { lang, color: opts.color && pc.isColorSupported, verbose: opts.verbose ?? false })}\n`,
        );
      }

      process.exitCode = exceedsFailOn(result.findings, failOn) ? 1 : 0;

      if (opts.markdown !== undefined) {
        const file = path.resolve(opts.markdown);
        try {
          writeFileSync(file, renderMarkdownSummary(result, lang, failOn), 'utf8');
        } catch {
          process.stderr.write(`${m.ui.markdownError(file)}\n`);
          process.exitCode = 2;
        }
      }

      if (opts.html !== undefined && opts.html !== false) {
        const file = path.resolve(opts.html === true ? DEFAULT_HTML_FILE : opts.html);
        try {
          writeFileSync(file, renderHtml(result, { lang }), 'utf8');
          process.stderr.write(`${m.ui.htmlWritten(file)}\n`);
        } catch {
          process.stderr.write(`${m.ui.htmlError(file)}\n`);
          process.exitCode = 2;
        }
      }
    } catch (err) {
      if (err instanceof TargetNotFoundError) {
        process.stderr.write(`${m.ui.targetNotFound(err.target)}\n`);
        process.exitCode = 2;
        return;
      }
      throw err;
    }
  });

program
  .command('mcp')
  .description('serveur MCP (stdio), lecture seule / MCP server (stdio), read-only')
  .action(async () => {
    await serveMcp(process.stdin, process.stdout);
  });

await program.parseAsync();

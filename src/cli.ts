#!/usr/bin/env node
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { Command, Option } from 'commander';
import pc from 'picocolors';
import { addAiAdvice } from './ai/explain';
import { AI_PROVIDERS, type AiProviderId } from './ai/providers';
import { TargetNotFoundError, runAudit } from './audit';
import { renderHtml } from './html';
import { detectLang, isLang, messages, type Lang } from './i18n';
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
  .option(
    '--ai [provider]',
    'explications IA optionnelles : claude | openai | ollama (clé via ANTHROPIC_API_KEY / OPENAI_API_KEY) / optional AI explanations',
  )
  .option('--no-history', "ne pas analyser l'historique git / skip git history")
  .option(
    '--offline',
    'aucun accès réseau : ni OSV ni IA distante / no network: no OSV check, no remote AI',
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

    try {
      const offline = opts.offline ?? false;
      const result = await runAudit(dir, { history: opts.history, offline });
      if (aiChoice) await addAiAdvice(result, aiChoice, { lang, offline, env: process.env });

      if (opts.json) {
        const findings = result.findings.map((f) => ({ ...f, ...localizeFinding(f, lang) }));
        process.stdout.write(`${JSON.stringify({ ...result, lang, findings }, null, 2)}\n`);
      } else {
        process.stdout.write(
          `${renderReport(result, { lang, color: opts.color && pc.isColorSupported, verbose: opts.verbose ?? false })}\n`,
        );
      }

      const blocking = result.findings.some((f) => f.severity === 'critical' || f.severity === 'high');
      process.exitCode = blocking ? 1 : 0;

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

await program.parseAsync();

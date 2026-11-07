#!/usr/bin/env node
import { Command, Option } from 'commander';
import pc from 'picocolors';
import { TargetNotFoundError, runAudit } from './audit';
import { detectLang, isLang, messages, type Lang } from './i18n';
import { localizeFinding, renderReport } from './report';
import { VERSION } from './version';

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
  .option('--no-history', "ne pas analyser l'historique git / skip git history")
  .option('--offline', 'aucun accès réseau : dépendances non vérifiées sur OSV / no network: skip the OSV dependency check')
  .option('--no-color', 'désactiver les couleurs / disable colors')
  .action(async (dir: string, opts: { lang?: string; json?: boolean; history: boolean; offline?: boolean; color: boolean }) => {
    const lang: Lang = opts.lang && isLang(opts.lang) ? opts.lang : detectLang();
    try {
      const result = await runAudit(dir, { history: opts.history, offline: opts.offline ?? false });
      if (opts.json) {
        const findings = result.findings.map((f) => ({ ...f, ...localizeFinding(f, lang) }));
        process.stdout.write(`${JSON.stringify({ ...result, lang, findings }, null, 2)}\n`);
      } else {
        process.stdout.write(
          `${renderReport(result, { lang, color: opts.color && pc.isColorSupported })}\n`,
        );
      }
      const blocking = result.findings.some((f) => f.severity === 'critical' || f.severity === 'high');
      process.exitCode = blocking ? 1 : 0;
    } catch (err) {
      if (err instanceof TargetNotFoundError) {
        process.stderr.write(`${messages(lang).ui.targetNotFound(err.target)}\n`);
        process.exitCode = 2;
        return;
      }
      throw err;
    }
  });

await program.parseAsync();

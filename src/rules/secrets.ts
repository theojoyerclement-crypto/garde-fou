import {
  PROVIDER_LABELS,
  basenameOf,
  detectSecrets,
  isEnvFile,
  isEnvTemplate,
  lineOf,
  maskSecret,
} from '../patterns';
import type { Finding, Rule, ScanContext } from '../types';

/**
 * Hard-coded provider keys (OpenAI, Anthropic, Stripe live, Supabase
 * service_role / secret) in the working tree AND in the git history.
 *
 * Not reported here (no false positives):
 * - secrets in gitignored files: that is where they belong;
 * - secrets in an untracked, non-template `.env`: the env rule reports the
 *   file itself as at risk instead.
 */
export const secretsRule: Rule = {
  id: 'secrets',
  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const seenValues = new Set<string>();
    const seenLocations = new Set<string>();

    for (const f of ctx.files) {
      if (f.gitignored) continue;
      const name = basenameOf(f.rel);
      if (isEnvFile(name) && !isEnvTemplate(name) && !ctx.git?.tracked.has(f.rel)) continue;

      for (const m of detectSecrets(f.content)) {
        const line = lineOf(f.content, m.index);
        const key = `${f.rel}:${line}:${m.value}`;
        if (seenLocations.has(key)) continue;
        seenLocations.add(key);
        seenValues.add(m.value);
        findings.push({
          ruleId: 'secrets',
          severity: 'critical',
          messageId: 'secret.file',
          params: { provider: PROVIDER_LABELS[m.provider], masked: maskSecret(m.value) },
          file: f.rel,
          line,
        });
      }
    }

    // History: only secrets no longer visible in the current files.
    for (const h of ctx.git?.history ?? []) {
      for (const m of detectSecrets(h.text)) {
        if (seenValues.has(m.value)) continue;
        seenValues.add(m.value);
        findings.push({
          ruleId: 'secrets',
          severity: 'critical',
          messageId: 'secret.history',
          params: {
            provider: PROVIDER_LABELS[m.provider],
            masked: maskSecret(m.value),
            commit: h.commit.slice(0, 7),
          },
          file: h.file,
          commit: h.commit.slice(0, 7),
        });
      }
    }

    return findings;
  },
};

import {
  PROVIDER_LABELS,
  basenameOf,
  detectSecrets,
  isEnvFile,
  isEnvTemplate,
  lineOf,
} from '../patterns';
import type { Finding, Rule, ScanContext } from '../types';

/** Prefixes that make a variable end up in the client bundle. */
export const PUBLIC_PREFIXES = ['NEXT_PUBLIC_', 'VITE_', 'EXPO_PUBLIC_', 'REACT_APP_'] as const;

/** Name tokens that always denote a server-only value. */
const SENSITIVE_TOKENS = new Set(['SECRET', 'PASSWORD', 'PASSWD']);
/** Token sequences that denote a server-only value. */
const SENSITIVE_SEQUENCES: readonly string[][] = [
  ['SERVICE', 'ROLE'],
  ['SERVICE', 'KEY'],
  ['PRIVATE', 'KEY'],
  ['OPENAI', 'API', 'KEY'],
  ['OPENAI', 'KEY'],
  ['ANTHROPIC', 'API', 'KEY'],
  ['ANTHROPIC', 'KEY'],
  ['CLAUDE', 'API', 'KEY'],
  ['DATABASE', 'URL'],
  ['POSTGRES', 'URL'],
];

const CODE_EXTENSIONS = /\.(c|m)?(j|t)sx?$|\.(vue|svelte|astro)$/i;

export function publicPrefixOf(name: string): string | null {
  return PUBLIC_PREFIXES.find((p) => name.startsWith(p)) ?? null;
}

/** True when a public-prefixed variable name obviously holds a server secret. */
export function isSensitiveName(name: string): boolean {
  const prefix = publicPrefixOf(name);
  const rest = prefix ? name.slice(prefix.length) : name;
  const tokens = rest.toUpperCase().split('_').filter(Boolean);
  if (tokens.some((t) => SENSITIVE_TOKENS.has(t))) return true;
  return SENSITIVE_SEQUENCES.some((seq) =>
    tokens.some((_, i) => seq.every((s, j) => tokens[i + j] === s)),
  );
}

const ENV_LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$/;
const CODE_REF =
  /(?:process\.env\.|import\.meta\.env\.|process\.env\[\s*['"`])((?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_)[A-Za-z0-9_]+)/g;

export const envRule: Rule = {
  id: 'env',
  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    const tracked = ctx.git?.tracked;

    for (const f of ctx.files) {
      const name = basenameOf(f.rel);

      if (isEnvFile(name)) {
        // 1. Is the .env file committed / about to be committed?
        if (!isEnvTemplate(name)) {
          if (tracked?.has(f.rel)) {
            findings.push({
              ruleId: 'env',
              severity: 'high',
              messageId: 'env.tracked',
              params: { file: f.rel },
              file: f.rel,
            });
          } else if (!f.gitignored) {
            const hasSecrets = detectSecrets(f.content).length > 0;
            findings.push({
              ruleId: 'env',
              severity: hasSecrets ? 'high' : 'medium',
              messageId: 'env.notIgnored',
              params: { file: f.rel },
              file: f.rel,
            });
          }
        }

        // 2. Secrets declared with a public prefix (even in gitignored files: they ship to the browser).
        const lines = f.content.split(/\r?\n/);
        lines.forEach((text, i) => {
          const m = ENV_LINE.exec(text);
          const varName = m?.[1];
          if (!m || !varName) return;
          const prefix = publicPrefixOf(varName);
          if (!prefix) return;
          const secret = detectSecrets(m[2] ?? '')[0];
          if (secret) {
            findings.push({
              ruleId: 'env',
              severity: 'critical',
              messageId: 'env.publicSecretValue',
              params: { name: varName, prefix, provider: PROVIDER_LABELS[secret.provider] },
              file: f.rel,
              line: i + 1,
            });
          } else if (isSensitiveName(varName)) {
            findings.push({
              ruleId: 'env',
              severity: 'high',
              messageId: 'env.publicSensitive',
              params: { name: varName, prefix },
              file: f.rel,
              line: i + 1,
            });
          }
        });
        continue;
      }

      // 3. Sensitive public variables read from client-side code.
      if (f.gitignored || !CODE_EXTENSIONS.test(name)) continue;
      const seen = new Set<string>();
      for (const m of f.content.matchAll(CODE_REF)) {
        const varName = m[1];
        if (!varName || seen.has(varName) || !isSensitiveName(varName)) continue;
        seen.add(varName);
        findings.push({
          ruleId: 'env',
          severity: 'high',
          messageId: 'env.publicSensitive',
          params: { name: varName, prefix: publicPrefixOf(varName) ?? '' },
          file: f.rel,
          line: lineOf(f.content, m.index ?? 0),
        });
      }
    }

    // 4. .env files committed in the past and since removed from the index.
    for (const [file, commit] of ctx.git?.filesInHistory ?? []) {
      const name = basenameOf(file);
      if (!isEnvFile(name) || isEnvTemplate(name) || tracked?.has(file)) continue;
      findings.push({
        ruleId: 'env',
        severity: 'high',
        messageId: 'env.history',
        params: { file, commit: commit.slice(0, 7) },
        file,
        commit: commit.slice(0, 7),
      });
    }

    return findings;
  },
};

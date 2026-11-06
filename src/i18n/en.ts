import type { Messages } from './types';

export const en: Messages = {
  severity: { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' },
  findings: {
    'secret.file': {
      title: (p) => `${p.provider} key hard-coded in the source (${p.masked})`,
      why: () =>
        'Anyone who sees this file (public repo, teammate, third-party tool) can use this key on your bill or reach your data.',
      fix: () =>
        'Revoke the key at the provider and create a new one, store it in a .env file ignored by git, and read it through process.env on the server.',
    },
    'secret.history': {
      title: (p) => `${p.provider} key found in git history (${p.masked}, commit ${p.commit})`,
      why: () =>
        'The key is gone from the current code but still readable in git history: anyone who clones the repo can find it.',
      fix: () =>
        'Treat the key as compromised: revoke and replace it. Deleting the file is not enough; rewriting history (git filter-repo) is optional once the key is revoked.',
    },
    'env.tracked': {
      title: (p) => `${p.file} is committed to git`,
      why: () =>
        'A .env file is where secrets live. If git tracks it, it ships with every push and every clone.',
      fix: (p) =>
        `Run "git rm --cached ${p.file}", add it to .gitignore, then revoke the keys it contained. Commit a value-less .env.example instead.`,
    },
    'env.history': {
      title: (p) => `${p.file} found in git history (commit ${p.commit})`,
      why: () =>
        'This .env is no longer tracked, but it was committed once: its content is still readable in history.',
      fix: () => 'Revoke every key it may have contained. Make sure it is listed in .gitignore.',
    },
    'env.notIgnored': {
      title: (p) => `${p.file} is not protected by .gitignore`,
      why: () =>
        'It is not committed yet, but the next "git add ." will push it, secrets included.',
      fix: () => 'Add ".env*" and "!.env.example" to your .gitignore.',
    },
    'env.publicSensitive': {
      title: (p) => `Sensitive variable exposed to the browser: ${p.name}`,
      why: (p) =>
        `The ${p.prefix} prefix tells the framework to inline the value into the JavaScript sent to visitors. Anyone can read it in the dev tools.`,
      fix: (p) =>
        `Rename the variable without the ${p.prefix} prefix and use it on the server only (API route, server action, edge function). If the value was already deployed, revoke it.`,
    },
    'env.publicSecretValue': {
      title: (p) => `${p.provider} key exposed to the browser through ${p.name}`,
      why: (p) =>
        `This variable holds a real secret key and the ${p.prefix} prefix publishes it in the code sent to every visitor.`,
      fix: (p) =>
        `Revoke the key now, drop the ${p.prefix} prefix and move the call to the server.`,
    },
  },
  ui: {
    title: (target) => `Garde-Fou — audit of ${target}`,
    filesScanned: (n) => `${n} file${n === 1 ? '' : 's'} scanned`,
    gitHistoryScanned: 'git history scanned',
    gitHistorySkipped: 'git history skipped (--no-history)',
    noGit: 'not a git repository',
    noIssues: 'No issues found.',
    why: 'Why',
    fix: 'Fix',
    inHistory: (commit) => `git history, commit ${commit}`,
    score: 'Score',
    summary: (c) => `${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low`,
    verdict: (s) =>
      s >= 90
        ? 'Nothing alarming.'
        : s >= 60
          ? 'Fix these before going live.'
          : 'Do not put this project online as it is.',
    targetNotFound: (t) => `Directory not found: ${t}`,
  },
};

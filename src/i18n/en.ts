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
      prompt: (p) =>
        `A ${p.provider} key is hard-coded in ${p.location}. Remove it from the code and read it from a server-only environment variable (process.env), without a NEXT_PUBLIC_ or VITE_ prefix. Add the variable without a value to .env.example and make sure .env is in .gitignore. If this code runs in the browser, move the call to an API route or an edge function. Never copy the key's value.`,
    },
    'secret.history': {
      title: (p) => `${p.provider} key found in git history (${p.masked}, commit ${p.commit})`,
      why: () =>
        'The key is gone from the current code but still readable in git history: anyone who clones the repo can find it.',
      fix: () =>
        'Treat the key as compromised: revoke and replace it. Deleting the file is not enough; rewriting history (git filter-repo) is optional once the key is revoked.',
      prompt: (p) =>
        `A ${p.provider} key was committed in ${p.location} (commit ${p.commit}). I will revoke it myself at the provider. Check that no file in the project still contains a hard-coded key: every key must be read through process.env on the server, and .env must be in .gitignore.`,
    },
    'env.tracked': {
      title: (p) => `${p.file} is committed to git`,
      why: () =>
        'A .env file is where secrets live. If git tracks it, it ships with every push and every clone.',
      fix: (p) =>
        `Run "git rm --cached ${p.file}", add it to .gitignore, then revoke the keys it contained. Commit a value-less .env.example instead.`,
      prompt: (p) =>
        `The file ${p.file} is tracked by git although it holds secrets. Add ".env*" and "!.env.example" to .gitignore, create a .env.example with the same variable names but no values, and give me the command "git rm --cached ${p.file}" to run. Do not delete the file from my disk.`,
    },
    'env.history': {
      title: (p) => `${p.file} found in git history (commit ${p.commit})`,
      why: () =>
        'This .env is no longer tracked, but it was committed once: its content is still readable in history.',
      fix: () => 'Revoke every key it may have contained. Make sure it is listed in .gitignore.',
      prompt: () =>
        `A .env file was committed in the past. Make sure .gitignore contains ".env*" and "!.env.example", and that a value-less .env.example documents the required variables. I will revoke the affected keys myself.`,
    },
    'env.notIgnored': {
      title: (p) => `${p.file} is not protected by .gitignore`,
      why: () =>
        'It is not committed yet, but the next "git add ." will push it, secrets included.',
      fix: () => 'Add ".env*" and "!.env.example" to your .gitignore.',
      prompt: (p) =>
        `The file ${p.file} is not ignored by git. Add ".env*" and "!.env.example" to the .gitignore at the project root, and create a .env.example with the same variable names but no values.`,
    },
    'env.publicSensitive': {
      title: (p) => `Sensitive variable exposed to the browser: ${p.name}`,
      why: (p) =>
        `The ${p.prefix} prefix tells the framework to inline the value into the JavaScript sent to visitors. Anyone can read it in the dev tools.`,
      fix: (p) =>
        `Rename the variable without the ${p.prefix} prefix and use it on the server only (API route, server action, edge function). If the value was already deployed, revoke it.`,
      prompt: (p) =>
        `The variable ${p.name} (${p.location}) has the ${p.prefix} prefix, so its secret value is sent to the browser. Rename it without the ${p.prefix} prefix in the .env files and across the code, and only read it on the server (API route, server action or edge function). If browser code uses it, create a server route that makes the call instead and call that route from the front end.`,
    },
    'env.publicSecretValue': {
      title: (p) => `${p.provider} key exposed to the browser through ${p.name}`,
      why: (p) =>
        `This variable holds a real secret key and the ${p.prefix} prefix publishes it in the code sent to every visitor.`,
      fix: (p) =>
        `Revoke the key now, drop the ${p.prefix} prefix and move the call to the server.`,
      prompt: (p) =>
        `The variable ${p.name} holds a secret ${p.provider} key and its ${p.prefix} prefix sends it to the browser. Rename it without the ${p.prefix} prefix everywhere (.env files and code), use it on the server only (API route, server action or edge function) and update the front end to go through that route. I will revoke the old key myself.`,
    },
    'supabase.noRls': {
      title: (p) => `Table ${p.table} has no Row Level Security (Supabase)`,
      why: () =>
        "Without RLS, anyone holding the anon key (it is public: visible in your site's code) can read, change and delete every row of this table through the Supabase API.",
      fix: (p) =>
        `Add a migration with "alter table public.${p.table} enable row level security;", then policies that restrict access (for example auth.uid() = user_id).`,
      prompt: (p) =>
        `In Supabase, the table public.${p.table} (${p.location}) has no Row Level Security: any visitor can read and change all its rows with the anon key. Create a new SQL migration that enables RLS (alter table public.${p.table} enable row level security) and adds minimal policies: each signed-in user only reads and changes their own rows (auth.uid() equal to the owner column, add it if it does not exist). Do not edit migrations that were already applied. Then tell me which app features relied on broader access.`,
    },
    'supabase.openWritePolicy': {
      title: (p) => `Policy "${p.policy}": anyone can ${p.command} on ${p.table}`,
      why: (p) =>
        `This policy's condition is "true": it checks nothing. The ${p.roles} role can therefore change or delete any row, other users' rows included (the anon key is public).`,
      fix: () =>
        'In a new migration, drop the policy and recreate it with a user-bound condition, for example "auth.uid() = user_id".',
      prompt: (p) =>
        `In Supabase, the policy "${p.policy}" on table ${p.table} (${p.location}) allows ${p.command} with the condition true, so anyone can change or delete other users' rows. Create a new migration that drops this policy and replaces it with one that limits ${p.command} to the signed-in user's rows (auth.uid() equal to the owner column), with a matching with check clause. Do not edit migrations that were already applied.`,
    },
    'supabase.openInsertPolicy': {
      title: (p) => `Policy "${p.policy}": anyone can add rows to ${p.table}`,
      why: () =>
        'The "true" condition lets anyone insert rows with any values (spam, fake accounts, data on behalf of someone else). Sometimes intended (public contact form): check it.',
      fix: () =>
        'If only signed-in users should write: "to authenticated" and "with check (auth.uid() = user_id)". If public inserts are intended, restrict the columns and add spam protection.',
      prompt: (p) =>
        `In Supabase, the policy "${p.policy}" on table ${p.table} (${p.location}) lets anyone insert rows (with check (true)). If this table is not a public form, create a new migration that replaces this policy with a to authenticated policy using with check (auth.uid() equal to the owner column). If public inserts are intended, change nothing and suggest how to limit abuse (allowed columns, constraints, rate limiting).`,
    },
    'supabase.openReadPolicy': {
      title: (p) => `Policy "${p.policy}": ${p.table} is readable by everyone`,
      why: (p) =>
        `The "true" condition makes every row of ${p.table} readable by the ${p.roles} role. Fine for public content (posts, products), not for personal data.`,
      fix: () =>
        'Make sure this table holds no sensitive column (email, phone, address, private data). Otherwise restrict reads with "auth.uid() = user_id".',
      prompt: (p) =>
        `In Supabase, the policy "${p.policy}" on table ${p.table} (${p.location}) makes every row readable with the condition true. Check whether this table holds personal or private data. If so, create a new migration that limits reads to the signed-in user's rows (auth.uid() equal to the owner column) or moves the sensitive columns to a protected table. If everything is public by design, change nothing and tell me.`,
    },
    'firebase.openWrite': {
      title: (p) => `${p.service}: anyone can write to ${p.path}`,
      why: () =>
        'The rule allows writes with no condition: anyone on the Internet can change, overwrite or erase this data, without even signing in.',
      fix: () =>
        'Require at least a signed-in user ("request.auth != null") and, better, that the user owns the data ("request.auth.uid == userId").',
      prompt: (p) =>
        `The ${p.service} security rules (${p.location}) let anyone write to ${p.path} with no condition. Rewrite these rules so that only a signed-in user can write, and only to their own data (request.auth != null and request.auth.uid equal to the owner id; for the Realtime Database: auth != null and auth.uid === $uid). Keep the rest of the app working and list the screens that might depend on it.`,
    },
    'firebase.openRead': {
      title: (p) => `${p.service}: the whole database is readable by everyone`,
      why: () =>
        'The rule grants read access to all data with no condition: anyone can download the entire database (accounts, messages, orders…).',
      fix: () => 'Remove the global rule and open reads collection by collection, only for what is truly public.',
      prompt: (p) =>
        `The ${p.service} rules (${p.location}) allow reading the whole database (${p.path}) with no condition. Replace this global rule with per-collection rules: public reads only for truly public data, and for everything else reads restricted to the signed-in owner (request.auth.uid). List the collections and what you chose for each.`,
    },
    'firebase.testMode': {
      title: (p) => `${p.service}: "test mode" rules open to everyone until a date`,
      why: () =>
        'These are the default test-mode rules: until the given date, anyone can read and change the data. After that, the app stops working.',
      fix: () => 'Replace them with real rules based on request.auth before going live.',
      prompt: (p) =>
        `The ${p.service} rules (${p.location}) are still the test-mode ones (request.time < timestamp.date(...)): anyone can read and write. Write real security rules: reads and writes restricted to the signed-in user on their own data (request.auth.uid), public reads only for truly public collections. Explain each rule.`,
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
    prompt: 'Prompt to paste into your AI tool',
    notes: {
      'osv.checked': 'dependencies checked against OSV',
      'osv.offline': 'dependencies not checked (--offline)',
      'osv.error': 'OSV unreachable: dependencies not checked',
    },
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

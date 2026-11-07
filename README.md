# Garde-Fou

> Audit de sécurité local pour les projets générés par IA. · Local security audit for AI-generated projects.

```bash
npx gardefou [dossier]
```

## Français

Votre app a été écrite par une IA (Cursor, Bolt, Lovable, v0, Claude Code…) ? Avant de la
mettre en ligne, **Garde-Fou** vérifie en quelques secondes, **sur votre machine**, les erreurs
qui coûtent le plus cher :

| Vérification | Gravité |
| --- | --- |
| Clé OpenAI, Anthropic, Stripe live ou Supabase `service_role` en clair dans le code, ou dans l'**historique git** | critique |
| Clé secrète placée dans une variable `NEXT_PUBLIC_*` / `VITE_*` (envoyée au navigateur) | critique |
| Table Supabase sans **Row Level Security** (migrations `supabase/**.sql`) | critique |
| Règles Firebase qui laissent **écrire tout le monde** (`allow write`, `if true`) | critique |
| Policy Supabase `using (true)` en update / delete / all | élevé |
| Règles Firebase : lecture de toute la base sans condition, ou « mode test » | élevé |
| Route API (Next.js, Express, Supabase Edge Function) qui utilise la clé `service_role`, un SDK admin, une écriture en base ou une **API d'IA payante** sans vérifier qui l'appelle | élevé |
| Dépendance de production avec une **vulnérabilité connue** (base [OSV](https://osv.dev)) | selon l'avis |
| Fichier `.env` commité, ou présent dans l'historique git | élevé |
| Variable sensible (`…_SECRET`, `…_SERVICE_ROLE_KEY`, `…_OPENAI_API_KEY`…) avec un préfixe public | élevé |
| Policy Supabase `with check (true)` en insert | moyen |
| Fichier `.env` non protégé par `.gitignore` | moyen (élevé s'il contient des clés) |
| Policy Supabase `using (true)` en lecture (normal pour du contenu public : à vérifier) | faible |

Chaque problème est expliqué simplement, avec le correctif à appliquer et un **prompt prêt à
coller** dans Lovable, Cursor ou Claude Code pour le corriger. Le projet reçoit un **score sur 100**.

Principes : **zéro faux positif en priorité**, règles déterministes, aucune IA. Le seul accès
réseau est la vérification des dépendances sur OSV.dev : seuls les noms et versions des paquets
du `package-lock.json` sont envoyés, jamais votre code. `--offline` la désactive.

### Options

```bash
npx gardefou                 # audite le dossier courant
npx gardefou mon-projet      # audite un autre dossier
npx gardefou --lang en       # messages en anglais (fr / en, détecté automatiquement sinon)
npx gardefou --json          # sortie JSON (CI), avec textes et prompts localisés
npx gardefou --no-history    # ne pas lire l'historique git
npx gardefou --offline       # aucun accès réseau (dépendances non vérifiées)
```

Code de sortie `1` s'il y a au moins un problème critique ou élevé : idéal en CI.

## English

Your app was written by an AI? Before shipping it, **Garde-Fou** checks in seconds, **on your
machine**, for the most expensive mistakes: hard-coded OpenAI / Anthropic / Stripe live /
Supabase `service_role` keys (in files **and** git history), committed `.env` files, secrets
exposed to the browser through `NEXT_PUBLIC_*` / `VITE_*` variables, Supabase tables without
Row Level Security and `using (true)` policies, Firebase rules open to everyone, API routes
(Next.js, Express, Supabase Edge Functions) that use privileged access or a paid AI API without
checking the caller, and production dependencies with known vulnerabilities (OSV).

Every finding comes with a plain-language explanation, a fix, a **ready-to-paste prompt** for
your AI coding tool, and a score out of 100. The only network access is the OSV dependency
check (package names and versions only); `--offline` turns it off.

```bash
npx gardefou [dir] [--lang fr|en] [--json] [--no-history] [--offline] [--no-color]
```

Exit code `1` when at least one critical or high issue is found.

## Développement · Development

```bash
npm install
npm test                  # vitest — hors ligne, fausses clés générées à l'exécution
npm run fixture           # génère les fausses clés de fixtures/vulnerable-app (jamais commitées)
npx tsx src/cli.ts fixtures/vulnerable-app
npm run build
```

Fixtures : une app vulnérable par règle (`fixtures/vulnerable-app`, `supabase-rls`, `firebase`,
`api-auth`, `dependencies`) et `fixtures/clean-app`, sosie sécurisé de chaque cas (0 problème attendu).

Voir [CLAUDE.md](./CLAUDE.md) pour l'architecture et les règles de contribution.

## Licence

MIT

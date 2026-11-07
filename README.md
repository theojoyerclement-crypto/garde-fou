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
| Dépendance de production avec une **vulnérabilité connue** (base [OSV](https://osv.dev)), avec le paquet parent à mettre à jour ; ignorées : dépendances de dev et outils de build (`@expo/cli`, `metro`, `node-gyp`…) | selon l'avis |
| Outil de dev (jest, eslint…) rangé dans `dependencies` et qui amène des failles | faible |
| Fichier `.env` commité, ou présent dans l'historique git | élevé |
| Variable sensible (`…_SECRET`, `…_SERVICE_ROLE_KEY`, `…_OPENAI_API_KEY`…) avec un préfixe public | élevé |
| Policy Supabase `with check (true)` en insert | moyen |
| Fichier `.env` non protégé par `.gitignore` | moyen (élevé s'il contient des clés) |
| Policy Supabase `using (true)` en lecture (normal pour du contenu public : à vérifier) | faible |

Chaque problème est expliqué simplement, avec le correctif à appliquer et un **prompt prêt à
coller** dans Lovable, Cursor ou Claude Code pour le corriger. Le projet reçoit un **score sur 100**.

Principes : **zéro faux positif en priorité**, règles déterministes : la détection n'utilise
jamais d'IA. Par défaut, le seul accès réseau est la vérification des dépendances sur OSV.dev :
seuls les noms et versions des paquets du `package-lock.json` sont envoyés, jamais votre code.
`--offline` coupe tout accès réseau.

### Rapport HTML (`--html`)

`npx gardefou --html` écrit `garde-fou-report.html` (ou le fichier indiqué) : une page autonome,
sans ressource externe, lisible sur mobile, avec le score, les problèmes triés par gravité, un
détails repliés, un même problème présent dans plusieurs fichiers regroupé en une carte, un
bouton « Copier » pour chaque prompt et un lien « Signaler un faux positif » qui ouvre une issue
GitHub pré-remplie **sans secret, chemin ni code**. Le rapport contient les clés masquées
(`sk-proj-1f…DGqC`) : ne le commitez pas.

### Explications IA (`--ai`, optionnel)

```bash
ANTHROPIC_API_KEY=… npx gardefou --ai          # Claude (ou OpenAI si seule OPENAI_API_KEY existe)
npx gardefou --ai openai                         # OPENAI_API_KEY
npx gardefou --ai ollama                         # modèle local (OLLAMA_HOST, défaut 127.0.0.1:11434)
GARDEFOU_AI_MODEL=… npx gardefou --ai claude     # autre modèle (défaut : claude-opus-5-5 / gpt-4o-mini / llama3.2)
```

L'IA **n'ajoute ni ne retire aucun problème** et ne change ni la gravité ni le score : elle
explique les 10 problèmes les plus graves et adapte le correctif à votre code. Elle ne reçoit que
de courts extraits (±6 lignes) **après masquage des secrets** (clés, JWT, clés privées, mots de
passe dans les URL, valeurs des `.env`…) ; une requête qui contiendrait encore un secret
reconnaissable n'est pas envoyée. Sans clé, hors ligne ou en cas d'erreur, le rapport est
identique, avec une simple mention. Les réponses de l'IA sont à vérifier.

### Options

```bash
npx gardefou                 # audite le dossier courant
npx gardefou mon-projet      # audite un autre dossier
npx gardefou --lang en       # messages en anglais (fr / en, détecté automatiquement sinon)
npx gardefou --json          # sortie JSON (CI), avec textes et prompts localisés
npx gardefou --no-history    # ne pas lire l'historique git
npx gardefou --offline       # aucun accès réseau (ni OSV ni IA distante)
npx gardefou --html          # rapport HTML autonome (garde-fou-report.html)
npx gardefou --ai            # explications IA (Claude, OpenAI ou Ollama), optionnel
npx gardefou --verbose       # liste les dépendances ignorées (build, dev…) et leurs failles connues
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
your AI coding tool, and a score out of 100. Detection never uses AI. By default the only network
access is the OSV dependency check (package names and versions only); `--offline` turns off all
network access.

- `--verbose`: list every ignored dependency (build tools, devDependencies…) with what installs
  it and its known advisories. Without it, the report shows a one-line count.
- `--html [file]`: standalone HTML report (no external resource, mobile friendly) with collapsed
  details, repeated problems grouped into one card, copy buttons and a "report a false positive" link that opens a pre-filled GitHub issue with no
  secret, path or code. It contains masked keys: do not commit it.
- `--ai [claude|openai|ollama]`: optional AI explanations of the 10 most severe findings, with a
  fix adapted to your code. Keys from `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`, `OLLAMA_HOST` for a
  local model, `GARDEFOU_AI_MODEL` to change the model. Only short excerpts are sent, **after
  secrets are masked**. The AI never adds or removes findings; without a key or on error the
  report is unchanged.

```bash
npx gardefou [dir] [--lang fr|en] [--json] [--html [file]] [--ai [provider]] [--no-history] [--offline] [--no-color] [--verbose]
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
`api-auth`, `dependencies`, `dependencies-expo`, `dependencies-devtool`, `dependencies-native`) et `fixtures/clean-app`, sosie sécurisé de chaque cas (0 problème attendu).

Voir [CLAUDE.md](./CLAUDE.md) pour l'architecture et les règles de contribution.

## Licence

MIT

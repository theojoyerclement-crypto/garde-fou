# CLAUDE.md — Garde-Fou

## Contexte

**Garde-Fou** est un CLI Node/TypeScript qui audite **en local** un projet généré par IA
(Cursor, Bolt, Lovable, v0, Claude Code…) et signale les erreurs de sécurité typiques :
clés d'API en clair, `.env` commité, secrets exposés au navigateur, Supabase sans RLS,
règles Firebase ouvertes, routes API sans auth, dépendances vulnérables.

- Package npm : `gardefou` (le nom `garde-fou` est pris sur npm).
- Commande officielle : **`npx gardefou [dossier]`**. `package.json` expose aussi l'alias
  `garde-fou` (même fichier `dist/cli.js`) ; dans la doc et les messages, toujours écrire `npx gardefou`.
- Nom du produit : **Garde-Fou**.
- Public : des développeurs débutants ou pressés. Les messages doivent être compréhensibles
  sans culture sécurité.

## Règles du projet

1. **Messages FR + EN.** Tout texte affiché passe par `src/i18n/` (`fr.ts` et `en.ts`, même
   structure typée par `Messages`). Aucune chaîne utilisateur en dur dans les règles :
   une règle émet un `messageId` + des `params`. Chaque message a `title`, `why`, `fix`
   **et `prompt`** (prompt de correction prêt à coller dans Lovable / Cursor / Claude Code).
   Les `params` viennent du projet audité (non fiables) : `localizeFinding()` les nettoie
   (`cleanParam`, et `promptParam` pour les prompts) ; ne jamais les afficher sans passer par là.
2. **Zéro faux positif, priorité absolue.** Mieux vaut rater un cas que crier au loup.
   Dans le doute, on ne signale pas. Tout nouveau détecteur arrive avec des tests de
   faux positifs (placeholders, clés de test, valeurs publiques par design).
3. **Règles déterministes.** Regex strictes par fournisseur + validation (entropie de
   Shannon ≥ `MIN_ENTROPY`, filtre de placeholders, décodage JWT). Même entrée ⇒ même sortie.
4. **Pas d'IA.** Aucun LLM. Tout tourne en local, **sauf** la règle `dependencies` qui
   interroge OSV.dev (`src/osv.ts`, seul accès réseau ; noms + versions des paquets uniquement),
   désactivable avec `--offline`. Les tests n'accèdent jamais au réseau (client OSV factice).
5. **1 fichier par règle dans `src/rules/`**, enregistré dans `src/rules/index.ts`.
   Les détecteurs partagés vivent dans `src/patterns.ts`.
6. **Ne jamais afficher un secret en entier** : toujours `maskSecret()`.
7. **Jamais de vraie ou fausse clé en dur dans le dépôt** (GitHub push protection).
   Les fausses clés sont fabriquées à l'exécution par `scripts/fake-keys.ts`, en
   assemblant les préfixes par morceaux.

## Architecture

```
src/
  cli.ts          point d'entrée commander (--lang, --json, --no-history, --offline, --no-color)
  audit.ts        runAudit(dir) (async) : scanner + git + règles → findings triés + score + notes
  scanner.ts      parcours des fichiers ; respecte les .gitignore (du dossier racine git
                  jusqu'au dossier scanné) ; ignore toujours node_modules/, .git/, fixtures/ ;
                  garde les .env* gitignorés (marqués gitignored) pour la règle env
  git.ts          fichiers suivis (git ls-files) + lignes ajoutées dans tout l'historique
                  (git log -p --all), limité au dossier scanné
  patterns.ts     détecteurs de secrets, entropie, masquage, helpers .env
  osv.ts          client OSV.dev (querybatch + détails), sévérité, version corrigée, semver
  report.ts       tri par gravité, score /100, nettoyage des params, rendu terminal
  rules/          secrets.ts, env.ts, supabase-rls.ts, firebase-rules.ts, api-auth.ts,
                  dependencies.ts, index.ts
  i18n/           fr.ts, en.ts, types.ts, index.ts (détection de la langue)
  types.ts        Severity, Finding, Rule, ScanContext…
scripts/
  fake-keys.ts         générateurs de fausses clés (utilisés par les tests et la fixture)
  generate-fixture.ts  `npm run fixture` : écrit les fausses clés dans fixtures/vulnerable-app
fixtures/vulnerable-app/   secrets + env (fausses clés générées, jamais commitées)
fixtures/supabase-rls/     migrations sans RLS / policies using (true)
fixtures/firebase/         règles Firestore, Storage, Realtime Database ouvertes
fixtures/api-auth/         routes Next.js / Express / Edge Functions sans auth
fixtures/dependencies/     package-lock.json avec versions vulnérables
fixtures/clean-app/        sosie sécurisé de chaque cas : 0 problème attendu
test/                      tests vitest
```

## Gravité et score

`critical` (-30), `high` (-15), `medium` (-5), `low` (-2), score plancher 0.
Code de sortie : 1 s'il y a au moins un problème critique ou élevé, 2 si le dossier est introuvable.

## Règles actuelles

- **secrets** : OpenAI (`sk-proj-`, `sk-svcacct-`, `sk-admin-`, ancien format `T3BlbkFJ`),
  Anthropic (`sk-ant-api03-`, `sk-ant-admin01-`), Stripe live (`sk_live_`, `rk_live_`),
  Supabase (`sb_secret_`, JWT dont le payload a `role: service_role`). Fichiers + historique git.
  Non signalé : fichiers gitignorés, `.env` non suivi (couvert par la règle env).
- **supabase-rls** : rejoue `supabase/**.sql` dans l'ordre des noms. Table `public` sans RLS
  (critique) ; policy permissive `using (true)` en update/delete/all (élevé), `with check (true)`
  en insert (moyen), `using (true)` en select (faible). Commentaires, chaînes et corps de fonctions
  ignorés. Non signalé : tables temporaires / autre schéma, tables fermées (tous les privilèges
  révoqués à `anon` **et** `authenticated`, sans grant ni changement de propriétaire ensuite),
  policies restrictives, réservées aux rôles admin, supprimées ou modifiées ensuite.
- **firebase-rules** : `*.rules` (Firestore, Storage) : `allow write`/create/update/delete sans
  condition ou `if true` (critique), lecture sans condition sur `{document=**}` (élevé), mode test
  `request.time < timestamp.date(…)` (élevé). `database.rules.json` : `".write": true` (critique),
  `".read": true` à la racine (élevé). Lecture publique d'une collection précise : non signalée.
- **api-auth** (élevé) : route Next.js (`app/**/route.ts`, `pages/api/**`), Express ou Supabase
  Edge Function qui utilise un accès privilégié (service_role, firebase-admin, écritures
  Prisma/Drizzle/Mongo) ou une API d'IA payante, **et** dont le fichier ne contient aucun marqueur
  d'auth. Non signalé : routes publiques par nature (auth, login, signup, webhook, callback, cron,
  health, og), projets Next.js avec middleware/proxy, Express avec `.use(<auth>)`, tests.
- **dependencies** : versions exactes de `package-lock.json` / `npm-shrinkwrap.json` (v1-v3)
  vérifiées sur OSV ; un problème par paquet de production vulnérable, gravité = pire avis
  (inconnue ⇒ moyen), version corrigée. Ignorés : dev, liens, workspaces, versions non semver.
- **env** : `.env` suivi par git, `.env` présent dans l'historique, `.env` non protégé par
  `.gitignore`, variables sensibles avec préfixe public (`NEXT_PUBLIC_`, `VITE_`,
  `EXPO_PUBLIC_`, `REACT_APP_`) dans les `.env*` et dans le code.

## Commandes

```bash
npm test                 # vitest (génère ses fausses clés dans un dossier temporaire)
npm run typecheck        # tsc --noEmit
npm run build            # tsup → dist/cli.js
npm run fixture          # écrit les fausses clés dans fixtures/vulnerable-app (exclues via .git/info/exclude)
npx tsx src/cli.ts fixtures/vulnerable-app
```

## Ajouter une règle

1. Créer `src/rules/<nom>.ts` qui exporte un `Rule`.
2. Ajouter les `MessageId` dans `src/types.ts` et les textes (`title`, `why`, `fix`, `prompt`)
   dans `fr.ts` **et** `en.ts`.
3. L'enregistrer dans `src/rules/index.ts`.
4. Tests : vrais positifs + faux positifs. Une fixture vulnérable dédiée dans `fixtures/<règle>/`
   et son sosie sécurisé dans `fixtures/clean-app/` (le test clean-app exige 0 problème).

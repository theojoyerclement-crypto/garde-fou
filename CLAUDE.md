# CLAUDE.md — Garde-Fou

## Contexte

**Garde-Fou** est un CLI Node/TypeScript qui audite **en local** un projet généré par IA
(Cursor, Bolt, Lovable, v0, Claude Code…) et signale les erreurs de sécurité typiques :
clés d'API en clair, `.env` commité, secrets exposés au navigateur.

- Package npm : `gardefou` (le nom `garde-fou` est pris sur npm).
- Commande officielle : **`npx gardefou [dossier]`**. `package.json` expose aussi l'alias
  `garde-fou` (même fichier `dist/cli.js`) ; dans la doc et les messages, toujours écrire `npx gardefou`.
- Nom du produit : **Garde-Fou**.
- Public : des développeurs débutants ou pressés. Les messages doivent être compréhensibles
  sans culture sécurité.

## Règles du projet

1. **Messages FR + EN.** Tout texte affiché passe par `src/i18n/` (`fr.ts` et `en.ts`, même
   structure typée par `Messages`). Aucune chaîne utilisateur en dur dans les règles :
   une règle émet un `messageId` + des `params`.
2. **Zéro faux positif, priorité absolue.** Mieux vaut rater un cas que crier au loup.
   Dans le doute, on ne signale pas. Tout nouveau détecteur arrive avec des tests de
   faux positifs (placeholders, clés de test, valeurs publiques par design).
3. **Règles déterministes.** Regex strictes par fournisseur + validation (entropie de
   Shannon ≥ `MIN_ENTROPY`, filtre de placeholders, décodage JWT). Même entrée ⇒ même sortie.
4. **Pas d'IA pour l'instant.** Aucun appel réseau, aucun LLM. Tout tourne en local.
5. **1 fichier par règle dans `src/rules/`**, enregistré dans `src/rules/index.ts`.
   Les détecteurs partagés vivent dans `src/patterns.ts`.
6. **Ne jamais afficher un secret en entier** : toujours `maskSecret()`.
7. **Jamais de vraie ou fausse clé en dur dans le dépôt** (GitHub push protection).
   Les fausses clés sont fabriquées à l'exécution par `scripts/fake-keys.ts`, en
   assemblant les préfixes par morceaux.

## Architecture

```
src/
  cli.ts          point d'entrée commander (options --lang, --json, --no-history, --no-color)
  audit.ts        runAudit(dir) : scanner + git + règles → findings triés + score
  scanner.ts      parcours des fichiers ; respecte les .gitignore (du dossier racine git
                  jusqu'au dossier scanné) ; ignore toujours node_modules/, .git/, fixtures/ ;
                  garde les .env* gitignorés (marqués gitignored) pour la règle env
  git.ts          fichiers suivis (git ls-files) + lignes ajoutées dans tout l'historique
                  (git log -p --all), limité au dossier scanné
  patterns.ts     détecteurs de secrets, entropie, masquage, helpers .env
  report.ts       tri par gravité, score /100, rendu terminal
  rules/          secrets.ts, env.ts, index.ts
  i18n/           fr.ts, en.ts, types.ts, index.ts (détection de la langue)
  types.ts        Severity, Finding, Rule, ScanContext…
scripts/
  fake-keys.ts         générateurs de fausses clés (utilisés par les tests et la fixture)
  generate-fixture.ts  `npm run fixture` : écrit les fausses clés dans fixtures/vulnerable-app
fixtures/vulnerable-app/   app volontairement vulnérable (sans clés commitées)
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
2. Ajouter les `MessageId` dans `src/types.ts` et les textes dans `fr.ts` **et** `en.ts`.
3. L'enregistrer dans `src/rules/index.ts`.
4. Tests : vrais positifs + faux positifs ; compléter `fixtures/vulnerable-app` si utile.

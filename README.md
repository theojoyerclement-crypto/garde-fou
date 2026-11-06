# Garde-Fou

> Audit de sécurité local pour les projets générés par IA. · Local security audit for AI-generated projects.

```bash
npx gardefou [dossier]
```

## Français

Votre app a été écrite par une IA (Cursor, Bolt, Lovable, v0, Claude Code…) ? Avant de la
mettre en ligne, **Garde-Fou** vérifie en quelques secondes, **sans rien envoyer sur Internet**,
les erreurs qui coûtent le plus cher :

| Vérification | Gravité |
| --- | --- |
| Clé OpenAI, Anthropic, Stripe live ou Supabase `service_role` en clair dans le code | critique |
| …ou toujours présente dans l'**historique git** | critique |
| Clé secrète placée dans une variable `NEXT_PUBLIC_*` / `VITE_*` (envoyée au navigateur) | critique |
| Fichier `.env` commité, ou présent dans l'historique git | élevé |
| Variable sensible (`…_SECRET`, `…_SERVICE_ROLE_KEY`, `…_OPENAI_API_KEY`…) avec un préfixe public | élevé |
| Fichier `.env` non protégé par `.gitignore` | moyen (élevé s'il contient des clés) |

Chaque problème est expliqué simplement, avec le correctif à appliquer, et le projet reçoit un **score sur 100**.

Principes : **zéro faux positif en priorité**, règles déterministes (regex + entropie), aucun appel réseau, aucune IA.

### Options

```bash
npx gardefou                 # audite le dossier courant
npx gardefou mon-projet      # audite un autre dossier
npx gardefou --lang en       # messages en anglais (fr / en, détecté automatiquement sinon)
npx gardefou --json          # sortie JSON (CI)
npx gardefou --no-history    # ne pas lire l'historique git
```

Code de sortie `1` s'il y a au moins un problème critique ou élevé : idéal en CI.

## English

Your app was written by an AI? Before shipping it, **Garde-Fou** checks in seconds, **fully
offline**, for the most expensive mistakes: hard-coded OpenAI / Anthropic / Stripe live /
Supabase `service_role` keys (in files **and** git history), committed `.env` files, and
secrets exposed to the browser through `NEXT_PUBLIC_*` / `VITE_*` variables. Every finding
comes with a plain-language explanation, a fix and a score out of 100.

```bash
npx gardefou [dir] [--lang fr|en] [--json] [--no-history] [--no-color]
```

Exit code `1` when at least one critical or high issue is found.

## Développement · Development

```bash
npm install
npm test                  # vitest — les fausses clés sont générées à l'exécution
npm run fixture           # génère les fausses clés de fixtures/vulnerable-app (jamais commitées)
npx tsx src/cli.ts fixtures/vulnerable-app
npm run build
```

Voir [CLAUDE.md](./CLAUDE.md) pour l'architecture et les règles de contribution.

## Licence

MIT

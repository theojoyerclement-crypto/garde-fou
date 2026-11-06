# vulnerable-app

Application volontairement vulnérable, utilisée pour tester Garde-Fou.
Deliberately insecure app used to test Garde-Fou.

Les fichiers contenant de (fausses) clés ne sont **pas** commités : ils sont
générés à la demande par `npm run fixture` (et à chaque exécution de `npm test`,
dans un dossier temporaire).
Files containing (fake) keys are **not** committed: they are generated on
demand by `npm run fixture` (and by `npm test`, in a temporary directory).

Generated: `.env`, `src/lib/ai.generated.ts`, `src/lib/payments.generated.ts`.

Mentioning process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY in Markdown is
not a finding: only code and .env files are checked.

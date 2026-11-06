import type { Messages } from './types';

export const fr: Messages = {
  severity: { critical: 'CRITIQUE', high: 'ÉLEVÉ', medium: 'MOYEN', low: 'FAIBLE' },
  findings: {
    'secret.file': {
      title: (p) => `Clé ${p.provider} en clair dans le code (${p.masked})`,
      why: () =>
        "Toute personne qui voit ce fichier (dépôt public, collègue, outil tiers) peut utiliser cette clé à vos frais ou accéder à vos données.",
      fix: () =>
        "Révoquez la clé chez le fournisseur et créez-en une nouvelle, placez-la dans un fichier .env ignoré par git, puis lisez-la via process.env côté serveur.",
    },
    'secret.history': {
      title: (p) => `Clé ${p.provider} présente dans l'historique git (${p.masked}, commit ${p.commit})`,
      why: () =>
        "La clé a disparu du code actuel mais reste lisible dans l'historique git : quiconque clone le dépôt peut la retrouver.",
      fix: () =>
        "Considérez la clé comme compromise : révoquez-la et remplacez-la. Supprimer le fichier ne suffit pas ; réécrire l'historique (git filter-repo) est optionnel une fois la clé révoquée.",
    },
    'env.tracked': {
      title: (p) => `Fichier ${p.file} commité dans git`,
      why: () =>
        "Un fichier .env sert à stocker des secrets. S'il est suivi par git, il part avec chaque push et chaque clone.",
      fix: (p) =>
        `Exécutez « git rm --cached ${p.file} », ajoutez-le à .gitignore, puis révoquez les clés qu'il contenait. Commitez plutôt un .env.example sans valeurs.`,
    },
    'env.history': {
      title: (p) => `Fichier ${p.file} présent dans l'historique git (commit ${p.commit})`,
      why: () =>
        "Ce .env n'est plus suivi, mais il a été commité un jour : son contenu reste lisible dans l'historique.",
      fix: () =>
        "Révoquez toutes les clés qu'il a pu contenir. Vérifiez qu'il est bien dans .gitignore.",
    },
    'env.notIgnored': {
      title: (p) => `Fichier ${p.file} non protégé par .gitignore`,
      why: () =>
        "Il n'est pas encore commité, mais le prochain « git add . » l'enverra dans le dépôt avec tous ses secrets.",
      fix: () => "Ajoutez « .env* » et « !.env.example » à votre .gitignore.",
    },
    'env.publicSensitive': {
      title: (p) => `Variable sensible exposée au navigateur : ${p.name}`,
      why: (p) =>
        `Le préfixe ${p.prefix} demande au framework d'inclure la valeur dans le JavaScript envoyé aux visiteurs. N'importe qui peut la lire dans les outils de développement.`,
      fix: (p) =>
        `Renommez la variable sans le préfixe ${p.prefix} et n'utilisez-la que côté serveur (route API, server action, edge function). Si la valeur a déjà été déployée, révoquez-la.`,
    },
    'env.publicSecretValue': {
      title: (p) => `Clé ${p.provider} exposée au navigateur via ${p.name}`,
      why: (p) =>
        `Cette variable contient une vraie clé secrète et le préfixe ${p.prefix} la publie dans le code envoyé à chaque visiteur.`,
      fix: (p) =>
        `Révoquez la clé immédiatement, retirez le préfixe ${p.prefix} et déplacez l'appel côté serveur.`,
    },
  },
  ui: {
    title: (target) => `Garde-Fou — audit de ${target}`,
    filesScanned: (n) => `${n} fichier${n > 1 ? 's' : ''} analysé${n > 1 ? 's' : ''}`,
    gitHistoryScanned: 'historique git analysé',
    gitHistorySkipped: 'historique git ignoré (--no-history)',
    noGit: 'pas de dépôt git',
    noIssues: 'Aucun problème détecté.',
    why: 'Pourquoi',
    fix: 'Correctif',
    inHistory: (commit) => `historique git, commit ${commit}`,
    score: 'Score',
    summary: (c) =>
      `${c.critical} critique${c.critical > 1 ? 's' : ''}, ${c.high} élevé${c.high > 1 ? 's' : ''}, ${c.medium} moyen${c.medium > 1 ? 's' : ''}, ${c.low} faible${c.low > 1 ? 's' : ''}`,
    verdict: (s) =>
      s >= 90
        ? 'Rien d’alarmant.'
        : s >= 60
          ? 'À corriger avant de mettre en ligne.'
          : 'Ne mettez pas ce projet en ligne en l’état.',
    targetNotFound: (t) => `Dossier introuvable : ${t}`,
  },
};

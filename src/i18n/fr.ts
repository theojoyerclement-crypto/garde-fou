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
      prompt: (p) =>
        `Une clé ${p.provider} est écrite en dur dans ${p.location}. Retire-la du code et lis-la depuis une variable d'environnement côté serveur uniquement (process.env), sans préfixe NEXT_PUBLIC_ ni VITE_. Ajoute la variable sans valeur dans .env.example et vérifie que .env est dans .gitignore. Si ce code tourne dans le navigateur, déplace l'appel dans une route API ou une edge function. Ne recopie jamais la valeur de la clé.`,
    },
    'secret.history': {
      title: (p) => `Clé ${p.provider} présente dans l'historique git (${p.masked}, commit ${p.commit})`,
      why: () =>
        "La clé a disparu du code actuel mais reste lisible dans l'historique git : quiconque clone le dépôt peut la retrouver.",
      fix: () =>
        "Considérez la clé comme compromise : révoquez-la et remplacez-la. Supprimer le fichier ne suffit pas ; réécrire l'historique (git filter-repo) est optionnel une fois la clé révoquée.",
      prompt: (p) =>
        `Une clé ${p.provider} a été commitée dans ${p.location} (commit ${p.commit}). Je la révoque moi-même chez le fournisseur. Vérifie que plus aucun fichier du projet ne contient de clé en dur : toutes les clés doivent être lues via process.env côté serveur, et .env doit être dans .gitignore.`,
    },
    'env.tracked': {
      title: (p) => `Fichier ${p.file} commité dans git`,
      why: () =>
        "Un fichier .env sert à stocker des secrets. S'il est suivi par git, il part avec chaque push et chaque clone.",
      fix: (p) =>
        `Exécutez « git rm --cached ${p.file} », ajoutez-le à .gitignore, puis révoquez les clés qu'il contenait. Commitez plutôt un .env.example sans valeurs.`,
      prompt: (p) =>
        `Le fichier ${p.file} est suivi par git alors qu'il contient des secrets. Ajoute « .env* » et « !.env.example » à .gitignore, crée un .env.example avec les mêmes noms de variables mais sans aucune valeur, et donne-moi la commande « git rm --cached ${p.file} » à lancer. Ne supprime pas le fichier de mon disque.`,
    },
    'env.history': {
      title: (p) => `Fichier ${p.file} présent dans l'historique git (commit ${p.commit})`,
      why: () =>
        "Ce .env n'est plus suivi, mais il a été commité un jour : son contenu reste lisible dans l'historique.",
      fix: () =>
        "Révoquez toutes les clés qu'il a pu contenir. Vérifiez qu'il est bien dans .gitignore.",
      prompt: () =>
        `Un fichier .env a été commité dans le passé. Vérifie que .gitignore contient « .env* » et « !.env.example », et qu'un .env.example sans valeurs documente les variables nécessaires. Je révoque moi-même les clés concernées.`,
    },
    'env.notIgnored': {
      title: (p) => `Fichier ${p.file} non protégé par .gitignore`,
      why: () =>
        "Il n'est pas encore commité, mais le prochain « git add . » l'enverra dans le dépôt avec tous ses secrets.",
      fix: () => "Ajoutez « .env* » et « !.env.example » à votre .gitignore.",
      prompt: (p) =>
        `Le fichier ${p.file} n'est pas ignoré par git. Ajoute « .env* » et « !.env.example » au .gitignore à la racine du projet, et crée un .env.example avec les mêmes noms de variables mais sans valeurs.`,
    },
    'env.publicSensitive': {
      title: (p) => `Variable sensible exposée au navigateur : ${p.name}`,
      why: (p) =>
        `Le préfixe ${p.prefix} demande au framework d'inclure la valeur dans le JavaScript envoyé aux visiteurs. N'importe qui peut la lire dans les outils de développement.`,
      fix: (p) =>
        `Renommez la variable sans le préfixe ${p.prefix} et n'utilisez-la que côté serveur (route API, server action, edge function). Si la valeur a déjà été déployée, révoquez-la.`,
      prompt: (p) =>
        `La variable ${p.name} (${p.location}) a le préfixe ${p.prefix}, donc sa valeur est envoyée au navigateur alors qu'elle est secrète. Renomme-la sans le préfixe ${p.prefix} dans les fichiers .env et dans tout le code, et n'y accède que côté serveur (route API, server action ou edge function). Si du code navigateur l'utilise, crée une route serveur qui fait l'appel à sa place et appelle cette route depuis le front.`,
    },
    'env.publicSecretValue': {
      title: (p) => `Clé ${p.provider} exposée au navigateur via ${p.name}`,
      why: (p) =>
        `Cette variable contient une vraie clé secrète et le préfixe ${p.prefix} la publie dans le code envoyé à chaque visiteur.`,
      fix: (p) =>
        `Révoquez la clé immédiatement, retirez le préfixe ${p.prefix} et déplacez l'appel côté serveur.`,
      prompt: (p) =>
        `La variable ${p.name} contient une clé ${p.provider} secrète et son préfixe ${p.prefix} l'envoie au navigateur. Renomme-la sans le préfixe ${p.prefix} partout (fichiers .env et code), utilise-la uniquement côté serveur (route API, server action ou edge function) et adapte le front pour passer par cette route. Je révoque l'ancienne clé moi-même.`,
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
    prompt: 'Prompt à coller dans votre outil IA',
    notes: {
      'osv.checked': 'dépendances vérifiées sur OSV',
      'osv.offline': 'dépendances non vérifiées (--offline)',
      'osv.error': 'OSV injoignable : dépendances non vérifiées',
    },
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

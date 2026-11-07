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
    'supabase.noRls': {
      title: (p) => `Table ${p.table} sans Row Level Security (Supabase)`,
      why: () =>
        "Sans RLS, n'importe qui possédant la clé anon (elle est publique : visible dans le code de votre site) peut lire, modifier et supprimer toutes les lignes de cette table via l'API Supabase.",
      fix: (p) =>
        `Ajoutez une migration avec « alter table public.${p.table} enable row level security; », puis des policies qui limitent l'accès (par exemple auth.uid() = user_id).`,
      prompt: (p) =>
        `Dans Supabase, la table public.${p.table} (${p.location}) n'a pas de Row Level Security : n'importe quel visiteur peut lire et modifier toutes ses lignes avec la clé anon. Crée une nouvelle migration SQL qui active la RLS (alter table public.${p.table} enable row level security) et ajoute des policies minimales : chaque utilisateur connecté ne lit et ne modifie que ses propres lignes (auth.uid() égal à la colonne propriétaire, ajoute-la si elle n'existe pas). Ne modifie pas les migrations déjà appliquées. Dis-moi ensuite quelles fonctionnalités de l'app dépendaient d'un accès plus large.`,
    },
    'supabase.openWritePolicy': {
      title: (p) => `Policy « ${p.policy} » : tout le monde peut faire ${p.command} sur ${p.table}`,
      why: (p) =>
        `La condition de cette policy est « true » : elle ne vérifie rien. Le rôle ${p.roles} peut donc modifier ou supprimer n'importe quelle ligne, y compris celles des autres utilisateurs (la clé anon est publique).`,
      fix: () =>
        "Dans une nouvelle migration, supprimez la policy (drop policy) et recréez-la avec une condition liée à l'utilisateur, par exemple « auth.uid() = user_id ».",
      prompt: (p) =>
        `Dans Supabase, la policy « ${p.policy} » de la table ${p.table} (${p.location}) autorise ${p.command} avec la condition true, donc n'importe qui peut modifier ou supprimer les lignes des autres. Crée une nouvelle migration qui supprime cette policy et la remplace par une policy qui limite ${p.command} aux lignes de l'utilisateur connecté (auth.uid() égal à la colonne propriétaire), avec une clause with check équivalente. Ne modifie pas les migrations déjà appliquées.`,
    },
    'supabase.openInsertPolicy': {
      title: (p) => `Policy « ${p.policy} » : tout le monde peut ajouter des lignes dans ${p.table}`,
      why: () =>
        "La condition « true » laisse n'importe qui insérer des lignes avec n'importe quelles valeurs (spam, faux comptes, données au nom d'un autre). C'est parfois voulu (formulaire de contact public) : vérifiez.",
      fix: () =>
        "Si seuls les utilisateurs connectés doivent écrire : « to authenticated » et « with check (auth.uid() = user_id) ». Si l'insertion publique est voulue, limitez les colonnes et ajoutez une protection anti-spam.",
      prompt: (p) =>
        `Dans Supabase, la policy « ${p.policy} » de la table ${p.table} (${p.location}) laisse n'importe qui insérer des lignes (with check (true)). Si cette table n'est pas un formulaire public, crée une nouvelle migration qui remplace cette policy par une policy to authenticated avec with check (auth.uid() égal à la colonne propriétaire). Si l'insertion publique est voulue, ne change rien et propose-moi comment limiter les abus (colonnes autorisées, contraintes, rate limit).`,
    },
    'supabase.openReadPolicy': {
      title: (p) => `Policy « ${p.policy} » : ${p.table} est lisible par tout le monde`,
      why: (p) =>
        `La condition « true » rend toutes les lignes de ${p.table} lisibles par le rôle ${p.roles}. C'est normal pour du contenu public (articles, produits), pas pour des données personnelles.`,
      fix: () =>
        "Vérifiez qu'aucune colonne sensible (e-mail, téléphone, adresse, données privées) n'est dans cette table. Sinon, limitez la lecture avec « auth.uid() = user_id ».",
      prompt: (p) =>
        `Dans Supabase, la policy « ${p.policy} » de la table ${p.table} (${p.location}) rend toutes les lignes lisibles avec la condition true. Vérifie si cette table contient des données personnelles ou privées. Si oui, crée une nouvelle migration qui limite la lecture aux lignes de l'utilisateur connecté (auth.uid() égal à la colonne propriétaire) ou déplace les colonnes sensibles dans une table protégée. Si tout est public par design, ne change rien et dis-le-moi.`,
    },
    'firebase.openWrite': {
      title: (p) => `${p.service} : écriture ouverte à tout le monde sur ${p.path}`,
      why: () =>
        "La règle autorise l'écriture sans aucune condition : n'importe qui sur Internet peut modifier, remplacer ou effacer ces données, sans même être connecté.",
      fix: () =>
        "Exigez au minimum une connexion (« request.auth != null ») et, mieux, que l'utilisateur soit le propriétaire de la donnée (« request.auth.uid == userId »).",
      prompt: (p) =>
        `Les règles de sécurité ${p.service} (${p.location}) autorisent n'importe qui à écrire sur ${p.path} sans condition. Réécris ces règles pour que seul un utilisateur connecté puisse écrire, et uniquement dans ses propres données (request.auth != null et request.auth.uid égal à l'identifiant du propriétaire ; pour le Realtime Database : auth != null et auth.uid === $uid). Garde le reste du fonctionnement de l'app et liste-moi les écrans qui pourraient en dépendre.`,
    },
    'firebase.openRead': {
      title: (p) => `${p.service} : toute la base est lisible par tout le monde`,
      why: () =>
        "La règle donne accès en lecture à toutes les données, sans condition : n'importe qui peut télécharger la base complète (comptes, messages, commandes…).",
      fix: () =>
        'Supprimez la règle globale et ouvrez la lecture collection par collection, uniquement pour ce qui est vraiment public.',
      prompt: (p) =>
        `Les règles ${p.service} (${p.location}) autorisent la lecture de toute la base (${p.path}) sans condition. Remplace cette règle globale par des règles par collection : lecture publique uniquement pour les données vraiment publiques, et pour le reste lecture réservée à l'utilisateur connecté propriétaire (request.auth.uid). Liste-moi les collections et ce que tu as choisi pour chacune.`,
    },
    'firebase.testMode': {
      title: (p) => `${p.service} : règles « mode test » ouvertes à tous jusqu'à une date`,
      why: () =>
        "Ce sont les règles par défaut du mode test : jusqu'à la date indiquée, tout le monde peut lire et modifier les données. Ensuite, l'app cessera de fonctionner.",
      fix: () => 'Remplacez-les par de vraies règles basées sur request.auth avant la mise en ligne.',
      prompt: (p) =>
        `Les règles ${p.service} (${p.location}) sont encore celles du mode test (request.time < timestamp.date(...)) : tout le monde peut lire et écrire. Écris de vraies règles de sécurité : lecture et écriture réservées à l'utilisateur connecté sur ses propres données (request.auth.uid), lecture publique seulement pour les collections vraiment publiques. Explique-moi chaque règle.`,
    },
    'api.noAuthPrivileged': {
      title: (p) => `Route ${p.route} sans vérification d'identité (${p.framework})`,
      why: () =>
        "Cette route utilise un accès privilégié à vos données (clé service_role, SDK admin ou écriture en base) mais ne vérifie jamais qui l'appelle : n'importe qui peut l'appeler directement et lire, modifier ou supprimer des données.",
      fix: () =>
        "Au début du handler, récupérez l'utilisateur connecté (session, getUser(), jeton de l'en-tête Authorization) et renvoyez 401 s'il n'y en a pas, puis vérifiez qu'il a le droit d'agir sur la donnée demandée.",
      prompt: (p) =>
        `La route ${p.route} (${p.framework}, ${p.location}) utilise un accès privilégié (clé service_role, SDK admin ou écriture en base) sans vérifier qui l'appelle. Ajoute au début du handler une vérification d'authentification avec le système d'auth déjà utilisé dans le projet (session, supabase.auth.getUser() avec le jeton de l'en-tête Authorization, etc.) : renvoie 401 si personne n'est connecté, puis 403 si l'utilisateur n'a pas le droit d'agir sur la ressource demandée. N'utilise l'accès privilégié qu'après ces vérifications, et jamais côté navigateur.`,
    },
    'api.noAuthAI': {
      title: (p) => `Route IA ${p.route} ouverte à tout le monde (${p.framework})`,
      why: () =>
        "Cette route appelle une API d'IA payante sans vérifier qui l'appelle. N'importe qui peut l'utiliser en boucle à vos frais : la facture peut atteindre des centaines d'euros en quelques heures.",
      fix: () =>
        "Exigez un utilisateur connecté (renvoyez 401 sinon), ajoutez une limite de requêtes par utilisateur et plafonnez la taille des messages envoyés au modèle.",
      prompt: (p) =>
        `La route ${p.route} (${p.framework}, ${p.location}) appelle une API d'IA payante sans vérifier qui l'appelle : n'importe qui peut la spammer à mes frais. Ajoute au début du handler une vérification d'authentification avec le système d'auth déjà utilisé dans le projet (renvoie 401 si personne n'est connecté), puis une limite de requêtes par utilisateur (rate limit) et une taille maximale pour les messages envoyés au modèle. Garde la clé de l'API IA côté serveur uniquement.`,
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

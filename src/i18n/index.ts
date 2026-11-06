import { en } from './en';
import { fr } from './fr';
import type { Messages } from './types';

export type Lang = 'fr' | 'en';
export type { Messages } from './types';

const DICTS: Record<Lang, Messages> = { fr, en };

export function isLang(v: string): v is Lang {
  return v === 'fr' || v === 'en';
}

/** French when the system locale is French, English otherwise. */
export function detectLang(env: NodeJS.ProcessEnv = process.env): Lang {
  const candidates = [env.GARDEFOU_LANG, env.LC_ALL, env.LC_MESSAGES, env.LANG];
  try {
    candidates.push(Intl.DateTimeFormat().resolvedOptions().locale);
  } catch {
    // ignore
  }
  for (const c of candidates) {
    if (!c) continue;
    const l = c.toLowerCase();
    if (l.startsWith('fr')) return 'fr';
    if (l.startsWith('en')) return 'en';
  }
  return 'en';
}

export function messages(lang: Lang): Messages {
  return DICTS[lang];
}

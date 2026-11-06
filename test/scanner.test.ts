import { afterAll, describe, expect, it } from 'vitest';
import { scanFiles } from '../src/scanner';
import { cleanupTempDirs, makeTempDir, writeFiles } from './helpers';

afterAll(cleanupTempDirs);

describe('scanFiles', () => {
  it('respects .gitignore (root and nested) and always skips node_modules, .git, fixtures', () => {
    const root = makeTempDir();
    writeFiles(root, {
      '.gitignore': 'dist/\n*.log\n.env*\n!.env.example\n',
      'src/index.ts': 'export {}',
      'src/.gitignore': 'secret-notes.txt\n',
      'src/secret-notes.txt': 'ignored',
      'dist/bundle.js': 'ignored',
      'debug.log': 'ignored',
      'node_modules/pkg/index.js': 'ignored',
      'fixtures/app/index.ts': 'ignored',
      'test/fixtures/data.json': '{}',
      '.env': 'A=1',
      '.env.example': 'A=',
    });

    const files = scanFiles(root);
    const rels = files.map((f) => f.rel);
    expect(rels).toEqual(['.env', '.env.example', '.gitignore', 'src/.gitignore', 'src/index.ts']);
    expect(files.find((f) => f.rel === '.env')?.gitignored).toBe(true);
    expect(files.find((f) => f.rel === '.env.example')?.gitignored).toBe(false);
  });

  it('skips binary files', () => {
    const root = makeTempDir();
    writeFiles(root, { 'a.txt': 'hello', 'b.bin': 'ab\0cd' });
    expect(scanFiles(root).map((f) => f.rel)).toEqual(['a.txt']);
  });
});

/**
 * Writes the fake secrets into fixtures/vulnerable-app so that
 * `npx tsx src/cli.ts fixtures/vulnerable-app` has something to find.
 *
 * The generated paths are added to .git/info/exclude (local, never pushed)
 * rather than to .gitignore, so the scanner still audits them.
 */
import { execFileSync } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateFixtureSecrets } from './fake-keys';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fixtureRoot = path.join(repoRoot, 'fixtures', 'vulnerable-app');

export const EXCLUDE_PATTERNS = [
  '/fixtures/vulnerable-app/.env',
  '/fixtures/vulnerable-app/**/*.generated.*',
];

function excludeFile(): string | null {
  try {
    const p = execFileSync('git', ['rev-parse', '--git-path', 'info/exclude'], {
      cwd: repoRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    return path.resolve(repoRoot, p);
  } catch {
    return null;
  }
}

const exclude = excludeFile();
if (exclude) {
  mkdirSync(path.dirname(exclude), { recursive: true });
  const current = existsSync(exclude) ? readFileSync(exclude, 'utf8') : '';
  const missing = EXCLUDE_PATTERNS.filter((p) => !current.split(/\r?\n/).includes(p));
  if (missing.length > 0) {
    appendFileSync(
      exclude,
      `${current.endsWith('\n') || current === '' ? '' : '\n'}# garde-fou: fake fixture secrets\n${missing.join('\n')}\n`,
    );
  }
} else {
  console.warn('Not a git repository: make sure you never commit the generated files.');
}

const { files } = generateFixtureSecrets();
for (const [rel, content] of Object.entries(files)) {
  const abs = path.join(fixtureRoot, rel);
  mkdirSync(path.dirname(abs), { recursive: true });
  writeFileSync(abs, content);
  console.log(`wrote ${path.relative(repoRoot, abs)}`);
}

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import ignore, { type Ignore } from 'ignore';
import { isEnvFile } from './patterns';
import type { ScannedFile } from './types';

/** Directories never scanned, whatever .gitignore says. */
export const ALWAYS_IGNORED_DIRS = new Set(['node_modules', '.git', 'fixtures']);

export const MAX_FILE_SIZE = 1_000_000;

interface Matcher {
  base: string;
  ig: Ignore;
}

export function toPosix(p: string): string {
  return p.split(path.sep).join('/');
}

/** Directory containing `.git` (dir or file, for worktrees), walking up from `start`. */
export function findGitRoot(start: string): string | null {
  let dir = path.resolve(start);
  for (;;) {
    if (existsSync(path.join(dir, '.git'))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

function loadMatcher(dir: string): Matcher | null {
  const file = path.join(dir, '.gitignore');
  if (!existsSync(file)) return null;
  try {
    return { base: dir, ig: ignore().add(readFileSync(file, 'utf8')) };
  } catch {
    return null;
  }
}

/** Git semantics: later (deeper) .gitignore files override earlier ones. */
function isIgnored(abs: string, isDir: boolean, matchers: Matcher[]): boolean {
  let ignored = false;
  for (const m of matchers) {
    const rel = toPosix(path.relative(m.base, abs));
    if (!rel || rel.startsWith('..')) continue;
    const r = m.ig.test(isDir ? `${rel}/` : rel);
    if (r.ignored) ignored = true;
    else if (r.unignored) ignored = false;
  }
  return ignored;
}

function isBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

/**
 * Lists the text files of `root`, honouring every .gitignore from the git
 * repository root down to each directory. Gitignored files are skipped, except
 * `.env*` files, which are returned with `gitignored: true`.
 */
export function scanFiles(root: string): ScannedFile[] {
  const rootAbs = path.resolve(root);
  const matchers: Matcher[] = [];

  // .gitignore files of ancestor directories, up to the repository root.
  const gitRoot = findGitRoot(rootAbs);
  if (gitRoot && gitRoot !== rootAbs) {
    const chain: string[] = [];
    for (let d = path.dirname(rootAbs); ; d = path.dirname(d)) {
      chain.unshift(d);
      if (d === gitRoot || path.dirname(d) === d) break;
    }
    for (const d of chain) {
      const m = loadMatcher(d);
      if (m) matchers.push(m);
    }
  }

  const files: ScannedFile[] = [];
  walk(rootAbs, rootAbs, matchers, files);
  files.sort((a, b) => a.rel.localeCompare(b.rel));
  return files;
}

function walk(dir: string, rootAbs: string, inherited: Matcher[], out: ScannedFile[]): void {
  const own = loadMatcher(dir);
  const matchers = own ? [...inherited, own] : inherited;

  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const e of entries) {
    const abs = path.join(dir, e.name);
    if (e.isSymbolicLink()) continue;

    if (e.isDirectory()) {
      if (ALWAYS_IGNORED_DIRS.has(e.name)) continue;
      if (isIgnored(abs, true, matchers)) continue;
      walk(abs, rootAbs, matchers, out);
      continue;
    }
    if (!e.isFile()) continue;

    const gitignored = isIgnored(abs, false, matchers);
    if (gitignored && !isEnvFile(e.name)) continue;

    let buf: Buffer;
    try {
      if (statSync(abs).size > MAX_FILE_SIZE) continue;
      buf = readFileSync(abs);
    } catch {
      continue;
    }
    if (isBinary(buf)) continue;

    out.push({
      abs,
      rel: toPosix(path.relative(rootAbs, abs)),
      content: buf.toString('utf8'),
      gitignored,
    });
  }
}

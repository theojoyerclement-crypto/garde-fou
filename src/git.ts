import { execFileSync } from 'node:child_process';
import { ALWAYS_IGNORED_DIRS } from './scanner';
import type { GitInfo, HistoryLine } from './types';

function git(cwd: string, args: string[]): string | null {
  try {
    return execFileSync('git', ['-c', 'core.quotepath=false', ...args], {
      cwd,
      encoding: 'utf8',
      maxBuffer: 512 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true,
    });
  } catch {
    return null;
  }
}

function isAlwaysIgnored(file: string): boolean {
  return file.split('/').some((seg) => ALWAYS_IGNORED_DIRS.has(seg));
}

/**
 * Git facts about `root`, scoped to `root` (paths are relative to it).
 * Returns null when `root` is not inside a git work tree or git is missing.
 */
export function readGitInfo(root: string, opts: { history: boolean }): GitInfo | null {
  if (git(root, ['rev-parse', '--is-inside-work-tree'])?.trim() !== 'true') return null;

  const tracked = new Set(
    (git(root, ['ls-files', '-z']) ?? '').split('\0').filter((f) => f && !isAlwaysIgnored(f)),
  );

  const filesInHistory = new Map<string, string>();
  let history: HistoryLine[] | null = null;

  if (opts.history) {
    // Fails on a repository without commits: history is then simply empty.
    const log =
      git(root, [
        'log',
        '-p',
        '--all',
        '--no-color',
        '--no-ext-diff',
        '--no-textconv',
        '--no-renames',
        '--relative',
        '--format=%x00%H',
        '--',
        '.',
      ]) ?? '';
    history = parseLog(log, filesInHistory);
  }

  return { tracked, history, filesInHistory };
}

/** Extracts added lines from `git log -p`. Exported for tests. */
export function parseLog(log: string, filesInHistory: Map<string, string>): HistoryLine[] {
  const out: HistoryLine[] = [];
  let commit = '';
  let file: string | null = null;
  let inHeader = false;

  for (const raw of log.split('\n')) {
    const line = raw.endsWith('\r') ? raw.slice(0, -1) : raw;

    if (line.startsWith('\0')) {
      commit = line.slice(1).trim();
      file = null;
      inHeader = false;
      continue;
    }
    if (line.startsWith('diff --git ')) {
      inHeader = true;
      file = null;
      const m = / b\/(.+)$/.exec(line);
      if (m?.[1]) {
        file = m[1];
        if (!filesInHistory.has(file)) filesInHistory.set(file, commit);
      }
      continue;
    }
    if (inHeader) {
      if (line.startsWith('+++ ')) {
        const target = line.slice(4);
        file = target === '/dev/null' ? null : target.replace(/^b\//, '');
      } else if (line.startsWith('@@')) {
        inHeader = false;
      }
      continue;
    }
    if (file && line.startsWith('+') && !isAlwaysIgnored(file)) {
      out.push({ commit, file, text: line.slice(1) });
    }
  }
  return out;
}

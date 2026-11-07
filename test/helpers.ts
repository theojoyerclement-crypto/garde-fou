import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runAudit, type AuditOptions, type AuditResult } from '../src/audit';

export const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const fixturesDir = path.join(repoRoot, 'fixtures');
export const fixtureRoot = path.join(fixturesDir, 'vulnerable-app');

/** runAudit without network unless a fake OSV client is given. */
export function audit(root: string, opts: AuditOptions = {}): Promise<AuditResult> {
  return runAudit(root, { offline: !opts.osv, ...opts });
}

/** Copies fixtures/<name> to a fresh temp dir (no git) and returns its path. */
export function copyNamedFixture(name: string): string {
  const dest = path.join(makeTempDir(), name);
  cpSync(path.join(fixturesDir, name), dest, { recursive: true });
  return dest;
}

const tempDirs: string[] = [];

export function makeTempDir(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'garde-fou-test-'));
  tempDirs.push(dir);
  return dir;
}

export function cleanupTempDirs(): void {
  for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
}

/** Copies the committed part of the fixture (never the locally generated secrets). */
export function copyFixture(dest: string): void {
  cpSync(fixtureRoot, dest, {
    recursive: true,
    filter: (src) => {
      const name = path.basename(src);
      return name !== '.env' && !name.includes('.generated.');
    },
  });
}

export function writeFiles(root: string, files: Record<string, string>): void {
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    mkdirSync(path.dirname(abs), { recursive: true });
    writeFileSync(abs, content);
  }
}

export function git(cwd: string, ...args: string[]): string {
  return execFileSync(
    'git',
    [
      '-c', 'user.name=garde-fou-test',
      '-c', 'user.email=test@example.invalid',
      '-c', 'commit.gpgsign=false',
      '-c', 'init.defaultBranch=main',
      '-c', 'core.autocrlf=false',
      ...args,
    ],
    { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
}

export function commitAll(cwd: string, message: string): void {
  git(cwd, 'add', '-A');
  git(cwd, 'commit', '--no-verify', '-q', '-m', message);
}

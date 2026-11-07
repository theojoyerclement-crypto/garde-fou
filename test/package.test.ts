import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { VERSION } from '../src/version';
import { repoRoot } from './helpers';

const pkg = JSON.parse(readFileSync(path.join(repoRoot, 'package.json'), 'utf8')) as Record<string, unknown>;
const readme = readFileSync(path.join(repoRoot, 'README.md'), 'utf8');

describe('npm package', () => {
  it('is @gardefou/cli, public, with the gardefou and garde-fou commands on the same file', () => {
    expect(pkg.name).toBe('@gardefou/cli');
    expect(pkg.publishConfig).toEqual({ access: 'public' });
    // Both bins point to one file: `npx @gardefou/cli` then knows what to run.
    expect(pkg.bin).toEqual({ gardefou: 'dist/cli.js', 'garde-fou': 'dist/cli.js' });
    expect(pkg.version).toBe(VERSION);
  });

  it('ships only the build, README and LICENSE, built and tested before publishing', () => {
    expect(pkg.files).toEqual(['dist', 'README.md', 'LICENSE']);
    expect((pkg.scripts as Record<string, string>).prepublishOnly).toBe('npm run typecheck && npm test && npm run build');
  });

  it('README uses the scoped package everywhere, MCP setup included', () => {
    expect(readme).not.toMatch(/npx gardefou\b/);
    expect(readme).toContain('npx @gardefou/cli');
    expect(readme).toContain('claude mcp add gardefou -- npx -y @gardefou/cli mcp');
    const json = /\{ "mcpServers": .+ \}/.exec(readme)?.[0] ?? '';
    expect(JSON.parse(json)).toEqual({ mcpServers: { gardefou: { command: 'npx', args: ['-y', '@gardefou/cli', 'mcp'] } } });
  });
});

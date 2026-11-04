/// <reference types="node" />
import { afterEach, describe, expect, it } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { URL, fileURLToPath } from 'node:url';

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function fixture(missing?: string) {
  const root = mkdtempSync(join(tmpdir(), 'vendor-verify-'));
  roots.push(root);
  const source = join(root, 'upstream');
  const pkg = join(source, 'trust-record-verify');
  const worker = join(root, 'worker');
  mkdirSync(join(pkg, 'dist/generated'), { recursive: true });
  mkdirSync(join(worker, 'scripts'), { recursive: true });
  copyFileSync(fileURLToPath(new URL('../scripts/vendor-trust-record-verify.sh', import.meta.url)), join(worker, 'scripts/vendor-trust-record-verify.sh'));
  writeFileSync(join(source, '.gitignore'), 'trust-record-verify/dist/\n');
  writeFileSync(join(pkg, 'package.json'), JSON.stringify({ name: '@fixture/verifier', version: '1.2.3', license: 'Apache-2.0' }));
  for (const name of ['LICENSE', 'NOTICE']) if (missing !== name) writeFileSync(join(source, name), `${name}: upstream root bytes\r\nCopyright fixture\n`);
  for (const name of ['index.js', 'index.d.ts', 'generated/validators.js', 'generated/validators.d.ts']) writeFileSync(join(pkg, 'dist', name), '// built fixture\n');
  const git = (...args: string[]) => execFileSync('git', ['-C', source, ...args], { encoding: 'utf8' }).trim();
  git('init', '-q');
  git('config', 'core.autocrlf', 'false');
  git('add', '.');
  git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture');
  const dest = join(worker, 'vendor/trust-record-verify');
  return { source, dest, git, run: () => spawnSync('bash', [join(worker, 'scripts/vendor-trust-record-verify.sh'), pkg], { encoding: 'utf8' }) };
}

describe('vendor trust-record-verify legal provenance', () => {
  it('copies repository LICENSE and NOTICE verbatim alongside pinned package provenance', () => {
    const f = fixture();
    expect(f.run().status).toBe(0);
    for (const name of ['LICENSE', 'NOTICE']) expect(readFileSync(join(f.dest, name))).toEqual(readFileSync(join(f.source, name)));
    const provenance = readFileSync(join(f.dest, 'SOURCE.md'), 'utf8');
    expect(provenance).toContain(`Commit: ${f.git('rev-parse', 'HEAD')}`);
    expect(provenance).toContain(`Commit date: ${f.git('show', '-s', '--format=%cs', 'HEAD')}`);
    expect(provenance).toContain('Package: @fixture/verifier\nVersion: 1.2.3\nPackage license: Apache-2.0');
    expect(provenance).toContain('Repository-root LICENSE and NOTICE are retained verbatim');
  });

  it.each(['LICENSE', 'NOTICE'])('rejects missing root %s before changing the destination', (name) => {
    const f = fixture(name);
    mkdirSync(f.dest, { recursive: true });
    for (const file of ['index.js', 'SOURCE.md']) writeFileSync(join(f.dest, file), 'existing destination\n');
    const result = f.run();
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain(`Missing upstream legal file: ${name}`);
    for (const file of ['index.js', 'SOURCE.md']) expect(readFileSync(join(f.dest, file), 'utf8')).toBe('existing destination\n');
  });
});

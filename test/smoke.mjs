/**
 * Plain-JS checks against the built package, so they run on every Node version
 * in `engines` — the TypeScript suite needs type stripping and only runs on 24+.
 *
 *   npm run build && node --test test/smoke.mjs
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test, { describe } from 'node:test';

const here = path.dirname(fileURLToPath(import.meta.url));
const execFileAsync = promisify(execFile);

const {
  evaluate,
  DEFAULT_CONFIG,
  findSlsaBundle,
  extractProvenancePredicate,
  extractRepository,
  parseLockfile,
  formatText,
} = await import('../dist/index.js');

function fixture(name) {
  return JSON.parse(readFileSync(path.join(here, 'fixtures', name), 'utf8'));
}

describe('dist: library API', () => {
  test('decodes a real captured attestation and matches a policy', () => {
    const audit = fixture('npm-audit-verified.real.json');
    const lockfileRaw = readFileSync(path.join(here, 'fixtures', 'package-lock.real.json'), 'utf8');
    const deps = parseLockfile(lockfileRaw, 'package-lock.real.json');

    const sigstore = audit.verified.find((p) => p.name === 'sigstore');
    const predicate = extractProvenancePredicate(findSlsaBundle(sigstore.attestationBundles));
    assert.equal(extractRepository(predicate), 'https://github.com/sigstore/sigstore-js');

    const config = { ...DEFAULT_CONFIG, allow: ['https://github.com/sigstore/*'] };
    const report = evaluate(deps, audit, config);
    const result = report.results.find((r) => r.name === 'sigstore');
    assert.equal(result.verdict, 'ok');

    const text = formatText(report, config);
    assert.match(text, /fs-minipass@3\.0\.3/); // the real mismatch this fixture contains
  });
});

describe('dist: the actual bin', () => {
  test('provenance-gate --help exits 0 via the built CLI', async () => {
    const cli = path.join(here, '..', 'dist', 'cli.js');
    const { stdout } = await execFileAsync(process.execPath, [cli, '--help']);
    assert.match(stdout, /Usage:/);
  });

  test('provenance-gate --version exits 0 and prints a semver', async () => {
    const cli = path.join(here, '..', 'dist', 'cli.js');
    const { stdout } = await execFileAsync(process.execPath, [cli, '--version']);
    assert.match(stdout.trim(), /^\d+\.\d+\.\d+$/);
  });

  test('provenance-gate exits 2 with an actionable message when there is no lockfile', async () => {
    const cli = path.join(here, '..', 'dist', 'cli.js');
    await assert.rejects(
      execFileAsync(process.execPath, [cli, '--cwd', path.join(here, 'fixtures')]),
      (err) => {
        assert.equal(err.code, 2);
        assert.match(err.stderr, /could not analyse/);
        return true;
      },
    );
  });
});

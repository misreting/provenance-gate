/**
 * The one test file in this suite that touches the network and a real `npm`.
 * Everything else uses recorded fixtures (see provenance-gate.test.ts).
 *
 * It installs a real package known to ship npm provenance (sigstore@2.3.1,
 * used throughout the README) into a scratch directory, then runs the actual
 * `runNpmAuditSignatures` shell-out against it — exercising the one part of
 * this library that fixtures cannot: whether npm's real output still looks
 * the way `src/audit.ts` assumes it does.
 *
 * If there's no network, this SKIPS (not fails) with an actionable message,
 * so `npm test` still passes offline.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { runGate } from '../src/index.ts';
import { DEFAULT_CONFIG } from '../src/policy.ts';

const execFileAsync = promisify(execFile);

async function checkOnline(): Promise<boolean> {
  try {
    const res = await fetch('https://registry.npmjs.org/sigstore', { signal: AbortSignal.timeout(5000) });
    return res.ok;
  } catch {
    return false;
  }
}

const online = await checkOnline();
const skipReason = online
  ? false
  : 'No network access to registry.npmjs.org detected — skipping the live npm-install integration test. ' +
    'Re-run with network access to exercise the real "npm audit signatures --include-attestations" path.';

test(
  'runs the real gate against a real, fresh install of sigstore@2.3.1',
  { skip: skipReason, timeout: 120_000 },
  async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'provenance-gate-integration-'));
    try {
      await writeFile(
        path.join(dir, 'package.json'),
        JSON.stringify({ name: 'provenance-gate-integration-fixture', version: '1.0.0', private: true }),
      );

      // sigstore@2.3.1 is real, published-with-provenance (see README). left-pad
      // is real too, and — as of writing — has no provenance at all, which is
      // exactly the "most of the ecosystem" case this tool has to report calmly.
      await execFileAsync('npm', ['install', 'sigstore@2.3.1', 'left-pad', '--no-fund', '--loglevel=error'], {
        cwd: dir,
      });

      const allowlisted = await runGate({ ...DEFAULT_CONFIG, allow: ['https://github.com/sigstore/*'] }, { cwd: dir });
      const sigstoreResult = allowlisted.results.find((r) => r.name === 'sigstore');
      assert.ok(sigstoreResult, 'expected sigstore to appear in the dependency list');
      assert.equal(sigstoreResult!.verdict, 'ok');
      assert.equal(sigstoreResult!.repository, 'https://github.com/sigstore/sigstore-js');
      // NOT asserting `allowlisted.hasViolations === false` here: sigstore's own
      // transitive deps (make-fetch-happen, cacache, tuf-js, ...) are themselves
      // attested from *other* real orgs (npm, theupdateframework, ...), so an
      // allowlist scoped to just "sigstore/*" correctly reports those as
      // mismatches too. That is the tool doing its job, not a bug — see the
      // README's "narrow allowlists surface transitive deps" note.
      assert.equal(allowlisted.counts.mismatch > 0, true, 'expected real transitive deps attested from other orgs');

      const mismatched = await runGate(
        { ...DEFAULT_CONFIG, allow: ['https://github.com/some-org-that-does-not-publish-this/*'] },
        { cwd: dir },
      );
      const mismatchResult = mismatched.results.find((r) => r.name === 'sigstore');
      assert.equal(mismatchResult!.verdict, 'mismatch');
      assert.equal(mismatched.hasViolations, true);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  },
);

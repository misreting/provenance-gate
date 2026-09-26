import assert from 'node:assert/strict';
import { test, describe } from 'node:test';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { compileAllowlist, matchAllowlist } from '../src/allowlist.ts';
import {
  decodeDssePayload,
  findSlsaBundle,
  extractProvenancePredicate,
  extractRepository,
  MalformedAttestationError,
  type AttestationBundleEntry,
} from '../src/attestation.ts';
import { parseLockfile, readLockfileDependencies } from '../src/lockfile.ts';
import { evaluate, DEFAULT_CONFIG, isViolation, type ProvenanceGateConfig } from '../src/policy.ts';
import { loadConfig } from '../src/config.ts';
import { formatText, formatJson } from '../src/report.ts';
import { runGate } from '../src/gate.ts';
import { main } from '../src/cli-core.ts';
import { AnalysisError, ConfigError } from '../src/errors.ts';
import type { NpmAuditSignaturesResult } from '../src/audit.ts';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(here, 'fixtures');

function loadFixture<T>(name: string): T {
  return JSON.parse(readFileSync(path.join(fixturesDir, name), 'utf8')) as T;
}

/**
 * Real data captured from `npm audit signatures --json --include-attestations`
 * after `npm install sigstore@2.3.1`, trimmed to a few packages. See the file
 * for provenance. Cross-referenced against a real, matching, trimmed
 * package-lock.json fixture below.
 */
const REAL_AUDIT = () => loadFixture<NpmAuditSignaturesResult>('npm-audit-verified.real.json');
const REAL_LOCKFILE_PATH = path.join(fixturesDir, 'package-lock.real.json');
const REAL_LOCKFILE_RAW = readFileSync(REAL_LOCKFILE_PATH, 'utf8');

async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(path.join(tmpdir(), 'provenance-gate-test-'));
  try {
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

describe('allowlist matching', () => {
  test('matches an exact repository URL', () => {
    const compiled = compileAllowlist(['https://github.com/sigstore/sigstore-js']);
    assert.equal(matchAllowlist('https://github.com/sigstore/sigstore-js', compiled), 'https://github.com/sigstore/sigstore-js');
  });

  test('org-level glob matches any repo in the org, not sub-paths', () => {
    const compiled = compileAllowlist(['https://github.com/myorg/*']);
    assert.equal(matchAllowlist('https://github.com/myorg/anything', compiled), 'https://github.com/myorg/*');
    assert.equal(matchAllowlist('https://github.com/myorg/anything/nested', compiled), undefined);
  });

  test('does not let a glob bleed into a similarly-named org', () => {
    const compiled = compileAllowlist(['https://github.com/myorg/*']);
    assert.equal(matchAllowlist('https://github.com/myorg-evil/repo', compiled), undefined);
  });

  test('normalizes a trailing .git and trailing slash on both sides', () => {
    const compiled = compileAllowlist(['https://github.com/sigstore/sigstore-js/']);
    assert.equal(matchAllowlist('https://github.com/sigstore/sigstore-js.git', compiled), 'https://github.com/sigstore/sigstore-js/');
  });

  test('no patterns matches nothing', () => {
    assert.equal(matchAllowlist('https://github.com/anyone/anything', compileAllowlist([])), undefined);
  });
});

describe('attestation decoding (real captured data)', () => {
  const sigstore = REAL_AUDIT().verified.find((p) => p.name === 'sigstore')!;

  test('decodes the DSSE payload to an in-toto statement', () => {
    const slsa = findSlsaBundle(sigstore.attestationBundles)!;
    const statement = decodeDssePayload(slsa.bundle.dsseEnvelope);
    assert.equal(statement._type, 'https://in-toto.io/Statement/v1');
    assert.equal(statement.predicateType, 'https://slsa.dev/provenance/v1');
    assert.equal(statement.subject?.[0]?.name, 'pkg:npm/sigstore@2.3.1');
  });

  test('extracts the workflow repository from a real sigstore@2.3.1 attestation', () => {
    const slsa = findSlsaBundle(sigstore.attestationBundles)!;
    const predicate = extractProvenancePredicate(slsa);
    assert.equal(extractRepository(predicate), 'https://github.com/sigstore/sigstore-js');
    assert.equal(predicate?.buildDefinition?.externalParameters?.workflow?.ref, 'refs/heads/main');
  });

  test('findSlsaBundle ignores the sibling npm publish-attestation bundle', () => {
    assert.equal(sigstore.attestationBundles?.length, 2);
    const slsa = findSlsaBundle(sigstore.attestationBundles)!;
    assert.equal(slsa.predicateType, 'https://slsa.dev/provenance/v1');
  });

  test('a different real package (fs-minipass) names a different real repo', () => {
    const fsMinipass = REAL_AUDIT().verified.find((p) => p.name === 'fs-minipass')!;
    const predicate = extractProvenancePredicate(findSlsaBundle(fsMinipass.attestationBundles)!);
    assert.equal(extractRepository(predicate), 'https://github.com/npm/fs-minipass');
  });

  test('rejects a payload that is not valid base64-of-JSON', () => {
    const bogus: AttestationBundleEntry = {
      predicateType: 'https://slsa.dev/provenance/v1',
      bundle: { dsseEnvelope: { payload: Buffer.from('not json').toString('base64'), payloadType: 'x' } },
    };
    assert.throws(() => decodeDssePayload(bogus.bundle.dsseEnvelope), MalformedAttestationError);
  });

  test('a bundle whose own predicateType label disagrees with its payload is not trusted', () => {
    const slsa = findSlsaBundle(sigstore.attestationBundles)!;
    const mislabeled: AttestationBundleEntry = { ...slsa, predicateType: 'https://slsa.dev/provenance/v1' };
    // Swap in the *other* bundle's payload under the SLSA label.
    const publishBundle = sigstore.attestationBundles!.find((b) => b !== slsa)!;
    mislabeled.bundle = publishBundle.bundle;
    assert.equal(extractProvenancePredicate(mislabeled), undefined);
  });
});

describe('lockfile parsing (real captured lockfile)', () => {
  test('lists every unique name@version, deduplicated, skipping the root and links', () => {
    const deps = parseLockfile(REAL_LOCKFILE_RAW, REAL_LOCKFILE_PATH);
    const keys = deps.map((d) => `${d.name}@${d.version}`).sort();
    assert.deepEqual(keys, [
      '@sigstore/core@1.1.0',
      'fs-minipass@2.1.0',
      'fs-minipass@3.0.3',
      'lodash@4.18.1',
      'sigstore@2.3.1',
    ]);
  });

  test('keeps two different installed versions of the same package independent', () => {
    const deps = parseLockfile(REAL_LOCKFILE_RAW, REAL_LOCKFILE_PATH);
    const fsMinipass = deps.filter((d) => d.name === 'fs-minipass');
    assert.equal(fsMinipass.length, 2);
  });

  test('readLockfileDependencies throws AnalysisError when there is no lockfile', async () => {
    await withTempDir(async (dir) => {
      await assert.rejects(readLockfileDependencies(dir), AnalysisError);
    });
  });

  test('readLockfileDependencies throws AnalysisError on a lockfile v1 (no "packages" map)', async () => {
    await withTempDir(async (dir) => {
      await writeFile(path.join(dir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 1, dependencies: {} }));
      await assert.rejects(readLockfileDependencies(dir), AnalysisError);
    });
  });
});

describe('policy evaluation (real audit + real lockfile data)', () => {
  const deps = parseLockfile(REAL_LOCKFILE_RAW, REAL_LOCKFILE_PATH);

  function config(overrides: Partial<ProvenanceGateConfig> = {}): ProvenanceGateConfig {
    return { ...DEFAULT_CONFIG, ...overrides };
  }

  test('an empty allowlist runs report-only: nothing fails, even a repo mismatch', () => {
    const report = evaluate(deps, REAL_AUDIT(), config());
    assert.equal(report.reportOnly, true);
    assert.equal(report.hasViolations, false);
    assert.equal(report.counts.mismatch, 3); // sigstore, @sigstore/core, fs-minipass all unmatched
  });

  test('allowlisting the real sigstore org passes sigstore packages, flags fs-minipass', () => {
    const report = evaluate(deps, REAL_AUDIT(), config({ allow: ['https://github.com/sigstore/*'] }));
    assert.equal(report.reportOnly, false);
    const byName = Object.fromEntries(report.results.map((r) => [`${r.name}@${r.version}`, r]));
    assert.equal(byName['sigstore@2.3.1']!.verdict, 'ok');
    assert.equal(byName['@sigstore/core@1.1.0']!.verdict, 'ok');
    assert.equal(byName['fs-minipass@3.0.3']!.verdict, 'mismatch');
    assert.equal(byName['fs-minipass@3.0.3']!.repository, 'https://github.com/npm/fs-minipass');
    assert.equal(byName['lodash@4.18.1']!.verdict, 'no-provenance');
    assert.equal(report.hasViolations, true); // the fs-minipass mismatch
  });

  test('allowlisting both real orgs leaves only no-provenance (which does not fail by default)', () => {
    const report = evaluate(
      deps,
      REAL_AUDIT(),
      config({ allow: ['https://github.com/sigstore/*', 'https://github.com/npm/*'] }),
    );
    assert.equal(report.counts.mismatch, 0);
    assert.equal(report.counts.ok, 3);
    assert.equal(report.counts['no-provenance'], 2); // lodash, fs-minipass@2.1.0
    assert.equal(report.hasViolations, false);
  });

  test('failOnMissing turns "no provenance" into a violation', () => {
    const allow = ['https://github.com/sigstore/*', 'https://github.com/npm/*'];
    const lenient = evaluate(deps, REAL_AUDIT(), config({ allow, failOnMissing: false }));
    const strict = evaluate(deps, REAL_AUDIT(), config({ allow, failOnMissing: true }));
    assert.equal(lenient.hasViolations, false);
    assert.equal(strict.hasViolations, true);
  });

  test('ignore excludes a package from enforcement and from the no-provenance count', () => {
    const report = evaluate(
      deps,
      REAL_AUDIT(),
      config({ allow: ['https://github.com/sigstore/*'], ignore: ['fs-minipass', 'lodash'] }),
    );
    const byName = Object.fromEntries(report.results.map((r) => [`${r.name}@${r.version}`, r]));
    assert.equal(byName['fs-minipass@3.0.3']!.verdict, 'ignored');
    assert.equal(byName['fs-minipass@2.1.0']!.verdict, 'ignored');
    assert.equal(byName['lodash@4.18.1']!.verdict, 'ignored');
    assert.equal(report.hasViolations, false);
  });

  test('an exact "name@version" ignore entry only excludes that version', () => {
    const report = evaluate(
      deps,
      REAL_AUDIT(),
      config({ allow: ['https://github.com/sigstore/*'], ignore: ['fs-minipass@2.1.0'] }),
    );
    const byName = Object.fromEntries(report.results.map((r) => [`${r.name}@${r.version}`, r]));
    assert.equal(byName['fs-minipass@2.1.0']!.verdict, 'ignored');
    assert.equal(byName['fs-minipass@3.0.3']!.verdict, 'mismatch');
  });

  test('an unparseable-but-present attestation is unverifiable, not silently ok', () => {
    const audit = REAL_AUDIT();
    const sigstoreEntry = audit.verified.find((p) => p.name === 'sigstore')!;
    // Corrupt the SLSA bundle's payload so it no longer decodes as JSON.
    const slsaBundle = sigstoreEntry.attestationBundles!.find((b) => b.predicateType.includes('slsa'))!;
    slsaBundle.bundle.dsseEnvelope.payload = Buffer.from('not json').toString('base64');

    const report = evaluate(deps, audit, config({ allow: ['https://github.com/sigstore/*'] }));
    const sigstoreResult = report.results.find((r) => r.name === 'sigstore')!;
    assert.equal(sigstoreResult.verdict, 'unverifiable');
    assert.equal(isViolation(sigstoreResult, config({ allow: ['x'] }), false), true);
  });
});

describe('policy evaluation (synthetic invalid/missing registry-signature fixture)', () => {
  // See the fixture file's own "_comment" for why this one is hand-built rather than captured.
  const synthetic = loadFixture<NpmAuditSignaturesResult>('npm-audit-invalid-missing.synthetic.json');
  const syntheticDeps = [
    { name: 'totally-not-tampered', version: '1.0.0', location: 'node_modules/totally-not-tampered' },
    { name: 'ancient-unsigned-package', version: '0.0.1', location: 'node_modules/ancient-unsigned-package' },
  ];

  test('an invalid registry signature fails by default, independent of any allowlist', () => {
    const report = evaluate(syntheticDeps, synthetic, { ...DEFAULT_CONFIG, allow: ['https://github.com/anyone/*'] });
    const result = report.results.find((r) => r.name === 'totally-not-tampered')!;
    assert.equal(result.verdict, 'invalid-signature');
    assert.equal(report.hasViolations, true);
  });

  test('a missing registry signature also fails by default', () => {
    const report = evaluate(syntheticDeps, synthetic, DEFAULT_CONFIG);
    const result = report.results.find((r) => r.name === 'ancient-unsigned-package')!;
    assert.equal(result.verdict, 'missing-signature');
    assert.equal(report.hasViolations, true);
  });

  test('failOnInvalidSignature: false opts back out of that (documented as not recommended)', () => {
    const report = evaluate(syntheticDeps, synthetic, { ...DEFAULT_CONFIG, failOnInvalidSignature: false });
    assert.equal(report.hasViolations, false);
  });
});

describe('report formatting', () => {
  const deps = parseLockfile(REAL_LOCKFILE_RAW, REAL_LOCKFILE_PATH);
  const config: ProvenanceGateConfig = { ...DEFAULT_CONFIG, allow: ['https://github.com/sigstore/*'] };
  const report = evaluate(deps, REAL_AUDIT(), config);

  test('text report names the mismatched package and its real repo', () => {
    const text = formatText(report, config);
    assert.match(text, /fs-minipass@3\.0\.3/);
    assert.match(text, /https:\/\/github\.com\/npm\/fs-minipass/);
    assert.match(text, /Policy violations \(1\)/);
  });

  test('json report round-trips through JSON.parse with a violation flag per result', () => {
    const parsed = JSON.parse(formatJson(report, config));
    const fsMinipass = parsed.results.find((r: { name: string }) => r.name === 'fs-minipass');
    assert.equal(fsMinipass.violation, true);
    const sigstore = parsed.results.find((r: { name: string }) => r.name === 'sigstore');
    assert.equal(sigstore.violation, false);
  });
});

describe('config loading', () => {
  test('defaults to report-only when no config file exists', async () => {
    await withTempDir(async (dir) => {
      const cfg = await loadConfig(dir, 'provenance-gate.config.json');
      assert.deepEqual(cfg, DEFAULT_CONFIG);
    });
  });

  test('merges a partial config file over the defaults', async () => {
    await withTempDir(async (dir) => {
      await writeFile(path.join(dir, 'provenance-gate.config.json'), JSON.stringify({ allow: ['https://github.com/x/*'] }));
      const cfg = await loadConfig(dir, 'provenance-gate.config.json');
      assert.deepEqual(cfg.allow, ['https://github.com/x/*']);
      assert.equal(cfg.failOnMismatch, true); // default retained
    });
  });

  test('rejects a config file that is not an object', async () => {
    await withTempDir(async (dir) => {
      await writeFile(path.join(dir, 'provenance-gate.config.json'), JSON.stringify(['nope']));
      await assert.rejects(loadConfig(dir, 'provenance-gate.config.json'), ConfigError);
    });
  });

  test('rejects a wrongly-typed field', async () => {
    await withTempDir(async (dir) => {
      await writeFile(path.join(dir, 'provenance-gate.config.json'), JSON.stringify({ allow: 'not-an-array' }));
      await assert.rejects(loadConfig(dir, 'provenance-gate.config.json'), ConfigError);
    });
  });

  test('rejects invalid JSON', async () => {
    await withTempDir(async (dir) => {
      await writeFile(path.join(dir, 'provenance-gate.config.json'), '{ not json');
      await assert.rejects(loadConfig(dir, 'provenance-gate.config.json'), ConfigError);
    });
  });
});

describe('runGate (orchestration, with an injected audit runner — no network)', () => {
  test('wires the lockfile and a fake audit runner together end to end', async () => {
    await withTempDir(async (dir) => {
      await writeFile(path.join(dir, 'package-lock.json'), REAL_LOCKFILE_RAW);
      const report = await runGate(
        { ...DEFAULT_CONFIG, allow: ['https://github.com/sigstore/*'] },
        { cwd: dir, auditRunner: async () => REAL_AUDIT() },
      );
      assert.equal(report.hasViolations, true); // fs-minipass mismatch
      assert.equal(report.counts.ok, 2);
    });
  });
});

describe('cli-core main() (argv + injected I/O, no network, no real npm)', () => {
  function capture() {
    const out: string[] = [];
    const err: string[] = [];
    return { out, err, stdout: (l: string) => out.push(l), stderr: (l: string) => err.push(l) };
  }

  test('--help exits 0 and prints usage without touching the filesystem', async () => {
    const io = capture();
    const code = await main(['--help'], io);
    assert.equal(code, 0);
    assert.match(io.out.join('\n'), /Usage:/);
  });

  test('--version exits 0 and prints a version string', async () => {
    const io = capture();
    const code = await main(['--version'], io);
    assert.equal(code, 0);
    assert.match(io.out[0]!, /^\d+\.\d+\.\d+$/);
  });

  test('an unknown flag exits 2 without running anything', async () => {
    const io = capture();
    const code = await main(['--nope'], io);
    assert.equal(code, 2);
    assert.match(io.err.join('\n'), /Unknown argument/);
  });

  test('exits 0 clean when everything is allowlisted', async () => {
    await withTempDir(async (dir) => {
      await writeFile(path.join(dir, 'package-lock.json'), REAL_LOCKFILE_RAW);
      const io = capture();
      const code = await main(
        ['--cwd', dir, '--allow', 'https://github.com/sigstore/*', '--allow', 'https://github.com/npm/*'],
        { ...io, auditRunner: async () => REAL_AUDIT() },
      );
      assert.equal(code, 0);
    });
  });

  test('exits 1 on a repo mismatch', async () => {
    await withTempDir(async (dir) => {
      await writeFile(path.join(dir, 'package-lock.json'), REAL_LOCKFILE_RAW);
      const io = capture();
      const code = await main(['--cwd', dir, '--allow', 'https://github.com/sigstore/*'], {
        ...io,
        auditRunner: async () => REAL_AUDIT(),
      });
      assert.equal(code, 1);
    });
  });

  test('exits 2 when there is no lockfile to analyse', async () => {
    await withTempDir(async (dir) => {
      const io = capture();
      const code = await main(['--cwd', dir], { ...io, auditRunner: async () => REAL_AUDIT() });
      assert.equal(code, 2);
      assert.match(io.err.join('\n'), /could not analyse/);
    });
  });

  test('--json produces parseable JSON on stdout', async () => {
    await withTempDir(async (dir) => {
      await writeFile(path.join(dir, 'package-lock.json'), REAL_LOCKFILE_RAW);
      const io = capture();
      await main(['--cwd', dir, '--json', '--allow', 'https://github.com/sigstore/*'], {
        ...io,
        auditRunner: async () => REAL_AUDIT(),
      });
      const parsed = JSON.parse(io.out.join('\n'));
      assert.ok(Array.isArray(parsed.results));
    });
  });

  test('--fail-on-missing flips the default from the CLI without a config file', async () => {
    await withTempDir(async (dir) => {
      await writeFile(path.join(dir, 'package-lock.json'), REAL_LOCKFILE_RAW);
      const allow = ['--allow', 'https://github.com/sigstore/*', '--allow', 'https://github.com/npm/*'];
      const io1 = capture();
      const clean = await main(['--cwd', dir, ...allow], { ...io1, auditRunner: async () => REAL_AUDIT() });
      const io2 = capture();
      const strict = await main(['--cwd', dir, ...allow, '--fail-on-missing'], {
        ...io2,
        auditRunner: async () => REAL_AUDIT(),
      });
      assert.equal(clean, 0);
      assert.equal(strict, 1);
    });
  });
});

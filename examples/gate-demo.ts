/**
 * Installs two real packages — one with npm provenance, one without — into a
 * scratch directory, then runs the real gate (real npm audit signatures shell-out,
 * real DSSE decode) against them and prints the report. Needs network.
 *
 *   node examples/gate-demo.ts
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { runGate, formatText, DEFAULT_CONFIG } from '../src/index.ts';

const execFileAsync = promisify(execFile);

const dir = await mkdtemp(path.join(tmpdir(), 'provenance-gate-demo-'));
try {
  await writeFile(
    path.join(dir, 'package.json'),
    JSON.stringify({ name: 'provenance-gate-demo', version: '1.0.0', private: true }),
  );

  console.log('installing sigstore@2.3.1 (has provenance) and left-pad (does not)...\n');
  await execFileAsync('npm', ['install', 'sigstore@2.3.1', 'left-pad', '--no-fund', '--loglevel=error'], { cwd: dir });

  console.log('--- no allowlist configured (report-only default) ---\n');
  const reportOnly = await runGate(DEFAULT_CONFIG, { cwd: dir });
  console.log(formatText(reportOnly, DEFAULT_CONFIG));

  console.log('\n--- allowlisting only https://github.com/sigstore/* ---\n');
  const scoped = { ...DEFAULT_CONFIG, allow: ['https://github.com/sigstore/*'] };
  const scopedReport = await runGate(scoped, { cwd: dir });
  console.log(formatText(scopedReport, scoped));
  console.log(`\nexit code would be: ${scopedReport.hasViolations ? 1 : 0}`);

  console.log('\n--- allowlisting a repo that is NOT the real one, to show a mismatch ---\n');
  const wrong = { ...DEFAULT_CONFIG, allow: ['https://github.com/some-org-that-does-not-publish-sigstore/*'] };
  const wrongReport = await runGate(wrong, { cwd: dir });
  console.log(formatText(wrongReport, wrong));
  console.log(`\nexit code would be: ${wrongReport.hasViolations ? 1 : 0}`);
} finally {
  await rm(dir, { recursive: true, force: true });
}

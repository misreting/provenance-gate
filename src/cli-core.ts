import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './config.ts';
import { runGate } from './gate.ts';
import { formatText, formatJson } from './report.ts';
import { AnalysisError, ConfigError } from './errors.ts';
import type { AuditRunner } from './audit.ts';

/** Everything `main` needs beyond argv, injectable so tests never touch the network or real npm. */
export interface CliOptions {
  auditRunner?: AuditRunner;
  stdout?: (line: string) => void;
  stderr?: (line: string) => void;
}

interface ParsedArgs {
  cwd: string;
  configPath: string;
  json: boolean;
  allow: string[];
  failOnMissing?: boolean;
  failOnMismatch?: boolean;
  help: boolean;
  version: boolean;
}

class CliUsageError extends Error {}

const HELP = `provenance-gate — fail CI when a dependency's npm provenance names a build repo you did not allowlist

Usage:
  provenance-gate [options]

Requires an installed project (node_modules present, package-lock.json v2/v3)
in the current directory — it reads the lockfile and shells out to
"npm audit signatures --json --include-attestations".

Options:
  --config <path>          Config file (default: provenance-gate.config.json)
  --cwd <path>             Project directory (default: current directory)
  --allow <pattern>        Add an allowlist entry (repeatable), merged with the config file
  --fail-on-missing        Fail on packages with no provenance at all (default: off)
  --no-fail-on-missing     Explicitly keep that off
  --no-fail-on-mismatch    Do not fail when an attested repo isn't allowlisted (default: fails)
  --json                   Print a machine-readable report instead of text
  -h, --help               Show this help
  -v, --version            Show the installed version

Exit codes:
  0  clean
  1  policy violation found
  2  could not analyse (no lockfile, npm missing, bad config, ...)

Config file (provenance-gate.config.json):
  {
    "allow": ["https://github.com/myorg/*", "https://github.com/sigstore/sigstore-js"],
    "ignore": ["some-vendored-fork@1.2.3"],
    "failOnMissing": false,
    "failOnMismatch": true,
    "failOnInvalidSignature": true
  }
`;

function requireValue(argv: readonly string[], index: number, flag: string): string {
  const value = argv[index];
  if (value === undefined) throw new CliUsageError(`${flag} requires a value`);
  return value;
}

export function parseArgs(argv: readonly string[]): ParsedArgs {
  const args: ParsedArgs = {
    cwd: process.cwd(),
    configPath: 'provenance-gate.config.json',
    json: false,
    allow: [],
    help: false,
    version: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case '--config':
        args.configPath = requireValue(argv, ++i, '--config');
        break;
      case '--cwd':
        args.cwd = requireValue(argv, ++i, '--cwd');
        break;
      case '--allow':
        args.allow.push(requireValue(argv, ++i, '--allow'));
        break;
      case '--fail-on-missing':
        args.failOnMissing = true;
        break;
      case '--no-fail-on-missing':
        args.failOnMissing = false;
        break;
      case '--fail-on-mismatch':
        args.failOnMismatch = true;
        break;
      case '--no-fail-on-mismatch':
        args.failOnMismatch = false;
        break;
      case '--json':
        args.json = true;
        break;
      case '-h':
      case '--help':
        args.help = true;
        break;
      case '-v':
      case '--version':
        args.version = true;
        break;
      default:
        throw new CliUsageError(`Unknown argument: ${arg}`);
    }
  }
  return args;
}

function readVersion(): string {
  try {
    const dir = path.dirname(fileURLToPath(import.meta.url));
    const pkgPath = path.join(dir, '..', 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

/**
 * The CLI's whole behavior, as a pure-ish function of argv + injectable I/O —
 * no `process.exit`, so tests can call it directly and assert on the return
 * code and captured output instead of spawning a subprocess.
 */
export async function main(argv: readonly string[], options: CliOptions = {}): Promise<number> {
  const stdout = options.stdout ?? ((line: string) => console.log(line));
  const stderr = options.stderr ?? ((line: string) => console.error(line));

  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (err) {
    stderr(`provenance-gate: ${(err as Error).message}`);
    stderr('Run "provenance-gate --help" for usage.');
    return 2;
  }

  if (args.help) {
    stdout(HELP);
    return 0;
  }
  if (args.version) {
    stdout(readVersion());
    return 0;
  }

  let config;
  try {
    config = await loadConfig(args.cwd, args.configPath);
  } catch (err) {
    if (err instanceof ConfigError) {
      stderr(`provenance-gate: ${err.message}`);
      return 2;
    }
    throw err;
  }

  if (args.allow.length > 0) config = { ...config, allow: [...config.allow, ...args.allow] };
  if (args.failOnMissing !== undefined) config = { ...config, failOnMissing: args.failOnMissing };
  if (args.failOnMismatch !== undefined) config = { ...config, failOnMismatch: args.failOnMismatch };

  let report;
  try {
    report = await runGate(config, { cwd: args.cwd, auditRunner: options.auditRunner });
  } catch (err) {
    if (err instanceof AnalysisError) {
      stderr(`provenance-gate: could not analyse — ${err.message}`);
      return 2;
    }
    throw err;
  }

  stdout(args.json ? formatJson(report, config) : formatText(report, config));
  return report.hasViolations ? 1 : 0;
}

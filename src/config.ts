import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { ConfigError } from './errors.ts';
import { DEFAULT_CONFIG, type ProvenanceGateConfig } from './policy.ts';

/** The on-disk shape: every field optional, merged over `DEFAULT_CONFIG`. */
export interface ProvenanceGateConfigFile {
  allow?: string[];
  ignore?: string[];
  failOnMissing?: boolean;
  failOnMismatch?: boolean;
  failOnInvalidSignature?: boolean;
}

function assertStringArray(value: unknown, field: string): asserts value is string[] {
  if (!Array.isArray(value) || !value.every((v) => typeof v === 'string')) {
    throw new ConfigError(`"${field}" must be an array of strings`);
  }
}

function assertBoolean(value: unknown, field: string): asserts value is boolean {
  if (typeof value !== 'boolean') {
    throw new ConfigError(`"${field}" must be a boolean`);
  }
}

/** Validate an already-parsed config object (exported so callers building a config in code can reuse it). */
export function validateConfigFile(raw: unknown): ProvenanceGateConfigFile {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new ConfigError('Config must be a JSON object');
  }
  const obj = raw as Record<string, unknown>;
  if ('allow' in obj) assertStringArray(obj.allow, 'allow');
  if ('ignore' in obj) assertStringArray(obj.ignore, 'ignore');
  if ('failOnMissing' in obj) assertBoolean(obj.failOnMissing, 'failOnMissing');
  if ('failOnMismatch' in obj) assertBoolean(obj.failOnMismatch, 'failOnMismatch');
  if ('failOnInvalidSignature' in obj) assertBoolean(obj.failOnInvalidSignature, 'failOnInvalidSignature');
  return obj as ProvenanceGateConfigFile;
}

/**
 * Load and validate a config file, falling back to `DEFAULT_CONFIG` (report-only:
 * no allowlist, so nothing can mismatch) when it does not exist. `configPath` may
 * be relative to `cwd` or absolute.
 */
export async function loadConfig(cwd: string, configPath: string): Promise<ProvenanceGateConfig> {
  const resolved = path.isAbsolute(configPath) ? configPath : path.join(cwd, configPath);

  let raw: string;
  try {
    raw = await readFile(resolved, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return { ...DEFAULT_CONFIG };
    }
    throw new ConfigError(`Could not read config file ${resolved}: ${(err as Error).message}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new ConfigError(`${resolved} is not valid JSON: ${(err as Error).message}`);
  }

  const file = validateConfigFile(parsed);
  return {
    allow: file.allow ?? DEFAULT_CONFIG.allow,
    ignore: file.ignore ?? DEFAULT_CONFIG.ignore,
    failOnMissing: file.failOnMissing ?? DEFAULT_CONFIG.failOnMissing,
    failOnMismatch: file.failOnMismatch ?? DEFAULT_CONFIG.failOnMismatch,
    failOnInvalidSignature: file.failOnInvalidSignature ?? DEFAULT_CONFIG.failOnInvalidSignature,
  };
}

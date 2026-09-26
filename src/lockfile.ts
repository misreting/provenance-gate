import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { AnalysisError } from './errors.ts';

/** One resolved, installed dependency: what a policy check runs against. */
export interface DependencyRef {
  name: string;
  version: string;
  /** `node_modules/...` path from the lockfile, kept for diagnostics. */
  location: string;
}

interface LockfilePackageEntry {
  name?: string;
  version?: string;
  link?: boolean;
  resolved?: string;
}

interface NpmLockfile {
  lockfileVersion?: number;
  packages?: Record<string, LockfilePackageEntry>;
  /** lockfile v1 shape, kept only to give a clearer error message. */
  dependencies?: Record<string, unknown>;
}

/** The package name a `packages["node_modules/..."]` key implies. */
function nameFromKey(key: string): string {
  const idx = key.lastIndexOf('node_modules/');
  return key.slice(idx + 'node_modules/'.length);
}

/**
 * Parse an already-read `package-lock.json` string into the deduplicated set
 * of packages actually installed — including every nested copy at a different
 * version, since those are audited independently and can carry different (or
 * no) provenance. Pure and synchronous, so it's the part of lockfile handling
 * that's actually easy to unit test with fixtures.
 *
 * Requires lockfile v2/v3 (`npm` >= 7's `"packages"` map). Local `file:`/workspace
 * links are skipped: they were never fetched from a registry, so "no provenance"
 * would be true but meaningless noise.
 */
export function parseLockfile(raw: string, lockPath: string): DependencyRef[] {
  let lockfile: NpmLockfile;
  try {
    lockfile = JSON.parse(raw) as NpmLockfile;
  } catch (err) {
    throw new AnalysisError(`${lockPath} is not valid JSON.`, err);
  }

  if (!lockfile.packages) {
    throw new AnalysisError(
      `${lockPath} is lockfileVersion ${lockfile.lockfileVersion ?? 1}, which has no "packages" ` +
        `map. provenance-gate needs a v2 or v3 lockfile (npm >= 7): reinstall with a current npm ` +
        `so the lockfile is upgraded, then commit it.`,
    );
  }

  const deps = new Map<string, DependencyRef>();
  for (const [key, entry] of Object.entries(lockfile.packages)) {
    if (key === '') continue; // the project root itself
    if (entry.link) continue; // workspace/`file:` symlink, never came from a registry
    if (!entry.version) continue; // defensive: malformed or root-like entry
    const name = entry.name ?? nameFromKey(key);
    const dedupeKey = `${name}@${entry.version}`;
    if (!deps.has(dedupeKey)) {
      deps.set(dedupeKey, { name, version: entry.version, location: key });
    }
  }

  return [...deps.values()];
}

/** Read and parse `<cwd>/package-lock.json`. See `parseLockfile` for the format requirements. */
export async function readLockfileDependencies(cwd: string): Promise<DependencyRef[]> {
  const lockPath = path.join(cwd, 'package-lock.json');
  let raw: string;
  try {
    raw = await readFile(lockPath, 'utf8');
  } catch (err) {
    throw new AnalysisError(
      `No package-lock.json in ${cwd}. provenance-gate reads the resolved dependency ` +
        `tree from the lockfile — run "npm install" (or "npm ci") first.`,
      err,
    );
  }
  return parseLockfile(raw, lockPath);
}

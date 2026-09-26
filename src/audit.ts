import { execFile, type ExecFileException } from 'node:child_process';
import { AnalysisError } from './errors.ts';
import type { AttestationBundleEntry } from './attestation.ts';

/** A package reference the way `npm audit signatures` names it. */
export interface NpmAuditPackageRef {
  name: string;
  version: string;
  location?: string;
  registry?: string;
}

/** An entry of `verified[]`: registry-signature-verified, and possibly attested too. */
export interface NpmAuditVerifiedPackage extends NpmAuditPackageRef {
  attestations?: {
    url: string;
    provenance?: { predicateType: string };
  };
  attestationBundles?: AttestationBundleEntry[];
}

/** The parsed shape of `npm audit signatures --json --include-attestations`. */
export interface NpmAuditSignaturesResult {
  /** Registry signature failed cryptographic verification — a serious, non-provenance signal. */
  invalid: NpmAuditPackageRef[];
  /** Registry signature absent where one was expected. */
  missing: NpmAuditPackageRef[];
  /**
   * Registry-signature-verified packages. Only present with `--include-attestations`,
   * and even then only lists packages that also carry a provenance attestation —
   * npm does not enumerate the (usually much larger) set of signed-but-unattested
   * packages here at all.
   */
  verified: NpmAuditVerifiedPackage[];
}

/** Runs `npm audit signatures --json --include-attestations` and returns its parsed output. */
export type AuditRunner = (cwd: string) => Promise<NpmAuditSignaturesResult>;

function runNpm(cwd: string): Promise<{ stdout: string; error?: ExecFileException }> {
  return new Promise((resolvePromise) => {
    execFile(
      'npm',
      ['audit', 'signatures', '--json', '--include-attestations'],
      { cwd, maxBuffer: 64 * 1024 * 1024 },
      (error, stdout) => {
        // npm audit signatures exits non-zero when it finds invalid/missing
        // signatures — that is a normal, meaningful result, not a failure to run.
        // We still capture `error` so a genuinely missing/broken npm is caught below.
        resolvePromise({ stdout, error: error ?? undefined });
      },
    );
  });
}

/**
 * The real `AuditRunner`: shells out to the `npm` on PATH.
 *
 * Why shell out rather than fetch `registry.npmjs.org/-/npm/v1/attestations/<pkg>`
 * ourselves: `npm audit signatures` already (a) resolves exactly the installed
 * tree, including scoped/aliased/private-registry packages and whatever registry
 * auth is configured, and (b) performs npm's own Sigstore verification (cert
 * chain + Rekor inclusion) before a package lands in `verified` — reimplementing
 * that with a direct fetch would mean either skipping that verification (worse)
 * or reimplementing Sigstore's client ourselves (a much bigger, riskier surface
 * than this tool is trying to be). The trade-off: this tool inherits whatever
 * `npm audit signatures` does and does not check, and needs an installed
 * `node_modules` (a plain lockfile is not enough — see the failure mode below).
 */
export const runNpmAuditSignatures: AuditRunner = async (cwd: string) => {
  let result: Awaited<ReturnType<typeof runNpm>>;
  try {
    result = await runNpm(cwd);
  } catch (err) {
    throw new AnalysisError(`Failed to spawn "npm" in ${cwd}. Is npm on PATH?`, err);
  }

  if (result.error && result.error.code === 'ENOENT') {
    throw new AnalysisError('"npm" was not found on PATH.', result.error);
  }

  const trimmed = result.stdout.trim();
  if (trimmed === '') {
    throw new AnalysisError(
      `"npm audit signatures" produced no output in ${cwd}.` +
        (result.error ? ` (${result.error.message})` : ''),
      result.error,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch (err) {
    throw new AnalysisError(
      `Could not parse "npm audit signatures" output as JSON. First 300 chars:\n` +
        trimmed.slice(0, 300),
      err,
    );
  }

  const obj = parsed as Record<string, unknown>;
  if (obj.error) {
    const err = obj.error as { summary?: string; detail?: string };
    throw new AnalysisError(
      `"npm audit signatures" reported: ${err.summary ?? 'unknown error'}. ` +
        `This usually means node_modules is missing or out of sync with package-lock.json — ` +
        `run "npm install" (or "npm ci") in ${cwd} first.`,
    );
  }

  return {
    invalid: Array.isArray(obj.invalid) ? (obj.invalid as NpmAuditPackageRef[]) : [],
    missing: Array.isArray(obj.missing) ? (obj.missing as NpmAuditPackageRef[]) : [],
    verified: Array.isArray(obj.verified) ? (obj.verified as NpmAuditVerifiedPackage[]) : [],
  };
};

import { extractProvenancePredicate, extractRepository, findSlsaBundle } from './attestation.ts';
import { compileAllowlist, matchAllowlist, type CompiledPattern } from './allowlist.ts';
import type { DependencyRef } from './lockfile.ts';
import type { NpmAuditSignaturesResult } from './audit.ts';

/** How one package came out of the gate. */
export type Verdict =
  /** Attested, and its build-source repository is on the allowlist. */
  | 'ok'
  /** No attestation of any kind. Normal for most of the ecosystem today. */
  | 'no-provenance'
  /** Attested, but the build-source repository is not on the allowlist. */
  | 'mismatch'
  /** Has an attestation bundle, but not one this tool can read a repo claim out of. */
  | 'unverifiable'
  /** npm's own registry-signature check failed outright — not a provenance question. */
  | 'invalid-signature'
  /** npm expected a registry signature and found none. */
  | 'missing-signature'
  /** Listed in the config's `ignore`, excluded from enforcement entirely. */
  | 'ignored';

export interface PackageResult {
  name: string;
  version: string;
  verdict: Verdict;
  /** The `workflow.repository` claim, when an SLSA predicate was readable. */
  repository?: string;
  /** Which allowlist entry matched, when `verdict === 'ok'`. */
  matchedPattern?: string;
  /** Extra detail for the report, e.g. why a bundle was unverifiable. */
  detail?: string;
}

export interface ProvenanceGateConfig {
  /**
   * Allowed build-source repositories, e.g. `https://github.com/sigstore/sigstore-js`
   * or the org-level glob `https://github.com/myorg/*`. An empty (or absent)
   * allowlist disables mismatch enforcement automatically — see `failOnMismatch`.
   */
  allow: string[];
  /**
   * `name` or `name@version` entries excluded from every check. Use for a
   * specific, reviewed exception — not as a way to silence the whole report.
   */
  ignore: string[];
  /**
   * Fail the gate for packages with no attestation at all.
   *
   * Defaults to `false`. Most published npm packages carry no provenance today,
   * so failing on missing-by-default turns the gate into a wall of noise on
   * essentially every real dependency tree and trains people to ignore it (or
   * disable it). Flip it on once your own supply chain — and the parts of the
   * ecosystem you depend on — has actually adopted provenance.
   */
  failOnMissing: boolean;
  /**
   * Fail the gate for packages that are attested but whose build-source repo
   * is not on `allow` (including packages this tool can't extract a repo claim
   * from at all). Defaults to `true` — but only takes effect when `allow` is
   * non-empty; see `allow`.
   */
  failOnMismatch: boolean;
  /**
   * Fail the gate when npm's own registry-signature check fails or is missing.
   * Defaults to `true`. This is not a provenance/policy question — it means npm
   * could not confirm the tarball you installed is the one the registry holds,
   * which is a stronger, independent red flag. Turning it off is not recommended.
   */
  failOnInvalidSignature: boolean;
}

export const DEFAULT_CONFIG: ProvenanceGateConfig = {
  allow: [],
  ignore: [],
  failOnMissing: false,
  failOnMismatch: true,
  failOnInvalidSignature: true,
};

export interface GateReport {
  results: PackageResult[];
  /** Whether `allow` was empty, meaning mismatch enforcement was auto-disabled. */
  reportOnly: boolean;
  /** `true` if any result should fail the build under this config. */
  hasViolations: boolean;
  counts: Record<Verdict, number>;
}

function ignoreKeySet(ignore: readonly string[]): Set<string> {
  return new Set(ignore);
}

function isIgnored(dep: DependencyRef, ignored: Set<string>): boolean {
  return ignored.has(dep.name) || ignored.has(`${dep.name}@${dep.version}`);
}

/**
 * Apply a policy to the raw audit result and lockfile dependency list, producing
 * one verdict per installed package. Pure and synchronous — no I/O — so it is
 * the easiest part of this library to unit test.
 */
export function evaluate(
  deps: readonly DependencyRef[],
  audit: NpmAuditSignaturesResult,
  config: ProvenanceGateConfig,
): GateReport {
  const ignored = ignoreKeySet(config.ignore);
  const compiled: CompiledPattern[] = compileAllowlist(config.allow);
  const reportOnly = config.allow.length === 0;

  const invalidKeys = new Set(audit.invalid.map((p) => `${p.name}@${p.version}`));
  const missingKeys = new Set(audit.missing.map((p) => `${p.name}@${p.version}`));
  const verifiedByKey = new Map(audit.verified.map((p) => [`${p.name}@${p.version}`, p]));

  const results: PackageResult[] = deps.map((dep) => {
    const key = `${dep.name}@${dep.version}`;

    if (isIgnored(dep, ignored)) {
      return { name: dep.name, version: dep.version, verdict: 'ignored' };
    }
    if (invalidKeys.has(key)) {
      return {
        name: dep.name,
        version: dep.version,
        verdict: 'invalid-signature',
        detail: 'npm reports the registry signature failed verification',
      };
    }
    if (missingKeys.has(key)) {
      return {
        name: dep.name,
        version: dep.version,
        verdict: 'missing-signature',
        detail: 'npm expected a registry signature and found none',
      };
    }

    const verified = verifiedByKey.get(key);
    const slsaBundle = findSlsaBundle(verified?.attestationBundles);
    if (!slsaBundle) {
      return { name: dep.name, version: dep.version, verdict: 'no-provenance' };
    }

    let repository: string | undefined;
    try {
      const predicate = extractProvenancePredicate(slsaBundle);
      repository = extractRepository(predicate);
    } catch (err) {
      return {
        name: dep.name,
        version: dep.version,
        verdict: 'unverifiable',
        detail: `attestation present but could not be decoded: ${(err as Error).message}`,
      };
    }

    if (!repository) {
      return {
        name: dep.name,
        version: dep.version,
        verdict: 'unverifiable',
        detail: 'attestation present but has no buildDefinition.externalParameters.workflow.repository',
      };
    }

    const matched = matchAllowlist(repository, compiled);
    if (matched) {
      return { name: dep.name, version: dep.version, verdict: 'ok', repository, matchedPattern: matched };
    }
    return { name: dep.name, version: dep.version, verdict: 'mismatch', repository };
  });

  const counts: Record<Verdict, number> = {
    ok: 0,
    'no-provenance': 0,
    mismatch: 0,
    unverifiable: 0,
    'invalid-signature': 0,
    'missing-signature': 0,
    ignored: 0,
  };
  for (const r of results) counts[r.verdict]++;

  const hasViolations = results.some((r) => isViolation(r, config, reportOnly));

  return { results, reportOnly, hasViolations, counts };
}

/** Whether one package's verdict should fail the gate under `config`. */
export function isViolation(result: PackageResult, config: ProvenanceGateConfig, reportOnly: boolean): boolean {
  switch (result.verdict) {
    case 'ok':
    case 'ignored':
      return false;
    case 'no-provenance':
      return config.failOnMissing;
    case 'mismatch':
    case 'unverifiable':
      return !reportOnly && config.failOnMismatch;
    case 'invalid-signature':
    case 'missing-signature':
      return config.failOnInvalidSignature;
  }
}

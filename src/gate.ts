import { readLockfileDependencies } from './lockfile.ts';
import { runNpmAuditSignatures, type AuditRunner } from './audit.ts';
import { evaluate, type GateReport, type ProvenanceGateConfig } from './policy.ts';

export interface RunGateOptions {
  /** Project directory containing `package-lock.json`. Default: `process.cwd()`. */
  cwd?: string;
  /** Injectable for tests; defaults to actually shelling out to `npm`. */
  auditRunner?: AuditRunner;
}

/**
 * Run the whole gate: read the lockfile, ask npm for signature/attestation
 * data, and score every installed package against `config`.
 *
 * Throws `AnalysisError` (exit code 2 territory) if the lockfile can't be read
 * or `npm audit signatures` can't be run/parsed — both are "could not analyse",
 * distinct from "analysed, and it's a policy violation".
 */
export async function runGate(
  config: ProvenanceGateConfig,
  options: RunGateOptions = {},
): Promise<GateReport> {
  const cwd = options.cwd ?? process.cwd();
  const auditRunner = options.auditRunner ?? runNpmAuditSignatures;

  const [deps, audit] = await Promise.all([readLockfileDependencies(cwd), auditRunner(cwd)]);
  return evaluate(deps, audit, config);
}

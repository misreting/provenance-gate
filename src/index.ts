export { runGate, type RunGateOptions } from './gate.ts';
export {
  evaluate,
  isViolation,
  DEFAULT_CONFIG,
  type ProvenanceGateConfig,
  type GateReport,
  type PackageResult,
  type Verdict,
} from './policy.ts';
export { loadConfig, validateConfigFile, type ProvenanceGateConfigFile } from './config.ts';
export { formatText, formatJson } from './report.ts';
export { readLockfileDependencies, parseLockfile, type DependencyRef } from './lockfile.ts';
export {
  runNpmAuditSignatures,
  type AuditRunner,
  type NpmAuditSignaturesResult,
  type NpmAuditPackageRef,
  type NpmAuditVerifiedPackage,
} from './audit.ts';
export {
  decodeDssePayload,
  extractProvenancePredicate,
  extractRepository,
  findSlsaBundle,
  MalformedAttestationError,
  SLSA_PROVENANCE_V1,
  type DsseEnvelope,
  type AttestationBundleEntry,
  type SlsaProvenancePredicate,
  type SlsaBuildDefinition,
  type SlsaWorkflow,
  type InTotoStatement,
} from './attestation.ts';
export { compileAllowlist, matchAllowlist, type CompiledPattern } from './allowlist.ts';
export { ProvenanceGateError, AnalysisError, ConfigError } from './errors.ts';

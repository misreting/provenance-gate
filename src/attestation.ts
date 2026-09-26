/**
 * Decoding for the DSSE-wrapped SLSA provenance attestation that `npm audit
 * signatures --include-attestations` returns for a package, and extraction of
 * the one field this whole library is built around:
 * `buildDefinition.externalParameters.workflow.repository`.
 *
 * None of this verifies anything cryptographically. It parses base64 and JSON.
 * See the README's "What this does not verify" section.
 */

/** The predicate type npm publishes provenance under, per the SLSA v1 spec. */
export const SLSA_PROVENANCE_V1 = 'https://slsa.dev/provenance/v1';

/** A DSSE envelope as it appears inside an npm attestation bundle. */
export interface DsseEnvelope {
  payload: string;
  payloadType: string;
  signatures?: Array<{ keyid?: string; sig: string }>;
}

/** One entry of `verified[].attestationBundles` from `npm audit signatures`. */
export interface AttestationBundleEntry {
  predicateType: string;
  bundle: {
    mediaType?: string;
    dsseEnvelope: DsseEnvelope;
  };
}

/** The in-toto `workflow` claim inside a SLSA `buildDefinition`. */
export interface SlsaWorkflow {
  ref?: string;
  repository?: string;
  path?: string;
}

/** The subset of a SLSA v1 `buildDefinition` this library reads. */
export interface SlsaBuildDefinition {
  buildType?: string;
  externalParameters?: {
    workflow?: SlsaWorkflow;
    [key: string]: unknown;
  };
  internalParameters?: Record<string, unknown>;
  resolvedDependencies?: Array<{ uri?: string; digest?: Record<string, string> }>;
}

/** The SLSA v1 provenance predicate: `statement.predicate` when `predicateType` matches. */
export interface SlsaProvenancePredicate {
  buildDefinition?: SlsaBuildDefinition;
  runDetails?: {
    builder?: { id?: string };
    metadata?: { invocationId?: string };
  };
}

/** An in-toto v1 Statement: the JSON a DSSE envelope's `payload` decodes to. */
export interface InTotoStatement {
  _type?: string;
  subject?: Array<{ name?: string; digest?: Record<string, string> }>;
  predicateType?: string;
  predicate?: unknown;
}

/** Thrown when a DSSE payload isn't the base64+JSON envelope we expect. */
export class MalformedAttestationError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message, cause !== undefined ? { cause } : undefined);
    this.name = 'MalformedAttestationError';
  }
}

/** Base64-decode and JSON-parse a DSSE envelope's `payload` into an in-toto Statement. */
export function decodeDssePayload(envelope: DsseEnvelope): InTotoStatement {
  let json: string;
  try {
    json = Buffer.from(envelope.payload, 'base64').toString('utf8');
  } catch (err) {
    throw new MalformedAttestationError('DSSE payload is not valid base64', err);
  }
  try {
    return JSON.parse(json) as InTotoStatement;
  } catch (err) {
    throw new MalformedAttestationError('DSSE payload did not decode to JSON', err);
  }
}

/** Pick the SLSA v1 provenance bundle out of a package's attestation bundles, if present. */
export function findSlsaBundle(
  bundles: AttestationBundleEntry[] | undefined,
): AttestationBundleEntry | undefined {
  return bundles?.find((b) => b.predicateType === SLSA_PROVENANCE_V1);
}

/**
 * Decode a SLSA v1 attestation bundle down to its provenance predicate.
 * Returns `undefined` (rather than throwing) if the statement's own
 * `predicateType` doesn't match — a mismatch between the bundle's declared
 * type and its payload's declared type is itself a signal we surface, not
 * paper over by trusting whichever label is convenient.
 */
export function extractProvenancePredicate(
  entry: AttestationBundleEntry,
): SlsaProvenancePredicate | undefined {
  const statement = decodeDssePayload(entry.bundle.dsseEnvelope);
  if (statement.predicateType !== SLSA_PROVENANCE_V1) return undefined;
  return statement.predicate as SlsaProvenancePredicate | undefined;
}

/** The `workflow.repository` claim a SLSA predicate makes about its own build source, if any. */
export function extractRepository(predicate: SlsaProvenancePredicate | undefined): string | undefined {
  return predicate?.buildDefinition?.externalParameters?.workflow?.repository;
}

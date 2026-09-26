/** Base class for every error this library throws. */
export class ProvenanceGateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/**
 * The gate could not be run to a conclusion at all: no lockfile, `npm` missing,
 * `npm audit signatures` produced output we don't understand, and so on.
 *
 * Maps to exit code 2 ("could not analyse"), which is deliberately distinct
 * from exit code 1 ("analysed, and found a policy violation").
 */
export class AnalysisError extends ProvenanceGateError {
  /** The underlying error, when one triggered this. */
  cause?: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.cause = cause;
  }
}

/** The policy config file exists but is not valid. Also maps to exit code 2. */
export class ConfigError extends ProvenanceGateError {}

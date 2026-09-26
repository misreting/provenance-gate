/**
 * Matching a build-source repository URL against a project's allowlist.
 *
 * Entries are plain repository URLs (`https://github.com/sigstore/sigstore-js`)
 * or org-level globs (`https://github.com/myorg/*`). `*` stands for exactly one
 * path segment — the repo name — which is all GitHub/GitLab/etc. URLs need: a
 * host, an owner, and a repo. It does not cross a `/`, so
 * `https://github.com/myorg/*` allows `https://github.com/myorg/anything` but
 * not `https://github.com/myorg/anything/nested` or `https://github.com/myorg-evil/x`.
 */

export interface CompiledPattern {
  /** The pattern as written in the config, for reporting which entry matched. */
  source: string;
  regex: RegExp;
}

function escapeRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Strip a trailing `.git` and trailing slashes so `owner/repo`, `owner/repo/`,
 *  and `owner/repo.git` all compare equal. */
function normalize(url: string): string {
  return url.trim().replace(/\.git$/i, '').replace(/\/+$/, '');
}

function patternToRegExp(pattern: string): RegExp {
  const segments = normalize(pattern).split('*').map(escapeRegExp);
  return new RegExp(`^${segments.join('[^/]*')}$`, 'i');
}

/** Precompile allowlist patterns once, so matching many packages is cheap. */
export function compileAllowlist(patterns: readonly string[]): CompiledPattern[] {
  return patterns.map((source) => ({ source, regex: patternToRegExp(source) }));
}

/** The first pattern (in order) that allows `repository`, or `undefined` if none does. */
export function matchAllowlist(repository: string, compiled: readonly CompiledPattern[]): string | undefined {
  const target = normalize(repository);
  return compiled.find((c) => c.regex.test(target))?.source;
}

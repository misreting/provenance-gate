# provenance-gate

A CI gate that enforces a **policy** on npm provenance attestations: which repos
are you willing to let your build come from?

```
Policy violations (12):
  x  @npmcli/agent@2.2.2  [attested, repo NOT allowlisted] — https://github.com/npm/agent
  x  @tufjs/canonical-json@2.0.0  [attested, repo NOT allowlisted] — https://github.com/theupdateframework/tuf-js
  x  cacache@18.0.4  [attested, repo NOT allowlisted] — https://github.com/npm/cacache
  x  fs-minipass@3.0.3  [attested, repo NOT allowlisted] — https://github.com/npm/fs-minipass
  x  semver@7.8.5  [attested, repo NOT allowlisted] — https://github.com/npm/node-semver
  x  tuf-js@2.2.1  [attested, repo NOT allowlisted] — https://github.com/theupdateframework/tuf-js
  ... (12 total)

No provenance at all: 73 package(s) — informational only.

Checked 92 package(s): 7 ok, 12 mismatched, 0 unverifiable, 0 invalid-signature,
0 missing-signature, 73 no-provenance, 0 ignored.
```

That's real output — `npm run demo` — from installing exactly one package
(`sigstore@2.3.1`) with an allowlist of `https://github.com/sigstore/*`. Even
one well-behaved dependency drags in a transitive tree attested from other
real orgs (`npm`, `theupdateframework`) that a narrow allowlist correctly
flags. See [Design decisions](#design-decisions).

## The gap this fills

npm packages can carry a [SLSA](https://slsa.dev/) provenance attestation:
cryptographic proof, signed via [Sigstore](https://www.sigstore.dev/), of
which CI workflow in which repo built the tarball you're about to install.
That sounds like exactly what you want to stop a compromised or
typosquatted dependency. In practice, almost nothing reads it:

- **A plain `npm install` never looks at attestations.** Verified directly:
  running `npm install sigstore@2.3.1 --loglevel silly` and grepping the full
  1164-line log for `rekor.sigstore.dev`, `fulcio.sigstore.dev`, or
  `/-/npm/v1/attestations` returns **zero matches**. The only host contacted
  besides `registry.npmjs.org` is a `github.com` string that's just
  `package.json` metadata, not a request. `npm install` checks that the
  tarball matches the registry's integrity hash. That's it.
- **`npm audit signatures` is the only built-in thing that looks**, and it
  has to be invoked separately, on purpose, every time. It reports
  valid/invalid **per package** with no concept of a policy — there's no
  config field anywhere in npm for "only allow builds from my org's repos."
- **The claim you actually care about is buried three layers down.** The
  attestation is a DSSE envelope; the payload is base64; decoded, it's an
  in-toto statement whose `predicate.buildDefinition.externalParameters`
  looks like:
  ```json
  { "workflow": {
      "ref": "refs/heads/main",
      "repository": "https://github.com/sigstore/sigstore-js",
      "path": ".github/workflows/release.yml"
  } }
  ```
  That `repository` field is the whole ballgame — it's the one part of the
  attestation that tells you *where the build actually came from* — and
  nothing in the default flow, or in `npm audit signatures`, ever reads it.

The consequence: a dependency can be legitimately signed, pass
`npm audit signatures` cleanly, and still have been built from a repo you've
never heard of, because a maintainer's account was compromised and used to
publish from a fork, or the package was republished under a different CI
pipeline than usual. **Nobody checks which repo.** This tool checks which repo.

## Install

```sh
npm install --save-dev provenance-gate
```

Requires Node >= 20.6 and a reasonably current `npm` on `PATH` (developed and
tested against npm 11.19.0; needs `npm audit signatures --include-attestations`
support). Zero runtime dependencies.

## Use

1. Install your dependencies as normal — `npm install` or `npm ci`. This tool
   reads `package-lock.json` **and** needs `node_modules` to already exist:
   `npm audit signatures` audits the installed tree, not just the lockfile.
2. Write `provenance-gate.config.json` at your project root:

   ```json
   {
     "allow": [
       "https://github.com/myorg/*",
       "https://github.com/sigstore/sigstore-js"
     ]
   }
   ```
3. Run it:

   ```sh
   npx provenance-gate
   ```

In CI (GitHub Actions):

```yaml
- run: npm ci
- run: npx provenance-gate
```

`provenance-gate` exits `1` on a policy violation, which fails the step.

### No config file yet?

Run it anyway. With no `allow` list, it runs **report-only**: it still shows
you every package's provenance status, but nothing fails on a repo mismatch,
because there's nothing to compare against yet. Use this to see what your
tree actually looks like before writing an allowlist.

## Options

`provenance-gate.config.json`:

| Field | Default | Meaning |
| --- | --- | --- |
| `allow` | `[]` | Allowed build-source repos. Exact URLs or org globs (`https://github.com/myorg/*`, matching one path segment — the repo name — so it doesn't bleed into `myorg-evil` or `myorg/repo/nested`). Empty ⇒ report-only, see below. |
| `ignore` | `[]` | `"name"` or `"name@version"` entries excluded from every check — for a specific, reviewed exception, not for silencing noise. |
| `failOnMissing` | `false` | Fail on packages with **no attestation at all**. See [why this defaults off](#why-warn-on-missing-fail-on-mismatch). |
| `failOnMismatch` | `true` | Fail on packages that are attested but whose repo isn't on `allow`. Only takes effect when `allow` is non-empty. |
| `failOnInvalidSignature` | `true` | Fail when npm's own registry-signature check fails or is missing (not a provenance question — see below). Turning this off is not recommended. |

CLI flags (override the config file): `--config <path>`, `--cwd <path>`,
`--allow <pattern>` (repeatable, merged with the config file), `--json`,
`--fail-on-missing` / `--no-fail-on-missing`, `--no-fail-on-mismatch`,
`--help`, `--version`.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Clean — no violations under the active config. |
| `1` | At least one policy violation. |
| `2` | Could not analyse: no lockfile, no `node_modules`, `npm` not found, bad config, etc. — distinct from `1` on purpose, so CI doesn't confuse "we found a problem" with "we couldn't even check." |

## Design decisions

### How this gets attestation data: shelling out to `npm audit signatures`

There are two ways to get a package's attestation: fetch
`registry.npmjs.org/-/npm/v1/attestations/<pkg>@<version>` directly, or shell
out to `npm audit signatures --json --include-attestations`. This tool does
the latter, because:

- `npm audit signatures` already resolves the *installed* tree — scoped
  packages, whatever registry a package actually came from (including a
  private registry your `.npmrc` points at), and whatever auth is configured.
  A direct fetch would have to reimplement all of that.
- **It has already done the Sigstore verification** — certificate chain,
  Rekor inclusion proof — before a package shows up in its `verified` list.
  A direct fetch would either skip that (worse) or require reimplementing a
  Sigstore verifier ourselves, which is a much bigger and riskier piece of
  code than a policy layer has any business containing.

The cost of that choice: this tool needs a real, installed `node_modules`
(confirmed — pointing it at a lockfile with no install produces npm's own
`found no dependencies to audit that were installed from a supported
registry` error, surfaced as exit code `2`), and it inherits whatever
`npm audit signatures` does and doesn't check. See the next section.

### Why "warn on missing, fail on mismatch" is the default

Most of the ecosystem has no provenance yet. In the demo above, 73 of 92
installed packages (79%) have none at all — and that's installing a package
(`sigstore`) whose own maintainers are unusually provenance-conscious. Making
`failOnMissing` the default would fail almost every real dependency tree on
day one, for packages that were never malicious — just never republished
with `--provenance`. A gate that fails 79% of builds gets disabled, not
fixed. So the default is:

- **No provenance at all → informational**, not a failure. It's the
  overwhelmingly normal case today, not a signal of anything.
- **Provenance present, but the repo isn't allowlisted → fail.** This is
  the case that's actually informative: the package chose to publish
  verifiable provenance, and it doesn't say what you expected. That's worth
  stopping a build over.

`failOnMissing: true` is there for teams that want the stricter posture once
their supply chain (and the packages they depend on) have actually adopted
provenance — flip it on deliberately, not as a starting default.

### Invalid/missing *registry* signatures always fail, independent of policy

`npm audit signatures`'s `invalid` and `missing` buckets are about npm's
baseline package-signing scheme (has been in place since npm 9), not SLSA
provenance — they mean npm could not confirm the tarball you have is the one
the registry holds. That's a stronger, more basic integrity signal than "which
repo built this," so it fails by default regardless of `allow`/`failOnMismatch`,
and disabling it (`failOnInvalidSignature: false`) is deliberately awkward and
not recommended. We could not produce a real example of either state to
capture (that would mean a genuinely tampered or unsigned publish), so the
tests for this path use a clearly hand-built, clearly-labeled fixture — see
`test/fixtures/npm-audit-invalid-missing.synthetic.json`.

### A narrow allowlist finds your real dependency graph, not the package you had in mind

Discovered while writing the integration test, and left in the demo output on
purpose: allowlisting only `https://github.com/sigstore/*` and installing only
`sigstore@2.3.1` still produces 12 mismatches — `make-fetch-happen`, `cacache`,
`tuf-js`, `semver`, and others that `sigstore` depends on, each attested from
its own real, different org (`npm`, `theupdateframework`). That's correct
behavior, not a bug: those packages really were built by different orgs. It
does mean a workable allowlist has to cover your actual installed tree, which
is usually wider than the packages you went looking for — run report-only
mode first to see what's really there.

## What this does **not** verify

This section matters more than anything else in this file.

- **This tool does not verify Sigstore certificate chains or Rekor inclusion
  proofs itself.** It relies entirely on `npm audit signatures` having
  already done that cryptographic verification — a package only reaches this
  tool's policy layer after npm has decided its attestation is
  cryptographically valid. If `npm audit signatures` has a bug, is tricked,
  or is bypassed, this tool inherits that blind spot completely. **We are
  layering a repo-allowlist policy on top of npm's verification, not doing
  our own cryptography.** If that distinction matters to your threat model —
  it should — go read npm's own documentation of what `npm audit signatures`
  checks, not just this README.
- **It does not check that the source code actually matches what's in the
  named repository.** The `workflow.repository` field is a claim the build
  pipeline made about itself. This tool checks that claim is on an allowlist;
  it does not clone the repo, diff it against the published tarball, or do
  anything resembling a reproducible-builds check.
- **It does not inspect the workflow file itself.** A repo can be on your
  allowlist and still run a compromised or malicious release workflow. This
  is a source-of-build gate, not a build-content gate.
- **It does not check maintainer identity, 2FA status, or account history.**
  A legitimate, allowlisted repo can still be pushed to by a compromised
  maintainer account.
- **It only understands the `https://slsa.dev/provenance/v1` predicate
  type.** A package with a different or newer predicate type is reported as
  `unverifiable`, not silently passed.
- **It needs a real `npm install`/`npm ci` to have already happened.** It
  cannot evaluate a lockfile in isolation — see [Design decisions](#how-this-gets-attestation-data-shelling-out-to-npm-audit-signatures).
- **No SSRF/network protections, no sandboxing of the packages themselves.**
  This only reasons about provenance metadata; it has no opinion on what the
  code in an allowlisted package actually does at install or run time.

If any of the above is the actual guarantee you need, this tool alone does
not provide it.

## Develop

```sh
npm install
npx tsc --noEmit                 # typecheck
node --test "test/*.test.ts"     # unit tests (fixtures) + one live integration test
node examples/gate-demo.ts       # the output pasted above, regenerated live (needs network)

npm run build && npm run test:dist   # what CI runs against the built dist/
```

`test/*.test.ts` is almost entirely fixture-based — the fixtures under
`test/fixtures/*.real.json` are real data captured from
`npm audit signatures --json --include-attestations` and a real
`package-lock.json`, trimmed but not altered. The one exception is
`test/integration.test.ts`, which does a real `npm install` of
`sigstore@2.3.1` and runs the real gate against it; it checks connectivity to
`registry.npmjs.org` first and **skips loudly** with an actionable message
instead of failing when offline.

## License

MIT

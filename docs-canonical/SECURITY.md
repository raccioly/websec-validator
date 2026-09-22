# Security

<!-- docguard:version 0.9.0 -->
<!-- docguard:status approved -->
<!-- docguard:last-reviewed 2026-09-16 -->
<!-- docguard:owner @raccioly -->
<!-- docguard:quality negation-load off — a security model is correctly stated as invariants (MUST NOT, never, read-only, out-of-scope); negation is the right register for safety guarantees. -->

> **Canonical document** — Design intent. This file defines the security model.  
> Last updated: 2026-09-14

`websec-validator` is itself a security tool, so its security model is about **the safety of running
the tool**, not about authenticating end users (it has none). The governing principle: the core pass
is **code-in, artifacts-out** — it reads the target repo, runs read-only subprocesses, and writes files
locally. The core pass contains no LLM or server and never touches a running application unless you
explicitly invoke the gated dynamic phase against a TEST target you control.

---

## Trust Boundaries

| Boundary | What crosses it | Safety property |
|----------|-----------------|-----------------|
| Target repo → tool | source files and configuration (read-only) | Shared root containment, exclusions, bounded regular-file reads, and private-tree pruning; target code is never executed. |
| Tool → scanner subprocesses | the target path | Scanners are detected and only **executed with `--scan`**; they are read-only and shelled out, never imported. |
| Tool → network | nothing, in the core pass | Recon + briefing are fully offline. Outbound traffic requires optional scanner/Noir subprocesses, the **explicit TEST URL** for dynamic checks, an explicit public-feed refresh, an opt-in `--network` dependency-existence check, or a corpus preparation command. |
| Tool → disk | artifacts under `websec-out/` + a gitignored calibration overlay | Each attempt has a unique directory; `latest` is atomically published only after completed execution. Target source is not mutated. |

## Authentication & Authorization

The core CLI has no end-user accounts. The optional MCP HTTP transport authorizes filesystem
recon and is therefore a separate security boundary. It binds only to loopback, requires
`WEBSEC_MCP_TOKEN` bearer authentication, validates Host/Origin, and restricts requests to configured
`--allow-root` directories (default: startup directory). Root selection pins canonical path and
filesystem identity through request dispatch and context creation. Request framing, body limits,
bounded workers, and an absolute receive deadline constrain malformed or slow clients. Stdio trusts
the launching process and its filesystem permissions.

## Repository Read Boundary and Limits

`RepoContext` applies containment and exclusions to code, text, manifests, existence checks, and
file globs. `.local` is private even for intentional direct configuration reads. Traversal prunes
skipped directories before descent and never follows directory symlinks. Safe in-root file symlinks
may be read only when both their visible and resolved paths satisfy policy. Explicit `.claude`
configuration reads bypass general traversal skips, while retaining containment and exclusions.

Readers reject special files and cap bytes. Source contexts retain at most 64 MiB of successfully
cached raw payload; separate read caps can create separate cache entries, while file aliases share
payload and retain their own analyzed path/hash entries. This is not a total Python-memory limit.
The `.local` private-directory check is case-insensitive, including explicit artifact readers.
On POSIX, descriptor-relative no-follow component
opens and root identity checks narrow path replacement races. The portable fallback performs
identity checks and assumes a stable checkout. This is not a claim of complete isolation from
arbitrary concurrent filesystem mutation; use a stable, operator-controlled checkout. The shared
Python read policy does not sandbox an external scanner's own filesystem or network access.

Failed reads, oversized inputs, traversal caps, and extractor/scanner failures enter the coverage
manifest. Execution completeness is separate from scope exclusions and unsupported types, and
`protection_complete` is always false. `--require-complete` or `--fail-on` exits 3 for incomplete
requested execution while preserving partial artifacts; a run that is both incomplete and
gate-failing exits 1 and records `gate.failure_kind: findings+incomplete`. Explicit external graph/report inputs use
bounded regular-file readers and distinct input identities.

## The Dynamic-Phase Safety Model (explicit and non-negotiable)

The optional `websec dynamic` phase is the only part of the tool that contacts a live system. Its
guarantees are enforced in code (`dynamic.py`, `cli.py`):

- **Read-only by default.** `--config` (authenticated cross-tenant BOLA) and `--unauth` (reachability)
  issue **GET-only** requests.
- **Write probes are localhost-only.** `--probe-writes` is refused unless `--target` is localhost; it
  sends empty bodies / dummy ids. Even these requests can change application state, so use an
  authorized isolated test instance.
- **Production is out of scope without written authorization.** The human owns every credential and
  authorizes every live run. Never point it at production.
- **Trigger-style paths are excluded** from unauth GET probing because a GET can still be side-effecting
  (cron / scrape / generate …).

## Secrets Management

| Secret | Storage | Access pattern |
|--------|---------|----------------|
| Dynamic-phase TEST credentials | `dynamic-config.json` (gitignored; copied from `dynamic-config.example.json`) | Read at runtime for `websec dynamic --config`; never written to artifacts. |
| PyPI publish | GitHub OIDC **Trusted Publishing** — no API token stored in the repo | Used only by `publish.yml` on a version tag. |
| Calibration overlay | `~/.cache/websec-validator/` (or `$WEBSEC_CALIBRATION_HOME`), gitignored | Local-only personalization; **never shipped**, never leaves the machine. |

`WEBSEC_CALIBRATION_HOME` relocates the calibration overlay. `WEBSEC_MCP_TOKEN` is required only
for HTTP MCP. The core pass requires no secrets; see ENVIRONMENT.md for optional integration settings.

## Supply Chain

- **Zero runtime dependencies** (stdlib only) — the smallest possible dependency-confusion / malicious-
  package surface. External scanners are invoked as subprocesses, not imported.
- Published to PyPI via **Trusted Publishing (OIDC)**; the release workflow builds, installs, and
  smoke-tests the wheel before it can reach PyPI, so a bad build fails CI instead of shipping.

## Security Rules

- The core pass (`recon` / `run`) MUST remain offline and read-only on the target.
- The tool MUST NOT execute or modify the target repository's code.
- Live probing MUST be opt-in, default read-only, and localhost-only for any write verb.
- Secrets (dynamic creds, calibration overlay) MUST stay gitignored and out of shipped artifacts.
- Runtime dependencies MUST stay at zero; new third-party tools are integrated by shelling out, not importing.

## Reporting a Vulnerability

Open a security advisory or issue at <https://github.com/raccioly/websec-validator>. Because the tool
runs locally without telemetry, relevant boundaries include repository reads, optional MCP HTTP,
dynamic probing, scanner subprocesses, and output/evidence handling. Report violations of these
containment, authorization, execution-accounting, or evidence-integrity guarantees.

## Evidence and Repair Integrity

Dynamic HTTP status changes are candidate observations. A success response alone cannot establish
protected data access, identity change, or a state-changing operation. A redirect or absent DAST
finding cannot prove auth enforcement. Unmatched corpus findings remain unknown; only explicit
evidence-backed labels enter calibration, and legacy unproven samples are quarantined.

Baseline disappearance records “no longer observed”. Repair verification requires a bound original
plan, complete fixed-build rerun, unchanged detector/scope/policy, and contained hashed test artifacts
identifying application, build, source, finding, plan, and test. The negative test must also have a
matching failed report for the original build. Validation never executes supplied code and treats
these artifacts as operator-supplied evidence, not an independently trusted test runner.

## Dependency Existence (`--network`)

`run --network` is an opt-in network entry point, off by default, alongside `intel refresh`. It
sends **bare package names only** — never versions, file paths, repository identity or operator
identity — as HEAD requests to `registry.npmjs.org` and `pypi.org`, transferring zero body bytes.
It enforces the same host allowlist, HTTPS-only, no-userinfo, no-alternate-port and per-redirect
re-validation policy as the feed refresh, and never issues a POST.

A membership query is itself a disclosure: asking a public registry about `@acme/billing-core`
reveals that an internal package exists, and a 404 on such a name tells an observer precisely which
name is available to squat. The check could therefore create the dependency-confusion exposure it
exists to detect. Suppression is consequently applied **offline, before any socket is opened** — a
name that reaches a public registry cannot be un-sent. Names published by any manifest in the
repository (resolved through the workspace graph, not a version-spec heuristic), scopes bound to a
private registry by repo-local `.npmrc`/`.yarnrc.yml`, non-PyPI pip `index-url` overrides, and
non-registry specs are all removed first. `--network-dry-run` discloses the exact name list and
makes no request.

Results are graded, not asserted. `exists` is explicitly **not** evidence of safety: a squatter who
has already registered a hallucinated name also answers 200. An explicit 404 is a lead, split by
offline lockfile evidence into a package that never published and one that published and was
removed. Any other outcome — rate limit, timeout, offline — is UNKNOWN, which is neither clean nor
missing; it records a coverage gap and makes execution incomplete. Existence findings are
ledger-bound but excluded from `--fail-on` unless `--fail-on-network` is also given, because the
UNKNOWN rate is outside the operator's control and gating on it would make registry availability a
precondition for shipping.

The default pass remains fully offline and makes zero network calls; a test asserts this by
intercepting socket connections during recon.

## Public Intelligence and Data-only Research

`intel refresh` is the explicit network entry point for FIRST EPSS and CISA KEV feeds. It sends no
project source or findings, enforces publisher HTTPS redirect policy and byte/decompression bounds,
and validates dated feed content before atomically selecting a snapshot. Download deadlines include
bounded blocking-read overshoot; they are not instantaneous cancellation guarantees. Offline status,
core enrichment and known-CVE reassessment disclose freshness and provenance; legacy flat caches are
unverified. Detector changes require source rescanning rather than an invented fresh analysis.

Research proposals select only shipped allowlisted detectors. They may supply bounded data fixtures,
never executable plugins, commands or fetched templates. Promotion remains a human-review decision.
Claimed provenance/license metadata is operator-declared and requires human verification. Corpus
revision pinning improves reproducibility but does not revalidate historical labels or benchmark scores.

Each intelligence feed's publication date is checked independently under a bounded publication lock.
Older caches cannot replace newer finding provenance; newer publisher corrections remain valid updates.
Repair and proof consumers independently reject contradictory execution flags, read losses and native
scanner error diagnostics instead of trusting a top-level `execution_complete: true` alone.

## Imported SARIF Evidence

`--sarif REPORT` is an explicit, offline, data-only import. The parser reads only that report, never
the source URIs, external property references, suggested fixes or commands it contains. Paths must
be safe relative lexical paths; absolute CI paths require an upstream remapping before import.
Lexical acceptance does not attest filesystem containment, symlink targets or source freshness.

Input is bounded to 16 MiB per report and at most eight reports per CLI run. Per-report limits also
bound runs, results, rules and trace steps. A conservative 8 MiB expanded-evidence budget, a 16 MiB
serialized output ceiling and a CLI aggregate budget prevent small shared references from producing
unbounded retained output. Truncation, unresolved references, contradictory rule/component identifiers,
invalid kind/level pairs and unknown/failed analyzer execution produce explicit execution gaps.
Intentional private/test/operator exclusions remain disclosed scope omissions.

Native suppressions are provenance, never automatic local acknowledgement. Pass, absent and
not-applicable results remain observations; review/open results remain unconfirmed leads with no
applicable severity. Unique producer fingerprints support continuity; collisions bind all affected
identities to the report so reordered reports cannot migrate acknowledgement between sites.
Report SHA values remain separate from analyzed-source digests. Imported evidence cannot currently
support verified repair completion, even when the producer reports successful execution.

Bandit uses its built-in configuration with target `.bandit` discovery disabled and `nosec` ignored.
Other scanner configuration policies remain adapter-specific and visible in coverage. Installed
analyzers and their plugins are operator-trusted executables; Python containment does not sandbox them.

## Agent instruction preservation

Installing or removing agent guidance must preserve foreign dedicated files and text outside the
managed region. Ambiguous, duplicate or reversed markers are errors, not permission to delete the
rest of a file. Historical generated headers remain recognized across CRLF/LF line endings.
Instruction reads are bounded regular-file reads. As with other local operations, installation
assumes an operator-controlled stable checkout rather than hostile concurrent directory mutation.

The current-attempt selector rejects nested output/run symlink aliases. Early CLI errors without
a usable envelope cannot select artifacts; partial execution is disclosed without selecting stale
latest output. Guidance does not install or upgrade a floating engine automatically, execute report
text, infer authorization from HTTP status, or treat finding disappearance as a verified repair.


Nested output `runs` paths must be real directories, not symlinks or other file types, before run
reservation. An explicitly selected output-base alias may resolve to its operator-chosen location.
The checks prevent static redirection; subsequent path writes still assume a stable output tree.
Pre-commit examples use isolated installed Python and never install the target package. Hosted
examples check out a required reviewed engine revision separately from PR content and keep token
permissions read-only; no target installer, hooks or local Action are invoked.

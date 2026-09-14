# Security review and expansion roadmap — websec-validator

Review date: September 11, 2026 (America/New_York)
Reviewed revision: 2f75cc607eec972c550584694cc05fc2dca40012, main, v0.13.0
Status: the user approved all six roadmap batches. This document preserves the initial assessment;
the completed implementation and final validation appear in [validation.md](validation.md). The initial baseline statements below
describe the pre-change checkout, not current implementation status.

## Assessment

The strongest direction is an evidence-driven security workbench: discover each project's trust boundaries, combine specialist scanners, explain coverage gaps, propose verifiable repairs, and revisit findings when code, policy, or threat intelligence changes.

The existing product already supports much of that workflow. Its main limitation is the reliability of its conclusions. Several reproducible paths turn incomplete evidence into reassuring output or incorrect calibration labels. Expanding detector counts before fixing those paths would amplify that weakness.

No scanner can promise protection against all threats or all project types. The useful promise is explicit coverage, reproducible findings, and tested improvements. A new language appearing in a stack list is not equivalent to security analysis of that language.

This was a broad architecture, detection, trust-boundary, testing, and research review, with targeted source inspection and synthetic reproductions. It is not an exhaustive line-by-line audit or a live penetration test of deployed projects. No other private projects were scanned; no upstream code was copied; no project source, commits, or deployments were changed.

## Verified baseline

- Main tree was clean at the beginning and after the checks.
- 22 registered extractors; zero Python runtime dependencies.
- 555 application tests passed in 10.040 seconds on local Python 3.14.7.
- 41 repository automation tests passed.
- All 17 application test modules and both automation test modules were inventoried; high-risk assertions were inspected directly.
- DocGuard: 136/141 checks passed, five freshness warnings, exit 2. All reported HIGH gates passed. Metrics consistency was N/A; DocGuard does not certify the stale counts.
- Canonical docs still refer to 324 tests, parts of README/AGENTS to 285, while CI correctly enforces a floor of 555.
- Local installed distribution metadata reports 0.10.0 although source pyproject declares 0.13.0. Tests import this checkout's source. This is an environment mismatch, not evidence of a broken release.
- The documented 10/10 proof result was inspected, not rerun. It measures ten surface checks across three applications, not vulnerability recall. No head-to-head benchmark or agent A/B experiment was performed.

Strengths worth preserving: offline core, external-tool adapters, separate severity and confidence, extractor exception isolation, regression fixtures, read-only defaults, redirect handling, SHA-pinned CI actions, Trusted Publishing, wheel smoke tests, and the CI test-count floor.

## Existing functionality — do not rebuild

| Area | Already implemented | Appropriate next step |
|---|---|---|
| Detection | Auth/authz, tenancy, browser security, upload, PII, integrations, LLM use, agent config, dependencies | More precise evidence and explicit unsupported surfaces |
| Specialist scanners | Trivy, Gitleaks, Semgrep, Checkov, OSV, gosec, Brakeman; opt-in TruffleHog verification | Versioned adapter capability and health checks |
| Distribution | CLI, agent instructions, stdio MCP, HTTP JSON-RPC | Harden HTTP and verify protocol compatibility |
| Continuous checks | Baselines, severity CI gates, diff scoping, git hooks | Gate scan completeness; detect changes in threat evidence |
| Output | SARIF, versioned JSON, reports, fix prompts, inventory, OpenAPI comparison, test plans | Stable identities, evidence lineage, repair verification |
| Prioritization | Import-based hints, graph blast radius, EPSS/KEV cache | Freshness and provenance; do not call import absence unreachability |
| Learning | Corpus calibration, local overlay, dynamic/DAST ingestion | Stop deriving ground truth from unrelated alerts and ambiguous statuses |

Bandit and Prowler are detect-only registry entries: they have no execution adapter. Installed/available/runnable/actually-ran must be different capability states.

## Findings requiring implementation

Priorities below are engineering priorities, not CVSS scores.

### F1 — P1: HTTP MCP exposes local recon without a client boundary

Evidence: [mcp_server.py](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/mcp_server.py#L185) and its unrestricted [_resolve](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/mcp_server.py#L50).

A localhost reproduction sent an unauthenticated tools/call request with foreign Origin and Host headers and Content-Type text/plain. It received HTTP 200 and facts for a synthetic directory. The HTTP handler checks neither client authentication, Origin, Host, nor permitted scan roots. Binding it to a routable interface shares its filesystem recon capability with reachable clients. Loopback binding alone does not replace browser-origin protection.

The reproduction establishes accepted requests and arbitrary-directory recon. It does not establish a complete browser DNS-rebinding exploit or arbitrary raw-file disclosure.

Fix: retain stdio; constrain HTTP to loopback initially, validate Host/Origin, authenticate HTTP clients, restrict requested paths to explicitly configured roots, reject malformed/oversized requests, and bound concurrent work. Reject unsafe exposure at startup. Update HTTP compatibility claims against the selected protocol version.

Acceptance: bad/missing credentials, foreign origins, unexpected Host, sibling roots, symlink escape, invalid body length, and oversized requests are rejected; an authorized in-root scan succeeds. The [MCP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) requires Origin validation and recommends authentication.

### F2 — P1: A file symlink escapes the scan root; exclusions are inconsistent

Evidence: [base.py reader](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/extractors/base.py#L149) and [glob](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/extractors/base.py#L177).

A synthetic repo containing linked.py pointing to a synthetic sibling file outside the repo returned that file's marker through iter_code(). Separately, excluding an omit directory did not stop the dependency extractor from reading omit/package.json and emitting an install-script finding: glob does not apply the same exclusions as the code walk.

Fix: one root-relative file-access policy for code, manifests, globbed specs, agent configs, and auxiliary artifacts. Refuse paths escaping the resolved scan root; skip non-regular files; apply exclusions consistently. Keep explicitly requested external artifacts a separate, visible input.

Acceptance: no out-of-root reads, no FIFO/device hangs, identical exclusions across extractors, explicit accounting of skipped paths, and continued support for repositories located under ancestors named vendor or .cache. Do not scan private .local directories.

### F3 — P1: An incomplete scan can pass the security CI gate

Evidence: [CLI gate](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/cli.py#L335), [extractor driver](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/extractors/__init__.py#L66), and [scanner normalization](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/scanners.py#L720).

Injected a Semgrep timeout into a CLI run with --scan --scanners semgrep --fail-on high. Exit code was 0. Existing normalization already tracks scanner_errors and parse_failed; the gate does not consume them. This is a missing end-to-end contract, not a need to invent error collection from scratch.

A 2,000,001-byte Python file produced files_scanned=1 and files_truncated=false. RepoContext records oversized internally, but the facts output has no oversized disclosure. The file contributes no analyzed contents.

Fix: expose a coverage record with per-extractor and per-scanner outcomes, unsupported formats, unreadable/oversized files, and caps. Add a distinct incomplete exit status under an explicit completeness policy; require explicitly selected scanners to run successfully. Preserve useful partial artifacts.

Acceptance: timeout, malformed report, missing requested tool, extractor exception, unreadable file, and truncated walk cannot be reported as complete. Report-only runs can still finish, but show incompleteness prominently.

### F4 — P1: XSS detection can be silenced by a comment

Evidence: [surface.py sanitizer suppression](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/extractors/surface.py#L248).

Synthetic input document.write(location.search) produced one XSS lead. Adding a comment mentioning DOMPurify removed the lead. Adding an unrelated DOMPurify.sanitize call also removed it. The implementation treats sanitizer presence anywhere in a file as protection for every sink in that file.

Fix: associate a sanitizer with the actual expression reaching each sink. Retain uncertainty when that relationship cannot be established. Apply the same audit to authorization, redirect, transaction, and LLM guard co-occurrence rules.

Acceptance: vulnerable plus unrelated-safe code remains detected; comments/imports cannot suppress findings; directly sanitized output remains quiet; aliases, reassignment, branches, and multiple sinks have paired vulnerable/safe cases.

### F5 — P1: DAST feedback creates incorrect permanent learning labels

Evidence: [dast_ingest.py](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/dast_ingest.py#L105).

A report containing one reflected-XSS alert at /public confirmed an XSS finding in never-crawled/admin.js and refuted a SQLi finding in never-crawled/search.py. The matcher collapses results to attack classes and treats any active alert as evidence that all active classes could have been tested.

Fix: correlate by application, endpoint, method, parameter, identity, rule, build, and scan coverage. A class-level alert is supporting evidence, not confirmation of every finding in that class. Silence is inconclusive unless the exact check and relevant surface were exercised successfully.

Acceptance: an alert on route A never confirms/refutes route B; a passive scan never refutes an active finding; incomplete authentication or crawling yields unknown. Preserve sample provenance and deduplicate repeat observations. Existing overlays may contain weak labels; quarantine/review them rather than silently deleting user history.

### F6 — P1: Dynamic verdicts overstate both safety and confirmation

Evidence: [BOLA summary](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/dynamic.py#L255), [write verdicts](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/dynamic.py#L395), and [calibration labels](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/calibration.py#L213).

Both synthetic cross-tenant requests returned 500; summary still said “0/2 cross-tenant GET reads blocked — all isolated.” A synthetic 400 validation response was converted into is_real=true for missing-auth. Validation can precede authentication; the status alone does not prove bypass. Likewise, a nonempty 200 needs ownership evidence before it proves cross-tenant leakage.

Fix: explicit confirmed-vulnerable / blocked / inconclusive / not-tested states, positive controls for the legitimate user, victim-owned resource markers, expected route policy, and repeatable comparisons. Only evidence-backed confirmations enter calibration.

Acceptance: all-error and zero-test runs never claim isolation; validation errors cannot become confirmed vulnerabilities alone; tests distinguish public responses, soft denials, real victim data, and transport failure.

### F7 — P2: “Immutable” runs collide within the same second

Evidence: [_new_run_dir](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/cli.py#L55).

Two calls with a fixed same-second timestamp returned the same directory because mkdir uses exist_ok=True. Later artifact writes can overwrite the earlier run.

Fix: exclusive unique directory creation; publish latest atomically after the run finishes. Acceptance: simultaneous runs are distinct and failed runs never replace the last complete latest pointer.

### F8 — P2: Threat-intelligence changes destabilize finding identity

Evidence: [baseline fingerprint](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/baseline.py#L23) and [enrichment](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/enrichment.py#L138).

Fingerprints include the human-readable title. Adding an EPSS annotation changes identity for the same synthetic CVE/location. Line-number changes can also churn identities when included in location. Findings that disappear are counted as fixed without proving comparable coverage.

Fix: stable detector/rule identity, normalized resource identity and semantic sink anchor; keep presentation, confidence, and threat evidence outside identity. Track newly exploited, severity-changed, no-longer-observed, and verified-fixed separately.

Acceptance: wording/EPSS updates preserve identity; a newly added sink gets a new identity; scanner loss never marks an issue fixed. Define a migration for existing baselines and acknowledgements.

### F9 — P2: Language/framework coverage is substantially narrower than the broad product ambition

Evidence: [CODE_EXT](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/extractors/base.py#L24).

Isolated files with .vue, .svelte, .mts, .cts, .html, .cs, .rs, .kt, and .swift extensions each yielded zero built-in code files. A v-html signature exists, but native .vue files do not enter that source loop. Optional tools may see additional formats; this finding concerns built-in coverage.

Fix: inventory formats independently from detector support; expose a capability matrix; add template and module variants with tested semantics. Route larger language additions through specialist analyzer outputs.

Acceptance: every recognized file family is either analyzed by named checks or explicitly unsupported. “Framework detected” must not imply “authorization verified.”

### F10 — P2: Freshness, provenance, and evaluation do not support continuous-protection claims yet

Evidence: [enrichment loaders](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/enrichment.py#L160), [refresh script](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/scripts/refresh-epss-kev.sh), [proof harness](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/src/websec_validator/proof.py#L24), and [benchmarks](https://github.com/raccioly/websec-validator/blob/2f75cc607eec972c550584694cc05fc2dca40012/BENCHMARKS.md).

EPSS/KEV data is already available, but the reader does not report feed age, source revision, or model date. The refresh script is not part of the wheel's packaged data. Corpus cloning follows a default branch and reuses existing directories without a revision contract. Current calibration has only three deliberately vulnerable applications, and several standards citations lack an explicit ASVS version.

Fix: validated, dated intelligence snapshots; atomic refresh with last-known-good fallback and explicit failed-refresh status; packaged refresh entrypoint; pinned corpus revisions; versioned standards mappings; held-out safe and vulnerable cases.

Acceptance: stale/malformed feeds are visible; identical pinned inputs reproduce conclusions; benchmark results include actual analyzed counts and unknown labels.

## Expansion strategy

### 1. Coverage as a first-class artifact

Create a coverage manifest for each service, language, threat class, and analyzer. Report checked, partial, unavailable, and unsupported independently of finding counts. This is the foundation for protecting heterogeneous repositories honestly.

For monorepos, identify service boundaries before merging framework and control evidence. A guard in service A must not suppress service B. Include HTTP, queues, scheduled jobs, CLIs handling untrusted files, browser extensions, and agent tools as distinct input boundaries.

### 2. Evidence that follows a finding

Extend the existing ledger with source-to-sink evidence, guard scope, analyzer/rule version, input revision, and coverage references. Reuse external flow traces where available; Python's stdlib AST can support narrowly scoped Python checks. Do not attempt a universal regex dataflow engine.

A high-value innovation is a counterexample test for each control: remove the guard and prove the bad case fails; restore it and prove legitimate behavior remains. Adding unrelated safe code must never erase a dangerous path.

### 3. Continuous protection triggered by three kinds of change

- Code change: existing hooks/CI rerun relevant checks, with periodic full scans to cover shared-control changes.
- Threat change: a new advisory, exploitation status, or detector revision re-evaluates affected dependencies/surfaces even when source is unchanged.
- Assurance change: expired suppression, failed scanner, stale feed, new unsupported format, or missing verification reopens review.

The research and update path should remain separate from offline recon. Use versioned artifacts and optional external CI scheduling. This report does not install an unattended monitor or authorize ongoing background writes.

### 4. Repairs with a verifiable completion record

Build on fixprompt.py, rather than adding a second prompt system. Each repair should have a stable finding ID, precondition, minimal suggested change, affected services, positive/negative tests, and a rerun result. “No longer observed” is not “verified fixed.”

Add dependency upgrade candidates and compatibility evidence through existing OSV integration, without automatically running package-manager fixes during recon. [OSV documents](https://google.github.io/osv-scanner/usage/) that guided fixes can execute project scripts or use external registries.

### 5. Threat research becomes tested detector proposals

Recommended research cadence, implemented only after approval:

1. Check primary advisories, OSV, CISA KEV, FIRST EPSS, OWASP standards, and upstream analyzer/template releases.
2. Deduplicate by advisory aliases and existing detector coverage.
3. Record affected ecosystem, prerequisites, evidence source/date, applicability, and remediation.
4. Build a synthetic vulnerable example and a safe sibling.
5. Add adversarial variants: comments, renamed identifiers, unrelated guards, wrappers, different frameworks, and monorepo placement.
6. Evaluate on a held-out corpus before promoting the rule.
7. Review licensing and provenance; ship a versioned update through the normal release gates.
8. Notify users only when their projects become newly affected or a protection check stops working.

Do not convert every blog post into a detector or execute downloaded research templates automatically.

## Ideas to adapt from other tools

These are capability comparisons from primary documentation, not measured superiority claims.

| Source | Useful idea | Fit for websec |
|---|---|---|
| [Semgrep taint rules](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/overview) | Sources, propagators, sanitizers, sinks | Replace file-wide safety assumptions with evidence tied to a sink |
| [CodeQL dataflow](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/) and [language matrix](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/) | Global flow traces and explicit language support | Import analysis results for deeper and broader coverage; review execution/licensing requirements before integration |
| [OSV Scanner](https://google.github.io/osv-scanner/usage/) | Separate inventory from vulnerability matching; guided repair | Improve the existing adapter and freshness contract, rather than duplicate SCA |
| [ZAP authentication testing](https://www.zaproxy.org/docs/authentication/test-the-context/) | Verify the authenticated context before trusting scans | Require positive controls and per-identity evidence |
| [Schemathesis stateful testing](https://schemathesis.readthedocs.io/en/stable/explanations/stateful/) | Chain operations using real returned IDs | Generate two-identity ownership tests and entitlement/revocation sequences |
| [Nuclei template signing](https://docs.projectdiscovery.io/templates/reference/template-signing) | Provenance and integrity for executable checks | Pin and review optional templates; a valid signature does not make a probe harmless |
| [OWASP Benchmark](https://owasp.org/www-project-benchmark/) | Explicit true/false cases with TP/FN/TN/FP reporting | Evaluate precision and recall per class/framework, including safe controls |
| [ASVS 5.0](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0) | Versioned verification requirements | Map checks and manual gaps to exact versioned controls |
| [OWASP Agentic risks](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/) | Tool misuse, behavior hijacking, identity/privilege abuse | Expand existing agent checks to delegation, approval scope, tool-result trust, and memory provenance |
| [FIRST EPSS](https://www.first.org/epss/) | Empirical exploitation probability | Preserve model date and uncertainty; prioritize alongside context rather than treating it as proof |

Borrow concepts and interoperable output formats first. Copy code, rules, or fixtures only after checking the exact license and preserving required notices.

## Prioritized delivery sequence

| Batch | Deliverable | Completion evidence |
|---|---|---|
| A — containment | Shared file-access boundary and HTTP client boundary | Root escape/foreign-origin/unauthorized-request regressions fail before and pass after |
| B — honest outcomes | Coverage manifest, incomplete CI state, conservative dynamic/DAST labels, unique runs | Fault injection cannot produce all-clear or false learning labels |
| C — better detection | Per-sink controls, template/module coverage, per-service context | Paired vulnerable/safe tests plus comment/alias/unrelated-guard mutations |
| D — durable tracking | Stable identities, intelligence-change tracking, expiring acknowledgements, verified repair records | Evidence changes do not create duplicate findings; coverage loss does not close findings |
| E — broader projects | Java/Spring and .NET first-class profiles; then Go/Ruby/PHP depth and mobile/native profiles | Published support matrix and held-out results for each added profile |
| F — continuing research | Packaged intelligence refresh, versioned detector proposals, benchmark promotion gates | Freshness failures visible; newly affected unchanged projects receive actionable results |

Ordering rationale: containment and honest outcomes protect users immediately. Broad language badges without per-language tests would increase marketing coverage while hiding technical gaps. A hosted multi-tenant service would add authentication, storage, and operations responsibilities without solving the current detection problems.

## Evaluation and release requirements

Use a version-pinned corpus containing safe and vulnerable pairs, not only vulnerable apps. Split training and holdout repositories to avoid calibrating and validating on the same examples. Unlabeled findings are unknown until adjudicated, not automatically false.

Track recall and precision by threat class/framework, false positives per reviewed project, unsupported/incomplete coverage, time to confirmed finding, time to verified repair, and repeat-regression rate. Report sample size and intervals. Include metamorphic tests for comments, renames, unrelated sanitizers, code movement, and service splits.

For agent A/B evaluation, use identical commits, tool versions, agent configuration, budgets, and adjudication. Measure confirmed results. Do not claim improvement until that experiment is run.

Changes must preserve the existing test assertions and raise the CI test floor when tests are added. Refresh canonical docs to describe actual behavior and counts, run DocGuard, and retain the no-runtime-dependency invariant. Source changes, commits, PRs, and releases remain subject to the user's requested approvals.

## Concrete first implementation batch for approval

Start with the shared read boundary (F2), which protects CLI and MCP scans alike.

- Docs reviewed: all four canonical documents, README, AGENTS, BENCHMARKS, proof protocol, and the relevant OpenWolf protocol.
- Existing pattern: “Walk the tree once; cache file text; serve cheap queries to every extractor.” RepoContext is the common policy point; glob and manifest currently bypass parts of its policy.
- Proposed approach: centralize allowed-file checks in RepoContext; require resolved paths to remain within the scan root; skip non-regular files and .local; apply exclusions equally to code, text, manifests, and glob. Preserve existing skip-directory behavior relative to the root. External scanner traversal requires a separate follow-up contract.
- Files to change: src/websec_validator/extractors/base.py; tests/test_hardening.py; docs-canonical/SECURITY.md; docs-canonical/TEST-SPEC.md; CHANGELOG.md; .github/workflows/ci.yml. Six files, no new dependency.
- Risk: HIGH because this changes a security boundary and scan inclusion semantics.
- Acceptance tests: escaping file symlink; in-root normal file; excluded nested package manifest; direct manifest exclusion; non-regular file; private .local; skip-named ancestor; existing fixture and source scans.
- Waiting for approval before implementation.

This first batch contains a specific, reproduced defect and a bounded regression plan. Later batches need their own concrete implementation checklist.

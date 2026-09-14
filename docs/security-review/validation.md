# Security expansion validation

Initial phase: 2026-09-12. Final fourth-phase record updated: 2026-09-14.
Base commit: `2f75cc607eec972c550584694cc05fc2dca40012`.
This document retains immutable local validation checkpoints. Release preparation now targets
0.14.0 on `codex/security-expansion-release`; release publication must be verified separately.
No deployment, installed hook or background monitor is implied by these validation records.

## 0.14.0 pre-release wheel validation — 2026-09-14

The isolated `websec_validator-0.14.0-py3-none-any.whl` passed all **15 command/contract checks**:
version, capabilities, offline intelligence status, research example/evaluation, repair verification,
core strict run, SARIF strict import, Django converter integration, React Native browser exclusion,
agent-install preservation, research catalog/control-scope suite, assigned SQL, and output-boundary
refusal. Its SHA256 is
`5047bfb98e40b52ec32b40d5c63c2d5debf0e96a7cd0de16cd958df959f2ebb0`.
The eight adoption tests were repeated successfully (1.343s). The full source matrix below remains
1082 tests on each Python version; this wheel records the final 0.14.0 package version independently
from the earlier 0.13.0 checkpoint. No dependencies were installed or remote publication performed
by this local validation. GitHub release/PyPI publication must be verified by the release workflow.

## Final fourth-phase validation — 2026-09-14

| Check | Result |
|---|---|
| Full application suite, Python 3.14.7 | **1082 passed**, 21.492s |
| Full application suite, Python 3.12.14 | **1082 passed**, 22.536s |
| Repository automation | **41 passed**, 0.004s |
| Current CI application floor | **1082** |
| Documentation | `docguard guard`: **166/166 passed** |
| Whitespace | `git diff --check`: passed |
| Isolated extracted wheel | **15 command/contract checks passed**; no dependencies installed or external network used |

The final wheel is `websec_validator-0.13.0-py3-none-any.whl`, SHA256
`1897f54de3d11f162f4af0a2d07b5d081bd09a9876c795387bb5b968c17c38ca`.
At this pre-version-bump checkpoint, source version was 0.13.0; the wheel was not published. It includes both new parser modules,
all three research bundles and schemas. The 11 prior smoke checks were repeated, plus research
catalog, the full control-scope suite, assigned Python SQL flow, and rejection of nested output
symlinks before outside writes. JSON Schemas were parsed and output contracts checked without
installing a third-party schema validator.

Independent review cleared 14 SQL-flow, 8 adoption, 7 research-CLI and 7 output-boundary tests,
including the original counterexamples. Python query flow distinguishes matched query/bound-value
unpacking; later loop iterations stay explicit review gaps. The analysis is bounded and
intraprocedural, not a fixed-point computation, cross-function reachability proof or SQL execution.
Pre-commit/YAML frameworks and a hosted schedule were not run: adoption validation exercised actual
isolated CLI argv, trusted-copy privacy and limited scalar configuration checks only.

Main/local HEAD/live origin remained `2f75cc607eec972c550584694cc05fc2dca40012`; all 53 open PR
heads matched their cached heads, with 51 overlapping tracked edits. The [selected overlap review](upstream-overlap-review.md)
retains 18 exact reviewed heads and remaining ideas. Recheck latest target and PR state before any
future integration and rerun combined tests. No source/PR merge, commit, publish, hook installation
or hosted schedule activation occurred. Earlier wheels and corpus scores below remain historical;
no renewed vulnerability-recall score is claimed for this final wheel.

## Release documentation validation — 2026-09-14

`docguard guard` exits successfully with **172/182 checks passed and ten traceability warnings**.
The warnings correspond to the new specification’s six functional requirements and four success
criteria, which intentionally describe future work without claimed test coverage. No test markers or
validator exemptions were added to make unimplemented work appear complete. `git diff --check`
passes. All 53 exact PR heads map to a named workstream; release/package version is 0.14.0 solely
in `pyproject.toml`, and the two tracked plugin manifests intentionally omit duplicate versions.

## Corpus environment comparison — 2026-09-14

A fresh pinned-corpus pass of the fourth-phase wheel with a minimal PATH and **Noir absent**
completed all three projects with **8/10 surface checks**, seven unknown truth labels and zero
unavailable projects. The two missing VAmPI checks were route/IDOR surface presence. Comparing
the third- and fourth-phase wheels on the same VAmPI revision under the same minimal PATH yielded
zero fallback routes in both. Connexion spec-first registration (`specification_dir` plus `add_api`)
is not yet resolved by the fallback; it is retained as W20 in the
[remaining-work spec](../../specs/001-continuous-security-improvement/spec.md).

The historical 10/10 record below did not retain optional-tool availability metadata. A normal
operator PATH contained Noir, which is consistent with the difference but does not establish its
cause. Neither score measures vulnerability recall; the new 8/10 result must not be hidden by the
historical score. The forthcoming 0.14.0 wheel requires its own validation record.

## Third-phase checkpoint — 2026-09-14 (historical)

| Check | Result |
|---|---|
| Full application suite, Python 3.14.7 | **1046 passed**, 18.691s |
| Full application suite, Python 3.12.14 | **1046 passed**, 19.561s |
| Repository automation | **41 passed** |
| CI floor at that checkpoint | **1046** |
| Documentation | `docguard guard`: **162/162 passed** |
| Whitespace | `git diff --check`: passed |
| Isolated extracted wheel | **11 command/contract checks passed**; no dependencies installed or external network used |

The final wheel is `websec_validator-0.13.0-py3-none-any.whl`, SHA256
`d6d260bc6d3d707f7b9657c8c54823db2d728e33df7094f5b8a04c831db884b6`.
It includes the new Django module, all three research bundles and the schemas. The eight earlier
command checks were repeated, plus literal Django URL conversion through the real CLI, native React
without an invented browser baseline, and agent-guidance installation preserving project policy.
The smoke test parses actual schemas and checks output contracts; it does not install a third-party
JSON Schema validator. Version 0.13.0 comes from source package metadata; this wheel was not published.

The first third-phase wheel exposed a parameter-contract defect that leaf tests missed: Django
converter parameters used `param_type`, while route targeting/inventory require `where`. The fix
normalizes parameters to `where: path` and adds a real CLI regression covering literal mounts and
converter targeting. The corrected complete suite and rebuilt isolated wheel both pass. Earlier
1042/1045-test runs and the failed intermediate wheel are not the final validation result.

Independent checks covered the original triple-f-string and commented-HTML counterexamples,
crypto comparison safe/unsafe pairs, native/browser service separation, Django bindings, and
installer ownership/current-attempt preservation. Ambiguous JavaScript regex literals remain an
explicit advisory-analysis limitation. Full test success does not measure vulnerability recall.
The previous corpus score below belongs to its historical wheel; no new corpus score is claimed
for this final third-phase wheel.

Main and live origin remained `2f75cc607eec972c550584694cc05fc2dca40012` at phase close. The 18
selected PR heads were stable when checked. Before future integration, re-fetch and recompare the
latest target/PR heads and rerun combined checks; no PR was applied or merged in this review.

## Reviewed checkpoint — 2026-09-14 (historical)

| Check | Result |
|---|---|
| Full application suite, Python 3.14.7 | **983 passed**, 18.851s |
| Full application suite, Python 3.12.13 | **983 passed**, 19.442s |
| Repository automation | **41 passed** |
| CI application floor | **983** |
| Documentation | `docguard guard`: **160/160 passed** |
| Whitespace | `git diff --check`: passed |
| Isolated extracted wheel | Eight command/contract checks passed; no dependencies installed and no external network used |

Commands were `python3 -m unittest discover -s tests` under each interpreter and
`python3 -m unittest discover -s .github/scripts -p 'test_*.py'` for repository automation.
Public-source precision corrections passed independent review, including the nested-header counterexamples.

The checkpoint wheel is `websec_validator-0.13.0-py3-none-any.whl`, SHA256
`207c6da97ca95a2d7422294679148b52e23e6e82a9d6d937bb24335c46b4083f`.
Its isolated checks covered version, capabilities, offline intelligence status, research example and
evaluation, synthetic repair verification, complete synthetic recon, and complete SARIF import with
explicitly unverified source freshness. Schemas and all three research JSON bundles were packaged;
schema documents were parsed and output contracts checked without installing a third-party validator.
This is a built working-tree checkpoint, not a published release or a claim about the remote v0.13.0 tag.

The immutable checkpoint wheel also completed a [pinned corpus run](public-proof-20260914.json):
**3/3 applications complete, 10/10 surface checks, seven unknown truth labels, zero unavailable**.
The detector revision was
`sha256:e115caaaa8cf9e0a2a3b286a3dfcb91e1acfd041244ae6de2d7afc96fc51bc4c`.
Only temporary checkout paths were removed from the retained report. The corpus revisions match
the earlier pinned run below. This dates the measurement to this wheel; subsequent source work
requires its own validation and does not inherit the checkpoint's score.

## Initial frozen validation (historical)

| Check | Command or method | Result |
|---|---|---|
| Application suite | `python3 -m unittest discover -s tests` | **813 passed** in 15.054s |
| Repository automation | `python3 -m unittest discover -s .github/scripts -p 'test_*.py'` | **41 passed** |
| Documentation | `docguard guard` | **156/156 passed**, zero warnings |
| Whitespace | `git diff --check` | Passed |
| Package build | Existing bundled setuptools `build_meta.build_wheel` in a temporary source copy | Passed; no dependencies installed |
| Isolated wheel | Extracted wheel imported with `python -I`; source checkout excluded from import path | Passed |

At that freeze CI enforced **813** application tests. Factual inventory: **22 registered extractors**,
**17 sink classes**, **10 scanner entries**, **9 named profiles**, and zero Python runtime dependencies.
The AGENTS update changed factual counts/review date only and preserved behavioral/approval rules.

## Implemented and independently reviewed

| Batch | Delivered behavior | Evidence |
|---|---|---|
| Read and MCP boundaries | Contained, excluded, pruned regular-file reads; authenticated loopback HTTP, resource bounds and root identity | Positive and rejected read cases; escape/private/FIFO/cap/root-swap cases; socket deadline and dispatch tests |
| Coverage and publication | Complete execution versus scope limitations; fail-closed gates and preserved partial attempts | Extractor/scanner fault injection, malformed/oversized reports, missing tools, unique directories and latest preservation |
| Detector precision | Controls tied to sink values; templates/modules; distinct occurrences | Paired fixtures plus six independently reproduced control-scope regressions |
| Evidence and lifecycle | Unknown observations, scoped DAST labels, semantic identities, expiry/reopening and bound repair validation | Dynamic controls, unknown-only calibration, alias migration, evidence tampering/reuse tests |
| Profiles and services | Nine named profiles, manual/unknown gaps, direct language/config checks and service-scoped joins/guards | Paired language controls, malformed config errors, sibling routes/guards and repeated sites |
| Intelligence and research | Explicit feed refresh, offline reassessment, dated snapshots, data-only proposals and corpus pins | Feed validation/failure preservation, stable/reopened IDs, data-only fixture evaluation and revision mismatch tests |

The [evidence examples](examples/README.md) pass the actual APIs/CLI: dynamic identity/resource
controls, exact positive/negative DAST contexts, and a complete synthetic repair artifact triplet
with original failed negative test. They are contract fixtures, not evidence of an actual repair.

## Initial wheel evidence (historical)

- Wheel: `websec_validator-0.13.0-py3-none-any.whl`.
- SHA256: `8535143cf564a8b7c9e0fbe5f6b509aa80418812b6745898511db713eb1cd7b1`.
- Detector revision from the isolated wheel: `sha256:35fc545401b56eaf78ebda32660d083685efabeb0597dd653341ed914900ab26`.
- Packaged schemas, proposal example, profile case data, profiles and intelligence modules were present;
  JSON data parsed successfully and output contract assertions passed.
- Commands passed: `--version`, `capabilities`, offline `intel status` with empty isolated cache,
  `research example`, `research evaluate`, `repair-verify` on the synthetic documented artifact set,
  and `run` on a synthetic target with `--require-complete`.
- Facts and ledger used schema 2.0; coverage matched across artifacts; SARIF marked completed execution.
- No global environment or cache changed. Wheel validation used no external network or new dependency.

The active source-test interpreter's installed distribution metadata reports 0.10.0 while source
pyproject declares 0.13.0. The isolated wheel correctly reports **0.13.0**. This verifies packaging
without treating a stale local installation as a broken release or claiming a release occurred.

## Research and limits

A separate temporary live FIRST/CISA feed refresh succeeded during implementation; no project source
was uploaded and no global snapshot was retained. Corpus commit pins were verified from public source
metadata. At the initial freeze the historical **10/10** surface-proxy score had **not yet been rerun**
against those pins. A subsequent executed run is recorded below; historical labels were not
revalidated. No competitor head-to-head or agent A/B experiment was performed.

Expression/profile detectors remain bounded conservative heuristics. Native C/C++ analysis is manual;
manifest service boundaries approximate deployment boundaries. Python read protections retain a
stable-checkout assumption for residual filesystem races and do not sandbox external scanner programs.
Execution completeness describes requested checks; it never establishes complete protection.
Repair verification validates operator-supplied evidence without executing or attesting tests.

The environment had no third-party JSON Schema validator; no dependency was installed to add one.
Published schemas were parsed and their version/lifecycle/output contracts checked by tests. SARIF
navigation, line/column handling and legal lifecycle values have explicit regressions. Synthetic
research holdouts are authored regression evidence, not independently sampled production recall.

## Second-phase verified contracts

The user authorized continued improvements after the initial freeze. These source changes remain
unreleased; the initial wheel hash, test count and remote v0.13.0 tag do not identify the expanded
working tree. The reviewed checkpoint above supersedes the initial suite/package result for that
snapshot; subsequent work is validated separately.

| Area | Verified evidence |
|---|---|
| Scanner contracts | 21 focused tests; real offline Trivy report retained eight CVE occurrences across two manifests/installed versions instead of collapsing to four. Checkov native diagnostics and resource identity, Bandit configuration/confidence/CWE, and intelligence passthrough have controls. |
| SARIF ingestion and integration | `python3 -m unittest discover -s tests -p 'test_sarif*.py'`: 41 passed. Contradictory references/kind/level rejected; valid siblings retained; reduced-budget trace/help amplification tests and producer-collision identity controls passed. Canonical failure evidence wins review/open in either report order. |
| Source and assurance | Source budget/privacy/alias tests and evidence-consumer tests passed in focused reviews. Actual read policy binds repair scope; contradictory completed flags cannot override native errors or byte losses. |
| Hooks and Action | 19 hook tests and five Action contracts passed; independent review checked repeated failed gates, atomic accepted policy, isolated imports, safe hook composition and exact current artifact outputs. |
| Value-scoped controls | Paired cases cover webhook payload replacement, upload byte checks, weak hashes, extension message origin/sender checks, individual cookie setters and actual returned PII projections. These are supported-pattern regressions. |
| Public-source precision | Three bounded corrections distinguish executable auth decisions from error strings, browser responses from ordinary file streams, and exact numeric GitHub identifiers from text/unknown expressions. Independent review and the 983-test suite passed; this remains separate from corpus scoring. |

### Executed pinned corpus run

The retained [public proof result](public-proof-20260912.json) records three analyzed applications,
complete declared execution, **10/10 documented surface checks** and **seven unknown labels** at:

- VAmPI: `f16052dce83f05847133ec98f01c5193a41de7d8`.
- NodeGoat: `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`.
- DVGA: `a961308c02d1fb462b192681c336b0739e432da7`.

The recorded detector revision is
`sha256:35fc545401b56eaf78ebda32660d083685efabeb0597dd653341ed914900ab26`.
Later detector edits mean this is a dated execution result, not a fresh score for the current tree.
Unknown labels remain unknown; the result does not establish vulnerability recall or exploitability.

### Focused performance measurement

A single sequential full-recon pair on the same Actual checkout measured **75.838 s before** and
**69.241 s after** lexical inventory-path caching (about **8.7%**). All noncoverage facts and the
analyzed source digest matched, including the same oversized Yarn input gap. The comparison used
the same loaded extractor code in one process on a shared host. Other agents changed source files
while it ran, so filesystem detector hashes differed; this is an indicative local measurement,
not a frozen reproducible benchmark or a completeness claim.

## Subsequent framework, comparison and adoption review

The next source slice adds bounded Django URL candidates, manifest/service metadata consistency,
native/browser distinctions, scoped crypto comparison evidence, and safe agent-guidance adoption.
The [PR overlap review](upstream-overlap-review.md) retains exact reviewed heads and the limits of
its inert reproductions; no PR was applied or declared merge-ready.

A scoped Linkding recheck at `27b7303` produced 53 route candidates, zero definitive paths, one
dynamic mount gap and zero parser errors. This is a parser-specific read-only check, not an
immutable full-repository proof or a measurement of vulnerability recall. The 983-test wheel above
remains historical; the final third-phase matrix and 11-command wheel validation are recorded first.


## Fourth-phase verified contracts

Independently reviewed slices add static output-directory containment, discoverable research-suite
CLI evaluation and opt-in adoption configurations. Research tests retain the 24-case synthetic,
non-blind limitation and correct explicit empty-argument rejection. Adoption tests execute actual
isolated CLI argv and limited scalar configuration checks; neither pre-commit nor a YAML parser was
installed, and no hosted workflow or hook lifecycle was activated. The test engine copy now prunes
private directories and every symlink before descent. Assigned Python SQL-flow work passed independent review, including tuple/bound-value precision
and explicit later-loop-iteration gaps. Final combined counts and package validation appear first.

A scoped public-source follow-up found Linkding's reader view assigning CSP `sandbox allow-scripts`
to the same rendered response. This is concrete source control evidence, not a template comment or
a confirmed vulnerability. Future template-to-response control mapping is a research idea; no live
probe or claim of complete deployed protection follows from that inspection.

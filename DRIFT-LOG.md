# Drift Log

> Documents conscious deviations from canonical specifications.  
> Every `// DRIFT:` (or `# DRIFT:`) comment in code MUST have a matching entry here.

---

## Active Drift

Canonical security, execution-accounting and evidence contracts were updated alongside the
approved hardening batch on 2026-09-12. Remaining feature and validation documentation is finalized
with its corresponding implementation; historical benchmark numbers are not treated as current proof.

The continued 2026-09-14 review adds bounded source caching, native scanner diagnostics and offline
SARIF evidence contracts. These are approved source changes, not claims about an existing release
tag. The reviewed checkpoint passed 983 application tests on Python 3.14 and 3.12 plus 41 automation
tests; isolated-wheel smoke checks also passed. Local-hook and Action documentation is finalized
with its separate integration review; distribution examples remain an explicit next phase.

### DocGuard 0.41.3 adoption — 2026-09-15

Every validator key in the published `docguard-config.schema.json` is pinned explicitly in
`.docguard.json`, each to the value it already had, so the repo does not inherit upstream defaults.
(A bare "N validators" count is deliberately not written here: MET001 binds such a claim to a
project-local enabled-validator count, not to the tool's validator total, and would flag a
correct statement as stale.)
DocGuard 0.41.3 added the three runtime validators (`diffSuspicion`, `referenceExistence`,
`apiDocSmells`) that earlier schemas omitted, so the config is now schema-complete with no
unknown keys.

The ten requirements of `websec.continuous-security-improvement` (FR-001…006, SC-001…004) have no
test coverage, which is accurate and intentional: that specification describes prioritized remaining
work. No `@req` annotations or validator exemptions were added, because doing so would assert
coverage that does not exist. DocGuard reconciles this correctly once `.docguard-specs.json` is
committed — the registry records `delivery: planned` and the traceability validator then excludes
those requirements rather than warning about them. Note the dependency on tracked state: with the
identical registry present but untracked, traceability reports 4/14 with ten TRC004 warnings; once
committed it reports 4/4. Do not "fix" those warnings during that window.

`docs/METHODOLOGY.md` carries `docguard:last-reviewed 2026-07-02` while its content changed in the
0.14.0 release commit, so FRS002 reports a review as due. Its countable claims were re-verified
against code on 2026-09-15 (22 extractors, 17 sink classes, 10 scanner entries, 9 named profiles —
all correct). The date was deliberately NOT bumped: a full methodology review is a human judgement
and the marker must not assert one that did not happen.

Updated 2026-09-16: a CHANGE-DRIVEN review of the same document corrected one claim that the
working-tree gitleaks pass had falsified (the scanner table said Gitleaks catches "committed
secrets"), documented the opt-in `--network` existence check beside the scanner layer, and added a
section on where in the workflow analysis runs (review-time full pass versus in-loop scoped gate).
The marker remains 2026-07-02 for the reason above: correcting claims touched by a change is not
the full human methodology review the marker asserts, and FRS002 stays open by choice. Scanner
entries are now **11**, not 10 — gitleaks runs as two disjoint passes.

## Resolved Drift

| ID | Resolution | Date |
|----|------------|------|
| review-root-boundary | Shared contained read policy now covers code/config/auxiliary inputs; documented stable-checkout and external-scanner limits. | 2026-09-12 |
| review-mcp-boundary | Replaced unauthenticated/LAN HTTP guidance with authenticated loopback-only transport and approved roots. | 2026-09-12 |
| review-coverage | Schema 2.0 exposes execution gaps and scope; `latest` denotes last completed execution. | 2026-09-12 |
| review-evidence | Replaced status/silence-as-proof and unmatched-as-false assumptions with evidence-backed labels and explicit unknowns. | 2026-09-12 |
| review-lifecycle | Disappearance is no longer observed; repair validation requires bound before/after evidence. | 2026-09-12 |
| review-external-analysis | SARIF import reuses specialist reports without executing target builds; freshness remains unverified and imported repair completion unsupported. | 2026-09-14 |
| review-source-budget | Aggregate retained payload budget and case-insensitive private paths are disclosed; alias hashes and read policy participate in evidence accounting. | 2026-09-14 |
| review-scanner-contracts | Native errors/contradictory counts prevent complete execution; manifest/version/resource identities and intelligence metadata survive normalization. | 2026-09-14 |
| review-control-scope | Cookie flags and PII/webhook/upload/extension controls require evidence tied to the affected value or response. | 2026-09-14 |
| review-continuous-gates | Accepted hook baselines advance only on successful policy-matched gates; isolated imports and trusted Action inputs/current artifacts replace implicit trust in target paths and latest output. | 2026-09-14 |

## Accepted Tool Meta-False-Positives

DocGuard reasons about the **target** apps this tool is built to scan, and `websec-validator`'s own
source legitimately *contains the patterns it detects* — so a few DocGuard signals are false on this
repo by construction. These are accepted, not bugs:

| Signal | Why it's a false positive | Disposition |
|--------|---------------------------|-------------|
| `docguard diff` — "`JWT_SECRET` documented but not found in code" | `JWT_SECRET` appears in `docs-canonical/ENVIRONMENT.md` only inside an explanatory note: it is a **detection signature** the `auth` extractor searches for in *target* repos (the forgeable-`dev-secret` lead), never an env var this tool reads. The note itself documents this. | Accepted. `guard` passes (Environment 3/3, Drift validators green); the `diff` flag is informational. Do not remove the note. |
| (historical) DocGuard mislabeling the tool as an Express/Flask/AWS web app | the deliberately-vulnerable sample apps under `tests/fixtures/` and the probe templates are scan **data**, not this tool's surface | Resolved via `.docguardignore` (`tests/fixtures/**`, probe templates, `**/*.egg-info/**`). |

---

## Deliberately NOT built (rejected features, with reasons)

Recording these so the decision is auditable and nobody re-litigates it from scratch. Each was
explicitly requested or planned, investigated, and rejected on accuracy grounds — websec's value is its
low false-positive rate, so a feature that adds noise or de-ranks real findings is a net negative even
when it sounds impressive.

| Feature | Why it was rejected | Date |
|---|---|---|
| **Route→sink reachability** (import-graph BFS from route handlers to sink files, tagging `no-http-path-found`) | Redundant with stronger existing logic: `extractors/surface.py` already gates sinks at extraction time — it skips test files, treats client/script/CLI files as non-server for request-driven classes, gates SQL/NoSQL on the datastore existing, and skips request classes entirely when the repo has no web surface. A file-level import BFS would be a weaker duplicate whose failure mode is the dangerous one: tagging a *genuine* sink "no HTTP path found" when it is reached via dynamic dispatch, DI containers, or framework auto-registration — i.e. de-ranking a real bug. Verified empirically: on a fixture with a handler→db.js→SQL chain, surface.py correctly reports zero sinks because the query is not user-input-gated at that site. | 2026-07-19 |
| **`gitleaks --log-opts=--all`** (scan all refs for secrets) | The premise was false. `gitleaks detect` (without `--no-git`) already walks the commit graph across ALL refs — proven with a secret committed on a side branch and found from another branch with the file absent from HEAD and the working tree. The flag would have been a no-op. The real gap it exposed (a secret whose file is already deleted is still leaked) shipped instead as the HISTORY-ONLY annotation. | 2026-07-19 |
| **cppcheck / SpotBugs+FindSecBugs adapters** | cppcheck is noisy without heavy per-check tuning, and SpotBugs needs compiled bytecode — which breaks websec's "never build the target" guarantee. If added later they must be gated behind an explicit `--deep` opt-in, never the default pass. | 2026-07-19 |
| **Broad FuzzDB payload-corpus import** | Bulk payload data inflates the staged-probe surface without improving *detection* precision. The targeted, per-endpoint probe commands in briefing §5b already carry the payload shapes that matter, each with a confirm/disconfirm oracle. | 2026-07-19 |


## 2026-09-14 — framework and adoption contracts reconciled

Approved source expansion adds bounded Django route declarations, shared manifest/service metadata,
scoped credential comparisons and preserved agent instructions. Canonical docs now distinguish
route candidates from resolved paths, native React from browser renderer hints, and current-attempt
artifacts from older latest output. The isolated wheel found a Django converter parameter-shape
mismatch; normalization to the existing `where: path` contract plus an actual CLI regression closed
it before phase completion. Final validation is 1046 application tests and 11 isolated-wheel commands;
historical wheel/proof results remain dated separately. No runtime dependency or target execution
was introduced. The CI remediation text now directs restoration/investigation, never lowering the floor.


## 2026-09-14 — fourth-phase scope and adoption reconciliation

Approved work adds bounded Python assigned-query flow, rejects statically redirected output runs,
exposes the shipped control-scope research suite, and provides opt-in pre-commit/PR/weekly examples.
The examples reuse existing entrypoints and were not activated. Native/hosted/staged coverage limits,
read-only token scope, independent engine provenance and incomplete execution are documented.
The new synthetic SQL scope explicitly excludes fixed-point/interprocedural guarantees. Final
validation passed 1082 application tests, 41 automation tests and 15 isolated-wheel commands;
1046/983 checkpoints and the public corpus score remain historical.

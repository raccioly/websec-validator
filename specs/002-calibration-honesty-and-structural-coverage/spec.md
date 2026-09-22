# Feature Specification: Calibration honesty and structural coverage

**Spec ID**: `websec.calibration-honesty-structural-coverage`
**Feature Branch**: `claude/eager-fermat-1f1b81` (specification only)
**Created**: 2026-09-21
**Status**: Approved 2026-09-21 (D1 two-step · D2 opt-in · D3 include · D4 include). W01 (scoring-rule constraint), W02 (structural coverage) and W03 (feedback loop) are IMPLEMENTED; W04 planned.
**Input**: Design review of Laya (Apache-2.0 local decision model; RLCD against strictly proper
scoring rules, act/escalate head, per-shape temperature calibration, structural OOD detection)
applied to websec-validator. Every claim below was verified against source and by execution on
2026-09-21; the verification log is in the session record and summarised in "Verified findings".

## Verified findings (the evidence this spec rests on)

Baseline at `7b2f945` (v0.16.0): `python3 -m unittest discover -s tests` → 1295 tests OK
(skipped=1); `docguard guard` → 177/183 (six low-confidence FRS002 freshness warnings, no failures).

| # | Finding | Evidence |
|---|---------|----------|
| V1 | Confidence originates in four places: (a) 26 of 38 `_f()` call sites in `findings.py` pass a literal; (b) 12 sites compute it by branching on structural evidence (e.g. `findings.py:609` `"HIGH" if verified else "LOW"`, `:646-650`, `:918`); (c) extractors set it themselves (23 literal, 1 computed, across `client_integrity`, `integrations`, `auth`, `webext`, `profiles`, `dependencies`, `agent_config`); (d) scanner findings derive it from severity+category at `findings.py:695`, with native passthrough for **Bandit only** (`:697-702`, unknown → LOW). | AST census; source read |
| V2 | HIGH is reserved for verified evidence (dynamic-confirmed, verified secret, HIGH-CVE); recon-only output never emits HIGH. The ordinal is already semi-binary: LOW/MEDIUM = heuristic strength, HIGH = verified. | `.wolf/cerebrum.md` line 39; V1(b) sites |
| V3 | The calibration apparatus (`calibration.py`: Wilson CI, three-tier backoff, local overlay, claimspec export) is complete and **currently empty at runtime**: `load()` quarantines the shipped table (`evidence_status: historical-unverified`, `:130`), `by_class_label == {}`, every finding gets `basis: "prior (uncalibrated)"`, `ci: [0,1]`. All 7 `corpus.json` truth entries are `is_real: null` / `historical-class-level-unverified`. | executed `calibration.load()`; corpus census |
| V4 | The quarantined seed measurement was LOW 1/8 = 0.125 [0.022, 0.471] and MEDIUM 29/51 = 0.569 [0.433, 0.695]. **The intervals overlap** on [0.433, 0.471]; the ordinal's separation is suggestive, not established. | `calibration.json`; arithmetic |
| V5 | `feedback.py` is write-only. `feedback.jsonl` is written at `cli.py:891`/`:948` and read by nothing in `src/`, `scripts/`, `hooks/`, `.github/`, or `mcp_server.py`. `redact()` already carries `attack_class`, `confidence`, `fingerprint` and `calibrated {p,n,basis}` — the exact sample key `record_samples` needs — and `record_samples` (`calibration.py:206-208`) correctly refuses anything without `evidence_verified`, `sample_id` and `provenance`. | repo-wide grep; source read |
| V6 | No act/escalate channel exists. `identity_precision` (`baseline.py:63`) is fingerprint stability. `repairs.build()` gives every plan the prerequisite "Confirm the finding on the original build" — the current stance is that **every** finding needs a human. `fixprompt._VERIFY` is a per-class map of mechanical verification steps and is the only existing signal of actionability. | source read |
| V7 | `SOURCE_EXT - CODE_EXT == {".scala"}` (`extractors/base.py:29-47`). The `elif suffix in SOURCE_EXT` branch at `:313` can fire only for Scala, so `files.unsupported` and the `unsupported_source` gap are dead for every other language. The one existing test (`tests/test_coverage.py:178`) uses `server.scala` and therefore passes. | Python set arithmetic; test read |
| V8 | **Reproduced**: a Phoenix/Elixir app with raw SQL interpolation, `System.cmd` injection, a hardcoded `sk_live_` secret and no auth plug produces `files.seen: 2, scanned: 0, read: 0, unsupported: [], gaps: []`, `execution_complete: true`, headline **"REQUESTED CHECKS COMPLETED — 0 files read; 0 code files selected."** `--require-complete` exits 0; `--fail-on medium` exits 0 ("no findings at or above threshold"); `websec gate --only lib/user_controller.ex` exits 0 with `passed: true, analyzed: [], missed: ["lib/user_controller.ex"]`. The agent briefing explains the empty route table as "a library/CLI, or route discovery failed". | executed runs, scratchpad fixtures |
| V9 | **Reproduced**: a Vapor/Swift app with the same four vulnerability classes produces `scanned: 2, read: 2, gaps: [], profiles: []` and 3 findings (2 generic `missing-auth`, 1 `incomplete-hsts`); the secret, SQLi and command injection are missed with no gap. `.swift/.kt/.cpp/.m` have no rule references outside the extension sets and the `_LANG` map; the `ios` profile keys on `frameworks`, which resolved to `?`, so its single configuration check did not run. | executed run; grep |
| V10 | The gate's pass-on-all-missed behaviour is deliberate and **pinned by a test**: `tests/test_gate_command.py:125` asserts `passed == True` for `matched: [], missed: ["ghost.py"]`, together with `missed_note` containing "NOT a clean result". `AGENTS.md` forbids rewriting existing assertions. | test read |
| V11 | No proper scoring rule (Brier, log score) is named anywhere in the repo; `isotonic` is mentioned as a future upgrade. No threshold is currently tuned from data. `gate.verdict` applies no confidence floor by default and never treats UNKNOWN as below the floor (`gate.py:104-130`). | repo-wide grep; source read |
| V12 | `docs-canonical/SECURITY.md:58` already states "Execution completeness is separate from scope exclusions and unsupported types, and `protection_complete` is always false" — the coverage fix is canonical-compliant; no `DRIFT` entry is needed. Spec 001 FR-007 already requires "disclose partial results rather than silently pass". Coverage gap `kind` and `calibrated.basis` are free strings in the JSON schemas; findings are not `additionalProperties: false`. | canonical read; schema read |
| V13 | Labelled assets on disk: `tests/test_detector_precision.py` (26 paired vulnerable/sanitised cases), 13 fixture directories under `tests/fixtures/` in clean/poisoned and present/missing pairs, and `calibration.samples_from_dynamic` which labels **only** `bola` from controlled probes. `bug-212` records why the local overlay was poisoned once and why v2 quarantines old-schema overlays. | file census; `.wolf/buglog.json` |

Corrections to the preceding review, recorded so they are not repeated: "39 call sites, all literal"
(V1); "non-overlapping intervals" (V4); "148 quarantined samples" mixed the shipped 59 with an
operator's machine-local overlay and is withdrawn; the `walker_policy` gap in the first Elixir run
was caused by the review's own output directory inside the target — the clean result is `gaps: []`.

## Delivered foundation

0.16.0 supplies the Wilson-interval calibration table with quarantine of unverified labels, the
claimspec `calibration` export, the coverage manifest with execution-vs-scope gap classification,
`scope_missed` for gate targets, the `capabilities()` profile catalog, the tag-never-drop FP
pre-pass, and the metadata-only feedback channel. This specification feeds and connects those parts;
it does not replace any of them.

**Non-adoption decision (recorded):** a local decision model (Laya or any other) is **not** adopted.
Zero-shot base checkpoints are near chance; all capability would come from fine-tuning on a labelled
corpus the project does not have (V3); a 1.7 GB weight file plus an ML runtime ends the stdlib-only
guarantee that `detector_revision` and the zero-dependency claim rest on; and a model's ranking is
neither deterministic nor falsifiable, which the existing `fpfilter` doctrine forbids. The
methodology is adopted; the model is not.

## User Scenarios & Testing

### Story 1 — A scan that analysed nothing can never read as clean (P1)

An operator or an agent can tell, from the headline line, the gate verdict and the briefing, the
difference between "analysed and found nothing" and "had no analyser for this code".

**Acceptance scenarios**:

1. The Elixir reproducer (V8) yields a `files.unsupported` list containing both files, an
   `unsupported_source` gap (`execution: false`), a `language_without_analyzer` gap naming
   `elixir` with a file count, and a headline that begins **"NO ANALYSABLE SOURCE"** rather than
   "REQUESTED CHECKS COMPLETED". `execution_complete` stays `true` (nothing failed to run).
2. The Swift reproducer (V9) yields a `thin_language_coverage` gap (`execution: false`) stating that
   `swift` has no sink, secret or authorization rules and how many files were read under it, derived
   from `capabilities()` (a language whose profile has no `kind: "sink"` check). The two generic
   `missing-auth` findings are unchanged.
3. The agent briefing's empty-route line offers a third cause — "no analyser for the detected
   language(s): …" — only when such a gap exists; unchanged otherwise.
4. `websec gate` text output for `analyzed: []` with non-empty `missed` reads
   `pass — 0 file(s) analyzed, N requested path(s) never analyzed (NOT a clean result)`. The JSON
   `passed` value and exit code are **unchanged** (V10). A new opt-in `--fail-on-missed` exits 2 in
   that state and is documented as a merge-time setting, not an agent-loop default.
5. `websec run --require-analyzed` (opt-in) exits 2 when `files.seen > 0` and `files.scanned == 0`.
   `--require-complete` is unchanged: scope loss is not execution loss.
6. A repository of only `.md`, `.json` and `.yml` files raises **no** language gap; the signal is
   restricted to recognised source suffixes and manifest-detected languages so it cannot become noise.
7. The existing `server.scala` test keeps passing unmodified; every new test is additive.

**Candidate ownership/tests**: `extractors/base.py` (a maintained `KNOWN_SOURCE_EXT` that is a true
superset of `CODE_EXT`), `extractors/profiles.py` (language-without-profile and thin-profile
detection from `capabilities()`), `coverage.py` (`from_context`, `add_profiles`, `render_md`),
`briefing.py`, `gate.py`, `cli.py`; `tests/test_coverage.py`, `tests/test_gate_command.py`,
`tests/test_briefing.py`. Fixtures: `tests/fixtures/lang_elixir_vulnerable/`,
`tests/fixtures/lang_swift_vulnerable/` (copies of the V8/V9 reproducers).

### Story 2 — Every tuned number is honest by construction (P1)

Any future threshold, cut-off or bucket fitted from labels optimises a strictly proper scoring rule.

**Acceptance scenarios**:

1. `docs/METHODOLOGY.md` §Layer 3b gains an "Objective" bullet: fitted quantities are chosen by
   Brier or log score on held-out labels; accuracy, precision, recall and F1 are reported but never
   optimised, because they are maximised by confident wrongness. `BENCHMARKS.md` §2 cross-references it.
2. `calibration.py` carries the same sentence as a module-level constraint next to `PRIOR`, so the
   rule sits where the temptation will arise.
3. `websec calibrate` prints, whenever it writes a table with ≥ `MIN_N` labelled samples in any cell,
   the Brier score of the table against those labels alongside the interval — the metric exists
   before anyone tunes on it. No behaviour depends on the number.
4. DocGuard stays at or above 177/183; CHANGELOG `Unreleased` records the constraint.

**Candidate ownership/tests**: `docs/METHODOLOGY.md`, `BENCHMARKS.md`, `calibration.py`,
`cli.py` (`cmd_calibrate`), `CHANGELOG.md`; `tests/test_calibration*.py` (Brier computed on a
synthetic table equals the hand value).

### Story 3 — Feedback and reviewed fixtures refill the empty calibration table without lowering the evidence bar (P1)

A false-positive report becomes a *candidate* label visible to the operator, and enters a measured
probability only after review; authored fixture pairs are measured in their own, separately labelled
table.

**Acceptance scenarios**:

1. `websec feedback --verdict false-positive` additionally appends a **calibration candidate** to
   the local overlay under `legacy_uncertain.pending_review`: the redacted record plus
   `fingerprint`, `analyzed_input_digest` and `detector_revision`. Nothing changes in
   `by_class_label`; `apply()` output is byte-identical before and after. `feedback.jsonl` itself
   is unchanged in shape (`schema_version` stays 1.0).
2. `websec calibrate --review` lists pending candidates with their bucket and current `p`;
   `websec calibrate --accept <sample_id> --reason "<text>"` writes the row with
   `evidence_verified: true` and `provenance: {kind: "operator-review", reviewer_reason, digests}`
   into `observations` and increments the cell. Acceptance without a reason is refused.
   `--reject <sample_id>` removes it from pending. A candidate whose `detector_revision` differs from
   the current one is listed as *stale* and cannot be accepted (the detector that produced it no
   longer exists).
3. Accepted rows appear in the merged table with `meta.personalized: true` and are exported by
   `to_claimspec` under `source.kind: "mixed"` exactly as dynamic-confirmed samples are today; no
   claimspec field changes.
4. `websec calibrate --synthetic` runs the paired cases from a manifest
   (`tests/fixtures/calibration-pairs.json`, generated from `test_detector_precision.py` cases and the
   clean/poisoned, present/missing fixture pairs) and writes `calibration-synthetic.json` with the
   same cell shape and a `meta.caveat` stating that authored pairs measure regression precision on
   anticipated cases, not field precision. It is **never** merged into `by_class_label`; `apply()`
   ignores it; `websec explain <class>` shows it as a second line "precision on authored pairs:
   k/n [lo, hi]". `test_calibration_claimspec.py` assertions that `buckets == by_class_label` hold.
5. `corpus.json` truth entries are relabelled with pinned revisions and `location_contains`
   specific enough to bind one finding, each with `is_real: true|false` and
   `review_status: "reviewed"`; `websec calibrate` regenerates `calibration.json` with
   `evidence_status: "reviewed"`, which `load_shipped()` then stops quarantining. Until every entry of
   a class is reviewed, that class stays out of `researched_classes` and falls back to the label tier.

**Candidate ownership/tests**: `feedback.py`, `calibration.py` (`record_candidate`, `review`,
`accept`, `fit_synthetic`, `brier`), `cli.py` (`cmd_feedback`, `cmd_calibrate`), `explain.py`,
`corpus.json`, `calibration.json`; `tests/test_feedback.py` (candidate written, table unchanged),
`tests/test_calibration_review.py` (accept/reject/stale), `tests/test_calibration_synthetic.py`
(separate table; `apply()` unaffected).

### Story 4 — Severity, confidence and disposition are three visible axes (P2)

A finding says how bad it is if real, how likely it is real, and whether an agent can act on it
alone — as three separately falsifiable fields.

**Acceptance scenarios**:

1. Each ledger finding gains an additive, advisory `triage` block:
   `{"disposition": "agent-fixable" | "human-required", "reason": <text>, "basis": "attack-class policy"}`,
   derived from a static per-`attack_class` map that is published by `websec capabilities`. The map
   marks a class `agent-fixable` only when the remediation is a local code/config change **and**
   `fixprompt._VERIFY` names a mechanical check for it (headers, cookies, CSP, clickjacking, HSTS,
   CORS, JWT verify options); classes whose fix is a policy decision or out-of-band action
   (`missing-auth`, `bola`, `mass-assignment`, `missing-rls`, `secret`, tenant classes) are
   `human-required`. Unknown classes default to `human-required`.
2. `triage` never gates: `gate.verdict`, `--fail-on` and `fpfilter` ignore it; the briefing orders
   the "start here" list by `(severity, calibrated.p, disposition)` and states that `agent-fixable`
   means "an agent may *propose* the patch — a human still reviews every diff", preserving the
   current stance (V6).
3. `repairs.build()` copies `disposition` into each plan; the prerequisite text is unchanged.
4. `ledger.schema.json` gains the optional `triage` object; SARIF output is unchanged.

**Candidate ownership/tests**: `findings.py` (derivation after calibration), `fixprompt.py`,
`briefing.py`, `repairs.py`, `schemas/ledger.schema.json`, `cli.py` (`capabilities`);
`tests/test_triage.py`, `tests/test_gate_command.py` (a `triage` value never changes a verdict).

## Functional Requirements

- **FR-007**: A run that read zero analysable source while seeing source files MUST say so in the
  headline, the coverage manifest, the gate text and the briefing, without changing default exit
  codes or any existing assertion. Opt-in flags may make it fail.
- **FR-008**: Language and profile coverage gaps MUST be derived from data the tool already holds
  (`files.types`, `service_inventory.languages`, `capabilities()`), classified `execution: false`,
  and restricted to recognised source suffixes and manifest-detected languages.
- **FR-009**: No label enters a measured cell without `evidence_verified`, `sample_id` and
  `provenance`; operator feedback is a candidate until an explicit, reasoned acceptance by a human.
  A candidate from a different `detector_revision` cannot be accepted.
- **FR-010**: Tables from different provenances (shipped corpus, operator-reviewed, dynamic-confirmed,
  authored pairs) are never summed across provenance except where the existing merge already does so
  (shipped + local overlay); authored-pair measurements live in their own file with their own caveat.
- **FR-011**: Any quantity fitted from labels is chosen by a strictly proper scoring rule; the Brier
  score is reported wherever a table with ≥ `MIN_N` samples per cell is written.
- **FR-012**: The `triage` field is advisory: it MUST NOT influence gate verdicts, `--fail-on`,
  suppression, or repair completion, and MUST be derived from a published static map, not asserted
  per finding.
- **FR-013**: Every change ships with the reproducer that motivated it as an additive test; the
  V8 and V9 fixtures become repository fixtures. Existing tests are not rewritten (`AGENTS.md`).
- **FR-014**: Runtime dependencies remain zero. No model, no ML runtime.

## Success Criteria

- **SC-005**: On the V8 fixture: headline "NO ANALYSABLE SOURCE", two coverage gaps, gate text
  contains "NOT a clean result", `--require-analyzed` exits 2, defaults exit 0. On the V9 fixture: a
  `thin_language_coverage` gap; findings unchanged.
- **SC-006**: A `false-positive` feedback record produces one pending candidate and zero change to
  `apply()` output; one `--accept` changes exactly one cell by one count.
- **SC-007**: `calibration-synthetic.json` exists after `calibrate --synthetic`, `by_class_label` is
  unchanged by it, and `explain` shows both lines.
- **SC-008**: METHODOLOGY, BENCHMARKS and `calibration.py` name the scoring-rule constraint; DocGuard
  ≥ 177/183; test count strictly increases; CHANGELOG `Unreleased` entry present.
- **SC-009**: With `triage` present, every existing gate and fail-on test passes unmodified.

## Edge Cases and Non-goals

- A `.py` file in an unsupported framework (Tornado, Sanic) is **not** covered by this spec: the
  language has analysers, the framework binding is a separate uncertainty already tracked by
  `profile_scope` and route-candidate status. Do not claim framework coverage from language coverage.
- Authored-pair precision is not field precision and must never be quoted as such.
- A `human-required` disposition is not a severity and must not be used to sort above a higher
  severity.
- The gate remains "a fast retry signal, not a review" (`gate.py` docstring); the new flags are for
  merge-time CI, and the default agent-loop behaviour is unchanged.
- No claim of Elixir, Swift, Kotlin or Rust *vulnerability* coverage is made by adding their gaps;
  the gaps exist precisely to say that coverage is absent.

## Decisions required before implementation

> **Decided 2026-09-21.** D1 two-step · D2 opt-in · D3 include · D4 include; order W01→W02→W03→W04.

- **D1 — Feedback evidence bar.** Proposed: candidate → explicit reasoned `--accept` by a human;
  stale-revision candidates unacceptable. Alternative: auto-accept when reproducible against a pinned
  digest (rejected here: reproducibility proves the finding fired, not that it is false).
- **D2 — Zero-analysed behaviour.** Proposed: mandatory text warning + opt-in `--fail-on-missed`
  (gate) and `--require-analyzed` (run); defaults and the pinned test unchanged. Alternative: change
  the default (requires rewriting `test_gate_command.py:125`, which `AGENTS.md` forbids without an
  explicit decision).
- **D3 — Triage channel.** Proposed: include as Story 4, advisory only. Alternative: defer; the
  three-axis clarification can be documentation-only.
- **D4 — Authored-pair table.** Proposed: include as a separate file. Alternative: defer until the
  corpus relabel (Story 3.5) lands, since it is the weaker evidence.

## Workstream register

| ID | Story | Files (expected) | Tests (additive) | Risk |
|----|-------|------------------|------------------|------|
| W01 ✅ | 2 | `docs/METHODOLOGY.md`, `BENCHMARKS.md`, `calibration.py` (`SCORING_RULE`, `brier()`), `cli.py`, `CHANGELOG.md` | `test_calibration_scoring.py` (10) | LOW |
| W02 ✅ | 1 | `extractors/base.py`, `coverage.py`, `inventory.py`, `briefing.py`, `gate.py`, `cli.py`, `CHANGELOG.md` | `test_unanalyzed_coverage.py` (24) + `test_unanalyzed_cli.py` (14) | MEDIUM |
| W03 ✅ | 3 | `calibration.py` (candidates/review/synthetic/reviewed_classes), `synthetic.py` + `pairs.json` (new), `cli.py`, `explain.py`, `corpus.json` | `test_calibration_review.py` (30) + `test_synthetic_pairs.py` (11) + `test_feedback_calibration_loop.py` (12) | HIGH |
| W04 | 4 | `findings.py`, `fixprompt.py`, `briefing.py`, `repairs.py`, `schemas/ledger.schema.json`, `cli.py` | triage derivation; gate invariance | MEDIUM |

Order: W01 → W02 → W03 → W04. W01 is documentation and governs the rest. W02 is a reproduced defect
with the evidence already collected. W03 needs D1. W04 needs D3. Each workstream lands as its own PR
with the reproducer test, per `AGENTS.md`; registration in `.docguard-specs.json` via
`docguard specs --write` accompanies the first PR.

## Implementation record — W01 + W02 (2026-09-21)

Baseline `7b2f945`: 1295 tests OK, DocGuard 177/183. After: **1343 tests OK**, DocGuard 188/208.

Measured no-degradation across six fixtures (`py_app`, `node_app`, `rls_missing`,
`agent_config_poisoned`, `webext_licensed`, `dep_supplychain`): findings, severities, confidences
and locations **byte-identical**; no coverage gap added or lost; fixture wall time 1.38s → 1.20s.
Both reproducers now disclose (`NO ANALYZABLE SOURCE` for Elixir; `thin_language_coverage` for
Swift) with default exit codes unchanged.

Two corrections made during implementation, both caught by measurement rather than review:

1. `.sql` was initially classified as unanalysed, which would have written a FALSE
   "never read" claim into the coverage manifest — `schemas.py:111` and `stack.py:189` glob
   `**/*.sql` for CREATE TABLE and RLS analysis. Caught because `rls_missing` and
   `webext_licensed` gained gaps they should not have. `test_no_unanalyzed_suffix_is_actually_read_by_an_explicit_glob`
   now reads the extractor sources and fails on any recurrence of this class of error.
2. Spec 002 originally reused `FR-001…SC-004`, colliding with spec 001 and making DocGuard warn on
   **both** specs' requirements. IDs now continue the sequence (`FR-007…FR-014`, `SC-005…SC-009`),
   which satisfies Spec-Kit's `FR-NNN` format and traceability's uniqueness requirement together.

DocGuard's 20 remaining warnings are all MEDIUM and none is a regression: 5 pre-existing FRS002
freshness heuristics, 1 pre-existing SPK002 (`.specify/` absent), 10 spec-001 requirements that
DocGuard only began evaluating once a second spec existed (pre-existing untraced debt, surfaced not
created), and 4 spec-002 requirements (FR-010, FR-014, SC-006, SC-007) that belong to the
unimplemented W03/W04 and are deliberately left untraced rather than given a false annotation.
Every HIGH validator passes, and Spec-Registry moved from warning to ✅ 2/2.


## Implementation record — W03 (2026-09-21)

After W02: 1343 tests, DocGuard 188/208. After W03: **1396 tests OK**, DocGuard **182/188** with
the same six pre-existing warnings as the original baseline (5 × FRS002 freshness heuristics, 1 ×
SPK002 `.specify/` absent); Traceability and Spec-Registry are both ✅ HIGH. Findings across all six
fixtures remain byte-identical to the 7b2f945 baseline, with no coverage gap added or lost.

D1 was implemented as approved (two-step). Three guards make the bar real rather than nominal:
acceptance without `--reason` is refused; acceptance of a candidate whose `detector_revision`
differs from the running build is refused as STALE; and accepting twice cannot double-count. One
accepted label deliberately does not move the probability, because `MIN_N` still governs whether a
cell is measured at all — a single verdict must not become a number.

D4 was implemented as approved (separate table). The pair manifest was rewritten mid-implementation:
the first version invented snippets, and four of eight pairs did not hold — including a control
(`DOMPurify.sanitize` assigned through an alias) that the tool fires on **by design**, per
`test_detector_precision.test_alias_reassignment_and_branch_uncertainty_keep_html_leads`. Declaring
that a false positive would have published a false claim about the detector. The manifest now uses
only forms whose behaviour is pinned by existing tests, and all five pairs hold with zero errors.

One gap found while implementing rather than while reviewing: `cmd_calibrate` computed
`researched_classes` as every class appearing in `corpus.json`, so an unreviewed class could still
be published as a class-specific cell. `calibration.reviewed_classes` now requires a reviewed entry
with an explicit boolean. The shipped corpus has **zero** reviewed classes today, which is the
honest state — relabelling requires cloning each pinned revision and reviewing findings by hand, and
there is deliberately no code path that promotes an unreviewed entry. FR-014 (zero runtime
dependencies) and SC-006/SC-007's remaining clauses stay untraced rather than falsely annotated.

# Benchmarks

How websec-validator is measured. Historical public-corpus measurements, authored regression controls
and unrun experiments are identified separately. A harness being available is not a measurement.

Last updated: 2026-09-14. Historical measurements below retain their original scope; a current
measurement requires a recorded corpus revision, detector revision and execution manifest.

## What "good" means for this tool

websec is not an autonomous scanner; it's the deterministic front-half that briefs an agent. So the
metrics that matter are:

1. **Coverage / recall** — does recon surface the app's known attack surface? (`websec proof`)
2. **Precision honesty** — for each finding, is the reported `P(real)` actually calibrated against
   ground truth? (`websec calibrate`)
3. **Reproducibility** — same input ⇒ same output, no LLM, no network to the target, zero runtime
   dependencies.

A tool that scores well on (1) but lies on (2) is worse than useless — it trains the agent to trust
false positives. So we report precision as a **calibrated probability with a confidence interval**,
not a single accuracy number.

## Corpus

Three deliberately-vulnerable, publicly-documented apps, so anyone can reproduce:

| App | Stack | What it exercises |
|-----|-------|-------------------|
| **VAmPI** | Python / Flask | BOLA, broken auth, mass assignment, SQLi |
| **NodeGoat** | Node / Express | OWASP Top 10 (injection, access control, SSRF) |
| **DVGA** | Python / GraphQL | GraphQL introspection, injection, DoS |

`websec proof` clones these on first run and scores whether recon surfaces each app's documented
surface.

## 1. Coverage (recall) — `websec proof`

```bash
websec proof
```

**Historical result: 10/10** documented-surface checks across the corpus (a deterministic, CI-trackable proxy).
An executed [2026-09-12 pinned run](docs/security-review/public-proof-20260912.json) also recorded
10/10 checks across all three available applications and seven unknown labels. Its recorded detector
revision predates subsequent edits, so it is a dated result rather than the current tree's score.
The [2026-09-14 isolated-wheel run](docs/security-review/public-proof-20260914.json) again completed
all three pinned applications and 10/10 checks with seven unknown labels. Its wheel and detector
hashes are retained in the report; later source changes do not inherit this measured result.
This is a *proxy* metric — the real question ("does the briefing lift an agent's bug-finding vs a
generic prompt?") is the manual A/B in [`corpus/PROOF-PROTOCOL.md`](corpus/PROOF-PROTOCOL.md), which
is human-run and reported separately.

## 2. Precision — calibrated `P(real)`, not a vibe

```bash
websec calibrate            # fits P(real) per (attack-class, confidence) bucket vs labeled ground truth
```

Fits a binomial proportion + **Wilson 95% CI** per bucket against `corpus.json`'s `truth` blocks
(historical n = 59 labels under the old unmatched-as-false policy). Legacy shipped calibration
(`calibration.json`), retained for transparency rather than claimed as a current remeasurement:

| Bucket | Real / Total | P(real) | 95% CI |
|--------|--------------|---------|--------|
| `missing-auth` · MEDIUM | 27 / 41 | 0.66 | [0.51, 0.78] |
| `graphql` · MEDIUM | 2 / 2 | 1.00 | [0.34, 1.00] |
| `command-injection` · LOW | 1 / 1 | 1.00 | [0.21, 1.00] |
| **MEDIUM (aggregate)** | 29 / 51 | 0.57 | [0.43, 0.70] |
| **LOW (aggregate)** | 1 / 8 | 0.13 | [0.02, 0.47] |

Findings can inherit a reviewed measured bucket estimate and interval; that is not an individual
finding's measured probability. Unmeasured/prior and legacy-unreviewed buckets must remain distinct
from reviewed evidence. Wide intervals mean thin evidence, not certainty.

**Objective constraint.** Anything fitted from labels is chosen by a **strictly proper scoring rule**
(Brier or log score), never by accuracy/precision/recall/F1 — those are maximized by confident
wrongness. `websec calibrate` prints the table's Brier score alongside the intervals. See
[METHODOLOGY.md § Layer 3b](docs/METHODOLOGY.md) for the full statement.

**Honest caveat (shipped in `calibration.json.meta`):** these rates are calibrated on a *deliberately
vulnerable* corpus and skew **optimistic on clean production code**. The current labeling policy keeps unmatched findings unknown unless explicit negative evidence
exists. Legacy estimates must be revalidated against reviewed labels before claiming current
precision. Unknown findings are reported separately and excluded from both true/false counts.

## 3. Zero-dependency, deterministic

- **Runtime dependencies: 0** (stdlib only). The tool shells out to scanners (Trivy, Gitleaks,
  Semgrep, Checkov) when present; it never imports them. `pip show websec-validator` lists no deps.
- **Reproducible scope:** compare analyzed-input and detector digests, selected profile/exclusions,
  scanner versions/rules, ignore policy, intelligence snapshots and calibration inputs. Timestamps,
  local tool availability and evidence overlays can vary output; repo contents alone do not pin them.

## Competitor comparison — protocol (not yet run)

To compare precision honestly against general-purpose SAST (Semgrep, Bandit), the numbers must come
from **identical conditions**: same pinned corpus, same reviewed positive/negative/unknown ground truth, and the same scope rules. That run isn't in this repo yet — rather than estimate it, here is the exact protocol
so the comparison is reproducible and not cherry-picked:

1. Pin the same corpus commit and explicit source-file scope. Capture each tool's version and
   configuration/rule bytes (SHA256). Use an offline captured Semgrep rule set, not floating
   `--config auto`; record Bandit plugins/configuration and WebSec detector/calibration provenance.
2. Run each tool separately in an operator-controlled environment. Record failed/partial/unavailable
   runs rather than omitting them. Normalize capture paths to corpus-relative paths without guessing.
3. Review explicit positive and negative labels and per-tool rule-to-class mappings. Match exact
   (file, line, class); unmatched, unreviewed and contradictory evidence stays unknown. Route-only
   WebSec locations cannot silently match file/line labels.
4. Import captured reports with `scripts/compare-reports.py`; publish its sanitized per-finding CSV
   and JSON alongside restricted original captures, provenance and reviewer decisions. Do not publish
   raw source excerpts/credentials just because they occur in a scanner report.
5. Report each tool's TP/FP/unknown separately. Precision is TP/(TP+FP), not TP/all findings.
   Reviewed-positive label hit coverage deduplicates label IDs and is **not general vulnerability
   recall**. Partial captures have no precision score. An unavailable/malformed capture is not clean.

This mirrors the identical-conditions discipline of good retrieval benchmarks: one shared corpus, one
grader, no per-tool tuning. Until it's run, we make **no** head-to-head precision claim.

### Offline report-import contract — 2026-10-01

The stdlib maintenance harness accepts native Semgrep/Bandit JSON or a WebSec findings ledger; it
does not execute scanners, import target code or access the network. Reports stay separated: no
cross-tool deduplication changes a denominator. Byte/row bounds, duplicate-key rejection and
contained input/output checks fail closed. `.local` inputs are forbidden. CSV formula prefixes are
escaped; source, messages and evidence text are not copied to outputs.

```bash
python3 scripts/compare-reports.py comparison-manifest.json --out comparison-output
```

The manifest uses schema version 1 and the following fields:

```json
{
  "schema_version": 1,
  "corpus_revision": "<40-lowercase-hex immutable commit>",
  "scope": ["app.py"],
  "labels": "reviewed-labels.json",
  "labels_sha256": "<SHA256 of exact label bytes>",
  "reports": [{
    "tool": "semgrep",
    "version": "<captured version>",
    "engine_source_revision": "<40-lowercase-hex tool source commit>",
    "package_sha256": "<SHA256 of captured installed distribution>",
    "configuration_sha256": "<SHA256 of reviewed captured configuration>",
    "scope_sha256": "<SHA256 of canonical sorted unique scope JSON>",
    "status": "completed",
    "report": "semgrep.json",
    "report_sha256": "<SHA256 of exact report bytes>",
    "rules": {"sql-rule": {"attack_class": "sqli", "reviewed": true}}
  }]
}
```

`labels` is a JSON list of objects with unique `id`, corpus-relative `file`, positive integer `line`,
`attack_class`, literal boolean `reviewed` and literal boolean `real`. Only reviewed boolean decisions
enter TP/FP. All labels must be in the common scope. To calculate `scope_sha256`, hash UTF-8 bytes of
`json.dumps(sorted(set(scope)), separators=(',', ':'))`. Supply at most one capture per tool
(`websec`, `semgrep`, `bandit`). Status is `completed`, `partial` or `unavailable`; the importer derives
`malformed` for unusable report bytes/structure/bindings and downgrades native execution errors,
skipped rules/paths and Bandit suppression counts to `partial`. Unavailable captures need
version/configuration/scope declarations but no report file.

Every capture declares a distinct immutable engine source revision and package byte digest. WebSec
captures additionally require `detector_sha256`, separate from the corpus/source and configuration
digests. Canonical grading-manifest and rule-mapping digests plus the CLI's exact manifest-byte digest
bind the grading policy; no raw source snippets or unrestricted report text are emitted.

The importer verifies report and label byte bindings and consistency of the declared common scope.
Versions, actual execution, configuration and review remain **operator-declared**, not independently
authenticated. Its paired fixture tests are synthetic contract evidence only: no new competitor
accuracy, current public-corpus recall or agent-benefit experiment has been run by this harness.

## Reproduce everything here

```bash
pipx install websec-validator
websec proof        # measures this run; historical scores are not promised
websec calibrate    # precision: refits calibration.json from the labeled corpus
```

## Security Regression Evidence

Synthetic boundary and fault-injection tests validate containment, MCP authorization/deadlines,
partial execution accounting and bound repair evidence. Paired detector fixtures validate specific
safe/unsafe expression patterns. Passing these tests is regression evidence, not a measured recall
rate on unseen applications, a live exploit test, or a head-to-head advantage over another scanner.
A release validation record should list exact commands, detector/source revision, executed test count,
corpus availability and skipped experiments. Comparisons remain unrun until raw results are published.

## Named-check and Proposal Evaluation

`websec capabilities` lists the nine named profiles and their manual/unknown limits. The packaged
`research/profile-cases.json` contains authored synthetic holdout controls; these differ from the
development fixture strings but do not constitute independent real-project measurement.

```bash
websec research catalog
websec research evaluate --suite control-scope --out suite-evaluation.json
websec research example --out proposal.json
websec research evaluate --proposal proposal.json --out evaluation.json
```

Evaluation reports development and holdout TP/FN/TN/FP/unknown counts, verifies the current detector
revision and rejects copied case content. “Eligible for human review” does not install or promote code.
Proposal provenance and license remain operator-declared metadata. The following primary sources
informed paired syntax checks: [PHP string interpolation](https://www.php.net/language.types.string.php),
[Rails hash conditions](https://guides.rubyonrails.org/v7.2/active_record_querying.html), and
[Java Runtime command arrays](https://docs.oracle.com/en/java/javase/18/docs/api/java.base/java/lang/Runtime.html).

## Resource and Performance Evidence

Source retention is bounded by per-file and per-context raw-byte caps; output imports additionally
bound expanded metadata and trace references. Cap tests assert incomplete execution with preserved
usable evidence. These limits do not establish a bound on total interpreter memory or analyzer subprocesses.

One same-checkout, sequential Actual full-recon pair measured 75.838 s before and 69.241 s after
lexical inventory-path caching (about 8.7%). Noncoverage facts and analyzed-input digest matched;
both scans retained the same oversized Yarn-input gap. The shared host and concurrent source edits
prevent treating this single pair as a frozen reproducible performance benchmark. Details are in the
[validation record](docs/security-review/validation.md). No competitor speed or accuracy claim follows.


## Source integration validation — 2026-09-14, third phase (historical)

The third-phase source suite passed 1046 tests on Python 3.14.7 and 3.12.14, with 41 repository automation
tests and 11 isolated-wheel command checks. Wheel SHA256:
`d6d260bc6d3d707f7b9657c8c54823db2d728e33df7094f5b8a04c831db884b6`.
This includes actual Django converter routing, native/browser metadata and safe agent installation.
These are integration checks, not a renewed vulnerability-recall benchmark. The historical 983-test
wheel's pinned corpus score stays bound to that earlier artifact. Full commands, timings and the
intermediate packaging defect are in [validation.md](docs/security-review/validation.md).


The discoverable `control-scope` suite contains three proposals and 24 authored cases. Its reviewed
CLI execution reported 18 TP and 6 TN across development/holdout partitions, with no failing or
unknown cases. This is synthetic, non-blind regression evidence only. Every proposal must pass,
the suite must be nonempty, and the detector revision must stay consistent; eligibility does not
activate a detector. Generate fresh examples when the shipped detector revision changes.


## Final source integration — fourth phase

The independently reviewed phase passed 1082 tests on Python 3.14.7 (21.492s) and Python 3.12.14
(22.536s), 41 automation checks, and 15 isolated-wheel commands. Wheel SHA256:
`1897f54de3d11f162f4af0a2d07b5d081bd09a9876c795387bb5b968c17c38ca`.
The added commands exercise suite discovery/evaluation, assigned Python SQL flow and output
symlink refusal. This validates integration and bounded synthetic behavior, not unseen-project
recall, full pre-commit lifecycle or a newly scored public corpus. The earlier wheel scores remain
bound to their recorded artifacts.

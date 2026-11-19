# Benchmarks

How websec-validator is measured. This page labels historical public-corpus measurements, authored regression controls
and unrun experiments separately. An available harness is not a measurement.

Last updated: 2026-09-14. Historical measurements below keep their original scope. A current
measurement needs a recorded corpus revision, detector revision and execution manifest.

## What "good" means for this tool

websec is not an autonomous scanner. It is the deterministic front half that briefs an agent. So these
metrics matter:

1. **Coverage / recall.** Does recon surface the app's known attack surface? (`websec proof`)
2. **Precision honesty.** For each finding, is the reported `P(real)` calibrated against
   ground truth? (`websec calibrate`)
3. **Reproducibility.** The same input gives the same output. There is no LLM, no network to the target, and zero runtime
   dependencies.

A tool that scores well on (1) but misreports (2) is worse than useless. It trains the agent to trust
false positives. So we report precision as a **calibrated probability with a confidence interval**,
not a single accuracy number.

## Corpus

The corpus has three deliberately vulnerable, publicly documented apps, so anyone can reproduce the results:

| App | Stack | What it exercises |
|-----|-------|-------------------|
| **VAmPI** | Python / Flask | BOLA, broken auth, mass assignment, SQLi |
| **NodeGoat** | Node / Express | OWASP Top 10 (injection, access control, SSRF) |
| **DVGA** | Python / GraphQL | GraphQL introspection, injection, DoS |

On its first run, `websec proof` clones these apps. It scores whether recon surfaces each app's documented
surface.

## 1. Coverage (recall) — `websec proof`

```bash
websec proof
```

**Historical result: 10/10** documented-surface checks across the corpus (a deterministic proxy that CI can track).
An executed [2026-09-12 pinned run](docs/security-review/public-proof-20260912.json) also recorded
10/10 checks across all three available applications and seven unknown labels. Its recorded detector
revision predates later edits. It is a dated result, not the current tree's score.
The [2026-09-14 isolated-wheel run](docs/security-review/public-proof-20260914.json) again completed
all three pinned applications and 10/10 checks with seven unknown labels. The report retains its wheel and detector
hashes. Later source changes do not inherit this measured result.
This is a *proxy* metric. The real question is whether the briefing helps an agent find more bugs than a
generic prompt. The manual A/B in [`corpus/PROOF-PROTOCOL.md`](corpus/PROOF-PROTOCOL.md) answers it.
A human runs that test and reports it separately.

## 2. Precision — calibrated `P(real)`, not a vibe

```bash
websec calibrate            # fits P(real) per (attack-class, confidence) bucket vs labeled ground truth
```

The command fits a binomial proportion + **Wilson 95% CI** per bucket against `corpus.json`'s `truth` blocks
(historical n = 59 labels under the old unmatched-as-false policy). The table shows the legacy shipped calibration
(`calibration.json`). We retain it for transparency. It is not a current remeasurement:

| Bucket | Real / Total | P(real) | 95% CI |
|--------|--------------|---------|--------|
| `missing-auth` · MEDIUM | 27 / 41 | 0.66 | [0.51, 0.78] |
| `graphql` · MEDIUM | 2 / 2 | 1.00 | [0.34, 1.00] |
| `command-injection` · LOW | 1 / 1 | 1.00 | [0.21, 1.00] |
| **MEDIUM (aggregate)** | 29 / 51 | 0.57 | [0.43, 0.70] |
| **LOW (aggregate)** | 1 / 8 | 0.13 | [0.02, 0.47] |

A finding can inherit a reviewed measured bucket estimate and interval. That is not the measured probability of the individual
finding. Unmeasured/prior buckets and legacy-unreviewed buckets must stay distinct
from reviewed evidence. Wide intervals mean thin evidence, not certainty.

**Objective constraint.** A **strictly proper scoring rule** (Brier or log score) chooses anything fitted from labels.
Accuracy, precision, recall and F1 never choose it, because confident wrongness maximizes them.
`websec calibrate` prints the table's Brier score alongside the intervals. See
[METHODOLOGY.md § Layer 3b](docs/METHODOLOGY.md) for the full statement.

**Honest caveat (shipped in `calibration.json.meta`):** these rates are calibrated on a *deliberately
vulnerable* corpus and skew **optimistic on clean production code**. The current labeling policy keeps unmatched findings unknown unless explicit negative evidence
exists. Revalidate legacy estimates against reviewed labels before you claim current
precision. The report lists unknown findings separately and excludes them from both true and false counts.

## 3. Zero-dependency, deterministic

- **Runtime dependencies: 0** (stdlib only). The tool shells out to scanners (Trivy, Gitleaks,
  Semgrep, Checkov) when present and never imports them. `pip show websec-validator` lists no deps.
- **Reproducible scope:** compare analyzed-input and detector digests, selected profile/exclusions,
  scanner versions/rules, ignore policy, intelligence snapshots and calibration inputs. Timestamps,
  local tool availability and evidence overlays can change the output. The repo contents alone do not pin them.

## Competitor comparison — protocol (not yet run)

To compare precision honestly against general-purpose SAST (Semgrep, Bandit), the numbers must come
from **identical conditions**: the same pinned corpus, the same reviewed positive/negative/unknown ground truth, and the same scope rules. This repo does not contain that run yet. We do not estimate it. Here is the exact protocol,
so the comparison is reproducible and not cherry-picked:

1. Pin the same corpus commit and explicit source-file scope. Capture each tool's version and
   configuration/rule bytes (SHA256). Use an offline captured Semgrep rule set, not floating
   `--config auto`. Record Bandit plugins/configuration and WebSec detector/calibration provenance.
2. Run each tool separately in an operator-controlled environment. Record failed, partial and unavailable
   runs. Do not omit them. Normalize capture paths to corpus-relative paths without guessing.
3. Review explicit positive and negative labels and per-tool rule-to-class mappings. Match exact
   (file, line, class). Unmatched, unreviewed and contradictory evidence stays unknown. Route-only
   WebSec locations cannot silently match file/line labels.
4. Import captured reports with `scripts/compare-reports.py`. Publish its sanitized per-finding CSV
   and JSON alongside restricted original captures, provenance and reviewer decisions. Do not publish
   raw source excerpts or credentials only because they occur in a scanner report.
5. Report each tool's TP/FP/unknown separately. Precision is TP/(TP+FP), not TP/all findings.
   Reviewed-positive label hit coverage deduplicates label IDs and is **not general vulnerability
   recall**. Partial captures have no precision score. An unavailable or malformed capture is not clean.

This follows the identical-conditions discipline of good retrieval benchmarks: one shared corpus, one
grader, no per-tool tuning. Until the run happens, we make **no** head-to-head precision claim.

### Offline report-import contract — 2026-10-01

The stdlib maintenance harness accepts native Semgrep/Bandit JSON or a WebSec findings ledger. It
does not execute scanners, import target code or access the network. Reports stay separate, so no
cross-tool deduplication changes a denominator. Byte/row bounds, duplicate-key rejection and
contained input/output checks fail closed. `.local` inputs are forbidden. The harness escapes CSV formula prefixes.
It does not copy source, messages or evidence text to outputs.

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
enter TP/FP. All labels must be in the common scope. To calculate `scope_sha256`, hash the UTF-8 bytes of
`json.dumps(sorted(set(scope)), separators=(',', ':'))`. Supply at most one capture per tool
(`websec`, `semgrep`, `bandit`). Status is `completed`, `partial` or `unavailable`. The importer derives
`malformed` for unusable report bytes, structure or bindings. It downgrades native execution errors,
skipped rules/paths and Bandit suppression counts to `partial`. Unavailable captures need
version/configuration/scope declarations but no report file.

Every capture declares a distinct immutable engine source revision and package byte digest. WebSec
captures also require `detector_sha256`, separate from the corpus/source and configuration
digests. Canonical grading-manifest and rule-mapping digests plus the CLI's exact manifest-byte digest
bind the grading policy. The harness emits no raw source snippets and no unrestricted report text.

The importer verifies report and label byte bindings and the consistency of the declared common scope.
Versions, actual execution, configuration and review remain **operator-declared**. Nothing authenticates them independently.
Its paired fixture tests are synthetic contract evidence only. This harness has not run a new competitor
accuracy, current public-corpus recall or agent-benefit experiment.

## Reproduce everything here

```bash
pipx install websec-validator
websec proof        # measures this run; historical scores are not promised
websec calibrate    # precision: refits calibration.json from the labeled corpus
```

## Security Regression Evidence

Synthetic boundary and fault-injection tests validate containment, MCP authorization/deadlines,
partial execution accounting and bound repair evidence. Paired detector fixtures validate specific
safe/unsafe expression patterns. Passing these tests is regression evidence. It is not a measured recall
rate on unseen applications, a live exploit test, or a head-to-head advantage over another scanner.
A release validation record should list exact commands, detector/source revision, executed test count,
corpus availability and skipped experiments. Comparisons remain unrun until someone publishes raw results.

## Named-check and Proposal Evaluation

`websec capabilities` lists the nine named profiles and their manual/unknown limits. The packaged
`research/profile-cases.json` contains authored synthetic holdout controls. They differ from the
development fixture strings. They are not an independent real-project measurement.

```bash
websec research catalog
websec research evaluate --suite control-scope --out suite-evaluation.json
websec research example --out proposal.json
websec research evaluate --proposal proposal.json --out evaluation.json
```

Evaluation reports development and holdout TP/FN/TN/FP/unknown counts. It verifies the current detector
revision and rejects copied case content. “Eligible for human review” does not install or promote code.
Proposal provenance and license remain operator-declared metadata. These primary sources
informed the paired syntax checks: [PHP string interpolation](https://www.php.net/language.types.string.php),
[Rails hash conditions](https://guides.rubyonrails.org/v7.2/active_record_querying.html), and
[Java Runtime command arrays](https://docs.oracle.com/en/java/javase/18/docs/api/java.base/java/lang/Runtime.html).

## Resource and Performance Evidence

Per-file and per-context raw-byte caps bound source retention. Output imports also
bound expanded metadata and trace references. Cap tests assert incomplete execution with preserved
usable evidence. These limits do not bound total interpreter memory or analyzer subprocesses.

One same-checkout, sequential Actual full-recon pair measured 75.838 s before and 69.241 s after
lexical inventory-path caching (about 8.7%). Noncoverage facts and analyzed-input digest matched.
Both runs retained the same oversized Yarn-input gap. The host was shared and the source was edited concurrently.
So do not treat this single pair as a frozen, reproducible performance benchmark. Details are in the
[validation record](docs/security-review/validation.md). No competitor speed or accuracy claim follows.


## Source integration validation — 2026-09-14, third phase (historical)

The third-phase source suite passed 1046 tests on Python 3.14.7 and 3.12.14, with 41 repository automation
tests and 11 isolated-wheel command checks. Wheel SHA256:
`d6d260bc6d3d707f7b9657c8c54823db2d728e33df7094f5b8a04c831db884b6`.
This includes actual Django converter routing, native/browser metadata and safe agent installation.
These are integration checks, not a renewed vulnerability-recall benchmark. The pinned corpus score of the historical 983-test
wheel stays bound to that earlier artifact. Full commands, timings and the
intermediate packaging defect are in [validation.md](docs/security-review/validation.md).


The discoverable `control-scope` suite contains three proposals and 24 authored cases. Its reviewed
CLI execution reported 18 TP and 6 TN across development/holdout partitions, with no failing or
unknown cases. This is synthetic, non-blind regression evidence only. Every proposal must pass.
The suite must be nonempty. The detector revision must stay consistent. Eligibility does not
activate a detector. Generate fresh examples when the shipped detector revision changes.


## Final source integration — fourth phase

The independently reviewed phase passed 1082 tests on Python 3.14.7 (21.492s) and Python 3.12.14
(22.536s), 41 automation checks, and 15 isolated-wheel commands. Wheel SHA256:
`1897f54de3d11f162f4af0a2d07b5d081bd09a9876c795387bb5b968c17c38ca`.
The added commands exercise suite discovery/evaluation, assigned Python SQL flow and output
symlink refusal. This validates integration and bounded synthetic behavior. It does not validate unseen-project
recall, the full pre-commit lifecycle or a newly scored public corpus. The earlier wheel scores remain
bound to their recorded artifacts.

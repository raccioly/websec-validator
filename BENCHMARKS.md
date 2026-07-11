# Benchmarks

How websec-validator is measured, on an open and reproducible harness. Every number here is produced
by a command in this repo against a **public** corpus — nothing is hand-tuned, and the protocol for
the one comparison that isn't yet run is documented rather than estimated.

Last updated: 2026-07-11.

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

**Result: 10/10** documented-surface checks across the corpus (a deterministic, CI-trackable proxy).
This is a *proxy* metric — the real question ("does the briefing lift an agent's bug-finding vs a
generic prompt?") is the manual A/B in [`corpus/PROOF-PROTOCOL.md`](corpus/PROOF-PROTOCOL.md), which
is human-run and reported separately.

## 2. Precision — calibrated `P(real)`, not a vibe

```bash
websec calibrate            # fits P(real) per (attack-class, confidence) bucket vs labeled ground truth
```

Fits a binomial proportion + **Wilson 95% CI** per bucket against `corpus.json`'s `truth` blocks
(n = 59 labeled findings). Current shipped calibration (`calibration.json`):

| Bucket | Real / Total | P(real) | 95% CI |
|--------|--------------|---------|--------|
| `missing-auth` · MEDIUM | 27 / 41 | 0.66 | [0.51, 0.78] |
| `graphql` · MEDIUM | 2 / 2 | 1.00 | [0.34, 1.00] |
| `command-injection` · LOW | 1 / 1 | 1.00 | [0.21, 1.00] |
| **MEDIUM (aggregate)** | 29 / 51 | 0.57 | [0.43, 0.70] |
| **LOW (aggregate)** | 1 / 8 | 0.13 | [0.02, 0.47] |

The point is not the headline number — it's that **each finding ships with its own measured hit-rate
and interval**, and a wide CI or a `basis: prior` bucket is surfaced as "thin data, verify manually"
rather than dressed up as certainty.

**Honest caveat (shipped in `calibration.json.meta`):** these rates are calibrated on a *deliberately
vulnerable* corpus and skew **optimistic on clean production code**. An unmatched finding is counted a
false positive (conservative). Only the five researched classes get class-specific cells; everything
else falls back to the per-label aggregate.

## 3. Zero-dependency, deterministic

- **Runtime dependencies: 0** (stdlib only). The tool shells out to scanners (Trivy, Gitleaks,
  Semgrep, Checkov) when present; it never imports them. `pip show websec-validator` lists no deps.
- **Deterministic:** recon and the ledger are a pure function of the repo contents — re-running
  produces byte-identical `FACTS.json` / `findings-ledger.json` (modulo the run timestamp).

## Competitor comparison — protocol (not yet run)

To compare precision honestly against general-purpose SAST (Semgrep, Bandit), the numbers must come
from **identical conditions**: same corpus, same labeled ground truth, same "unmatched = false
positive" rule. That run isn't in this repo yet — rather than estimate it, here is the exact protocol
so the comparison is reproducible and not cherry-picked:

1. On each corpus app, run websec (`websec run --scan`), Semgrep (`--config auto`), and Bandit.
2. Map every tool's findings to the corpus `truth` labels by (file, class), applying the same
   unmatched-is-FP rule to all three.
3. Report, per tool: precision (real / total), recall (real-found / real-total), and for websec the
   calibration reliability (does observed hit-rate fall inside the reported CI?).
4. Publish the harness script and raw per-finding CSV alongside the summary, as this file does for
   the websec-only numbers.

This mirrors the identical-conditions discipline of good retrieval benchmarks: one shared corpus, one
grader, no per-tool tuning. Until it's run, we make **no** head-to-head precision claim.

## Reproduce everything here

```bash
pipx install websec-validator
websec proof        # coverage: 10/10
websec calibrate    # precision: refits calibration.json from the labeled corpus
```

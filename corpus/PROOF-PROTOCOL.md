# Proof protocol — does the tool actually make you safer?

The whole tool rests on one claim: **handing an AI coding agent the
`AGENT-BRIEFING.md` makes it find real bugs more reliably than handing it the raw
repo with a generic prompt.** This doc defines how we test that, at two levels.

## Level 1 — recon coverage (automated: `websec proof`)

A deterministic, regression-trackable **proxy**: for each deliberately-vulnerable
app in the corpus, does the recon engine *surface the attack surface the app is
known to have* — right framework, auth scheme, endpoint count, IDOR/GraphQL
presence?

```bash
websec proof                       # clones the bundled corpus to ~/.cache/websec-corpus, scores
websec proof --corpus my.json      # your own corpus
```

This does **not** prove the briefing helps an agent. It proves the briefing
points at the right places. Run it in CI to catch recon regressions (a change
that drops endpoint detection or mis-detects auth will lower the score).

The corpus (`src/websec_validator/corpus.json`) currently includes VAmPI (Flask
API), NodeGoat (Express), and DVGA (GraphQL). Add apps by appending entries with
a `repo` (or `local_path`) and an `expect` block.

## Level 2 — the real kill-criterion (manual A/B)

This is the test that actually decides whether the tool earns its existence.
Run it before investing further.

**Setup.** Pick 5+ vuln apps with a *published vulnerability list* (Juice Shop,
crAPI, VAmPI, DVGA, NodeGoat). For each, you have a ground-truth set of real bugs.

**The A/B.** For each app, in two fresh agent sessions:
- **Control:** give the coding agent the repo + "find the security vulnerabilities."
- **Treatment:** give the agent the repo + `websec run` output (`AGENT-BRIEFING.md`
  + `FACTS.json` + the staged probes) and have it follow the briefing.

Run both against a *running* instance with the documented test accounts.

**Measure, per app:**
- **Recall** — fraction of the app's known bugs each arm actually found + confirmed.
- **Precision** — confirmed bugs ÷ all reported (the false-positive tax).
- **Time / steps** to first confirmed high/critical.

**Pass bar (from the market analysis):** the treatment arm must beat control on
recall **and** keep precision such that there are **< 2 false positives per true
positive** — repeatably, across the corpus. If the briefing doesn't lift recall
over a generic prompt, the tool is not earning its keep and the premise fails.

**Why it must be manual (for now):** it requires driving real coding agents
(Claude Code, Codex, Gemini) against running apps with auth — there's no
faithful way to automate the agent's judgment here. Automate Level 1; run Level 2
by hand at milestones.

> Record results in this folder as `results-YYYY-MM-DD.md` so regressions and
> improvements are visible over time.

## Evidence Discipline

Every experiment records corpus source revision, detector revision (including dirty implementation
changes), analyzed-input digest, profile/exclusions, scanner/rule versions, and execution completeness.
Use paired vulnerable and repaired examples with authorized synthetic data. Keep application splits
separate when tuning a detector; evaluating only its development fixtures measures regression, not
generalization. Unmatched findings remain unknown until reviewed, and unknowns are reported separately
from positive and negative labels. An empty scanner report is not a negative security proof.

A repair result requires a failing negative test on the original build plus the corresponding passing
negative and legitimate-behavior positive tests on the fixed build. Bind reports to application, source,
build, finding, plan and test IDs, hash them, and preserve the complete rerun ledger. The offline
`repair-verify` validator checks this operator-supplied evidence; it does not run or attest the tests.

Historical 10/10 surface checks are a narrow proxy. They neither establish complete protection nor
prove an agent-benefit/competitor benchmark. Publish current raw results and limitations before
claiming improvement.

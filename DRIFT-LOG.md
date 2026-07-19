# Drift Log

> Documents conscious deviations from canonical specifications.  
> Every `// DRIFT:` (or `# DRIFT:`) comment in code MUST have a matching entry here.

---

## Active Drift

_None._ The canonical docs in `docs-canonical/` were re-synced to the shipped **v0.9.1** tree
(2026-07-02) — extractor inventory (20, adds `webext`), test count (238), and version markers updated
to match code, so code and canonical intent are currently aligned. When code must deviate, add a
`# DRIFT: reason` comment at the site and a row here.

| ID | File | Line | Canonical Doc | Deviation | Reason | Date |
|----|------|------|---------------|-----------|--------|------|
| —  | —    | —    | —             | —         | —      | —    |

## Resolved Drift

| ID | Resolution | Date |
|----|------------|------|
| —  | —          | —    |

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

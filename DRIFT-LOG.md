# Drift Log

> Documents conscious deviations from canonical specifications.  
> Every `// DRIFT:` (or `# DRIFT:`) comment in code MUST have a matching entry here.

---

## Active Drift

_None._ The canonical docs in `docs-canonical/` were re-synced to the shipped **v0.9.0** tree
(2026-07-02) — extractor inventory (20, adds `webext`), test count (232), and version markers updated
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

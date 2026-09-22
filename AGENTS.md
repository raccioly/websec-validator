# Agent Instructions

<!-- docguard:version 0.9.1 -->
<!-- docguard:status approved -->
<!-- docguard:last-reviewed 2026-09-16 -->
<!-- docguard:owner @raccioly -->

> This project follows **Canonical-Driven Development (CDD)**.  
> Read canonical docs before making changes. Log drift when deviating.

---

## Project Overview

`websec-validator` is a local-first security-recon CLI that briefs an AI coding agent. It maps a repo's
attack surface, de-duplicates the static scanners it finds, stages a tailored probe library, and emits
an `AGENT-BRIEFING.md` — **code in, artifacts out; no LLM, no server, no running app** for the core
pass. Pure-Python, **stdlib only, zero runtime dependencies**; it shells out to external scanners
(Trivy/Gitleaks/Semgrep/Checkov/Prowler) and OWASP Noir when present. The package lives in
`src/websec_validator/`; the architecture is in [`docs-canonical/ARCHITECTURE.md`](docs-canonical/ARCHITECTURE.md).

## Project Documentation (CDD)

- **Canonical docs** (design intent, review-gated): `docs-canonical/` — `ARCHITECTURE.md`, `SECURITY.md`, `TEST-SPEC.md`, `ENVIRONMENT.md`
- **Long-form methodology** (the why behind every check): `docs/METHODOLOGY.md`
- **Proof protocol**: `corpus/PROOF-PROTOCOL.md`
- **Drift tracking**: `DRIFT-LOG.md` · **Change tracking**: `CHANGELOG.md`
- **Spec Kit constitution**: `.specify/memory/constitution.md`

## Build & Dev Commands

| Command | Purpose |
|---------|---------|
| `pipx install --editable .` | Install the CLI from source (or `pip install -e .` in a 3.11+ venv) |
| `python3 -m unittest discover -s tests` | Run the suite (1579 tests, stdlib only, no public network) |
| `websec run ./target` | Full pipeline → `FACTS.json` + `AGENT-BRIEFING.md` + `probes/` |
| `websec doctor ./target` | Show which optional scanners are installed |
| `websec gate` | Fast scoped pass/fail on the files you just changed (agent-loop check) |
| `websec attest` | Project a run into an audit-evidence table (gaps first; no verdict) |
| `websec proof` | Score recon coverage vs the vuln-app corpus (needs network on first clone) |
| `docguard guard` | Validate documentation against the code (CDD) |

## DocGuard — Documentation Enforcement

This project uses **DocGuard** (it is the maintainer's own tool — `npm i -g docguard-cli`) for CDD
compliance:

```bash
docguard guard                 # validate compliance (errors + warnings); ~16s here
docguard score                 # CDD maturity score (0-100)
docguard diff                  # gaps between docs and code
docguard diagnose              # guard → emit AI fix prompts
docguard verify --evidence     # declared doc claims vs committed artifacts (deterministic)
docguard verify --instructions # duplicate / contradictory / stale rules in AGENTS.md + CLAUDE.md
docguard specs --check         # spec lifecycle registry is present and consistent
docguard reconcile --since <ref>  # classify changed facts before editing intent (use a narrow ref)
docguard retire --plan         # read-only inventory of docs eligible to leave active context
```

### Committed DocGuard state

| File | Purpose |
|---|---|
| `.docguard.json` | Validator configuration. **All validators are pinned explicitly** — DocGuard's validators are opt-out, so new releases widen the gate on their own: the 0.33.1 → 0.40.5 upgrade historically moved this repo from 182 to 203 checks with no config change. This repo therefore does not inherit defaults. That 182 → 203 pair is a historical record of that upgrade, not a current count — do not cite a live check count here, it moves every release. |
| `.docguardignore` | Paths excluded from documentation scanning. |
| `.docguard-specs.json` | Spec lifecycle registry: immutable spec IDs, reviewed approval/delivery state, and observed artifact digests. Refresh observed fields with `docguard specs --write`; never hand-edit the `observed` block. |
| `.docguard-evidence.json` | Declared-evidence manifest binding exact statements in `docs/security-review/validation.md` to JSON pointers in the committed `public-proof-*.json` artifacts. A doc number that drifts from its artifact is caught deterministically. |

Local Git hooks (not tracked; `.git/hooks/`) run the sub-second gates
(`specs --check`, `verify --evidence`) on **pre-commit**, and the full `guard` on
**pre-push**. Both fail open when DocGuard is absent, matching the name-guard convention, and both carry
`# BEGIN/END DOCGUARD MANAGED` markers so a future `docguard init --with hooks` splices its
content instead of overwriting the name-guard.

### AI Agent Workflow

1. **Before any work**: read `docs-canonical/` and run `docguard guard` to see the compliance state.
2. **After changing code or docs**: re-run `docguard guard`; keep the numbers (22 extractors, 17 sink
   classes, 11 scanner entries, 1579 tests, dated 10/10 proof (not vulnerability recall)) consistent across every doc — DocGuard's metrics-consistency
   validator cross-checks them.
3. **Update `CHANGELOG.md`** for any user-visible change.
4. **Document drift**: if code must deviate from a canonical doc, add a `// DRIFT: reason` (or
   `# DRIFT: reason`) comment and a matching `DRIFT-LOG.md` entry.

## Code Conventions

- Python 3.11+, stdlib only — **do not add runtime dependencies**. Integrate external tools by shelling
  out (see `src/websec_validator/scanners.py`), never by importing.
- Add a recon dimension by dropping a module in `src/websec_validator/extractors/` and appending it to
  `REGISTRY` in `extractors/__init__.py`. One extractor must never crash the whole run (wrap in the
  registry driver's try/except, as existing extractors do).
- Keep recon **read-only and offline**; keep dynamic write probes **localhost-only**. These are
  security invariants, not preferences — see `docs-canonical/SECURITY.md`.
- Derive `__version__` from package metadata (already wired in `__init__.py`); the single source of
  truth for the version is `pyproject.toml`.

## File Change Rules

- Changes to >3 files warrant a short plan first.
- New extractors/probes need a matching test (`tests/test_recon.py` or `tests/test_pentest_regressions.py`).
- New shelled-out tools must degrade gracefully when absent (detected, reported, never hard-fail).
- Never add a runtime dependency without explicit justification.
- Documentation changes must pass `docguard guard` before commit.
- Never commit without explicit approval.

## Automated agents (Jules, Dependabot, and any other bot opening PRs)

This repo receives agent-authored PRs continuously. Follow these rules or the PR will be closed
automatically by `.github/workflows/bot-triage.yml`.

**Before opening a PR, search open AND closed PRs for the same change.** One failing test produced
79 open PRs here across two months, ~27 of them the same one-line edit worded differently each time.
Duplicates are detected by changed-file overlap, not by title, so rewording does not help.

**Only open a PR for a genuinely new finding, backed by evidence:**
- a defect → a failing test that demonstrates it
- a false positive → the input that triggers it, plus the expected output
- a performance claim → a measurement on a real workload

**If the test suite fails for you but CI is green, the difference is your environment, not the code.**
Say so in an issue rather than opening a PR. This was the exact cause of the 27-PR cluster: the suite
was not hermetic against a global `core.hooksPath`, which agent sandboxes set and GitHub runners do
not — so CI could never reproduce or confirm the fix. That defect is fixed (bug-217) and CI now has a
`hermeticity` job that manufactures the hostile config, so a real regression fails there.

**What merges without a human** (`.github/scripts/triage.py` is the authority):
- docs-only changes
- test changes that are **purely additive** — a diff that deletes or rewrites an existing assertion
  is a change to the detection contract and always gets a human
- dependabot patch/minor bumps confined to its own ecosystems' paths

**What never merges automatically:** anything under `src/`, `.github/`, packaging files, instruction
files (`AGENTS.md`, `CLAUDE.md`), binaries, or any major version bump.

**Never make a PR pass by removing coverage.** A deleted or gutted test makes this suite greener
*and* faster, so nothing else catches it. The floor is derived at CI time by counting the base
commit's suite — there is no `MIN_TESTS` to edit, and none should be reintroduced: a stored
counter is a shared number every branch adding tests must bump, and two branches that each add
the same count bump it identically and merge cleanly while being jointly wrong. If a removal is
genuinely correct, put a `Test-Removal: <reason>` trailer on the commit so the drop is recorded
in the history rather than hidden.

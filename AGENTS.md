# Agent Instructions

<!-- docguard:version 0.4.1 -->
<!-- docguard:status approved -->
<!-- docguard:last-reviewed 2026-06-10 -->
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
| `python3 -m unittest discover -s tests` | Run the suite (136 tests, stdlib only, no network) |
| `websec run ./target` | Full pipeline → `FACTS.json` + `AGENT-BRIEFING.md` + `probes/` |
| `websec doctor ./target` | Show which optional scanners are installed |
| `websec proof` | Score recon coverage vs the vuln-app corpus (needs network on first clone) |
| `docguard guard` | Validate documentation against the code (CDD) |

## DocGuard — Documentation Enforcement

This project uses **DocGuard** (it is the maintainer's own tool — `npm i -g docguard-cli`) for CDD
compliance:

```bash
docguard guard                 # validate compliance (errors + warnings)
docguard score                 # CDD maturity score (0-100)
docguard diff                  # gaps between docs and code
docguard diagnose              # guard → emit AI fix prompts
```

### AI Agent Workflow

1. **Before any work**: read `docs-canonical/` and run `docguard guard` to see the compliance state.
2. **After changing code or docs**: re-run `docguard guard`; keep the numbers (16 extractors, 15 sink
   classes, 136 tests, 10/10 proof) consistent across every doc — DocGuard's metrics-consistency
   validator cross-checks them.
3. **Update `CHANGELOG.md`** for any user-visible change.
4. **Document drift**: if code must deviate from a canonical doc, add a `// DRIFT: reason` (or
   `# DRIFT: reason`) comment and a matching `DRIFT-LOG.md` entry.

## Code Conventions

- Python 3.11+, stdlib only — **do not add runtime dependencies**. Integrate external tools by shelling
  out (see `scanners.py`), never by importing.
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

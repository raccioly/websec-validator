# Environment & Configuration

<!-- docguard:version 0.4.1 -->
<!-- docguard:status approved -->
<!-- docguard:last-reviewed 2026-06-10 -->
<!-- docguard:owner @raccioly -->
<!-- docguard:quality negation-load off — the tool's defining property is needing almost nothing (no runtime deps, no required env vars, no running app); the negations accurately describe optional-everything setup. -->

> **Canonical document** — Design intent. This file documents everything needed to run this project.  
> Last updated: 2026-06-10

The core pass needs **only Python 3.11+** — zero Python runtime dependencies. External scanners and
the Noir route engine are **optional**: the tool detects them, uses them when present, reports them
when absent, and never hard-fails. Or skip all of it and run the Docker image, which bundles them.

---

## Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Python | 3.11+ | Runtime (on stock macOS `python3` is often 3.9 — use `pipx`, Homebrew, or pyenv) |
| pipx | latest | Recommended install method (isolates the CLI, picks a 3.11+ interpreter) |
| OWASP Noir | latest | **Optional** route engine (50+ frameworks); regex fallback if absent — `brew install noir` |
| Trivy / Gitleaks / Semgrep (or OpenGrep) / Checkov / Prowler | latest | **Optional** static scanners, only run with `--scan`; install for fuller coverage |
| Docker | latest | **Optional** — `docker build` for the all-scanners-bundled image (no local installs needed) |

`websec doctor` reports which of the optional tools are present on your machine.

## Environment Variables

The tool requires **no** environment variables to run. It reads exactly one, and it is optional:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WEBSEC_CALIBRATION_HOME` | ❌ No | `~/.cache/websec-validator/` | Relocates the gitignored, local-only calibration overlay that personalizes confidence to your apps. |

> **Detection signatures, not consumed by the tool.** `JWT_SECRET` (and the `'dev-secret'` fallback)
> appears in `src/websec_validator/extractors/auth.py` only as a *pattern the recon engine searches for
> in the **target** repo* — it flags a target app that reads `JWT_SECRET` with an insecure hard-coded
> fallback (a forgeable-JWT lead). The validator itself never reads `JWT_SECRET`.

## Configuration Files

| File | Purpose | Template |
|------|---------|----------|
| `dynamic-config.json` | TEST target + role credentials for `websec dynamic --config` (gitignored) | `dynamic-config.example.json` |
| `.websec-ignore` | Per-target findings-ledger suppressions (glob paths or `category:<x>`) | — (committed per target repo) |
| `.docguard.json` / `.docguardignore` | DocGuard (CDD) config + doc-validation excludes | created by `docguard init` |
| `pyproject.toml` | Package metadata, entry point, packaged data | — |

## Setup Steps

```bash
# 1. Install the CLI (picks a 3.11+ interpreter)
pipx install websec-validator
#    …or bleeding-edge from source:
pipx install git+https://github.com/raccioly/websec-validator

# 2. (Optional) install the route engine + scanners for fuller coverage
brew install noir trivy gitleaks semgrep checkov

# 3. Verify what's available
websec --version
websec doctor ./my-app

# 4. Run it
websec run ./my-app            # recon + tailored probes + briefing
websec run ./my-app --scan     # …and execute the available static scanners
```

Then point your agent at the output: **"Read `websec-out/AGENT-BRIEFING.md` and follow it."**

### Or run via Docker (everything bundled, zero install)

```bash
docker build -t websec-validator .
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/scan" websec-validator run /scan --out /scan/websec-out
```

The image carries Noir + Trivy + Gitleaks + Semgrep + Checkov (arch-aware, amd64 + arm64); mount your
repo at `/scan` and the artifacts land in `/scan/websec-out`.

### Dynamic phase (optional, live TEST target)

```bash
cp dynamic-config.example.json dynamic-config.json   # fill in TEST URL + role creds (gitignored)
websec run ./my-app                                   # produces websec-out/FACTS.json
websec dynamic --config dynamic-config.json --facts websec-out/latest/FACTS.json
```

Never point the dynamic phase at production.

## Development Setup

```bash
git clone https://github.com/raccioly/websec-validator && cd websec-validator
pipx install --editable .                # or: pip install -e . in a 3.11+ venv
python3 -m unittest discover -s tests    # 103 tests, stdlib only
docguard guard                           # validate the documentation (CDD)
```

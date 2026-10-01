# Environment & Configuration

<!-- docguard:version 0.9.0 -->
<!-- docguard:status approved -->
<!-- docguard:last-reviewed 2026-09-30 -->
<!-- docguard:owner @raccioly -->
<!-- docguard:quality negation-load off — the tool's defining property is needing almost nothing (no runtime deps, no required env vars, no running app); the negations accurately describe optional-everything setup. -->

> **Canonical document** — Design intent. This file documents everything needed to run this project.  
> Last updated: 2026-09-14

The core pass needs **only Python 3.11+** — zero Python runtime dependencies. External scanners and
the Noir route engine are **optional**: the tool detects them, uses them when present, reports them
when absent. Explicitly selected unavailable tools make gated execution incomplete. Or skip all of it and run the Docker image, which bundles them.

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

The core CLI requires no environment variables. Optional integrations use:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WEBSEC_ENRICH_DIR` | No | `$XDG_CACHE_HOME/websec` or `~/.cache/websec` | Relocates validated intelligence snapshots; `--cache-dir` overrides it for intel commands. |
| `XDG_CACHE_HOME` | No | `~/.cache` | Base directory for the default intelligence cache. |
| `WEBSEC_MCP_TOKEN` | HTTP MCP only | — | Bearer token required at startup by `websec mcp --http`; provide through a secret environment. |
| `WEBSEC_CALIBRATION_HOME` | ❌ No | `~/.cache/websec-validator/` | Relocates the gitignored, local-only calibration overlay that personalizes confidence to your apps. |
| `WEBSEC_UPDATE_HOME` | No | `~/.cache/websec-validator/` | Absolute operator-selected directory for version/check-time `release.json` only; does not enable online checks. |
| `WEBSEC_HOOK_FAIL_ON` | No | `high` | Native pre-push severity gate; changing it invalidates accepted baseline policy. |
| `WEBSEC_HOOK_SCAN` | No | `0` | Set to `1` to execute optional scanners in native hooks. |
| `WEBSEC_HOOK_SCANNERS` | No | Empty | Comma-separated required adapters; requires `WEBSEC_HOOK_SCAN=1`. |
| `WEBSEC_SKIP_HOOK` | No | `0` | Explicit native-hook bypass when set to `1`; does not advance the accepted baseline. An honoured bypass is now RECORDED to `$GIT_DIR/websec-guardrail/bypass.jsonl`. It is NOT honoured by the agent-loop hook, because an agent can set an environment variable itself. |
| `WEBSEC_GATE_FAIL_ON` | No | `medium` | Severity threshold for the agent-loop `PostToolUse` gate. |
| `WEBSEC_GATE_MIN_CONFIDENCE` | No | `low` | Confidence floor for the agent-loop gate; `low` applies no filtering. |
| `WEBSEC_ACTOR` | No | — | Operator identity recorded under `attribution.declared`. SELF-ASSERTED and labelled as unverified — not audit evidence. |
| `WEBSEC_AGENT_MODEL` / `WEBSEC_AGENT_HARNESS` / `WEBSEC_AGENT_SESSION` | No | — | Agent identity recorded under `attribution.declared`; same self-asserted caveat. |

> **Detection signatures, not consumed by the tool.** `JWT_SECRET` (and the `'dev-secret'` fallback)
> appears in `src/websec_validator/extractors/auth.py` only as a *pattern the recon engine searches for
> in the **target** repo* — it flags a target app that reads `JWT_SECRET` with an insecure hard-coded
> fallback (a forgeable-JWT lead). The validator itself never reads `JWT_SECRET`.

## Configuration Files

| File | Purpose | Template |
|------|---------|----------|
| `dynamic-config.json` | TEST target + role credentials for `websec dynamic --config` (gitignored) | `dynamic-config.example.json` |
| `.websec-ignore` | Target-only suppressions plus fingerprint acknowledgements with optional `expires:YYYY-MM-DD`; malformed/expired dates reopen review | — (committed per target repo) |
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

Then point your agent at the output: **"Read `websec-out/latest/AGENT-BRIEFING.md` and follow it."**

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
websec run ./my-app                                   # produces websec-out/latest/FACTS.json
websec dynamic --config dynamic-config.json --facts websec-out/latest/FACTS.json
```

Never point the dynamic phase at production.

## Development Setup

```bash
git clone https://github.com/raccioly/websec-validator && cd websec-validator
pipx install --editable .                # or: pip install -e . in a 3.11+ venv
python3 -m unittest discover -s tests    # stdlib tests; see TEST-SPEC.md for verified inventory
docguard guard                           # validate the documentation (CDD)
```

## Advisory Version Checks

Available beginning with 0.20.0. Refresh installed managed agent guidance after upgrading with
`websec install <host>`; old guidance/plugin copies do not rewrite themselves. An older engine
without `update-check` must report that limitation rather than silently run an alternate online check.

```bash
websec update-check                         # cached metadata only; zero network calls
websec update-check --online                # explicit approval to check PyPI, never install
websec update-check --online --format json  # structured advisory status
```

Every security review should offer a check and ask the human before going online. A decline
does not block review. Doctor and generated briefings remain offline and give the same consent
reminder. MCP `websec_check_updates` defaults to `online: false`; true is the client's assertion
that the human approved a check. HTTP authentication applies even though this tool needs no repo.

The per-user cache contains only version/check-time metadata, never project data. Observations
older than 24 hours are stale and never refresh themselves. A failed check is `unavailable`, not
evidence that the installation is current; source/preview engine versions are `unknown_version`.
`current`, `ahead` and `update_available` compare the engine's stable version with the observed
stable release, not source provenance or install compatibility. JSON includes `freshness`,
`checked_at`, a bounded error code and `installation_performed: false`. Check-only exits remain
zero even when unavailable; these notices do not affect scan, gate or hook exits. Upgrade approval
is separate from check approval, and CLI and agent-plugin updates remain separate operations.

## Execution and HTTP MCP Options

`websec run ./my-app --scan --scanners semgrep,gitleaks --require-complete` requires the selected
checks to finish. `--fail-on high` also gates incomplete execution, with exit 3; findings-only failure
is exit 1, and exit 2 is reserved for a usage/configuration error in which nothing was scanned. Without `--scanners`, `--scan` selects available runnable adapters. Missing unselected
optional tools remain reported coverage limitations. Each attempt has a unique run directory;
`latest` continues to identify the most recent fully executed scan.

`websec gate` also requires complete scoped execution: unread, oversized or truncated selected
source returns exit 3 unless blocking findings already require exit 1. The agent hook blocks both
outcomes; unexpected internal crashes retain its loud fail-open behavior. Inventory matches are
reported separately from files actually read.

Regenerate staged probe drafts after upgrading: the shell drafts require their adjacent `_lib.bash`
and `_lib.py` transport helpers. Probe writes require localhost; explicitly configured remote login
POSTs remain credential setup, not write probes. Dynamic and draft transports bypass ambient HTTP
proxies and curl configuration so local-only destinations cannot be rerouted by those settings.

For MCP HTTP, supply `WEBSEC_MCP_TOKEN`, then run
`websec mcp --http --allow-root /absolute/project`. Repeat `--allow-root` to add approved roots.
The default root is the startup directory. Binding to non-loopback addresses is refused.

## Offline Workbench and Explicit Feed Refresh

`websec capabilities` prints named profiles and manual gaps without reading a target.
`websec intel status` and `websec intel reassess --ledger findings-ledger.json` consume local snapshots
offline. Only `websec intel refresh` downloads the public FIRST/CISA feeds; seven-day freshness is
visible, failed refreshes preserve prior snapshots, and absent/legacy data stays unverified.

`websec research example --out proposal.json` creates a current detector-bound example.
`websec research evaluate --proposal proposal.json` evaluates the bundled data-only cases; use
`--cases cases.json` for a separate case array. Both intel and research `--out` write new files only.
The evaluation never executes fixture source or installs proposal code.

### External Analysis Reports

The following capabilities are included beginning with 0.14.0; older packages/tags do not contain
the complete contract. No native analyzer is installed automatically by a report import.

```bash
websec run ./my-app --sarif ./analysis.sarif --require-complete
websec run ./my-app --sarif ./codeql.sarif --sarif ./other.sarif --fail-on high
websec run ./my-python-app --scan --scanners bandit --require-complete
```

SARIF import supports version 2.1.0 and safe relative source paths. Up to eight explicit reports may
be supplied; referenced files and URLs are never loaded. Successful producer invocations are required
for complete execution, while source freshness always remains unverified. Use `sarif-imports.json`
and the coverage manifest for protocol gaps, scope exclusions and report hashes.

Bandit must already be installed by the operator. Its adapter bypasses target `.bandit`/YAML/project
configuration and ignores inline `nosec`; coverage records that policy. Native errors, missing
explicitly selected analyzers and oversized reports fail gated execution with exit 3.

The package's control-scope regression corpus has a Python API and the explicit CLI selector
`websec research catalog` / `websec research evaluate --suite control-scope`. It is separate from
the default `research example` bundle; suite selection evaluates every shipped proposal in that
named suite without executing fixture source or installing rules.

## Agent guidance installation

Native `websec hooks` installation respects `core.hooksPath`. Husky's generated `.husky/_`
dispatchers are not modified: the managed block lives in the durable `.husky/<hook>` user script.
Shebangless Husky shell fragments are supported, existing foreign commands are preserved, and
explicit non-shell hooks require manual chaining rather than text insertion.

`websec install <host>` writes a generated skill or managed instruction block. Use a trusted selected
engine revision and inspect its source provenance, especially for editable checkouts. Existing
foreign skills or malformed markers produce an actionable refusal; there is no forced overwrite.
The shipped security-pass skill supplies an executable current-envelope selection example and
keeps engine/plugin updates explicit. Optional scanners remain separate executables with their own
configuration, filesystem and network behavior.


## Optional pre-commit and scheduled CI adoption

The [integration examples](../docs/integrations/README.md) publish a whole-repository pre-commit
manifest and inactive local/hosted configurations. Existing installations and user schedules are
unchanged. Use the explicitly configured trusted environment for a local checkout; remote adoption must
identify a reviewed 0.14.0-or-later commit containing the required implementation.
The hosted example grants contents read access, separates trusted engine and target checkouts,
and uploads only the current attempt's report. Pinned engines need reviewed updates for new rules;
scanner/feed refresh is a separate explicit operation.

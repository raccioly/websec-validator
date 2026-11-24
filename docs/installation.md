# Installation

This page covers every supported way to install `websec-validator`. It also covers the optional
external tools it can drive, and how to verify, upgrade and remove it. It is for anyone who sets up the
tool on a workstation, a CI runner or an air-gapped machine. When you finish, `websec --version` and
`websec doctor` confirm a working engine, and you know which optional analyzers it found.

For the fastest path to a first result, see the [Quickstart](quickstart.md).

## Requirements

| Requirement | Detail |
|---|---|
| Python | **3.11 or newer** (`requires-python = ">=3.11"` in [`pyproject.toml`](../pyproject.toml)). CI runs the suite on 3.11, 3.12 and 3.13. |
| Runtime Python dependencies | None. The package is stdlib-only; external tools are run as subprocesses when present, never imported. |
| Git | Optional for a plain `websec run`. Used by `--diff`, `websec gate`, `websec hooks`, the Gitleaks history pass and installs from a Git URL. |
| OS | CI runs on Linux (Ubuntu). macOS is a common development platform (the README and install hints assume Homebrew). See [Windows](#windows) for what is known and what is not. |

> [!WARNING]
> On stock macOS, `/usr/bin/python3` is often Python 3.9, which is too old. An install into it fails,
> because no release of `websec-validator` supports that interpreter. Use pipx or uv with a
> newer Python (Homebrew, pyenv or python.org), as described below.

## Choose an install channel

| Channel | Best for | Isolation | Notes |
|---|---|---|---|
| [pipx](#pipx-recommended) | Most people | Own virtualenv | Recommended. Puts `websec` on your `PATH`. |
| [pip in a venv](#pip-in-a-python-311-virtualenv) | CI jobs, scripted setups | The venv you create | Use a 3.11+ interpreter. |
| [uv](#uv-alternative) | uv users | Own tool environment | Equivalent to pipx; not exercised in this repo's CI. |
| [From source](#from-source-bleeding-edge) | Unreleased changes, contributors | pipx or venv | `doctor` labels non-index installs. |
| [Docker](#docker) | No local Python, bundled scanners | Container | Built locally from a clone; no published image. |
| [Claude Code plugin](#claude-code-plugin) | Claude Code users | n/a | Delivers agent instructions and a hook; you still need the CLI. |

Every channel installs the same three console scripts.

| Command | Purpose |
|---|---|
| `websec` | The CLI. |
| `websec-agent-hook` | The `PostToolUse` agent-loop gate used by `websec hooks install --agent` and the Claude Code plugin. |
| `websec-mcp` | The MCP server entry point (same server as `websec mcp`). |

### pipx (recommended)

pipx installs the CLI into its own virtualenv. It links the commands onto your `PATH`.

1. Install pipx if you do not have it (see the [pipx installation docs](https://pipx.pypa.io/stable/installation/)).
   On macOS with Homebrew:

   ```bash
   brew install pipx
   pipx ensurepath        # adds pipx's bin directory to PATH; open a new shell afterwards
   ```

2. Install websec-validator from PyPI:

   ```bash
   pipx install websec-validator
   ```

3. If pipx's default interpreter is older than 3.11, point it at a newer one explicitly:

   ```bash
   pipx install --python python3.12 websec-validator   # any 3.11+ interpreter on PATH
   ```

pipx uses the interpreter it was installed with, unless you pass `--python`. A pipx installed with
Homebrew normally uses Homebrew's current Python, which meets the requirement.

To pin a release (for example, to match a reviewed CI configuration), use a normal version specifier:
`pipx install "websec-validator==<version>"`.

### pip in a Python 3.11+ virtualenv

```bash
python3.12 -m venv .venv-websec                 # any 3.11+ interpreter
. .venv-websec/bin/activate
python -m pip install websec-validator
websec --version
```

Keep this virtualenv separate from the environment of the application you check. The integration
examples make the same point. The engine you run must be a trusted install, not the target's own
Python environment.

### uv (alternative)

[uv](https://docs.astral.sh/uv/) can install the package as an isolated tool, the same way pipx does:

```bash
uv tool install websec-validator
websec --version
```

uv follows the package's `requires-python` (3.11+). This repository's CI does not test uv installs.
Treat it as a convenient equivalent to pipx, not a verified channel.

### From source (bleeding edge)

Use this channel for unreleased changes on the default branch, or when you contribute.

```bash
# Latest default-branch code, isolated by pipx
pipx install git+https://github.com/raccioly/websec-validator

# From a local clone, editable (code changes take effect without reinstalling)
git clone https://github.com/raccioly/websec-validator
cd websec-validator
pipx install --editable .
```

Contributors can also use `python3 -m pip install -e .` in a 3.11+ virtualenv; see
[CONTRIBUTING.md](../CONTRIBUTING.md).

> [!NOTE]
> A version string does not identify a source install. A dirty editable checkout, a wheel installed
> from a local file and a clean PyPI install can all print the same `websec --version`.
> `websec doctor` prints where the running engine came from (package index, editable checkout,
> local file). It warns when the imported code is outside the installed distribution. Check it
> before you cite a version in a review.

### Docker

There is no published image. Build it from a clone of the repository. The
[`Dockerfile`](../Dockerfile) has two targets.

| Target | Build command | Contains |
|---|---|---|
| bundled (default, last stage) | `docker build -t websec-validator .` | The engine plus OWASP Noir, Trivy, Gitleaks, Semgrep and Checkov |
| core | `docker build --target core -t websec-core .` | The stdlib engine only, no external tools |

Both images run as a non-root `websec` user (UID 1001) and use `websec` as the entrypoint. They disable
recurring health checks, because the CLI is one-shot. `ARG` lines in the Dockerfile pin the scanner versions.
The bundled archives for Noir, Trivy and Gitleaks are checked against reviewed
SHA-256 digests before installation
([`scripts/install-container-scanners.sh`](../scripts/install-container-scanners.sh)). Those digest
checks do not make apt packages or transitive dependencies reproducible. They do not certify
every scanner adapter.

Run the image with your repository mounted at `/scan`:

```bash
# Core pass: recon + briefing. Noir (bundled) runs; the static scanners do not.
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/scan" websec-validator run /scan --out /scan/websec-out

# Also execute the bundled static scanners
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/scan" websec-validator run /scan --out /scan/websec-out --scan

# Check which tools the image carries
docker run --rm websec-validator doctor
```

What the bundled image does and does not include:

| Included | Absent (reported as missing, never silently skipped) |
|---|---|
| OWASP Noir, Trivy, Gitleaks, Semgrep, Checkov | OSV-Scanner, Bandit, gosec, Brakeman, TruffleHog, Prowler |

A bundled tool does not always run. Noir runs on every `run`. Trivy, Gitleaks, Semgrep and Checkov
run only under `--scan`. A plain `run` lists them and prints `(add --scan to execute them)`, exactly
as it does outside Docker.

Pass `--user "$(id -u):$(id -g)"` so the container runs with your UID. Without it, the container's
UID 1001 usually cannot write to a bind-mounted directory that you own on a Linux host. Anything
it does write is owned by UID 1001. The `$(id -u)` syntax needs a POSIX shell. On Windows, run these
commands from WSL.

The repository's container CI builds both targets natively on amd64 and arm64, runs an offline
source-only fixture with `--network none`, and executes each bundled tool's version command.

### Claude Code plugin

The repository is also a Claude Code plugin. The plugin delivers the `security-pass` skill and a
`PostToolUse` hook that calls `websec-agent-hook`. It does **not** install the Python CLI. Install
the CLI with one of the channels above first. The [AI agents guide](guides/ai-agents.md) has the install steps,
the `websec-validator@websec-plugins` install id, and the settings-file alternative for environments
without `/plugin`.

## Optional external tools

`websec run` needs nothing but the code. External tools add coverage when they are on your `PATH`.
websec never installs them and never imports them. It detects them and runs the relevant ones as
subprocesses. It de-duplicates their output into one ledger. The source of truth for this list is
`REGISTRY` in [`src/websec_validator/scanners.py`](../src/websec_validator/scanners.py).

### When each tool runs

- **OWASP Noir** runs on every `run` when installed, because it is the route engine, not a scanner.
  If Noir is absent or fails, websec uses its built-in route heuristics and a regex fallback.
- **Static scanners** run only when you pass `--scan`. Without `--scan`, websec lists the ones it
  found. It prints `(add --scan to execute them)`.
- **Language-specific SAST** (Bandit, gosec, Brakeman) is selected automatically. It runs only when the
  stack detector finds that language in the target. Brakeman also needs an `app/` directory
  at the root of the target, its own Rails precondition. Without it, `websec doctor` lists Brakeman under "not
  applicable to this target".
- **TruffleHog** never runs implicitly. It needs `--scan --verify-secrets`, because it sends each
  candidate credential to the provider's API.
- **`--scanners a,b`** turns selection into a requirement. A selected tool that is not installed is
  recorded as `unavailable`. The run is then incomplete (exit `3` under `--fail-on` or
  `--require-complete`). Missing tools that you did not select appear as limitations only.

### Tool reference

The macOS column repeats the install hints that websec prints (in `websec doctor`, and for Noir
also in the run output). Where the table lists no cross-platform command, use the project's official install
instructions.

| Tool | What it adds | Runs | Minimum version websec checks | macOS (Homebrew) | Linux / WSL | Project |
|---|---|---|---|---|---|---|
| OWASP Noir | Endpoint discovery across many frameworks; methods, paths, params | Every `run` | No minimum; `doctor` reports whether `noir --version` works | `brew install noir` | Official releases | [owasp-noir/noir](https://github.com/owasp-noir/noir) |
| Trivy | Dependency CVEs, secrets and IaC misconfigurations (`trivy fs`); also the engine behind `--sbom` | `--scan` | 0.38 | `brew install trivy` | Official releases | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) |
| OSV-Scanner | Dependency CVEs from OSV.dev, recursive lockfile discovery; cross-checks Trivy | `--scan` | 2.0 | `brew install osv-scanner` | Official releases | [google/osv-scanner](https://github.com/google/osv-scanner) |
| Gitleaks | Secrets in Git history (all refs) and in the working tree, as two passes | `--scan` | 8.0 (8.19+ preferred) | `brew install gitleaks` | Official releases | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) |
| Semgrep | SAST with `--config auto` plus websec's bundled rules | `--scan` | 1.0 | `pipx install semgrep` | `pipx install semgrep` | [semgrep/semgrep](https://github.com/semgrep/semgrep) |
| Checkov | IaC misconfiguration | `--scan` | 2.0 | `pipx install checkov` | `pipx install checkov` | [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) |
| Bandit | Python SAST (built-in defaults; ignores the target's Bandit config and `nosec`) | `--scan`, Python detected | 1.7 | `pipx install bandit` | `pipx install bandit` | [PyCQA/bandit](https://github.com/PyCQA/bandit) |
| gosec | Go SAST | `--scan`, Go detected | 2.0 | `brew install gosec` | `go install github.com/securego/gosec/v2/cmd/gosec@latest` | [securego/gosec](https://github.com/securego/gosec) |
| Brakeman | Rails SAST | `--scan`, Ruby detected and `app/` at the scan root | 4.0 | `gem install brakeman` | `gem install brakeman` | [presidentbeef/brakeman](https://github.com/presidentbeef/brakeman) |
| TruffleHog | Live verification of discovered secrets (network egress to providers) | `--scan --verify-secrets` only | Not version-checked | `brew install trufflehog` | Official releases | [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) |
| Prowler | Cloud posture | Detected and reported only; the current registry entry has no invocation, so websec does not execute it | Not version-checked | `pipx install prowler` | `pipx install prowler` | [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) |

Notes:

- **Semgrep / OpenGrep.** websec looks for an executable named `semgrep`. The `doctor` hint mentions
  [OpenGrep](https://github.com/opengrep/opengrep) as a fully open-source alternative. websec
  detects OpenGrep only if it is reachable as `semgrep`.
- **Version checks.** websec still runs a scanner that is older than its minimum, and reports the problem.
  `websec doctor` marks that scanner incompatible and exits `2`. See
  [Verify the installation](#verify-the-installation).
- **Noir in `doctor`.** Since 0.22.0, `websec doctor` has a "route engine" section. It shows `✓` with the
  version when `noir --version` works, and `?` when Noir prints no version. It shows `✗` when Noir crashes or times
  out, and the install hint when Noir is absent. A run also names the engine that produced the routes on
  its `routes:` line: `via noir`, or `via regex-fallback` with the reason (not installed, or
  `OWASP Noir failed: …`). See [Troubleshooting](troubleshooting.md#routes-come-from-regex-fallback-even-though-noir-is-installed).

## Verify the installation

```bash
websec --version          # prints: websec-validator <version>
websec doctor             # engine provenance, release-check advisory, scanners, route engine (Noir)
websec doctor ./my-app    # also scopes language-specific scanners to that repo's stack
```

`websec doctor` reports, for each relevant scanner, whether it is on `PATH` and which version it
found.

- `✓` means the version works with the command line that websec builds. `?` means the version could not be read.
  `✗` means the installed version is too old for that command line.
- It exits `2` when any installed, relevant scanner is too old. You can use `websec doctor .` as a CI preflight
  before you trust a `--scan` result. An incompatible scanner can run, fail in its own way,
  and look exactly like a clean run.
- Without a target, `doctor` does not know the stack, so it omits Bandit, gosec and Brakeman. Pass
  the repository path to see them. With a target, a relevant scanner whose own precondition fails
  (Brakeman without an `app/` directory) appears under "not applicable to this target".
- The "route engine" section reports OWASP Noir. A broken Noir is marked `✗`, but the
  exit code does not change. Every run falls back to regex route discovery until you fix Noir.
- `doctor` makes no network call. Its release line reads only cached metadata. See
  [Upgrade](upgrade.md) for the online check that needs your consent.

To see real output without pointing the tool at your own code, run `websec demo`. It checks a bundled
sample in a temporary directory and writes nothing to the current directory.

## Offline and air-gapped use

The core pass (`websec run <path>` with no network flags) needs no network. It reads the repository,
writes artifacts locally, and makes no network requests of its own. If OWASP Noir is installed, it
runs during the core pass as a local subprocess. Like every external tool, its network behavior
is outside websec's control. These paths do contact the network, and each one is opt-in:

| What | Network destination | Data sent |
|---|---|---|
| `websec run --scan` | Whatever each external tool contacts by default. websec passes no offline flags to Trivy, OSV-Scanner or Semgrep: for example Trivy downloads its vulnerability database, OSV-Scanner queries OSV.dev, and Semgrep's `--config auto` fetches registry rules. | Determined by each tool. Consult its own offline documentation. |
| `websec run --scan --verify-secrets` | Each secret's provider API, via TruffleHog | The candidate credential itself |
| `websec run --network` | `registry.npmjs.org`, `pypi.org` | Dependency names only; no versions, paths or repository identity. Use `--network-dry-run` to print the names first and send nothing. |
| `websec intel refresh` | FIRST EPSS feed and CISA KEV feed | No project data |
| `websec update-check --online` (or MCP `websec_check_updates` with `online: true`) | `pypi.org` release metadata | No project data; nothing is downloaded or installed |
| `websec dynamic` | The TEST instance you configure | HTTP requests to your own target |
| `websec proof`, `websec calibrate` (development commands) | GitHub, to clone the vuln-app corpus on first run | None beyond the clone |

`websec mcp --http` listens on loopback only and refuses non-loopback binds. It makes no outbound
connections of its own.

To install on a machine without network access, download the wheel elsewhere and copy it across.
The package has no runtime dependencies, so the wheel is the only file you need:

```bash
# On a connected machine
python3 -m pip download websec-validator --no-deps -d ./wheels

# On the air-gapped machine (Python 3.11+)
python3 -m pip install --no-index --find-links ./wheels websec-validator
```

## Upgrading

See [Upgrade](upgrade.md) for versioning, breaking changes and migration guides. Use these commands:

```bash
pipx upgrade websec-validator            # pipx
uv tool upgrade websec-validator         # uv
python -m pip install -U websec-validator  # pip, inside the venv
```

## Uninstalling

Remove what websec wrote into your repositories **before** you remove the package. The git hooks call
the installed engine. A pre-push gate with a missing runtime blocks the push.

1. Remove git guardrail hooks from each repository where you installed them:

   ```bash
   websec hooks status                 # shows whether post-commit / pre-push hooks are installed
   websec hooks uninstall              # removes websec's post-commit and pre-push blocks
   websec hooks uninstall --agent      # removes the PostToolUse gate from .claude/settings.json
   ```

   The uninstall command removes only the blocks that websec manages. Your own hook content stays.

2. Remove the agent instructions that `websec install` wrote:

   ```bash
   websec install status                 # lists what is installed in this project, per host
   websec install status --user          # the same for home-wide installs
   websec install codex --uninstall      # repeat per host: claude, cursor, codex, gemini, aider, generic
   websec install cursor --user --uninstall   # for home-wide installs made with --user
   ```

3. If you use the Claude Code plugin, remove it through `/plugin`.
4. Remove the package:

   ```bash
   pipx uninstall websec-validator         # or: uv tool uninstall websec-validator
   ```

5. Optionally delete local state. These are not removed by the package manager:

   | Path | Contents |
   |---|---|
   | `websec-out/` in each project | Run artifacts. They contain findings, so treat them as sensitive. |
   | `~/.cache/websec-validator/` | Release-check cache (`release.json`) and your local calibration overlay (`calibration-local.json`). Overridable with `WEBSEC_UPDATE_HOME` and `WEBSEC_CALIBRATION_HOME`. |
   | `~/.cache/websec/` | Threat-intelligence snapshots from `websec intel refresh` (or `$XDG_CACHE_HOME/websec`, or `WEBSEC_ENRICH_DIR`). |
   | `~/.cache/websec-corpus/` | Corpus clones from `websec proof` / `websec calibrate`. |
   | `.git/websec-guardrail/` | Records of honoured `WEBSEC_SKIP_HOOK` bypasses. |

## Windows

What is known:

- CI runs only on Linux. Native Windows is not tested.
- The code has some Windows-aware paths (for example, a Windows file lock for intelligence refresh and
  Windows drive handling in SARIF paths). That is not evidence of end-to-end support.
- The git guardrail hooks are shell scripts. The Docker examples use POSIX shell syntax.

The recommended path on Windows is **WSL** (Windows Subsystem for Linux). Install Python 3.11+ and
pipx inside your WSL distribution, and follow the Linux instructions. If you try native Windows and
have a problem, please [file a bug report](troubleshooting.md#reporting-a-bug-or-a-false-positive)
with your environment.

## Next steps

- [Quickstart](quickstart.md): first useful result in about five minutes.
- [Upgrade](upgrade.md): versions, breaking changes and migration guides.
- [Troubleshooting](troubleshooting.md): symptoms, causes and fixes.
- [AI agents guide](guides/ai-agents.md): Claude Code plugin, `websec install <host>`, MCP.
- [CLI reference](reference/cli.md): every command and flag.

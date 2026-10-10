# Upgrade

This page explains how to move to a newer `websec-validator`, how its version numbers work, and which
releases changed a contract you may depend on. It is for anyone maintaining a CI job, a git hook or
an agent integration that uses websec. At the end you will have upgraded the CLI, refreshed what it
installed into your repositories, and checked the migration notes that apply to you.

The per-release record is [CHANGELOG.md](../CHANGELOG.md). Each release entry starts with a
`Migration:` line (or section) saying whether you need to do anything.

## Check whether a newer release exists

websec never checks for updates on its own and never installs anything. Two commands exist:

```bash
websec update-check            # offline: reads only cached release metadata
websec update-check --online   # asks PyPI for release metadata; downloads and installs nothing
```

`--online` contacts `pypi.org`, so agents following websec's instructions ask you before running it
(the MCP equivalent is `websec_check_updates` with `online: true`). A decline or a failed check does
not block a review or change its findings. The result is cached per user in
`~/.cache/websec-validator/release.json` (override with an absolute path in `WEBSEC_UPDATE_HOME`).
`websec doctor` prints the same advisory line from the cache.

## Upgrade the CLI

1. Upgrade with the tool you installed it with:

   ```bash
   pipx upgrade websec-validator                 # pipx
   uv tool upgrade websec-validator              # uv
   python -m pip install -U websec-validator     # pip, inside the venv
   ```

   For a Git or editable install, reinstall so the package metadata (and therefore
   `websec --version`) matches the code:

   ```bash
   pipx install --force git+https://github.com/raccioly/websec-validator   # Git URL install
   git pull && pipx install --force --editable .                         # editable clone
   ```

   For Docker, pull the new source and rebuild the image (`docker build -t websec-validator .`, or
   with `--target core`).

2. Verify which engine is now running:

   ```bash
   websec --version
   websec doctor
   ```

   `doctor` shows where the engine came from. If it does not say the engine was resolved from a
   package index when you expected one, see
   [Troubleshooting](troubleshooting.md#websec---version-or-doctor-shows-an-old-or-unexpected-engine).

3. Read the changelog entries between your old and new version, and any migration guide listed
   [below](#migration-guides-and-notable-changes).

4. Refresh what websec wrote into your repositories. Upgrading the package does not change them:

   ```bash
   websec install status                 # which agent instructions are installed
   websec install <host>                 # re-run per host to refresh the managed instructions
   websec hooks status                   # which git hooks are installed
   websec hooks install                  # re-run with the same flags (e.g. --pre-push) if release notes ask
   ```

   Re-run `websec install <host>` only after verifying the engine (step 2). Known generated skills and
   complete managed blocks are refreshed in place; foreign files and ambiguous markers are refused
   without writes.

5. Before accepting a new baseline, review new, changed and reopened findings and any coverage gaps.
   Keep earlier run directories and accepted baselines as history. A finding that disappears after
   an upgrade is "no longer observed", not proof of a fix.

### Pinning and rolling back

Pin an exact release with a normal version specifier, for example in CI:

```bash
pipx install --force "websec-validator==<version>"
```

For the GitHub Action, pin a reviewed commit (`uses: raccioly/websec-validator@<reviewed-commit-sha>`)
rather than a branch. See the [GitHub Actions guide](guides/ci/github-actions.md).

## Two delivery paths: CLI and Claude Code plugin

The CLI and the Claude Code plugin are delivered separately:

| Component | Delivered by | Updated by |
|---|---|---|
| CLI engine (`websec`, `websec-agent-hook`, `websec-mcp`) | PyPI releases (semver) | Your package manager, as above |
| Claude Code plugin (skill and hook definition) | Reviewed Git content from this repository | An explicit marketplace refresh in Claude Code's `/plugin` |

The plugin manifests deliberately carry no version field of their own, and neither component
upgrades the other. When an agent's instructions look stale, check both: the engine with
`websec --version` and `websec doctor`, and the plugin through `/plugin`. The `security-pass` skill
checks the engine's version and provenance and reports a missing or stale engine rather than
installing one.

## How versions work

- The version is declared once, in [`pyproject.toml`](../pyproject.toml). `websec --version` reads
  it from the installed package metadata.
- The project is in the **0.x** series. A **minor** bump (0.20 to 0.21) means new features or an
  incompatible contract change. A **patch** bump (0.21.0 to 0.21.1) is for fixes and performance.
- Patch releases can still change observable behaviour. For example, 0.15.2 made two commands that
  had wrongly exited `0` exit `2`. Always read the `Migration:` line.
- Machine-readable artifacts carry their own version. `FACTS.json`, `findings-ledger.json` and
  `findings.envelope.json` use `schema_version: "2.0"` (since 0.14.0); SARIF output is 2.1.0. Check
  `schema_version` explicitly in anything that parses these files. JSON Schemas ship in the package
  under [`src/websec_validator/schemas/`](../src/websec_validator/schemas/).
- Only the latest release receives security fixes (see [SECURITY.md](../SECURITY.md)).

## The 0.17.0 exit-code change

0.17.0 split the exit codes so CI can tell a vulnerability from a broken toolchain. This is the
change most likely to break an older CI script.

| Code | Meaning since 0.17.0 | Before 0.17.0 |
|---|---|---|
| `0` | The gate ran and nothing met the threshold (or no gate was requested). This does not prove protection. | Same |
| `1` | Findings at or above `--fail-on`. | Same |
| `2` | Usage or configuration error, or `websec doctor` found an incompatible scanner. Nothing was scanned. | Also meant *requested checks did not complete* |
| `3` | Requested checks did not complete (`--require-complete`, or `--fail-on` with an execution gap), or `--require-analyzed` found nothing analyzable. The result is **not** a pass. | Did not exist |

What to change:

- A CI step that tested for `2` to detect an incomplete run must test for `3`, or read
  `coverage.execution_complete` from the artifacts, which did not change.
- A run that is both gate-failing and incomplete exits `1`, prints both facts, and records
  `gate.failure_kind` as `findings+incomplete` in the ledger. The finding count is then a floor.

A handler that keeps the four outcomes distinct:

```bash
set +e
websec run . --fail-on high --require-complete
status=$?
set -e
case "$status" in
  0) echo "gate passed (requested checks ran; not proof of protection)" ;;
  1) echo "findings at or above the threshold"; exit 1 ;;
  2) echo "usage or configuration error; nothing was scanned"; exit 2 ;;
  3) echo "requested checks did not complete; read coverage.json gaps"; exit 3 ;;
  *) echo "unexpected exit $status"; exit "$status" ;;
esac
```

> [!NOTE]
> Before 0.22.0, some early argument errors (a target that is not a directory, several `dynamic`
> and `calibrate` errors) exited `1`, the same code as findings. From 0.22.0 every usage error exits
> `2`. See the [0.22.0 migration notes](MIGRATING-0.22.0.md).

## Migration guides and notable changes

| Release | What changed | Read |
|---|---|---|
| 0.14.0 | Schema 2.0 for facts, ledger and envelope; one immutable directory per run under `websec-out/runs/` with a `latest` pointer; fingerprint V2 with V1 aliases; ignore files discovered from the target, not the working directory; GitHub Action and integration contracts. | [MIGRATING-0.14.0.md](MIGRATING-0.14.0.md) |
| 0.15.2 | An unknown subcommand that is not an existing path now exits `2` with a suggestion instead of being scanned as a path. | [CHANGELOG](../CHANGELOG.md) |
| 0.17.0 | **Breaking:** exit codes split (`2` = usage error, `3` = incomplete). `websec init` and `websec doctor` version checks added. | [Above](#the-0170-exit-code-change), [CHANGELOG](../CHANGELOG.md) |
| 0.17.1 | No behaviour change; corrected `--help` text that still described the old exit codes. | [CHANGELOG](../CHANGELOG.md) |
| 0.18.0 | Opt-in `--require-analyzed` (exit `3` when no source could be analyzed). `run` no longer version-probes scanners unless `--scan` is given. Measured `P(real)` from a relabelled corpus. | [CHANGELOG](../CHANGELOG.md) |
| 0.19.1 | Husky users: re-run `websec hooks install` (and `--pre-push`) to move the guardrail into the durable `.husky/<hook>` script. | [CHANGELOG](../CHANGELOG.md) |
| 0.21.0 | Changed findings from bounded source analysis; budget overruns now persist as incomplete execution. Consent and exit contracts unchanged. | [MIGRATING-0.21.0.md](MIGRATING-0.21.0.md) |
| 0.22.0 | Exit codes follow the contract everywhere (usage errors `2`; `dynamic` gates only dynamic evidence; `attest` never picks a partial run). Subdirectory `--diff`/`gate` now gate what changed. `security/` is scanned. `.websec-ignore` path patterns match on path components, with warnings for lines that relied on substring matching. | [MIGRATING-0.22.0.md](MIGRATING-0.22.0.md) |

> [!NOTE]
> The "Interpret exit codes" section of [MIGRATING-0.14.0.md](MIGRATING-0.14.0.md) describes the
> pre-0.17.0 meaning of exit `2`. For current behaviour, use the table above.

## See also

- [CHANGELOG.md](../CHANGELOG.md): every release, with its migration line.
- [Installation](installation.md): install channels, verification and uninstalling.
- [Troubleshooting](troubleshooting.md): stale engines, exit codes and incomplete runs.
- [CLI reference](reference/cli.md) and [outputs reference](reference/outputs.md).

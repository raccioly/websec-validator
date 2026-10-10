# CLI reference

Every `websec` command, option, default and exit code, written from the argparse tree in
[`src/websec_validator/cli.py`](../../src/websec_validator/cli.py) (`build_parser()`). A test binds
this page to that parser: a new subcommand or long option fails CI until it is documented here.

Options that send data off the machine are marked **[network]**. Everything else reads local files
and writes local artifacts only.

## Contents

- [Global options](#global-options)
- [Exit codes](#exit-codes)
- [Environment variables](#environment-variables)
- Review: [`run`](#websec-run) · [`init`](#websec-init) · [`doctor`](#websec-doctor) ·
  [`update-check`](#websec-update-check) · [`demo`](#websec-demo) · [`explain`](#websec-explain) ·
  [`capabilities`](#websec-capabilities)
- Agent integration: [`gate`](#websec-gate) · [`hooks`](#websec-hooks) ·
  [`install`](#websec-install) · [`emit-context`](#websec-emit-context) · [`mcp`](#websec-mcp)
- Evidence and triage: [`attest`](#websec-attest) · [`feedback`](#websec-feedback) ·
  [`repair-verify`](#websec-repair-verify)
- Workbench: [`intel`](#websec-intel) · [`research`](#websec-research)
- Live testing: [`dynamic`](#websec-dynamic)
- [Development commands](#development-commands): [`recon`](#websec-recon) ·
  [`proof`](#websec-proof) · [`calibrate`](#websec-calibrate)

## Global options

```text
websec [-h] [--version] <command> ...
websec <path> [run options]
```

| Option | Description |
|---|---|
| `--version` | Print `websec-validator <version>` and exit 0. The version comes from the installed package metadata; a source tree that is not installed reports `0.0.0+source`. |
| `-h`, `--help` | Print help for `websec` or for any subcommand. |

Dispatch rules (from `main()`):

- `websec` with no arguments prints the help and exits 0.
- `websec <path>` with no subcommand is rewritten to `websec run <path>`, but **only if the path
  exists**. An unknown word that is not an existing path is an error (exit 2) with a "did you mean"
  suggestion, so a typo such as `websec atest .` never silently becomes a scan of `.`.
- The usage line lists the main user-facing commands. `emit-context`, `gate` and `attest` are
  listed in the help body but not in the usage line; `recon`, `proof` and `calibrate` are hidden
  from help entirely (see [Development commands](#development-commands)). All of them work when
  invoked by name.

```bash
websec --version
websec ./my-app                 # same as: websec run ./my-app
websec run --help
```

## Exit codes

`websec run` and `websec gate` follow a four-code contract so CI can tell a vulnerability from a
broken toolchain. The constants are `EXIT_OK`, `EXIT_FINDINGS`, `EXIT_USAGE` and `EXIT_INCOMPLETE`
in `cli.py`.

| Code | Meaning | What to do |
|---|---|---|
| `0` | Clean: the gate ran and nothing met the threshold, or no gate was requested. | Ship. It does not prove protection. |
| `1` | Findings at or above `--fail-on`. A fact about the code. | Fix or acknowledge the findings. |
| `2` | Usage or configuration error, or `websec doctor` found an incompatible scanner. Nothing was scanned. | Fix the invocation or the toolchain. |
| `3` | Requested checks did not complete (`--require-complete`, or `--fail-on` with an execution gap), or `--require-analyzed` found no analyzable source. | The result is **not** a pass. Read `coverage.gaps` in `coverage.json`. |

**Both failing and incomplete.** A run with findings at or above `--fail-on` **and** an execution
gap exits `1`, and prints both facts on stderr: the finding is definite, and the count is a floor,
not a total. The ledger records the exact combination so nothing is lost by the collapse.

**The verdict is evidence, not only an exit code.** `findings-ledger.json` carries a `gate` object
written before any artifact, so the artifact and the exit code cannot disagree:

| `gate.verdict` | `gate.failure_kind` | Exit |
|---|---|---|
| `fail` | `findings` or `findings+incomplete` | `1` |
| `incomplete` | `incomplete` | `3` |
| `no-analyzable-source` | `no-analyzable-source` | `3` |
| `pass` | `null` | `0` |
| `not-evaluated` (no `--fail-on`) | `null` | `0` |

The same object records `threshold`, `count_at_or_above`, `require_complete`, `require_analyzed`,
`new_only` (baseline mode), `diff_scoped`, `network_findings_excluded`, and an `enforcement` note:
a client-side gate is advisory unless it runs as a required status check.

> [!IMPORTANT]
> **Changed in 0.17.0.** Exit `2` used to mean *incomplete execution* as well as usage errors, and
> an incomplete run short-circuited the gate so a real CRITICAL could be reported as `2`. Incomplete
> is now `3` and is evaluated after the findings count. A CI job that tested for `2` to detect an
> incomplete run should test for `3`, or read `coverage.execution_complete`, which is unchanged.

**Without a gate.** If you pass neither `--fail-on` nor `--require-complete`, an incomplete run
still exits `0`. It does not advance the `latest` pointer, and `coverage.json` records the gap.

Other commands have their own codes, listed in each section. Two current exceptions to the
contract are worth knowing:

- A `run`, `recon`, `init`, `doctor` or `emit-context` target that is not a directory exits **`1`**
  (the error is raised through `sys.exit(message)`), not `2`. Validate the path before relying on
  `1` meaning "findings".
- `dynamic` and `calibrate` report several argument errors the same way, also as exit `1`.

## Environment variables

Every variable the CLI, hooks, MCP server and update check read. None is required for a plain
`websec run`.

| Variable | Read by | Meaning |
|---|---|---|
| `WEBSEC_ACTOR` | `run` | Fallback for `--actor`. Stored under `attribution.declared` and labelled self-asserted. |
| `WEBSEC_AGENT_MODEL`, `WEBSEC_AGENT_HARNESS`, `WEBSEC_AGENT_SESSION` | `run` | Optional agent labels stored under `attribution.declared.agent`. Self-asserted, never verified. |
| `WEBSEC_MCP_TOKEN` | `mcp --http` | Required bearer token. Must be non-empty visible ASCII (no spaces or control characters). Startup is refused without it. |
| `WEBSEC_UPDATE_HOME` | `update-check`, `doctor`, MCP `websec_check_updates` | Directory for the release-metadata cache (`release.json`). Must be absolute; a path with a `.local` component is refused. Default: `~/.cache/websec-validator/`. |
| `WEBSEC_ENRICH_DIR` | `intel`, `run --scan` | Threat-intelligence (EPSS/KEV) cache directory. `--cache-dir` takes precedence for `intel` commands. |
| `XDG_CACHE_HOME` | `intel`, `run --scan` | When `WEBSEC_ENRICH_DIR` is unset, the cache is `$XDG_CACHE_HOME/websec`, else `~/.cache/websec`. |
| `WEBSEC_CALIBRATION_HOME` | `run`, `gate`, `dynamic`, `feedback`, `calibrate`, MCP | Directory of the local calibration overlay (`calibration-local.json`, pending feedback candidates, `calibration-synthetic.json`). Default: `~/.cache/websec-validator/`. |
| `WEBSEC_HOOK_FAIL_ON` | git hooks | Pre-push severity threshold: `critical`, `high`, `medium` or `low`. Default `high`. Any other value makes the hook's execution incomplete. |
| `WEBSEC_HOOK_SCAN` | git hooks | `1` runs the static scanners (`--scan`). Default: recon only. |
| `WEBSEC_HOOK_SCANNERS` | git hooks | Comma-separated scanners to require. Needs `WEBSEC_HOOK_SCAN=1`, otherwise the hook's execution is incomplete. |
| `WEBSEC_SKIP_HOOK` | git hooks | `1` skips the git hook for one invocation. The bypass is appended to `$GIT_DIR/websec-guardrail/bypass.jsonl`. The agent hook ignores it on purpose. |
| `WEBSEC_GATE_FAIL_ON` | agent hook | Threshold for the PostToolUse gate. Default `medium`; an unrecognised value falls back to `medium`. |
| `WEBSEC_GATE_MIN_CONFIDENCE` | agent hook | Confidence floor for the PostToolUse gate. Default `low` (no filtering); an unrecognised value means no filtering. |
| `CLAUDE_PROJECT_DIR` | agent hook | Used as the working directory when the hook event carries no `cwd`. |
| `GITHUB_ACTIONS` + `GITHUB_*`, `GITLAB_CI` + `CI_*` / `GITLAB_USER_LOGIN` | `run` | When a recognised runner sets them, `attribution.ci` records repository, commit, run and actor fields and a `corroborate_at` link. Read only. |

Also relevant:

- websec removes every `GIT_*` variable from the environment of its own `git` subprocesses, so a
  stray `GIT_DIR` cannot redirect what it reads.
- Staged probe scripts under `probes/` read their own variables (`TARGET`, `TOKEN_A`, `TOKEN_B`,
  `COOKIE_A`, `APIKEY`, `OBJ_A`, and others). The CLI never reads them; see
  `probes/_lib.py` in a run directory.
- `WEBSEC_INPUT_*` and `WEBSEC_ACTION_PATH` are internal to [`action.yml`](../../action.yml). Set
  the action's inputs instead.

Configuration that lives in files rather than variables is described in
[configuration.md](configuration.md).

## `websec run`

The full pipeline: recon, optional scanners, findings ledger, staged probes and the agent briefing.

```text
websec run <target> [--scan] [--scanners A,B] [--sarif REPORT ...] [--out DIR]
                    [--exclude PATH ...] [--include-fixtures] [--only PATH ...]
                    [--format {briefing,sarif,json}] [--fail-on {critical,high,medium,low}]
                    [--require-complete] [--require-analyzed] [--diff REF] [--baseline LEDGER.json]
                    [--graph GRAPH.json] [--sbom [FMT]] [--verify-secrets]
                    [--network | --network-dry-run] [--fail-on-network]
                    [--actor WHO] [--application-id ID] [--build-id ID]
```

**Positional:** `target`, the repository directory to analyze (required).

**Scope and inputs**

| Option | Default | Description |
|---|---|---|
| `--scan` | off | Also execute the static scanners found on `PATH` (see Network below). |
| `--scanners A,B` | all available | Comma-separated scanners to **require** and run. Needs `--scan`. A selected scanner that is not installed is recorded as unavailable and makes the run incomplete (exit 3 under `--fail-on` or `--require-complete`). Selecting `gitleaks` selects both of its passes. Keys are those shown by `websec doctor`, for example `trivy`, `gitleaks`, `semgrep`, `checkov`, `osv-scanner`, `bandit`, `gosec`, `brakeman`. |
| `--sarif REPORT` | none | Import an existing SARIF 2.1.0 report without running its analyzer. Repeatable, at most 8. Source freshness is recorded as unverified. A malformed or missing report makes the run incomplete. |
| `--exclude PATH` | none | Exclude a path from recon **and** scanners. Repeatable. Matches when the value is a substring of the repo-relative path or an `fnmatch` glob of it, so `--exclude docs` also excludes `src/docsgen/`. Quote globs: `--exclude 'docs/**'`. |
| `--include-fixtures` | off | Treat test, example and fixture code as product code: fixture routes count as attack surface and fixture secrets keep full severity. By default they are split out and demoted to LOW. |
| `--only PATH` | whole tree | Narrow **analysis** to these repo-relative files (repeatable). The tree is still walked, so stack detection, ignore policy and fixture classification are unchanged. A requested path the walker never selected is reported as missed, not clean. |
| `--graph GRAPH.json` | `<target>/graphify-out/graph.json` if present | A graphify graph for blast-radius enrichment. See [configuration.md](configuration.md#graphify-graph-input) for failure behaviour. |
| `--baseline LEDGER.json` | none | A prior `findings-ledger.json`. Findings are classified new, unchanged, changed, reopened or no-longer-observed; only new, changed and reopened findings count toward `--fail-on`. A malformed, missing or oversized (over 16 MiB) baseline makes the run incomplete. |
| `--diff REF` | none | Scope to what changed versus `REF` (three-dot `REF...HEAD`, committed work only). Tags findings `in-changed-file`, writes hunk ranges to `diff-scope.json`, and narrows `--fail-on` to changed files. If the ref cannot be resolved the run continues **unscoped** and is marked incomplete. |

**Output and gating**

| Option | Default | Description |
|---|---|---|
| `--out DIR` | `./websec-out` (current directory) | Output root. Each attempt gets a new directory under `DIR/runs/`. The implicit default must not be a symlink. |
| `--format FMT` | `briefing` | What goes to stdout: `briefing` (human progress), `sarif` (SARIF 2.1.0) or `json` (findings envelope). In `sarif` and `json` modes progress goes to stderr so stdout can be piped. `results.sarif` is always written to the run directory. |
| `--fail-on SEV` | none | Exit 1 if any finding at or above `critical`, `high`, `medium` or `low` remains. Acknowledged findings and (by default) registry-existence findings do not count. |
| `--require-complete` | off | Exit 3 when requested checks cannot complete, even without a severity threshold. |
| `--require-analyzed` | off | Exit 3 when source files are present but none could be analyzed (no analyzer for the language). An empty findings list there means "not checked". |
| `--sbom [FMT]` | off; bare flag = `cyclonedx` | Also write an SBOM via Trivy: `cyclonedx` → `sbom.cdx.json`, `spdx` → `sbom.spdx.json`. If Trivy is not on `PATH` the SBOM is skipped and recorded as an execution gap. |

**Network and third parties**

| Option | Default | Description |
|---|---|---|
| `--verify-secrets` | off | **[network]** Needs `--scan`. Runs TruffleHog with live verification, which sends each candidate credential to its provider's API to test whether it is live. |
| `--network` | off | **[network]** Check whether declared dependencies exist on `registry.npmjs.org` and `pypi.org`. Sends bare package **names** only, never versions, paths or repository identity. Names this repo publishes and scopes bound to a private registry are suppressed offline first. Unresolved names are an execution gap, never "clean". |
| `--network-dry-run` | off | Print the exact names `--network` would send, and send nothing. |
| `--fail-on-network` | off | Let registry-existence findings (`dependency-nonexistent`, `dependency-unpublished-or-removed`) count toward `--fail-on`. Off by default because registry availability would become a dependency of shipping; a 404 is an observation, not a proof, and a 200 is not evidence of safety. |

**Identity and attribution**

| Option | Default | Description |
|---|---|---|
| `--actor WHO` | `$WEBSEC_ACTOR` | Who initiated the run. Stored under `attribution.declared` and labelled as not verified. |
| `--application-id ID` | target path | Stable application identity recorded in `verification_context`, used by `repair-verify`. |
| `--build-id ID` | analyzed input digest | Reviewed build identity recorded in `verification_context`. |

**Network:** none by default. `--scan` runs third-party tools as subprocesses; websec itself sends
nothing, but those tools follow their own network behaviour. websec invokes `semgrep scan --config
auto`, `osv-scanner scan` and `trivy fs` without offline flags, so check each tool's documentation
for what it fetches or transmits. Only `--verify-secrets` and `--network` make websec send data.

**Files written:** a new directory `DIR/runs/<timestamp>-<random>/` containing `FACTS.json`,
`coverage.json`, `findings-ledger.json`, `findings.envelope.json`, `results.sarif`,
`repair-plans.json`, `attack-surface.json`, `CONSTITUTION.md`, `AGENT-BRIEFING.md`, `REPORT.md`,
`manifest.json` (with sha256 digests of the artifacts) and `probes/`; plus `findings.json` with
`--scan` or `--sarif`, `sarif-imports.json` with `--sarif`, `diff-scope.json` with `--diff`, the SBOM
with `--sbom`, and each scanner's native output. `DIR/latest` is replaced atomically **only when
execution completed**; a partial attempt keeps its own directory and leaves `latest` on the previous
completed run. Nothing is ever overwritten. Field-by-field descriptions are in
[outputs.md](outputs.md).

**Exit codes:** see [Exit codes](#exit-codes). Argument conflicts (`--scanners` without `--scan`,
`--verify-secrets` without `--scan`, more than 8 `--sarif`) exit 2.

```bash
websec run ./my-app --scan --fail-on high --require-complete
websec run . --diff main --baseline prior/findings-ledger.json --fail-on medium --format sarif > results.sarif
websec run . --network-dry-run
```

## `websec init`

Scaffold a `.websec-ignore` for this repository from the test, fixture, seed and vendor
directories that actually exist in it, or export its reviewed acknowledgements.

```text
websec init [target] [--dry-run] [--force] [--claimspec PATH]
```

**Positional:** `target`, the repository directory (default `.`).

| Option | Default | Description |
|---|---|---|
| `--dry-run` | off | Print the proposed `.websec-ignore` without writing it. |
| `--force` | off | Replace an existing `.websec-ignore`. Without it an existing file is never overwritten, because it may hold reviewed `fingerprint:` acknowledgements. |
| `--claimspec PATH` | none | Instead of scaffolding, export the reviewed `fingerprint:` acknowledgements already in `.websec-ignore` as a claimspec v1 `ignore` document. `-` writes to stdout. Path and category patterns and acknowledgements without a usable reason or expiry are omitted and reported on stderr, so the export is never mistaken for the whole policy. |

Every proposal is printed with its file count before anything is written. The file grammar is in
[configuration.md](configuration.md#websec-ignore).

**Network:** none. **Files written:** `<target>/.websec-ignore`, or the `--claimspec` file.
**Exit codes:** `0` written, dry run, or exported; `2` when the file exists without `--force` or
cannot be written.

```bash
websec init --dry-run
websec init ./my-app
websec init --claimspec -
```

## `websec doctor`

Show which scanners are installed, their versions, and whether each is compatible with the
invocation websec builds.

```text
websec doctor [target]
```

**Positional:** `target`, an optional repository used to scope scanner relevance to its detected
languages.

`doctor` also prints the engine's provenance (which installation is running) and the offline
release-check advisory. A scanner marked `✗` is too old for websec's argv; one marked `?` has an
unknown version.

**Network:** none (the release check reads the local cache only). **Files written:** none.
**Exit codes:** `0`; `2` when an installed scanner is incompatible, so a CI preflight can stop
before trusting a scan that would silently produce nothing.

```bash
websec doctor
websec doctor ./my-app
```

## `websec update-check`

Advisory release metadata. Offline unless you pass `--online`.

```text
websec update-check [--online] [--format {text,json}]
```

| Option | Default | Description |
|---|---|---|
| `--online` | off | **[network]** Fetch `https://pypi.org/simple/websec-validator/` metadata to find the newest stable, non-yanked release. Installs nothing. Ask the human before using it. |
| `--format` | `text` | `text` or `json`. |

Without `--online` it reads the cached result of the last online check and labels it `cached`
(under 24 hours old) or `stale`. The cache holds only `latest_version` and `checked_at`. The
approval rule it prints is the one AI agents must follow: ask before checking, and treat an upgrade
as a separate decision. See [mcp.md](mcp.md#update-check-approval-rule).

**Files written:** `release.json` in `$WEBSEC_UPDATE_HOME` or `~/.cache/websec-validator/`, after an
online check only. **Exit codes:** always `0`; release advice is never a gate.

```bash
websec update-check
websec update-check --online --format json
```

## `websec demo`

Run a real pass against a bundled sample application so you can see the output before pointing
the tool at your own code.

```text
websec demo
```

No options. The sample is materialized in a temporary directory that is deleted afterwards; the
current project is not touched. **Network:** none. **Exit codes:** `0`; `1` if the sample
produced no findings, which indicates a detector regression rather than a clean result.

```bash
websec demo
```

## `websec explain`

What an attack class means, how to confirm it, and what its calibrated number is worth. Offline.

```text
websec explain [term] [--list] [--format {text,json}]
```

**Positional:** `term`, an attack class (for example `bola`) or a CWE id (for example `CWE-918`).

| Option | Default | Description |
|---|---|---|
| `--list` | off | List every attack class this build cites. |
| `--format` | `text` | `text` or `json`. |

**Exit codes:** `0`; `2` for an unknown term, or when neither `term` nor `--list` is given.

```bash
websec explain bola
websec explain CWE-918 --format json
websec explain --list
```

## `websec capabilities`

Print the offline matrix of named security profiles, their checks and limitations, plus the
per-class triage disposition policy, as JSON.

```text
websec capabilities
```

No options. Reads no target. **Exit codes:** `0`. Profile details are in
[languages.md](languages.md).

```bash
websec capabilities
```

## `websec gate`

A fast, scoped pass/fail on the files you just changed, for use inside an agent loop. Writes no
artifacts and never advances a baseline or the `latest` pointer.

```text
websec gate [target] [--only PATH ...] [--fail-on {critical,high,medium,low}]
                     [--min-confidence {low,medium,high}] [--exclude PATH ...]
                     [--fail-on-missed] [--format {text,json}]
```

**Positional:** `target`, the repository (default `.`).

| Option | Default | Description |
|---|---|---|
| `--only PATH` | working-tree changes | Analyze these files instead of the changed set (repeatable). |
| `--fail-on SEV` | `medium` | Block at or above this severity. The default is medium because command injection and SSRF in agent-written code are often rated MEDIUM. |
| `--min-confidence LEVEL` | `low` | Ignore findings below this calibrated confidence. `low` means no filtering. A finding with an unrecognised confidence is never filtered out. |
| `--exclude PATH` | none | Exclude a path or glob (repeatable), with the same matching as `run`. |
| `--fail-on-missed` | off | Exit 1 when a requested path was never analyzed (unsupported language, excluded or absent). Off by default in the loop; turn it on at merge time. |
| `--format` | `text` | `text` is what a harness feeds back to the model; `json` for tooling. |

**Default scope** is the working tree: tracked modifications plus untracked files with an
analyzable suffix, deletions excluded, at most 200 files (more is recorded as an execution gap).
It is not `base...HEAD`, which would miss uncommitted agent edits. `.websec-ignore` applies exactly
as in `run`. A finding attributed to a *different* existing repository file is reported under
`outside_scope` and does not block; one that names no file still blocks.

> [!NOTE]
> Outside a git repository, with no `--only`, there is no changed-file set: `gate` prints a JSON
> pass with `scope_source: "not-a-git-repository"` and exits 0. Pass `--only` explicitly there.

A scoped pass is a fast retry signal, not a review. **Network:** none. **Files written:** none.

**Exit codes:** `0` pass (or nothing changed); `1` blocking findings, or missed paths with
`--fail-on-missed`; `2` target is not a directory; `3` the changed-file set could not be determined
(`git status` failed) or analysis was incomplete and nothing blocked.

```bash
websec gate
websec gate --only src/api/users.py --format json
websec gate --fail-on high --fail-on-missed
```

## `websec hooks`

Install, remove or inspect the git guardrail hooks or the agent-loop hook.

```text
websec hooks {install,uninstall,status} [--pre-push] [--agent] [--path DIR]
```

**Positional:** `action`, one of `install`, `uninstall`, `status`.

| Option | Default | Description |
|---|---|---|
| `--pre-push` | off | Install a blocking pre-push gate instead of the advisory post-commit hook. |
| `--agent` | off | Act on the agent-loop hook instead of a git hook: a `PostToolUse` entry (matcher `Write\|Edit\|MultiEdit`, command `websec-agent-hook`, 30 s timeout) in `.claude/settings.json`. `--pre-push` is ignored with `--agent`. |
| `--path DIR` | current directory | Repository directory. |

**Git hooks.** The hook directory is resolved through `git rev-parse --git-path hooks`, so worktrees,
`core.hooksPath` and Husky's durable `.husky/<hook>` script are respected. Existing shell hooks are
preserved (websec inserts a marked section); non-shell hooks are refused. The hook launches the
installed package with an isolated interpreter. Both hooks run with `--require-complete`; the
pre-push hook adds `--fail-on` (`WEBSEC_HOOK_FAIL_ON`, default `high`) and a baseline accepted by the
previous successful gate under the same policy. Advisory runs and failed gates never advance that
accepted baseline. Artifacts live in `$GIT_DIR/websec-guardrail/` (the five most recent runs are
kept). The hooks inspect the working tree, not the pushed objects. See the git-hook variables in
[Environment variables](#environment-variables).

**Agent hook.** Runs the same evaluation as `websec gate` in-process on each file the agent writes,
with an analyzable suffix, and blocks the loop (hook exit 2, finding text on stderr) on a finding at
or above `WEBSEC_GATE_FAIL_ON` (default `medium`). If the gate cannot run it **fails open, loudly**:
exit 0 with a stderr warning that the edit was not checked. It does not honour `WEBSEC_SKIP_HOOK`,
because the agent can set environment variables. Installing is an idempotent JSON merge that leaves
your other hooks alone; an unparseable `settings.json` is refused rather than overwritten.

> [!WARNING]
> Both kinds of hook are developer ergonomics, not a control. They can be skipped with
> `git push --no-verify`, an uninstalled hook, or an edited settings file, and websec cannot
> observe those bypasses. For enforcement, run `websec run --fail-on ...` as a required CI status
> check.

**Exit codes:** `0`; `2` when there is no git repository, the existing hook is not a shell script,
or `settings.json` is invalid. `status --agent` prints JSON.

```bash
websec hooks install
websec hooks install --pre-push
websec hooks install --agent
websec hooks status --agent
```

## `websec install`

Teach an AI coding agent to use websec by writing a marked instruction block or a dedicated skill
file where that host reads its standing instructions.

```text
websec install {claude,cursor,codex,gemini,aider,generic,status} [--user] [--project-dir DIR] [--uninstall]
```

**Positional:** `host`, an agent host or `status` (list what is installed).

| Option | Default | Description |
|---|---|---|
| `--user` | off | Install into your home directory (all repositories) instead of the project. |
| `--project-dir DIR` | current directory | Project directory to install into. |
| `--uninstall` | off | Remove the websec block or skill instead. |

| Host | Style | Project path | `--user` path (under `~`) |
|---|---|---|---|
| `claude` | skill file | `.claude/skills/security-pass/SKILL.md` | `.claude/skills/security-pass/SKILL.md` |
| `cursor` | skill file | `.cursor/rules/websec-validator.mdc` | `.cursor/rules/websec-validator.mdc` |
| `codex` | marked block | `AGENTS.md` | `.codex/AGENTS.md` |
| `gemini` | marked block | `GEMINI.md` | `.gemini/GEMINI.md` |
| `aider` | marked block | `CONVENTIONS.md` | `.config/aider/CONVENTIONS.md` |
| `generic` | marked block | `AGENTS.md` | `AGENTS.md` |

A skill file is owned by websec and deleted on uninstall. A block is the region between
`<!-- websec-validator:start -->` and `<!-- websec-validator:end -->` in a file you also edit; only
that region is replaced or removed; a file with duplicated or broken markers is refused rather than
guessed at. Destinations must resolve inside the project or home directory. **Exit codes:** `0`;
`2` on an invalid host, an unsafe destination, or ambiguous markers.

```bash
websec install claude
websec install codex --user
websec install status
```

## `websec emit-context`

Print recon as a Claude Code `SessionStart` `additionalContext` JSON envelope, so an agent session
starts with the attack-surface map already in context. Recon only; no scanners.

```text
websec emit-context <target> [--markdown]
```

**Positional:** `target`, the repository directory (required).

| Option | Default | Description |
|---|---|---|
| `--markdown` | off | Print the raw `## SECURITY CONTEXT` block instead of the JSON envelope, for other harnesses. |

**Network:** none. **Files written:** none. **Exit codes:** `0`. Wiring it into a session hook is
covered in [ai-agents.md](../guides/ai-agents.md).

```bash
websec emit-context .
websec emit-context ./my-app --markdown
```

## `websec mcp`

Serve websec's recon as typed Model Context Protocol tools over stdio (default) or authenticated
loopback HTTP.

```text
websec mcp [--http] [--host HOST] [--port PORT] [--allow-root PATH ...]
```

| Option | Default | Description |
|---|---|---|
| `--http` | off (stdio) | Serve JSON-RPC over HTTP POST on a loopback address. Requires `WEBSEC_MCP_TOKEN`. |
| `--host HOST` | `127.0.0.1` | Bind address. Must be a loopback IP or `localhost`; anything else is refused. |
| `--port PORT` | `8733` | HTTP port. |
| `--allow-root PATH` | none | A directory the HTTP tools may scan (repeatable). **At least one is required with `--http`**; the server refuses to start without it. |

The `--allow-root` help text says the default is the startup directory; the code requires an
explicit root. Tools, limits, and client registration are in [mcp.md](mcp.md). **Network:** the
server listens on loopback only; the `websec_check_updates` tool contacts PyPI only when called
with `online: true`.

**Exit codes:** stdio returns `0` when stdin closes; `--http` exits `2` on a refused startup
(missing token, non-loopback host, missing or invalid root, port in use).

```bash
websec mcp
websec mcp --http --allow-root /absolute/path/to/project
```

## `websec attest`

Project an existing run into an audit-evidence table, gaps first. It computes nothing and renders
no verdict, score or badge.

```text
websec attest [--run DIR] [--out DIR] [--repo DIR] [--format {text,json,in-toto}]
```

| Option | Default | Description |
|---|---|---|
| `--run DIR` | see below | The run directory to project. |
| `--out DIR` | `./websec-out` | Output root to search when `--run` is not given. |
| `--repo DIR` | `.` | Repository whose `$GIT_DIR/websec-guardrail/bypass.jsonl` supplies honoured `WEBSEC_SKIP_HOOK` bypass records. |
| `--format` | `text` | `text`, `json`, or `in-toto` (an **unsigned** in-toto Statement for you to sign with your own key; a websec-signed one would attest only that websec ran). |

> [!NOTE]
> Without `--run`, `attest` looks for `<out>/runs/latest`. `websec run` publishes `latest` at
> `<out>/latest`, so in practice `attest` falls back to the lexically last directory under
> `<out>/runs/`, which can be a partial attempt. Pass `--run websec-out/latest` to project the
> latest **completed** run.

The bypass record cannot see `--no-verify`, an uninstalled hook or a deleted hook; an empty list is
not evidence that no bypass occurred. **Network:** none. **Exit codes:** `0` whenever a run is
found (it reports, it does not judge); `2` when no run directory or no `findings-ledger.json` is
found.

```bash
websec attest --run websec-out/latest
websec attest --run websec-out/latest --format in-toto > statement.json
```

## `websec feedback`

Record, offline, that a detector is wrong. Metadata-only by default; nothing is sent.

```text
websec feedback --verdict {false-positive,severity-wrong,false-negative} --reason TEXT
                [--fingerprint FP] [--expected-severity {INFO,LOW,MEDIUM,HIGH,CRITICAL}]
                [--attack-class CLASS] [--file-extension EXT] [--ledger PATH]
                [--include-snippet [--yes]] [--out DIR] [--format {text,json}]
```

| Option | Default | Description |
|---|---|---|
| `--verdict` | required | `false-positive` (not a real issue), `severity-wrong` (real but misrated) or `false-negative` (a missed issue). |
| `--reason TEXT` | required | Why the detector is wrong, at most 1000 characters. |
| `--fingerprint FP` | none | The finding's fingerprint from the ledger. Required for `false-positive` and `severity-wrong`; rejected for `false-negative`. |
| `--expected-severity SEV` | none | Required with `severity-wrong`. |
| `--attack-class CLASS` | none | What was missed. Required with `false-negative`. |
| `--file-extension EXT` | none | Optional language hint for a false negative; only the suffix is kept. |
| `--ledger PATH` | `<out>/latest/findings-ledger.json` | The ledger to look the fingerprint up in. |
| `--include-snippet` | off | Also include title, route, file and evidence. Shows the record and asks before writing; fails closed when stdin is not a terminal. |
| `--yes` | off | Skip the `--include-snippet` prompt (for scripts). |
| `--out DIR` | `websec-out` | Output directory for `feedback.jsonl`. |
| `--format` | `text` | `text` or `json`. |

A `false-positive` verdict also queues a pending calibration candidate that changes no probability
until a human runs `websec calibrate --accept`. Feedback never suppresses a finding; use a
`fingerprint:` line in `.websec-ignore` for that. The command prints a prefilled issue link; opening
it is your choice. **Files written:** `<out>/feedback.jsonl`, and the candidate in the local
calibration overlay. **Exit codes:** `0`; `2` on invalid input, missing ledger or a declined prompt.

```bash
websec feedback --fingerprint b9c7f23e49bdab85 --verdict false-positive --reason "behind an nginx auth_request"
websec feedback --verdict false-negative --attack-class ssrf --file-extension .py --reason "requests.get(url) from a query param"
```

## `websec repair-verify`

Validate operator-supplied repair evidence offline. It never executes tests or any command from
the artifacts.

```text
websec repair-verify --plan PLAN --record RECORD --rerun LEDGER --evidence-root DIR
                     [--plan-id ID] [--out RESULT.json]
```

| Option | Default | Description |
|---|---|---|
| `--plan` | required | A repair plan JSON, or a run's `repair-plans.json`. |
| `--plan-id ID` | none | Which plan to use when the file contains more than one. |
| `--record` | required | The operator-supplied verification record JSON. |
| `--rerun` | required | The findings ledger from the fixed build. |
| `--evidence-root` | required | Directory containing the test reports the record references. |
| `--out RESULT.json` | none | Also persist the result. Refuses to overwrite an existing file. |

The result always carries `tests_executed_by_websec: false`. Field requirements are in the
[evidence examples](../security-review/examples/README.md). **Exit codes:** `0` accepted; `2`
rejected, invalid input, or `--out` already exists.

```bash
websec repair-verify --plan websec-out/latest/repair-plans.json --plan-id <plan-id> --record record.json --rerun fixed/findings-ledger.json --evidence-root ./evidence --out verification.json
```

## `websec intel`

Explicit public threat-feed refresh (EPSS and CISA KEV) and offline reassessment of known CVEs.

```text
websec intel {refresh,status,reassess} [--cache-dir DIR] [--out FILE]
```

Shared options for all three actions:

| Option | Default | Description |
|---|---|---|
| `--cache-dir DIR` | `$WEBSEC_ENRICH_DIR`, else `$XDG_CACHE_HOME/websec`, else `~/.cache/websec` | Local snapshot directory. |
| `--out FILE` | stdout only | Also write the JSON result to a new file. Existing files are refused. |

### `websec intel refresh`

**[network]** Download the EPSS scores and the CISA KEV catalog, validate them, and publish a new
local snapshot atomically. A feed older than the current snapshot is rejected, and a failed refresh
keeps the last valid snapshot. Only the public feeds are fetched; no project data is uploaded.
**Exit codes:** `0` on success, `2` otherwise.

```bash
websec intel refresh
```

### `websec intel status`

Report the local snapshot's availability, feed dates, age and freshness (`fresh` within 7 days,
then `stale`) without any network access. **Exit codes:** `0`.

```bash
websec intel status --out intel-status.json
```

### `websec intel reassess`

Re-evaluate the known CVEs in an existing ledger against the local snapshot, offline. The input
ledger is never overwritten.

| Option | Default | Description |
|---|---|---|
| `--ledger` | required | The `findings-ledger.json` to reassess. |

Finding identities and source evidence are preserved. An acknowledged CVE that becomes
known-exploited or crosses EPSS 0.5 is reopened for review. A detector change since the ledger was
written is reported as `detector-changed-rescan-required`. This does **not** discover new CVEs;
that needs a fresh `run --scan`. **Exit codes:** `0` when the snapshot is fresh and no finding was
blocked; `2` when intelligence is stale or unavailable, a finding's provenance blocks the update, or
the input is invalid.

```bash
websec intel reassess --ledger websec-out/latest/findings-ledger.json --out reassessment.json
```

## `websec research`

Evaluate data-only detector proposals against an allowlist of shipped detectors, offline. Source
snippets become disposable text fixtures and are never executed.

```text
websec research {example,catalog,evaluate} [--out FILE]
```

All three actions accept `--out FILE`, which writes the JSON result to a new file and refuses
existing files.

### `websec research example`

Print a current, detector-bound synthetic proposal to start from. **Exit codes:** `0`.

```bash
websec research example --out proposal.json
```

### `websec research catalog`

List the shipped regression suites without evaluating them. **Exit codes:** `0`.

```bash
websec research catalog
```

### `websec research evaluate`

| Option | Default | Description |
|---|---|---|
| `--proposal FILE` | one of `--proposal` / `--suite` is required | A proposal object, or a bundle containing `proposal` and `cases`. |
| `--suite NAME` | | Evaluate every proposal in a shipped suite. Current choice: `control-scope`. |
| `--cases FILE` | none | Separate synthetic cases when the proposal is not bundled. Not allowed with `--suite`. |

Passing means **eligible for human review**, not automatic promotion; the authored holdout is
regression evidence, not an independent benchmark. **Exit codes:** `0` when promotion-eligible,
`2` otherwise or on invalid input.

```bash
websec research evaluate --suite control-scope --out suite-evaluation.json
websec research evaluate --proposal proposal.json --out evaluation.json
```

## `websec dynamic`

Live probes against a **running test instance you own**. Never point it at production.

```text
websec dynamic --unauth --target URL [--probe-writes] [--facts FACTS.json] [--out DIR]
websec dynamic --config CONFIG.json [--facts FACTS.json] [--out DIR]
```

| Option | Default | Description |
|---|---|---|
| `--unauth` | off | **[network]** Unauthenticated mode, needs `--target`. GETs each data-read endpoint with no credentials, then presents a deliberately invalid JWT to routes that were gated without auth (forged-token probe). Side-effecting paths and paths with unfilled `{params}` are skipped; redirects are never followed. |
| `--target URL` | none | Base URL of the test instance, for `--unauth`. |
| `--probe-writes` | off | **[network]** With `--unauth`: also send `POST`/`PUT`/`PATCH`/`DELETE` with an empty JSON body and dummy ids, both unauthenticated and with the forged token, to check write-verb auth enforcement. Refused unless `--target` is `localhost`, `127.0.0.1`, `::1` or `0.0.0.0`. Empty bodies reduce impact but cannot guarantee a handler will not mutate. |
| `--config CONFIG.json` | none | **[network]** Authenticated cross-tenant BOLA: log in two roles (one `POST` to the login path each), then test with `GET` requests only whether each role can read the other tenant's data. The target is not restricted to localhost. See [configuration.md](configuration.md#dynamic-configjson). |
| `--facts FACTS.json` | `<out>/latest/FACTS.json` | Recon from a prior `websec run`. |
| `--out DIR` | `./websec-out` | Output root. |

If both `--unauth` and `--config` are given, `--unauth` runs. Status codes are observations, not
proof: candidate results are labelled `inconclusive` unless the configured controls confirm them,
and a run where nothing enforced auth is flagged as a suspected fail-open test environment.

**Files written:** a new run directory with `dynamic-unauth-findings.json` or
`dynamic-findings.json`, plus `findings-ledger.json`, `CONSTITUTION.md`, `REPORT.md`, `FACTS.json`
and `coverage.json`. Confirmed results are folded into the local calibration overlay.

**Exit codes:** `0`; `1` if the merged ledger contains a CRITICAL finding; `3` if the source
`FACTS.json` records incomplete execution; `2` if the output run cannot be reserved. Missing
`FACTS.json`, a missing config, `--unauth` without `--target`, or `--probe-writes` against a
non-localhost target exit `1` with an error message.

```bash
websec dynamic --unauth --target http://127.0.0.1:3000
websec dynamic --unauth --target http://localhost:3000 --probe-writes
websec dynamic --config dynamic-config.json
```

## Development commands

`recon`, `proof` and `calibrate` are for working on websec itself or for narrow uses. They are
hidden from `websec --help` but work when invoked by name.

## `websec recon`

Recon only: write `FACTS.json`, with no ledger, briefing or probes. A subset of `run`.

```text
websec recon <target> [--out DIR]
```

| Option | Default | Description |
|---|---|---|
| `--out DIR` | `./websec-out` | Directory for `FACTS.json`. Unlike `run`, the file is written directly into `DIR`, not into a new run directory. |

**Exit codes:** `0`; `2` if the output cannot be written.

```bash
websec recon ./my-app --out recon-out
```

## `websec proof`

**[network]** Clone the vulnerable-app corpus and score whether recon surfaces each app's
documented attack surface. A proxy, not vulnerability precision or agent-lift evidence.

```text
websec proof [--corpus FILE] [--workdir DIR]
```

| Option | Default | Description |
|---|---|---|
| `--corpus FILE` | bundled `corpus.json` | Corpus definition. |
| `--workdir DIR` | `~/.cache/websec-corpus` | Where corpus applications are cloned. |

**Exit codes:** `0` all evaluated checks passed; `1` some failed; `2` an application was
incomplete or unavailable, a check was unknown, or nothing was evaluated.

```bash
websec proof
```

## `websec calibrate`

Fit, inspect and export the confidence calibration that gives each finding its `P(real)`.

```text
websec calibrate [--corpus FILE] [--workdir DIR] [--out FILE]
websec calibrate --review | --accept ID --reason TEXT | --reject ID   [--format {text,json}]
websec calibrate --ingest FILE
websec calibrate --ingest-dast REPORT.json --ledger findings-ledger.json
websec calibrate --synthetic [--pairs PAIRS.json] [--format {text,json}]
websec calibrate --claimspec PATH
```

| Option | Default | Description |
|---|---|---|
| `--corpus FILE` | bundled | Corpus JSON with `truth` blocks, for a fit. |
| `--workdir DIR` | `~/.cache/websec-corpus` | Where corpus applications are cloned. **[network]** on first run. |
| `--out FILE` | the bundled `calibration.json` next to the package | Where a fit writes its table. |
| `--ingest FILE` | none | Fold a hand-labeled findings JSON (`attack_class`, `confidence`, `is_real`) into the local overlay. Only evidence-backed rows (`evidence_verified`, `sample_id`, `provenance`) become measured samples. |
| `--ingest-dast REPORT.json` | none | Match a ZAP or Nuclei report against a ledger's DAST-predictable findings and fold confirmations and explicit refutations into the overlay. Needs `--ledger`. |
| `--ledger FILE` | none | The ledger `--ingest-dast` matches against. |
| `--synthetic` | off | Score the authored paired fixtures into a separate `calibration-synthetic.json`. Never merged into `P(real)`. |
| `--pairs PAIRS.json` | bundled `pairs.json` | Pair manifest for `--synthetic`. |
| `--review` | off | List pending candidates queued by `websec feedback --verdict false-positive`. |
| `--accept ID` | none | Promote one candidate into a measured `is_real=False` sample. Requires `--reason`; refuses a candidate reported against a different detector build. Permanent for every project on this machine. |
| `--reject ID` | none | Discard one pending candidate. |
| `--reason TEXT` | none | Why the finding is wrong. Required with `--accept`. |
| `--claimspec PATH` | none | Export the calibration the runtime uses (shipped table plus local overlay) as a claimspec v1 `calibration` document. `-` writes to stdout. |
| `--format` | `text` | Output format for `--review`, `--accept`, `--reject` and `--synthetic`. |

Only one mode runs per invocation, checked in this order: review/accept/reject, `--synthetic`,
`--claimspec`, `--ingest-dast`, `--ingest`, then a corpus fit. The overlay lives in
`$WEBSEC_CALIBRATION_HOME`. **Exit codes:** `0`; `2` when nothing could be measured, exported or
reviewed; `1` when a fit produced no labeled findings or an input file is missing.

```bash
websec calibrate --review
websec calibrate --accept <candidate-id> --reason "route is behind an auth proxy"
websec calibrate --claimspec -
```

## See also

- [configuration.md](configuration.md): `.websec-ignore`, `dynamic-config.json`, caches and tokens
- [mcp.md](mcp.md): the MCP server, its tools and client registration
- [outputs.md](outputs.md): every artifact a run writes
- [triage-and-suppression.md](../guides/triage-and-suppression.md)
- [github-actions.md](../guides/ci/github-actions.md) and [other-ci.md](../guides/ci/other-ci.md)
- [pre-commit-and-git-hooks.md](../guides/ci/pre-commit-and-git-hooks.md)
- [troubleshooting.md](../troubleshooting.md)

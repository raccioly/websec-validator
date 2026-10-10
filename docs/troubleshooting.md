# Troubleshooting

This page lists known problems as symptom, cause and fix. It is for anyone whose install, run, CI
gate, hook or agent integration is not behaving as expected. When you finish, you should either have
a fix or know exactly what to include in a bug or false-positive report.

Two habits resolve most problems faster:

- Run `websec doctor .` first. It shows which engine is running, where it came from, and which
  optional scanners are present and compatible.
- Read `coverage.json` in the run directory. A run that "looks clean" is often one that could not
  read something, and `coverage.json` says what and why.

## Installation

### `websec: command not found`

**Cause.** The install succeeded, but the directory where pipx (or uv) puts commands is not on your
`PATH`, or you installed into a virtualenv that is not activated.

**Fix.**

```bash
pipx ensurepath        # then open a new shell
pipx list              # confirm websec-validator is listed with its commands
```

For a pip install, activate the virtualenv you installed into. For uv, `uv tool dir --bin` prints the
command directory and `uv tool update-shell` adds it to `PATH`.

### Installation fails because Python is too old

**Symptom.** pip reports that no matching distribution was found, or that the available versions
require a different Python.

**Cause.** websec needs Python 3.11 or newer. On stock macOS, `python3` is often 3.9.

**Fix.** Install with an interpreter that is 3.11 or newer:

```bash
python3 --version
pipx install --python python3.12 websec-validator   # point pipx at any 3.11+ interpreter
```

Get a newer Python from Homebrew, pyenv or python.org if you do not have one. See
[Installation](installation.md#requirements).

### `websec --version` or `doctor` shows an old or unexpected engine

**Causes.**

- More than one `websec` is on your `PATH` (for example a pipx install and a pyenv or venv install),
  and the shell picks the older one first.
- An editable install was updated with `git pull`. The code changed, but the package metadata that
  `--version` reads was written at install time.
- pipx was installed from a local wheel file. `pipx upgrade` then re-resolves that same file and
  reports "already at latest" while the engine stays behind.

**Fix.**

```bash
which -a websec        # every websec on PATH, in resolution order
websec doctor          # prints engine path, source (package index, editable, local file) and Python
```

`doctor` also warns when the code being imported is not inside the installed distribution, in which
case the printed version describes the install, not the code. To get back to a clean PyPI engine:

```bash
pipx uninstall websec-validator
pipx install websec-validator
```

For an editable clone, re-run `pipx install --force --editable .` after pulling.

## Running a scan

### Routes come from `regex-fallback` even though Noir is installed

**Symptom.** The run prints `routes: N endpoints via regex-fallback (install OWASP Noir for full
coverage: brew install noir)` although you installed Noir.

**Cause.** That message means websec did not find an executable named `noir` on the `PATH` of the
websec process. A shell where `noir` works can still differ from the environment of your CI job,
agent or hook.

If the line reads `via noir (0 routes) → regex-fallback backstop`, Noir did run but found nothing,
and the fallback supplemented it.

**Fix.**

```bash
command -v noir        # is it on PATH for this shell (and for your CI job / agent)?
websec doctor .        # the "route engine" section shows what websec itself finds
```

### `⚠ OWASP Noir failed: … — routes came from the regex fallback`

**Cause.** Noir is installed but did not produce usable output. websec runs
`noir scan <target> -f json -o <tmpfile> --exclude-path … --no-log --no-color` with a 300-second
timeout; a non-zero exit with no output, a timeout, invalid JSON or a launch error is a failure.
Since 0.22.0 this is reported instead of looking like an absent Noir: the run prints the reason,
`FACTS.json` → `routes.noir` records `{"state": "failed", "reason": …}`, and `coverage.json` gets a
`route_engine` gap. The gap is a scope limit (`execution: false`), so it does not make the run
incomplete or change the exit code, but the route inventory is the narrower regex result.

**Fix.**

```bash
websec doctor .        # route engine: ✓ version, ? no version printed, ✗ crashed or timed out
noir --version
noir scan . -f json -o /tmp/noir-check.json   # does this build accept websec's invocation?
```

If the manual command fails, upgrade or reinstall Noir. The bundled Docker image pins a Noir
version in the [`Dockerfile`](../Dockerfile) that its CI checks.

### Scanners are listed but never run

**Symptom.** The output says `scanners available: Trivy, Gitleaks, … (add --scan to execute them)`,
and `findings.json` is missing or empty.

**Cause.** Static scanners run only with `--scan`. This is the same inside the Docker image, even
though it bundles scanners.

**Fix.** `websec run . --scan`. Note that `--scanners` and `--verify-secrets` each require `--scan`;
without it websec prints `error: --scanners requires --scan` (or the `--verify-secrets` equivalent)
and exits `2`.

### A specific scanner never runs

| Scanner | Why |
|---|---|
| Bandit, gosec, Brakeman | Selected only when the stack detector finds Python, Go or Ruby respectively. Check the `stack:` line. |
| Brakeman, on a Ruby target | Also needs an `app/` directory at the scan root, Brakeman's own Rails precondition. Without one it is listed by `websec doctor .` under "not applicable to this target" and is not run. Scan the Rails application's root directory. |
| TruffleHog | Never runs implicitly. It needs `--scan --verify-secrets` because it sends candidate credentials to provider APIs. |
| Prowler | Detected and reported only. The current registry entry has no invocation, so websec does not execute it. |
| OpenGrep | websec looks for an executable named `semgrep`. An `opengrep` binary is not detected under that name. |

### A scanner runs but contributes nothing, or `doctor` shows `✗`

**Cause.** The installed version is older than the command line websec builds for it. An
incompatible scanner can run, fail in its own way, and look exactly like a clean scan.

**Fix.** Run `websec doctor .`. A `✗` row names the installed version and the minimum websec needs;
`?` means the version could not be read. Upgrade that tool. Minimums are in `REGISTRY` in
[`src/websec_validator/scanners.py`](../src/websec_validator/scanners.py), and `websec doctor` exits
`2` while any relevant installed scanner is incompatible.

### `error: unknown command '…' (and no such path)`

**Cause.** `websec <path>` is shorthand for `websec run <path>`, but only when the path exists. A
mistyped subcommand that is also not an existing path is rejected (exit `2`) with a near-match
suggestion rather than being scanned as a directory.

**Fix.** Check the spelling against `websec --help`, or pass an existing path.

### `error: target is not a directory: …` (exit 2)

**Cause.** The target path does not exist or is a file.

**Fix.** Pass the repository directory. Since 0.22.0 this is a usage error (exit `2`); earlier
releases exited `1`, the same code as findings.

### `⚠ PARTIAL SCAN — hit the …-file cap`

**Cause.** The repository has more code files than the walker's per-run cap (`MAX_FILES` in
[`src/websec_validator/extractors/base.py`](../src/websec_validator/extractors/base.py)), so recon
may be incomplete.

**Fix.** Exclude generated or vendored trees with `--exclude '<glob>'`, or scan a subdirectory (for
example one service of a monorepo) as the target. See the [monorepo guide](guides/monorepo.md).

## Coverage and results

### Exit `3`: requested checks did not complete

**Symptom.** `✗ requested security checks did not complete; partial artifacts saved (exit 3 —
toolchain/coverage, NOT a finding).`

**Cause.** You asked for completeness (`--require-complete`, or `--fail-on`) and something that was
requested did not run to completion. The run directory is kept, but `latest` is not advanced.

**Fix.** Open `coverage.json` in the run directory the console printed and read `gaps`. Common
entries:

| Gap | Meaning | Fix |
|---|---|---|
| `scanner`: `<name>: unavailable` | You selected it with `--scanners` but it is not installed | Install it, or drop it from `--scanners` |
| Scanner timeout, error, invalid report, or `scanner_rules` partial | The tool ran but did not produce a usable result | Run the tool by hand; check `websec doctor` for version problems |
| Read loss, oversized files, byte budget | Some source could not be read within limits | Narrow the target or exclude generated files |
| `graph`, `baseline`, SARIF import | An explicitly supplied `--graph`, `--baseline` or `--sarif` input was missing, malformed, unreadable or over a cap. A graph's own cap is 64 MiB, and the gap names the reason (`not found`, `oversized`, `excluded or out of scope`, `invalid`) | Fix or remove the input |
| `dependency-existence` | `--network` could not resolve some names | Retry; UNKNOWN is never treated as clean |

A run can be **both** gate-failing and incomplete. It then exits `1`, prints both facts, and records
`gate.failure_kind` as `findings+incomplete`; the finding count is a floor, not a total.

### `latest` points at an older run, or there is no `latest`

**Cause.** `latest` advances only after a run whose requested checks all completed. A partial
attempt keeps its own directory under `websec-out/runs/` and prints `partial attempt retained at …;
latest completed scan unchanged`. If your very first run was partial, there is no `latest` yet.

**Fix.** Use the run directory the console printed, fix the gap above, and re-run. For automation,
select the current attempt from the JSON envelope (`--format json`, field `generated`) instead of
trusting `latest`; see the [outputs reference](reference/outputs.md).

### "REQUESTED CHECKS COMPLETED", but part of the code was not analyzed

**Symptom.** The banner says `REQUESTED CHECKS COMPLETED`, followed by a line such as
`Partially outside coverage: no analyzer for elixir (1). Those files were never read.`

**Cause.** "Completed" describes execution of the checks you requested, not coverage of every file.
websec recognises some source types it has no analyzer for: Elixir, Erlang, Scala, Clojure, Groovy,
Perl, Lua, Dart, Haskell, shell scripts, several server-side template languages and others (the list
is `UNANALYZED_SOURCE_EXT` in
[`src/websec_validator/extractors/base.py`](../src/websec_validator/extractors/base.py)). Those files
are counted and reported, never read. Their absence from findings is not a clean result.

**Fix.**

- Check `coverage.json` → `files.unanalyzed_languages` and the `language_without_analyzer` gap.
- If **no** source at all could be analyzed, the banner is `NO ANALYZABLE SOURCE` instead.
  `--require-analyzed` turns that case into exit `3`.
- `--require-analyzed` does **not** fail a mixed repository where some languages were analyzed. If
  you need that in CI, test `files.unanalyzed_languages` yourself:

  ```bash
  python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); u=c["files"].get("unanalyzed_languages") or {}; print(u); sys.exit(1 if u else 0)' websec-out/runs/<run-id>/coverage.json
  ```

- See the [languages reference](reference/languages.md) for what is analyzed.

### Code under a directory named `build/`, `out/` or `vendor/` was not analyzed

**Symptom.** Findings you expected are missing; `coverage.json` shows a `walker_policy` gap and
`files.skipped_samples` lists your directory with reason `skip_directory`. Since 0.22.0 there is
usually also a `skipped_directory_code` gap naming the directory and how many analysable files it
holds.

**Cause.** The walker skips any directory whose **name** is on a fixed list, at any depth below the
target. The list is meant for dependencies, build output, caches and agent tooling, but it includes
names that real projects use for source, such as `build`, `dist`, `out`, `target`, `vendor` and
`coverage`. The full list is `SKIP_DIRS` in
[`src/websec_validator/extractors/base.py`](../src/websec_validator/extractors/base.py). For those
six names, websec counts (never reads) the files with an analysable suffix inside a skipped
directory and reports them as a `skipped_directory_code` gap, with the directories in
`files.skipped_code_dirs` (at most 50 listed; `files.skipped_code_files` is the total). The gap is a
scope limit, not an execution failure, so the banner can still read `REQUESTED CHECKS COMPLETED`,
and neither `--require-complete` nor `--require-analyzed` fails on it.

A directory named `security/` is no longer skipped. The walker now skips only this tool's own output
by content, whatever its name: a run directory (`FACTS.json` next to `coverage.json`) or an output
root (`runs/` with a `latest` link into it), with skip reason `websec_output`. Unless it is named
`websec-out`, such a directory is also counted in the `skipped_directory_code` gap when it holds
analysable files, such as staged probe scripts.

**Fix.** There is no flag to re-include a skipped directory name. Skip matching is relative to the
target, so scan the affected directory directly as its own target:

```bash
websec run ./app/build --out ./websec-out
```

If this affects your project, please [report it](#reporting-a-bug-or-a-false-positive) with the
directory layout.

### Many findings come from tests, examples or fixtures

**Cause.** Most repositories vendor test fixtures, examples or seed data that are not product attack
surface. websec already splits fixture routes out of the attack surface and demotes secrets found in
fixture files to LOW (never dropping them, because a real key pasted into a test is still committed).
When most findings are in such code and there is no `.websec-ignore`, the run prints a one-line
pointer.

**Fix.** Scope at setup rather than after each report:

```bash
websec init --dry-run       # show proposed .websec-ignore entries with file counts; writes nothing
websec init                 # write .websec-ignore (refuses to overwrite one without --force)
websec run . --exclude 'examples/**' --exclude 'tests/**'   # or exclude per run
```

For a single confirmed false positive, prefer a `fingerprint:` acknowledgement with a reason in
`.websec-ignore`: the finding stays visible and auditable but stops gating. Details are in the
[triage and suppression guide](guides/triage-and-suppression.md).

### A secret is reported in a file that no longer exists (`in-tree: false`)

**Cause.** Gitleaks scans Git history across refs. The file was deleted, but the blob is still in
history and fetchable by anyone with the repository.

**Fix.** Rotate the credential at its provider. Deleting the file does not un-leak it; rewriting
history is a separate, destructive decision for your team.

## CI and exit codes

### A CI step that checked for exit `2` no longer catches incomplete runs

**Cause.** Since 0.17.0, `2` means usage or configuration error and `3` means requested checks did
not complete.

**Fix.** Test for `3`, or read `coverage.execution_complete`. See
[Upgrade](upgrade.md#the-0170-exit-code-change) for a handler that keeps all four outcomes distinct.

### `websec doctor` exits `2` in a CI preflight

**Cause.** An installed scanner relevant to the target is older than websec's invocation needs. This
is deliberate, so a preflight fails before a scan that would silently produce nothing.

**Fix.** Upgrade the scanner marked `✗`, or remove it from the runner image.

### `--scanners` run exits `3` with `<name>: unavailable`

**Cause.** `--scanners` is a requirement, not only a filter. A selected scanner that is not installed
makes the run incomplete, so a CI job whose scanner install failed fails instead of reporting zero
findings.

**Fix.** Fix the scanner install step, or remove the scanner from `--scanners`.

## Hooks and agent integrations

### The agent hook prints "gate could not run … NOT blocking. This edit was not security-checked."

**Cause.** The `PostToolUse` agent-loop hook **fails open by design**: if the gate itself errors
(broken install, missing interpreter, unreadable repository), it exits `0` and says so on stderr. A
check that blocks every edit when broken gets uninstalled, and then there is no check at all.

**Fix.** Read the error in the message, then reproduce it outside the hook:

```bash
websec gate --only path/to/the/file.py
websec hooks status --agent
```

A pass from this hook means "nothing blocking was found", never "this edit was verified". The hook
is developer ergonomics, not a compliance control; use `websec run --fail-on …` as a required CI
status check for enforcement.

### The agent hook blocks on a file the agent did not touch

**Cause.** Older releases applied neither `.websec-ignore` nor the requested scope in `gate`, so a
finding in another file (for example a config manifest some extractors always read) could block
every edit. Since 0.19.1, `gate` applies `.websec-ignore` exactly as `run` does and reports findings
in other existing files under `outside_scope` instead of blocking.

**Fix.** Upgrade. If the finding is a reviewed false positive, add a `fingerprint:` acknowledgement
with a reason to `.websec-ignore`; the gate honours it. A finding that names no file at all still
blocks, because it cannot be shown to be outside the scope.

### `WEBSEC_SKIP_HOOK=1` does not skip the agent hook

**Cause.** Deliberate. The agent can set environment variables in its own shell calls, so an
environment escape hatch would be one the agent could operate. `WEBSEC_SKIP_HOOK=1` applies only to
the git guardrail hooks, where each honoured bypass is recorded.

**Fix.** To stop the agent hook, uninstall it: `websec hooks uninstall --agent`.

### Git hooks were installed into an unexpected directory

**Cause.** `websec hooks install` resolves the hooks directory through Git
(`git rev-parse --git-path hooks`), which honours `core.hooksPath`, including a **global**
`core.hooksPath` set in your user config. With Husky (`core.hooksPath=.husky/_`), websec writes to
the durable `.husky/<hook>` script instead of the generated dispatcher.

**Fix.**

```bash
git config --show-origin --get core.hooksPath   # where the setting comes from
websec hooks status                             # prints the hooks directory websec uses
```

Unset or change `core.hooksPath` if the global value is not what you want for this repository, then
re-run `websec hooks install`. Husky users on releases before 0.19.1 should re-run
`websec hooks install` (and `--pre-push`) after upgrading.

### `git push` is blocked after uninstalling or moving websec

**Cause.** The git hooks launch an isolated Python bound to the installed engine. A pre-push gate
whose runtime is missing blocks the push; the post-commit hook stays advisory.

**Fix.** Reinstall websec, or remove the hooks with `websec hooks uninstall` (while websec is still
installed). For a single push, `WEBSEC_SKIP_HOOK=1 git push` is an explicit, recorded override.

### Test suite fails locally but CI is green (contributors)

**Cause.** The most common cause has been ambient Git configuration, especially a global
`core.hooksPath`, which agent sandboxes and Husky users set and GitHub runners do not. Before the
bug-217 fix, hook tests resolved the hooks directory through that global setting and could act on
the real shared hooks directory instead of the temporary test repository. The suite now pins the Git
settings it depends on, and CI has a `hermeticity` job that manufactures a hostile global config.

**Fix.** If the suite still fails only in your environment, treat it as an environment difference and
[open an issue](#reporting-a-bug-or-a-false-positive) rather than a PR that changes tests. Include
`git config --list --show-origin`. See [AGENTS.md](../AGENTS.md) and
[CONTRIBUTING.md](../CONTRIBUTING.md).

### Claude Code plugin will not install

**Cause.** The install id is `<plugin>@<marketplace>`. The marketplace is named `websec-plugins`
(from `.claude-plugin/marketplace.json`), not after the repository.

**Fix.**

```text
/plugin marketplace add raccioly/websec-validator
/plugin install websec-validator@websec-plugins
```

`@websec-validator` does not work.

### `/plugin` is not available

**Cause.** `/plugin` works only in the Claude Code terminal CLI, not in the Claude app or the Agent
SDK.

**Fix.** Register and enable the plugin in `.claude/settings.json` (project) or
`~/.claude/settings.json` (just you):

```json
{
  "extraKnownMarketplaces": {
    "websec-plugins": { "source": { "source": "github", "repo": "raccioly/websec-validator" } }
  },
  "enabledPlugins": { "websec-validator@websec-plugins": true }
}
```

This registers and enables the plugin but does not download it. The first download still needs
`/plugin install websec-validator@websec-plugins` once from the terminal CLI. See the
[AI agents guide](guides/ai-agents.md).

### Plugin installed, but nothing runs or the hook command is not found

**Cause.** The plugin delivers instructions (the `security-pass` skill) and a `PostToolUse` hook that
calls `websec-agent-hook`. It does not install the Python CLI that provides `websec` and
`websec-agent-hook`.

**Fix.** Install the CLI ([Installation](installation.md)), then confirm with `websec --version` and
`command -v websec-agent-hook`.

## Docker

### Permission denied writing `/scan/websec-out`, or output owned by another user

**Cause.** The image runs as a non-root user with UID 1001. On a Linux host, that UID usually cannot
write to a bind-mounted directory you own, and anything it does write is owned by UID 1001.

**Fix.** Run the container with your own UID and GID:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/scan" websec-validator run /scan --out /scan/websec-out
```

`$(id -u)` needs a POSIX shell; on Windows, run Docker commands from WSL.

### Some scanners are missing in the Docker image

**Cause.** The bundled image carries OWASP Noir, Trivy, Gitleaks, Semgrep and Checkov only.
OSV-Scanner, Bandit, gosec, Brakeman, TruffleHog and Prowler are absent and reported as missing.
The `core` target carries no external tools at all.

**Fix.** Use a local install for those tools, or extend the image yourself. Remember that scanners
run only with `--scan`.

## Reporting a bug or a false positive

Before reporting, collect `websec --version`, the output of `websec doctor .`, your OS and Python
version, and the exact command. Sanitize anything sensitive: findings describe security-relevant
code.

| What you found | Where to report |
|---|---|
| A vulnerability **in websec itself** | Privately, via [GitHub security advisories](https://github.com/raccioly/websec-validator/security/advisories/new). Do not open a public issue. See [SECURITY.md](../SECURITY.md). |
| The tool crashed, misbehaved or produced malformed output | The **Bug report** issue template: version, environment, command, what happened, and optionally the target's rough stack. |
| A finding fired on code that is actually safe | `websec feedback` (below), then the **False positive report** template with a sanitized minimal snippet and why it is safe. |
| A detector, extractor or integration that does not exist yet | The **Feature request** template. |
| Documentation that is wrong, missing or out of date | The **Documentation** template. |

Issue templates live in [`.github/ISSUE_TEMPLATE/`](../.github/ISSUE_TEMPLATE/).

### Recording feedback with `websec feedback`

`websec feedback` records your verdict locally and prints a pre-filled GitHub issue link. It performs
no network I/O; sending is your own action in the browser.

```bash
# A finding that is not a real issue (fingerprint comes from findings-ledger.json)
websec feedback --fingerprint <fp> --verdict false-positive --reason "behind an nginx auth_request"

# A real issue with the wrong severity
websec feedback --fingerprint <fp> --verdict severity-wrong --expected-severity LOW --reason "internal-only endpoint"

# Something websec should have reported but did not
websec feedback --verdict false-negative --attack-class ssrf --reason "URL from query string reaches fetch()" --file-extension .ex
```

What it does:

- Appends a record to `websec-out/feedback.jsonl` (or under `--out`). By default the record is
  metadata-only: classification and stable identity, no path, route, evidence or source text.
  `--include-snippet` adds title, route, file and evidence, and asks you to confirm first.
- For `false-positive`, it also queues a **pending calibration candidate** in your local overlay
  (`~/.cache/websec-validator/calibration-local.json`). No probability changes until a reviewer
  accepts it with `websec calibrate --accept <id> --reason "…"` (or discards it with `--reject`).
- It does not suppress anything. To stop a finding gating locally, add a `fingerprint:`
  acknowledgement to `.websec-ignore`.

## See also

- [Installation](installation.md) and [Upgrade](upgrade.md)
- [FAQ](faq.md)
- [Triage and suppression](guides/triage-and-suppression.md)
- [Outputs reference](reference/outputs.md) for `coverage.json` and the ledger
- [CLI reference](reference/cli.md)

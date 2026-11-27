# Troubleshooting

This page lists known problems as symptom, cause and fix. It is for anyone whose install, run, CI
gate, hook or agent integration does not work as expected. When you finish, you have either a fix or
a clear list of what to include in a bug or false-positive report.

Two habits solve most problems faster:

- Run `websec doctor .` first. It shows which engine runs, where it came from, and which
  optional scanners are present and compatible.
- Read `coverage.json` in the run directory. A run that "looks clean" is often a run that could not
  read something. `coverage.json` says what and why.

## Installation

### `websec: command not found`

**Cause.** The install succeeded, but the directory where pipx (or uv) puts commands is not on your
`PATH`. Or you installed into a virtualenv that is not activated.

**Fix.**

```bash
pipx ensurepath        # then open a new shell
pipx list              # confirm websec-validator is listed with its commands
```

For a pip install, activate the virtualenv you installed into. For uv, `uv tool dir --bin` prints the
command directory and `uv tool update-shell` adds it to `PATH`.

Since 0.22.2 there is also a form that does not depend on `PATH`. The interpreter that installed the package can
always run it, so `python -m websec_validator <command>` works wherever `websec <command>` works. Use
it in CI images and agent sandboxes where the directory of the console script is not on `PATH`.

### Installation fails because Python is too old

**Symptom.** pip reports that no matching distribution was found, or that the available versions
require a different Python.

**Cause.** websec needs Python 3.11 or newer. On stock macOS, `python3` is often 3.9.

**Fix.** Install with an interpreter that is 3.11 or newer:

```bash
python3 --version
pipx install --python python3.12 websec-validator   # point pipx at any 3.11+ interpreter
```

If you do not have a newer Python, get one from Homebrew, pyenv or python.org. See
[Installation](installation.md#requirements).

### `websec --version` or `doctor` shows an old or unexpected engine

**Causes.**

- More than one `websec` is on your `PATH` (for example, a pipx install and a pyenv or venv install),
  and the shell picks the older one first.
- You updated an editable install with `git pull`. The code changed, but the package metadata that
  `--version` reads was written at install time.
- pipx was installed from a local wheel file. `pipx upgrade` then re-resolves that same file and
  reports "already at latest", while the engine stays behind.

**Fix.**

```bash
which -a websec        # every websec on PATH, in resolution order
websec doctor          # prints engine path, source (package index, editable, local file) and Python
```

`doctor` also warns when the imported code is not inside the installed distribution. In that case,
the printed version describes the install, not the code. To get back to a clean PyPI engine:

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
websec process. The environment of your CI job, agent or hook can differ from a shell where `noir` works.

If the line reads `via noir (0 routes) → regex-fallback backstop`, Noir did run but found nothing.
The fallback then added routes.

**Fix.**

```bash
command -v noir        # is it on PATH for this shell (and for your CI job / agent)?
websec doctor .        # the "route engine" section shows what websec itself finds
```

### `⚠ OWASP Noir failed: … — routes came from the regex fallback`

**Cause.** Noir is installed but did not produce usable output. websec runs
`noir scan <target> -f json -o <tmpfile> --exclude-path … --no-log --no-color` with a 300-second
timeout. A non-zero exit with no output, a timeout, invalid JSON or a launch error counts as a failure.
Since 0.22.0, websec reports this failure, so it no longer looks like an absent Noir. The run prints the reason,
`FACTS.json` → `routes.noir` records `{"state": "failed", "reason": …}`, and `coverage.json` gets a
`route_engine` gap. The gap is a scope limit (`execution: false`). It does not make the run
incomplete and does not change the exit code. But the route inventory is the narrower regex result.

**Fix.**

```bash
websec doctor .        # route engine: ✓ version, ? no version printed, ✗ crashed or timed out
noir --version
noir scan . -f json -o /tmp/noir-check.json   # does this build accept websec's invocation?
```

If the manual command fails, upgrade or reinstall Noir. The bundled Docker image pins a Noir
version in the [`Dockerfile`](../Dockerfile), and its CI checks that version.

### Scanners are listed but never run

**Symptom.** The output says `scanners available: Trivy, Gitleaks, … (add --scan to execute them)`,
and `findings.json` is missing or empty.

**Cause.** Static scanners run only with `--scan`. This is the same inside the Docker image, even
though the image bundles scanners.

**Fix.** `websec run . --scan`. `--scanners` and `--verify-secrets` each require `--scan`.
Without `--scan`, websec prints `error: --scanners requires --scan` (or the `--verify-secrets` equivalent)
and exits `2`.

### A specific scanner never runs

| Scanner | Why |
|---|---|
| Bandit, gosec, Brakeman | Selected only when the stack detector finds Python, Go or Ruby respectively. Check the `stack:` line. |
| Brakeman, on a Ruby target | Also needs an `app/` directory at the root of the target, Brakeman's own Rails precondition. Without one, `websec doctor .` lists it under "not applicable to this target" and websec does not run it. Use the root directory of the Rails application as the target. |
| TruffleHog | Never runs implicitly. It needs `--scan --verify-secrets`, because it sends candidate credentials to provider APIs. |
| Prowler | Detected and reported only. The current registry entry has no invocation, so websec does not execute it. |
| OpenGrep | websec looks for an executable named `semgrep`. An `opengrep` binary is not detected under that name. |

### A scanner runs but contributes nothing, or `doctor` shows `✗`

**Cause.** The installed version is older than the command line that websec builds for it. An
incompatible scanner can run, fail in its own way, and look exactly like a clean run.

**Fix.** Run `websec doctor .`. A `✗` row names the installed version and the minimum that websec needs.
`?` means the version could not be read. Upgrade that tool. The minimums are in `REGISTRY` in
[`src/websec_validator/scanners.py`](../src/websec_validator/scanners.py). `websec doctor` exits
`2` while any relevant installed scanner is incompatible.

### `error: unknown command '…' (and no such path)`

**Cause.** `websec <path>` is shorthand for `websec run <path>`, but only when the path exists.
websec rejects a mistyped subcommand that is also not an existing path (exit `2`). It prints a near-match
suggestion and does not run the text as a directory.

**Fix.** Check the spelling against `websec --help`, or pass an existing path.

### `error: target is not a directory: …` (exit 2)

**Cause.** The target path does not exist or is a file.

**Fix.** Pass the repository directory. Since 0.22.0 this is a usage error (exit `2`). Earlier
releases exited `1`, the same code as findings.

### `⚠ PARTIAL SCAN — hit the …-file cap`

**Cause.** The repository has more code files than the per-run cap of the walker (`MAX_FILES` in
[`src/websec_validator/extractors/base.py`](../src/websec_validator/extractors/base.py)). Recon
can be incomplete.

**Fix.** Exclude generated or vendored trees with `--exclude '<glob>'`. Or use a subdirectory (for
example, one service of a monorepo) as the target. See the [monorepo guide](guides/monorepo.md).

## Coverage and results

### Exit `3`: requested checks did not complete

**Symptom.** `✗ requested security checks did not complete; partial artifacts saved (exit 3 —
toolchain/coverage, NOT a finding).`

**Cause.** You asked for completeness (`--require-complete`, or `--fail-on`), and something that you
requested did not run to completion. websec keeps the run directory, but `latest` does not move forward.

**Fix.** Open `coverage.json` in the run directory the console printed and read `gaps`. Common
entries:

| Gap | Meaning | Fix |
|---|---|---|
| `scanner`: `<name>: unavailable` | You selected it with `--scanners` but it is not installed | Install it, or drop it from `--scanners` |
| Scanner timeout, error, invalid report, or `scanner_rules` partial | The tool ran but did not produce a usable result | Run the tool by hand; check `websec doctor` for version problems. For Checkov or Semgrep parse errors, see [Checkov](#checkov-error-from-files-you-excluded) and [Semgrep](#semgrep-error-on-valid-shell-scripts) below |
| Read loss, oversized files, byte budget | Some source could not be read within limits | Narrow the target or exclude generated files. Since 0.24.0, dependency lockfiles and `.sql` files have their own budget, so they no longer fill the source cache. Raise a limit with `--max-source-bytes`, `--max-data-bytes` or `--max-sql-files`; `coverage.json` `files.read_policy` lists the active values |
| `glob_limit` on `**/*.sql` | More `.sql` files than `--max-sql-files` (default 5000) | Raise `--max-sql-files` |
| `extractor`: `surface` with `source_flow_limit` | Bounded source-flow analysis stopped at a budget in the named files | See [below](#source_flow_limit-on-an-ordinary-js-module) |
| `graph`, `baseline`, SARIF import | An explicitly supplied `--graph`, `--baseline` or `--sarif` input was missing, malformed, unreadable or over a cap. A graph's own cap is 64 MiB, and the gap names the reason (`not found`, `oversized`, `excluded or out of scope`, `invalid`) | Fix or remove the input |
| `dependency-existence` | `--network` could not resolve some names | Retry; UNKNOWN is never treated as clean |

A run can fail the gate **and** be incomplete. It then exits `1`, prints both facts, and records
`gate.failure_kind` as `findings+incomplete`. The finding count is a floor, not a total.

### `checkov: error` from files you excluded

**Symptom.** A `--scan` run is incomplete with a `scanner` gap `checkov: error`. Also,
`coverage.json` → `scanners.checkov.report_details.errors` reads `<framework>: N input parsing
errors`. The files that failed to parse are under a path that you passed to `--exclude`, or under a
skipped directory such as `node_modules`. Or they are ordinary JSON files, such as a `tsconfig.app.json`
with comments.

**Cause.** Before 0.22.0, Checkov received no path exclusion. It walked excluded and skipped trees,
and one parse error anywhere marked the whole scanner `error`. Its `terraform_plan` framework also
tries to parse every `*.json` file as a plan.

**Since 0.22.0:**

- `--exclude` patterns and the skipped directory names reach Checkov as `--skip-path` patterns
  anchored to the target root. If Checkov still reports a parse error for such a file, websec counts it in
  `report_details.file_limitations_excluded` and otherwise ignores it.
- A parse error on an in-scope file, in a framework that evaluated other resources, is a per-file
  limitation, not a scanner failure. websec lists the file in `scanners.checkov.file_limitations` and in
  a `scanner_file_limits` gap, which is a scope limit (`execution: false`).
- These cases are still an error: a framework that evaluated nothing and failed to parse in-scope files (the message
  names them), parse errors that Checkov did not attribute to a file, and an abnormal exit.
- websec skips `terraform_plan` (`--skip-framework terraform_plan`) only when no in-scope `*.json`
  looks like a `terraform show -json` plan. That means its first 64 KiB contain `"terraform_version"`
  and `"planned_values"` or `"resource_changes"`. When websec cannot decide (an unreadable file, too
  many JSON files to check), the framework stays on.

**Fix.**

- Set the scope with `--exclude`, not `.websec-ignore`. `.websec-ignore` filters findings after analysis.
  It never changes what a scanner reads, so a scanner still parses a path that only `.websec-ignore` lists.
- An error that names an in-scope file is a real parse failure. Fix the file, or exclude it if it is
  not your product. To reproduce the error, run `checkov -d . --compact -o json` and read the `parsing_errors`
  of each framework.
- A `scanner_file_limits` entry does not fail the run, but the IaC in that file was not checked. If the file
  has no findings, that is not a clean result.

### `semgrep: error` on valid shell scripts

**Symptom.** A `scanner` gap `semgrep: error`, with a `PartialParsing` or `Syntax error` diagnostic
on a valid file. An example is a bash script that uses syntax that the Semgrep parser does not support.

**Cause.** Semgrep reports per-file parse diagnostics (`PartialParsing`, `Syntax error`,
`Lexical error`, `Other syntax error`) at level `warn`. It still exits `0` and checks every other file.
Before 0.22.0, websec counted those diagnostics as a scanner failure.

**Since 0.22.0,** such a diagnostic (level `warn`, attributed to a file, no rule id) is a per-file
limitation. websec lists the file in `scanners.semgrep.file_limitations` with `reason`
`partial_parse` (`PartialParsing`) or `parse_failed` (the others), and names it in a
`scanner_file_limits` gap. websec only counts a diagnostic for a file under `--exclude` or a skipped directory.
These cases still mark Semgrep `error`: fatal, configuration and rule errors, a parse diagnostic at level `error` or without a
file, any other diagnostic type, and an exit code other than `0` or `1`.

**Fix.** Completeness needs no action. Review the listed files by hand if they matter, because
Semgrep did not fully analyze them. Or `--exclude` them if they are not your product. If Semgrep is
still `error`, read `scanners.semgrep.report_details.errors` and run
`semgrep scan --config auto --json .` by hand.

### `source_flow_limit` on an ordinary JS module

**Symptom.** The run is incomplete with an `extractor` gap `surface` and, since 0.22.0, a
`source_flow_limit` gap such as `1 file(s) not fully analysed by source-flow: src/app.js
(assigned_flow: LimitReached: JS assignment expression budget exceeded)`. The same rows are in
`FACTS.json` → `surface.assigned_flow.errors`.

**Cause.** The JS assignment-flow lane follows request values into sinks, and it has a bound. Before
0.22.0, it abandoned ordinary modules in three cases. A quote inside a regex literal (`/'/g`, `/["']/`) opened a
phantom string. A long right-hand side (an `async (event) => {…}` handler, a large object literal)
exceeded the expression bound. A module with more than 128 function scopes was rejected. Each case
stopped the analysis of that file and made the run incomplete, with a gap that named only `surface`.

**Since 0.22.0,** websec blanks regex literal bodies before the walk where JS grammar requires an
operand. A long right-hand side draws on a bounded extension. The scope budget grows with file
size up to a cap (the budgets are in `surface.assigned_flow.limits`). A file can still exhaust a
budget, such as deeply nested or generated code. Then the analysis stops at a visible `LimitReached`, and the run
stays incomplete, like an oversized file that websec did not fully analyze. Other files are unaffected.

**Fix.** Read the gap for the file and the reason. Exclude generated, minified or vendored code with
`--exclude`. If the file is hand-written product code, [report it](#reporting-a-bug-or-a-false-positive)
with a sanitized description of its shape. Do not treat the gap as noise. websec did not check request-to-sink flows in
that file. websec still reads a `/` after `)`, `]`, `}` or an identifier as division.
A regex literal in that position can still trigger the old behavior.

**A file that `.websec-ignore` already hides.** A `.websec-ignore` path line hides the findings of a
file. It does not remove the file from analysis, so the file can still use up a budget. Since
0.23.2, the gap names the `.websec-ignore` line that already covers each stopped file. The gap stays
an execution gap, because websec did not finish the analysis of that file. If the file is generated
or a copy of other source, pass the same pattern to `--exclude` to take it out of analysis.
Capacitor web copies (`ios/App/App/public/` and `android/app/src/main/assets/public/`) are skipped
automatically, as the next section explains.

### `latest` points at an older run, or there is no `latest`

**Cause.** `latest` moves forward only after a run whose requested checks all completed. A partial
attempt keeps its own directory under `websec-out/runs/` and prints `partial attempt retained at …;
latest completed scan unchanged`. If your first run was partial, there is no `latest` yet.

**Fix.** Use the run directory that the console printed, fix the gap above, and run again. For automation,
select the current attempt from the JSON envelope (`--format json`): since 0.24.0 its `run` field
gives `directory`, `execution_complete` and `published_as`, and a partial run is also published as
`websec-out/partial`. Do not trust `latest` for a run you just started. See the
[outputs reference](reference/outputs.md).

### `osv-scanner: error` on a Maven project

**Cause.** osv-scanner resolves `pom.xml` dependencies transitively against Maven Central. A
dependency that exists only in another repository (a MuleSoft connector, a company Nexus) fails the
whole manifest. Since 0.25.0, websec then runs osv-scanner again with `--no-resolve`, checks the
direct dependencies, and records a `dependency_resolution` gap that names the unresolved packages.
A POM with no dependencies is recorded as "no package sources found" (`scanner_scope`), not an
error. If a scanner still errors, `coverage.json` `scanners.<name>.report_details.errors` holds the
end of its stderr.

### A Mule or Salesforce project reads 0 code files

**Cause.** Mule flows, DataWeave, Salesforce Flow, Visualforce and Aura markup are not code files.
Since 0.25.0 the `mule` and `salesforce-metadata` profiles read them, `coverage.json`
`files.dialects` counts them, and the banner names them as profile files. Mule listener routes are
in the route inventory; a missing in-code guard on them is a low-confidence lead, because API
Manager policies live outside the repository. AMPscript pages are listed as `ampscript` under
`language_without_analyzer`.

### Every Spring route is reported as `Missing authorization`

**Cause.** Before 0.24.0, websec did not read Spring Security. Since 0.24.0, a route is guarded when
the first `SecurityFilterChain` rule that matches it is `authenticated()`, `hasRole(...)`,
`hasAuthority(...)`, `access(...)` or `denyAll()`, or when `@PreAuthorize`, `@PostAuthorize`,
`@Secured` or `@RolesAllowed` is on the handler or its class and `@EnableMethodSecurity` (or
`@EnableGlobalMethodSecurity`) turns that annotation family on. A chain applies to its own
Maven/Gradle module and to modules whose build file depends on that module.

**What you still see.** A route under a `permitAll()` matcher stays a lead, and its evidence names
the matcher. A module that depends on Spring Security, but whose chain websec could not resolve
(auto-configuration, a chain more than one module away, Spring Boot's default), gets a LOW-confidence
lead that says so. Check `authz.endpoint_guards[]` in `FACTS.json`: `guard_evidence`, `public_rule`,
`central_auth_unresolved` and `unverified_controls` explain each decision.

### Java code in a `com/example`, `build`, `tool` or `migration` package was not analyzed

**Cause.** Before 0.24.0, directory-name rules (example, build output, script) also matched Java
package directories. Since 0.24.0, the segments below a source root such as `src/main/java/` are
package names, and those rules read only the path above the root. A real `svc/build/` directory is
still skipped. Routes that websec excludes as test, example or fixture code are now listed in
`coverage.json` as a `fixture_excluded_routes` gap. Re-include them with `--include-fixtures`.

### "REQUESTED CHECKS COMPLETED", but part of the code was not analyzed

**Symptom.** The banner says `REQUESTED CHECKS COMPLETED`, followed by a line such as
`Partially outside coverage: no analyzer for elixir (1). Those files were never read.`

**Cause.** "Completed" describes the execution of the checks that you requested. It does not describe coverage of every file.
websec recognizes some source types that it has no analyzer for: Elixir, Erlang, Scala, Clojure, Groovy,
Perl, Lua, Dart, Haskell, shell scripts, several server-side template languages and others (the list
is `UNANALYZED_SOURCE_EXT` in
[`src/websec_validator/extractors/base.py`](../src/websec_validator/extractors/base.py)). websec counts and reports those files.
It never reads them. If those files have no findings, that is not a clean result.

**Fix.**

- Check `coverage.json` → `files.unanalyzed_languages` and the `language_without_analyzer` gap.
- If **no** source at all could be analyzed, the banner is `NO ANALYZABLE SOURCE` instead.
  `--require-analyzed` turns that case into exit `3`.
- `--require-analyzed` does **not** fail a mixed repository where websec analyzed some languages. If
  you need that in CI, test `files.unanalyzed_languages` yourself:

  ```bash
  python3 -c 'import json,sys; c=json.load(open(sys.argv[1])); u=c["files"].get("unanalyzed_languages") or {}; print(u); sys.exit(1 if u else 0)' websec-out/runs/<run-id>/coverage.json
  ```

- See the [languages reference](reference/languages.md) for what is analyzed.

### Code under a directory named `build/`, `out/` or `vendor/` was not analyzed

**Symptom.** Findings that you expected are missing. `coverage.json` shows a `walker_policy` gap and
`files.skipped_samples` lists your directory with reason `skip_directory`. Since 0.22.0, there is
usually also a `skipped_directory_code` gap that names the directory and says how many analyzable files it
holds.

**Cause.** The walker skips any directory whose **name** is on a fixed list, at any depth below the
target. The list is meant for dependencies, build output, caches and agent tooling. But it includes
names that real projects use for source, such as `build`, `dist`, `out`, `target`, `vendor` and
`coverage`. The full list is `SKIP_DIRS` in
[`src/websec_validator/extractors/base.py`](../src/websec_validator/extractors/base.py). For those
six names, websec counts the files with an analyzable suffix inside a skipped
directory, and never reads them. It reports them as a `skipped_directory_code` gap, with the directories in
`files.skipped_code_dirs` (at most 50 listed; `files.skipped_code_files` is the total). The gap is a
scope limit, not an execution failure. The banner can still read `REQUESTED CHECKS COMPLETED`,
and neither `--require-complete` nor `--require-analyzed` fails on it.

The walker no longer skips a directory named `security/`. It now skips only the output of this tool,
which it recognizes by content, whatever the name: a run directory (`FACTS.json` next to `coverage.json`) or an output
root (`runs/` with a `latest` link into it), with skip reason `websec_output`. If such a directory is not named
`websec-out` and holds analyzable files, such as staged probe scripts, websec also counts it in the `skipped_directory_code` gap.

Since 0.23.2, the walker also skips the copies of the web build that Capacitor's `cap sync` writes
into the native projects: `ios/App/App/public/` and `android/app/src/main/assets/public/`, at the
target root, when a `capacitor.config.*` file is also at the root. The skip reason is
`generated_copy`. websec analyzes the web source that these copies come from. The copies are
counted in the `skipped_directory_code` gap in the same way.

**Fix.** No flag re-includes a skipped directory name. Skip matching is relative to the
target. Use the affected directory directly as its own target:

```bash
websec run ./app/build --out ./websec-out
```

If this affects your project, please [report it](#reporting-a-bug-or-a-false-positive) with the
directory layout.

### Many findings come from tests, examples or fixtures

**Cause.** Most repositories vendor test fixtures, examples or seed data that are not product attack
surface. websec already splits fixture routes out of the attack surface. It lowers secrets in
fixture files to LOW, and never drops them, because a real key pasted into a test is still committed.
When most findings are in such code and there is no `.websec-ignore`, the run prints a one-line
pointer.

**Fix.** Set the scope at setup, not after each report:

```bash
websec run . --scan         # optional: gives init a ledger to read
websec init --dry-run       # show proposed .websec-ignore entries with file counts; writes nothing
websec init                 # write .websec-ignore (refuses to overwrite one without --force)
websec run . --exclude 'examples/**' --exclude 'tests/**'   # or exclude per run
```

A directory line in `.websec-ignore` also hides every **future** finding under it, including a real
credential that someone commits there later. Since 0.22.0, each line that `init` proposes says so. With the ledger of a prior
run, `init` proposes dated `fingerprint:` acknowledgements instead of a glob for a
directory whose only findings are secrets. A new secret there still gates. See
[`websec init`](reference/cli.md#websec-init).

The two tools set different scopes. `--exclude` stops recon **and** the
scanners from reading a path. `.websec-ignore` filters findings after analysis. Scanners still read and parse those
paths. If a scanner fails on a file that you never meant to check, use `--exclude`.

For a single confirmed false positive, prefer a `fingerprint:` acknowledgement with a reason in
`.websec-ignore`. The finding stays visible and auditable but stops gating. Details are in the
[triage and suppression guide](guides/triage-and-suppression.md).

### A secret is reported in a file that no longer exists (`in-tree: false`)

**Cause.** Gitleaks scans Git history across refs. Someone deleted the file, but the blob is still in
history, and anyone with the repository can fetch it.

**Fix.** Rotate the credential at its provider. Deleting the file does not undo the leak. A rewrite of
history is a separate, destructive decision for your team.

## CI and exit codes

### A CI step that checked for exit `2` no longer catches incomplete runs

**Cause.** Since 0.17.0, `2` means usage or configuration error and `3` means requested checks did
not complete.

**Fix.** Test for `3`, or read `coverage.execution_complete`. See
[Upgrade](upgrade.md#the-0170-exit-code-change) for a handler that keeps all four outcomes distinct.

### `websec doctor` exits `2` in a CI preflight

**Cause.** An installed scanner that is relevant to the target is older than the websec invocation needs. This
is deliberate. A preflight then fails before a run that would silently produce nothing.

**Fix.** Upgrade the scanner marked `✗`, or remove it from the runner image.

### `--scanners` run exits `3` with `<name>: unavailable`

**Cause.** `--scanners` is a requirement, not only a filter. A selected scanner that is not installed
makes the run incomplete. A CI job whose scanner install failed then fails, and does not report zero
findings.

**Fix.** Fix the scanner install step, or remove the scanner from `--scanners`.

## Hooks and agent integrations

### The agent hook prints "gate could not run … NOT blocking. This edit was not security-checked."

**Cause.** The `PostToolUse` agent-loop hook **fails open by design**. If the gate itself errors
(broken install, missing interpreter, unreadable repository), it exits `0` and says so on stderr. People uninstall a
check that blocks every edit when it breaks, and then no check remains.

**Fix.** Read the error in the message, then reproduce it outside the hook:

```bash
websec gate --only path/to/the/file.py
websec hooks status --agent
```

A pass from this hook means "nothing blocking was found". It never means "this edit was verified". The hook
helps developers work. It is not a compliance control. To enforce a gate, use `websec run --fail-on …` as a required CI
status check.

### The agent hook blocks on a file the agent did not touch

**Cause.** Older releases applied neither `.websec-ignore` nor the requested scope in `gate`. A
finding in another file (for example, a config manifest that some extractors always read) could block
every edit. Since 0.19.1, `gate` applies `.websec-ignore` exactly as `run` does. It reports findings
in other existing files under `outside_scope` and does not block.

**Fix.** Upgrade. If the finding is a reviewed false positive, add a `fingerprint:` acknowledgement
with a reason to `.websec-ignore`. The gate honors it. A finding that names no file at all still
blocks, because nothing shows that it is outside the scope.

### `emit-context` says `jwt` but the app does not use JWTs

**Cause.** Before 0.22.0, any name-level match made `jwt (bearer)` the primary auth scheme. Examples: a comment
that mentions `jsonwebtoken`, a `token_required` error code, a person called "Jose" in seed data.
`emit-context` stated that scheme as fact. It also printed the
route count without a caveat, even when route discovery was flagged incomplete. Every agent session
that started from this block began with the wrong auth model.

**Since 0.22.0,** a `jwt (bearer)` reading needs a JWT library that is imported or called in a file that
mentions JWT. A bare `Authorization: Bearer` header is not JWT evidence. websec keeps a name-only mention as
`jwt? (weak evidence: …)`, ranked after every other
scheme, with `auth.scheme_confidence` `low`. `emit-context` labels a `low` scheme
`LOW-CONFIDENCE guess, unverified` with its basis. It labels any scheme `inferred, unverified` when
route discovery is flagged incomplete, and it marks the route count as a floor. See
[`websec emit-context`](reference/cli.md#websec-emit-context).

**Fix.** Read the evidence behind the reading:

```bash
jq '.auth | {scheme, scheme_confidence, scheme_basis, scheme_evidence, schemes_detected, signal_counts}' \
  websec-out/latest/FACTS.json
```

If it still reads `jwt (bearer)` at `high`, `scheme_basis` gives the number of files where a JWT
library is imported or called (or where a JOSE `alg` or JWKS reference sits beside a JWT mention). Find
those files and check whether they serve the own requests of your app. If they do not, report a false positive.
websec can still stage JWT probes, because `signal_counts.jwt` stays the permissive name-level count. This way,
real JWT leads are not dropped. Discard a JWT probe that does not apply.

### `WEBSEC_SKIP_HOOK=1` does not skip the agent hook

**Cause.** This is deliberate. The agent can set environment variables in its own shell calls, so an
environment escape hatch would be one that the agent could operate. `WEBSEC_SKIP_HOOK=1` applies only to
the git guardrail hooks, where websec records each bypass that it honors.

**Fix.** To stop the agent hook, uninstall it: `websec hooks uninstall --agent`.

### Git hooks were installed into an unexpected directory

**Cause.** `websec hooks install` resolves the hooks directory through Git
(`git rev-parse --git-path hooks`). Git honors `core.hooksPath`, including a **global**
`core.hooksPath` in your user config. With Husky (`core.hooksPath=.husky/_`), websec writes to
the durable `.husky/<hook>` script, not to the generated dispatcher.

**Fix.**

```bash
git config --show-origin --get core.hooksPath   # where the setting comes from
websec hooks status                             # prints the hooks directory websec uses
```

If the global value is not what you want for this repository, unset or change `core.hooksPath`. Then
re-run `websec hooks install`. Husky users on releases before 0.19.1 must re-run
`websec hooks install` (and `--pre-push`) after they upgrade.

### `git push` is blocked after uninstalling or moving websec

**Cause.** The git hooks launch an isolated Python bound to the installed engine. A pre-push gate
with a missing runtime blocks the push. The post-commit hook stays advisory.

**Fix.** Reinstall websec, or remove the hooks with `websec hooks uninstall` (while websec is still
installed). For a single push, `WEBSEC_SKIP_HOOK=1 git push` is an explicit override, and websec records it.

### Test suite fails locally but CI is green (contributors)

**Cause.** The most common cause has been ambient Git configuration, especially a global
`core.hooksPath`. Agent sandboxes and Husky users set it, and GitHub runners do not. Before the
bug-217 fix, hook tests resolved the hooks directory through that global setting. They could act on
the real shared hooks directory, not on the temporary test repository. The suite now pins the Git
settings that it depends on. CI has a `hermeticity` job that builds a hostile global config.

**Fix.** If the suite still fails only in your environment, treat it as an environment difference.
[Open an issue](#reporting-a-bug-or-a-false-positive). Do not open a PR that changes tests. Include
`git config --list --show-origin`. See [AGENTS.md](../AGENTS.md) and
[CONTRIBUTING.md](../CONTRIBUTING.md).

### Claude Code plugin will not install

**Cause.** The install id is `<plugin>@<marketplace>`. The marketplace is named `websec-plugins`
(from `.claude-plugin/marketplace.json`). It does not use the name of the repository.

**Fix.**

```text
/plugin marketplace add raccioly/websec-validator
/plugin install websec-validator@websec-plugins
```

`@websec-validator` does not work.

### `/plugin` is not available

**Cause.** `/plugin` works only in the Claude Code terminal CLI. It does not work in the Claude app or the Agent
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

This registers and enables the plugin, but it does not download the plugin. For the first download, run
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
write to a bind-mounted directory that you own. Anything it does write is owned by UID 1001.

**Fix.** Run the container with your own UID and GID:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/scan" websec-validator run /scan --out /scan/websec-out
```

`$(id -u)` needs a POSIX shell. On Windows, run Docker commands from WSL.

### Some scanners are missing in the Docker image

**Cause.** The bundled image carries OWASP Noir, Trivy, Gitleaks, Semgrep and Checkov only.
OSV-Scanner, Bandit, gosec, Brakeman, TruffleHog and Prowler are absent and reported as missing.
The `core` target carries no external tools at all.

**Fix.** Use a local install for those tools, or extend the image yourself. Remember that scanners
run only with `--scan`.

## Reporting a bug or a false positive

Before you report, collect `websec --version`, the output of `websec doctor .`, your OS and Python
version, and the exact command. Sanitize anything sensitive, because findings describe security-relevant
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
no network I/O. You send the report yourself in the browser.

```bash
# A finding that is not a real issue (fingerprint comes from findings-ledger.json)
websec feedback --fingerprint <fp> --verdict false-positive --reason "behind an nginx auth_request"

# A real issue with the wrong severity
websec feedback --fingerprint <fp> --verdict severity-wrong --expected-severity LOW --reason "internal-only endpoint"

# Something websec should have reported but did not
websec feedback --verdict false-negative --attack-class ssrf --reason "URL from query string reaches fetch()" --file-extension .ex
```

What it does:

- It appends a record to `websec-out/feedback.jsonl` (or under `--out`). By default, the record has
  metadata only: classification and stable identity, with no path, route, evidence or source text.
  `--include-snippet` adds title, route, file and evidence, and asks you to confirm first.
- For `false-positive`, it also queues a **pending calibration candidate** in your local overlay
  (`~/.cache/websec-validator/calibration-local.json`). No probability changes until a reviewer
  accepts the candidate with `websec calibrate --accept <id> --reason "…"` (or discards it with `--reject`).
- It does not suppress anything. To stop a finding from gating locally, add a `fingerprint:`
  acknowledgement to `.websec-ignore`.

## See also

- [Installation](installation.md) and [Upgrade](upgrade.md)
- [FAQ](faq.md)
- [Triage and suppression](guides/triage-and-suppression.md)
- [Outputs reference](reference/outputs.md) for `coverage.json` and the ledger
- [CLI reference](reference/cli.md)

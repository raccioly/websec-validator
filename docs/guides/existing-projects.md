# Adopting websec-validator in an existing project

You do not need to clear a security backlog before adopting websec. Start report-only on a branch,
scope out code that is not your product, record what already exists as a baseline, and only then
tighten the gate. At the end of this guide you will have a committed `.websec-ignore`, a reviewed
baseline ledger, a CI job that fails only on new or reopened findings, and (optionally) an agent-loop
check on every file your coding agent writes.

Each step is written for a human first. The **Tell your agent** block after it is a plain-English
prompt you can give an AI coding agent to do the same step for you.

| Stage | Main command | What it changes in your repository |
|---|---|---|
| 1. Reviewable baseline | `git switch -c …` | `.gitignore` gains `websec-out/` |
| 2. Toolchain and language check | `websec doctor .` | nothing |
| 3. Scope non-product code | `websec init --dry-run`, then `websec init` | adds `.websec-ignore` |
| 4. First runs | `websec run .`, then `websec run . --scan` | nothing (artifacts go to `websec-out/`) |
| 5. Triage | `websec explain`, `websec feedback` | `fingerprint:` lines in `.websec-ignore` |
| 6. Baseline | `websec run . --baseline <ledger>` | a stored prior ledger |
| 7. Phased gating | `--fail-on`, `--require-complete`, `--diff`, `websec gate` | CI config, optional hooks |
| 8. Policy aging | `expires:` dates, `websec intel …` | dated acknowledgements |

## Before you begin

- websec-validator installed (`pipx install websec-validator`) on Python 3.11 or newer. See
  [installation](../installation.md).
- A Git checkout of the project. `--diff`, `websec gate` and `websec hooks` all read Git.
- Authority to review the code. websec is read-only by default and never touches a running app,
  but frame agent requests as a *defensive review of your own code* (see
  [AI agents](ai-agents.md)).

## 1. Start from a reviewable baseline

Begin with a clean tree on a dedicated branch, so every file websec or your agent adds shows up in
one reviewable diff.

```bash
git status                      # should report a clean tree
git switch -c chore/adopt-websec
```

`websec run` writes its artifacts to `./websec-out/` **in the current working directory** (not in
the scanned target) unless you pass `--out`. Every attempt gets its own directory under
`websec-out/runs/`, and the `websec-out/latest` pointer advances only after a run whose requested
checks completed. The run ends by printing ``add `websec-out/` to .gitignore`` — it does not edit
`.gitignore` for you. Do it once:

```bash
echo 'websec-out/' >> .gitignore
git add .gitignore
```

The artifacts describe findings, paths and evidence from your code, so treat them as sensitive and
keep them out of version control. The walker already skips directories named `websec-out`, so a
stale output tree is never scanned as source.

`websec run` never edits your source. The only commands that write into your repository are the
ones you invoke for that purpose: `websec init` (`.websec-ignore`), `websec install <host>` (agent
instruction files), `websec hooks install --agent` (`.claude/settings.json`) and `websec hooks
install` (Git hooks).

> **Tell your agent:** "Create a branch named `chore/adopt-websec` from a clean working tree. Add
> `websec-out/` to `.gitignore` and stage only that change. Do not run any scan yet."

## 2. Check your toolchain and language coverage

```bash
websec --version
websec doctor .          # installed and missing scanners, versions, install hints
websec capabilities      # offline matrix of named profiles, checks and their limits
```

`doctor` tells you which optional scanners (Trivy, OSV-Scanner, Gitleaks, Semgrep/OpenGrep,
Checkov, Bandit and others) are present. They only execute when you add `--scan`. A scanner you
name with `--scanners` but have not installed makes the run incomplete rather than clean.

Before you trust a clean result, know how deeply websec reads your stack. Coverage falls into
three tiers. [Language support](../reference/languages.md) is the authoritative list.

| Tier | What it means | What you see |
|---|---|---|
| Full recon | Framework, route, auth, access-control and sink extractors (the JavaScript/TypeScript and Python web stacks) | normal findings and attack-surface map |
| Named-check profile | Bounded direct-syntax checks only — for example Java/Spring, .NET, Go, Ruby, PHP, Android, iOS, Rust, C/C++ | listed in `websec capabilities` with each profile's limitations |
| Unanalysed | Recognised as source but never read or matched — for example Elixir, Scala, Clojure, shell, server-side templates | `coverage.json` → `files.unanalyzed_languages` and a `language_without_analyzer` gap |

A completed named check that finds nothing is not a statement that the service is secure, and an
unanalysed language produces no findings at all. That silence is **not** a clean result.

> **Tell your agent:** "Run `websec doctor .` and `websec capabilities`. Tell me which scanners are
> missing, and which languages in this repository fall into full recon, a named-check profile, or
> no analysis at all according to docs/reference/languages.md. Do not install anything without
> asking me."

## 3. Scope out non-product code first

Most real repositories carry test suites, fixtures, seed data and load-test harnesses, often with
planted fake credentials. Scope these out *before* the first report, or the first report will be
mostly noise.

```bash
websec init --dry-run    # print the proposal; write nothing
websec init              # write .websec-ignore
```

`init` walks the repository (to a depth of four directories) and proposes a directory only if
its name is on a fixed list of conventional non-product names (`tests`, `fixtures`, `seed`,
`examples`, `capacity-test`, `load-test`, `benchmarks`, `third_party` and so on) **and** it
actually holds files. Every proposed line carries its file count, and the summary says how much of
the analysed surface the proposal would remove (`covers N of M analyzed file(s)`). If that number
is most of your repository, the proposal is too aggressive. Edit it.

If a `.websec-ignore` already exists, `init` refuses to overwrite it and exits `2`, because that
file may hold reviewed `fingerprint:` acknowledgements. Pass `--force` only when you mean to replace
it.

Things `init` does not propose:

- Directories the walker already skips entirely, such as `node_modules`, `vendor`, `dist`, `build`,
  `out`, `target`, `coverage`, `.next` and `security`. If real product code lives in a directory
  with one of these names, it is **not analysed**. The skip is counted in `coverage.json` under
  `files.skipped_counts.skip_directory`.

Pick the right scoping tool for each case:

| Tool | Effect | Use it for |
|---|---|---|
| Fixture auto-scoping (default) | Fixture/example routes move to `fixture_endpoints` and are not probed. Under `--scan`, secrets in test files are demoted to LOW and annotated, never dropped. Fixture manifests do not drive framework detection. | nothing to do; `--include-fixtures` turns it off |
| `--exclude '<glob>'` (repeatable) | Removes a path from recon **and** the static scanners | generated code or directories you never want read |
| `.websec-ignore` path line | Drops matching findings from the ledger after analysis; the count stays in `suppressed` | committed, persistent scoping |
| `.websec-ignore` `fingerprint:` line | Keeps one finding visible but not gating, with a required reason | a reviewed false positive or accepted risk |

> [!NOTE]
> Auto-scoping does not demote everything in a test directory. Recon findings such as a hard-coded
> fallback signing secret in `tests/fixtures/` keep their full severity. Scope those paths with
> `.websec-ignore` or `--exclude` if they are not your product.

The full `.websec-ignore` grammar, including how patterns match, is in
[triage and suppression](triage-and-suppression.md#websec-ignore-reference). When you write a
`category:` line, copy the category name from the `category` field in `findings-ledger.json`
(for example `secret` or `sca`).

> **Tell your agent:** "Run `websec init --dry-run` and show me each proposed entry with its file
> count and the 'covers N of M' total. For each entry, tell me whether the directory contains
> anything that ships to production. Write the file with `websec init` only after I approve, and
> never use `--force`."

## 4. First run: recon only, then with scanners

Run the core pass first. It needs nothing but the code:

```bash
websec run .
```

Read three artifacts in `websec-out/latest/`:

| Artifact | Read it for |
|---|---|
| `AGENT-BRIEFING.md` | The handoff to your agent: surface, access-control map, targeting, findings, staged probes |
| `REPORT.md` | The human record: executive summary, §1 findings ledger, §1a clustered view, §1b acknowledged findings |
| `coverage.json` | What was and was not examined: `execution_complete`, `gaps`, `files.unanalyzed_languages`, skipped directories |

Then add the static scanners you have installed:

```bash
websec run . --scan
websec run . --scan --scanners trivy,gitleaks   # named scanners become required
```

The console ends with one of three banners. Each means something different:

| Banner | Meaning |
|---|---|
| `REQUESTED CHECKS COMPLETED` | Everything you asked for ran. It does **not** mean the code is safe, and some languages may still be unanalysed. |
| `PARTIAL SCAN — REQUESTED CHECKS INCOMPLETE` | Something you asked for did not run. The attempt is kept in its own run directory and `latest` is not moved. |
| `NO ANALYZABLE SOURCE` | Source files exist but websec has no analyzer for any of them. An empty findings list means *not checked*. |

Keep completeness and cleanliness apart. `coverage.json` records `execution_complete` (did the
requested checks run), and its `limitation` field states that completed execution does not prove the
absence of vulnerabilities. A quick look:

```bash
jq '{execution_complete, gaps: [.gaps[].kind], unanalyzed: .files.unanalyzed_languages}' \
  websec-out/latest/coverage.json
```

See [outputs](../reference/outputs.md) for every artifact and field.

> **Tell your agent:** "Run `websec run .` and then `websec run . --scan`. For each run, report the
> final coverage banner, every entry in `coverage.json` `gaps`, and any `unanalyzed_languages`.
> Do not call the repository clean if any language was unanalysed or any requested check did not
> complete."

## 5. Triage the first report

Work from the clustered view, not the raw count. REPORT.md §1a groups findings by detector rule (and
history-only secrets by the commit that removed them), so thirteen sites of one pattern read as one
issue with thirteen places to fix. Clusters are a **view, not a filter**: every site still has its
own fingerprint and still gates on its own.

For each finding or cluster, decide one of four outcomes:

| Outcome | Action |
|---|---|
| Real issue | Fix it, re-run, confirm the finding is no longer observed |
| Not your product | Add a path line to `.websec-ignore` (step 3) |
| Reviewed false positive or accepted risk | Add a dated `fingerprint:` acknowledgement with a reason |
| The detector is wrong | Also record it with `websec feedback` so it can be fixed upstream |

Useful signals on each finding in `findings-ledger.json`: `severity`, `calibrated` (a measured
`P(real)` with interval and sample size), `triage.disposition` (`agent-fixable` or
`human-required`), and `likely_filtered` with `filter_reason` for classes a reviewer usually drops.
None of these change what gates. To learn what a class means and how to confirm it:

```bash
websec explain ssrf
websec explain --list
```

Acknowledge a reviewed finding by its fingerprint, with an expiry and a reason:

```text
fingerprint:3f080182df0d1a4d expires:2026-12-31  # headers set by the CDN edge config, see infra/cdn.tf
```

Report a wrong detector. This is offline and metadata-only by default, and it does **not**
suppress anything:

```bash
websec feedback --fingerprint <fp> --verdict false-positive \
  --reason "url is validated against an allowlist in middleware"
```

[Triage and suppression](triage-and-suppression.md) covers every field, acknowledgement state and
feedback option.

> **Tell your agent:** "Read `websec-out/latest/REPORT.md` starting with §1a. For each cluster,
> propose fix, scope out, acknowledge, or report as a false positive, with your evidence. Do not
> add any `.websec-ignore` line or run `websec feedback` until I approve the specific entry. Every
> acknowledgement must have a reason and an `expires:` date."

## 6. Record a baseline

Once triage is done, run again and keep the resulting ledger as your baseline. From then on, only
findings that are **new**, **changed** (severity went up, or the CVE newly appears in CISA KEV) or
**reopened** (an acknowledgement expired or became invalid) count toward the gate.

```bash
websec run . --scan --require-complete
cp websec-out/latest/findings-ledger.json <baseline-dir>/findings-ledger.json

# later runs
websec run . --scan --baseline <baseline-dir>/findings-ledger.json --fail-on high
```

The console reports `N new · N unchanged · N no longer observed`. Identities are semantic (attack
class, category, location without line number, rule, package, CVE and similar), so moving code
within a file does not create a "new" finding. A finding that disappears is reported as **no longer
observed**, which is not proof of a fix. A malformed or unreadable baseline makes the requested
execution incomplete (exit `3`) rather than silently gating everything or nothing.

Store the baseline where your team keeps review records (a protected path, or an artifact your CI
can read). The ledger contains finding titles, paths and evidence, so review it before committing
it anywhere.

> **Tell your agent:** "Run `websec run . --scan --require-complete`. If it completes, copy
> `websec-out/latest/findings-ledger.json` to the baseline location I give you and summarise its
> totals by severity. If it does not complete, stop and show me `coverage.json` gaps instead."

## 7. Roll out gating in phases

Tighten in three phases. Move to the next only when the current one is quiet and trusted.

| Phase | Local | CI | Fails the build on |
|---|---|---|---|
| **Observe** | `websec hooks install` (advisory post-commit) | `websec run . --require-complete` | only toolchain/coverage problems (exit `3`) |
| **Warn** | `websec hooks install --agent` (agent-loop gate) | `websec run . --require-complete --fail-on high --baseline <ledger>` in a job that is not yet required | nothing blocks merges; failures are visible |
| **Block** | `websec hooks install --pre-push` | the same command as a **required** status check, or PR mode with `--diff` | new HIGH+ findings, or incomplete execution |

PR mode scopes the gate to files the branch changed (three-dot `base...HEAD`) and writes exact hunk
ranges to `diff-scope.json`. Make sure the base ref exists in the CI checkout. An unknown ref is
recorded as a coverage gap and the run continues unscoped.

```bash
websec run . --diff origin/main --fail-on high --require-complete
```

> [!WARNING]
> Run `--diff` with the **repository root** as the target. When the target is a subdirectory, the
> changed-file paths from Git (relative to the repository root) do not match finding locations
> (relative to the target), so every finding is classed as untouched and the scoped gate passes.
> See [monorepo](monorepo.md#root-run-vs-subdirectory-run).

Exit codes keep "vulnerability" and "broken toolchain" apart:

| Code | Meaning |
|---|---|
| `0` | the gate ran and nothing met the threshold (not proof of protection) |
| `1` | findings at or above `--fail-on`; if the run was also incomplete, the count is a floor |
| `2` | usage or configuration error; nothing was scanned |
| `3` | requested checks did not complete, or `--require-analyzed` found nothing analysable |

The agent-loop gate (`websec gate`, installed as a `PostToolUse` hook by `websec hooks install
--agent`) checks only the files just changed. It defaults to `--fail-on medium`, writes no
artifacts and never advances a baseline. It fails open, loudly, if it cannot run. Local hooks of any
kind are developer ergonomics, not controls: settings and hook files are editable. Enforcement
belongs in a server-side required status check.

CI specifics: [GitHub Actions](ci/github-actions.md), [other CI](ci/other-ci.md),
[pre-commit and Git hooks](ci/pre-commit-and-git-hooks.md).

> **Tell your agent:** "Add a CI job that runs `websec run . --require-complete` and uploads
> `results.sarif`, without `--fail-on`. Do not make it a required check. Separately, run
> `websec hooks install --agent` and show me the resulting `.claude/settings.json` change. Do not
> install the pre-push hook yet."

## 8. Decide how the policy ages

A suppression policy that never expires drifts into a list of things nobody remembers deciding.
Agree on these rules up front:

- **Date every acknowledgement.** `fingerprint:<fp> expires:YYYY-MM-DD  # reason` stays active
  through the expiry date. After that it excuses nothing: the finding returns to the gate with a
  `reopened_reason`. A line with no reason, or a malformed expiry, never excused anything in the
  first place. An undated acknowledgement is accepted as a legacy entry that never expires. Avoid
  it.
- **Review on a cadence.** Every ledger carries `acknowledgement_history` with each entry's state
  (`active`, `expired`, `malformed`, `missing-reason`, `legacy-no-expiry`):

  ```bash
  jq '.acknowledgement_history[] | {fingerprint, state, expires, reason}' \
    websec-out/latest/findings-ledger.json
  ```

  To hand reviewed acknowledgements to an auditor, export them as a claimspec `ignore` document.
  Path and category lines carry no reason, so they are counted as omitted rather than exported:

  ```bash
  websec init --claimspec websec-acks.json
  ```

- **Refresh threat intelligence deliberately.** EPSS and CISA KEV data are read from a local cache.
  Refreshing is an explicit network action that sends no project data. Reassessing an existing
  ledger is offline, and a newly exploited, acknowledged CVE can reopen:

  ```bash
  websec intel status
  websec intel refresh
  websec intel reassess --ledger <baseline-dir>/findings-ledger.json --out reassessment.json
  ```

  Reassessment updates known CVEs only. Finding new dependency CVEs needs a fresh `--scan`.
- **Re-baseline on purpose.** Replace the stored baseline after a triage cycle or a websec upgrade,
  never automatically from an advisory or failed run. See [upgrading](../upgrade.md).

> **Tell your agent:** "List every `fingerprint:` entry in `.websec-ignore` with its state from
> `acknowledgement_history`. Flag entries that are expired, missing a reason, malformed, or have no
> `expires:` date, and propose a dated replacement for each. Do not change the file until I
> approve."

## Existing-project examples

### Python/Django monolith

Django URL configurations and Python web frameworks are in the full-recon tier. Bandit is
auto-selected for Python when installed. A typical first week:

```bash
websec init --dry-run                         # usually proposes tests/, fixtures/, seed data
websec run . --scan                           # Bandit runs here if installed
websec run . --scan --scanners bandit --require-complete   # once Bandit is part of the toolchain
```

Expect the tenant boundary candidates and unguarded write endpoints in the briefing to need human
confirmation. These are leads, not verdicts.

### Node/Express or Next.js app

Express route guards, router-mount auth and Next.js configuration are read directly. A Next.js app
with no `headers()` block in `next.config.*` gets a MEDIUM `nextjs-no-security-headers` finding,
and response-header findings (CSP, HSTS, clickjacking) are LOW and architectural. A static scan
cannot see your CDN or edge. If the edge sets those headers, verify them against the live response
and acknowledge the finding with a dated reason that names where the headers are configured.

### Monorepo

Run from the root. Services are separated by their nearest manifest, `websec init` finds nested
directories such as `backend/capacity-test/`, and `--diff` works only with a root target. See
[monorepo](monorepo.md) for service boundaries, per-service CI and what changes when you point
websec at a subdirectory.

### Polyglot repository with an unanalysed language (Elixir)

A repository with a Node API and an Elixir billing service still produces a complete run, because
nothing websec was asked to do failed. The Elixir files were simply never read. Example output from
a small synthetic repository:

```text
> **REQUESTED CHECKS COMPLETED** — 12 files read; 8 code files selected.
> Completion describes execution, not complete protection. See `coverage.json` for scope and limits.
> Partially outside coverage: no analyzer for elixir (2). Those files were never read.
```

`--require-analyzed` does not trip here. It fires only when *no* source could be analysed, which
is what an Elixir-only repository gets (exit `3`, `NO ANALYZABLE SOURCE`). For a mixed repository,
gate on the coverage record yourself, using a fresh `--out` per CI job so `latest` can only point at
this job's completed run:

```bash
websec run . --out websec-ci --require-complete --fail-on high
jq -e '(.files.unanalyzed_languages // {}) | length == 0' websec-ci/latest/coverage.json
```

The second command exits non-zero while any language is unanalysed. Either keep it as a reminder
that those services need another reviewer, or drop it once you have one in place.

## Next steps

- [Triage and suppression](triage-and-suppression.md): every `.websec-ignore` rule and ledger field
  used in triage.
- [Monorepo](monorepo.md): service boundaries and per-service runs.
- [GitHub Actions](ci/github-actions.md) and [other CI](ci/other-ci.md): wire the gate.
- [AI agents](ai-agents.md): briefing hand-off, the agent-loop gate and MCP.

## See also

- [New projects](new-projects.md): the same setup for a repository on day one.
- [CLI reference](../reference/cli.md) and [configuration](../reference/configuration.md).
- [Methodology](../METHODOLOGY.md): the reasoning behind every check.

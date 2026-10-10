# Run websec in GitHub Actions

This guide sets up websec-validator in GitHub Actions. When you finish, every pull request runs a
security review from a pinned, reviewed engine revision. The build fails on findings at your chosen
severity, an incomplete run never reads as a pass, and you can optionally see results inline in
Code Scanning.

Two building blocks exist:

- The composite **[`action.yml`](../../../action.yml)** at the repository root.
- A reviewed, inactive workflow **[`security-review.yml.example`](../../integrations/security-review.yml.example)**.
  It wires the Action with a separate engine checkout. This guide starts from it and does not
  replace it. Its full security contract is in [integrations/README.md](../../integrations/README.md).

## Before you start

- Pick a **reviewed engine revision**: a full 40-character commit SHA of `raccioly/websec-validator`
  that you have inspected. This guide writes it as `<reviewed-commit-sha>`. The shape of a SHA is
  validation, not trust; you must review the revision itself. Use a reviewed commit from 0.14.0 or
  later. The historical `v0.13.0` tag does not contain the hardened Action.
- Decide where results go. Workflow artifacts are the default in the example. Code Scanning is a
  separate opt-in that needs `security-events: write`.
- Reports can contain sensitive source evidence. Review who can read your artifacts and how long
  they are kept.

## Action inputs and outputs

Inputs, from [`action.yml`](../../../action.yml):

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Repository or subdirectory to scan |
| `scan` | `"false"` | Also run the static scanners present on the runner (Trivy, Gitleaks, Semgrep and so on) |
| `fail-on` | `""` | Gate at `critical`, `high`, `medium` or `low`. Empty disables the severity gate; `require-complete` still applies |
| `baseline` | `""` | Prior `findings-ledger.json`; gate only on findings new, changed or reopened since that ledger |
| `upload-sarif` | `"true"` | Upload `results.sarif` to Code Scanning |
| `out` | `websec-out` | Output directory |
| `require-complete` | `"true"` | Fail incomplete requested checks even with no `fail-on` |
| `scanners` | `""` | Comma-separated scanners to **require**; needs `scan: "true"` |

`scan` and `require-complete` must be exactly `true` or `false`. Inputs containing newlines or NUL
are rejected. Inputs pass to the CLI as an argument array, never interpolated into shell code.

Outputs:

| Output | Meaning |
|---|---|
| `run-directory` | The exact current attempt, including an incomplete attempt |
| `sarif-file` | SARIF from this attempt; never from an earlier `latest` run |
| `execution-complete` | `"true"` or `"false"`: whether the requested execution completed |

What the Action does, step by step:

1. Sets up Python 3.11 with a pinned `actions/setup-python`.
2. Installs websec from the Action's own checkout (`github.action_path`), not from the target
   repository.
3. Runs `websec run <path> --out <out> --format json`, adding `--require-complete`, `--scan`,
   `--fail-on`, `--baseline` and `--scanners` according to the inputs. It then selects the current
   attempt's directory from the JSON envelope.
4. When `upload-sarif` is `true` and a SARIF file exists, uploads it to Code Scanning under category
   `websec-validator`. This step runs under `always()`, so it also uploads after a failing or
   incomplete scan. The SARIF records whether execution completed
   (`invocations[].executionSuccessful`).

> [!NOTE]
> The Action has no input for `--diff`, `--sbom` or `--sarif` import. For those, call the CLI
> directly. See [PR mode with `--diff`](#pr-mode-with---diff).

## Step 1: Start from the reviewed workflow example

[`security-review.yml.example`](../../integrations/security-review.yml.example) runs on
`pull_request`, on `workflow_dispatch` and weekly. Its design choices:

- It validates that the repository variable `WEBSEC_REVIEWED_SHA` is a 40-character SHA before
  doing anything else.
- It checks out the **engine** (`raccioly/websec-validator` at that SHA) into `.websec-engine`, and
  the **review target** into `.websec-target`, as data. Both checkouts use
  `persist-credentials: false`.
- It runs the Action from `./.websec-engine` with `path: .websec-target`, `scan: "false"`,
  `require-complete: "true"`, `fail-on: high` and `upload-sarif: "false"`.
- It uploads only the current attempt's run directory as a 7-day artifact, including partial
  results. Missing output never falls back to `latest`.
- It uses `pull_request`, not `pull_request_target`, with `contents: read`.

To adopt it:

1. Review the engine revision you plan to pin.
2. In the target repository, create the repository variable `WEBSEC_REVIEWED_SHA` with that full
   SHA (**Settings > Secrets and variables > Actions > Variables**).
3. Copy the example to `.github/workflows/security-review.yml`, review it, and commit it.
4. Open a pull request and confirm the job ran. Download the `websec-<run_id>-<attempt>` artifact and
   read `coverage.json` before trusting an empty finding list.

**Why the engine stays separate from the target.** The target is untrusted input. Its package
installer, tests, Git hooks and any local Action it contains are never invoked. Never run
`uses: ./` from the target's own checkout, and never install websec from the target's tree. Doing
either would let a pull request change the code that reviews it.

## Step 2 (optional): Upload SARIF to Code Scanning

Every `websec run` writes `results.sarif` (SARIF 2.1.0). Uploaded, each finding appears inline on
the pull request diff and in the Security tab, ranked by a security-severity band, with its
CWE/ASVS/OWASP citation and remediation.

Turn it on in the example's review step and grant the permission at the job level:

```yaml
jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required to upload SARIF
      actions: read            # required by the upload on private repositories
    steps:
      # ... the example's SHA check and two checkouts, unchanged ...
      - name: Review target
        id: audit
        uses: ./.websec-engine
        with:
          path: .websec-target
          out: ${{ runner.temp }}/websec-review
          scan: "false"
          require-complete: "true"
          fail-on: high
          upload-sarif: ${{ github.event_name != 'pull_request' }}
```

Gotchas:

- **Fork pull requests get a read-only token**, so the upload fails there. The expression above
  uploads only on non-PR events, such as the scheduled run or a manual dispatch. Do **not** switch
  to `pull_request_target` or other privileged fork execution to work around this.
- Code Scanning availability on private repositories depends on your GitHub plan.
- SARIF locations are written relative to the scanned `path`. Scan the root of the target checkout
  so annotations line up with repository files.

### The shorter form

If you don't need the two-checkout layout, you can call the Action by its pinned SHA. GitHub fetches
the Action outside your workspace, so it stays separate from the target source:

```yaml
name: websec
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
jobs:
  websec:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      actions: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1 (same pin as the example)
        with:
          persist-credentials: false
      - id: websec
        uses: raccioly/websec-validator@<reviewed-commit-sha>
        with:
          fail-on: high
          upload-sarif: ${{ github.event_name == 'push' }}
```

This form writes `websec-out/` inside the checked-out workspace. Retain the `run-directory` output
as an artifact if you need the full report.

## Step 3: Choose your gates

| Flag (CLI) / input (Action) | Effect |
|---|---|
| `--fail-on <severity>` / `fail-on` | Exit `1` if any finding at or above that severity remains |
| `--require-complete` / `require-complete` | Exit `3` if a requested check did not complete, even with no severity gate |
| `--baseline <ledger>` / `baseline` | New, changed and reopened findings count toward the gate; unchanged ones don't |
| `--scan --scanners a,b` / `scan` + `scanners` | Run and **require** the named scanners |

Details that matter in CI:

- **Without `--fail-on` or `--require-complete`, an incomplete run exits `0`.** The Action defaults
  `require-complete` to `true` for this reason. Keep it.
- **Naming a scanner requires it.** A selected scanner that isn't installed makes the run
  incomplete, not clean: `scan: "true"` with `scanners: trivy,osv-scanner` exits `3` with
  `trivy: unavailable` in `coverage.json` if Trivy is missing. GitHub-hosted runners don't ship
  these scanners, so install the reviewed executables in an earlier step. Unselected optional
  scanners that are missing are reported as unavailable, not as gaps.
- **`scanners` without `scan: "true"` is a usage error** (exit `2`). Nothing is scanned and no SARIF
  is produced.
- **Baselines.** Supply the prior ledger from a location you control and trust, for example an
  artifact kept from a reviewed default-branch run. A malformed or unreadable baseline makes the run
  incomplete. A finding that disappears is recorded as "no longer observed", which does not prove a
  repair. For lifecycle states, see [triage and suppression](../triage-and-suppression.md).
- **Toolchain preflight.** `websec doctor` reports each scanner's version and exits `2` if a
  selected scanner is too old for the invocation websec builds. Run it before trusting a `--scan`
  result.

## Exit codes

"You have a vulnerability" and "the toolchain is broken" need opposite responses, so they never
share a code:

| Code | Meaning | What to do |
|---|---|---|
| `0` | The gate ran and nothing met the threshold | Ship. This does not prove protection |
| `1` | Findings at or above `--fail-on` | A fact about the code: fix the findings |
| `2` | Usage or configuration error, or `websec doctor` found an incompatible scanner | Nothing was scanned: fix the invocation or toolchain |
| `3` | Requested checks did not complete (or `--require-analyzed` found nothing analyzable) | Not a pass: read `coverage.gaps` in `coverage.json` |

A run that is **both** gate-failing and incomplete exits `1`; the definite fact wins. It says so on
stderr, because the finding count in that case is a floor, not a total. Nothing is lost by the
collapse: `gate.failure_kind` in `findings-ledger.json` records the exact combination, one of
`findings`, `incomplete`, `findings+incomplete` or `no-analyzable-source`.

> [!WARNING]
> **Upgrading from before 0.17.0:** exit `2` used to mean *incomplete execution*. Incomplete is now
> `3`, and `2` means usage or configuration error. A job that tested for `2` must test for `3`, or
> read `coverage.execution_complete`, which is unchanged.

Inside the Action, a nonzero exit fails the step. The SARIF upload still runs because of `always()`,
and `execution-complete` tells a later step which kind of failure happened.

## PR mode with `--diff`

`--diff <ref>` scopes a run to what changed versus `<ref>`, using three-dot (`<ref>...HEAD`)
semantics, the same view a pull request shows. Findings are tagged `in-changed-file` or
`in-changed-hunk`. Exact added-line ranges go to `diff-scope.json`. `--fail-on` narrows to changed
files, so a pull request doesn't fail on debt it didn't touch.

The Action has no `diff` input, so call the CLI. This example keeps the example's two-checkout
layout, fetches full history so the base branch resolves, and passes the base ref as data through
`env`. *Illustrative; adapt and test it in your repository:*

```yaml
name: websec PR diff
on: pull_request
permissions:
  contents: read
jobs:
  diff-review:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      # Keep the example's "Require a reviewed engine revision" step here.
      - name: Check out trusted engine separately
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          repository: raccioly/websec-validator
          ref: ${{ vars.WEBSEC_REVIEWED_SHA }}
          path: .websec-engine
          persist-credentials: false
          submodules: false
      - name: Check out review target as data
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          path: .websec-target
          fetch-depth: 0
          persist-credentials: false
          submodules: false
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0 (same pin as action.yml)
        with:
          python-version: "3.11"
      - name: Install the trusted engine
        run: python -I -m pip install --disable-pip-version-check ./.websec-engine
      - name: Review changed files
        env:
          BASE_REF: ${{ github.base_ref }}
        run: >
          websec run .websec-target --diff "origin/$BASE_REF"
          --fail-on high --require-complete --out "$RUNNER_TEMP/websec-review"
```

If the ref doesn't resolve, for example because history is shallow, websec records a `diff` coverage
gap and runs **unscoped** over the whole repository. Under `--require-complete` that exits `3`, not
a silent pass. To keep the artifacts, upload the run directory as the example does.

## Pin and update the engine

- Pin by full commit SHA (`<reviewed-commit-sha>`), never a floating branch or tag.
- A pinned engine gains no new detection rules until you review and pin a newer revision
  deliberately. The default workflow doesn't refresh threat intelligence or scan a vulnerability
  database.
- Scheduled runs can be delayed or disabled by GitHub; they don't guarantee continuous coverage.
- To review changing CVEs, provision reviewed scanner executables and databases, set `scan: "true"`,
  and name the required `scanners` so a missing tool fails visibly.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Exit `3` with no findings | A requested check didn't run. Read `coverage.gaps` in the run's `coverage.json` |
| Exit `2`, no SARIF | Usage error, such as `scanners` without `scan: "true"` or an invalid `scan` value |
| SARIF upload fails on PRs from forks | Read-only token; upload on push or schedule instead |
| `--diff` reports an unknown ref | Shallow clone; use `fetch-depth: 0` and an `origin/<base>` ref |

For more, see [troubleshooting](../../troubleshooting.md).

## See also

- [Other CI systems](other-ci.md): GitLab, Azure DevOps, Jenkins, CircleCI, Docker.
- [Pre-commit and git hooks](pre-commit-and-git-hooks.md): local gates before push.
- [Integrations contract](../../integrations/README.md): the full security model of these examples.
- [Outputs reference](../../reference/outputs.md) and [CLI reference](../../reference/cli.md).

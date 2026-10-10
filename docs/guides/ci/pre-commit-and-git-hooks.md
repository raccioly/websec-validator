# Pre-commit and git hooks

This guide adds local security guardrails that run before code leaves your machine. When you finish,
you will have either a [pre-commit framework](https://pre-commit.com/) hook or websec's native git
hooks: an advisory post-commit review, a blocking pre-push gate, or both. You will also know how
each one decides what to block.

Local hooks are developer ergonomics, not enforcement. `git push --no-verify`, an uninstalled hook
or a deleted hook skip them, and websec cannot see that happen. For enforcement, run
`websec run --fail-on ...` as a required CI check. See [GitHub Actions](github-actions.md).

For the full security contract and validation limits behind both options, see
[integrations/README.md](../../integrations/README.md). This page is the how-to.

## Which option to choose

| | pre-commit framework hook | Native `websec hooks` |
|---|---|---|
| Setup | `.pre-commit-config.yaml` entry | `websec hooks install [--pre-push]` |
| Engine | pre-commit installs the engine repository at a pinned `rev` | The websec package you installed |
| Stages | `pre-commit`, `pre-push`, `manual` | Advisory `post-commit`; blocking `pre-push` |
| Default gate | Incomplete execution or HIGH/CRITICAL findings fail | Pre-push: incomplete execution or HIGH+ findings **new since the accepted baseline** fail |
| Baseline | None: every run gates on all current findings | Remembers the last successful gate under the same policy |
| Output | `websec-out/` in the repository (gitignore it) | `$GIT_DIR/websec-guardrail/` |
| Bypass | pre-commit's own mechanisms | `WEBSEC_SKIP_HOOK=1`, recorded |

Choose **one dispatcher per git event**. Don't install both a pre-commit framework `pre-push` hook
and the native `--pre-push` hook, and don't replace an existing hook dispatcher blindly.

## Option A: the pre-commit framework

The repository root publishes [`.pre-commit-hooks.yaml`](../../../.pre-commit-hooks.yaml) with one
hook, `websec-security`:

- `entry: python -I -m websec_validator.cli run .`, isolated Python, scanning the repository root.
- `args: [--require-complete, --fail-on, high, --out, websec-out]`
- `pass_filenames: false` and `always_run: true`, so it is a whole-repository check that also
  catches changes such as deletions.
- `require_serial: true`, `stages: [pre-commit, pre-push, manual]`, minimum pre-commit `3.2.0`.

### Remote configuration (trusted engine at a pinned revision)

pre-commit builds a Python environment from the **engine repository** at `rev`, not from the
application you are scanning.

1. Pick a reviewed full commit SHA of `raccioly/websec-validator` that contains the manifest (0.14.0
   or later). Don't use a floating branch or the old `v0.13.0` tag.
2. Add to `.pre-commit-config.yaml`:

   ```yaml
   repos:
     - repo: https://github.com/raccioly/websec-validator
       rev: <reviewed-commit-sha>
       hooks:
         - id: websec-security
   ```

3. Add `websec-out/` to `.gitignore`.
4. Validate and try it manually before activating anything:

   ```bash
   pre-commit validate-config
   pre-commit run websec-security --all-files --hook-stage manual
   ```

5. After reviewing the result, opt in to the stages you want:

   ```bash
   pre-commit install --hook-type pre-commit --hook-type pre-push
   ```

### Local configuration (trusted local checkout)

To use an engine you already installed in a trusted virtualenv, start from
[`pre-commit-config.yaml.example`](../../integrations/pre-commit-config.yaml.example). It uses
`repo: local` with `language: system`, so pre-commit installs nothing. Replace the placeholder with
the absolute path to your trusted venv's interpreter:

```yaml
entry: '"/ABSOLUTE/PATH/TO/TRUSTED/WEBSEC-VENV/bin/python" -I -m websec_validator.cli run .'
```

The placeholder is deliberately not runnable until you configure it. Never point it at the
application's own Python, its editable package or its install scripts.

### Caveats

- **No `--scan` by default.** Optional external analyzers don't run in this hook. Noir route discovery
  may run if it is installed. Check the coverage manifest for unavailable or manual scope.
- **No baseline acceptance.** Each run gates on all current HIGH and CRITICAL findings, not just new
  ones.
- **Not an exact index snapshot.** At the `pre-commit` stage, pre-commit temporarily hides unstaged
  changes to tracked files, but websec can still see untracked files under its normal policy. Manual
  and pre-push runs inspect the working tree, not every pushed Git object. The framework manages its
  own temporary stash.
- **Review config changes before running them.** pre-commit can execute any configured hook, not
  only this one.

## Option B: native `websec hooks`

```bash
websec hooks install              # advisory post-commit
websec hooks install --pre-push   # blocking pre-push gate
websec hooks status               # which websec sections are present
websec hooks uninstall            # remove websec's section from both hooks
```

`--path <dir>` targets a repository other than the current directory. The commands need a git
repository and exit `2` if none is found.

### Post-commit (advisory)

After each commit, websec runs `websec run --require-complete` against the working tree. It prints
the exit code and the current attempt's path, and **always exits `0`**. It informs; it never blocks,
and it never changes the accepted baseline.

### Pre-push (blocking)

Before each push, websec runs `websec run --require-complete --fail-on <threshold>` against the
working tree. Any nonzero result blocks the push: findings, incomplete execution or a usage error. A
run that exits `0` but reports incomplete execution is treated as a failure.

### Accepted-baseline semantics

The pre-push gate remembers what it has already approved:

1. A pre-push gate that **succeeds** (exit `0`, execution complete) stores its ledger as the
   accepted state, bound to its **policy**: severity threshold, whether scanners ran, and which
   scanners were required.
2. The next pre-push gate under the **same policy** runs with that ledger as `--baseline`. Only
   findings that are new, changed or reopened since then count toward the threshold.
3. The **first** gate, or any gate after a **policy change**, has no matching baseline, so it checks
   all current findings.
4. Advisory post-commit runs and failed gates **never** advance the accepted state. Retrying an
   unchanged failed gate keeps failing until you fix or acknowledge the findings. See
   [triage and suppression](../triage-and-suppression.md).

If your repository already has HIGH findings, the first `--pre-push` gate blocks. That is by design:
nothing gets accepted without a successful gate.

### Environment variables

Verified in [`hooks.py`](../../../src/websec_validator/hooks.py):

| Variable | Default | Effect |
|---|---|---|
| `WEBSEC_HOOK_FAIL_ON` | `high` | Pre-push threshold: `critical`, `high`, `medium` or `low`. It is part of the policy, so changing it means no accepted baseline matches |
| `WEBSEC_HOOK_SCAN` | unset (recon only) | `1` runs the available static scanners (`--scan`) |
| `WEBSEC_HOOK_SCANNERS` | empty | Comma-separated scanners to **require** (`--scanners`). Needs `WEBSEC_HOOK_SCAN=1` |
| `WEBSEC_SKIP_HOOK` | `0` | `1` skips the native hook for that invocation |

An invalid threshold, or `WEBSEC_HOOK_SCANNERS` without `WEBSEC_HOOK_SCAN=1`, makes execution
incomplete. That blocks pre-push; post-commit stays advisory.

```bash
WEBSEC_HOOK_FAIL_ON=medium git push                         # stricter threshold for this push
WEBSEC_HOOK_SCAN=1 WEBSEC_HOOK_SCANNERS=gitleaks git push   # require Gitleaks for this push
```

A one-off variable is a policy change. That push is checked against all current findings, and if it
succeeds, its ledger becomes the accepted state under the new policy. The next push with your usual
settings then has no matching baseline and checks everything again. For a lasting change, set the
variables in your shell profile rather than per push.

### Bypassing

`WEBSEC_SKIP_HOOK=1 git push` is an explicit one-off override. No scan runs and the accepted baseline
doesn't move. An honored bypass is recorded in `$GIT_DIR/websec-guardrail/bypass.jsonl` with the
hook, `HEAD` and a timestamp. websec cannot observe `--no-verify`, an uninstalled hook or a deleted
hook, so **an empty bypass log is not evidence that no bypass happened**.

The agent-loop `PostToolUse` hook deliberately does **not** honor `WEBSEC_SKIP_HOOK`. See
[AI agents](../ai-agents.md#agent-loop-gate-posttooluse).

### Where results go

Native hooks write to `$GIT_DIR/websec-guardrail/`, not to `websec-out/`:

| Path | Contents |
|---|---|
| `runs/<generated>/` | Each attempt's full artifacts. The 5 most recent are kept, plus `latest` and the current attempt |
| `latest` | Last completed attempt |
| `hook.log` | stderr of the last run |
| `accepted-state.json` | The policy-bound accepted ledger |
| `bypass.jsonl` | Recorded `WEBSEC_SKIP_HOOK` bypasses |

### How the hook is installed

- **Trusted, isolated launch.** The hook runs isolated Python bound to the installed websec package
  path, including editable source installs. Repository-local modules and `PYTHONPATH` can't replace
  the validator. It prefers the interpreter you installed from and falls back to `python3`.
- **Existing hooks are preserved.** websec inserts a marked section after the shebang of an existing
  `sh`/`bash` hook, and re-installing replaces that section in place. It refuses to modify a hook
  written in another language (`refusing to modify non-shell hook ...; chain websec explicitly`).
- **Hook location.** websec respects worktrees and `core.hooksPath`. With Husky v9, it writes the
  durable user scripts in `.husky/`, not the generated `.husky/_` dispatchers.
- **Uninstall** removes only websec's section, and deletes the hook file if only a shebang remains.

### Gotchas

- **Working tree, not pushed objects.** The native hooks inspect your current working tree, not
  immutable snapshots of every pushed commit.
- **Operations in progress.** During a rebase, merge or cherry-pick, the check is deferred: pre-push
  blocks and post-commit skips.
- **Concurrent runs.** A second gate while one is running fails with `another guardrail is running`.
  If a run was killed, remove the stale `$GIT_DIR/websec-guardrail/running.lock` yourself.
- **Missing runtime.** If no usable Python or websec package is found, pre-push blocks and
  post-commit stays advisory. After moving, reinstalling or upgrading websec into a different
  environment, run `websec hooks install` (and `--pre-push`) again.

## See also

- [Integrations contract](../../integrations/README.md): the security model and validation limits.
- [AI agents](../ai-agents.md): the agent-loop `PostToolUse` gate and `websec gate`.
- [GitHub Actions](github-actions.md) and [other CI systems](other-ci.md): enforcement as a
  required check.
- [Triage and suppression](../triage-and-suppression.md): acknowledging findings with `.websec-ignore`.

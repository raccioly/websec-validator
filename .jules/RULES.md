# Rules for every Jules routine on websec-validator

Read this before any routine file. `AGENTS.md` still applies, except where its *Scheduled agents*
section says this file takes over. The policy that enforces these rules on GitHub is
`.github/scripts/jules_policy.py`; a PR that breaks them is closed or held automatically.

## 1. Preflight decides whether there is work

Run `python3 .jules/preflight.py <routine>` first. It prints `GO` with the one target for this
run, or `STOP: <reason>`.

- **STOP** means end the task now: no changes, no branch, no pull request. Put the reason in the
  task summary.
- **GO** means work on that target only, whatever else you notice. Mention anything else in the
  task summary instead.

## 2. No finding, no pull request

Open a pull request only for a change backed by evidence:

- a missed detection → a test that fails before your change and passes after;
- a false positive → the input that triggers it, plus a test proving the true positive still fires;
- a docs error → the `--help` output or command run that contradicts the docs.

If the routine finds nothing, end the task with a one-paragraph summary. A pull request that
changes nothing, reports that something is up to date, or restates a count is closed on arrival.

## 3. One pull request, titled by the preflight

- Use the `title:` line preflight printed, replacing `<one-line summary>`. The
  `[jules:<routine>] <target>` prefix is how duplicates are detected; do not change it.
- Ten files or fewer. Not a draft: a draft never merges.
- The body has three sections:
  - **Evidence:** the exact commands you ran and their output, before and after.
  - **What changed:** what you changed and why that is the smallest fix.
  - **Dropped:** what you looked at and rejected, and why.

## 4. Before you open the pull request, run

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
npx -y docguard-cli@0.43.0 guard
```

Both must pass. For a change under `src/`, also run the CLI on the bundled demo to prove the run
still completes:

```bash
PYTHONPATH=src python3 -c 'import sys; from websec_validator.cli import main; sys.exit(main(sys.argv[1:]))' demo
```

## 5. Never ask a question: decide, or stop

Nobody answers a scheduled run. A question leaves the task in "waiting for your input" forever,
and the finding is lost with it. That has already happened here: a run found a real missed
command injection (`os.popen(cmd)` with `cmd` a function parameter) and then asked which fix to
take.

When you reach a choice these rules do not settle:

- **Take the pessimistic option** if one is within scope, then continue. Pessimistic means:
  detect more rather than less, never drop a finding, never weaken or delete a test, never turn
  an incomplete run into a complete one, never claim what is not proven.
- **Otherwise, end the task** with no pull request. The task summary has three parts: the
  question; each option with its consequence; the evidence (commands and output). A maintainer
  reads the summary.

## 6. If the suite is red before you change anything

That is your environment, not the code: CI on `main` is green, including a job that runs the
suite under a hostile global git config. Do not fix it. End the task and describe the failure in
the summary. (This exact mismatch once produced 27 copies of the same one-line "fix".)

## 7. The detection contract: strictly no regression

websec's tests are its detection contract. Every change must be quality-monotonic:

- never delete, weaken or rewrite an existing test or assertion; add a new test file instead
  (`tests/test_jules_<routine>_<target>.py`, with every `-` written as `_`, e.g.
  `tests/test_jules_fn_hunt_command_injection.py`);
- a false-positive fix must keep every true positive: add a test where the real vulnerability in
  the same shape still fires, next to the test where the safe code no longer does;
- a missed-detection fix must not add false positives: add a test where the safe variant (the
  parameterised query, the constant argument, the sanitised value) stays quiet.

## 8. Never

- touch `.github/`, `.jules/`, `AGENTS.md`, `CLAUDE.md`, `pyproject.toml`, `action.yml`,
  `Dockerfile`, `skills/`, `.claude-plugin/`, `docs-canonical/`, `specs/` or
  `docs/security-review/`;
- edit `tests/fixtures/**` (deliberately vulnerable sample apps, verified by hand) or
  `src/websec_validator/calibration.json`;
- add a runtime dependency, or a network call to the core pass;
- record a test count, extractor count or any other moving number in prose;
- commit scratch files (`patch.diff`, `commit_message.txt`, notes);
- quote names, paths or text from any private codebase. Use neutral names (`acme`, `example.com`).

## 9. What merges without a maintainer

On a green CI, with no maintainer:

- user docs: `README.md` and `docs/**/*.md`, except `docs/security-review/`;
- purely additive tests under `tests/` (new files, or lines added with none deleted).

Everything else, including every change under `src/`, waits for review. That is expected, not a
failure. At most five Jules pull requests wait at once; past that, preflight answers STOP.

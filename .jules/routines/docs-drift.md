# Routine: docs-drift (weekly, Friday)

Check what the user docs say about one subcommand against what the CLI actually does, and fix the
docs where they are wrong.

Follow `.jules/RULES.md` throughout.

## Steps

1. Run `python .jules/preflight.py docs-drift`. On STOP, end the task. On GO, the `target:` line
   is the one subcommand you check; a nested one is written `intel/refresh` (`websec intel refresh`).
2. Read the truth from the CLI: `python -m websec_validator <subcommand> --help`, and its section in
   `docs/reference/cli.md`.
3. Find every mention of that subcommand in `README.md` and `docs/**/*.md`
   (not `docs/security-review/`).
4. A drift is any of these:
   - a flag the docs describe that the CLI does not accept;
   - a flag whose meaning or default the docs state differently from `--help`;
   - an exit code the docs state differently from what the command returns;
   - an example command that fails or behaves differently when you run it. Run it on a copy of
     the bundled demo (`python -m websec_validator demo` shows the sample) or a small temporary repository.

   These are **not** drift:
   - wording or style;
   - counts of tests, extractors, checks or anything else;
   - version numbers and links;
   - a feature the CLI does not have. That is a feature request; mention it in the summary.
5. If you found no drift, end the task with no pull request.
6. Where the docs are wrong, fix the docs.
   - Edit only `README.md` and `docs/**/*.md` outside `docs/security-review/`.
   - In `docs/i18n/`, fix only the same wrong flag or value; English is authoritative.
   - Where the docs are right and the CLI is wrong, that is a bug: change nothing, and describe it
     in the task summary.
7. Run the checks in `.jules/RULES.md` §4 — `tests/test_docs_reference.py` already fails when a
   documented `websec …` command does not parse — then open the pull request with the preflight
   title.

A docs-only change merges on a green CI without a maintainer.

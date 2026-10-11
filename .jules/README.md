# Google Jules on websec-validator

Jules runs scheduled maintenance routines against this repository. This directory is what it
reads; `.github/scripts/jules_policy.py` is what enforces it on GitHub. Both change only through a
maintainer: a Jules PR that edits `.jules/` is closed as noise.

## Why it is set up this way

Before this, 69 Jules PRs in 60 days merged none. Nine scheduled prompts forced "open one PR"
every run, so the same declined ideas came back (the weak-password-hash extractor about nine
times), counts were re-synced in prose (one "sync" was wrong), and runs that found real defects
stalled on "Jules is waiting for your input". The design below fixes each cause:

| Cause | Fix |
|---|---|
| Every run had to open a PR | Preflight prints `STOP` when there is no work; "no finding, no PR" (RULES §2) |
| Declined work came back | PRs closed unmerged within 60 days block the same target or file set |
| Duplicates worded differently | Duplicates match on the `[jules:<routine>] <target>` tag or the identifying file set |
| Unbounded review queue | At most 5 Jules PRs wait; past that, preflight STOPs and triage closes |
| Runs stalled on a question | RULES §5: decide pessimistically, or stop and summarise |
| Count syncs | Closed as noise; AGENTS.md no longer asks for counts in prose |
| A red sandbox produced fake fixes | `setup.sh` fails, leaving no snapshot, unless the suite is green |

## Jules configuration (web UI)

**Initial setup** (repository → Configuration): enter `bash .jules/setup.sh`, then click
**Run and Snapshot**. Re-snapshot after a Python version change or a large merge.

**Scheduled tasks:** delete any others, then create exactly these three. Each prompt is one line:

| Routine | When | Prompt |
|---|---|---|
| `fp-hunt` | weekly, Monday | `Follow .jules/routines/fp-hunt.md exactly. Read .jules/RULES.md first. If preflight prints STOP, end the task with no changes and no pull request.` |
| `fn-hunt` | weekly, Wednesday | `Follow .jules/routines/fn-hunt.md exactly. Read .jules/RULES.md first. If preflight prints STOP, end the task with no changes and no pull request.` |
| `docs-drift` | weekly, Friday | `Follow .jules/routines/docs-drift.md exactly. Read .jules/RULES.md first. If preflight prints STOP, end the task with no changes and no pull request.` |

**Suggestions and personas** (Sentinel, Bolt, Palette): off. Persona PRs are closed as noise.

**Reactive Mode:** a comment that mentions the agent is an instruction to it. The automation in
`.github/` never mentions it by handle, and maintainers should not either unless they mean it.

## What each routine does

| Routine | Target rotates over | Typical outcome |
|---|---|---|
| `fp-hunt` | every extractor in `REGISTRY` | a held PR: an extractor fix plus paired tests (safe stays quiet, vulnerable still fires) |
| `fn-hunt` | every sink class in `SINKS` | a held PR: a detector fix plus paired tests (vulnerable fires, safe stays quiet) |
| `docs-drift` | every `websec` subcommand | a docs-only PR that merges on green CI |

The rotation starts at the ISO week number and skips targets that are open or were declined in the
last 60 days, so a quiet week costs nothing and the same target is not re-proposed.

## Running preflight yourself

```bash
python .jules/preflight.py fp-hunt     # GO + target, or STOP + reason (exit 3)
```

It reads the public GitHub API and fails closed: if the queue cannot be read, it answers STOP.

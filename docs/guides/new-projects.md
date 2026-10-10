# Setting up websec-validator in a new project

On a new repository, every finding is new, so you can gate from the first pull request with no
baseline to manage. This page wires websec in on day one: agent instructions, a pre-scoped session
context, the agent-loop gate, a committed scope policy and a CI gate. Each step is short and links
to the guide that covers it in depth.

## Prerequisites

- websec-validator installed: `pipx install websec-validator` (Python 3.11+). See
  [installation](../installation.md).
- A Git repository, even an empty one. `websec gate` and `--diff` read Git.

## 1. Keep run artifacts out of Git

`websec run` writes to `./websec-out/` in the current directory by default. It reminds you to ignore
that directory but does not edit `.gitignore` itself:

```bash
echo 'websec-out/' >> .gitignore
```

If you later use the [dynamic phase](dynamic-testing.md), keep its credentials file
(`dynamic-config.json`) out of Git too.

## 2. Teach your agent to use websec

```bash
websec install claude      # or: codex · cursor · gemini · aider · generic
websec install status
```

This writes the standing instruction your agent reads: a skill file for Claude Code
(`.claude/skills/security-pass/SKILL.md`) or Cursor (`.cursor/rules/websec-validator.mdc`), or a
marked block in `AGENTS.md` (Codex, generic), `GEMINI.md` or `CONVENTIONS.md` (Aider). Add `--user`
to install it for every repository, and `--uninstall` to remove it. Commit the project-level files
so the whole team's agents get the same instruction. Details: [AI agents](ai-agents.md).

## 3. Prime every session with the security context (Claude Code)

`websec emit-context` prints a compact `## SECURITY CONTEXT` block (stack, routes, auth model,
tenant candidates, unguarded writes, sinks, top findings, coverage) inside Claude Code's
`SessionStart` envelope. Add it to `.claude/settings.json`:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "websec emit-context \"$CLAUDE_PROJECT_DIR\"" } ] }
    ]
  }
}
```

For other harnesses, `websec emit-context . --markdown` prints the raw block.

## 4. Gate the agent loop

```bash
websec hooks install --agent     # PostToolUse on Write|Edit|MultiEdit in .claude/settings.json
websec hooks status --agent
```

Each file the agent writes is checked by `websec gate` (default threshold `medium`), and a finding
blocks the loop so the agent fixes it on the next turn. The gate writes no artifacts. It fails open,
loudly, if it cannot run. It is developer ergonomics, not a control: the settings file is editable,
so enforcement belongs in CI (step 6).

## 5. Commit a scope policy early

```bash
websec init --dry-run
websec init
git add .websec-ignore
```

On a fresh repository `init` usually finds nothing to scope and writes a commented template. Commit
it anyway. Once the file exists, `init` refuses to overwrite it without `--force`, and every later
`fingerprint:` acknowledgement arrives as a reviewable diff with its reason and `expires:` date. Add
paths as test and fixture directories appear. Grammar and matching rules:
[triage and suppression](triage-and-suppression.md#websec-ignore-reference).

## 6. Gate CI from the first pull request

With no backlog, gate the whole repository on every pull request and make the job a **required**
status check:

```bash
websec run . --require-complete --require-analyzed --fail-on high
```

- `--fail-on high` fails on HIGH or CRITICAL findings (exit `1`).
- `--require-complete` fails if a requested check did not run (exit `3`). This is a toolchain
  problem, not a finding.
- `--require-analyzed` fails if source is present but none of it can be analysed (exit `3`), so an
  unsupported stack cannot look clean. It does not trip on an empty repository.

Add `--scan` once your CI image has the scanners you want, and name them with `--scanners` so a
missing one fails visibly instead of silently. When the repository grows, consider PR mode
(`--diff origin/main`) or a baseline. See [existing projects, step 7](existing-projects.md#7-roll-out-gating-in-phases).
Workflow syntax: [GitHub Actions](ci/github-actions.md), [other CI](ci/other-ci.md).

Optionally, add a local pre-push gate as well:

```bash
websec hooks install --pre-push
```

## Checklist

| Item | Command or file |
|---|---|
| Artifacts ignored | `websec-out/` in `.gitignore` |
| Agent instructions | `websec install <host>` |
| Session context | `SessionStart` → `websec emit-context` |
| Agent-loop gate | `websec hooks install --agent` |
| Scope policy | `websec init`, committed `.websec-ignore` |
| Required CI check | `websec run . --require-complete --require-analyzed --fail-on high` |

## See also

- [Quickstart](../quickstart.md)
- [Adopting websec in an existing project](existing-projects.md)
- [Monorepo](monorepo.md)
- [Pre-commit and Git hooks](ci/pre-commit-and-git-hooks.md)
- [CLI reference](../reference/cli.md)

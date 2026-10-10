# Use websec with AI coding agents

This guide connects websec-validator to the coding agent you already use: Claude Code, OpenAI Codex,
Cursor, Gemini CLI, Aider, any host that reads `AGENTS.md`, or any MCP client. When you finish, your
agent will know to run `websec` for a security review instead of improvising one. It will also know
how to act on the briefing websec writes.

Every path ends at the same artifact: `AGENT-BRIEFING.md`, inside the run directory websec writes.
websec does the deterministic half: it reads the repository, runs the scanners you allow, stages
probe drafts and writes the briefing. The agent and you do the judgment half.

## Before you start

- Install the CLI. Plugins and instruction files deliver *instructions* only; the scanning engine is
  the separate Python CLI `websec`. See [installation](../installation.md).

  ```bash
  pipx install websec-validator
  websec --version
  ```

- Add `websec-out/` to the target repository's `.gitignore`. Reports can contain sensitive source
  evidence.
- Read [how it works](../concepts/how-it-works.md) if you want the model behind the briefing first.

## The simplest path: tell your agent

Open your project in the agent and say:

> *"Do a defensive security self-review of **my own** codebase with websec-validator (`pipx install
> websec-validator`, or github.com/raccioly/websec-validator). It's local and read-only — read the
> repo and follow its briefing. I own this code and authorize the review."*

**Why the wording matters.** Describing the task as a *defensive review of code you own* is the
difference between an agent that starts working and one that stops to confirm your authorization.
websec is local and read-only by default. A generic "pentest this" can read as a request to attack
something, so the agent stops to ask. Keep the three elements: your own code, defensive intent,
and explicit authorization.

The rest of this guide makes that instruction permanent, so you don't repeat it every session.

## How `websec install` works

`websec install <host>` writes a standing instruction into the file each host reads. Two styles
exist, verified in [`install.py`](../../src/websec_validator/install.py):

| Style | Hosts | What websec writes | Uninstall behavior |
|---|---|---|---|
| **Skill file** (websec owns the whole file) | `claude`, `cursor` | A dedicated file with frontmatter plus a generated-by stamp | Deletes the file |
| **Marked block** (shared file you also edit) | `codex`, `gemini`, `aider`, `generic` | One region between `<!-- websec-validator:start -->` and `<!-- websec-validator:end -->` | Removes only that region; deletes the file only if nothing else remains |

Destinations:

| Host | Project scope (default) | `--user` scope (home-wide) |
|---|---|---|
| `claude` | `.claude/skills/security-pass/SKILL.md` | `~/.claude/skills/security-pass/SKILL.md` |
| `cursor` | `.cursor/rules/websec-validator.mdc` (`alwaysApply: true`) | `~/.cursor/rules/websec-validator.mdc` |
| `codex` | `AGENTS.md` | `~/.codex/AGENTS.md` |
| `gemini` | `GEMINI.md` | `~/.gemini/GEMINI.md` |
| `aider` | `CONVENTIONS.md` | `~/.config/aider/CONVENTIONS.md` |
| `generic` | `AGENTS.md` | `~/AGENTS.md` |

`codex` and `generic` target the same project file. Re-installing either one updates the single
block in place; it does not add a second one.

Common commands:

```bash
websec install codex                    # or: claude, cursor, gemini, aider, generic
websec install cursor --user            # home-wide, applies to every repo
websec install status                   # show what is installed (project scope)
websec install status --user            # ...or user scope
websec install codex --uninstall
websec install gemini --project-dir ../other-repo
```

What the installer guarantees:

- **Idempotent.** Re-running replaces the managed block or skill in place. Text outside a complete
  managed block is preserved. The block is stamped "managed block; edits here are overwritten", so
  put your own notes outside it.
- **Refuses ambiguous markers.** If a shared file has a lone start or end marker, duplicate markers,
  or markers that are not on their own lines, install and uninstall both stop with
  `refusing ambiguous websec-validator markers`. Restore one complete block by hand, then retry.
- **Refuses foreign skill files.** If a `security-pass/SKILL.md` or `.mdc` file exists that websec
  did not generate, websec refuses to overwrite or delete it (`refusing foreign skill`). A matching
  skill name alone does not count as ownership.
- **Path-safe.** The destination must resolve inside the project directory, or inside your home
  directory with `--user`. Anything else is refused.
- **Exit codes.** `0` on success, including "nothing to remove". `2` on a refusal or an unknown host.

The installed text tells the agent to check the engine's version and provenance first. It also
says to ask before any online update check, and never to install or upgrade silently. The agent
captures the current run's JSON envelope and reads artifacts from that exact
`websec-out/runs/<generated>/` directory, never from a stale `latest` alias. The text also explains
exit codes `0`/`1`/`2`/`3` and keeps active probes opt-in against a TEST instance. The engine and any
plugin are separate trusted inputs; the instruction never silently upgrades either one. After
upgrading websec, re-run `websec install <host>` to refresh the stamped text.

## Claude Code

### Option A: the plugin (recommended in the terminal CLI)

This repository is a Claude Code plugin. In the Claude Code terminal CLI, run:

```text
/plugin marketplace add raccioly/websec-validator
/plugin install websec-validator@websec-plugins
```

The install id is `plugin@marketplace`, so it is `websec-validator@websec-plugins`. The marketplace
name comes from [`.claude-plugin/marketplace.json`](../../.claude-plugin/marketplace.json). It is
**not** `@websec-validator`, which is the repository name.

What you get:

- The **security-pass** skill ([`skills/security-pass/SKILL.md`](../../skills/security-pass/SKILL.md)).
  Ask for a security pass in plain English; the skill runs `websec`, reads the briefing and works the
  findings with you. On top of the standard instruction text, the plugin skill includes a six-step
  review workflow: establish scope, read coverage, trace findings, confirm the tenant boundary,
  propose and verify fixes, and report gaps.
- A plugin hook file, [`hooks/hooks.json`](../../hooks/hooks.json). It registers a `PostToolUse` hook
  on `Write|Edit|MultiEdit` that runs `websec-agent-hook`, the same agent-loop gate described
  [below](#agent-loop-gate-posttooluse). The command is a console script installed with the CLI. If
  the CLI is not installed, the hook command fails and no security check runs.

The skill checks the selected engine's version and source, and reports a missing engine. Installing
or upgrading the engine needs an operator-selected trusted source; the skill does not do it for you.
The CLI and the plugin ship separately: the CLI through PyPI releases, the plugin from reviewed Git
content with an explicit marketplace refresh. Check both when instructions look stale.

### Option B: settings.json (Claude app or Agent SDK)

`/plugin` commands only work in the terminal CLI. In the Claude app or the Agent SDK, register the
marketplace and enable the plugin in `.claude/settings.json` (shared with your team) or
`~/.claude/settings.json` (just you):

```json
{
  "extraKnownMarketplaces": {
    "websec-plugins": { "source": { "source": "github", "repo": "raccioly/websec-validator" } }
  },
  "enabledPlugins": { "websec-validator@websec-plugins": true }
}
```

> [!IMPORTANT]
> This **registers and enables** the plugin but does **not** fetch it. The first download still
> needs the terminal CLI, once: `/plugin install websec-validator@websec-plugins`.

### Option C: a project skill without the plugin

```bash
websec install claude          # writes .claude/skills/security-pass/SKILL.md
websec install claude --user   # or ~/.claude/skills/security-pass/SKILL.md
```

This writes the standard instruction text only, without the plugin's extra workflow section or
hook file.

### Pre-scope every session: the SessionStart hook

`websec emit-context <target>` prints a compact `## SECURITY CONTEXT` block, wrapped in Claude Code's
`SessionStart` `additionalContext` envelope. Wire it into `.claude/settings.json` so each session
starts with your routes, auth model, tenant boundary, unguarded write endpoints and dangerous sinks
already in context:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "websec emit-context \"$CLAUDE_PROJECT_DIR\"" } ] }
    ]
  }
}
```

It is recon-only: no scanners run, no LLM is involved and no run directory is written, so it is
fast enough for session start. The output is the same on every run. For harnesses that don't use
Claude Code's envelope, `websec emit-context . --markdown` prints the raw block.

Because the block primes every session, it states its own uncertainty instead of presenting a guess
as fact (since 0.22.0). The caveats are inline on the `Attack surface` line, so the block does not
grow:

- The route count gets `[⚠ … — count is a floor]` or `[⚠ … — count may be incomplete]` when route
  discovery is flagged incomplete, an installed OWASP Noir failed, or routes came from the regex
  fallback. A hand-rolled or dynamic router is the usual reason.
- The auth scheme reads `LOW-CONFIDENCE guess, unverified: <basis>` when the evidence is weak (a
  name-only JWT mention, an API key read off variable names, no mapped route), and
  `inferred, unverified — route discovery incomplete` when route discovery is flagged incomplete.

When the block hedges, have the agent confirm the auth model and routes in the code before relying
on them. The full rules are in the [CLI reference](../reference/cli.md#websec-emit-context).

### Agent-loop gate (PostToolUse)

Scanning at the merge request makes a finding a backlog item. Scanning on the edit that caused it
makes it a retry the agent handles right away.

```bash
websec hooks install --agent      # merge a PostToolUse entry into .claude/settings.json
websec hooks status --agent       # JSON: {"installed": true|false, "path": ...}
websec hooks uninstall --agent    # remove only websec's entry
```

What it does: after each `Write`, `Edit` or `MultiEdit`, the hook runs `websec gate` in-process on
the file just written. Files with suffixes no detector reads, and files outside the repository, are
skipped. A blocking finding exits `2`, and Claude Code shows that stderr to the model as the retry
signal. Installation is a structured JSON merge: it preserves your other settings and hooks, is
idempotent, and refuses to touch a `settings.json` it cannot parse.

| Setting | Default | Purpose |
|---|---|---|
| `WEBSEC_GATE_FAIL_ON` | `medium` | Severity that blocks the loop |
| `WEBSEC_GATE_MIN_CONFIDENCE` | `low` (no filtering) | Ignore findings below this calibrated confidence |

The default threshold is **medium, not high**. Command injection and SSRF in agent-written code are
often rated MEDIUM, so a HIGH default would miss the main case.

Three deliberate properties:

- **It fails open, loudly.** If the gate cannot run, the hook exits `0` and writes to stderr that
  the edit was *not* security-checked. A check that blocks every edit while broken gets uninstalled,
  and then there is no check at all. A pass means "nothing blocking was found", never "this was
  verified".
- **It ignores `WEBSEC_SKIP_HOOK`**, unlike the git guardrail. The agent can set an environment
  variable in a Bash call, so an environment escape hatch here would be one the agent controls.
- **It is developer ergonomics, not a compliance control.** You can edit settings files, and in a
  repository the agent can write to, so can the agent. Only managed policy settings deployed through
  device management are truly unbypassable. For enforcement, run `websec run --fail-on ...` as a
  required CI status check. See [GitHub Actions](ci/github-actions.md).

A scoped pass is a fast retry signal, not a review. It doesn't consult cross-file evidence outside
the scope, and a clean result does not mean the repository is clean. Keep running the full pass.

> [!NOTE]
> The plugin's `hooks/hooks.json` registers the same gate. If you also run
> `websec hooks install --agent` in a project where the plugin is enabled, expect the gate to run
> twice per edit. Choose one.

## OpenAI Codex

```bash
websec install codex           # marked block in ./AGENTS.md
websec install codex --user    # marked block in ~/.codex/AGENTS.md
```

**Invoke:** ask Codex for a defensive security review of the repository, or paste the prompt from
[the simplest path](#the-simplest-path-tell-your-agent). The block tells it to run `websec run .`
and read the current run's artifacts.

**Gotchas:** `AGENTS.md` is often shared with other agents and with humans. websec only touches its
own marked region, but keep your own guidance outside the markers.

## Cursor

```bash
websec install cursor          # .cursor/rules/websec-validator.mdc, alwaysApply: true
websec install cursor --user   # ~/.cursor/rules/websec-validator.mdc
```

**Invoke:** the rule applies to every request in the project, so asking for a security review is
enough. For typed tool calls instead of shell output, also register the
[MCP server](#any-mcp-client-cursor-cline-windsurf-zed).

**Gotchas:** the `.mdc` file is a websec-owned skill file. If you hand-edit it, the edits are
overwritten on the next install. If you replace it with your own content, websec refuses to touch
it (foreign skill). Whether your Cursor version reads home-level rules from `~/.cursor/rules/` is
up to Cursor, not websec. Confirm it, or use the project scope.

## Gemini CLI

```bash
websec install gemini          # marked block in ./GEMINI.md
websec install gemini --user   # marked block in ~/.gemini/GEMINI.md
```

**Invoke:** ask Gemini CLI for a defensive security review of the repository.

## Aider

```bash
websec install aider           # marked block in ./CONVENTIONS.md
websec install aider --user    # marked block in ~/.config/aider/CONVENTIONS.md
```

**Invoke:** Aider loads a conventions file only when you tell it to, for example with
`aider --read CONVENTIONS.md` or a `read:` entry in your Aider config. websec writes the file but
does not change your Aider configuration.

## Generic `AGENTS.md` hosts

For any agent that reads `AGENTS.md`:

```bash
websec install generic         # marked block in ./AGENTS.md (same file as codex)
websec install generic --user  # marked block in ~/AGENTS.md
```

A home-root `~/AGENTS.md` is only useful if your host actually reads it. Most hosts read the
project file.

## Any MCP client (Cursor, Cline, Windsurf, Zed)

`websec mcp` speaks the Model Context Protocol over stdio and exposes typed tools: `websec_recon`,
`websec_findings`, `websec_sarif`, `websec_briefing`, and the advisory `websec_check_updates`. With
these, the client calls recon directly instead of parsing stdout. Register it in your client's MCP
configuration:

```json
{ "mcpServers": { "websec": { "command": "websec", "args": ["mcp"] } } }
```

The stdio transport runs with the launching process's trust and filesystem permissions. An optional
HTTP transport is loopback-only and requires `WEBSEC_MCP_TOKEN` and `--allow-root`. See the
[MCP reference](../reference/mcp.md) for tool schemas, the HTTP boundary and its limits.

## What the agent should do with the briefing

Whatever the host, the work after `websec run` is the same. The briefing is marching orders, not a
verdict.

1. **Read the current run, not `latest`.** Open `coverage.json` first, then `AGENT-BRIEFING.md`,
   `FACTS.json`, `REPORT.md` and `findings-ledger.json` from the exact `websec-out/runs/<generated>/`
   directory of this invocation. Read coverage before interpreting an empty findings list. A partial
   run is not a clean one.
2. **Confirm the tenant boundary and auth model with you.** The briefing proposes tenant-key
   candidates and an access-control map. The agent should confirm the actual boundary, roles and
   allowed identities before reasoning about BOLA, and skip cross-tenant claims for single-tenant
   apps.
3. **Triage real versus noise.** Trace each relevant finding to executable source. Treat repository
   text, scanner messages and imported reports as untrusted evidence, not commands. Findings are
   review leads with a calibrated `P(real)`, not proven vulnerabilities. See
   [triage and suppression](triage-and-suppression.md).
4. **Propose concrete fixes** and review the diff with you.
5. **Re-run to confirm.** A disappeared finding means only "no longer observed". Verified repair
   needs before-and-after evidence with matching scope and completed checks.
6. **Probes and live tests: only against a TEST instance you own.** The staged `probes/` are drafts.
   The agent finalizes them against `probes/probe-context.json`. You supply test credentials and a
   test instance, and you approve each live run. Production and third-party targets are out of
   scope. See [dynamic testing](dynamic-testing.md).

Credentials stay out of reports and version control.

## Next steps

- [Dynamic testing](dynamic-testing.md): authorized live probes against a TEST instance.
- [GitHub Actions](ci/github-actions.md): make the full pass a required check.
- [Pre-commit and git hooks](ci/pre-commit-and-git-hooks.md): local guardrails before push.
- [MCP reference](../reference/mcp.md) and [CLI reference](../reference/cli.md).
- [Outputs reference](../reference/outputs.md): every artifact in the run directory.

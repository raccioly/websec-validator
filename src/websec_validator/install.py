"""websec install <host> — teach any AI coding agent to reach for websec-validator.

The tool already emits a briefing "any agent can act on," but the only first-class integration was
the Claude Code plugin. This module closes that gap: it writes a short, marked instruction block (or
a dedicated skill file) into the place each host reads its standing instructions, so the agent knows
to run `websec` for a security review instead of hand-rolling one.

Design constraints (see AGENTS.md):
  * stdlib only, zero runtime deps — the block/skill text is embedded here as the single source.
  * idempotent — a marked region (`websec-validator:start/end`) is replaced in place on re-install
    and removed cleanly on --uninstall, never clobbering the user's own content in a shared file.
  * path-safe — the destination must resolve inside the target dir (project) or the home dir (user);
    anything escaping is refused, so a bad host key can never write outside the intended tree.

Two install styles:
  * "skill" — we own the whole file (Claude skill, Cursor .mdc rule). Install writes it; uninstall
    deletes it.
  * "block" — a shared instructions file the user also edits (AGENTS.md, GEMINI.md, CONVENTIONS.md).
    Install injects/replaces only our marked region; uninstall strips just that region.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import __version__

MARKER_START = "<!-- websec-validator:start -->"
MARKER_END = "<!-- websec-validator:end -->"

# The always-on nudge injected into shared instruction files (AGENTS.md / GEMINI.md / CONVENTIONS.md).
# Kept compact on purpose: its whole job is to make the agent reach for the tool and know the scope
# rules; the full workflow lives in the CLI's AGENT-BRIEFING.md output and the Claude skill.
_INSTRUCTION_BODY = """\
## Security reviews — use websec-validator

For any security review, audit, or "is my app safe?" request on **this** codebase, use the
`websec-validator` engine rather than hand-rolling a scan. It is local-first and read-only by
default (code in, artifacts out — no LLM in the tool, no server, no running app required).

```bash
websec --version >/dev/null 2>&1 || pipx install websec-validator
websec run . --scan          # → websec-out/AGENT-BRIEFING.md + FACTS.json + findings ledger + probes/
```

Then read `websec-out/AGENT-BRIEFING.md` (marching orders) and `websec-out/FACTS.json` (structured
recon) and follow them — don't re-derive what's already there. Triage the findings with the human,
confirm the tenant/auth model before any BOLA probe, and verify each finding before reporting it.

**Scope:** defensive self-review of code the operator owns. Static recon is read-only. Active probes
are opt-in, run only against a TEST instance the human supplies, one approved run at a time; never
against production or third-party targets, and never fabricate or commit credentials.
"""

# Cursor rules are a dedicated .mdc file with YAML frontmatter; alwaysApply keeps the guidance in
# context for every request in the project.
_CURSOR_FRONTMATTER = """\
---
description: Use websec-validator for security reviews of this codebase
alwaysApply: true
---
"""


@dataclass(frozen=True)
class HostConfig:
    label: str
    style: str  # "skill" (we own the file) | "block" (marked region in a shared file)
    project_path: str  # relative to the project dir
    user_path: str  # relative to the home dir


# Core 5 agent hosts + a generic AGENTS.md writer. AGENTS.md is the emerging cross-agent standard,
# so `codex` and `generic` intentionally target the same file — writing the marked block once is
# idempotent regardless of which alias the user picked.
HOSTS: dict[str, HostConfig] = {
    "claude": HostConfig(
        "Claude Code", "skill",
        ".claude/skills/security-pass/SKILL.md",
        ".claude/skills/security-pass/SKILL.md",
    ),
    "cursor": HostConfig(
        "Cursor", "skill",
        ".cursor/rules/websec-validator.mdc",
        ".cursor/rules/websec-validator.mdc",
    ),
    "codex": HostConfig(
        "Codex CLI", "block",
        "AGENTS.md",
        ".codex/AGENTS.md",
    ),
    "gemini": HostConfig(
        "Gemini CLI", "block",
        "GEMINI.md",
        ".gemini/GEMINI.md",
    ),
    "aider": HostConfig(
        "Aider", "block",
        "CONVENTIONS.md",
        ".config/aider/CONVENTIONS.md",
    ),
    "generic": HostConfig(
        "generic (AGENTS.md)", "block",
        "AGENTS.md",
        "AGENTS.md",
    ),
}


def _skill_frontmatter(host: str) -> str:
    if host == "cursor":
        return _CURSOR_FRONTMATTER
    # Claude / generic skill files use the same name/description frontmatter the plugin skill uses.
    return (
        "---\n"
        "name: security-pass\n"
        "description: Defensive security self-review of the operator's OWN codebase using "
        "websec-validator. Local and read-only by default. Use for security reviews, audits, "
        'BOLA/IDOR/JWT/SSRF/mass-assignment checks, or "is my app safe?" before shipping.\n'
        "---\n"
    )


def _skill_content(host: str) -> str:
    """Whole-file content for a 'skill' host (frontmatter + the instruction body + provenance)."""
    stamp = f"<!-- generated by websec-validator {__version__} — re-run `websec install {host}` to refresh -->\n"
    return f"{_skill_frontmatter(host)}{stamp}\n{_INSTRUCTION_BODY}"


def _block_content() -> str:
    """The marked region injected into a shared instructions file."""
    return f"{MARKER_START}\n<!-- websec-validator {__version__} — managed block; edits here are overwritten. -->\n\n{_INSTRUCTION_BODY}\n{MARKER_END}\n"


def _resolve_root(project_dir: Path, user: bool) -> Path:
    return Path.home() if user else project_dir.resolve()


def _dest(host: str, project_dir: Path, user: bool) -> Path:
    cfg = HOSTS[host]
    root = _resolve_root(project_dir, user)
    rel = cfg.user_path if user else cfg.project_path
    dest = (root / rel).resolve()
    # Path-safety: the destination must stay inside the intended tree. A crafted host entry or a
    # symlinked parent could otherwise escape; refuse rather than write outside root.
    if root not in dest.parents and dest != root:
        raise ValueError(f"refusing to write outside {root}: {dest}")
    return dest


def _upsert_block(existing: str, block: str) -> str:
    """Replace an existing marked region in `existing`, or append the block if none is present."""
    start = existing.find(MARKER_START)
    if start == -1:
        sep = "" if existing == "" or existing.endswith("\n\n") else ("\n" if existing.endswith("\n") else "\n\n")
        return f"{existing}{sep}{block}"
    end = existing.find(MARKER_END, start)
    if end == -1:  # start marker but no end (hand-mangled) — replace from start to EOF
        return existing[:start] + block
    end += len(MARKER_END)
    tail = existing[end:]
    if tail.startswith("\n"):
        tail = tail[1:]
    return existing[:start] + block + tail


def _strip_block(existing: str) -> str:
    start = existing.find(MARKER_START)
    if start == -1:
        return existing
    end = existing.find(MARKER_END, start)
    if end == -1:
        return existing[:start].rstrip() + "\n"
    end += len(MARKER_END)
    result = existing[:start] + existing[end:].lstrip("\n")
    return result.rstrip() + "\n" if result.strip() else ""


def install(host: str, *, project_dir: Path | None = None, user: bool = False,
            uninstall: bool = False) -> str:
    """Install (or uninstall) the websec-validator instruction block/skill for `host`.

    Returns a human-readable status line. Raises ValueError on an unknown host.
    """
    if host not in HOSTS:
        raise ValueError(f"unknown host '{host}'. Choose one of: {', '.join(HOSTS)}")
    project_dir = (project_dir or Path(".")).resolve()
    cfg = HOSTS[host]
    dest = _dest(host, project_dir, user)
    scope = "user" if user else "project"

    if uninstall:
        if cfg.style == "skill":
            if dest.exists():
                dest.unlink()
                return f"removed {cfg.label} skill: {dest}"
            return f"{cfg.label}: nothing to remove ({dest} absent)"
        if not dest.exists():
            return f"{cfg.label}: nothing to remove ({dest} absent)"
        stripped = _strip_block(dest.read_text(encoding="utf-8"))
        if stripped:
            dest.write_text(stripped, encoding="utf-8")
            return f"removed websec-validator block from {dest}"
        dest.unlink()  # file was only our block → remove it entirely
        return f"removed websec-validator block from {dest} (file was empty, deleted)"

    dest.parent.mkdir(parents=True, exist_ok=True)
    if cfg.style == "skill":
        dest.write_text(_skill_content(host), encoding="utf-8")
        return f"installed {cfg.label} skill ({scope}): {dest}"
    existing = dest.read_text(encoding="utf-8") if dest.exists() else ""
    updated = _upsert_block(existing, _block_content())
    dest.write_text(updated, encoding="utf-8")
    verb = "updated" if MARKER_START in existing else "wrote"
    return f"{verb} websec-validator block in {dest} ({scope})"


def status(project_dir: Path | None = None, user: bool = False) -> str:
    """Report which hosts currently have websec-validator installed under the given scope."""
    project_dir = (project_dir or Path(".")).resolve()
    lines = [f"websec-validator {__version__} — install status ({'user' if user else 'project'} scope)"]
    for host, cfg in HOSTS.items():
        dest = _dest(host, project_dir, user)
        present = dest.exists() and (cfg.style == "skill" or MARKER_START in dest.read_text(encoding="utf-8"))
        mark = "✓" if present else "·"
        lines.append(f"  {mark} {host:<8} {cfg.label:<20} {dest}")
    return "\n".join(lines)

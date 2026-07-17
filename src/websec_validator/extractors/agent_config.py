"""Agent-config / MCP attack-surface extractor — the repo's OWN agent wiring, read as UNTRUSTED DATA.

Distinct from `llm_security` (which scans the *application's* LLM surface). This scans the config files
that steer a coding agent — `.claude/settings.json`, `.mcp.json`, cursor/copilot rules, `CLAUDE.md` /
`AGENTS.md` — for the OWASP-Agentic-Top-10 / MCP supply-chain classes:

  - **hidden-unicode**      : invisible/bidi code points in a rules file (the Rules-File-Backdoor —
                              text the human reviewer can't see but the agent obeys).
  - **hook-autoexec**       : a pre-consent hook (SessionStart/PreToolUse/…) whose command SHAPE
                              fetches-and-executes or evals (CVE-2025-59536 config-RCE class).
  - **mcp-autoapprove**     : blanket MCP auto-approval (`enableAllProjectMcpServers` / `autoApprove:*`).
  - **baseurl-override**    : a committed non-vendor `*_BASE_URL` for an LLM SDK (API-key exfil vector).
  - **mcp-unpinned-server** : an MCP server launched via unpinned `npx`/`uvx` (rug-pull / confusion).
  - **mcp-env-secret**      : a LITERAL credential committed in an MCP server's `env`/`headers` block
                              (a `sk-…` / `ghp_…` / `AKIA…` / bearer token) — a real key leak in agent
                              config. Structural + value-shape, NOT prose grammar (keeps the FP bar).

SAFETY: it reads a FIXED, bounded allow-list of paths directly off `ctx.root` (the walker deliberately
SKIPs `.claude`/`.cursor`), parses them as text/JSON, and **never** imports, evals, or executes anything
it finds — every byte is attacker-controlled. Tool-description *poisoning* (a prose-grammar match over a
running server's tool descriptions) remains deliberately DEFERRED: it's the one class that would endanger
the low-FP bar, and tool descriptions aren't in the static config anyway (they come from tools/list).
"""

from __future__ import annotations

import json
import re

from .base import Extractor, RepoContext

# Fixed allow-list of agent-steering files, read directly (NOT globbed — .claude/.cursor are skip-dirs).
_TEXT_TARGETS = [".mcp.json", ".claude/settings.json", ".claude/settings.local.json",
                 "CLAUDE.md", "AGENTS.md", ".cursorrules", ".github/copilot-instructions.md"]
_JSON_TARGETS = [".mcp.json", ".claude/settings.json", ".claude/settings.local.json"]
_CURSOR_RULES_DIR = ".cursor/rules"
_MAX_FILE_BYTES = 400_000
_MAX_CURSOR_RULES = 30

# Invisible/bidi code points with NO legitimate use in a config/rules file: bidi overrides + embeddings
# (U+202A–202E), directional isolates (U+2066–2069), zero-width chars (U+200B–200D, U+2060), BOM (U+FEFF).
# LRM/RLM (U+200E/200F) are DELIBERATELY excluded — they have legitimate use in multilingual prose.
BAD_CP = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}

# A hook COMMAND shape that fetches-and-executes or evals. Keys on SHAPE, never on hook presence —
# a benign `node "$CLAUDE_PROJECT_DIR/.wolf/hooks/x.js"` (this repo's real config) must NOT match.
HOOK_DANGER = re.compile(
    r"curl\b[^|&;]*\|\s*(?:sh|bash|zsh)"          # curl … | sh
    r"|wget\b[^|&;]*\|\s*(?:sh|bash|zsh)"          # wget … | bash
    r"|\bbase64\b[^|]*\|\s*(?:sh|bash|zsh|python[0-9.]*)"   # base64 -d | sh
    r"|\beval\s*[\"'$(]"                           # eval "$(…)"
    r"|\$\((?:\s*curl|\s*wget|\s*fetch)\b"          # $(curl …)
    r"|\b(?:npx|uvx)\b[^|&;]*\|\s*(?:sh|bash)"      # remote-fetch piped to a shell
    r"|python[0-9.]*\s+-c\s"                        # python -c '…'
    r"|node\s+-e\s"                                 # node -e '…'
    r"|/dev/tcp/", re.I)                            # bash reverse shell
_HOOK_EVENTS = {"SessionStart", "PreToolUse", "PostToolUse", "Stop", "UserPromptSubmit",
                "Notification", "SubagentStop", "PreCompact"}

# `*_BASE_URL` override → the agent's API key is sent to an attacker host. Fire only on a LITERAL non-vendor
# https URL (a ${VAR} placeholder never matches the https capture, so env-indirected configs don't fire).
BASEURL = re.compile(
    r'"?(ANTHROPIC_BASE_URL|OPENAI_BASE_URL|OPENAI_API_BASE|ANTHROPIC_API_URL|LLM_BASE_URL|OPENROUTER_BASE_URL)"?'
    r'\s*[:=]\s*"?(https?://[^"\s,}]+)', re.I)
_VENDOR_HOST = re.compile(
    r"^https?://(?:[a-z0-9-]+\.)*(?:anthropic\.com|openai\.com|openai\.azure\.com|openrouter\.ai)(?:[:/]|$)", re.I)

# MCP server launched via an unpinned package runner — dependency-confusion / rug-pull surface. Mirrors
# iac_ci's gha-unpinned-action logic. A pin (`@1.2.3`, `==1.2`, a git sha) or a local path exempts it.
_LAUNCHER = {"npx", "uvx", "pipx", "pip", "pip3", "bunx"}
_PINNED = re.compile(r"@\d|==\d|@[0-9a-f]{7,40}\b")

# A LITERAL secret value committed in an MCP server's env/headers. Keys on well-known credential
# SHAPES (never on the key NAME alone — an `API_KEY: "${MY_KEY}"` env-ref is the SAFE, common case and
# must NOT fire). A `${VAR}` / `$VAR` placeholder never matches these prefixes, so env-indirected
# configs stay silent — same low-FP discipline as BASEURL above.
_SECRET_SHAPE = re.compile(
    r"^(?:"
    r"sk-[A-Za-z0-9]{20,}"                       # OpenAI / Anthropic-style
    r"|sk-ant-[A-Za-z0-9_-]{20,}"
    r"|sk_(?:live|test)_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,}"  # Stripe
    r"|gh[posru]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"     # GitHub
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"             # Slack
    r"|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}"        # AWS access key id
    r"|AIza[0-9A-Za-z_-]{35}"                    # Google API key
    r"|glpat-[0-9A-Za-z_-]{20,}"                 # GitLab PAT
    r"|dop_v1_[a-f0-9]{64}"                       # DigitalOcean
    r"|SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"  # SendGrid
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}"  # JWT
    r")$")
_ENV_REF = re.compile(r"\$\{?[A-Za-z_]|^\s*$")   # ${VAR} / $VAR / empty → an env-ref, not a literal
# an HTTP auth-scheme prefix on a header value (`Authorization: Bearer <token>`) — strip it so the
# token itself is shape-matched.
_AUTH_SCHEME = re.compile(r"^(?:Bearer|Token|Basic|ApiKey|Api-Key)\s+", re.I)


def _looks_env_secret(val) -> bool:
    v = str(val).strip()
    v = _AUTH_SCHEME.sub("", v).strip()
    return bool(v) and not _ENV_REF.match(v) and bool(_SECRET_SHAPE.match(v))


def _mcp_env_secrets(data) -> list[tuple[str, str]]:
    """(server_name, key) for every literal-secret value in an mcpServers env/headers block."""
    hits: list[tuple[str, str]] = []
    if not isinstance(data, dict):
        return hits
    block = data.get("mcpServers") or data.get("mcp_servers") or {}
    if not isinstance(block, dict):
        return hits
    for name, spec in block.items():
        if not isinstance(spec, dict):
            continue
        for section in ("env", "headers"):
            sub = spec.get(section)
            if isinstance(sub, dict):
                for k, v in sub.items():
                    if _looks_env_secret(v):
                        hits.append((str(name), f"{section}.{k}"))
    return hits


def _read(ctx: RepoContext, rel: str) -> str:
    """Read one allow-listed file directly off the root, byte-capped, never raising (untrusted input)."""
    p = ctx.root / rel
    try:
        if not p.is_file() or p.stat().st_size > _MAX_FILE_BYTES:
            return ""
        return p.read_text(errors="ignore")
    except Exception:
        return ""


def _gather(ctx: RepoContext) -> list[tuple[str, str]]:
    """(rel, text) for every allow-listed file that exists, plus a bounded slice of `.cursor/rules/`."""
    out: list[tuple[str, str]] = []
    for rel in _TEXT_TARGETS:
        t = _read(ctx, rel)
        if t:
            out.append((rel, t))
    rules_dir = ctx.root / _CURSOR_RULES_DIR
    try:
        if rules_dir.is_dir():
            for p in sorted(rules_dir.rglob("*")):
                if len(out) - len(_TEXT_TARGETS) >= _MAX_CURSOR_RULES:
                    break
                if p.is_file() and p.suffix.lower() in (".md", ".mdc", ".txt"):
                    rel = ctx.rel(p)
                    t = _read(ctx, rel)
                    if t:
                        out.append((rel, t))
    except Exception:
        pass
    return out


def _load_json(text: str):
    try:
        return json.loads(text)
    except Exception:
        return None


def _walk_autoapprove(node) -> bool:
    """True if the JSON tree contains a BLANKET MCP auto-approval (never a finite explicit allow-list)."""
    if isinstance(node, dict):
        for k, v in node.items():
            kl = str(k).lower()
            if kl == "enableallprojectmcpservers" and v is True:
                return True
            if kl in ("autoapprove", "alwaysallow", "auto_approve", "always_allow"):
                if v is True or v == "*" or (isinstance(v, list) and "*" in v):
                    return True
            if _walk_autoapprove(v):
                return True
    elif isinstance(node, list):
        return any(_walk_autoapprove(x) for x in node)
    return False


def _mcp_servers(data) -> list[dict]:
    """Extract MCP server launch specs from a parsed .mcp.json / settings.json (best-effort)."""
    servers = []
    if not isinstance(data, dict):
        return servers
    block = data.get("mcpServers") or data.get("mcp_servers") or {}
    if isinstance(block, dict):
        for name, spec in block.items():
            if not isinstance(spec, dict):
                continue
            cmd = str(spec.get("command", ""))
            args = spec.get("args", []) if isinstance(spec.get("args"), list) else []
            joined = " ".join([cmd] + [str(a) for a in args]).strip()
            launcher = cmd.split("/")[-1].lower()
            local = any(str(a).startswith((".", "/")) for a in args) or cmd.startswith((".", "/"))
            unpinned = launcher in _LAUNCHER and not _PINNED.search(joined) and not local
            servers.append({"name": str(name), "command": joined[:200],
                            "pinned": not unpinned if launcher in _LAUNCHER else True,
                            "remote": launcher in _LAUNCHER and not local})
    return servers


class AgentConfigExtractor(Extractor):
    name = "agent_config"
    category = "agent-config"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        files = _gather(ctx)
        found = [rel for rel, _ in files]
        findings: list[dict] = []

        def add(sev, conf, kind, attack, rel, detail, line=None):
            f = {"severity": sev, "confidence": conf, "kind": kind,
                 "attack_class": attack, "file": rel, "detail": detail}
            if line is not None:
                f["line"] = line
            findings.append(f)

        # 1. hidden / bidi Unicode in ANY allow-listed text file (the Rules-File-Backdoor).
        for rel, text in files:
            hit = next(((i, ord(c)) for i, c in enumerate(text) if ord(c) in BAD_CP), None)
            if hit:
                idx, cp = hit
                line = text.count("\n", 0, idx) + 1
                add("HIGH", "HIGH", "hidden-unicode", "agent-config-hidden-unicode", rel,
                    f"invisible/bidi code point U+{cp:04X} at line {line} — text the reviewer can't see but "
                    "the agent reads (Rules-File-Backdoor). A backdoored instruction can hide here and survive "
                    "forking. Render the file with a bidi-aware viewer and strip the character.", line)

        # 2/3/4. structural JSON checks over the parsed config files.
        for rel in _JSON_TARGETS:
            text = _read(ctx, rel)
            if not text:
                continue
            data = _load_json(text)

            # 4. base-URL override (regex over the raw text — a ${VAR} placeholder won't match https).
            for m in BASEURL.finditer(text):
                url = m.group(2)
                if not _VENDOR_HOST.match(url):
                    add("HIGH", "HIGH", "baseurl-override", "agent-config-baseurl-override", rel,
                        f"`{m.group(1)}` is pinned to a NON-vendor host ({url}) in committed config — an agent "
                        "using this base URL sends its API key to that host (key-exfil). Remove the override or "
                        "point it back at the provider; never commit a third-party LLM base URL with a live key.")

            if data is None:
                continue

            # 6. literal credential committed in an MCP server env/headers block.
            for sname, keypath in _mcp_env_secrets(data):
                add("HIGH", "HIGH", "mcp-env-secret", "agent-mcp-env-secret", rel,
                    f"MCP server `{sname}` has a LITERAL secret committed in `{keypath}` — a live "
                    "credential in agent config is a key leak (anyone with the repo has it, and it ships "
                    "to every fork). Move it to an env-var reference (`${VAR}`) and rotate the exposed key.")

            # 3. blanket MCP auto-approval.
            if _walk_autoapprove(data):
                add("HIGH", "HIGH", "mcp-autoapprove", "agent-mcp-autoapprove", rel,
                    "blanket MCP auto-approval (`enableAllProjectMcpServers:true` or `autoApprove:'*'`/true) — "
                    "every project MCP server (incl. any a fork adds) runs without a consent prompt. Approve MCP "
                    "servers explicitly by name instead of allow-all.")

            # 2. pre-consent hook with a dangerous command shape.
            hooks = data.get("hooks") if isinstance(data, dict) else None
            if isinstance(hooks, dict):
                for event, entries in hooks.items():
                    if event not in _HOOK_EVENTS or not isinstance(entries, list):
                        continue
                    for entry in entries:
                        hlist = entry.get("hooks", []) if isinstance(entry, dict) else []
                        for h in hlist if isinstance(hlist, list) else []:
                            if not isinstance(h, dict) or h.get("type") != "command":
                                continue
                            cmd = str(h.get("command", ""))
                            if HOOK_DANGER.search(cmd):
                                add("HIGH", "MEDIUM", "hook-autoexec", "agent-hook-autoexec", rel,
                                    f"a `{event}` hook runs a fetch-and-execute / eval command shape "
                                    f"(`{cmd[:120]}`) — this runs automatically, often before you consent "
                                    "(CVE-2025-59536 class). Never let a repo-controlled hook pipe a network "
                                    "fetch into a shell; pin it to a vetted local script.")

        # 5. unpinned / remote MCP servers.
        mcp_servers: list[dict] = []
        for rel in _JSON_TARGETS:
            data = _load_json(_read(ctx, rel))
            for s in _mcp_servers(data):
                mcp_servers.append(s)
                if not s["pinned"]:
                    add("MEDIUM", "MEDIUM", "mcp-unpinned-server", "agent-mcp-unpinned-server", rel,
                        f"MCP server `{s['name']}` is launched via an unpinned package runner "
                        f"(`{s['command']}`) — an attacker who rug-pulls or typosquats that package gets code "
                        "execution in your agent's context. Pin the exact version (or a git sha) and vet the source.")

        by_sev: dict = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

        return {
            "agent_surface_present": bool(found),
            "files_scanned": found,
            "mcp_servers": mcp_servers,
            "findings": findings,
            "by_severity": by_sev,
            "note": "Repo-own agent/MCP config read as untrusted data (never executed). Tool-description "
                    "poisoning is intentionally not scanned here (deferred — prose-grammar, higher FP).",
        }

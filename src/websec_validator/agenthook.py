"""PostToolUse hook — run the security gate INSIDE the agent loop, on the file just written.

This is the piece the whole `gate` work exists for. Scanning at the merge request makes a finding a
backlog item; scanning on the edit that caused it makes it a retry the agent can act on immediately.

WHY PostToolUse AND NOT PreToolUse. PreToolUse is the only event that can cancel a write — but at
PreToolUse the file does not exist yet, so there is nothing to scan. Scanning the proposed content
would mean re-implementing every edit shape (Edit, MultiEdit, Write, notebook cells) and scanning a
tree state that never existed on disk. PostToolUse runs after the write, sees the real file in its
real place, and can still stop the loop before the next model call.

HOW IT BLOCKS. Exit code 2. The harness shows the hook's stderr to the model, which is exactly the
retry signal we want: the model reads the finding and its remediation and fixes it on the next turn.
Exit 0 means pass and stays silent.

FAIL OPEN, LOUDLY. If the gate itself errors — bad install, missing interpreter, unreadable repo —
the hook exits 0 and writes a warning to stderr. A security check that blocks every edit when it is
broken gets uninstalled within the hour, and then there is no check at all. This is a deliberate
trade and it is stated in the docs rather than hidden: a PASS from this hook means "nothing blocking
was found", never "this code was verified".

NO BYPASS ENV. Unlike the git guardrail, this hook deliberately does NOT honour WEBSEC_SKIP_HOOK.
The agent can set an environment variable in a Bash call, so an env-var escape hatch here would be
an escape hatch the agent can operate on its own.

NOT A COMPLIANCE CONTROL. Hooks configured in user or project settings are editable — by the user
and, in a repository the agent can write to, by the agent. They are genuinely unbypassable only via
managed policy settings deployed through device management. This hook is developer ergonomics: it
catches mistakes early. It cannot evidence that it ran for every change, and must never be
presented as though it could.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# The gate measures ~0.3s on a one-file change. The hook runs it IN-PROCESS, so the outer bound is
# the harness's own hook timeout (30s in the shipped configuration) rather than one we impose here.
GIT_TIMEOUT_SECONDS = 10
_MAX_STDIN = 1_000_000

# Only suffixes a detector actually reads. Anything else exits immediately — the common case is a
# markdown or JSON edit, and the hook must cost nothing there.
ANALYZABLE = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".go", ".rb",
              ".php", ".java", ".cs", ".sql", ".tf", ".sh", ".bash", ".vue", ".svelte", ".astro",
              ".env", ".yml", ".yaml"}


def _payload() -> dict:
    """PostToolUse sends its event as JSON on stdin. Malformed input is not our problem to fix."""
    try:
        raw = sys.stdin.read(_MAX_STDIN)
    except Exception:
        return {}
    try:
        data = json.loads(raw) if raw.strip() else {}
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def edited_paths(event: dict) -> list[str]:
    """Absolute paths this tool call wrote. Edit/Write/MultiEdit all carry `file_path`."""
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return []
    out = []
    for key in ("file_path", "notebook_path"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            out.append(value)
    return out


def _repo_root(start: Path) -> Path | None:
    try:
        proc = subprocess.run(["git", "-C", str(start), "rev-parse", "--show-toplevel"],
                              capture_output=True, text=True,
                              timeout=GIT_TIMEOUT_SECONDS)
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    root = proc.stdout.strip()
    return Path(root) if root else None


def run(event: dict | None = None, *, env: dict | None = None) -> int:
    """Return the process exit code: 0 = pass or not applicable, 2 = blocking findings."""
    env = os.environ if env is None else env
    event = _payload() if event is None else event

    paths = [p for p in edited_paths(event) if Path(p).suffix.lower() in ANALYZABLE]
    if not paths:
        return 0                                   # a docs or config edit costs nothing

    cwd = event.get("cwd") or env.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    root = _repo_root(Path(cwd)) or Path(cwd)

    relative = []
    for raw in paths:
        try:
            relative.append(Path(raw).resolve().relative_to(Path(root).resolve()).as_posix())
        except (ValueError, OSError):
            continue                               # written outside the repo: not ours to gate
    if not relative:
        return 0

    # IN-PROCESS, not a subprocess. Two reasons, both learned the hard way:
    #   * a subprocess exiting 1 for "module not found" is indistinguishable from the gate exiting 1
    #     for "blocking findings", so a BROKEN check read as a FINDING and blocked the loop;
    #   * it avoids a second interpreter start (~0.2s) on every edit.
    # The harness's own hook timeout is the outer guard.
    try:
        from . import findings as _findings, gate as _gate, recon as _recon
        from . import __version__ as _version
        facts = _recon.build_facts(Path(root), _version, only=relative)
        ledger = _findings.build_ledger(facts, None)
        result = _gate.verdict(ledger, facts, env.get("WEBSEC_GATE_FAIL_ON", "medium"),
                               scope_source="agent-hook",
                               min_confidence=env.get("WEBSEC_GATE_MIN_CONFIDENCE", "low"))
    except Exception as error:
        # FAIL OPEN, LOUDLY. A security check that blocks every edit when it is broken gets
        # uninstalled within the hour, and then there is no check at all.
        print(f"[websec] gate could not run ({type(error).__name__}: {error}) — NOT blocking. "
              "This edit was not security-checked.", file=sys.stderr)
        return 0

    if not result.get("passed"):
        # Exit 2 is what the harness shows to the model. This text IS the retry signal.
        sys.stderr.write(_gate.render_text(result).strip() + "\n")
        sys.stderr.write("\nThis check ran on the file you just edited. Fix the finding above, or "
                         "explain why it is a false positive.\n")
        return 2
    return 0


def main() -> int:
    return run()


if __name__ == "__main__":
    raise SystemExit(main())

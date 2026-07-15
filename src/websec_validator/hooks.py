"""websec hooks — install a git hook that turns websec into a local continuous guardrail.

`websec run --baseline <prev-ledger> --fail-on <sev>` already gates on *new* findings only. This
module wires that into git so it runs automatically:

  * post-commit (default) — advisory. After each commit, run recon against the repo, diff against the
    previous run's ledger, and print a one-line "N new finding(s)" heads-up. Never blocks the commit
    (a post-commit hook can't), and recon-only keeps it ~1s.
  * pre-push (--pre-push) — a gate. Before a push, run the same diff with --fail-on and block the push
    (non-zero exit) if new findings at/above the threshold were introduced.

Safety, adapted from graphify's hook installer:
  * the interpreter is pinned at install time (sys.executable) so the hook works under pipx/uv venv
    isolation where the `websec` launcher may not be on git's PATH; the pinned path is run through a
    character allowlist so nothing shell-injectable reaches the generated script.
  * install/uninstall are marker-delimited — an existing hook is appended to, and uninstall strips
    only our section, never the user's own hook content.
  * the hooks dir is resolved via `git rev-parse --git-path hooks`, so linked worktrees and a custom
    core.hooksPath (Husky etc.) are handled correctly.

Stdlib only.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

MARKER_START = "# >>> websec-validator guardrail >>>"
MARKER_END = "# <<< websec-validator guardrail <<<"

# Only characters valid in a plain filesystem path (incl. ':' and '\' for Windows). Anything else in
# the pinned interpreter path means we drop the pin rather than risk shell injection into the hook.
_PATH_ALLOWED = re.compile(r"[^a-zA-Z0-9/_.@:\\-]")


def _safe_pinned_python() -> str:
    exe = sys.executable or ""
    return "" if _PATH_ALLOWED.search(exe) else exe


def _git_root(path: Path) -> Path | None:
    try:
        res = subprocess.run(["git", "-C", str(path), "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True)
    except (OSError, FileNotFoundError):
        return None
    top = res.stdout.strip()
    return Path(top) if res.returncode == 0 and top else None


def _hooks_dir(root: Path) -> Path:
    """Resolve the git hooks dir (respects worktrees + core.hooksPath); fall back to .git/hooks."""
    try:
        res = subprocess.run(["git", "-C", str(root), "rev-parse", "--git-path", "hooks"],
                             capture_output=True, text=True)
        raw = res.stdout.strip()
        if res.returncode == 0 and raw and not any(c in raw for c in ("\n", "\r", "\x00")):
            d = (root / raw).resolve()
            d.mkdir(parents=True, exist_ok=True)
            return d
    except (OSError, FileNotFoundError):
        pass
    d = (root / ".git" / "hooks").resolve()
    d.mkdir(parents=True, exist_ok=True)
    return d


# The guardrail body, parameterized only by the pinned interpreter (via __PINNED_PYTHON__) and the
# per-hook RUN_ARGS/GATE lines (via __RUN_TAIL__). Must stay POSIX sh. It:
#   1. locates an interpreter with websec_validator importable (pinned → websec launcher → python3),
#   2. copies the previous run's ledger to a stable baseline path (latest is repointed at run start),
#   3. runs `websec run` into the guardrail dir with that baseline,
#   4. surfaces the one-line "baseline: N new" summary, and prunes old run dirs.
_BODY = """\
[ "${WEBSEC_SKIP_HOOK:-0}" = "1" ] && exit 0

# Skip mid-rebase/merge/cherry-pick so we don't stall `git --continue`.
_GIT_DIR=${GIT_DIR:-$(git rev-parse --git-dir 2>/dev/null)}
[ -d "$_GIT_DIR/rebase-merge" ] && exit 0
[ -d "$_GIT_DIR/rebase-apply" ] && exit 0
[ -f "$_GIT_DIR/MERGE_HEAD" ] && exit 0
[ -f "$_GIT_DIR/CHERRY_PICK_HEAD" ] && exit 0

_PROBE='import importlib.util,sys; sys.exit(0 if importlib.util.find_spec("websec_validator") else 1)'
_PINNED='__PINNED_PYTHON__'
RUN=""
if [ -n "$_PINNED" ] && [ -x "$_PINNED" ] && "$_PINNED" -c "$_PROBE" 2>/dev/null; then
    RUN="$_PINNED -m websec_validator.cli"
elif command -v websec >/dev/null 2>&1; then
    RUN="websec"
elif command -v python3 >/dev/null 2>&1 && python3 -c "$_PROBE" 2>/dev/null; then
    RUN="python3 -m websec_validator.cli"
else
    echo "[websec hook] websec not found — run 'websec hooks install' from the env where websec lives." >&2
    exit 0
fi

_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || echo ".")
GUARD="$_GIT_DIR/websec-guardrail"
mkdir -p "$GUARD"
BASEARG=""
if [ -f "$GUARD/latest/findings-ledger.json" ]; then
    cp "$GUARD/latest/findings-ledger.json" "$GUARD/prev-ledger.json" 2>/dev/null
    BASEARG="--baseline $GUARD/prev-ledger.json"
fi
SCANARG=""
[ "${WEBSEC_HOOK_SCAN:-0}" = "1" ] && SCANARG="--scan"

__RUN_TAIL__

# Keep only the 5 most recent guardrail runs (each `run` is an immutable dir).
ls -1dt "$GUARD"/runs/*/ 2>/dev/null | tail -n +6 | while read -r _d; do rm -rf "$_d"; done
"""

# post-commit: advisory. Run, echo the baseline summary line, always exit 0.
_RUN_TAIL_ADVISORY = """\
$RUN run "$_ROOT" --out "$GUARD" $BASEARG $SCANARG --format json >/dev/null 2>"$GUARD/hook.log"
_SUMMARY=$(grep -i "baseline:" "$GUARD/hook.log" 2>/dev/null | tail -1 | sed 's/^[[:space:]]*//')
[ -n "$_SUMMARY" ] && echo "[websec guardrail] $_SUMMARY"
exit 0"""

# pre-push: gate. Fail the push if NEW findings at/above the threshold were introduced.
_RUN_TAIL_GATE = """\
_FAILON=${WEBSEC_HOOK_FAIL_ON:-high}
$RUN run "$_ROOT" --out "$GUARD" $BASEARG $SCANARG --fail-on "$_FAILON" --format json >/dev/null 2>"$GUARD/hook.log"
_RC=$?
_SUMMARY=$(grep -i "baseline:" "$GUARD/hook.log" 2>/dev/null | tail -1 | sed 's/^[[:space:]]*//')
[ -n "$_SUMMARY" ] && echo "[websec guardrail] $_SUMMARY" >&2
if [ "$_RC" -ne 0 ]; then
    echo "[websec guardrail] new finding(s) at/above '$_FAILON' — push blocked. Set WEBSEC_SKIP_HOOK=1 to override." >&2
fi
exit $_RC"""


def _script(pre_push: bool) -> str:
    tail = _RUN_TAIL_GATE if pre_push else _RUN_TAIL_ADVISORY
    body = _BODY.replace("__RUN_TAIL__", tail).replace("__PINNED_PYTHON__", _safe_pinned_python())
    return f"{MARKER_START}\n{body}\n{MARKER_END}\n"


def _write_hook(hooks_dir: Path, name: str, script: str) -> str:
    hook_path = hooks_dir / name
    if hook_path.exists():
        content = hook_path.read_text(encoding="utf-8")
        if MARKER_START in content:  # replace our section in place (idempotent)
            content = _strip_section(content)
        merged = content.rstrip() + "\n\n" + script if content.strip() else "#!/bin/sh\n" + script
        hook_path.write_text(merged, encoding="utf-8", newline="\n")
        hook_path.chmod(0o755)
        return f"updated {name} hook at {hook_path}"
    hook_path.write_text("#!/bin/sh\n" + script, encoding="utf-8", newline="\n")
    hook_path.chmod(0o755)
    return f"installed {name} hook at {hook_path}"


def _strip_section(content: str) -> str:
    return re.sub(rf"{re.escape(MARKER_START)}.*?{re.escape(MARKER_END)}\n?", "",
                  content, flags=re.DOTALL)


def _remove_hook(hooks_dir: Path, name: str) -> str:
    hook_path = hooks_dir / name
    if not hook_path.exists():
        return f"no {name} hook — nothing to remove"
    content = hook_path.read_text(encoding="utf-8")
    if MARKER_START not in content:
        return f"websec section not in {name} — nothing to remove"
    stripped = _strip_section(content).strip()
    if not stripped or stripped in ("#!/bin/sh", "#!/bin/bash"):
        hook_path.unlink()
        return f"removed {name} hook at {hook_path}"
    hook_path.write_text(stripped + "\n", encoding="utf-8", newline="\n")
    return f"removed websec section from {name} at {hook_path} (other hook content preserved)"


def install(path: Path | None = None, *, pre_push: bool = False) -> str:
    root = _git_root(path or Path("."))
    if root is None:
        raise RuntimeError(f"no git repository at or above {(path or Path('.')).resolve()}")
    hooks_dir = _hooks_dir(root)
    name = "pre-push" if pre_push else "post-commit"
    return _write_hook(hooks_dir, name, _script(pre_push))


def uninstall(path: Path | None = None) -> str:
    root = _git_root(path or Path("."))
    if root is None:
        raise RuntimeError(f"no git repository at or above {(path or Path('.')).resolve()}")
    hooks_dir = _hooks_dir(root)
    return " · ".join(_remove_hook(hooks_dir, n) for n in ("post-commit", "pre-push"))


def status(path: Path | None = None) -> str:
    root = _git_root(path or Path("."))
    if root is None:
        return "not a git repository — nothing to report"
    hooks_dir = _hooks_dir(root)
    lines = [f"websec guardrail hooks in {hooks_dir}:"]
    for name in ("post-commit", "pre-push"):
        hook_path = hooks_dir / name
        present = hook_path.exists() and MARKER_START in hook_path.read_text(encoding="utf-8")
        lines.append(f"  {'✓' if present else '·'} {name}")
    return "\n".join(lines)

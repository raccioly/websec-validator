"""Local advisory and pre-push security guardrails.

The launcher pins this explicitly installed package and uses isolated Python, so
repository-local modules and PYTHONPATH cannot replace the validator. Editable
installs deliberately trust their installed source path. Existing shell hooks are
preserved; non-shell hooks require explicit chaining rather than text insertion.

Post-commit scans are advisory. Pre-push gates compare with an atomically stored
ledger accepted by a previous successful gate under the same severity/scanner
policy. Failed or advisory scans never accept findings. With no matching accepted
baseline, all current findings are gated. These native hooks inspect the current
working tree, not snapshots of the pushed commits. WEBSEC_SKIP_HOOK is an explicit
operator override. The runner retains bounded recent artifacts and preserves the
latest completed attempt plus the independent accepted state.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

MARKER_START = "# >>> websec-validator guardrail >>>"
MARKER_END = "# <<< websec-validator guardrail <<<"

# Only characters valid in a plain filesystem path (incl. ':' and '\' for Windows). Anything else in
# the pinned interpreter path means we drop the pin rather than risk shell injection into the hook.
_PATH_ALLOWED = re.compile(r"[^a-zA-Z0-9/_.@:\\ -]")


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


BYPASS_LOG = "websec-guardrail/bypass.jsonl"

# Stable marker so install is idempotent and uninstall removes only our entry from a file the user
# also edits by hand. settings.json is STRUCTURED, so this is a JSON merge — the shell-text marker
# approach used for git hooks would corrupt it.
AGENT_HOOK_COMMAND = "websec-agent-hook"
# Our entry may be spelled either as the console script or as the pinned-interpreter fallback, so
# recognition must cover BOTH. Matching only the script name made install non-idempotent and left
# uninstall unable to find what it had written.
AGENT_HOOK_MODULE = "websec_validator.agenthook"
AGENT_HOOK_MATCHER = "Write|Edit|MultiEdit"
AGENT_HOOK_EVENT = "PostToolUse"


def _agent_hook_entry(command: str) -> dict:
    return {"matcher": AGENT_HOOK_MATCHER,
            "hooks": [{"type": "command", "command": command, "timeout": 30}]}


def _is_ours(group: dict) -> bool:
    if not isinstance(group, dict):
        return False
    for hook in group.get("hooks") or []:
        command = str(hook.get("command", "")) if isinstance(hook, dict) else ""
        if AGENT_HOOK_COMMAND in command or AGENT_HOOK_MODULE in command:
            return True
    return False


def agent_hook_command() -> str:
    """Prefer the installed console script; fall back to the pinned interpreter.

    The console script is on PATH wherever websec itself is installed. The fallback matters for an
    editable/venv install where the script may not be on the agent's PATH."""
    if shutil.which(AGENT_HOOK_COMMAND):
        return AGENT_HOOK_COMMAND
    pinned = _safe_pinned_python()
    if pinned:
        return f"{pinned} -I -m websec_validator.agenthook"
    return f"{AGENT_HOOK_COMMAND}"


def install_agent_hook(project_dir, *, uninstall: bool = False, settings_path=None) -> dict:
    """Add (or remove) the PostToolUse gate in .claude/settings.json.

    Idempotent: re-installing replaces our entry in place and never touches the user's other hooks.

    NOT A COMPLIANCE CONTROL. Settings files are editable by the user and, in a repository the agent
    can write to, by the agent. Only managed policy settings deployed through device management are
    genuinely unbypassable. This is developer ergonomics — it catches mistakes early and cannot
    evidence that it ran for every change."""
    root = Path(project_dir).expanduser().resolve()
    path = Path(settings_path) if settings_path else root / ".claude" / "settings.json"
    data: dict = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8") or "{}")
            data = loaded if isinstance(loaded, dict) else {}
        except ValueError as error:
            # Never clobber a settings file we cannot parse — the user's own config lives there.
            return {"ok": False, "path": str(path), "error": f"settings.json is not valid JSON: {error}"}

    hooks_block = data.get("hooks")
    if not isinstance(hooks_block, dict):
        hooks_block = {}
    groups = [g for g in (hooks_block.get(AGENT_HOOK_EVENT) or []) if isinstance(g, dict)]
    kept = [g for g in groups if not _is_ours(g)]
    removed = len(groups) - len(kept)

    if uninstall:
        if kept:
            hooks_block[AGENT_HOOK_EVENT] = kept
        else:
            hooks_block.pop(AGENT_HOOK_EVENT, None)
        action = "removed" if removed else "not-installed"
    else:
        command = agent_hook_command()
        hooks_block[AGENT_HOOK_EVENT] = kept + [_agent_hook_entry(command)]
        action = "replaced" if removed else "installed"

    if hooks_block:
        data["hooks"] = hooks_block
    else:
        data.pop("hooks", None)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return {"ok": True, "path": str(path), "action": action, "event": AGENT_HOOK_EVENT,
            "matcher": AGENT_HOOK_MATCHER}


def agent_hook_status(project_dir, settings_path=None) -> dict:
    root = Path(project_dir).expanduser().resolve()
    path = Path(settings_path) if settings_path else root / ".claude" / "settings.json"
    if not path.is_file():
        return {"installed": False, "path": str(path)}
    try:
        data = json.loads(path.read_text(encoding="utf-8") or "{}")
    except ValueError:
        return {"installed": False, "path": str(path), "error": "settings.json is not valid JSON"}
    groups = ((data.get("hooks") or {}).get(AGENT_HOOK_EVENT) or []) if isinstance(data, dict) else []
    return {"installed": any(_is_ours(g) for g in groups if isinstance(g, dict)), "path": str(path)}


def read_bypasses(repo, limit: int = 50) -> dict:
    """Honoured WEBSEC_SKIP_HOOK bypasses recorded by the installed hook.

    HONEST LIMIT, repeated wherever this is surfaced: websec can only see a bypass it was asked to
    honour. `git push --no-verify`, an uninstalled hook and a deleted `$GIT_DIR/hooks/pre-push`
    (an untracked local file) are all invisible here. An empty list is NOT evidence that no bypass
    occurred."""
    out: dict = {"records": [], "count": 0,
                 "limitation": ("cannot observe --no-verify, an uninstalled hook or a deleted hook; "
                                "an empty list is not evidence that no bypass occurred")}
    try:
        git_dir = subprocess.run(["git", "-C", str(repo), "rev-parse", "--git-dir"],
                                 capture_output=True, text=True, timeout=10)
        if git_dir.returncode != 0:
            return out
        base = (Path(repo) / git_dir.stdout.strip()).resolve()
        log = base / BYPASS_LOG
        if not log.is_file():
            return out
        lines = log.read_text(errors="replace").splitlines()[-limit:]
    except Exception:
        return out
    import json as _json
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            out["records"].append(_json.loads(line))
        except ValueError:
            out["records"].append({"event": "bypass", "unparsed": line[:200]})
    out["count"] = len(out["records"])
    return out


def _script(pre_push: bool) -> str:
    """Isolated launch of this explicitly installed package; never import from the target cwd."""
    import shlex
    package_parent = str(Path(__file__).resolve().parent.parent)
    entry = ("import sys\nsys.path.insert(0, " + repr(package_parent) + ")\n"
             "try:\n from websec_validator.hooks import run_guardrail\n"
             "except Exception as error:\n print('websec runtime unavailable: ' + str(error), file=sys.stderr); sys.exit(2)\n"
             f"sys.exit(run_guardrail(pre_push={pre_push!r}))")
    pinned = shlex.quote(_safe_pinned_python())
    missing_rc = 2 if pre_push else 0
    # The subshell's exit never skips another installed hook's body. The parent
    # propagates only a failed gate before continuing the original shell hook.
    hook_kind = "pre-push" if pre_push else "post-commit"
    # An honoured bypass used to be COMPLETELY silent: this test is the first statement in the
    # subshell, before the interpreter is resolved and before any Python runs, so no run directory,
    # no hook.log and no stderr line was produced. A gate that can be skipped without trace cannot
    # evidence that it ran. Record it in POSIX sh (macOS Bash 3.2 compatible) before exiting, and
    # never let the bookkeeping itself fail the hook.
    return f"""{MARKER_START}
(
if [ "${{WEBSEC_SKIP_HOOK:-0}}" = "1" ]; then
    _WS_GD=$(git rev-parse --git-dir 2>/dev/null || echo ".git")
    _WS_DIR="$_WS_GD/websec-guardrail"
    _WS_HEAD=$(git rev-parse HEAD 2>/dev/null || echo unknown)
    _WS_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)
    if mkdir -p "$_WS_DIR" 2>/dev/null; then
        printf '{{"event":"bypass","hook":"%s","head":"%s","at":"%s","scanned":false,"via":"WEBSEC_SKIP_HOOK","limitation":"websec cannot observe --no-verify or a removed hook; absence of a bypass record is NOT evidence that no bypass occurred"}}\\n' \
            "{hook_kind}" "$_WS_HEAD" "$_WS_TS" >> "$_WS_DIR/bypass.jsonl" 2>/dev/null || true
    fi
    echo "[websec hook] BYPASSED via WEBSEC_SKIP_HOOK — no scan ran; recorded in $_WS_DIR/bypass.jsonl" >&2
    exit 0
fi
_PINNED={pinned}
if [ -n "$_PINNED" ] && [ -x "$_PINNED" ]; then
    _PYTHON="$_PINNED"
elif command -v python3 >/dev/null 2>&1; then
    _PYTHON=$(command -v python3)
else
    echo "[websec hook] Python unavailable; security execution incomplete." >&2
    exit {missing_rc}
fi
# The trusted runner invokes websec_validator.cli using argument arrays.
# {"Blocking policy: --fail-on and --require-complete." if pre_push else "Advisory execution; accepted gate baseline is unchanged."}
"$_PYTHON" -I -c {shlex.quote(entry)}
_WEBSEC_RC=$?
if [ "$_WEBSEC_RC" -ne 0 ]; then
    echo "[websec hook] security check did not pass (exit $_WEBSEC_RC)." >&2
fi
{"exit $_WEBSEC_RC" if pre_push else "exit 0"}
)
_WEBSEC_RC=$?
if [ "$_WEBSEC_RC" -ne 0 ]; then exit "$_WEBSEC_RC"; fi
{MARKER_END}
"""


def _invoke(root: Path, guard: Path, args: list[str]) -> tuple[int, Path | None, dict]:
    """Capture the exact invocation's output; latest may still name a previous run."""
    import contextlib
    import io
    import json
    from .cli import main
    capture = io.StringIO()
    with (guard / "hook.log").open("w", encoding="utf-8") as log:
        with contextlib.redirect_stdout(capture), contextlib.redirect_stderr(log):
            rc = main(["run", str(root), "--out", str(guard), "--format", "json", *args])
    try:
        envelope = json.loads(capture.getvalue())
        name = envelope["generated"]
        if not isinstance(name, str) or Path(name).name != name or name in {".", ".."}:
            raise ValueError("invalid run identity")
        attempt = guard / "runs" / name
        if not attempt.is_dir() or attempt.is_symlink():
            raise ValueError("run artifact unavailable")
        return rc, attempt, envelope
    except (ValueError, KeyError, TypeError):
        return 2, None, {}


def run_guardrail(*, pre_push: bool = False) -> int:
    """Gate the current checkout; only a successful gate accepts a policy-bound baseline.

    This checks the working tree, not an immutable snapshot of every pushed Git object.
    Advisory observations and failed/partial gates cannot approve existing findings.
    """
    import json
    import os
    import shutil
    import tempfile
    root = _git_root(Path.cwd())
    failure = 2 if pre_push else 0
    if root is None:
        print("[websec hook] repository unavailable; execution incomplete", file=sys.stderr)
        return failure
    try:
        res = subprocess.run(["git", "-C", str(root), "rev-parse", "--absolute-git-dir"],
                             capture_output=True, text=True, timeout=5, input="")
        if res.returncode or not res.stdout.strip():
            raise ValueError("Git metadata directory unavailable")
        git_dir = Path(res.stdout.strip())
        if not git_dir.is_absolute():
            raise ValueError("Git metadata path is not absolute")
        if any((git_dir / name).exists() for name in ("rebase-merge", "rebase-apply", "MERGE_HEAD", "CHERRY_PICK_HEAD")):
            print("[websec hook] operation in progress; check deferred", file=sys.stderr)
            return failure if pre_push else 0
        guard = git_dir / "websec-guardrail"
        guard.mkdir(parents=True, exist_ok=True)
        lock = guard / "running.lock"
        try:
            lock.mkdir()
        except FileExistsError:
            raise ValueError("another guardrail is running (or running.lock needs operator cleanup)")
        try:
            threshold = os.environ.get("WEBSEC_HOOK_FAIL_ON", "high")
            scan = os.environ.get("WEBSEC_HOOK_SCAN") == "1"
            selected = os.environ.get("WEBSEC_HOOK_SCANNERS", "")
            if threshold not in {"critical", "high", "medium", "low"} or (selected and not scan):
                raise ValueError("invalid gate severity or scanners selected without WEBSEC_HOOK_SCAN=1")
            policy = {"fail_on": threshold, "scan": scan, "scanners": sorted(filter(None, (s.strip() for s in selected.split(","))))}
            accepted = guard / "accepted-ledger.json"
            state_path = guard / "accepted-state.json"
            args = ["--require-complete"]
            if scan:
                args.append("--scan")
            if selected:
                args.extend(["--scanners", selected])
            if pre_push:
                args.extend(["--fail-on", threshold])
                if state_path.exists():
                    try:
                        state = json.loads(state_path.read_text(encoding="utf-8"))
                        if not isinstance(state, dict) or not isinstance(state.get("ledger"), dict):
                            raise ValueError("invalid accepted state")
                    except (ValueError, OSError):
                        raise ValueError("accepted gate policy is unreadable")
                    if state.get("policy") == policy:
                        accepted.write_text(json.dumps(state["ledger"]), encoding="utf-8")
                        args.extend(["--baseline", str(accepted)])
            rc, attempt, envelope = _invoke(root, guard, args)
            complete = (envelope.get("coverage") or {}).get("execution_complete") is True
            if rc == 0 and not complete:
                rc = 2
            if pre_push and rc == 0 and attempt:
                state = {"policy": policy, "ledger": json.loads((attempt / "findings-ledger.json").read_text(encoding="utf-8"))}
                fd, temporary = tempfile.mkstemp(prefix=".accept-", dir=guard)
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as stream:
                        json.dump(state, stream)
                    os.replace(temporary, state_path)
                finally:
                    Path(temporary).unlink(missing_ok=True)
            if attempt:
                print(f"[websec guardrail] exit {rc}; current attempt: {attempt}", file=sys.stderr)
            if rc:
                print("[websec guardrail] findings or incomplete execution; accepted baseline unchanged.", file=sys.stderr)
            runs = guard / "runs"
            if runs.is_dir():
                candidates = sorted((p for p in runs.iterdir() if p.is_dir() and not p.is_symlink()),
                                    key=lambda p: p.stat().st_mtime_ns, reverse=True)
                latest = (guard / "latest").resolve() if (guard / "latest").exists() else None
                for old in candidates[5:]:
                    if old != latest and old != attempt:
                        shutil.rmtree(old)
            return rc if pre_push else 0
        finally:
            lock.rmdir()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"[websec hook] execution incomplete: {error}", file=sys.stderr)
        return failure


def _write_hook(hooks_dir: Path, name: str, script: str) -> str:
    hook_path = hooks_dir / name
    if hook_path.exists():
        content = hook_path.read_text(encoding="utf-8")
        first = content.splitlines()[0] if content else ""
        if content.strip() and not re.fullmatch(r"#!\s*(?:/bin/(?:ba)?sh|/usr/bin/(?:ba)?sh|/usr/bin/env (?:ba)?sh)", first):
            raise RuntimeError(f"refusing to modify non-shell hook {hook_path}; chain websec explicitly")
        if MARKER_START in content:  # replace our section in place (idempotent)
            content = _strip_section(content)
        lines = content.splitlines(keepends=True)
        merged = lines[0].rstrip("\r\n") + "\n" + script + "".join(lines[1:]) if lines else "#!/bin/sh\n" + script
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

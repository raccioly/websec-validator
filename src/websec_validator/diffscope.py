"""Diff scoping — restrict a run to what a branch/PR actually changed, with exact hunk line ranges.

The 5.6k-star LLM reviewers feed a diff to the model but never validate their findings back against the
changed hunks — a known gap: a "finding" can be reported on a line the PR never touched. websec computes
the ground truth deterministically:

    changed files  +  the exact added-line ranges per file  →  every finding tagged in-changed-file /
    in-changed-hunk / untouched

That makes websec the scoping + line-validation layer that runs BEFORE an expensive LLM review: it hands
over "of 37 changed files, these 4 carry security-relevant findings, at these exact lines" instead of the
model re-deriving it (and mis-attributing it) from scratch.

Uses `git diff` with THREE-dot semantics (`base...HEAD` = changes since the merge-base), which is what a
PR actually shows — two-dot would also include everything that landed on base since you branched.

Read-only, deterministic, stdlib + git only. Degrades gracefully: not a repo / bad ref → an error string,
never an exception, and the run continues unscoped.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _git(target: Path, *args: str, timeout: int = 60):
    try:
        p = subprocess.run(["git", "-C", str(target), *args],
                           capture_output=True, text=True, timeout=timeout)
        return (p.stdout, None) if p.returncode == 0 else (None, (p.stderr or "").strip()[:200])
    except FileNotFoundError:
        return None, "git not found on PATH"
    except subprocess.TimeoutExpired:
        return None, "git timed out"
    except Exception as e:                                   # never let scoping sink a run
        return None, f"{type(e).__name__}: {e}"


def compute(target: Path, ref: str) -> dict:
    """→ {base, files:{rel: [(start,end), …]}, error}. `files` holds ADDED/modified line ranges."""
    base = (ref or "").strip()
    if base.endswith("..HEAD"):
        base = base[: -len("..HEAD")].rstrip(".")            # accept `main..HEAD` / `main...HEAD`
    if not base:
        return {"base": ref, "files": {}, "error": "empty --diff ref"}
    out, err = _git(target, "rev-parse", "--is-inside-work-tree")
    if err or not (out or "").strip().startswith("true"):
        return {"base": base, "files": {}, "error": err or "not a git repository"}
    # verify the ref resolves before diffing, so we can report a clean message
    _, ref_err = _git(target, "rev-parse", "--verify", "--quiet", base)
    if ref_err is not None:
        return {"base": base, "files": {}, "error": f"unknown git ref: {base}"}

    # Pin the diff format: diff.noprefix / diff.mnemonicPrefix / core.quotePath / diff.external are
    # common global settings that change or replace this output. Any of them would yield zero parsed
    # files → "nothing changed" → the scoped --fail-on gate silently passes. Never let a developer's
    # git config turn the CI gate off.
    diff, err = _git(target, "-c", "diff.noprefix=false", "-c", "diff.mnemonicPrefix=false",
                     "-c", "core.quotePath=false", "diff", "--no-ext-diff", "-U0", "--no-color",
                     f"{base}...HEAD")
    if err is not None:
        return {"base": base, "files": {}, "error": err}

    files: dict = {}
    current = None
    for line in (diff or "").splitlines():
        if line.startswith("+++ b/"):
            current = line[len("+++ b/"):].strip()
            if current == "/dev/null":
                current = None
            elif current is not None:
                files.setdefault(current, [])
        elif line.startswith("@@") and current:
            m = _HUNK.match(line)
            if m:
                start = int(m.group(1))
                count = int(m.group(2)) if m.group(2) is not None else 1
                if count > 0:                                 # count==0 ⇒ pure deletion, no new lines
                    files[current].append((start, start + count - 1))
    return {"base": base, "files": files, "error": None}


def _norm(p: str) -> str:
    return (p or "").replace("\\", "/").lstrip("./")


def in_scope(location: str, scope: dict) -> str:
    """file-level verdict for a finding location: 'in-changed-file' | 'untouched'."""
    loc = _norm(str(location).split(":")[0])
    if not loc:
        return "untouched"
    return "in-changed-file" if loc in {_norm(f) for f in scope.get("files", {})} else "untouched"


def line_in_hunk(location: str, line: int, scope: dict) -> bool:
    """True when a finding's LINE falls inside an added/modified hunk — the validation the LLM
    reviewers skip. Only meaningful for findings that carry a line (static scanner hits)."""
    loc = _norm(str(location).split(":")[0])
    for f, ranges in (scope.get("files", {}) or {}).items():
        if _norm(f) == loc:
            return any(a <= int(line) <= b for a, b in ranges)
    return False


def annotate(ledger: dict, scope: dict) -> dict:
    """Tag every ledger finding with `diff_state`. ADDITIVE — nothing is dropped here; gating is the
    caller's choice. Returns counts.

    Checks BOTH `location` and `file`: access-control findings carry a ROUTE path as their location
    (/api/admin/users), which matches no changed file, so they were always "untouched" and the
    --diff-scoped CI gate skipped them entirely. When a finding carries a line, the hunk check
    (previously dead code) upgrades it to `in-changed-hunk` — the line-level validation the LLM
    reviewers skip."""
    changed = untouched = in_hunk = 0
    for f in (ledger or {}).get("findings", []) or []:
        candidates = [f.get("location", ""), f.get("file", "")]
        state = "untouched"
        for cand in candidates:
            if cand and in_scope(cand, scope) == "in-changed-file":
                state = "in-changed-file"
                # a location like "src/a.ts:42" carries a line — validate it against the hunks
                for c in candidates:
                    if c and ":" in str(c):
                        tail = str(c).rsplit(":", 1)[-1]
                        if tail.isdigit() and line_in_hunk(c, int(tail), scope):
                            state = "in-changed-hunk"
                break
        f["diff_state"] = state
        if state.startswith("in-changed"):
            changed += 1
            if state == "in-changed-hunk":
                in_hunk += 1
        else:
            untouched += 1
    return {"in_changed_file": changed, "in_changed_hunk": in_hunk, "untouched": untouched,
            "changed_files": len(scope.get("files", {}) or {})}


def render_md(scope: dict, counts: dict) -> str:
    if scope.get("error"):
        return (f"_Diff scoping unavailable ({scope['error']}) — the run below is UNSCOPED "
                "(whole repo)._")
    files = scope.get("files", {}) or {}
    if not files:
        return f"_No files changed vs `{scope.get('base')}` — nothing new to review._"
    lines = [f"Changed vs `{scope.get('base')}`: **{len(files)} file(s)**. "
             f"**{counts.get('in_changed_file', 0)}** finding(s) land in changed files "
             f"({counts.get('untouched', 0)} pre-existing elsewhere).\n",
             "| Changed file | Added/modified lines |", "|---|---|"]
    for f, ranges in sorted(files.items())[:40]:
        rng = ", ".join(f"{a}–{b}" if a != b else str(a) for a, b in ranges[:8]) or "_(no added lines)_"
        more = f" +{len(ranges) - 8} more" if len(ranges) > 8 else ""
        lines.append(f"| `{f}` | {rng}{more} |")
    if len(files) > 40:
        lines.append(f"\n_…{len(files) - 40} more changed files (full ranges in `diff-scope.json`)._")
    lines.append("\n_Exact hunk ranges are in `diff-scope.json` — use them to validate that any "
                 "reported finding actually sits on a changed line._")
    return "\n".join(lines)

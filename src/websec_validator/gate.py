"""`websec gate` — a fast, scoped security check for INSIDE the agent loop.

A finding surfaced after forty merges is a backlog item. The same finding surfaced inside the loop,
on the edit that caused it, is a retry. That is the whole difference, and it needs a pass that is
cheap enough to run per edit and a verdict an agent harness can act on.

`run` cannot be that: it walks and analyzes the whole tree (~43s on a 320-file repo), stages probe
templates, renders REPORT.md and AGENT-BRIEFING.md, emits SARIF and publishes an immutable run
directory. All of that is right for a review and wrong for a per-edit check.

`gate` keeps only the parts that decide pass/fail:
  * analysis scoped with `--only` semantics (~13x faster; see RepoContext for the two-tier design),
  * the findings ledger,
  * a severity threshold,
  * a JSON verdict on stdout and a meaningful exit code.

It writes NOTHING by default. An in-loop check that litters the tree with artifacts on every edit
would be worse than useless — and it must never advance an accepted baseline or a `latest` pointer,
because a fast scoped check is not a review.

TARGET SELECTION. Agent edits are UNCOMMITTED by definition, and `diffscope` uses three-dot
`base...HEAD`, which sees only committed work — it would return nothing for the exact case this
command exists to catch. So the default scope is the WORKING TREE: tracked modifications plus
untracked files, which is what an agent has just produced.

HONEST LIMITS, surfaced in the verdict rather than buried in docs:
  * A scoped pass sees one slice of the repo. It is a fast retry signal, NOT a review, and the
    verdict says so in `scope_note`.
  * Cross-file evidence outside the scope is not consulted. Measured on this project, scoping never
    INVENTED a finding (0 new across 17 files), which is the property that matters for a gate.
  * `missed` paths were never analyzed. Their absence from the findings is not a clean result.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

SEV_ORDER = ["low", "medium", "high", "critical"]
_TIMEOUT = 20
_MAX_FILES = 200

# Analyzing a file is pointless if no detector reads that suffix; this only trims the scope, it
# never suppresses a finding (an unlisted suffix would produce none anyway).
_CODE_SUFFIXES = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".go",
                  ".rb", ".php", ".java", ".cs", ".sql", ".tf", ".yml", ".yaml", ".json", ".toml",
                  ".env", ".sh", ".bash", ".vue", ".svelte", ".astro"}


def _git(repo: Path, *args: str):
    try:
        proc = subprocess.run(["git", "-C", str(repo), *args],
                              capture_output=True, text=True, timeout=_TIMEOUT)
    except Exception:
        return None
    return proc.stdout if proc.returncode == 0 else None


def working_tree_paths(repo: Path) -> dict:
    """Files an agent has just touched: tracked modifications plus untracked files.

    NOT `base...HEAD`. Three-dot diff is committed-only and would return nothing for uncommitted
    work, which is the entire case an in-loop gate exists to catch.
    """
    if _git(repo, "rev-parse", "--is-inside-work-tree") is None:
        return {"paths": [], "source": "not-a-git-repository",
                "note": "no VCS to derive changed files from; pass paths explicitly"}
    out: list[str] = []
    # -z keeps paths with spaces/newlines intact; porcelain v1 is stable across git versions.
    raw = _git(repo, "status", "--porcelain", "-z", "--untracked-files=all")
    if raw is None:
        # `git status` failed (timeout, index.lock contention, non-zero exit). An empty
        # path list here is NOT an empty working tree, and reporting source="working-tree"
        # would make the two indistinguishable — the gate would then pass having analysed
        # nothing. The rev-parse check above already draws this distinction; so does this.
        return {"paths": [], "source": "working-tree-unavailable",
                "note": "`git status` did not complete, so the changed-file set is unknown; "
                        "pass paths explicitly with --only"}
    if raw:
        for entry in raw.split("\0"):
            if len(entry) < 4:
                continue
            status, path = entry[:2], entry[3:]
            if "D" in status:            # deleted: nothing left to analyze
                continue
            if status.startswith("R"):   # rename records "new\0old"; the new name is this entry
                path = path.split("\0")[0]
            out.append(path)
    seen, paths = set(), []
    for path in out:
        if path in seen:
            continue
        seen.add(path)
        if Path(path).suffix.lower() in _CODE_SUFFIXES:
            paths.append(path)
    return {"paths": sorted(paths)[:_MAX_FILES], "source": "working-tree",
            "truncated": len(paths) > _MAX_FILES,
            "note": "tracked modifications plus untracked files; deletions excluded"}


CONF_ORDER = ["low", "medium", "high"]


def verdict(ledger: dict, facts: dict, threshold: str, *, scope_source: str = "explicit",
            min_confidence: str = "low") -> dict:
    """Pass/fail plus everything a harness needs to explain the decision to a model.

    THRESHOLD CHOICE. The default is MEDIUM, not HIGH, and that is deliberate: command injection,
    SSRF and the other classes this exists to catch on agent-written code are frequently rated
    MEDIUM here, so a HIGH default would look like it worked while missing the main case.

    CONFIDENCE. Severity and calibrated confidence are separate axes, and the gate does NOT apply a
    confidence floor by default. Repo-wide, MEDIUM/LOW is the largest bucket (38 of 97 on this
    project) — but a gate only ever analyses the one to three files just edited, so the per-edit
    volume is small. In the loop a false block costs one agent turn and is immediately recoverable,
    while a miss ships a vulnerability; at merge time that trade runs the other way. Confidence is
    reported on every finding so a model or a human can judge, and `--min-confidence` is there for
    teams that measure it as too noisy.
    """
    floor = SEV_ORDER.index(threshold.lower()) if threshold.lower() in SEV_ORDER else 1
    conf_floor = CONF_ORDER.index(min_confidence.lower()) if min_confidence.lower() in CONF_ORDER else 0

    def _blocks(f) -> bool:
        sev = str(f.get("severity", "LOW")).lower()
        if sev not in SEV_ORDER or SEV_ORDER.index(sev) < floor:
            return False
        conf = str(f.get("confidence", "LOW")).lower()
        # An UNKNOWN or unrecognised confidence must never be treated as below the floor: silently
        # dropping a finding because its confidence could not be graded is the wrong direction.
        return conf not in CONF_ORDER or CONF_ORDER.index(conf) >= conf_floor

    blocking = [f for f in ledger.get("findings", []) or [] if _blocks(f)]
    scope = facts.get("analysis_scope") or {}
    out = {
        "tool": "websec-validator",
        "command": "gate",
        "threshold": threshold.lower(),
        "min_confidence": min_confidence.lower(),
        "passed": not blocking,
        "blocking_count": len(blocking),
        "total_findings": ledger.get("total", len(ledger.get("findings", []) or [])),
        "analyzed": scope.get("matched", []),
        "missed": scope.get("missed", []),
        "scope_source": scope_source,
        "findings": [{"severity": f.get("severity"), "confidence": f.get("confidence"),
                      "title": f.get("title"), "file": f.get("file"), "line": f.get("line"),
                      "attack_class": f.get("attack_class"), "rule_id": f.get("rule_id"),
                      "remediation": f.get("remediation")}
                     for f in blocking],
        "scope_note": ("a scoped pass over the files just changed. This is a fast retry signal, not "
                       "a review: cross-file evidence outside the scope was not consulted, and a "
                       "clean result here does not mean the repository is clean."),
    }
    if out["missed"]:
        out["missed_note"] = ("these requested paths were never analyzed (excluded, generated, "
                              "unsupported suffix or absent); their absence from the findings is "
                              "NOT a clean result")
    return out


def render_text(result: dict) -> str:
    """What the agent harness feeds back to the model on a block — specific enough to act on."""
    if result["passed"]:
        n = len(result["analyzed"])
        return f"websec gate: pass ({n} file(s) analyzed, threshold {result['threshold']})"
    lines = [f"websec gate: FAILED — {result['blocking_count']} finding(s) at or above "
             f"{result['threshold']} in the files just changed.", ""]
    for f in result["findings"][:10]:
        where = f.get("file") or "(no file)"
        if f.get("line"):
            where += f":{f['line']}"
        lines.append(f"  [{f.get('severity')}] {where} — {f.get('title')}")
        if f.get("remediation"):
            lines.append(f"      fix: {f['remediation']}")
    if result["blocking_count"] > 10:
        lines.append(f"  … and {result['blocking_count'] - 10} more")
    lines += ["", "Fix these, then the check will re-run on the next edit.",
              "This is a scoped check of the changed files, not a full review."]
    return "\n".join(lines)


def to_json(result: dict) -> str:
    return json.dumps(result, indent=2)

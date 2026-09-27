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
  * Some extractors read manifests directly (CI workflows; with OWASP Noir, a `wrangler.jsonc`
    route table) no matter what `--only` names, so a scoped pass can still produce a finding ATTRIBUTED to a file
    outside the scope. That finding was not caused by this edit; it is reported under
    `outside_scope` and does not gate. A finding that names no repository file cannot be shown to
    be outside the scope, so it still gates — the safe direction for an unattributable result.
  * `.websec-ignore` applies exactly as it does in `run`: path/category suppressions drop, active
    `fingerprint:` acknowledgements move a finding to `acknowledged`, and an expired, malformed or
    reasonless acknowledgement excuses nothing (the finding gates with its `reopened_reason`).
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

SEV_ORDER = ["low", "medium", "high", "critical"]
_TIMEOUT = 20
_MAX_FILES = 200
_LIST_CAP = 20

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


def evaluate(root: Path, paths: list, threshold: str, *, version: str, scope_source: str,
             min_confidence: str = "low", excludes: list | None = None) -> dict:
    """The one gate path, shared by `websec gate` and the PostToolUse hook.

    Both used to build the ledger themselves with no ignore policy, and drifted from `run`
    identically: a finding reviewed and acknowledged in `.websec-ignore` blocked every agent edit.
    One function means the policy cannot be dropped from one entry point and kept in the other.
    """
    from . import findings, recon
    from .extractors.base import RepoContext
    root = Path(root)
    facts = recon.build_facts(root, version, excludes, only=paths)
    # One non-walking context serves both reads: `load_*` would otherwise walk the whole tree
    # twice more, tripling the cost of a check that runs on every edit.
    policy = RepoContext(root, walk=False)
    ledger = findings.build_ledger(facts, None, None,
                                   findings.load_suppressions(root, context=policy),
                                   findings.load_acknowledgements(root, context=policy))
    return verdict(ledger, facts, threshold, scope_source=scope_source,
                   min_confidence=min_confidence)


def _scope_key(path: str) -> str:
    # The exact normalization RepoContext applies to `only`, so both sides compare alike.
    return Path(path).as_posix()


def _named_paths(finding: dict, root: Path | None) -> list[str]:
    """Repository-relative paths a finding names: its `file` and its `location` minus :line."""
    out = []
    for value in (finding.get("file"), finding.get("location")):
        value = re.sub(r":L?\d+(?::\d+)?$", "", str(value or "").replace("\\", "/"))
        if not value:
            continue
        if Path(value).is_absolute():
            # A route location (/api/users) is absolute-looking too; only a path under the root
            # can name a repository file.
            try:
                value = Path(value).relative_to(root).as_posix() if root else ""
            except ValueError:
                value = ""
        if value and value not in out:
            out.append(value)
    return out


def _is_repo_file(root: Path, rel: str) -> bool:
    try:
        resolved = (root / rel).resolve()
        resolved.relative_to(root.resolve())
        return resolved.is_file()
    except (OSError, ValueError, RuntimeError):
        return False


def scope_state(finding: dict, requested: list, root: Path | None) -> str:
    """'in-scope' | 'outside-scope' | 'unattributed' for one finding against the requested paths.

    Outside-scope needs POSITIVE evidence: the finding names a file that exists in the repository
    and is not one of the requested paths. A route-only location or a missing file proves nothing
    about where the finding came from, so it stays gating ('unattributed').
    """
    if not requested:
        return "in-scope"
    wanted = {_scope_key(p) for p in requested}
    named = _named_paths(finding, root)
    if any(_scope_key(p) in wanted for p in named):
        return "in-scope"
    if root is not None and any(_is_repo_file(root, p) for p in named):
        return "outside-scope"
    return "unattributed"


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

    scope = facts.get("analysis_scope") or {}
    root = Path(facts["target"]) if facts.get("target") else None
    in_scope, outside = [], []
    for f in ledger.get("findings", []) or []:
        state = scope_state(f, scope.get("requested") or [], root)
        (outside if state == "outside-scope" else in_scope).append((f, state))
    blocking = [(f, state) for f, state in in_scope if _blocks(f)]
    acknowledged = ledger.get("acknowledged", []) or []
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
                      "remediation": f.get("remediation"), "fingerprint": f.get("fingerprint"),
                      "scope": state,
                      **({"reopened_reason": f["reopened_reason"]}
                         if f.get("reopened_reason") else {})}
                     for f, state in blocking],
        "outside_scope_count": len(outside),
        "outside_scope": [{"severity": f.get("severity"), "title": f.get("title"),
                           "file": f.get("file") or f.get("location"),
                           "fingerprint": f.get("fingerprint")}
                          for f, _ in outside[:_LIST_CAP]],
        "acknowledged_count": len(acknowledged),
        "acknowledged": [{"severity": f.get("severity"), "title": f.get("title"),
                          "file": f.get("file") or f.get("location"),
                          "fingerprint": f.get("fingerprint"),
                          "expires": (f.get("acknowledgement") or {}).get("expires"),
                          "reason": f.get("ack_reason")}
                         for f in acknowledged[:_LIST_CAP]],
        "scope_note": ("a scoped pass over the files just changed. This is a fast retry signal, not "
                       "a review: cross-file evidence outside the scope was not consulted, and a "
                       "clean result here does not mean the repository is clean."),
    }
    if outside:
        out["outside_scope_note"] = ("findings attributed to repository files OUTSIDE the requested "
                                     "scope (typically read directly from a config manifest). This "
                                     "edit did not cause them and they do not gate here; `websec "
                                     "run` still reports and gates them")
    if acknowledged:
        out["acknowledged_note"] = ("findings matched by an active `fingerprint:` acknowledgement in "
                                    ".websec-ignore; shown, not gating, exactly as in `websec run`")
    if out["missed"]:
        out["missed_note"] = ("these requested paths were never analyzed (excluded, generated, "
                              "unsupported suffix or absent); their absence from the findings is "
                              "NOT a clean result")
    return out


def render_text(result: dict) -> str:
    """What the agent harness feeds back to the model on a block — specific enough to act on."""
    if result["passed"]:
        n = len(result["analyzed"])
        missed = len(result.get("missed") or [])
        # Say what was set aside, so a pass never reads as "nothing was there at all".
        aside = [f"{c} {label}" for c, label in
                 ((result.get("acknowledged_count", 0), "acknowledged in .websec-ignore"),
                  (result.get("outside_scope_count", 0), "outside the changed files"))
                 if c]
        tail = f"; not gating: {', '.join(aside)}" if aside else ""
        # A pass over zero analysed files is the reading that must never look clean. The verdict
        # itself is unchanged (see `verdict`'s contract and test_gate_command); only the sentence
        # the model reads is, because a bare "pass (0 file(s) analyzed)" is indistinguishable from
        # a genuine all-clear.
        if missed and not n:
            return (f"websec gate: pass — but 0 file(s) were analyzed and {missed} requested path(s) "
                    f"were never looked at (threshold {result['threshold']}). "
                    "This is NOT a clean result: " + result.get("missed_note", "") + tail)
        if missed:
            return (f"websec gate: pass ({n} file(s) analyzed, threshold {result['threshold']}) — "
                    f"{missed} requested path(s) never analyzed; not a clean result for those{tail}")
        return f"websec gate: pass ({n} file(s) analyzed, threshold {result['threshold']}){tail}"
    lines = [f"websec gate: FAILED — {result['blocking_count']} finding(s) at or above "
             f"{result['threshold']} in the files just changed.", ""]
    for f in result["findings"][:10]:
        where = f.get("file") or "(no file)"
        if f.get("line"):
            where += f":{f['line']}"
        lines.append(f"  [{f.get('severity')}] {where} — {f.get('title')}")
        if f.get("remediation"):
            lines.append(f"      fix: {f['remediation']}")
        if f.get("reopened_reason"):
            lines.append(f"      note: {f['reopened_reason']} (fingerprint {f.get('fingerprint')})")
    if result["blocking_count"] > 10:
        lines.append(f"  … and {result['blocking_count'] - 10} more")
    lines += ["", "Fix these, then the check will re-run on the next edit.",
              "This is a scoped check of the changed files, not a full review."]
    return "\n".join(lines)


def to_json(result: dict) -> str:
    return json.dumps(result, indent=2)

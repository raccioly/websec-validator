"""Proof harness — score the recon engine against a known-vuln-app corpus.

WHAT THIS MEASURES (honest scope): for each deliberately-vulnerable app, does the
recon engine SURFACE the attack surface the app is known to have (right framework,
auth scheme, endpoint count, IDOR/GraphQL presence)? That's a deterministic,
regression-trackable PROXY for the engine's quality — it tells us the briefing
points the agent at the right places.

WHAT IT DOES NOT MEASURE: the full kill-criterion — whether handing the briefing
to a coding agent makes it find the *planted bugs* better than a generic prompt.
That A/B requires driving real agents against running apps; the protocol for it is
in corpus/PROOF-PROTOCOL.md and is a manual step.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from . import __version__, recon


def _ensure_repo(entry: dict, workdir: Path) -> Path | None:
    if entry.get("local_path") and Path(entry["local_path"]).is_dir():
        return Path(entry["local_path"])
    dest = workdir / entry["name"]
    if dest.is_dir() and any(dest.iterdir()):   # already cloned — reuse
        return dest
    if not entry.get("repo"):
        return None
    try:
        subprocess.run(["git", "clone", "--depth", "1", entry["repo"], str(dest)],
                       capture_output=True, text=True, check=True, timeout=240)
        return dest
    except Exception:
        return None


def _score(entry: dict, facts: dict) -> dict:
    exp = entry.get("expect", {})
    stack = facts.get("stack", {})
    routes = facts.get("routes", {})
    tgt = routes.get("targeting", {})
    auth = facts.get("auth", {})
    gql = facts.get("graphql", {})
    checks = []

    def chk(name, ok, got):
        checks.append({"check": name, "pass": bool(ok), "got": got})

    if "frameworks" in exp:
        got = stack.get("frameworks", [])
        chk("frameworks ⊇ expected", set(exp["frameworks"]).issubset(set(got)), got)
    if "min_endpoints" in exp:
        chk(f"endpoints ≥ {exp['min_endpoints']}", routes.get("count", 0) >= exp["min_endpoints"], routes.get("count", 0))
    if "auth_scheme_contains" in exp:
        hay = (auth.get("scheme", "") + " " + " ".join(auth.get("schemes_detected", []))).lower()
        chk(f"auth ~ '{exp['auth_scheme_contains']}'", exp["auth_scheme_contains"] in hay, auth.get("scheme"))
    if exp.get("idor_present"):
        n = len(tgt.get("idor_candidates", []))
        chk("IDOR candidates found", n > 0, n)
    if exp.get("graphql_present"):
        chk("GraphQL detected", gql.get("present", False), gql.get("present", False))
    if exp.get("tenant_key"):
        keys = [c["key"] for c in facts.get("tenant", {}).get("candidates", [])]
        chk(f"tenant key '{exp['tenant_key']}'", exp["tenant_key"] in keys, keys[:3])

    passed = sum(1 for c in checks if c["pass"])
    return {"checks": checks, "passed": passed, "total": len(checks),
            "score": round(passed / len(checks), 2) if checks else None}


def run_proof(corpus_path: Path, workdir: Path) -> dict:
    corpus = json.loads(Path(corpus_path).read_text())
    workdir.mkdir(parents=True, exist_ok=True)
    results = []
    for entry in corpus:
        repo = _ensure_repo(entry, workdir)
        if not repo:
            results.append({"name": entry["name"], "status": "unavailable (clone failed / no local_path)"})
            continue
        try:
            facts = recon.build_facts(repo, __version__)
        except Exception as e:
            results.append({"name": entry["name"], "status": f"recon error: {e}"})
            continue
        results.append({"name": entry["name"], "endpoints": facts.get("routes", {}).get("count"),
                        "vulns": entry.get("vulns", ""), **_score(entry, facts)})

    total_checks = sum(r.get("total", 0) for r in results)
    total_pass = sum(r.get("passed", 0) for r in results)
    return {"results": results,
            "aggregate": {"apps": len(results),
                          "overall_coverage": round(total_pass / total_checks, 2) if total_checks else None,
                          "checks_passed": total_pass, "checks_total": total_checks}}

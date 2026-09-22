"""Attack-Surface Inventory — the per-endpoint planning table a pentester (or an AI agent) actually needs.

Every other section of the briefing answers "what did we find?". This one answers **"where do I attack,
and in what order?"** — it joins data websec already collects into one ranked row per endpoint:

    method + path → handler file → auth guard? → path params → risk tags (IDOR/SSRF/upload/write/auth)
                  → dangerous sinks in that handler → a deterministic risk score + the reasons for it

Commercial platforms (Aikido's "whitebox discovery", pentest-tools' "attack-surface mapping") produce
this by running the app with an LLM driving. It is derivable **statically and deterministically** from
the extractor output — no LLM, no live target. This module is the substrate for the DAST-prediction and
pentest-test-plan sections, and it is emitted as `attack-surface.json` for downstream tooling.

Scoring is intentionally simple, explainable, and additive — every point carries a human-readable
reason. It ranks *what to test first*; it never asserts exploitability.
"""

from __future__ import annotations

from pathlib import Path

# Sinks whose presence in a handler materially raises "test this endpoint first". Ordered by blast
# radius: a SQLi/command-injection sink behind an unguarded route is the classic critical chain.
_HIGH_RISK_SINKS = {"sql-injection", "sqli", "command-injection", "eval-injection", "deserialization",
                    "nosql-injection", "path-traversal", "ssrf", "ssrf-outbound-http", "xxe"}
_WRITE_VERBS = {"POST", "PUT", "PATCH", "DELETE"}


def _rel(code_path: str, target: str | None) -> str:
    """Route code_paths come from Noir as ABSOLUTE; guards/sinks are repo-relative. Normalize."""
    p = (code_path or "").replace("\\", "/")
    if not p or not target:
        return p
    try:
        if Path(p).is_absolute():
            return Path(p).resolve().relative_to(Path(target).resolve()).as_posix()
    except (ValueError, OSError):
        return p
    return p


def _tagged(targeting: dict, key: str, method: str, path: str) -> bool:
    """targeting lists are display strings ('GET /api/x  (param: url)') — match the METHOD PATH head.

    Must match on a BOUNDARY, not a bare prefix: `GET /api/user` would otherwise pick up the entry
    for `GET /api/users/{id}` and inherit its IDOR tag, which then flows into the test plan as a BOLA
    target aimed at the wrong endpoint."""
    head = f"{method} {path}"
    for entry in (targeting.get(key) or []):
        e = str(entry)
        if e == head or e.startswith(head + " ") or e.startswith(head + "\t"):
            return True
    return False


def build(facts: dict) -> dict:
    """→ {endpoints: [ranked rows], summary: {...}}. Pure: no I/O, no network, deterministic."""
    routes = facts.get("routes", {}) or {}
    targeting = routes.get("targeting", {}) or {}
    target = facts.get("target")
    endpoints = routes.get("endpoints", []) or []
    guards = (facts.get("authz", {}) or {}).get("endpoint_guards", []) or []
    endpoint_groups, guard_groups = {}, {}
    for index, endpoint in enumerate(endpoints):
        endpoint_groups.setdefault((endpoint.get("method", "GET"), endpoint.get("path", "")), []).append(index)
    for guard in guards:
        guard_groups.setdefault((guard.get("method"), guard.get("path")), []).append(guard)

    def compatible(endpoint, guard):
        for key in ("service_id", "code_path"):
            left, right = endpoint.get(key), guard.get(key)
            if key == "code_path":
                left, right = _rel(left, target), _rel(right, target)
            if left and right and left != right:
                return False
        return True

    def guard_for(index, endpoint):
        key = (endpoint.get("method", "GET"), endpoint.get("path", ""))
        candidates = [guard for guard in guard_groups.get(key, []) if compatible(endpoint, guard)]
        if len(candidates) != 1:
            return {}
        guard = candidates[0]
        # Legacy rows without a service/source may be used only for a unique route.
        # Do not fan a single guard out to several same-path service registrations.
        matches = [other for other in endpoint_groups[key] if compatible(endpoints[other], guard)]
        return guard if matches == [index] else {}
    # sink class → set of files containing it
    sink_files: dict = {}
    for cls, info in ((facts.get("surface", {}) or {}).get("sinks", {}) or {}).items():
        for f in (info or {}).get("files", []) or []:
            sink_files.setdefault(str(f).replace("\\", "/"), set()).add(cls)

    rows = []
    for index, ep in enumerate(endpoints):
        method = ep.get("method", "GET")
        path = ep.get("path", "")
        rel = _rel(str(ep.get("code_path", "")), target)
        g = guard_for(index, ep)
        guarded = g.get("guarded")
        analyzed = bool(g.get("analyzed"))
        public_hint = bool(g.get("public_hint"))
        is_write = method in _WRITE_VERBS
        params = ep.get("params", []) or []
        path_params = [p.get("name") for p in params if p.get("where") == "path"]
        sinks = sorted(sink_files.get(rel, set()))
        hot_sinks = [s for s in sinks if s in _HIGH_RISK_SINKS]

        # auth verdict: only claim UNGUARDED when the analyzer actually looked and found no guard
        if not analyzed or guarded not in (True, False):
            auth = "unknown"
        elif guarded:
            auth = "guarded"
        elif public_hint:
            auth = "public (intentional)"
        else:
            auth = "UNGUARDED"

        risk, why = 0, []
        if auth == "UNGUARDED":
            if is_write:
                risk += 4
                why.append("write endpoint with no visible guard")
            else:
                risk += 3
                why.append("no visible auth guard")
        if _tagged(targeting, "idor_candidates", method, path):
            risk += 3
            why.append("IDOR/BOLA candidate (object id in path)")
        if hot_sinks:
            risk += 3
            # HONEST SCOPE: sinks are attributed per FILE (the extractors record file, not the enclosing
            # function). Say "in this file", never "in this handler" — several endpoints can share a file
            # and only one may hold the sink. Over-claiming per-endpoint would be a false positive.
            why.append(f"high-risk sink in the same file: {', '.join(hot_sinks)}")
        if _tagged(targeting, "upload_candidates", method, path):
            risk += 2
            why.append("file-upload surface")
        if _tagged(targeting, "ssrf_candidates", method, path):
            risk += 2
            why.append("SSRF candidate (url-ish param)")
        if _tagged(targeting, "open_redirect_candidates", method, path):
            risk += 1
            why.append("open-redirect candidate")
        if _tagged(targeting, "auth_endpoints", method, path):
            risk += 1
            why.append("auth endpoint (credential-attack surface)")
        if path_params and auth == "UNGUARDED":
            risk += 1
            why.append("enumerable path param on an unguarded route")

        rows.append({
            "method": method, "path": path, "handler": rel,
            "service_id": ep.get("service_id") or g.get("service_id") or "",
            "technology": ep.get("technology", ""), "auth": auth,
            "path_params": path_params,
            "params": [p.get("name") for p in params if p.get("name")],
            "sinks": sinks, "risk": risk, "why": why,
            "is_write": is_write,
        })

    # rank: highest risk first, then writes, then path for stable output
    rows.sort(key=lambda r: (-r["risk"], not r["is_write"], r["path"], r["method"], r["service_id"], r["handler"]))
    summary = {
        "endpoints": len(rows),
        "unguarded": sum(1 for r in rows if r["auth"] == "UNGUARDED"),
        "unguarded_writes": sum(1 for r in rows if r["auth"] == "UNGUARDED" and r["is_write"]),
        "with_high_risk_sink": sum(1 for r in rows if any(s in _HIGH_RISK_SINKS for s in r["sinks"])),
        "idor_candidates": len(targeting.get("idor_candidates") or []),
        "top_risk": rows[0]["risk"] if rows else 0,
    }
    return {"endpoints": rows, "summary": summary}


def render_md(inv: dict, limit: int = 25, coverage: dict | None = None) -> str:
    """Markdown table for the briefing/report — the 'test this first' ordering.

    `coverage` is optional so existing callers are unaffected; when supplied, an empty route table
    names the *actual* cause where we know it. Blaming "route discovery failed" for a repository
    written in a language we never read sends the reader to debug the wrong thing.
    """
    rows = inv.get("endpoints", []) or []
    if not rows:
        langs = ((coverage or {}).get("files", {}) or {}).get("unanalyzed_languages") or {}
        if langs:
            named = ", ".join(f"{lang} ({n} file(s))" for lang, n in langs.items())
            return (f"_No endpoints mapped — **websec has no analyzer for {named}**, so no route in "
                    "those files could be discovered. This is not an empty application._")
        return "_No endpoints mapped — nothing to inventory (a library/CLI, or route discovery failed)._"
    s = inv.get("summary", {})
    head = (f"**{s.get('endpoints', 0)} endpoint(s)** · **{s.get('unguarded', 0)} with no visible guard** "
            f"({s.get('unguarded_writes', 0)} of them writes) · "
            f"{s.get('with_high_risk_sink', 0)} whose file holds a high-risk sink\n\n"
            "_Sinks are attributed per FILE (not per handler function) — several endpoints can share a "
            "file and only one may hold the sink. Treat it as \"look here\", not \"this endpoint is "
            "vulnerable\"._\n\n"
            "| # | Endpoint | Service | Auth | Handler file | Sinks (in file) | Risk | Why test it |\n"
            "|---|---|---|---|---|---|---|---|\n")
    body = []
    for i, r in enumerate(rows[:limit], 1):
        why = "; ".join(r["why"]) or "—"
        sinks = ", ".join(r["sinks"]) or "—"
        body.append(f"| {i} | `{r['method']} {r['path']}` | `{r.get('service_id') or '?'}` | {r['auth']} | `{r['handler'] or '?'}` | "
                    f"{sinks} | **{r['risk']}** | {why} |")
    more = (f"\n\n_…{len(rows) - limit} more in `attack-surface.json`._" if len(rows) > limit else "")
    return head + "\n".join(body) + more

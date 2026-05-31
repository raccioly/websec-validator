"""Comprehensive, human-readable REPORT.md — the historical artifact.

Every `websec run` writes one of these into an immutable timestamped run dir, so
you get a durable record of the whole pass: stack, attack surface, access-control
map, de-duplicated static findings, and (when present) dynamic results — all in
one doc. Structured so it can grow into the traceable findings ledger (evidence
chain + standards citations + calibrated confidence) without being rebuilt.
"""

from __future__ import annotations

from .briefing import _bullets, _section


def render(facts: dict, scanners: dict, scan_results: list, unified: dict | None,
           probe_manifest: list, timestamp: str) -> str:
    stack = facts.get("stack", {})
    routes = facts.get("routes", {})
    tgt = routes.get("targeting", {})
    authz = facts.get("authz", {})
    gs = authz.get("guard_summary", {})
    surface = facts.get("surface", {})

    # executive summary
    sev = (unified or {}).get("by_severity", {})
    sev_line = " · ".join(f"{k}: {v}" for k, v in sev.items()) if sev else "_run with --scan for static findings_"
    unprot = authz.get("write_endpoints_without_visible_guard", [])

    top_findings = ""
    if unified and unified.get("top"):
        top_findings = "\n".join(
            f"- **{t['severity']}** [{t['category']}] {t['title']} — `{t['file']}` ({'+'.join(t['tools'])})"
            for t in unified["top"])
    else:
        top_findings = "_no static scan run (use `--scan`)_"

    sinks = ", ".join(f"{k} ({n})" for k, n in surface.get("sink_counts", {}).items()) or "none"

    return f"""# websec-validator report — {facts.get('target','')}

> Generated {timestamp} · websec-validator v{facts.get('version','')} · **immutable run record** (never overwritten).
> Deterministic recon — no LLM. Hand `AGENT-BRIEFING.md` (same dir) to your coding agent to act on this.

## Executive summary

| | |
|---|---|
| Stack | {", ".join(stack.get("languages", [])) or "?"} · {", ".join(stack.get("frameworks", [])) or "?"} · {", ".join(stack.get("datastores", [])) or "?"} |
| Endpoints | **{routes.get('count', 0)}** (via {routes.get('engine','?').split(' ')[0]}) |
| Auth | {facts.get('auth', {}).get('scheme','?')} · roles: {', '.join(authz.get('roles_detected', [])) or 'none'} |
| Access control | {gs.get('with_visible_guard', 0)} guarded · **{gs.get('no_visible_guard', 0)} no visible guard** · global-middleware: {authz.get('global_auth_middleware', False)} |
| Static findings | {sev_line} |
| Attack surface | IDOR: {len(tgt.get('idor_candidates', []))} · SSRF: {len(tgt.get('ssrf_candidates', []))} · upload: {len(tgt.get('upload_candidates', []))} · writes: {len(tgt.get('write_endpoints', []))} |

## 1. Static findings (de-duplicated, severity-ranked)

{top_findings}
{('' if not unified else f"_…{unified['total']} total, {unified['cross_tool_or_dup_merged']} merged. Full list in findings.json._")}

## 2. Access control

{_section("⚠ Write endpoints with no visible guard (verify — top missing-authz leads)", unprot)}
{authz.get("note","")}

## 3. Attack surface & targeting

{_section("IDOR / BOLA candidates", tgt.get("idor_candidates"))}
{_section("SSRF candidates", tgt.get("ssrf_candidates"))}
{_section("File-upload candidates", tgt.get("upload_candidates"))}
**Code-level sinks (user-input-gated):** {sinks}

## 4. Config / CI-CD / client-side

**IaC/CI:** {len((facts.get("iac_ci") or {}).get("findings", []))} finding(s) · **GraphQL:** {(facts.get("graphql") or {}).get("present", False)} · **client-side secret exposure:** {len((facts.get("client_exposure") or {}).get("public_secret_leaks", []) + (facts.get("client_exposure") or {}).get("server_secret_in_client_component", []))}

## 5. Staged probes

{_bullets([f"`{p['key']}` — {p.get('attack_class','')}" for p in probe_manifest if 'attack_class' in p])}

## Appendix — endpoint inventory

{_bullets([f"`{e['method']:6}` {e['path']}" for e in routes.get("endpoints", [])], cap=200)}

---
_Roadmap: this report grows into a traceable findings ledger — each finding gaining an evidence
chain (recon → static → dynamic), an OWASP/CWE citation, and a calibrated H/M/L confidence._
"""

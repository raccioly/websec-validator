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
           probe_manifest: list, timestamp: str, ledger: dict | None = None) -> str:
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

    if ledger and ledger.get("findings"):
        _ll = []
        for f in ledger["findings"][:60]:
            cwe = (f["standards"]["cwe"][:1] or [""])[0]
            chain = " → ".join(e["layer"] for e in f["evidence"])
            api = (" · " + ", ".join(f["standards"]["owasp_api"])) if f["standards"]["owasp_api"] else ""
            cal = f.get("calibrated") or {}
            calstr = (f" · P(real)≈**{cal.get('p')}** CI {cal.get('ci')} (n={cal.get('n')}, {cal.get('basis')})"
                      if cal else "")
            _ll.append(f"- **[{f['severity']}/{f['confidence']}]** {f['title']}  \n"
                       f"  `{f['location']}` · evidence: {chain} · {cwe}{api}{calstr}  \n"
                       f"  _fix:_ {f['remediation']}")
        ledger_block = "\n".join(_ll)
        ledger_hdr = (f"**{ledger['total']} findings** · {ledger['by_severity']} · "
                      f"confidence {ledger['by_confidence']}"
                      + (f" · {ledger['suppressed']} suppressed" if ledger.get('suppressed') else ""))
    else:
        ledger_block, ledger_hdr = top_findings, sev_line

    cal_caveat = ((ledger or {}).get("calibration", {}).get("caveat")
                  or "calibrated on a vuln-app corpus — indicative only, skews optimistic on clean code")

    return f"""# websec-validator report — {facts.get('target','')}

> Generated {timestamp} · websec-validator v{facts.get('version','')} · **immutable run record** (never overwritten).
> Deterministic recon — no LLM. Hand `AGENT-BRIEFING.md` (same dir) to your coding agent to act on this.

## Executive summary

| | |
|---|---|
| Stack | {", ".join(stack.get("languages", [])) or "?"} · {", ".join(stack.get("frameworks", [])) or "?"} · {", ".join(stack.get("datastores", [])) or "?"} |
| Endpoints | **{routes.get('count', 0)}** app routes (via {routes.get('engine','?').split(' ')[0]}){(" · " + str(routes.get('spec_derived_excluded')) + " spec-derived excluded") if routes.get('spec_derived_excluded') else ""} |
| Auth | {facts.get('auth', {}).get('scheme','?')} · roles: {', '.join(authz.get('roles_detected', [])) or 'none'} |
| Access control | {gs.get('with_visible_guard', 0)} guarded · **{gs.get('no_visible_guard', 0)} no visible guard** · global-middleware: {authz.get('global_auth_middleware', False)} |
| Static scanner (raw, pre-triage) | {sev_line} |
| **Findings ledger** (triaged + calibrated) | {ledger_hdr} |
| Attack surface | IDOR: {len(tgt.get('idor_candidates', []))} · SSRF: {len(tgt.get('ssrf_candidates', []))} · upload: {len(tgt.get('upload_candidates', []))} · writes: {len(tgt.get('write_endpoints', []))} |

## 1. Findings ledger (ranked · evidence chain · standards · confidence)

{ledger_block}

_Full ledger with complete evidence chains + remediation in `findings-ledger.json`. Confidence: HIGH = dynamically confirmed or verified; MEDIUM = concrete static evidence; LOW = single-source hypothesis to verify._

_**P(real)** = measured real-vuln rate for that attack-class/confidence bucket, with a 95% confidence interval and sample size `n` ({cal_caveat}). A wide CI or `basis: prior (uncalibrated)` means thin data — lean on the verification debate, not the number; to be conservative, threshold on the CI lower bound._

## 2. Access control

{_section("⚠ Write endpoints with no visible guard (verify — top missing-authz leads)", unprot)}
{authz.get("note","")}

## 3. Attack surface & targeting

{_section("IDOR / BOLA candidates", tgt.get("idor_candidates"))}
{_section("SSRF candidates", tgt.get("ssrf_candidates"))}
{_section("File-upload candidates", tgt.get("upload_candidates"))}
**Code-level sinks (user-input-gated):** {sinks}

**Mass-assignment targets (privileged model fields):** {", ".join(facts.get("schemas", {}).get("sensitive_fields", [])) or "none detected"}  ·  ORMs: {", ".join(facts.get("schemas", {}).get("orms", [])) or "?"}

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

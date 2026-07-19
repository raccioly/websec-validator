"""Render AGENT-BRIEFING.md — the marching orders for the AI coding agent.

Now driven by the full recon facts: it leads with the *targeting* (which exact
endpoints are SSRF/IDOR/upload candidates), because that's what turns a generic
probe into a precise one.
"""

from __future__ import annotations


def _bullets(items, empty="_(none)_", cap=40):
    items = list(items or [])
    if not items:
        return empty
    shown = items[:cap]
    out = "\n".join(f"- {x}" for x in shown)
    if len(items) > cap:
        out += f"\n- _…and {len(items) - cap} more (see FACTS.json)_"
    return out


def _section(title, items):
    return f"**{title}** ({len(items or [])}):\n{_bullets(items)}\n"


def render(facts: dict, scanners: dict, scan_results: list, probe_manifest: list,
           unified: dict | None = None, ledger: dict | None = None) -> str:
    stack = facts.get("stack", {})
    auth = facts.get("auth", {})
    routes = facts.get("routes", {})
    tgt = routes.get("targeting", {})
    tenant = facts.get("tenant", {})
    surface = facts.get("surface", {})
    sink_summary = ", ".join(f"{k} ({n})" for k, n in surface.get("sink_counts", {}).items()) or "_none_"

    # §3a/§4b/§5b — the planning trio, all off the same inventory (built once).
    from . import dast_predict as _dast
    from . import inventory as _inventory
    from . import testplan as _testplan
    _inv = _inventory.build(facts)
    _pred = _dast.predict(facts, ledger)
    inventory_md = _inventory.render_md(_inv)                      # §3a — ranked "test in this order"
    dast_md = _dast.render_md(_pred)                              # §4b — predicted scanner alerts + blind spots
    testplan_md = _testplan.render_md(_testplan.build(facts, _inv, _pred))  # §5b — phased runbook
    # §4c — findings a reviewer/LLM-reviewer would routinely filter (tagged, never dropped).
    from . import fpfilter as _fpfilter
    from . import fixprompt as _fixprompt
    _fp_counts = {"likely_filtered": sum(1 for f in ((ledger or {}).get("findings") or [])
                                         if f.get("likely_filtered"))}
    fpfilter_md = _fpfilter.render_md(ledger or {}, _fp_counts)
    # §6b — one paste-ready fix instruction per finding, each ending in a VERIFY step.
    fixprompts_md = _fixprompt.render_md(_fixprompt.build(ledger or {}))

    authz = facts.get("authz", {})
    gs = authz.get("guard_summary", {})
    global_auth = authz.get("global_auth_middleware", False)
    roles_str = ", ".join(f"`{r}`" for r in authz.get("roles_detected", [])) or "_none detected_"
    unprot = authz.get("write_endpoints_without_visible_guard", [])
    unprot_section = (_section("Write endpoints with NO guard visible in their handler file (verify)", unprot)
                      if unprot else "_Every write endpoint has a visible guard or looks public — still spot-check._")
    mw = authz.get("next_middleware", {})
    mw_line = (f"Next.js middleware `{mw.get('file')}` gates matchers: {mw.get('matchers')}"
               if mw.get("present") else "_No Next.js middleware.ts found — auth is per-handler._")

    iac = facts.get("iac_ci", {})
    iac_findings = iac.get("findings", [])
    iac_lines = "\n".join(f"- **{f['severity']}** `{f['kind']}` — `{f['file']}` — {f['detail']}"
                          for f in iac_findings[:20]) or "_none_"
    client = facts.get("client_exposure", {})
    client_leaks = (client.get("public_secret_leaks", []) + client.get("server_secret_in_client_component", [])
                    + client.get("public_secret_value_leaks", []) + client.get("public_var_from_cfn_output", []))
    client_section = _bullets(client_leaks) if client_leaks else "_none detected_"

    ci = facts.get("client_integrity", {})
    ci_findings = ci.get("findings", [])
    ci_section = ("\n".join(f"- **{f.get('severity')}/{f.get('confidence','LOW')}** {f.get('issue')}"
                            for f in ci_findings) if ci_findings
                  else "_no fund-redirecting display values detected (MITB class N/A)_" if not ci.get("sensitive_display")
                  else "_sensitive display present; strict CSP + out-of-band anchor look present — spot-check_")

    pp = facts.get("password_policy", {})
    if pp.get("drift"):
        pp_line = f"⚠ DRIFT — {len(pp['drift'])} sibling route(s) weaker than the strongest set {pp.get('strongest_policy')}"
    elif pp.get("weak_policy"):
        pp_line = f"uniform but WEAK — enforces only {pp.get('weak_policy')}"
    elif pp.get("password_blocks"):
        pp_line = f"looks consistent across {len(pp['password_blocks'])} validator block(s)"
    else:
        pp_line = "_no password validators detected_"
    if ((pp.get("password_reuse") or {}).get("gap")):
        pp_line += "  ·  ⚠ NO reuse/history control (#6)"

    up = facts.get("upload_security", {})
    up_findings = up.get("findings", [])
    up_section = ("\n".join(f"- **{f.get('severity')}** {f.get('kind')} — `{f.get('file')}`" for f in up_findings[:20])
                  if up_findings else
                  ("_upload handler(s) present; allow-list + nosniff look ok — spot-check_" if up.get("upload_handlers")
                   else "_no upload handlers detected_"))
    pii = facts.get("pii_exposure", {})
    pii_findings = pii.get("findings", [])
    pii_section = ("\n".join(f"- **{f.get('severity')}** {f.get('kind')} — `{f.get('file')}`" for f in pii_findings[:20])
                   if pii_findings else "_no obvious raw-PII responses / dead masking controls_")
    llm = facts.get("llm_security", {})
    llm_findings = llm.get("findings", [])
    if llm.get("is_ai_app"):
        llm_section = ("\n".join(f"- **{f.get('severity')}** {f.get('kind')} — `{f.get('file')}`" for f in llm_findings[:25])
                       if llm_findings else "_LLM call sites present; no obvious prompt-injection / unbounded / "
                       "insecure-output tells — verify the agentic surface by hand_")
        if len(llm_findings) > 25:
            llm_section += f"\n- _…and {len(llm_findings) - 25} more (see FACTS.json)_"
    else:
        llm_section = "_no direct LLM SDK call sites detected_"
    ws_line = (facts.get("client_integrity", {}) or {}).get("websocket_auth", "no websocket detected")
    _cs = (facts.get("transport_security", {}) or {}).get("cookie_security")
    if _cs:
        if _cs.get("httponly") and _cs.get("secure") and _cs.get("samesite"):
            cookie_line = "✓ HttpOnly + Secure + SameSite present (checked — verify against the live Set-Cookie)"
        else:
            _miss = [n for n, k in (("HttpOnly", "httponly"), ("Secure", "secure"), ("SameSite", "samesite")) if not _cs.get(k)]
            cookie_line = f"⚠ cookie set WITHOUT {', '.join(_miss)} — an auth/session cookie should be HttpOnly + Secure + SameSite"
    else:
        cookie_line = "_no Set-Cookie detected_"

    gql = facts.get("graphql", {})
    if gql.get("present"):
        gfind = "; ".join(f"{x['severity']} {x['issue']}" for x in gql.get("findings", [])) or "no obvious issues"
        gql_line = f"{', '.join(gql.get('endpoints', []))} · introspection={gql.get('introspection')} · {gfind}"
    else:
        gql_line = "_no GraphQL detected_"
    integ = facts.get("integrations", {})
    integ_line = ", ".join(integ.get("third_party_integrations", [])) or "none detected"
    wh_unverified = integ.get("webhooks_without_sig_verification", [])
    wh_line = (_section("⚠ Webhooks with NO signature-verification in their handler (verify)", wh_unverified)
               if wh_unverified else f"_{len(integ.get('webhook_endpoints', []))} webhook endpoint(s); signature code present or none found_")
    # licensing / entitlement verification-trust gaps (revocation bypass + no per-license seat cap)
    ent_finds = [f for f in integ.get("findings", [])
                 if f.get("attack_class") in ("entitlement-revocation-bypass", "missing-usage-cap")]
    ent_line = (_section("⚠ License/entitlement verification gaps (verify + fix)",
                         [f"{f['severity']} {f['attack_class']}: {f['file']}" for f in ent_finds])
                if ent_finds else "_no license/entitlement verification-trust gaps detected_")
    # WebExtension client-trust surface (chrome.storage entitlement gate / host perms / world:MAIN)
    wx = facts.get("webext", {})
    if wx.get("is_extension"):
        wx_finds = [f"{f['severity']} {f['attack_class']}: {f['file']}" for f in wx.get("findings", [])]
        webext_line = (f"MV{wx.get('manifest_version')} extension · entitlement gates: "
                       f"{', '.join(wx.get('client_entitlement_gates', [])) or 'none'}\n"
                       + (_section("⚠ Extension client-trust (client storage is USER-EDITABLE — enforce paid "
                                   "features server-side)", wx_finds)
                          if wx_finds else "_no extension client-trust findings_"))
    else:
        webext_line = "_no WebExtension manifest detected_"

    avail = ", ".join(s["name"] for s in scanners.get("available", [])) or "none on PATH"
    missing = "\n".join(f"- **{s['name']}** ({s['category']}) — `{s.get('install','')}`"
                        for s in scanners.get("missing", [])) or "_all relevant scanners present_"
    if scan_results:
        scan_lines = "\n".join(
            (f"- **{r.get('name')}** → {r.get('findings','?')} finding(s) (`{r.get('output','')}`)"
             if "findings" in r else f"- **{r.get('name')}** → {r.get('status','?')}")
            for r in scan_results)
    else:
        scan_lines = "_Detected but not executed — run `websec run <repo> --scan`._"

    if unified:
        top_lines = "\n".join(
            f"- **{t['severity']}** [{t['category']}] {t['title']} — `{t['file']}` ({'+'.join(t['tools'])})"
            for t in unified.get("top", [])) or "_no findings_"
        findings_block = (
            f"**{unified['total']} de-duplicated findings** "
            f"({unified['cross_tool_or_dup_merged']} cross-tool/duplicate merged) · "
            f"by severity {unified['by_severity']} · by category {unified['by_category']}\n\n"
            f"Top findings (full list in `findings.json`):\n{top_lines}")
    else:
        findings_block = scan_lines

    probe_lines = "\n".join(
        f"- **{p['key']}** — {p.get('attack_class','')}  \n"
        f"  `{p['file']}` · _supply:_ {p.get('agent_must_supply','')}"
        for p in probe_manifest if "attack_class" in p)

    endpoints = routes.get("endpoints", [])
    inventory = _bullets([f"`{e['method']:6}` {e['path']}" for e in endpoints], cap=80)

    partial_banner = (
        f"\n> ⚠️ **PARTIAL SCAN** — the walker stopped at the {facts.get('file_cap','?')}-file cap "
        f"({facts.get('files_scanned','?')} files read, filesystem order), so recon may be INCOMPLETE on "
        "this repo. Re-run scoped to a subdirectory or with `--exclude` to cover the rest before trusting "
        "an absence of findings.\n" if facts.get("files_truncated") else "")

    # Blast-radius prioritization (only when a graphify graph enriched the ledger). Highest-radius
    # findings touch the most of the app, so verify those first.
    blast_section = ""
    ge = (ledger or {}).get("graph_enrichment")
    if ge and ge.get("mapped"):
        ranked = sorted(
            ((f.get("graph", {}).get("blast_radius", 0), f) for f in (ledger.get("findings") or [])
             if f.get("graph", {}).get("blast_radius")),
            key=lambda x: -x[0])
        rows = "\n".join(
            f"- **{r}** module(s) depend on → `{f.get('location')}` — {f.get('title')}"
            for r, f in ranked[:8])
        blast_section = (
            f"\n## 3d. ★ Blast radius (graph-derived — verify high-radius findings FIRST)\n\n"
            f"A graphify knowledge graph mapped {ge['mapped']} finding(s) to code nodes. The more of the "
            f"app that transitively depends on a vulnerable file, the more a single bug there costs — so "
            f"triage these top-down:\n\n{rows}\n\n"
            f"_Source: {ge['graph']} · max radius {ge['max_blast_radius']} across {ge['nodes']} nodes._\n"
            if rows else "")

    return f"""# AGENT BRIEFING — security pass for `{facts.get('target','')}`

> **Scope & authorization.** Defensive self-assessment of the operator's own codebase, run with their
> consent. Static recon is **read-only** — nothing here touches a live system. The probes are
> **drafts**: run them only against a TEST instance the human owns and supplies, one approved run at a
> time; production and third-party targets are out of scope. Proceed on this basis — the static review
> needs no further escalation.

> Generated by **websec-validator v{facts.get('version','')}** — deterministic recon, no LLM.
> **You are an AI coding agent.** The tool did the reliable half (mapping the surface + staging
> the probes). You + the human do the reasoning, the running, and the fixing.

| Lane | Owns |
|---|---|
| 🔧 tool (done) | recon → {routes.get('count',0)} endpoints, scanner findings, staged probes |
| 🤖 you | confirm auth/tenant model, finalize + run the probes at the targets below, triage, fix |
| 🧑 human | running TEST instance + test accounts; review every diff |

⚠️ Static findings + recon need **no running app**. The probes need a **live test instance + test
credentials** — ask the human, never fabricate, never hit production.
{partial_banner}
---

## 1. What this app is (detected)

- **Languages:** {", ".join(stack.get("languages", [])) or "?"}  ·  **Frameworks:** {", ".join(stack.get("frameworks", [])) or "?"}
- **Datastores:** {", ".join(stack.get("datastores", [])) or "?"}  ·  **Monorepo:** {stack.get("monorepo", False)}
- **Auth scheme:** `{auth.get("scheme","?")}` (token in {auth.get("token_location","?")})  ·  guard files: {len(auth.get("guard_files", []))}
- **Route engine:** {routes.get("engine","?")}  ·  **{routes.get('count',0)} endpoints**  ·  by method: {routes.get("by_method", {})}
{("> " + routes["note"]) if routes.get("note") else ""}
{("> " + routes["coverage_warning"]) if routes.get("coverage_warning") else ""}

## 2. ★ Tenant boundary (confirm first — highest value, easiest to get wrong)

{_bullets([f"`{t['key']}` — {t['occurrences']}×" for t in tenant.get("candidates", [])],
          "_no common tenant key found — confirm whether this app is multi-tenant; if not, skip cross-tenant probes_")}

{tenant.get("note","")}

## 3. ★ Attack surface & targeting (point the probes HERE)

{"_⚠ route discovery may be INCOMPLETE (see §1) — treat empty lists below as 'couldn't map', not 'nothing there'._" if routes.get("coverage_warning") else ""}
{_section("IDOR / BOLA candidates — endpoints with a path/object id", tgt.get("idor_candidates"))}
{_section("SSRF candidates — endpoints taking a url/domain-ish param", tgt.get("ssrf_candidates"))}
{_section("Open-redirect candidates", tgt.get("open_redirect_candidates"))}
{_section("File-upload candidates — path-traversal / content-type", tgt.get("upload_candidates"))}
{_section("Write endpoints — mass-assignment / BOLA-write", tgt.get("write_endpoints"))}
{_section("Auth endpoints", tgt.get("auth_endpoints"))}
**Code-level sinks** (cross-reference with the above): {sink_summary}

**Mass-assignment targets** — this app's privileged model fields (try injecting these into create/update payloads): {", ".join(facts.get("schemas", {}).get("sensitive_fields", [])) or "_none detected_"}  ·  ORMs: {", ".join(facts.get("schemas", {}).get("orms", [])) or "?"}

## 3a. ★★ Attack-surface inventory — TEST IN THIS ORDER

{inventory_md}

## 3b. ★ Access control (who can reach what — your #1 test)

Guard coverage (file-level heuristic): {gs.get("with_visible_guard",0)} with visible guard · {gs.get("no_visible_guard",0)} none visible · {gs.get("unknown",0)} unknown.  Global auth middleware: **{global_auth}**.  Roles in code: {roles_str}

{authz.get("note","")}

{unprot_section}
{mw_line}

## 3c. Config, CI/CD & client-side risks

**Pipeline / IaC** ({len(iac_findings)} finding(s)):
{iac_lines}

**Client-side secret exposure** (ships to the browser if real): {client_section}
Production source maps exposed: {client.get("production_source_maps", False)}

**GraphQL surface:** {gql_line}

**Password policy (cross-route consistency):** {pp_line}

**Client integrity — man-in-the-browser / tamperable display:**
{ci_section}

**WebSocket auth model (CSWSH determinant — is it an ambient cookie?):** {ws_line}

**Cookie hardening (report-the-pass / gap):** {cookie_line}

**File-upload security (#2b — sniff bytes, derive stored name, nosniff on serve):**
{up_section}

**PII output boundary (#8 — verify by VALUE SHAPE, not field name):**
{pii_section}

**Third-party integrations:** {integ_line}
{wh_line}

**License / entitlement verification (revocation + seat-cap trust):** {ent_line}

**Browser-extension client-trust (chrome.storage entitlement gate / host perms / world:MAIN):**
{webext_line}

**LLM / AI-agent surface (OWASP LLM Top 10 — prompt injection, insecure output, excessive agency, unbounded):**
{llm_section}

{blast_section}
## 4. Static findings (no running app needed)

Scanners available: {avail}

> ⚠️ The count below is **raw scanner output (pre-triage)** — expect mostly noise (vulnerable-looking
> patterns that are guarded, intended-public, or not exploitable). The **triaged, calibrated view** is the
> findings ledger in `REPORT.md` / `findings-ledger.json` — each finding there carries a `P(real)`. Start
> from the ledger and debate-verify; don't report these raw counts as vulnerabilities.

{findings_block}

Install for fuller coverage:
{missing}

## 4b. ★★ What a DAST / pentest will report — predicted before you run one

{dast_md}

## 4c. Pre-triage — what a reviewer would filter (tagged, NOT dropped)

{fpfilter_md}

## 5. Tailored probes (staged — drafts you finalize against §2–§3)

{probe_lines}

Keep these in the repo after you run them — re-running after a fix proves "still blocked, now safer."

## 5b. ★★ Pentest runbook — phased & pre-aimed (opt-in, against an instance you own)

{testplan_md}

## 5c. ★ Fix prompts — paste one straight into your agent

{fixprompts_md}

## 6. How to work this — verify with a debate, then fix

The findings ledger (`findings-ledger.json` / REPORT.md) comes pre-ranked with a **confidence**
(HIGH = dynamically confirmed; MEDIUM/LOW = hypothesis). Each finding also carries a **calibrated**
estimate — `calibrated.p` (measured real-vuln rate for that attack-class/confidence bucket on a
labeled vuln corpus), `calibrated.ci` (95% interval), `calibrated.n` (sample size), `calibrated.basis`.
**A wide CI or `basis: prior (uncalibrated)` means thin data — lean on the debate, not the number.**
The rates skew optimistic (the corpus is deliberately vulnerable); to be conservative, threshold on the
CI lower bound. **The calibration self-improves:** every `websec dynamic` run folds its *confirmed*
results (a write that executed unauthenticated = real; one that's auth-enforced = a recon false positive)
into a local overlay, so these numbers personalize to your apps the more you run it. **Verify before you
report** — especially MEDIUM/LOW — by running a 4-role debate per finding (this is the FP killer):

- **Advocate** — argue it's real; cite the evidence chain + the CWE / OWASP-API.
- **Challenger** — try hard to *refute* it: false positive? intended-public? unreachable? guarded by a
  pattern the static scan missed? (default to skepticism)
- **Mediator** — decide: confirmed / false-positive / needs-data. You may override the tool.
- **Explainer** — write the survivor up: exact `curl` repro, real impact, and the fix.

**Generate probes the same way** — a Positive perspective (intended behavior holds) + Negative
(bypass / injection / error) + Edge (boundary / concurrency / unusual input), then a Critic dedupes
them into one runnable suite. More perspectives = broader coverage.

**Verify the constitution** (`CONSTITUTION.md`): every ⬜ line is a Given/When/Then to confirm with a
probe — flip it to ✅ holds or 🔴 VIOLATED.

Order: static triage (on a {surface.get("datastore_class","?")} datastore, injection alerts are usually FPs) →
confirm the auth/tenant model → run §3-targeted probes (low-priv, then cross-tenant; record PASS counts
like "14/14 blocked") → fix what fails → re-run to confirm. **Human reviews every diff; never run
destructive or production probes without explicit authorization.**

## 7. Hand back

What was tested, what held (PASS counts), what's open (repro + fix), which probes are now regression tests. Cite `FACTS.json` + `scanners/`.

---

## Appendix A — full endpoint inventory

{inventory}
"""

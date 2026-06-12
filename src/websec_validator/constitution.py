"""Security constitution — the app's invariants as checkable Given/When/Then.

Spec-kit's `constitution` idea applied to security: instead of (only) a list of
findings, emit the rules the app MUST uphold, derived deterministically from the
recon, each phrased as a verifiable acceptance scenario. The dynamic probes verify
them; a matching dynamically-confirmed ledger finding flips an invariant to VIOLATED.
This makes the output a *checkable spec*, not just prose.
"""

from __future__ import annotations


def build(facts: dict, ledger: dict | None = None) -> list:
    routes = facts.get("routes", {})
    tgt = routes.get("targeting", {})
    authz = facts.get("authz", {})
    integ = facts.get("integrations", {})
    tenant = facts.get("tenant", {})

    # endpoints with a dynamically-confirmed access-control finding → VIOLATED
    violated = {f["location"] for f in (ledger or {}).get("findings", [])
                if f.get("category") == "access-control"
                and any(e.get("layer") == "dynamic" for e in f.get("evidence", []))}

    inv = []

    def add(principle, statement, source, status="VERIFY"):
        inv.append({"principle": principle, "statement": statement, "source": source, "status": status})

    # P1 — Authentication: every non-public endpoint must reject unauthenticated access
    n = 0
    for eg in authz.get("endpoint_guards", []):
        if eg.get("public_hint") or eg.get("guarded") or not eg.get("analyzed"):
            continue
        n += 1
        if n > 40:
            continue
        status = "VIOLATED" if eg.get("path") in violated else "VERIFY"
        add("Authentication", f"Given no auth token, When `{eg['method']} {eg['path']}`, Then 401/403 "
            f"(no body, no mutation)", eg.get("code_path", "recon"), status)
    if n > 40:
        add("Authentication", f"_…and {n - 40} more endpoints with no visible guard — see findings-ledger.json_", "recon")

    # P2 — Tenant isolation
    for t in tenant.get("candidates", [])[:1]:
        add("Tenant isolation", f"Given role A's token, When reading another tenant's resource via "
            f"`{{{t['key']}}}`, Then 403/404 (no cross-tenant data)", "recon")

    # P3 — SSRF defense
    for s in tgt.get("ssrf_candidates", [])[:8]:
        add("SSRF defense", f"Given a url/host param = 169.254.169.254 / RFC1918 / file://, "
            f"When `{s}`, Then the fetch is blocked", "recon")

    # P4 — Webhook integrity
    for w in integ.get("webhook_endpoints", [])[:8]:
        add("Webhook integrity", f"Given a forged or missing signature, When `{w}`, Then 401 "
            f"(and replays inside the window are rejected)", "recon")

    # P5 — Secret hygiene (always)
    add("Secret hygiene", "Given the repo + git history, Then no live credential is present and no secret "
        "reaches the client bundle", "recon")

    # P6 — Signing-secret integrity (forgeable JWT, REF-PENTEST #8)
    for sd in ((facts.get("auth", {}) or {}).get("insecure_secret_defaults", []) or [])[:5]:
        add("Signing-secret integrity", f"Given the signing-secret env var is unset, When the app boots, Then it "
            f"FAILS CLOSED — no hard-coded fallback ({sd.get('literal')!r} in {sd.get('file')})",
            sd.get("file", "recon"))

    # P7 — Subscription authorization (cross-group BOLA, #5)
    for s in ((facts.get("graphql", {}) or {}).get("subscription_authz", []) or [])[:6]:
        add("Subscription authorization", f"Given a tenant id you do NOT own, When subscribing to `{s.get('field')}`, "
            f"Then the server rejects it (binds the tenant arg to your identity)", "recon")

    # P8 — Display integrity (man-in-the-browser, the agent-wallet class)
    if (facts.get("client_integrity", {}) or {}).get("sensitive_display"):
        add("Display integrity", "Given a fund-redirecting value is displayed, Then a strict CSP kills the scalable "
            "tamper vector AND an out-of-band anchor makes single-surface tampering user-detectable", "recon")

    return inv


def render(inv: list) -> str:
    by_principle: dict = {}
    for i in inv:
        by_principle.setdefault(i["principle"], []).append(i)
    mark = {"VIOLATED": "🔴 VIOLATED", "VERIFY": "⬜ verify", "HOLDS": "✅ holds"}
    out = ["# Security constitution\n",
           "> Invariants this app must uphold, derived from recon. The dynamic probes verify them; "
           "a dynamically-confirmed finding flips one to 🔴 VIOLATED. Treat ⬜ as a hypothesis to confirm.\n"]
    viol = sum(1 for i in inv if i["status"] == "VIOLATED")
    out.append(f"**{len(inv)} invariants · {viol} VIOLATED · {sum(1 for i in inv if i['status']=='VERIFY')} to verify**\n")
    for p, items in by_principle.items():
        out.append(f"## {p}")
        for i in items:
            out.append(f"- {mark.get(i['status'], i['status'])} — {i['statement']}  ·  _{i['source']}_")
        out.append("")
    return "\n".join(out)

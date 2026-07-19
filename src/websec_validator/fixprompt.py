"""Per-finding fix prompts — the paste-ready instruction that turns a finding into a fixed bug.

websec's whole thesis is "brief the agent". A finding tells you something is wrong; a *fix prompt* tells
the agent exactly what to change, with the evidence, the standard, the calibrated confidence, and — the
part that matters most — how to VERIFY the fix rather than trust it.

Deterministic templating over the ledger websec already produces. No LLM: websec writes the instruction,
the agent writes the patch, the human reviews it. That division of labour is the product.

Each prompt is self-contained (an agent in a fresh session can act on it) and ends with a verification
step, so "fixed" means demonstrated, not asserted.
"""

from __future__ import annotations

# How to prove a fix actually holds, per attack class. Generic fallback for anything unlisted.
_VERIFY: dict = {
    "bola": "re-run the staged BOLA probe with two identities — user B must get 403/404 for user A's id.",
    "missing-auth": "call the endpoint with no token and with a low-privilege token — both must be rejected.",
    "mass-assignment": "POST the privileged field again — it must be ignored/rejected, not persisted.",
    "sqli": "re-run sqlmap against that param — it must report 'not injectable'.",
    "nosql-injection": "replay the operator-injection payload — it must not alter the query shape.",
    "xss": "re-request with the payload — the response must escape it (no executable markup).",
    "command-injection": "replay with an OAST payload — no callback, no delay.",
    "path-traversal": "request `../` sequences — must resolve inside the intended dir or 400.",
    "ssrf": "point the param at your OAST domain — no inbound hit.",
    "open-redirect": "pass an external URL — must not 30x off-origin.",
    "secret": "confirm the credential is ROTATED at the provider, not just removed from the file "
              "(git history still holds it).",
    "cve": "re-run `websec run . --scan` — the CVE must be gone from the ledger.",
    "missing-csp": "curl -I the deployed route — the header must be present and without unsafe-inline.",
    "clickjacking": "curl -I — X-Frame-Options/frame-ancestors must be set.",
    "cors-misconfig": "send an Origin header from a foreign origin — must not be reflected with credentials.",
    "insecure-cookie": "inspect Set-Cookie — Secure, HttpOnly and SameSite must all be present.",
    "jwt-verify-options": "present a token signed with `none`/HS256-vs-RS256 confusion — must be rejected.",
    "webhook-forgery": "POST an unsigned payload — must be rejected with 401.",
}
_GENERIC_VERIFY = ("re-run `websec run . --scan` and confirm the finding is gone, then add a regression "
                   "test that fails without the fix.")


def _verify_for(attack_class: str) -> str:
    return _VERIFY.get((attack_class or "").lower(), _GENERIC_VERIFY)


def build(ledger: dict, limit: int = 12) -> list:
    """→ [{fingerprint, severity, attack_class, location, prompt}] for the top-ranked findings."""
    out = []
    for f in (ledger or {}).get("findings", [])[:limit]:
        ac = f.get("attack_class", "finding")
        loc = f.get("location", "(unknown location)")
        std = f.get("standards", {}) or {}
        cwe = (std.get("cwe") or [""])[0]
        evidence = ""
        for ev in f.get("evidence", []) or []:
            if ev.get("detail"):
                evidence = ev["detail"]
                break
        cal = f.get("calibrated") or {}
        pline = ""
        if cal.get("p") is not None and cal.get("n"):
            pline = (f"\nCalibrated prior: P(real)≈{cal.get('p')} (n={cal.get('n')}, "
                     f"{cal.get('basis')}) — treat as a lead to verify, not a fact.")
        prompt = (
            f"Fix a `{ac}` issue in `{loc}`.\n\n"
            f"What websec found: {f.get('title', ac)}\n"
            + (f"Evidence: {evidence}\n" if evidence else "")
            + (f"Standard: {cwe}\n" if cwe else "")
            + f"Recommended remediation: {f.get('remediation', '(see the standard above)')}\n"
            + pline
            + "\n\nBefore changing anything: read the surrounding code and confirm this is genuinely "
              "exploitable in THIS codebase — websec reports leads, and a guarded or unreachable path "
              "is a false positive worth saying so about rather than 'fixing'.\n"
            f"After fixing, VERIFY: {_verify_for(ac)}"
        )
        out.append({"fingerprint": f.get("fingerprint", ""), "severity": f.get("severity", ""),
                    "attack_class": ac, "location": loc, "prompt": prompt})
    return out


def render_md(prompts: list) -> str:
    if not prompts:
        return "_No findings to generate fix prompts for._"
    parts = ["_One self-contained instruction per finding — paste a block straight into your coding "
             "agent. Each ends with a VERIFY step, so \"fixed\" means demonstrated, not asserted._\n"]
    for i, p in enumerate(prompts, 1):
        parts.append(f"<details>\n<summary><b>{i}. [{p['severity']}] {p['attack_class']}</b> — "
                     f"<code>{p['location']}</code></summary>\n\n```text\n{p['prompt']}\n```\n</details>\n")
    return "\n".join(parts)

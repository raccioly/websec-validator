"""DAST prediction — what a dynamic scanner WILL report, computed before you run one.

The strategic idea: a ZAP/Nuclei/Burp run mostly re-discovers, at runtime and at great expense, things
that were already visible in the source. websec knows those statically — so it can tell you, *ahead of
time*, which alerts a scan is going to raise and where each one comes from in your code. Fix them and
the scan comes back clean on those classes; the dynamic run becomes CONFIRMATION rather than discovery.

Two lists, and the second is the honest half:

  1. **Predicted alerts** — a static finding with a known dynamic signature (missing CSP → ZAP 10038,
     SQLi sink → ZAP 40018 / sqlmap, …). These are the ones you can pre-empt.
  2. **Blind spots** — classes a scanner will NOT auto-find (BOLA/BFLA, tenant isolation, business
     logic, mass-assignment). No amount of static work makes a scanner find these; they need targeted,
     authenticated probes. Saying so is the point — it stops "the scan was clean" from meaning "we're
     safe", which is the single most dangerous false comfort in appsec.

Deterministic table lookup over the ledger's attack_class. No LLM, no network, no target.
"""

from __future__ import annotations

# attack_class → (scanner, alert name, alert id/template, one-line "why it fires").
# ZAP ids are the real pscan/ascan plugin ids so the mapping is checkable against a report.
_DAST_MAP: dict = {
    # --- passive header / config alerts: a scanner finds these on ANY page, instantly ---
    # covers both "no CSP at all" (10038) and "CSP present but allows unsafe-inline/eval" (10055) —
    # websec models both under the single `missing-csp` class.
    "missing-csp": ("ZAP (passive)", "CSP Header Not Set / CSP: unsafe-inline", "10038 / 10055",
                    "no CSP, or a CSP allowing unsafe-inline → flagged on every page"),
    "clickjacking": ("ZAP (passive)", "Missing Anti-clickjacking Header", "10020",
                     "no X-Frame-Options / frame-ancestors"),
    "content-sniffing": ("ZAP (passive)", "X-Content-Type-Options Header Missing", "10021",
                         "responses served without nosniff"),
    "incomplete-hsts": ("ZAP (passive)", "Strict-Transport-Security Header Not Set", "10035",
                        "HTTPS responses without (complete) HSTS"),
    "cors-misconfig": ("ZAP (passive)", "Cross-Domain Misconfiguration", "10098",
                       "Access-Control-Allow-Origin reflects/wildcards with credentials"),
    "subresource-integrity": ("ZAP (passive)", "Sub Resource Integrity Attribute Missing", "90003",
                              "external <script src> without an integrity hash"),
    "error-disclosure": ("ZAP (passive)", "Application Error Disclosure", "90022",
                         "stack traces / framework errors in responses"),
    "insecure-cookie": ("ZAP (passive)", "Cookie Without Secure Flag / No HttpOnly / no SameSite",
                        "10011 / 10010 / 10054", "session cookie attributes missing"),
    "graphql": ("Nuclei", "graphql-introspection (+ ZAP GraphQL add-on)", "graphql-detect",
                "introspection / playground reachable in the deployed env"),
    "csrf": ("ZAP (passive+active)", "Absence of Anti-CSRF Tokens", "10202 / 20012",
             "state-changing form/endpoint with no CSRF token and cookie auth"),
    # --- active injection alerts: the scanner fuzzes params it discovers ---
    "sqli": ("ZAP (active) / sqlmap", "SQL Injection", "40018",
             "a user-input-gated SQL sink is reachable from a request param"),
    "nosql-injection": ("ZAP (active)", "NoSQL Injection", "40033",
                        "user input flows into a NoSQL query document"),
    "xss": ("ZAP (active)", "Cross Site Scripting (Reflected / DOM)", "40012 / 40026",
            "user input reaches an HTML sink unescaped (server-reflected or a DOM sink)"),
    "ssti": ("ZAP (active)", "Server Side Template Injection", "90036",
             "user input is interpolated into a template that is then rendered"),
    "eval-injection": ("ZAP (active)", "Remote Code Execution / eval", "90020",
                       "user input reaches eval/exec"),
    "unrestricted-upload": ("ZAP (active) / manual", "Unrestricted File Upload", "110009",
                            "an upload endpoint accepts attacker-chosen type/name"),
    "command-injection": ("ZAP (active)", "Remote OS Command Injection", "90020",
                          "user input reaches a shell/exec sink"),
    "path-traversal": ("ZAP (active)", "Path Traversal", "6",
                       "user-controlled path segment reaches a filesystem read/serve"),
    "ssrf": ("Nuclei / ZAP OAST", "Server Side Request Forgery (out-of-band)", "40046",
             "a url-ish param drives an outbound fetch"),
    "open-redirect": ("ZAP (active)", "External Redirect", "20019",
                      "a redirect target is user-controlled"),
    "xxe": ("ZAP (active)", "XML External Entity Attack", "90023",
            "XML parsed with external entities enabled"),
    "insecure-deserialization": ("ZAP (active) / manual", "Insecure Deserialization", "90035",
                                 "untrusted data reaches a deserializer"),
    "proxy-escape": ("Nuclei / ZAP", "path-normalization / reverse-proxy bypass", "path-traversal-*",
                     "a proxy prefix rule can be escaped to reach an internal route"),
}

# Classes a dynamic scanner will NOT auto-discover — the honest half. Each names WHY, so "the scan was
# clean" can never be mistaken for "we're safe".
_BLIND_SPOTS: dict = {
    "bola": "object-level authz — a scanner has no notion of 'this record belongs to another tenant'. "
            "Needs two identities + an id swap (websec stages exactly this probe).",
    "missing-auth": "a crawler sees a 200; it cannot know the route was SUPPOSED to require auth.",
    "mass-assignment": "requires knowing which model fields are privileged (websec extracts them) and "
                       "injecting them into an otherwise-valid payload.",
    "claim-authz": "authz keyed on a user-influenceable token claim — needs a re-signed token.",
    "cookie-authz": "authz trusting an unsigned cookie — needs a tampered cookie, not a crawl.",
    "fail-open-auth": "the bypass only appears when the auth dependency errors/times out.",
    "missing-rls": "row-level-security gaps are data-shaped; invisible from the HTTP surface.",
    "rls-context": "the tenant context resets inside the transaction — a runtime data condition.",
    "jwt-verify-options": "algorithm-confusion needs a forged token, not a crawl.",
    "auth-backdoor": "a `dev-` token / accept-any-password path is only reachable if you know to try it.",
    "insecure-secret-default": "a fallback signing secret is only exploitable once you know its value.",
    "webhook-forgery": "needs a crafted unsigned callback delivered to your endpoint.",
    "secret": "committed credentials live in the repo/git history — a black-box scan cannot see them.",
    "cve": "dependency CVEs are inventory-derived; a scanner only sees them if a version banner leaks.",
    "malicious-install-script": "build/install-time RCE never appears in a request.",
    "lockfile-drift": "supply-chain drift is a build artifact, not a runtime response.",
    "excessive-agency": "AI-agent tool permissions are config, not an HTTP surface.",
    "llm-prompt-injection": "needs adversarial content routed through the model's context.",
    "llm-insecure-output": "requires observing model output reaching an executable sink.",
    "pii-exposure": "a scanner may see the field but cannot know it's regulated personal data.",
    "entitlement-revocation-bypass": "licence/seat logic is stateful business logic.",
    "timing-unsafe-compare": "a timing side-channel needs statistical measurement, not a crawl.",
    "weak-password-hash": "the hash algorithm is invisible from outside.",
}


def predict(facts: dict, ledger: dict | None) -> dict:
    """→ {predicted:[…], blind_spots:[…], summary:{…}} from the ledger's attack classes."""
    findings = (ledger or {}).get("findings", []) or []
    predicted: dict = {}
    blind: dict = {}
    for f in findings:
        ac = str(f.get("attack_class", "")).lower()
        loc = f.get("location", "")
        if ac in _DAST_MAP:
            scanner, alert, aid, why = _DAST_MAP[ac]
            key = (scanner, alert, aid)
            row = predicted.setdefault(key, {"scanner": scanner, "alert": alert, "alert_id": aid,
                                             "why": why, "attack_class": ac, "sources": [],
                                             "severity": f.get("severity", "MEDIUM")})
            if loc and loc not in row["sources"]:
                row["sources"].append(loc)
        elif ac in _BLIND_SPOTS:
            b = blind.setdefault(ac, {"attack_class": ac, "reason": _BLIND_SPOTS[ac], "sources": []})
            if loc and loc not in b["sources"]:
                b["sources"].append(loc)

    # a GraphQL surface with introspection on is predictable straight from facts, even with no finding
    gq = facts.get("graphql", {}) or {}
    if gq.get("present") and gq.get("introspection_enabled") and \
            not any(r["attack_class"] == "graphql" for r in predicted.values()):
        s, a, i, w = _DAST_MAP["graphql"]
        predicted[(s, a, i)] = {"scanner": s, "alert": a, "alert_id": i, "why": w,
                                "attack_class": "graphql",
                                "sources": [gq.get("endpoint", "(graphql endpoint)")],
                                "severity": "MEDIUM"}

    pred = sorted(predicted.values(), key=lambda r: (r["scanner"], r["alert"]))
    blinds = sorted(blind.values(), key=lambda r: r["attack_class"])
    return {"predicted": pred, "blind_spots": blinds,
            "summary": {"predicted_alerts": len(pred),
                        "blind_spot_classes": len(blinds),
                        "sources": sum(len(r["sources"]) for r in pred)}}


def render_md(pred: dict) -> str:
    p, b = pred.get("predicted", []), pred.get("blind_spots", [])
    if not p and not b:
        return ("_Nothing predicted — either no findings map to a known dynamic signature, or the "
                "ledger is empty._")
    out = []
    if p:
        out.append(f"**A scan of the deployed app should raise ~{len(p)} alert class(es) that are already "
                   "visible in your source. Fix these and that scan comes back clean on them:**\n")
        out.append("| Scanner | Alert (id) | Comes from | Why it will fire |")
        out.append("|---|---|---|---|")
        for r in p:
            src = ", ".join(f"`{s}`" for s in r["sources"][:3]) or "—"
            more = f" +{len(r['sources']) - 3}" if len(r["sources"]) > 3 else ""
            out.append(f"| {r['scanner']} | {r['alert']} ({r['alert_id']}) | {src}{more} | {r['why']} |")
    if b:
        out.append("\n**⚠ A scanner will NOT find these — do not read a clean scan as \"safe\":**\n")
        for r in b:
            src = ", ".join(f"`{s}`" for s in r["sources"][:2]) or "—"
            out.append(f"- **{r['attack_class']}** — {r['reason']}  \n  _seen at:_ {src}")
        out.append("\n_These are what the staged probes in §5 are for: they need identities, state, and "
                   "intent that no crawler has._")
    return "\n".join(out)

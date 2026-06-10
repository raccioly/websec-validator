"""Stage the probe library, tailored to the extracted attack surface.

Probe selection is driven by the real recon facts. Staging now also writes a
`probe-context.json` (the target's REAL routes/auth/sensitive-fields/tenant key,
from FACTS) next to the probes, prepends a "this is a draft — your surface is in
probe-context.json" banner to each, and records the real per-probe target endpoints
in the manifest — so the staged probes describe *this* app, not the reference app
the templates were authored against.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

WRITE_VERBS = ("POST", "PUT", "PATCH", "DELETE")

# label -> (filename, attack class, what the agent must supply)
PROBES = {
    "unauth-baseline": ("unauth-baseline.sh", "Missing authentication (no-creds baseline)",
                        "just the target base URL — it reads the routes from probe-context.json"),
    "bola-cross-tenant": ("bola-cross-tenant.sh", "BOLA / cross-tenant read (OWASP API #1)",
                          "two role tokens in different tenants + the IDOR-candidate routes"),
    "bola-write-verbs": ("bola-write-verbs.py", "BOLA on PATCH/PUT/POST/DELETE",
                         "two role tokens + the write endpoints + a sample object id per tenant"),
    "mass-assignment": ("mass-assignment.py", "BOPLA / mass assignment (OWASP API #3)",
                        "a low-priv token + a write endpoint that updates a record"),
    "jwt-attacks": ("jwt-attacks.sh", "JWT: alg:none, tamper, expiry, replay",
                   "a valid token + the login + a protected endpoint"),
    "forged-token": ("forged-token.sh", "Forged/unsigned-JWT acceptance (CWE-347 broken auth)",
                     "just the target base URL — it forges its own token + reads routes from probe-context.json"),
    "hs256-brute-force": ("hs256-brute-force.py", "Offline HS256 weak-secret brute",
                         "one HS256 JWT (offline — no live app needed)"),
    "ssrf-probes": ("ssrf-probes.sh", "SSRF: IMDS / RFC1918 / file://",
                   "an authorized token + the SSRF-candidate endpoints/params"),
    "race-conditions": ("race-conditions.py", "Race / claim-collision invariants",
                       "a token + an endpoint with a single-winner invariant + an idempotency key"),
    "webhook-forgery": ("webhook-forgery.py", "Inbound webhook signature/replay",
                       "the webhook path + signature header name + scheme"),
    "rate-limit-burst": ("rate-limit-burst.sh", "Rate-limit + X-Forwarded-For bypass",
                        "the login + a rate-limited endpoint"),
    "compare-roles": ("compare-roles.sh", "Two-role DAST surface diff",
                     "two SARIF reports from a role-A and role-B scan (dynamic phase)"),
    "dlp-bypass-offline": ("dlp-bypass-offline.py", "DLP/detection regex encoding bypass",
                          "your DLP/redaction regexes (offline)"),
    "s3-assess": ("s3-assess.sh", "S3 bucket posture", "a bucket name + AWS creds"),
    # --- PTREQ0013000 probes ---
    "error-disclosure-probe": ("error-disclosure-probe.sh", "Error/stack-trace disclosure in 500s (CWE-209)",
                               "a running TEST instance (+ usually a token) — reads routes from probe-context.json"),
    "appsync-introspection": ("appsync-introspection.sh", "AppSync introspection + WAF Unicode/junk bypass (#2)",
                              "APPSYNC_URL + APPSYNC_API_KEY (or a session header) for a TEST AppSync API"),
    "appsync-cswsh": ("appsync-cswsh.sh", "Cross-Site WebSocket Hijacking on AppSync realtime (#4)",
                      "APPSYNC_URL + APPSYNC_API_KEY (TEST); pip install websocket-client for the live attempt"),
    "appsync-subscription-bola": ("appsync-subscription-bola.sh", "Cross-group subscription BOLA (#5)",
                                  "APPSYNC_URL + a low-priv session + VICTIM_GROUP_ID you do NOT own + SUB_FIELD"),
    "client-integrity-checklist": ("client-integrity-checklist.sh", "Man-in-the-browser / tamperable-display posture",
                                   "a running TEST instance + the page that shows the address (PAGE=/receive)"),
    # --- PTREQ0013000 retest probes ---
    "upload-matrix": ("upload-matrix.sh", "Unrestricted upload + serve-side stored XSS (#2b)",
                      "a TEST instance + an upload token + the upload path (UPLOAD_PATH / UPLOAD_FIELD)"),
    "pii-output-diff": ("pii-output-diff.sh", "Unmasked PII by value-shape, per-role (#8)",
                        "a TEST instance + a LOW-priv token (TOKEN_A); optional priv TOKEN_B to diff"),
    "password-reuse": ("password-reuse.sh", "Password reuse / history on every set-password path (#6)",
                       "a TEST account token + CURRENT_PW + the set-password path(s)"),
}

# unauth-baseline is ALWAYS staged: it's the cheapest probe and directly exercises the
# #1 lead class (missing authentication) — the one a no-creds run can confirm immediately.
ALWAYS = ["unauth-baseline", "forged-token", "jwt-attacks", "hs256-brute-force", "rate-limit-burst"]

# which targeting bucket each probe should be pointed at (for the manifest's real targets)
_TARGET_KEYS = {
    "unauth-baseline": "write_endpoints",
    "bola-write-verbs": "write_endpoints",
    "mass-assignment": "write_endpoints",
    "bola-cross-tenant": "idor_candidates",
    "ssrf-probes": "ssrf_candidates",
    "webhook-forgery": "write_endpoints",
    "error-disclosure-probe": "write_endpoints",
    "upload-matrix": "upload_candidates",
}

_BANNER = (
    "# ─────────────────────────────────────────────────────────────────────────────\n"
    "# websec-validator — DRAFT probe. Any example endpoints / auth / login below are\n"
    "# PLACEHOLDERS from the template. THIS target's real surface — routes, auth scheme\n"
    "# + token location, sensitive fields, tenant key — is in  ./probe-context.json\n"
    "# (generated from FACTS.json for this app). Use those values before running; the\n"
    "# agent should finalize this draft against probe-context.json, then fill secrets.\n"
    "# ─────────────────────────────────────────────────────────────────────────────\n"
)


def _seed_hs256(text: str, facts: dict) -> str:
    """Inject this repo's harvested fallback signing-secret literals (auth.insecure_secret_defaults,
    #8) into the hs256 probe's PROJECT-SPECIFIC block, so a captured token confirms directly against
    the app's OWN default secret — the fastest path from 'flagged' to 'proven forgeable'."""
    import re as _re
    lits = [sd.get("literal") for sd in ((facts.get("auth") or {}).get("insecure_secret_defaults") or [])
            if sd.get("literal")]
    if not lits:
        return text
    seeded = "\n".join(f"    {json.dumps(lit)}," for lit in dict.fromkeys(lits))
    block = ("    # PROJECT-SPECIFIC START — seeded from this repo's insecure_secret_defaults (#8)\n"
             + seeded + "\n    # PROJECT-SPECIFIC END")
    new, n = _re.subn(r"    # PROJECT-SPECIFIC START.*?# PROJECT-SPECIFIC END", block, text, flags=_re.S)
    return new if n else text


def applicable(facts: dict) -> list:
    """Pick probes the extracted surface actually justifies."""
    chosen = list(ALWAYS)
    targeting = (facts.get("routes") or {}).get("targeting", {})
    tenant = (facts.get("tenant") or {}).get("candidates")

    if targeting.get("write_endpoints"):
        chosen += ["mass-assignment"]
    if tenant:
        chosen += ["bola-cross-tenant", "bola-write-verbs", "compare-roles"]
    if targeting.get("ssrf_candidates") or (facts.get("surface") or {}).get("sinks", {}).get("ssrf-outbound-http"):
        chosen += ["ssrf-probes"]
    if targeting.get("write_endpoints"):
        chosen += ["webhook-forgery", "race-conditions"]

    # PTREQ0013000 — stage probes for the surfaces the new extractors found
    surface_sinks = (facts.get("surface") or {}).get("sinks", {})
    if surface_sinks.get("error-disclosure"):
        chosen += ["error-disclosure-probe"]
    appsync = bool((facts.get("graphql") or {}).get("appsync")) or any(
        f.get("kind", "").startswith("appsync") for f in (facts.get("iac_ci") or {}).get("findings", []))
    if appsync:
        chosen += ["appsync-introspection", "appsync-cswsh", "appsync-subscription-bola"]
    if (facts.get("client_integrity") or {}).get("findings"):
        chosen += ["client-integrity-checklist"]
    if (facts.get("upload_security") or {}).get("findings") or targeting.get("upload_candidates"):
        chosen += ["upload-matrix"]
    if (facts.get("pii_exposure") or {}).get("findings"):
        chosen += ["pii-output-diff"]
    if ((facts.get("password_policy") or {}).get("password_reuse") or {}).get("gap"):
        chosen += ["password-reuse"]

    seen, ordered = set(), []
    for k in chosen:
        if k in PROBES and k not in seen:
            seen.add(k)
            ordered.append(k)
    return ordered


def build_context(facts: dict) -> dict:
    """The target's real, probe-ready surface — written to probe-context.json."""
    routes = facts.get("routes") or {}
    tgt = routes.get("targeting", {})
    auth = facts.get("auth") or {}
    writes = [f"{e.get('method')} {e.get('path')}" for e in routes.get("endpoints", [])
              if e.get("method") in WRITE_VERBS][:80]
    # GET/HEAD data-read routes — the read half of the protected surface (the forged-token probe
    # needs these; the bypass class hits reads like /api/wallets/lookup that are in no other bucket).
    reads = [f"{e.get('method')} {e.get('path')}" for e in routes.get("endpoints", [])
             if e.get("method") in ("GET", "HEAD")][:80]
    return {
        "target_base_url": "FILL_ME (e.g. http://localhost:3000)",
        "auth": {
            "scheme": auth.get("scheme"),
            "token_location": auth.get("token_location"),
            "cookie_names": auth.get("cookie_names", []),
            "login_endpoints": tgt.get("auth_endpoints", [])[:10],
            "how_to_authenticate": "cookie-session (e.g. NextAuth) → send the session cookie; "
                                   "bearer → Authorization: Bearer <jwt>; api-key → the documented key header",
        },
        "endpoints": {
            "writes": writes,
            "reads": reads,
            "idor_candidates": tgt.get("idor_candidates", [])[:60],
            "ssrf_candidates": tgt.get("ssrf_candidates", [])[:40],
            "upload_candidates": tgt.get("upload_candidates", [])[:40],
            "auth_endpoints": tgt.get("auth_endpoints", [])[:20],
        },
        "sensitive_fields": (facts.get("schemas") or {}).get("sensitive_fields", []),
        "tenant_keys": [c.get("key") for c in (facts.get("tenant") or {}).get("candidates", [])][:5],
        "datastore_class": (facts.get("surface") or {}).get("datastore_class"),
        "note": "These are THIS app's real routes/auth (from FACTS.json). Finalize each probe draft "
                "against this file, supply secrets/tokens, then run against a TEST instance only.",
    }


def stage(chosen: list, outdir: Path, facts: dict | None = None) -> list:
    dest = outdir / "probes"
    dest.mkdir(parents=True, exist_ok=True)
    facts = facts or {}

    ctx = build_context(facts)
    (dest / "probe-context.json").write_text(json.dumps(ctx, indent=2) + "\n")
    tgt = (facts.get("routes") or {}).get("targeting", {})

    manifest = [{"key": "_context", "file": "probes/probe-context.json",
                 "note": "the target's real routes/auth/fields — finalize the drafts against this"}]
    src_root = resources.files("websec_validator").joinpath("templates/probes")
    # always ship the shared helper the Python probes import (load context + env auth)
    try:
        (dest / "_lib.py").write_text(src_root.joinpath("_lib.py").read_text())
    except Exception:
        pass
    for key in chosen:
        fname, attack, needs = PROBES[key]
        targets = (tgt.get(_TARGET_KEYS[key], []) if key in _TARGET_KEYS else [])[:15]
        try:
            body = src_root.joinpath(fname).read_bytes()
            # prepend the draft banner after any shebang line
            text = body.decode("utf-8", "replace")
            if key == "hs256-brute-force":
                text = _seed_hs256(text, facts)
            if text.startswith("#!"):
                shebang, _, rest = text.partition("\n")
                text = f"{shebang}\n{_BANNER}{rest}"
            else:
                text = _BANNER + text
            (dest / fname).write_text(text)
            manifest.append({"key": key, "file": f"probes/{fname}", "attack_class": attack,
                             "agent_must_supply": needs, "targets": targets})
        except Exception as e:
            manifest.append({"key": key, "file": fname, "status": f"stage-error: {e}"})
    return manifest

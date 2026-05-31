"""Stage the probe library, tailored to the extracted attack surface.

Probe selection is now driven by the real recon facts — we only stage what the
surface justifies, and the briefing tells the agent exactly which endpoints to
point each probe at.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

# label -> (filename, attack class, what the agent must supply)
PROBES = {
    "bola-cross-tenant": ("bola-cross-tenant.sh", "BOLA / cross-tenant read (OWASP API #1)",
                          "two role tokens in different tenants + the IDOR-candidate routes"),
    "bola-write-verbs": ("bola-write-verbs.py", "BOLA on PATCH/PUT/POST/DELETE",
                         "two role tokens + the write endpoints + a sample object id per tenant"),
    "mass-assignment": ("mass-assignment.py", "BOPLA / mass assignment (OWASP API #3)",
                        "a low-priv token + a write endpoint that updates a record"),
    "jwt-attacks": ("jwt-attacks.sh", "JWT: alg:none, tamper, expiry, replay",
                   "a valid token + the login + a protected endpoint"),
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
}

ALWAYS = ["jwt-attacks", "hs256-brute-force", "rate-limit-burst"]


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

    seen, ordered = set(), []
    for k in chosen:
        if k in PROBES and k not in seen:
            seen.add(k)
            ordered.append(k)
    return ordered


def stage(chosen: list, outdir: Path) -> list:
    dest = outdir / "probes"
    dest.mkdir(parents=True, exist_ok=True)
    manifest = []
    src_root = resources.files("websec_validator").joinpath("templates/probes")
    for key in chosen:
        fname, attack, needs = PROBES[key]
        try:
            (dest / fname).write_bytes(src_root.joinpath(fname).read_bytes())
            manifest.append({"key": key, "file": f"probes/{fname}",
                             "attack_class": attack, "agent_must_supply": needs})
        except Exception as e:
            manifest.append({"key": key, "file": fname, "status": f"stage-error: {e}"})
    return manifest

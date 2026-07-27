#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# websec-validator — DRAFT probe. Any example endpoints / auth / login below are
# PLACEHOLDERS from the template. THIS target's real surface — routes, auth scheme
# + token location, sensitive fields, tenant key — is in  ./probe-context.json
# (generated from FACTS.json for this app). Use those values before running; the
# agent should finalize this draft against probe-context.json, then fill secrets.
# ─────────────────────────────────────────────────────────────────────────────
# ⚠ DEFENSIVE CHECK — run only against a system you own/operate, with consent. Not for production or third-party targets.
"""Mass assignment / BOPLA (OWASP API #3) — FACTS-driven.

Injects THIS app's privileged model fields (from probe-context.json → sensitive_fields,
i.e. the schema extractor's output: role/isAdmin/groupId/ownerId/…) into each write
endpoint and flags any request that's ACCEPTED (2xx). A correct server strips or rejects
server-controlled fields. Acceptance is a *lead*, not proof — re-fetch the object as the
agent to confirm the privileged field actually persisted/escalated before reporting.

Env (see _lib.py): TARGET, TOKEN_A|COOKIE_A|APIKEY, optional OBJ_A (your own object id for
self-edit paths; defaults to the literal 'me').
"""
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lib  # noqa: E402

BASE = _lib.base_url()
HDR = _lib.auth_headers("A")
if not HDR:
    sys.exit("Supply auth: TOKEN_A=<jwt> (or COOKIE_A / APIKEY). See _lib.py.")
OBJ_A = os.environ.get("OBJ_A", "me")
fields = _lib.context().get("sensitive_fields") or ["role", "isAdmin", "groupId", "ownerId", "permissions"]


def _val(f: str):
    fl = f.lower()
    if any(k in fl for k in ("isadmin", "admin", "verified", "enabled", "active")):
        return True
    if any(k in fl for k in ("permission", "scope", "group", "roles")):
        return ["*"]
    if any(k in fl for k in ("role", "status", "plan", "tier")):
        return "admin"
    return "websec-injected"


PAYLOAD = {f: _val(f) for f in fields}
eps = _lib.write_endpoints()
if not eps:
    sys.exit("No write endpoints in probe-context.json — nothing to probe.")

print(f"=== Mass-assignment probe vs {BASE}   injecting app fields: {list(PAYLOAD)} ===")
findings = []
for method, path in eps:
    url = BASE + re.sub(r"\{[^}]+\}", OBJ_A, path)
    code, body = _lib.curl(method, url, headers=HDR, body=dict(PAYLOAD))
    sev = "SUSPECT" if code in (200, 201, 204) else ("PASS" if code in (400, 403, 422) else "INVESTIGATE")
    mark = {"SUSPECT": "!!", "PASS": "ok", "INVESTIGATE": "??"}[sev]
    findings.append({"method": method, "path": path, "url": url, "status": code,
                     "severity": sev, "preview": body[:140]})
    print(f"  [{mark}] {sev:11} {method:6} {url}  -> {code}")

out = _lib.save("mass-assignment", findings)
sus = sum(1 for f in findings if f["severity"] == "SUSPECT")
print(f"\n  SUSPECT (privileged fields accepted — verify they stuck)={sus}  ·  saved {out.name}")
print("  Re-fetch the object as the agent to confirm the field persisted/escalated, then debate-verify.")
sys.exit(1 if sus else 0)

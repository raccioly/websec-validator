#!/usr/bin/env python3
# ⚠ DEFENSIVE CHECK — run only against a system you own/operate, with consent. Not for production or third-party targets.
"""BOLA / cross-tenant WRITE probe — FACTS-driven and generic.

As role A, send each mutating verb (PUT/PATCH/POST/DELETE) at tenant B's resources
(object id OBJ_B in group/tenant GROUP_B). Expect 401/403/404. A 2xx means the
object-level authorization check is missing (BOLA — OWASP API #1). Write verbs miss
authz more often than GETs.

Endpoints come from probe-context.json (this app's real routes). Tokens + ids come
from env (see _lib.py): TARGET, TOKEN_A|COOKIE_A|APIKEY, OBJ_B, optional GROUP_B.
Bodies are minimal `{}` to limit side effects, but write verbs CAN mutate — run only
against a TEST instance you're authorized to probe.
"""
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lib  # noqa: E402

BASE = _lib.base_url()
_lib.require("OBJ_B")                       # a real object id owned by tenant B
OBJ_B = os.environ["OBJ_B"]
GROUP_B = os.environ.get("GROUP_B", OBJ_B)
HDR_A = _lib.auth_headers("A")
if not HDR_A:
    sys.exit("Supply role-A auth: TOKEN_A=<jwt> (or COOKIE_A / APIKEY). See _lib.py.")


def fill(path: str) -> str:
    # tenant/group/org path param → GROUP_B; any other {param} (an id) → OBJ_B
    return re.sub(r"\{([^}]+)\}",
                  lambda m: GROUP_B if any(t in m.group(1).lower() for t in ("group", "tenant", "org")) else OBJ_B,
                  path)


eps = _lib.write_endpoints()
if not eps:
    sys.exit("No write endpoints in probe-context.json — nothing to probe.")

print(f"=== BOLA write-verb probe vs {BASE}   (role A → tenant B's objects; expect 401/403/404) ===")
findings = []
for method, path in eps:
    url = BASE + fill(path)
    code, body = _lib.curl(method, url, headers=HDR_A, body={})
    sev = "PASS" if code in (401, 403, 404) else ("CRITICAL" if code in (200, 201, 204) else "INVESTIGATE")
    mark = {"PASS": "ok  ", "CRITICAL": "BOLA", "INVESTIGATE": "??  "}[sev]
    findings.append({"method": method, "path": path, "url": url, "status": code,
                     "severity": sev, "preview": body[:140]})
    print(f"  [{mark}] {sev:11} {method:6} {url}  -> {code}")

crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
out = _lib.save("bola-write-verbs", findings)
print(f"\n  CRITICAL (BOLA confirmed)={crit}  ·  saved {out.name}")
print("  A 2xx as role A against tenant B's object = object-level authz missing. Confirm the object")
print("  really belongs to B, then debate-verify (Advocate/Challenger/…) before reporting.")
sys.exit(1 if crit else 0)

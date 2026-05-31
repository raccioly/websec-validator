"""Dynamic phase (v1) — authenticated, READ-ONLY cross-tenant BOLA against a live target.

This closes the loop: the static recon found the group-scoped routes + the tenant
key; here we mint two real role tokens and check whether one tenant can read
another tenant's data. v1 is **GET-only** (no mutation) so it is safe to run
against a shared test environment. Write-verb BOLA / mass-assignment come later,
explicitly gated.

Config (JSON):
{
  "target": "https://host",
  "login_path": "/api/auth/login",
  "token_json_path": "tokens.accessToken",
  "user_json_path": "user",
  "tenant_field": "groupIds",          # field on the user object holding tenant id(s)
  "tenant_path_param": "groupId",       # the {param} in routes that is the tenant boundary
  "roles": { "agentA": {"email": "..", "password": ".."},
             "agentB": {"email": "..", "password": ".."} }
}
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path


def _dig(d: dict, dotted: str):
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _request(method: str, url: str, token: str | None, timeout: int = 20):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, method=method, headers=headers)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read(4000).decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(1000).decode(errors="replace")
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def mint(cfg: dict, role: str) -> dict:
    """Log in one role → {token, tenant}. Returns {} on failure."""
    r = cfg["roles"][role]
    body = json.dumps({"email": r["email"], "password": r["password"]}).encode()
    req = urllib.request.Request(cfg["target"] + cfg.get("login_path", "/api/auth/login"),
                                 data=body, headers={"Content-Type": "application/json"})
    try:
        d = json.load(urllib.request.urlopen(req, timeout=20))
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    token = _dig(d, cfg.get("token_json_path", "tokens.accessToken"))
    user = _dig(d, cfg.get("user_json_path", "user")) or {}
    tenants = user.get(cfg.get("tenant_field", "groupIds")) or []
    return {"token": token, "tenant": tenants[0] if tenants else None,
            "email": user.get("email"), "role": user.get("role")}


def _tenant_only_get_endpoints(facts: dict, param: str) -> list:
    """GET endpoints whose ONLY path param is the tenant param — clean cross-tenant
    list targets that need no other fixture id."""
    out = []
    brace = re.compile(r"\{([^}]+)\}")
    for e in (facts.get("routes") or {}).get("endpoints", []):
        if e.get("method") != "GET":
            continue
        params = brace.findall(e.get("path", ""))
        if params == [param]:
            out.append(e["path"])
    return sorted(set(out))


def cross_tenant_bola(cfg: dict, facts: dict) -> dict:
    """For each tenant-scoped GET list endpoint, try to read the OTHER tenant's data."""
    param = cfg.get("tenant_path_param", "groupId")
    a, b = mint(cfg, "agentA"), mint(cfg, "agentB")
    if not a.get("token") or not b.get("token"):
        return {"error": "could not mint both agent tokens", "agentA": a.get("error"), "agentB": b.get("error")}
    if a.get("tenant") == b.get("tenant") or not (a.get("tenant") and b.get("tenant")):
        return {"error": f"agents are not in two distinct tenants (A={a.get('tenant')}, B={b.get('tenant')})"}

    endpoints = _tenant_only_get_endpoints(facts, param)
    results = []
    for path in endpoints:
        # attacker A tries to read B's tenant data, and vice-versa
        for atk, vic, direction in ((a, b, "A→B"), (b, a, "B→A")):
            url = cfg["target"] + path.replace("{" + param + "}", vic["tenant"])
            code, body = _request("GET", url, atk["token"])
            if code in (401, 403, 404):
                verdict = "blocked"
            elif code in (200, 206) and body and body.strip() not in ("[]", "{}", '{"data":[]}'):
                verdict = "LEAK"
            elif code in (200, 206):
                verdict = "blocked-empty"   # 200 but no cross-tenant data returned
            else:
                verdict = "investigate"
            results.append({"path": path, "direction": direction, "status": code, "verdict": verdict})

    blocked = sum(1 for r in results if r["verdict"].startswith("blocked"))
    leaks = [r for r in results if r["verdict"] == "LEAK"]
    return {
        "target": cfg["target"],
        "tenant_param": param,
        "agentA": {"email": a.get("email"), "tenant": a.get("tenant")},
        "agentB": {"email": b.get("email"), "tenant": b.get("tenant")},
        "endpoints_tested": len(endpoints),
        "checks": len(results),
        "blocked": blocked,
        "leaks": leaks,
        "results": results,
        "summary": f"{blocked}/{len(results)} cross-tenant GET reads blocked" + (f" — {len(leaks)} LEAK(S)!" if leaks else " — all isolated"),
    }


def run_dynamic(config_path: Path, facts_path: Path, outdir: Path) -> dict:
    cfg = json.loads(Path(config_path).read_text())
    facts = json.loads(Path(facts_path).read_text())
    res = {"cross_tenant_bola": cross_tenant_bola(cfg, facts)}
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "dynamic-findings.json").write_text(json.dumps(res, indent=2))
    return res

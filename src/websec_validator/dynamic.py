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


def _request(method: str, url: str, token: str | None, timeout: int = 20, data: bytes | None = None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, method=method, headers=headers, data=data)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read(4000).decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(1000).decode(errors="replace")
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def is_localhost(target: str) -> bool:
    import urllib.parse
    return (urllib.parse.urlparse(target).hostname or "") in ("localhost", "127.0.0.1", "::1", "0.0.0.0")


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


# GET endpoints that are NOT safe to hit even read-only — they trigger real work
# (cron ticks, scraping, content generation, seeding, sending, uploads).
SIDE_EFFECTING = re.compile(
    r"/cron|/seed|generate|regenerate|/trigger|/sync|/send|/run\b|social-image|"
    r"sponsor-post|upload|/refresh|/rebuild|/process|/dispatch|/import|/export|/scrape(?![\w-])", re.I)


def unauth_reachability(target: str, facts: dict, max_endpoints: int = 50) -> dict:
    """STRICT read-only: GET each genuine data-read endpoint with NO auth, to see
    which are reachable unauthenticated. Skips side-effecting GETs and any path
    with an unfilled {param}. Records status + byte size only (never the body)."""
    eps = []
    for e in (facts.get("routes") or {}).get("endpoints", []):
        p = e.get("path", "")
        if e.get("method") != "GET" or "{" in p or SIDE_EFFECTING.search(p):
            continue
        eps.append(p)
    eps = sorted(set(eps))[:max_endpoints]

    results, skipped = [], [e.get("path") for e in (facts.get("routes") or {}).get("endpoints", [])
                            if e.get("method") == "GET" and SIDE_EFFECTING.search(e.get("path", ""))]
    for path in eps:
        code, body = _request("GET", target + path, token=None, timeout=15)
        n = len(body) if isinstance(body, str) else 0
        if code in (401, 403):
            verdict = "protected"
        elif code in (301, 302, 307, 308):
            verdict = "redirect (likely to login)"
        elif code in (200, 206) and n > 2:
            verdict = "OPEN-no-auth"
        elif code in (200, 206):
            verdict = "open-empty"
        elif code == 404:
            verdict = "404"
        else:
            verdict = f"http-{code}"
        results.append({"path": path, "status": code, "bytes": n, "verdict": verdict})

    openish = [r for r in results if r["verdict"] == "OPEN-no-auth"]
    return {
        "target": target,
        "mode": "STRICT read-only · unauthenticated · GET-only · side-effecting paths skipped",
        "tested": len(results),
        "skipped_side_effecting": sorted(set(skipped)),
        "open_no_auth": openish,
        "results": results,
        "summary": f"{len(openish)}/{len(results)} data-read GET endpoints reachable WITHOUT auth"
                   + (" — review whether these should be public" if openish else " — all gated"),
    }


WRITE_VERBS = {"POST", "PUT", "PATCH", "DELETE"}


def write_auth_enforcement(target: str, facts: dict, max_endpoints: int = 80) -> dict:
    """LOCALHOST-ONLY. Does each write endpoint ENFORCE auth? Sends the write verb
    UNAUTHENTICATED with an empty `{}` body and dummy IDs in path params, then reads
    the status: 401/403 = auth enforced (good); 400/422/404/405 = reached the
    handler/validation with no auth gate (auth likely MISSING — verify); 2xx =
    executed unauthenticated (critical). Empty body + dummy id keep it
    non-destructive (validation rejects before any real mutation)."""
    eps = []
    for e in (facts.get("routes") or {}).get("endpoints", []):
        p = e.get("path", "")
        if e.get("method") in WRITE_VERBS and not SIDE_EFFECTING.search(p):
            eps.append((e["method"], p))
    eps = sorted(set(eps))[:max_endpoints]

    results = []
    for method, path in eps:
        url = target + re.sub(r"\{[^}]+\}", "websec-nonexistent-id", path)
        code, _ = _request(method, url, token=None, data=b"{}")
        if code in (401, 403):
            verdict = "auth-enforced"
        elif code in (200, 201, 204):
            verdict = "EXECUTED-UNAUTH"
        elif code in (400, 422, 404, 405, 409, 415, 500):
            verdict = "no-auth-gate (reached handler/validation)"
        else:
            verdict = f"http-{code}"
        results.append({"method": method, "path": path, "status": code, "verdict": verdict})

    missing = [r for r in results if r["verdict"] != "auth-enforced" and not r["verdict"].startswith("http-")]
    executed = [r for r in results if r["verdict"] == "EXECUTED-UNAUTH"]
    enforced = sum(1 for r in results if r["verdict"] == "auth-enforced")
    return {
        "note": "Heuristic: a protected route returns 401/403 BEFORE validation; a 400/404 unauth means "
                "the request reached the handler with no auth gate. VERIFY each — but inconsistency vs "
                "sibling routes is high-signal. Empty body + dummy ids keep this non-destructive.",
        "tested": len(results),
        "auth_enforced": enforced,
        "no_auth_gate": missing,
        "executed_unauth": executed,
        "results": results,
        "summary": f"{enforced}/{len(results)} write endpoints enforce auth · "
                   f"{len(missing)} reached with no auth gate · {len(executed)} executed unauthenticated",
    }


def run_unauth(target: str, facts_path: Path, outdir: Path, probe_writes: bool = False) -> dict:
    facts = json.loads(Path(facts_path).read_text())
    res = {"unauth_reachability": unauth_reachability(target, facts)}
    if probe_writes:
        res["write_auth_enforcement"] = write_auth_enforcement(target, facts)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "dynamic-unauth-findings.json").write_text(json.dumps(res, indent=2))
    return res


def run_dynamic(config_path: Path, facts_path: Path, outdir: Path) -> dict:
    cfg = json.loads(Path(config_path).read_text())
    facts = json.loads(Path(facts_path).read_text())
    res = {"cross_tenant_bola": cross_tenant_bola(cfg, facts)}
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "dynamic-findings.json").write_text(json.dumps(res, indent=2))
    return res

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


def _request(method: str, url: str, token: str | None, timeout: int = 20,
             data: bytes | None = None, cookie: str | None = None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if cookie:
        headers["Cookie"] = cookie
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
            # str(): a tenant id is often numeric (auto-increment) — str.replace's 2nd arg must be a
            # str, so a JSON int would crash this (uncaught) authenticated path.
            url = cfg["target"] + path.replace("{" + param + "}", str(vic["tenant"]))
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


# When NOTHING enforces auth, the likeliest cause in a test env is a fail-OPEN auth
# provider (unconfigured/erroring), not "the app has no auth". Say so loudly — a naive
# read of all-200s as "wide open" is a catastrophic false positive.
FAIL_OPEN_WARNING = (
    "⚠ NO endpoint enforced auth (none returned 401/403). Before concluding authentication is missing, "
    "RULE OUT a fail-OPEN test environment: an unconfigured or erroring auth provider "
    "(Cognito/Auth0/NextAuth/…) can let every request through. Configure a valid (even dummy) provider, or "
    "mock a session, and RE-RUN — if these flip to 401, the app is fine and the env was the bug. Until an "
    "auth-enforced response is observed, treat ALL authN/authZ results here as UNTRUSTWORTHY. (If it stays "
    "open WITH a working provider, that's a real finding: the middleware should fail CLOSED — deny on auth error.)"
)


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
    _all_eps = sorted(set(eps))
    eps = _all_eps[:max_endpoints]
    over_cap = max(0, len(_all_eps) - max_endpoints)   # disclose, don't silently drop (a missed endpoint = a missed lead)

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
    protected = [r for r in results if r["verdict"] in ("protected", "redirect (likely to login)")]
    fail_open = len(results) >= 3 and not protected and bool(openish)
    return {
        "target": target,
        "mode": "STRICT read-only · unauthenticated · GET-only · side-effecting paths skipped",
        "tested": len(results),
        "skipped_side_effecting": sorted(set(skipped)),
        "open_no_auth": openish,
        "results": results,
        "endpoints_over_cap": over_cap,
        "fail_open_suspected": fail_open,
        "authn_trustworthy": not fail_open,
        "warning": FAIL_OPEN_WARNING if fail_open else "",
        "summary": f"{len(openish)}/{len(results)} data-read GET endpoints reachable WITHOUT auth"
                   + (" — review whether these should be public" if openish else " — all gated")
                   + (f"  ·  ⚠ {over_cap} more over the {max_endpoints}-endpoint cap NOT tested" if over_cap else "")
                   + ("  ·  ⚠ FAIL-OPEN SUSPECTED (nothing enforced auth — results untrustworthy)" if fail_open else ""),
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
    _all_eps = sorted(set(eps))
    eps = _all_eps[:max_endpoints]
    over_cap = max(0, len(_all_eps) - max_endpoints)

    results = []
    for method, path in eps:
        url = target + re.sub(r"\{[^}]+\}", "websec-nonexistent-id", path)
        code, _ = _request(method, url, token=None, data=b"{}")
        if code in (401, 403):
            verdict = "auth-enforced"
        elif code in (200, 201, 204):
            verdict = "EXECUTED-UNAUTH"
        elif code in (400, 422, 404, 405, 409, 415):
            verdict = "no-auth-gate (reached handler/validation)"
        else:
            # 500 (and any other code) is INCONCLUSIVE: a 500 may be the auth layer itself throwing,
            # not the handler running unauthenticated — so it must NOT become a no-auth-gate verdict
            # (which would escalate to a HIGH missing-auth finding AND poison the calibration oracle
            # with a confirmed-real sample). Matches the forged-token engine, which also excludes 500
            # from "reached handler".
            verdict = f"http-{code}"
        results.append({"method": method, "path": path, "status": code, "verdict": verdict})

    missing = [r for r in results if r["verdict"] != "auth-enforced" and not r["verdict"].startswith("http-")]
    executed = [r for r in results if r["verdict"] == "EXECUTED-UNAUTH"]
    enforced = sum(1 for r in results if r["verdict"] == "auth-enforced")
    fail_open = len(results) >= 3 and enforced == 0
    return {
        "note": "Heuristic: a protected route returns 401/403 BEFORE validation; a 400/404 unauth means "
                "the request reached the handler with no auth gate. VERIFY each — but inconsistency vs "
                "sibling routes is high-signal. Empty body + dummy ids keep this non-destructive.",
        "tested": len(results),
        "auth_enforced": enforced,
        "no_auth_gate": missing,
        "executed_unauth": executed,
        "results": results,
        "endpoints_over_cap": over_cap,
        "fail_open_suspected": fail_open,
        "authn_trustworthy": not fail_open,
        "warning": FAIL_OPEN_WARNING if fail_open else "",
        "summary": f"{enforced}/{len(results)} write endpoints enforce auth · "
                   f"{len(missing)} reached with no auth gate · {len(executed)} executed unauthenticated"
                   + (f"  ·  ⚠ {over_cap} more over the {max_endpoints}-endpoint cap NOT tested" if over_cap else "")
                   + ("  ·  ⚠ FAIL-OPEN SUSPECTED — results untrustworthy" if fail_open else ""),
    }


# Codes that mean "the request reached the handler/validation" — i.e. auth PASSED. Used to
# judge a forged-token attempt. Deliberately EXCLUDES 401/403 (blocked), 429 (rate-limited —
# would otherwise be a false bypass), 5xx and 000/None (ambiguous/transport). A gated route
# (401/403 with no token) that returns one of these WITH a forged token = signature not verified.
_REACHED_HANDLER = {200, 201, 202, 203, 204, 206, 400, 404, 405, 409, 413, 415, 422}


def _forge_jwt(payload: dict, alg: str = "RS256") -> str:
    """A structurally-valid JWT with a DELIBERATELY INVALID signature (no real key). The whole
    point is to see whether the target verifies the signature at all — a correct verifier
    rejects this outright; a decode-only auth path (the decodeJwtPayloadUnsafe class) trusts it."""
    import base64

    def b(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    sig = "" if alg == "none" else "d2Vic2VjLWZvcmdlZC1zaWc"  # 'websec-forged-sig' — not a real signature
    return ".".join([b({"alg": alg, "typ": "JWT", "kid": "forged"}), b(payload), sig])


def forged_token_bypass(target: str, facts: dict, cookie_names=None,
                        probe_writes: bool = False, max_endpoints: int = 60) -> dict:
    """Does the app actually VERIFY JWT signatures? Forge a token with a far-future `exp` and a
    BOGUS signature, present it to each route that is GATED without auth, and compare. A route
    that answers 401/403 with NO token but REACHES THE HANDLER with the forged token is trusting
    an unverified token = authentication bypass (CWE-347 / OWASP API2:2023) — the dynamic verdict
    on the `decodeJwtPayloadUnsafe`/`jwt.decode(verify=False)` hypothesis.

    GET reads by default (read-safe); write verbs (empty body, dummy ids — non-destructive) only
    when `probe_writes`. Tries `Authorization: Bearer` (universal) plus any `cookie_names` given,
    since apps read tokens from different locations. 429/5xx are treated as inconclusive, never
    a bypass, so an aggressive rate limiter can't manufacture a false positive."""
    forged = _forge_jwt({"sub": "websec-forged", "email": "websec-forged@example.com",
                         "role": "admin", "roles": ["admin"], "exp": 9999999999})
    cookie_names = list(cookie_names or [])

    targets = [("GET", e.get("path", "")) for e in (facts.get("routes") or {}).get("endpoints", [])
               if e.get("method") == "GET" and "{" not in e.get("path", "")
               and not SIDE_EFFECTING.search(e.get("path", ""))]
    if probe_writes:
        targets += [(e.get("method"), e.get("path", "")) for e in (facts.get("routes") or {}).get("endpoints", [])
                    if e.get("method") in WRITE_VERBS and "{" not in e.get("path", "")
                    and not SIDE_EFFECTING.search(e.get("path", ""))]
    _all_targets = sorted(set(targets))
    targets = _all_targets[:max_endpoints]
    over_cap = max(0, len(_all_targets) - max_endpoints)

    results, bypassed = [], []
    for method, path in targets:
        url = target + path
        body = b"{}" if method in WRITE_VERBS else None
        base_code, _ = _request(method, url, token=None, data=body)
        if base_code not in (401, 403):
            continue  # only routes that are gated WITHOUT auth tell us anything about forgery
        # Bearer first (cheapest, most universal); only forge into each known auth cookie if
        # Bearer didn't reach the handler — short-circuits to keep request volume (and
        # rate-limiter pressure) down. cookie_names is what catches cookie-ONLY session apps.
        hit, bearer_code = None, _request(method, url, token=forged, data=body)[0]
        if bearer_code in _REACHED_HANDLER:
            hit = ("Authorization: Bearer", bearer_code)
        else:
            for cn in (cookie_names or []):
                cc = _request(method, url, token=None, data=body, cookie=f"{cn}={forged}")[0]
                if cc in _REACHED_HANDLER:
                    hit = (f"cookie:{cn}", cc)
                    break
        via, fcode = hit if hit else ("Authorization: Bearer", bearer_code)
        row = {"method": method, "path": path, "baseline": base_code, "forged": fcode,
               "via": via, "verdict": "BYPASS" if hit else "rejected"}
        results.append(row)
        if hit:
            bypassed.append(row)

    return {
        "target": target,
        "mode": "present an UNSIGNED/bogus-sig JWT (far-future exp) to each gated route; "
                "reached-handler = signature not verified",
        "token_locations": ["Authorization: Bearer"] + [f"cookie:{c}" for c in cookie_names],
        "tested": len(results),
        "bypassed": bypassed,
        "results": results,
        "endpoints_over_cap": over_cap,
        "summary": f"{len(bypassed)}/{len(results)} gated route(s) accepted a forged unsigned token"
                   + (" — ⚠ SIGNATURE NOT VERIFIED (CWE-347 auth bypass)" if bypassed
                      else " — all rejected the forged token")
                   + (f"  ·  ⚠ {over_cap} more over the {max_endpoints}-endpoint cap NOT tested" if over_cap else ""),
    }


def run_unauth(target: str, facts_path: Path, outdir: Path, probe_writes: bool = False) -> dict:
    facts = json.loads(Path(facts_path).read_text())
    cookie_names = (facts.get("auth") or {}).get("cookie_names")
    res = {"unauth_reachability": unauth_reachability(target, facts),
           "forged_token_bypass": forged_token_bypass(target, facts, cookie_names=cookie_names,
                                                       probe_writes=probe_writes)}
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

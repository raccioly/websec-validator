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

import hashlib
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


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never auto-follow 3xx. For an AUTH judgment a redirect is a MEANINGFUL answer, not a detour:
    a protected route responding `307 → /login` to an unauthenticated request is the app correctly
    refusing access. Following it hands back the login page's `200` (HTML), which every probe here
    then misreads as the endpoint itself being open — the exact false-positive the field report hit
    (`/api/platform-admin/secrets` reported OPEN when it 307s to /login). Returning None makes urllib
    surface the 3xx via HTTPError, so `_request` returns the real status (307/302/…)."""
    def redirect_request(self, *args, **kwargs):
        return None


# One shared opener so redirects are NOT followed anywhere in the dynamic phase.
_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect)


def _read_body(resp, limit: int):
    """Read at most `limit` bytes of a response body. NEVER raises. Returns None if the read FAILED.

    The status code decides every auth verdict here; the body is optional context. Reading it can
    genuinely fail mid-scan — a server that answers a POST with a 3xx *without consuming the request
    body* resets the connection (Errno 54), and truncated/chunked bodies can blow up too. Since the
    caller invokes this from inside an `except HTTPError` handler, an exception here would NOT be
    caught by the sibling `except Exception` and would abort the entire dynamic phase.

    None (read failed) is deliberately DISTINCT from "" (genuinely empty body). Collapsing them
    would turn "we don't know what came back" into "nothing came back" — which downgrades a
    cross-tenant LEAK to 'blocked-empty' and an open endpoint to 'open-empty'. Unknown must never
    silently read as safe."""
    try:
        return resp.read(limit).decode(errors="replace")
    except Exception:
        return None


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
        # NOTE: do NOT follow redirects — see _NoRedirect. A 3xx must reach the callers as a 3xx so a
        # redirect-to-login reads as "blocked", never as the endpoint being open.
        r = _NO_REDIRECT_OPENER.open(req, timeout=timeout)
        return r.status, _read_body(r, 4000)
    except urllib.error.HTTPError as e:
        # An HTTPError IS the answer (401/403/307/404 all decide a verdict) — never lose the status
        # because the BODY could not be read. See _read_body: an exception raised inside this handler
        # would NOT be caught by the sibling `except Exception` below and would kill the whole run.
        return e.code, _read_body(e, 1000)
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def is_localhost(target: str) -> bool:
    import urllib.parse
    return (urllib.parse.urlparse(target).hostname or "") in ("localhost", "127.0.0.1", "::1", "0.0.0.0")


def mint(cfg: dict, role: str) -> dict:
    """Log in one role → {token, tenant}. Returns {} on failure."""
    r = cfg["roles"][role]
    # The credential FIELD NAME is the app's, not ours. This sent {"email": ...} unconditionally, so
    # every API that logs in with `username` — VAmPI and a large share of real ones — failed to mint
    # a token, and the whole BOLA matrix was skipped for a reason that read like a network error.
    # The role object is now sent as-is, so it carries whatever the target expects; `email` +
    # `password` keeps working unchanged because that is simply one such shape.
    credentials = {key: value for key, value in r.items() if not str(key).startswith("_")}
    body = json.dumps(credentials or {"email": r.get("email"), "password": r.get("password")}).encode()
    req = urllib.request.Request(cfg["target"] + cfg.get("login_path", "/api/auth/login"),
                                 data=body, headers={"Content-Type": "application/json"})
    try:
        # Use the SHARED no-redirect opener (bug-208 discipline). urlopen would FOLLOW a login
        # redirect: a 302 → /dashboard replays as a GET with the credentials dropped, and whatever
        # that page returns gets mined for a token — so a FAILED login can mint a bogus identity and
        # the whole BOLA matrix then runs against two fake tenants. A login that redirects instead of
        # returning JSON is a configuration error we must REPORT, not silently follow.
        resp = _NO_REDIRECT_OPENER.open(req, timeout=20)
        d = json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            return {"error": f"login returned {e.code} → {e.headers.get('Location')} instead of a JSON "
                             "token (cookie-session login?). Point --config login_path at the JSON "
                             "auth endpoint, or supply tokens directly."}
        return {"error": f"HTTP {e.code} from the login endpoint"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    token = _dig(d, cfg.get("token_json_path", "tokens.accessToken"))
    user = _dig(d, cfg.get("user_json_path", "user")) or {}
    # A login response need not echo the user object; fall back to the credential we sent so the
    # two identities remain distinguishable in the report either way.
    identity = user.get("email") or credentials.get("email") or credentials.get("username")
    return {"token": token, "tenant": _first_tenant(user.get(cfg.get("tenant_field", "groupIds"))),
            "email": identity, "role": user.get("role")}


def _first_tenant(raw):
    """The first tenant id from a field that may be a list (`groupIds: [5]`) OR a singular scalar
    (`groupId: 5` / "acme"). Coerce to a list before indexing — else a scalar int crashes (`5[0]`
    TypeError, uncaught) and a scalar string silently yields a single-CHARACTER tenant."""
    tenants = raw if isinstance(raw, list) else ([raw] if raw is not None else [])
    return tenants[0] if tenants else None


# HTTP codes that mean "this route is GATED when unauthenticated". 3xx belongs here: a redirect to a
# login page is a refusal (bug-208). Used as the baseline test for the forged-token probe and as the
# 'protected' set elsewhere, so all probes agree on what "blocked" looks like.
_GATED_CODES = {401, 403, 301, 302, 303, 307, 308}

# A 200 that is actually a DENIAL. The other half of bug-208: plenty of apps answer an unauthenticated
# API call with `200 {"user":null,"error":"not authenticated"}` or an SPA/login HTML shell instead of a
# 401. Scoring those as "OPEN-no-auth" is the same catastrophic false positive as following a redirect.
# Deliberately TIGHT — only unambiguous denial markers, so a genuinely open endpoint is not hidden.
_SOFT_DENY = re.compile(
    r'"(?:user|session|data)"\s*:\s*null'
    r'|not\s+authenticated|unauthenticated|unauthorized|not\s+logged\s?in|must\s+be\s+logged\s?in'
    r'|please\s+(?:log|sign)\s?in|login\s+required|authentication\s+required'
    r'|"error"\s*:\s*"(?:forbidden|unauthorized|auth[^"]*)"'
    r'|<title>[^<]*(?:log\s?in|sign\s?in)[^<]*</title>', re.I)


def _looks_like_denial(body) -> bool:
    """True when a 2xx body is really an 'access refused' response (soft deny)."""
    return bool(body) and bool(_SOFT_DENY.search(body[:2000]))


def _no_records(body: str) -> bool:
    """True if a 200/206 response carries NO records (so a cross-tenant read is NOT a leak).

    Parses JSON and tests emptiness STRUCTURALLY instead of string-matching a tiny allowlist
    (`[]`/`{}`/`{"data":[]}`) — that allowlist misclassified common empty wrappers (`{"items":[]}`,
    whitespace-formatted `{ "data": [] }`, paginated `{"data":[],"total":0}`) as LEAKs. Conservative:
    anything that isn't provably empty is treated as DATA, so a real leak is never masked."""
    if not body or not body.strip():
        return True

    def empty(x) -> bool:
        if x is None or x == "" or x == []:
            return True
        if isinstance(x, list):
            return len(x) == 0
        if isinstance(x, dict):
            if not x:
                return True
            cols = [v for v in x.values() if isinstance(v, (list, dict))]
            # empty only when there's at least one data container and ALL of them are empty
            # (scalar siblings like total/page/count are treated as pagination meta).
            return bool(cols) and all(empty(c) for c in cols)
        return False   # a bare scalar payload → treat as data, not empty

    try:
        return empty(json.loads(body))
    except Exception:
        return False   # opaque / non-JSON 200 content → can't prove empty; surface it as a lead


def _tenant_only_get_endpoints(facts: dict, param: str) -> list:
    """GET endpoints whose ONLY path param is the tenant param — clean cross-tenant
    list targets that need no other fixture id."""
    out = []
    brace = re.compile(r"\{([^}]+)\}")
    for e in (facts.get("routes") or {}).get("endpoints", []):
        if e.get("method") != "GET":
            continue
        params = brace.findall(e.get("path", ""))
        # SAFETY: every OTHER probe filters side-effecting paths; this one did not — and it runs
        # AUTHENTICATED, so it is the most likely to actually execute. Without this websec would GET
        # /api/groups/{id}/send-invoices (twice, once per direction) against the user's test env.
        if params == [param] and not SIDE_EFFECTING.search(e.get("path", "")):
            out.append(e["path"])
    return sorted(set(out))


def _marker_matches(body, marker) -> bool:
    """Match an explicit JSON fixture marker without persisting response contents."""
    if not isinstance(marker, dict) or not marker.get("json_path") or "value" not in marker:
        return False
    if marker["value"] in (None, "", [], {}):
        return False
    try:
        value = json.loads(body)
        for part in marker["json_path"].split("."):
            value = value[int(part)] if isinstance(value, list) else value[part]
        return type(value) is type(marker["value"]) and value == marker["value"]
    except (ValueError, TypeError, KeyError, IndexError):
        return False


def cross_tenant_bola(cfg: dict, facts: dict) -> dict:
    """Compare tenant reads, confirming leakage only with explicit private fixture controls.

    Optional ``bola_controls`` declares expected_policy=tenant-isolated, identity_path,
    identities={agentA: {json_path, value}, agentB: ...}, and resources={route_template:
    {agentA: {json_path, value}, agentB: ...}}. Both authenticated identity controls must
    pass. The owner must read the victim marker, an anonymous request must be denied,
    and two attacker reads must return that marker before a LEAK is confirmed.
    """
    param = cfg.get("tenant_path_param", "groupId")
    a, b = mint(cfg, "agentA"), mint(cfg, "agentB")
    if not a.get("token") or not b.get("token"):
        return {"error": "could not mint both agent tokens", "state": "inconclusive",
                "agentA": a.get("error"), "agentB": b.get("error")}
    if (a.get("tenant") == b.get("tenant") or a["token"] == b["token"]
            or any(x.get("tenant") is None for x in (a, b))):
        return {"error": "agents are not in two distinct tenants", "state": "inconclusive"}
    controls = cfg.get("bola_controls") or {}
    identity_path = controls.get("identity_path", "")
    identities = controls.get("identities") or {}
    identity_ok = False
    if (controls.get("expected_policy") == "tenant-isolated" and identity_path.startswith("/")
            and not identity_path.startswith("//") and "{" not in identity_path
            and not SIDE_EFFECTING.search(identity_path)
            and isinstance(identities.get("agentA"), dict) and isinstance(identities.get("agentB"), dict)
            and identities["agentA"].get("json_path") == identities["agentB"].get("json_path")
            and identities["agentA"].get("value") != identities["agentB"].get("value")):
        passes = []
        for agent, name in ((a, "agentA"), (b, "agentB")):
            code, body = _request("GET", cfg["target"] + identity_path, agent["token"])
            passes.append(code == 200 and _marker_matches(body, identities.get(name)))
        identity_ok = all(passes)

    endpoints = _tenant_only_get_endpoints(facts, param)
    results = []
    for path in endpoints:
        markers = (controls.get("resources") or {}).get(path) or {}
        for atk, vic, victim_name, direction in ((a, b, "agentB", "A→B"), (b, a, "agentA", "B→A")):
            url = cfg["target"] + path.replace("{" + param + "}", str(vic["tenant"]))
            marker = markers.get(victim_name)
            owner_ok, private_ok = False, False
            if identity_ok and marker and markers.get("agentA") != markers.get("agentB"):
                owner_code, owner_body = _request("GET", url, vic["token"])
                owner_ok = owner_code == 200 and _marker_matches(owner_body, marker)
                anon_code, _ = _request("GET", url, None)
                private_ok = anon_code in (401, 403, 404)
            code, body = _request("GET", url, atk["token"])
            controlled = identity_ok and owner_ok and private_ok
            state, verdict = "inconclusive", "investigate"
            if code in (401, 403, 404):
                verdict = "blocked"
                state = "blocked" if controlled else "inconclusive"
            elif code in (200, 206) and body is None:
                verdict = "investigate (200 but response body unreadable — re-run)"
            elif code in (200, 206) and controlled and _marker_matches(body, marker):
                # A verified private marker outweighs heuristic denial/empty-body wrappers.
                repeat_code, repeat_body = _request("GET", url, atk["token"])
                if repeat_code in (200, 206) and _marker_matches(repeat_body, marker):
                    state, verdict = "confirmed-vulnerable", "LEAK"
                else:
                    verdict = "candidate cross-tenant data (repeat inconclusive)"
            elif code in (200, 206) and _looks_like_denial(body):
                verdict = "blocked (200 soft-deny)"
                state = "blocked" if controlled else "inconclusive"
            elif code in (200, 206):
                verdict = "blocked-empty" if _no_records(body) else "candidate cross-tenant data"
                if _no_records(body) and controlled:
                    state = "blocked"
            row = {"path": path, "direction": direction, "status": code, "verdict": verdict,
                   "state": state, "evidence_verified": state == "confirmed-vulnerable",
                   "controls": {"identity": identity_ok, "owner": owner_ok, "private": private_ok}}
            if state == "confirmed-vulnerable" and cfg.get("application_id") and cfg.get("build_id"):
                provenance = {"source": "dynamic-bola", "application_id": cfg["application_id"],
                              "build_id": cfg["build_id"], "endpoint": path, "method": "GET",
                              "direction": direction,
                              "fixture_digest": hashlib.sha256(json.dumps(marker, sort_keys=True).encode()).hexdigest()}
                row["provenance"] = provenance
                row["sample_id"] = hashlib.sha256(json.dumps(provenance, sort_keys=True).encode()).hexdigest()
            results.append(row)
    blocked = sum(r["state"] == "blocked" for r in results)
    leaks = [r for r in results if r["state"] == "confirmed-vulnerable"]
    inconclusive = sum(r["state"] == "inconclusive" for r in results)
    state = ("not-tested" if not results else "confirmed-vulnerable" if leaks else
             "inconclusive" if inconclusive else "blocked")
    return {"target": cfg["target"], "tenant_param": param,
            "agentA": {"email": a.get("email"), "tenant": a.get("tenant")},
            "agentB": {"email": b.get("email"), "tenant": b.get("tenant")},
            "endpoints_tested": len(endpoints), "checks": len(results), "blocked": blocked,
            "leaks": leaks, "results": results, "state": state, "inconclusive": inconclusive,
            "summary": ("No eligible cross-tenant reads tested" if not results else
                        f"{blocked}/{len(results)} controlled reads blocked · {len(leaks)} confirmed leak(s) · "
                        f"{inconclusive} inconclusive (conclusions apply only to these identities and fixtures)")}


# GET endpoints that are NOT safe to hit even read-only — they trigger real work
# (cron ticks, scraping, content generation, seeding, sending, uploads).
# Paths whose mere GET/POST may DO something (send mail, run a job, mutate state) — every probe skips
# them. Each alternative is bounded by `(?![\w-])` so it matches a whole path SEGMENT or a hyphenated
# action, never a longer word: `generate` must not swallow `/api/generated-content`, `/send` must not
# swallow `/api/sender-profiles`, `/run` must not swallow `/api/runners`. Over-matching here is not a
# safety win — it silently removes an endpoint from EVERY probe, so a real vulnerability goes untested.
SIDE_EFFECTING = re.compile(
    r"/cron(?![\w-])|/seed(?![\w-])|(?:re)?generate(?![\w-])|/trigger(?![\w-])|/sync(?![\w-])|"
    r"/send(?![\w-])|/send-[\w-]+|/run(?![\w-])|social-image|sponsor-post|upload(?![\w-])|"
    r"/refresh(?![\w-])|/rebuild(?![\w-])|/process(?![\w-])|/dispatch(?![\w-])|/import(?![\w-])|"
    r"/export(?![\w-])|/scrape(?![\w-])", re.I)


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
        elif code in (301, 302, 303, 307, 308):
            verdict = "redirect (likely to login)"
        elif code in (200, 206) and body is None:
            # read failed → we do NOT know what came back. Never let unknown read as "open-empty".
            verdict = "open? (200 but body unreadable — re-run)"
        elif code in (200, 206) and _looks_like_denial(body):
            # the other half of bug-208: a 200 that SAYS "not authenticated" is a refusal, not access.
            verdict = "soft-deny (200 but body says not authenticated — verify)"
        elif code in (200, 206) and n > 2:
            verdict = "OPEN-no-auth"
        elif code in (200, 206):
            verdict = "open-empty"
        elif code == 404:
            verdict = "404"
        else:
            verdict = f"http-{code}"
        results.append({"path": path, "status": code, "bytes": n, "verdict": verdict,
                        "state": "observed" if code in (200, 206, 401, 403) and body is not None else "inconclusive",
                        "evidence_verified": False})

    openish = [r for r in results if r["verdict"] == "OPEN-no-auth"]
    protected = [r for r in results if r["verdict"] in ("protected", "redirect (likely to login)")]
    fail_open = len(results) >= 3 and not protected and bool(openish)
    # TARGET UNREACHABLE: every probe failed at the transport layer (status None) — a typo'd --target,
    # an app that isn't up yet, a CI race. Without this the run reports "0/N reachable — all gated ·
    # authn_trustworthy", i.e. a clean bill of health for a host that was never contacted. Same class
    # as bug-208: a transport reality silently converted into a security verdict.
    unreachable = bool(results) and all(r["status"] is None for r in results)
    return {
        "target": target,
        "mode": "STRICT read-only · unauthenticated · GET-only · side-effecting paths skipped",
        "tested": len(results),
        "state": "not-tested" if not results else "observed" if all(r["state"] == "observed" for r in results) else "inconclusive",
        "skipped_side_effecting": sorted(set(skipped)),
        "open_no_auth": openish,
        "results": results,
        "endpoints_over_cap": over_cap,
        "target_unreachable": unreachable,
        "fail_open_suspected": fail_open,
        "authn_trustworthy": bool(results) and not (fail_open or unreachable or over_cap)
                               and all(r["state"] == "observed" for r in results),
        "warning": (f"⚠ TARGET UNREACHABLE — every request to {target} failed at the transport layer. "
                    "This is NOT a clean result: nothing was tested. Check the URL/port and that the "
                    "app is running." if unreachable else (FAIL_OPEN_WARNING if fail_open else "")),
        "summary": ("⚠ TARGET UNREACHABLE — 0 endpoints actually tested; this is NOT an all-clear"
                    if unreachable else
                    f"{len(openish)}/{len(results)} data-read GET endpoints reachable WITHOUT auth"
                    + (" — review whether these should be public" if openish else " — no unauthenticated data observed; errors and untested routes remain inconclusive"))
                   + (f"  ·  ⚠ {over_cap} more over the {max_endpoints}-endpoint cap NOT tested" if over_cap else "")
                   + ("  ·  ⚠ FAIL-OPEN SUSPECTED (nothing enforced auth — results untrustworthy)" if fail_open else ""),
    }


WRITE_VERBS = {"POST", "PUT", "PATCH", "DELETE"}


def write_auth_enforcement(target: str, facts: dict, max_endpoints: int = 80) -> dict:
    """Observe unauthenticated write responses on an explicitly authorized localhost target.

    Empty bodies and dummy ids reduce impact but cannot guarantee a handler will not mutate.
    Neither validation errors nor successful HTTP responses alone confirm missing authentication.
    """
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
        code, body = _request(method, url, token=None, data=b"{}")
        if code in (401, 403):
            verdict = "auth-enforced"
        elif code in (301, 302, 303, 307, 308):
            # The redirect was not followed; its destination and policy remain unverified.
            verdict = "redirect (auth enforcement unverified)"
        elif code in (200, 201, 204):
            verdict = "soft-deny" if _looks_like_denial(body) else "candidate unauthenticated response"
        elif code in (404, 405):
            # NOT evidence of a missing auth gate. A 405 comes from the ROUTER, before any auth
            # middleware — it proves the method isn't routed, nothing about authorization. A 404 is
            # usually a phantom route recon over-extracted. Treating either as "reached the handler"
            # produced a HIGH missing-auth finding AND fed the calibration oracle a confirmed-real
            # sample. unauth_reachability already gives 404 a neutral verdict; match it.
            verdict = f"http-{code} (route/method not present — inconclusive, not an auth signal)"
        elif code in (400, 422, 409, 415):
            verdict = f"http-{code} (validation response — auth enforcement inconclusive)"
        else:
            # 500 (and any other code) is INCONCLUSIVE: a 500 may be the auth layer itself throwing,
            # not the handler running unauthenticated — so it must NOT become a no-auth-gate verdict
            # (which would escalate to a HIGH missing-auth finding AND poison the calibration oracle
            # with a confirmed-real sample). Matches the forged-token engine, which also excludes 500
            # from "reached handler".
            verdict = f"http-{code}"
        results.append({"method": method, "path": path, "status": code, "verdict": verdict,
                        "state": "blocked" if code in (401, 403) else "inconclusive",
                        "evidence_verified": False})

    missing = []  # Status alone never proves an authentication bypass.
    candidates = [r for r in results if r["verdict"] == "candidate unauthenticated response"]
    executed = []  # Retained output field; execution requires evidence beyond HTTP status.
    enforced = sum(1 for r in results if r["verdict"] == "auth-enforced")
    fail_open = len(results) >= 3 and enforced == 0 and bool(candidates)
    unreachable = bool(results) and all(r["status"] is None for r in results)
    return {
        "note": "Status observations only: validation can precede authentication and a 2xx may be public or "
                "a soft denial. Confirm expected policy and actual protected behavior before labeling a vulnerability.",
        "tested": len(results),
        "state": "not-tested" if not results else "blocked" if all(r["state"] == "blocked" for r in results) else "inconclusive",
        "auth_enforced": enforced,
        "no_auth_gate": missing,
        "candidates": candidates,
        "target_unreachable": unreachable,
        "executed_unauth": executed,
        "results": results,
        "endpoints_over_cap": over_cap,
        "fail_open_suspected": fail_open,
        "authn_trustworthy": bool(results) and not (fail_open or unreachable) and all(r["state"] == "blocked" for r in results),
        "warning": FAIL_OPEN_WARNING if fail_open else "",
        "summary": f"{enforced}/{len(results)} write endpoints enforce auth · "
                   f"{len(candidates)} unauthenticated response candidate(s) · "
                   f"{sum(r['state'] == 'inconclusive' for r in results)} inconclusive"
                   + (f"  ·  ⚠ {over_cap} more over the {max_endpoints}-endpoint cap NOT tested" if over_cap else "")
                   + ("  ·  ⚠ FAIL-OPEN SUSPECTED — results untrustworthy" if fail_open else ""),
    }


# Successful status changes merit investigation, but do not alone prove signature acceptance.
_REACHED_HANDLER = {200, 201, 202, 203, 204, 206}


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
    """Compare gated requests with forged-token responses, recording candidates and uncertainty.

    Status changes alone do not prove a signature bypass: validate legitimate identities and
    protected resource behavior before confirmation. GET-only unless explicitly enabled for writes.
    """
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

    results, bypassed, candidates = [], [], []
    for method, path in targets:
        url = target + path
        body = b"{}" if method in WRITE_VERBS else None
        base_code, _ = _request(method, url, token=None, data=body)
        if base_code not in _GATED_CODES:
            continue  # only routes that are gated WITHOUT auth tell us anything about forgery
        # Bearer first (cheapest, most universal); only forge into each known auth cookie if
        # Bearer didn't reach the handler — short-circuits to keep request volume (and
        # rate-limiter pressure) down. cookie_names is what catches cookie-ONLY session apps.
        hit = None
        bearer_code, bearer_body = _request(method, url, token=forged, data=body)
        attempt_codes = [bearer_code]
        if bearer_code in _REACHED_HANDLER and bearer_body is not None and not _looks_like_denial(bearer_body):
            hit = ("Authorization: Bearer", bearer_code)
        else:
            for cn in (cookie_names or []):
                cc, cb = _request(method, url, token=None, data=body, cookie=f"{cn}={forged}")
                attempt_codes.append(cc)
                if cc in _REACHED_HANDLER and cb is not None and not _looks_like_denial(cb):
                    hit = (f"cookie:{cn}", cc)
                    break
        via, fcode = hit if hit else ("Authorization: Bearer", bearer_code)
        row = {"method": method, "path": path, "baseline": base_code, "forged": fcode,
               "via": via, "verdict": "candidate-bypass" if hit else
               "rejected" if all(c in (401, 403) for c in attempt_codes) else "inconclusive",
               "evidence_verified": False}
        results.append(row)
        if hit:
            candidates.append(row)

    return {
        "target": target,
        "mode": "present an UNSIGNED/bogus-sig JWT (far-future exp) to each gated route; "
                "response difference is a lead; verify protected behavior and legitimate identity controls",
        "token_locations": ["Authorization: Bearer"] + [f"cookie:{c}" for c in cookie_names],
        "tested": len(results),
        "bypassed": bypassed,
        "candidates": candidates,
        "results": results,
        "endpoints_over_cap": over_cap,
        # NOT_RUN is not a PASS. If no route presented a gated baseline there was nothing to forge
        # against, so "all rejected the forged token" would be an affirmative all-clear for a probe
        # that never ran (it read that way on every redirect-gated app before _GATED_CODES).
        "inconclusive": not results or bool(over_cap) or any(r["verdict"] != "rejected" for r in results),
        "summary": ("⚠ INCONCLUSIVE — no route returned a gated (401/403/3xx) baseline, so the "
                    "forged-token probe had nothing to test. This is NOT a pass: check the target is "
                    "up and that these routes really require auth."
                    if not results else
                    f"{len(candidates)}/{len(results)} forged-token response candidate(s) · "
                    f"{sum(r['verdict'] == 'inconclusive' for r in results)} inconclusive"
                    + (" — verify identity and protected behavior before confirming bypass" if candidates
                       else " — no bypass confirmed"))
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

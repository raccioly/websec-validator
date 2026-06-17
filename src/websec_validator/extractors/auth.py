"""Auth model extractor — scheme, login surface, guards.

Uses framework + route signals (e.g. a NextAuth catch-all route is a dead
giveaway) before falling back to grep, so it doesn't coin-flip between bearer and
cookie the way naive signal-counting does.
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext

JWT_LIBS = re.compile(r"jsonwebtoken|\bjose\b|\bPyJWT\b|import\s+jwt\b|get_jwt_identity|"
                      r"jwt\.(?:sign|verify|encode|decode)|jwtVerify|flask_jwt|@?jwt_required|token_required", re.I)
PASSPORT = re.compile(r"\bpassport\b|passport-jwt|passport-local")
SESSION = re.compile(r"express-session|cookie-session|iron-session|flask\.session|request\.session|getServerSession|getToken", re.I)
APIKEY = re.compile(r"x-api-key|api[_-]?key|apikey", re.I)
# HMAC-signed session cookies / payloads — the app authenticates by VERIFYING an HMAC (common in
# Cloudflare Workers / edge via crypto.subtle.sign/verify), NOT a JWT. Without this the scheme
# misreads as "api-key" and JWT-specific probes get staged for a no-JWT app (P2).
HMAC_AUTH = re.compile(r"crypto\.subtle\.(?:sign|verify)|createHmac|\bhmac\.new\b|compare_digest"
                       r"|timingSafeEqual|HMAC-SHA", re.I)
GUARDS = re.compile(r"requireAuth|requirePermission|requireRole|isAuthenticated|@login_required|@require|ensureAuth|withAuth|getServerSession|verifyToken|authMiddleware|@roles_required|can\(|ability\.", re.I)
# Cookie READ sites — the names the app pulls a token/session from. The forged-token probe
# forges into these (not just Authorization: Bearer) so a cookie-ONLY session app isn't a
# false negative. Covers cookies.get('X') / cookies['X'] / getCookie('X') / req.cookies.X.
COOKIE_READ = re.compile(
    r"""cookies\s*(?:\.get\(|\[)\s*['"]([A-Za-z0-9_.\-]{2,64})['"]"""      # cookies.get('X') / cookies['X']
    r"""|getCookie\(\s*['"]([A-Za-z0-9_.\-]{2,64})['"]"""                 # getCookie('X')
    r"""|\.cookies\.([A-Za-z_][A-Za-z0-9_]{1,63})\b(?!\s*\()""")          # req.cookies.X (not a .get()/.set() call)
_COOKIE_RESERVED = {"get", "set", "getall", "has", "delete", "clear", "tostring",
                    "foreach", "entries", "keys", "values", "size", "name", "value", "length"}
# Any cookie usage at all (set/read/header) — qualifies an HMAC app as cookie-SESSION vs webhook-only,
# even when the exact cookie name isn't captured by COOKIE_READ (e.g. a Worker parsing the Cookie header).
COOKIE_PRESENT = re.compile(r"set-cookie|getCookie|setCookie|req\.cookies|\.cookies\b|c\.req\.cookie"
                            r"|headers\.get\(\s*['\"]cookie|document\.cookie", re.I)

# Insecure DEFAULT signing secret — a hard-coded fallback on a secret/key var (the forgeable-JWT
# class, REF-PENTEST #8). JS/TS: `process.env.JWT_SECRET || 'dev-secret-do-not-use-in-prod'`;
# Python: os.environ.get('JWT_SECRET', 'dev-secret'). A quoted fallback on a *SECRET/*KEY var is
# almost never benign — and if it's a dev-ish placeholder AND the repo actually signs JWTs, anyone
# who reads the source can forge tokens for any user/role.
_SECRET_VAR = (r"(?:JWT[_-]?SECRET|TOKEN[_-]?SECRET|REFRESH[_-]?SECRET|SIGNING[_-]?KEY"
               r"|SESSION[_-]?SECRET|COOKIE[_-]?SECRET|AUTH[_-]?SECRET|APP[_-]?SECRET"
               r"|HMAC[_-]?KEY|PRIVATE[_-]?KEY|SECRET[_-]?KEY|SECRET)")
SECRET_DEFAULT_JS = re.compile(
    _SECRET_VAR + r"['\"\]\s]*\s*(?:\|\||\?\?)\s*[`'\"]([^`'\"]{3,80})[`'\"]", re.I)
SECRET_DEFAULT_PY = re.compile(
    r"(?:os\.environ\.get|os\.getenv|getenv)\(\s*['\"][^'\"]*" + _SECRET_VAR
    + r"[^'\"]*['\"]\s*,\s*['\"]([^'\"]{3,80})['\"]", re.I)
# placeholder markers that make a fallback unambiguously a non-production dev secret
SECRET_DEVISH = re.compile(r"dev|do[_-]?not[_-]?use|change[_-]?(?:me|it|this)|placeholder|secret|test"
                           r"|local|example|sample|default|your[_-]|xxx|todo|fixme|123456|password", re.I)
JWT_SIGN_VERIFY = re.compile(r"jwt\.(?:sign|verify)|jsonwebtoken|\bjose\b|jwtVerify|SignJWT|jwt\.encode", re.I)


def _looks_like_example(rel: str) -> bool:
    """Example/doc files are MEANT to hold placeholder secrets — don't cry forgeable-JWT on them."""
    r = rel.lower()
    return (".example" in r or ".sample" in r or ".dist" in r or ".template" in r
            or "/docs/" in r or "/doc/" in r or "/examples/" in r or r.endswith((".md", ".mdx")))


class AuthExtractor(Extractor):
    name = "auth"
    category = "authn"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        frameworks = set((facts.get("stack") or {}).get("frameworks", []))
        routes = facts.get("routes") or {}
        auth_eps = (routes.get("targeting") or {}).get("auth_endpoints", [])

        # scheme: framework/route signals first, then grep
        jwt = passport = session = apikey = hmac = 0
        guard_files = []
        cookie_names: list[str] = []
        secret_defaults: list = []          # (file, literal) hard-coded fallback signing secrets
        jwt_sign_verify = False             # does the repo actually sign/verify JWTs?
        cookie_present = False              # any cookie usage (qualifies HMAC as cookie-session)
        for _p, rel, text in ctx.iter_code():
            if JWT_LIBS.search(text):
                jwt += 1
            if PASSPORT.search(text):
                passport += 1
            if SESSION.search(text):
                session += 1
            if APIKEY.search(text):
                apikey += 1
            if HMAC_AUTH.search(text):
                hmac += 1
            if GUARDS.search(text) and len(guard_files) < 25:
                guard_files.append(rel)
            if len(cookie_names) < 20:
                for m in COOKIE_READ.finditer(text):
                    name = m.group(1) or m.group(2) or m.group(3)
                    if name and name.lower() not in _COOKIE_RESERVED and name not in cookie_names:
                        cookie_names.append(name)
            if JWT_SIGN_VERIFY.search(text):
                jwt_sign_verify = True
            if not cookie_present and COOKIE_PRESENT.search(text):
                cookie_present = True
            if not _looks_like_example(rel):
                for mm in SECRET_DEFAULT_JS.finditer(text):
                    secret_defaults.append((rel, mm.group(1)))
                for mm in SECRET_DEFAULT_PY.finditer(text):
                    secret_defaults.append((rel, mm.group(1)))

        # Hard-coded fallback signing secret → forgeable-JWT lead (REF-PENTEST #8). De-dup by
        # (file, literal); mark dev-ish placeholders. findings.py escalates dev-ish + jwt-in-use to
        # CRITICAL; probes.stage seeds the literal into the hs256 brute-force candidate list.
        seen_sd: set = set()
        insecure_secret_defaults: list = []
        for rel_, lit in secret_defaults:
            if (rel_, lit) in seen_sd:
                continue
            seen_sd.add((rel_, lit))
            insecure_secret_defaults.append({"file": rel_, "literal": lit,
                                             "dev_ish": bool(SECRET_DEVISH.search(lit))})
            if len(insecure_secret_defaults) >= 20:
                break

        nextauth = "nextauth" in frameworks or any("nextauth" in e.lower() for e in auth_eps)

        # Detect ALL schemes present, then pick a primary by priority. A JWT app
        # that also wires Passport for SSO must read as primary=jwt, not passport
        # (Passport is often SSO-only). Priority: nextauth > jwt > session > passport > api-key.
        route_count = len(routes.get("endpoints", []))
        # an HMAC-signed cookie is a real session mechanism — rank it above api-key (an x-api-key may
        # just be a secondary admin header), but below JWT/nextauth.
        hmac_cookie = bool(hmac and (cookie_names or session or cookie_present))
        detected = []
        if nextauth:
            detected.append("nextauth (session JWT in cookie)")
        if jwt:
            detected.append("jwt (bearer)")
        if hmac_cookie:
            detected.append("hmac-signed-cookie")
        if session:
            detected.append("session-cookie")
        if passport:
            detected.append("passport (often SSO/OAuth strategies)")
        if apikey:
            detected.append("api-key")
        primary = detected[0] if detected else "unknown"
        token_location = ("cookie" if primary.startswith(("nextauth", "session", "hmac"))
                          else "bearer" if primary.startswith("jwt")
                          else "header" if primary.startswith("api-key")
                          else "cookie-or-bearer" if primary.startswith("passport") else "unknown")

        return {
            "scheme": primary,
            "schemes_detected": detected,
            "token_location": token_location,
            "login_endpoints": auth_eps,
            "cookie_names": cookie_names[:15],
            "guard_files": guard_files,
            "signal_counts": {"jwt": jwt, "passport": passport, "session": session, "api_key": apikey, "hmac": hmac},
            "insecure_secret_defaults": insecure_secret_defaults,   # CRITICAL-class (forgeable JWT #8)
            "jwt_sign_verify_present": jwt_sign_verify,
            "route_count": route_count,
            "reliable_signal": route_count > 0 or bool(nextauth),
            "note": (("⚠ No HTTP routes detected — this auth scheme is LOW-CONFIDENCE (likely a "
                      "library/CLI/scanner that merely mentions auth, or routes weren't parsed). "
                      if not (route_count > 0 or nextauth) else "")
                     + "AGENT: confirm the PRIMARY auth flow + how a test token is minted before the "
                     "JWT/auth probes. Multiple schemes often mean primary bearer/session + secondary SSO."),
        }

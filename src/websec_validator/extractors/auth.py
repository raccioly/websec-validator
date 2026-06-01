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


class AuthExtractor(Extractor):
    name = "auth"
    category = "authn"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        frameworks = set((facts.get("stack") or {}).get("frameworks", []))
        routes = facts.get("routes") or {}
        auth_eps = (routes.get("targeting") or {}).get("auth_endpoints", [])

        # scheme: framework/route signals first, then grep
        jwt = passport = session = apikey = 0
        guard_files = []
        cookie_names: list[str] = []
        for _p, rel, text in ctx.iter_code():
            if JWT_LIBS.search(text):
                jwt += 1
            if PASSPORT.search(text):
                passport += 1
            if SESSION.search(text):
                session += 1
            if APIKEY.search(text):
                apikey += 1
            if GUARDS.search(text) and len(guard_files) < 25:
                guard_files.append(rel)
            if len(cookie_names) < 20:
                for m in COOKIE_READ.finditer(text):
                    name = m.group(1) or m.group(2) or m.group(3)
                    if name and name.lower() not in _COOKIE_RESERVED and name not in cookie_names:
                        cookie_names.append(name)

        nextauth = "nextauth" in frameworks or any("nextauth" in e.lower() for e in auth_eps)

        # Detect ALL schemes present, then pick a primary by priority. A JWT app
        # that also wires Passport for SSO must read as primary=jwt, not passport
        # (Passport is often SSO-only). Priority: nextauth > jwt > session > passport > api-key.
        route_count = len(routes.get("endpoints", []))
        detected = []
        if nextauth:
            detected.append("nextauth (session JWT in cookie)")
        if jwt:
            detected.append("jwt (bearer)")
        if session:
            detected.append("session-cookie")
        if passport:
            detected.append("passport (often SSO/OAuth strategies)")
        if apikey:
            detected.append("api-key")
        primary = detected[0] if detected else "unknown"
        token_location = ("cookie" if primary.startswith("nextauth") or primary.startswith("session")
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
            "signal_counts": {"jwt": jwt, "passport": passport, "session": session, "api_key": apikey},
            "route_count": route_count,
            "reliable_signal": route_count > 0 or bool(nextauth),
            "note": (("⚠ No HTTP routes detected — this auth scheme is LOW-CONFIDENCE (likely a "
                      "library/CLI/scanner that merely mentions auth, or routes weren't parsed). "
                      if not (route_count > 0 or nextauth) else "")
                     + "AGENT: confirm the PRIMARY auth flow + how a test token is minted before the "
                     "JWT/auth probes. Multiple schemes often mean primary bearer/session + secondary SSO."),
        }

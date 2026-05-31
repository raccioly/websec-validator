"""Auth model extractor — scheme, login surface, guards.

Uses framework + route signals (e.g. a NextAuth catch-all route is a dead
giveaway) before falling back to grep, so it doesn't coin-flip between bearer and
cookie the way naive signal-counting does.
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext

JWT_LIBS = re.compile(r"jsonwebtoken|\bjose\b|\bPyJWT\b|get_jwt_identity|jwt\.sign|jwt\.verify|jwtVerify|flask_jwt", re.I)
PASSPORT = re.compile(r"\bpassport\b|passport-jwt|passport-local")
SESSION = re.compile(r"express-session|cookie-session|iron-session|flask\.session|request\.session|getServerSession|getToken", re.I)
APIKEY = re.compile(r"x-api-key|api[_-]?key|apikey", re.I)
GUARDS = re.compile(r"requireAuth|requirePermission|requireRole|isAuthenticated|@login_required|@require|ensureAuth|withAuth|getServerSession|verifyToken|authMiddleware|@roles_required|can\(|ability\.", re.I)


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

        nextauth = "nextauth" in frameworks or any("nextauth" in e.lower() for e in auth_eps)
        if nextauth:
            scheme, token_location = "nextauth (session JWT in cookie)", "cookie"
        elif passport:
            scheme, token_location = "passport", "cookie-or-bearer"
        elif jwt:
            scheme, token_location = "jwt", "bearer"
        elif session:
            scheme, token_location = "session-cookie", "cookie"
        elif apikey:
            scheme, token_location = "api-key", "header"
        else:
            scheme, token_location = "unknown", "unknown"

        return {
            "scheme": scheme,
            "token_location": token_location,
            "login_endpoints": auth_eps,
            "guard_files": guard_files,
            "signal_counts": {"jwt": jwt, "passport": passport, "session": session, "api_key": apikey},
            "note": "AGENT: confirm the real auth flow + how a test token is minted before running the JWT/auth probes.",
        }

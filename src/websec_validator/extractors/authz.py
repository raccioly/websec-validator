"""Authorization extractor — the access-control map (who can reach what).

Per your methodology this is the highest-value test. For each endpoint we decide
whether a guard protects it, using three signals:
  1. a guard pattern in the handler's own file (incl. `router.use(authenticate)`),
  2. coverage by a Next.js middleware matcher,
  3. a GLOBAL auth middleware (`app.use(authenticate)`) — when present, routes are
     protected by default and "no visible guard" becomes a *verify* signal, not an
     alarm (this is what inflated the count on the Express monorepo).

File-level heuristic → results are HINTS the agent confirms. The high-signal
output is write endpoints with no visible guard that also don't look public.
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import Extractor, RepoContext

WRITE_VERBS = {"POST", "PUT", "PATCH", "DELETE"}

GUARD = re.compile(
    r"requireAuth|requirePermission|requireRole|requireGroupAccess|isAuthenticated|"
    r"@login_required|@jwt_required|@permission_required|@roles_required|ensureAuth|"
    r"withAuth|getServerSession|getToken\s*\(|verifyToken|authMiddleware|@UseGuards|"
    r"@Roles\b|Depends\s*\(\s*(?:get_current_user|oauth2_scheme|require_)|Security\s*\(|"
    r"PermissionRequired|LoginRequired|passport\.authenticate|"
    r"\.use\s*\(\s*[\w.]*(?:[Aa]uth|[Vv]erifyToken|[Rr]equire|[Gg]uard|jwt)\w*", re.I)

# a global, path-less auth middleware → everything downstream is protected by default
GLOBAL_AUTH = re.compile(
    r"app\.use\s*\(\s*[\w.]*(?:authenticate|requireAuth|authMiddleware|verifyToken|"
    r"isAuthenticated|jwtMiddleware|ensureAuth)\w*\s*\)", re.I)

PUBLIC_HINT = re.compile(
    r"/(login|logout|register|signup|signin|health|healthz|ping|status|webhooks?|"
    r"public|\.well-known|robots|favicon|sitemap|callback|refresh|csrf|metrics)\b", re.I)

ROLE = re.compile(
    r"@Roles\s*\(([^)]*)\)|allowedRoles\s*=\s*\[([^\]]*)\]|"
    r"\b(?:role|roles)\b\s*[!=]==?\s*['\"]([\w:.-]+)['\"]|"
    r"has_?[Rr]ole\s*\(\s*['\"]([\w:.-]+)['\"]|"
    r"authorizeRoles\s*\(([^)]*)\)|permission_required\s*\(\s*['\"]([\w:.-]+)['\"]")


def _parse_next_middleware(ctx: RepoContext) -> dict:
    for cand in ("middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js"):
        txt = ctx.manifest(cand)
        if not txt:
            continue
        matchers = re.findall(r"matcher\s*:\s*\[([^\]]*)\]", txt)
        patterns = re.findall(r"['\"]([^'\"]+)['\"]", matchers[0]) if matchers else []
        roles = [m for grp in ROLE.findall(txt) for m in grp if m]
        return {"present": True, "file": cand, "matchers": patterns, "role_checks": roles}
    return {"present": False, "matchers": []}


def _matcher_covers(path: str, matchers: list) -> bool:
    for m in matchers:
        base = m.split(":")[0].split("(")[0].rstrip("/*")
        if base and path.startswith(base):
            return True
        if m.startswith("/(") or m == "/:path*":
            return True
    return False


def _collect_roles(text: str, roles: set) -> None:
    for grp in ROLE.findall(text or ""):
        for m in grp:
            if not m:
                continue
            for part in m.split(","):
                v = part.strip().strip("'\" ")
                if v and len(v) < 40:
                    roles.add(v)


class AuthzExtractor(Extractor):
    name = "authz"
    category = "authz"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        endpoints = (facts.get("routes") or {}).get("endpoints", [])
        mw = _parse_next_middleware(ctx)

        global_auth = any(GLOBAL_AUTH.search(t) for _p, _r, t in ctx.iter_code())
        roles: set = set(mw.get("role_checks", []))
        protected = no_guard = unknown = 0
        no_guard_writes, egs = [], []

        for e in endpoints:
            cp = e.get("code_path", "")
            text = ctx.text(Path(cp)) if cp else ""
            _collect_roles(text, roles)
            guarded = bool(text and GUARD.search(text)) or _matcher_covers(e.get("path", ""), mw.get("matchers", []))
            relcp = ctx.rel(Path(cp)) if cp else ""
            egs.append({"method": e.get("method"), "path": e.get("path"), "code_path": relcp,
                        "guarded": bool(guarded), "analyzed": bool(text),
                        "public_hint": bool(PUBLIC_HINT.search(e.get("path", "")))})
            if guarded:
                protected += 1
            elif not text:
                unknown += 1
            else:
                no_guard += 1
                if e.get("method") in WRITE_VERBS and not PUBLIC_HINT.search(e.get("path", "")):
                    no_guard_writes.append(f"{e['method']} {e['path']}  ({relcp or '?'})")

        if global_auth:
            note = ("A GLOBAL auth middleware (`app.use(<auth>)`) was detected — most routes are likely "
                    "protected by default. The list below is write endpoints with NO guard visible in their "
                    "own handler file; they MAY be covered globally. Verify each is either covered or an "
                    "intentional public exemption — don't assume they're vulnerable.")
        else:
            note = ("No global auth middleware detected. Write endpoints with no visible guard are "
                    "high-signal missing-authz leads — verify each.")

        return {
            "global_auth_middleware": global_auth,
            "next_middleware": mw,
            "roles_detected": sorted(r for r in roles if r),
            "guard_summary": {"with_visible_guard": protected,
                              "no_visible_guard": no_guard, "unknown": unknown},
            "endpoint_guards": egs[:400],
            "write_endpoints_without_visible_guard": sorted(set(no_guard_writes))[:60],
            "note": note,
        }

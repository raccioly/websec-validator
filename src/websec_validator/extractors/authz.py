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

# endpoint_guards feeds the missing-auth ledger (findings.build_ledger), so capping it low was a
# silent coverage cliff: a big monorepo's unguarded write #401 never became a finding. Raised to
# cover realistic monorepos; truncation beyond this is DISCLOSED (endpoint_guards_truncated), never
# silent — mirrors constitution.py's "…and N more" pattern.
_MAX_ENDPOINT_GUARDS = 5000

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

# Does a Next.js middleware/proxy file actually enforce AUTH (vs. i18n/headers only)?
# `auth((req)=>…)` / `withAuth` / `req.auth` / getToken / getServerSession / redirect-to-login /
# a 401 / Clerk / Supabase updateSession all signal a global auth gate.
MW_AUTH = re.compile(
    r"\bauth\s*\(|withAuth\b|req\.auth\b|getToken\s*\(|getServerSession\s*\(|clerkMiddleware|"
    r"updateSession\s*\(|NextResponse\.redirect\([^)]*(?:login|signin)|status:\s*401|"
    r"['\"]Authentication required['\"]", re.I)

PUBLIC_HINT = re.compile(
    r"/(login|logout|register|signup|signin|health|healthz|ping|status|webhooks?|"
    r"public|\.well-known|robots|favicon|sitemap|callback|refresh|csrf|metrics)\b", re.I)

ROLE = re.compile(
    r"@Roles\s*\(([^)]*)\)|allowedRoles\s*=\s*\[([^\]]*)\]|"
    r"\b(?:role|roles)\b\s*[!=]==?\s*['\"]([\w:.-]+)['\"]|"
    r"has_?[Rr]ole\s*\(\s*['\"]([\w:.-]+)['\"]|"
    r"authorizeRoles\s*\(([^)]*)\)|permission_required\s*\(\s*['\"]([\w:.-]+)['\"]")

# F5: a call to a decoder/parser named "unsafe"/"unverified"/"noVerify"/"skipVerify"
# (e.g. decodeJwtPayloadUnsafe) — dangerous when its result feeds an auth decision.
UNSAFE_DECODER = re.compile(r"\b([A-Za-z_]\w*(?:[Uu]nsafe|[Uu]nverified|[Nn]o[Vv]erif\w*|[Ss]kip[Vv]erif\w*)\w*)\s*\(")
# does this file actually make an auth/identity decision? (so the unsafe decode matters)
AUTH_CONTEXT = re.compile(
    r"require(?:Auth|Admin|Role|Permission)|isAdmin|authoriz|getToken\s*\(|getServerSession|"
    r"req\.auth\b|currentUser|jwt\.(?:decode|verify)|decodeJwt", re.I)


def _parse_next_middleware(ctx: RepoContext) -> dict:
    # Next 15.5+/16 renamed `middleware.ts` → `proxy.ts` (both filenames are valid; the
    # framework recognizes either). Missing this made the tool report "no global auth" on
    # Next 16 apps and flag every handler — the single biggest false-positive cluster.
    for cand in ("middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js",
                 "proxy.ts", "proxy.js", "src/proxy.ts", "src/proxy.js"):
        txt = ctx.manifest(cand)
        if not txt:
            continue
        matchers = re.findall(r"matcher\s*:\s*\[([^\]]*)\]", txt)
        patterns = re.findall(r"['\"]([^'\"]+)['\"]", matchers[0]) if matchers else []
        roles = [m for grp in ROLE.findall(txt) for m in grp if m]
        return {"present": True, "file": cand, "matchers": patterns,
                "is_auth": bool(MW_AUTH.search(txt)), "role_checks": roles}
    return {"present": False, "matchers": [], "is_auth": False}


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
        mw_auth = mw.get("is_auth", False)

        # global auth = an Express path-less auth middleware OR a Next auth middleware/proxy
        global_auth = mw_auth or any(GLOBAL_AUTH.search(t) for _p, _r, t in ctx.iter_code())
        roles: set = set(mw.get("role_checks", []))
        protected = no_guard = unknown = 0
        no_guard_writes, egs = [], []

        for e in endpoints:
            cp = e.get("code_path", "")
            text = ctx.text(Path(cp)) if cp else ""
            _collect_roles(text, roles)
            # a matcher only counts as a guard when the middleware actually does auth — a
            # non-auth middleware.ts (i18n/headers) must NOT mark routes protected.
            guarded = bool(text and GUARD.search(text)) or \
                (mw_auth and _matcher_covers(e.get("path", ""), mw.get("matchers", [])))
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

        # F5: files that make an auth decision AND call an unsafe/unverified decoder
        unsafe_decoders = []
        for _p, rel, text in ctx.iter_code():
            if AUTH_CONTEXT.search(text):
                for dec in sorted(set(UNSAFE_DECODER.findall(text))):
                    unsafe_decoders.append({"file": rel, "decoder": dec})

        # A guard DEFINED in a file that also calls an unsafe/unverified decoder authenticates via
        # an unverified decode. Routes that call such a guard are the static "at-risk" set for the
        # forged-token bypass class — the dynamic probe confirms which actually fall, but this points
        # at them even with NO live target (turns the F5 hypothesis into named routes).
        unverified_routes: list = []
        unsafe_files = {ud["file"] for ud in unsafe_decoders}
        if unsafe_files:
            guard_def = re.compile(r"(?:export\s+)?(?:async\s+)?(?:function|const)\s+"
                                   r"(require\w+|ensure\w+|\w*[Aa]uth\w*|verify\w+)\b")
            unsafe_guards = set()
            for _p, rel, text in ctx.iter_code():
                if rel in unsafe_files:
                    unsafe_guards.update(g for g in guard_def.findall(text) if len(g) >= 5)
            if unsafe_guards:
                call = re.compile(r"\b(?:" + "|".join(re.escape(g) for g in sorted(unsafe_guards)) + r")\s*\(")
                for e in endpoints:
                    cp = e.get("code_path", "")
                    t = ctx.text(Path(cp)) if cp else ""
                    if t and call.search(t):
                        unverified_routes.append(f"{e.get('method')} {e.get('path')}")
            unverified_routes = sorted(set(unverified_routes))[:60]

        if global_auth:
            where = f"`{mw['file']}` (matcher {mw.get('matchers') or '—'})" if mw_auth else "`app.use(<auth>)`"
            note = (f"A GLOBAL auth middleware ({where}) was detected — most routes are protected by default. "
                    "Endpoints its matcher covers are reported as guarded (defense-in-depth handled centrally). "
                    "Any list below is write endpoints with NO guard visible in their own handler file AND not "
                    "covered by the matcher; verify each is either covered or an intentional public exemption — "
                    "don't assume they're vulnerable.")
        else:
            note = ("No global auth middleware detected. Write endpoints with no visible guard are "
                    "high-signal missing-authz leads — verify each.")

        return {
            "global_auth_middleware": global_auth,
            "next_middleware": mw,
            "roles_detected": sorted(r for r in roles if r),
            "guard_summary": {"with_visible_guard": protected,
                              "no_visible_guard": no_guard, "unknown": unknown},
            "endpoint_guards": egs[:_MAX_ENDPOINT_GUARDS],
            "endpoint_guards_truncated": max(0, len(egs) - _MAX_ENDPOINT_GUARDS),
            "write_endpoints_without_visible_guard": sorted(set(no_guard_writes))[:60],
            "unsafe_auth_decoders": unsafe_decoders[:30],
            "unverified_signature_routes": unverified_routes,
            "note": note,
        }

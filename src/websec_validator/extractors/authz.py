"""Authorization extractor — the access-control map (who can reach what).

Per your methodology this is the highest-value test. For each endpoint we decide
whether a guard protects it, using several signals:
  1. a guard pattern in the handler's own file (incl. `router.use(authenticate)`)
     or a project-specific auth helper (a `getRequest*Auth`-style getter),
  2. coverage by a Next.js middleware matcher (incl. monorepo `proxy.ts`),
  3. a GLOBAL auth middleware (`app.use(authenticate)`) — when present, routes are
     protected by default and "no visible guard" becomes a *verify* signal,
  4. ROUTER-MOUNT auth: `app.use('/prefix', authMiddleware(...), createXRouter())` —
     resolve the mounted router factory to its file and BFS the local-import graph to
     mark every composed sub-router guarded (this is what inflated the count on the
     Express monorepo: auth lives at the mount, not in the handler file),
  5. a one-hop delegated guard for thin Next route handlers (`route.ts` → `./proxy`).

File-level heuristic → results are HINTS the agent confirms. The high-signal
output is write endpoints with no visible guard that also don't look public.
"""

from __future__ import annotations

import posixpath
import re
from pathlib import Path

from .base import Extractor, RepoContext, is_client_file, is_test_file

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

# --- Router-mount auth (the dominant Express monorepo false-positive, validated on a real LLM-agent monorepo)
# Auth is frequently applied at the MOUNT, not in the handler: `app.use('/api/x', apiAuth, ...,
# createApiRouter(db))`. The handler files (routes/feature/*.ts) then carry no in-file guard, so the
# old GLOBAL_AUTH (which only matched a PATH-LESS `app.use(authMiddleware)`) saw nothing and every
# endpoint was flagged. We instead: (1) find each `.use(...)` mount, (2) decide if its arg list
# carries an auth middleware, (3) collect the router FACTORIES it mounts, (4) resolve each factory to
# its defining file, and (5) BFS the local-import graph from there to mark every route-bearing file
# composed under an authed mount as guarded — without crossing into a separately-UNAUTHed mount.
USE_CALL = re.compile(r"(\b[\w.]+)\.use\s*\(")
# Only a TOP-LEVEL app mount (`app.use`/`server.use`) without auth establishes an UNAUTHED router.
# An inner `router.use('/sub', createSubRouter())` legitimately omits auth because the parent prefix
# already applied it (Express runs parent middleware before the sub-router) — counting those as
# unauthed wrongly excluded inherited sub-routers (routes/feature/sub.ts) from coverage.
APP_RECEIVER = re.compile(r"(?:^|\.)(?:app|server|application|httpServer|expressApp|api)$", re.I)
# an auth middleware appearing in a mount arg list (a local guard const like `apiAuth`, a factory
# like `authMiddleware({...})`, or a named guard). Deliberately NOT matching `authenticatedWriteRateLimit`.
MOUNT_AUTH = re.compile(
    r"\bauthMiddleware\b|\brequireAuth\b|\brequireAdmin\b|\brequireRole\b|\brequirePermission\b|"
    r"\brequireTenantContext\b|\bensureAuth\w*|\bisAuthenticated\b|\bverifyToken\b|\bjwtMiddleware\b|"
    r"\bauthenticate\b|passport\.authenticate|\b[A-Za-z_]\w*Auth\b|\bauth\b\s*[,)]", re.I)
FACTORY_CALL = re.compile(r"\b((?:create|make|build|register|mount|init|setup|use)\w*(?:Router|Routes)|\w+Router)\s*\(")
FACTORY_DEF = re.compile(
    r"(?:export\s+)?(?:async\s+)?function\s+((?:create|make|build|register|mount|init|setup)\w*(?:Router|Routes)|\w+Router)\b"
    r"|(?:export\s+)?(?:const|let|var)\s+((?:create|make|build|register|mount|init|setup)\w*(?:Router|Routes)|\w+Router)\s*[:=]")
IMPORT_REL = re.compile(r"""(?:from\s*|require\s*\(\s*|import\s*\(\s*)['"](\.[^'"]+)['"]""")
ROUTE_MARK = re.compile(
    r"\.(?:get|post|put|patch|delete|all|options|head)\s*\(|\.route\s*\(|\brouter\b|FastifyInstance"
    r"|@(?:Get|Post|Put|Patch|Delete|Controller)\(", re.I)
# Project-specific auth helpers the in-file GUARD list misses — a getter that returns an auth state
# (e.g. Next's `getRequestSessionAuth()` → fail-closed) or a named auth-failure response. Required
# to clear the packages/web proxy handlers that ARE authenticated. Conservative: name must read as an
# auth/token/session getter or an explicit auth-failure helper, so a benign util isn't mistaken for one.
CUSTOM_GUARD = re.compile(
    r"\bget(?:Request)?\w*(?:Auth|Token|Session)\w*\s*\(|\brequire\w*(?:Auth|Token|Session)\w*\s*\("
    r"|\bensure\w*(?:Auth|Session)\w*\s*\(|\bassert\w*(?:Auth|Session)\w*\s*\("
    r"|[A-Za-z]\w*Auth(?:Failure|Required)Response\b", re.I)
_IMPORT_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")
NEXT_ROUTE = re.compile(r"(?:^|/)route\.[cm]?[jt]sx?$|(?:^|/)api/.*\.[cm]?[jt]sx?$", re.I)


def _call_args(text: str, paren_idx: int) -> str:
    """Return the substring inside the balanced parens of a call whose '(' is at paren_idx."""
    depth, out, i, n = 0, [], paren_idx, len(text)
    while i < n and len(out) < 4000:
        ch = text[i]
        if ch == "(":
            depth += 1
            if depth == 1:
                i += 1
                continue
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return "".join(out)
        if depth >= 1:
            out.append(ch)
        i += 1
    return "".join(out)


def _resolve_import(importer_rel: str, spec: str, rel_set: set) -> "str | None":
    base = posixpath.normpath(posixpath.join(posixpath.dirname(importer_rel), spec))
    cands = [base]
    # TS ESM convention: the import writes a `.js` extension but the file on disk is `.ts`/`.tsx`
    # (`import './sub/feature.js'` → `routes/sub/feature.ts`). Without this the import graph
    # dead-ends at the first hop and mount-auth coverage never reaches the sub-routers.
    m = re.match(r"(.*)\.(?:js|jsx|mjs|cjs)$", base)
    if m:
        cands += [m.group(1) + e for e in (".ts", ".tsx", ".mts", ".cts")] + [m.group(1)]
    for c in cands:
        if c in rel_set:
            return c
    for ext in _IMPORT_EXTS:
        if base + ext in rel_set:
            return base + ext
    for idx in ("/index.ts", "/index.tsx", "/index.js", "/index.jsx", "/index.mjs"):
        if base + idx in rel_set:
            return base + idx
    return None


def _mount_auth_coverage(ctx: RepoContext) -> dict:
    """Find Express router-mount auth and return the set of route files it covers.

    Returns {covered:set[rel], detected:bool, authed_factories:[...], rel_map, rel_set}.
    """
    rel_map = {ctx.rel(p): p for p in ctx.code_files}
    rel_set = set(rel_map)

    def txt(rel: str) -> str:
        p = rel_map.get(rel)
        return ctx.text(p) if p else ""

    authed_factories: set = set()
    unauthed_factories: set = set()
    for rel, p in rel_map.items():
        # Test harnesses wire `app.use(createXRouter())` WITHOUT auth to exercise a router in
        # isolation — that is test scaffolding, not the production mount, and counting it wrongly
        # marked real sub-routers (memory/marketplace-content) as unauthed. Skip test files.
        if is_test_file(rel):
            continue
        text = ctx.text(p)
        if ".use(" not in text:
            continue
        for m in USE_CALL.finditer(text):
            args = _call_args(text, m.end() - 1)
            facs = set(FACTORY_CALL.findall(args))
            if not facs:
                continue
            if MOUNT_AUTH.search(args):
                authed_factories.update(facs)
            elif APP_RECEIVER.search(m.group(1)):
                unauthed_factories.update(facs)
            # else: inner `router.use(...)` with no auth → inherits the parent mount's auth; ignore
    unauthed_factories -= authed_factories          # an authed mount anywhere wins

    factory_file: dict = {}                          # factory name -> defining file
    for rel, p in rel_map.items():
        if is_test_file(rel):
            continue
        text = ctx.text(p)
        if "Router" not in text and "Routes" not in text:
            continue
        for a, b in FACTORY_DEF.findall(text):
            nm = a or b
            if nm and nm not in factory_file:
                factory_file[nm] = rel

    authed_files = {factory_file[n] for n in authed_factories if n in factory_file}
    unauthed_files = {factory_file[n] for n in unauthed_factories if n in factory_file} - authed_files

    # BFS the local-import graph from each authed factory file; mark every route-bearing file
    # composed under it as covered, but never traverse INTO a separately-unauthed mount's file.
    covered: set = set()
    visited: set = set(authed_files)
    frontier: list = list(authed_files)
    # Cap bounds the walk to the repo's own files (the import graph is finite); a big assembler file
    # can have 100+ relative imports, so the per-file cap must be generous or sub-routers past it
    # (e.g. routes/feature/sub.ts) are silently dropped.
    while frontier and len(visited) <= 6000:
        cur = frontier.pop()
        t = txt(cur)
        if not t:
            continue
        if cur in authed_files or ROUTE_MARK.search(t):
            covered.add(cur)
        for spec in IMPORT_REL.findall(t)[:400]:
            tgt = _resolve_import(cur, spec, rel_set)
            if (tgt and tgt not in visited and tgt not in unauthed_files
                    and not is_test_file(tgt) and not is_client_file(tgt)):
                visited.add(tgt)
                frontier.append(tgt)

    return {"covered": covered, "detected": bool(authed_files),
            "authed_factories": sorted(authed_factories)[:40],
            "rel_map": rel_map, "rel_set": rel_set}


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

        # Router-mount auth coverage (Express `app.use('/x', authMiddleware, createXRouter())`).
        mount = _mount_auth_coverage(ctx)
        mount_covered, mount_detected = mount["covered"], mount["detected"]
        rel_map, rel_set = mount["rel_map"], mount["rel_set"]

        # A THIN Next.js route handler (route.ts / api/*) can delegate its auth one hop to a relative
        # module (e.g. `route.ts` → `./proxy.ts` where getRequestSessionAuth lives). Follow that one
        # hop — bounded to short handler files so the FN risk (marking a real gap as guarded) stays low.
        def _imported_guard(rel: str, text: str) -> bool:
            if not rel or not NEXT_ROUTE.search(rel) or len(text.splitlines()) > 80:
                return False
            for spec in IMPORT_REL.findall(text)[:20]:
                tgt = _resolve_import(rel, spec, rel_set)
                if tgt:
                    t2 = ctx.text(rel_map[tgt]) if tgt in rel_map else ""
                    if t2 and (GUARD.search(t2) or CUSTOM_GUARD.search(t2)):
                        return True
            return False

        # global auth = an Express path-less auth middleware OR a Next auth middleware/proxy OR a
        # detected router-mount-auth pattern (routes are protected centrally, at the mount).
        global_auth = (mw_auth or mount_detected
                       or any(GLOBAL_AUTH.search(t) for _p, _r, t in ctx.iter_code()))
        roles: set = set(mw.get("role_checks", []))
        protected = no_guard = unknown = 0
        no_guard_writes, egs = [], []

        for e in endpoints:
            cp = e.get("code_path", "")
            text = ctx.text(Path(cp)) if cp else ""
            _collect_roles(text, roles)
            relcp = ctx.rel(Path(cp)) if cp else ""
            # a matcher only counts as a guard when the middleware actually does auth — a
            # non-auth middleware.ts (i18n/headers) must NOT mark routes protected. Mount coverage,
            # the project's custom auth helper, and a one-hop delegated guard also count.
            guarded = (bool(text and (GUARD.search(text) or CUSTOM_GUARD.search(text)))
                       or (relcp and relcp in mount_covered)
                       or (mw_auth and _matcher_covers(e.get("path", ""), mw.get("matchers", [])))
                       or _imported_guard(relcp, text))
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
            if mount_detected:
                where = f"router-mount auth (`app.use('/prefix', <auth>, createXRouter())`) on {len(mount_covered)} route file(s)"
            elif mw_auth:
                where = f"`{mw['file']}` (matcher {mw.get('matchers') or '—'})"
            else:
                where = "`app.use(<auth>)`"
            note = (f"A GLOBAL/mount auth pattern ({where}) was detected — most routes are protected centrally, "
                    "not in each handler file. Endpoints under an authed mount are reported as guarded. "
                    "Any list below is write endpoints with NO guard via the handler file, an authed mount, the "
                    "Next matcher, or a one-hop delegated guard; verify each is either covered or an intentional "
                    "public exemption (e.g. a signed-token download) — don't assume they're vulnerable.")
        else:
            note = ("No global/mount auth middleware detected. Write endpoints with no visible guard are "
                    "high-signal missing-authz leads — verify each.")

        return {
            "global_auth_middleware": global_auth,
            "mount_auth_detected": mount_detected,
            "mount_authed_factories": mount["authed_factories"],
            "mount_covered_files": len(mount_covered),
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

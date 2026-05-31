"""Authorization extractor — the access-control map (who can reach what).

Per your methodology this is the single highest-value test: it catches broken
access control that scanners miss. For each discovered endpoint we determine
whether a guard protects it (per-file guard patterns + Next.js middleware
matcher coverage) and surface the **unprotected write endpoints** — the most
direct "missing authz" lead — plus the roles the codebase actually uses.

Deterministic and file-level (not full interprocedural data-flow), so results
are HINTS the agent confirms — but the unprotected-write list is high-signal.
"""

from __future__ import annotations

import re
from pathlib import Path

from .base import Extractor, RepoContext

WRITE_VERBS = {"POST", "PUT", "PATCH", "DELETE"}

# broad cross-framework guard signature (Express/Next/Nest/Flask/FastAPI/Django)
GUARD = re.compile(
    r"requireAuth|requirePermission|requireRole|requireGroupAccess|isAuthenticated|"
    r"@login_required|@jwt_required|@permission_required|@roles_required|ensureAuth|"
    r"withAuth|getServerSession|getToken\s*\(|verifyToken|authMiddleware|@UseGuards|"
    r"@Roles\b|Depends\s*\(\s*(?:get_current_user|oauth2_scheme|require_)|Security\s*\(|"
    r"PermissionRequired|LoginRequired|passport\.authenticate|auth\(\)", re.I)

# role literals: @Roles('admin'), allowedRoles=['admin','editor'], role === 'admin', has_role('admin')
ROLE = re.compile(
    r"@Roles\s*\(([^)]*)\)|allowedRoles\s*=\s*\[([^\]]*)\]|"
    r"\b(?:role|roles)\b\s*[!=]==?\s*['\"]([\w:.-]+)['\"]|"
    r"has_?[Rr]ole\s*\(\s*['\"]([\w:.-]+)['\"]|"
    r"authorizeRoles\s*\(([^)]*)\)|permission_required\s*\(\s*['\"]([\w:.-]+)['\"]")


def _parse_next_middleware(ctx: RepoContext) -> dict:
    """Extract the Next.js middleware matcher patterns + any role checks."""
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
    """Best-effort: does a Next matcher gate this path? (prefix heuristic, a hint)."""
    for m in matchers:
        base = m.split(":")[0].split("(")[0].rstrip("/*")
        if base and path.startswith(base):
            return True
        if m.startswith("/(") or m == "/:path*":   # broad catch-all
            return True
    return False


class AuthzExtractor(Extractor):
    name = "authz"
    category = "authz"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        endpoints = (facts.get("routes") or {}).get("endpoints", [])
        mw = _parse_next_middleware(ctx)

        roles: set = set(mw.get("role_checks", []))
        protected = unprotected = unknown = 0
        unprotected_writes = []

        for e in endpoints:
            cp = e.get("code_path", "")
            text = ctx.text(Path(cp)) if cp else ""
            guarded = bool(text and GUARD.search(text))
            covered = _matcher_covers(e.get("path", ""), mw.get("matchers", []))
            for grp in ROLE.findall(text or ""):
                for m in grp:
                    if m and "," not in m:
                        roles.add(m.strip().strip("'\""))
                    elif m:
                        roles.update(x.strip().strip("'\" ") for x in m.split(",") if x.strip())

            if guarded or covered:
                protected += 1
            elif not text:
                unknown += 1
            else:
                unprotected += 1
                if e.get("method") in WRITE_VERBS:
                    unprotected_writes.append(f"{e['method']} {e['path']}  ({ctx.rel(Path(cp)) if cp else '?'})")

        return {
            "next_middleware": mw,
            "roles_detected": sorted(r for r in roles if r and len(r) < 40),
            "protection_summary": {"protected": protected, "unprotected": unprotected, "unknown": unknown},
            "unprotected_write_endpoints": sorted(set(unprotected_writes)),
            "note": "⚠ 'unprotected' = no guard pattern found in the handler file AND not covered by a "
                    "Next.js middleware matcher. File-level heuristic — CONFIRM each before reporting, but "
                    "unprotected write endpoints are the highest-signal missing-authz leads.",
        }

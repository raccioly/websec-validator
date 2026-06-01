"""Tenant-boundary extractor — the multi-tenancy key candidates.

The single most important and easiest-to-get-wrong fact for BOLA testing. The
tool reports candidates by frequency; the agent confirms THE one with the human.
"""

from __future__ import annotations

from .base import Extractor, RepoContext

TENANT_KEYS = ["groupId", "group_id", "orgId", "org_id", "organizationId",
               "tenantId", "tenant_id", "workspaceId", "workspace_id",
               "accountId", "account_id", "companyId", "company_id",
               "teamId", "team_id", "projectId", "project_id"]


class TenantExtractor(Extractor):
    name = "tenant"
    category = "authz"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        route_count = len((facts.get("routes") or {}).get("endpoints", []))
        hits: dict = {}
        files: dict = {}
        for _p, rel, text in ctx.iter_code():
            for key in TENANT_KEYS:
                c = text.count(key)
                if c:
                    hits[key] = hits.get(key, 0) + c
                    bucket = files.setdefault(key, [])
                    if rel not in bucket and len(bucket) < 5:
                        bucket.append(rel)
        ranked = sorted(hits.items(), key=lambda kv: -kv[1])
        return {
            "candidates": [{"key": k, "occurrences": n, "files": files.get(k, [])} for k, n in ranked[:6]],
            "multi_tenant_likely": bool(route_count > 0 and ranked and ranked[0][1] >= 3),
            "route_count": route_count,
            "note": ("AGENT: confirm with the human which key (if any) is THE tenant boundary. "
                     "If single-tenant, skip the cross-tenant BOLA probes."
                     + ("  ⚠ No HTTP routes detected — a tenant key here may be a string in "
                        "library/scanner code, not a real boundary." if route_count == 0 else "")),
        }

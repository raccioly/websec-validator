"""Tenant-boundary extractor — the multi-tenancy key candidates.

The single most important and easiest-to-get-wrong fact for BOLA testing. The
tool reports candidates by frequency; the agent confirms THE one with the human.
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext, is_test_file

TENANT_KEYS = ["groupId", "group_id", "orgId", "org_id", "organizationId",
               "tenantId", "tenant_id", "workspaceId", "workspace_id",
               "accountId", "account_id", "companyId", "company_id",
               "teamId", "team_id", "projectId", "project_id",
               # per-license / per-device ownership keys — the isolation boundary for licensed and
               # browser-extension apps (Gumroad/Stripe/Paddle). license_hash keying a per-user row
               # (e.g. alert_configs) IS the BOLA boundary here, even though it isn't classic SaaS tenancy.
               "licenseHash", "license_hash", "licenseKey", "license_key",
               "visitorId", "visitor_id", "deviceId", "device_id",
               "subscriptionId", "subscription_id", "customerId", "customer_id"]

# Substring counting is deliberate: composites such as `current_tenant_id`, `session_org_id` and
# plurals such as `groupIds` (a membership list compared against the tenant key) ARE the boundary,
# and a `\b...\b` match would silently drop them. The only suppressed continuation is an
# `Id`/`_id` key running on into "identifier"/"identity" (`organizationIdentifier`,
# `tenant_identity`) — a different word that merely shares the prefix (#191).
_NOT_IDENTITY_WORD = r"(?!entif|entit)"
_TENANT_PATTERNS = {key: re.compile(re.escape(key) + _NOT_IDENTITY_WORD) for key in TENANT_KEYS}


class TenantExtractor(Extractor):
    name = "tenant"
    category = "authz"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        route_count = len((facts.get("routes") or {}).get("endpoints", []))
        hits: dict = {}
        files: dict = {}
        for _p, rel, text in ctx.iter_code():
            # a `groupId` in a test fixture is corpus data, not the app's isolation boundary
            # (DocGuard field report: fixture Express apps produced a phantom tenant key)
            if not getattr(ctx, "include_fixtures", False) and is_test_file(rel):
                continue
            for key, pattern in _TENANT_PATTERNS.items():
                c = len(pattern.findall(text)) if key in text else 0
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

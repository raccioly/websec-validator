"""GraphQL surface extractor.

GraphQL is its own attack surface (introspection schema-dump, alias/depth DoS,
GET-method mutations). Noir collapses a GraphQL server to one `POST /graphql`
endpoint, so we add the detail: is introspection on, is the playground exposed,
is there any depth/complexity limiting. Only emits when GraphQL is present.
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext

SCHEMA_CODE = re.compile(
    r"makeExecutableSchema|buildSchema|new ApolloServer|createYoga|type-graphql|"
    r"@Resolver|@ObjectType|gql`|type\s+Query\b|type\s+Mutation\b|strawberry\.|"
    r"graphene\.|ariadne|mercurius", re.I)
INTROSPECTION_ON = re.compile(r"introspection\s*:\s*true")
INTROSPECTION_OFF = re.compile(r"introspection\s*:\s*false|NoSchemaIntrospection|NoIntrospection")
PLAYGROUND = re.compile(r"playground\s*:\s*true|graphiql\s*:\s*true|LandingPageGraphQLPlayground|LandingPageLocalDefault")
LIMITING = re.compile(r"graphql-depth-limit|depthLimit|costAnalysis|graphql-cost-analysis|"
                      r"createComplexityLimitRule|query-complexity|graphql-armor")

# --- AppSync / managed GraphQL (PTREQ0013000 #2 introspection-via-WAF-bypass, #5 sub-authz) ---
APPSYNC_MARK = re.compile(r"appsync\.GraphqlApi|CfnGraphQLApi|Definition\.fromSchema|aws-appsync|aws_appsync", re.I)
AWS_AUTH_DIRECTIVE = re.compile(r"@aws_(?:api_key|iam|oidc|cognito_user_pools|auth|subscribe)")
# A Subscription field that carries a tenant-scoping arg MUST be authz-bound in its resolver, or any
# authenticated user can subscribe to any tenant's stream (the cross-group BOLA from the report).
SUB_BLOCK = re.compile(r"type\s+Subscription\b[^{]*\{([^}]*)\}", re.S)
TENANT_ARG = re.compile(r"\b(\w+)\s*\(([^)]*\b(?:groupId|group_id|orgId|org_id|tenantId|tenant_id"
                        r"|workspaceId|accountId|conversationId|channelId)\b[^)]*)\)")
# Identity-binding signals in a VTL resolver — the field is tied to the CALLER, not a free arg.
VTL_AUTHZ = re.compile(r"\$ctx(?:tx)?\.identity|\$context\.identity|identity\.(?:sub|username|claims|resolverContext)"
                       r"|util\.unauthorized|\bgroupIds?\b[\s\S]{0,80}?\bcontains\b|#if\s*\(\s*!?\s*\$ctx\.identity")


class GraphQLExtractor(Extractor):
    name = "graphql"
    category = "surface"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        frameworks = set((facts.get("stack") or {}).get("frameworks", []))
        schema_files = [ctx.rel(p) for p in (ctx.glob("**/*.graphql", 60) + ctx.glob("**/*.gql", 60))]
        endpoints = [e for e in (facts.get("routes") or {}).get("endpoints", [])
                     if "graphql" in e.get("path", "").lower()]

        introspection, playground, limiting, code_hit = "unknown", False, False, False
        appsync, aws_directives = False, False
        schema_texts = []          # (rel, text) for SDL files — parsed for Subscription authz
        for _p, rel, text in ctx.iter_code():
            if APPSYNC_MARK.search(text):
                appsync = True
            if rel.endswith((".graphql", ".gql")):
                schema_texts.append((rel, text))
                if AWS_AUTH_DIRECTIVE.search(text):
                    aws_directives = True
            if SCHEMA_CODE.search(text):
                code_hit = True
                if INTROSPECTION_ON.search(text):
                    introspection = "enabled"
                elif INTROSPECTION_OFF.search(text) and introspection != "enabled":
                    introspection = "disabled"
                if PLAYGROUND.search(text):
                    playground = True
                if LIMITING.search(text):
                    limiting = True

        managed = appsync or aws_directives
        if not ({"graphql", "apollo-graphql"} & frameworks) and not schema_files and not endpoints \
                and not managed and not code_hit:
            return {"present": False}

        findings = []
        sub_authz = []
        if managed:
            # AppSync exposes introspection and it is NOT disablable at the API layer (no Apollo-style
            # `introspection:false`). The report's #2 proved the WAF that "blocks" it is bypassable.
            findings.append({"severity": "MEDIUM", "issue": "AppSync GraphQL introspection reachable",
                             "attack_class": "graphql",
                             "detail": "AppSync exposes schema introspection; it can't be disabled at the API layer. "
                                       "If a WAF blocks the keyword, that string-match is bypassable via Unicode-escape "
                                       "/ junk-byte padding (PTREQ0013000 #2). Enforce field-level @aws_* auth + run the "
                                       "appsync-introspection probe (it attempts the bypass) — don't rely on the WAF."})
            sub_authz = self._subscription_authz(ctx, schema_texts, findings)
        else:
            if introspection in ("enabled", "unknown"):
                findings.append({"severity": "HIGH" if introspection == "enabled" else "MEDIUM",
                                 "attack_class": "graphql",
                                 "issue": f"introspection {'ENABLED' if introspection == 'enabled' else 'not explicitly disabled'}",
                                 "detail": "schema-dump exposure — disable in prod / add NoSchemaIntrospection"})
            if playground:
                findings.append({"severity": "MEDIUM", "issue": "GraphQL playground/landing page enabled",
                                 "attack_class": "graphql", "detail": "disable in production"})
            if not limiting:
                findings.append({"severity": "MEDIUM", "issue": "no query depth/complexity limiting detected",
                                 "attack_class": "graphql",
                                 "detail": "alias/deep-query DoS — add depth+cost limits (e.g. graphql-armor)"})

        return {"present": True,
                "appsync": managed,
                "endpoints": [f"{e['method']} {e['path']}" for e in endpoints]
                             or (["AppSync GraphQL API (HTTP + realtime WebSocket)"] if managed
                                 else ["(server detected; endpoint not routed by Noir)"]),
                "schema_files": schema_files[:20],
                "introspection": "appsync-reachable" if managed else introspection,
                "playground_enabled": playground, "query_limiting_detected": limiting,
                "subscription_authz": sub_authz,
                "findings": findings,
                "maps_to_probe": ("appsync-introspection (attempts the Unicode-escape WAF bypass) + appsync-cswsh "
                                  "(WebSocket Origin) + appsync-subscription-bola" if managed
                                  else "graphql-cop (run externally against the /graphql endpoint)")}

    def _subscription_authz(self, ctx: RepoContext, schema_texts: list, findings: list) -> list:
        """For each Subscription field carrying a tenant-scoping arg, check a co-located VTL resolver
        binds that arg to the caller's identity. Missing/passthrough VTL → cross-group BOLA: any
        authenticated user subscribes to any tenant's stream (PTREQ0013000 #5). Verified shape:
        the fixed (identity-bound) VTL PASSES; the pre-fix passthrough FIRES."""
        vtl_corpus = {ctx.rel(p): ctx.text(p) for p in ctx.glob("**/*.vtl", 300)}
        results = []
        for _rel, text in schema_texts:
            mblock = SUB_BLOCK.search(text)
            if not mblock:
                continue
            for fm in TENANT_ARG.finditer(mblock.group(1)):
                field, args = fm.group(1), fm.group(2).strip()
                cand = [t for r, t in vtl_corpus.items() if field.lower() in r.lower() or field in t]
                if not cand:
                    sev, verdict = "MEDIUM", "no-resolver-visible"
                    detail = (f"Subscription `{field}({args})` is tenant-scoped but no VTL resolver was found to "
                              f"inspect — VERIFY the server (e.g. a direct-Lambda resolver) binds the tenant arg to "
                              f"the caller's identity. If unbound, any user can subscribe to any tenant (#5).")
                elif any(VTL_AUTHZ.search(t) for t in cand):
                    sev, verdict = "OK", "authz-bound"
                    detail = ""
                else:
                    sev, verdict = "CRITICAL", "passthrough-no-authz"
                    detail = (f"Subscription `{field}({args})` accepts a tenant arg but its VTL resolver does NOT bind "
                              f"it to the caller's identity ($ctx.identity / groupIds.contains / util.unauthorized) — "
                              f"any authenticated user can subscribe to ANY tenant's stream (cross-group BOLA, "
                              f"PTREQ0013000 #5).")
                results.append({"field": field, "verdict": verdict, "severity": sev})
                if sev != "OK":
                    findings.append({"severity": sev, "attack_class": "bola",
                                     "issue": f"broken subscription authorization: {field}", "detail": detail})
        return results

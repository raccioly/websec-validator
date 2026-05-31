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


class GraphQLExtractor(Extractor):
    name = "graphql"
    category = "surface"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        frameworks = set((facts.get("stack") or {}).get("frameworks", []))
        schema_files = [ctx.rel(p) for p in (ctx.glob("**/*.graphql", 60) + ctx.glob("**/*.gql", 60))]
        endpoints = [e for e in (facts.get("routes") or {}).get("endpoints", [])
                     if "graphql" in e.get("path", "").lower()]

        if not ({"graphql", "apollo-graphql"} & frameworks) and not schema_files and not endpoints:
            return {"present": False}

        introspection, playground, limiting, code_hit = "unknown", False, False, False
        for _p, _rel, text in ctx.iter_code():
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

        if not (code_hit or schema_files or endpoints):
            return {"present": False}

        findings = []
        if introspection in ("enabled", "unknown"):
            findings.append({"severity": "HIGH" if introspection == "enabled" else "MEDIUM",
                             "issue": f"introspection {'ENABLED' if introspection == 'enabled' else 'not explicitly disabled'}",
                             "detail": "schema-dump exposure — disable in prod / add NoSchemaIntrospection"})
        if playground:
            findings.append({"severity": "MEDIUM", "issue": "GraphQL playground/landing page enabled",
                             "detail": "disable in production"})
        if not limiting:
            findings.append({"severity": "MEDIUM", "issue": "no query depth/complexity limiting detected",
                             "detail": "alias/deep-query DoS — add depth+cost limits (e.g. graphql-armor)"})

        return {"present": True,
                "endpoints": [f"{e['method']} {e['path']}" for e in endpoints] or ["(server detected; endpoint not routed by Noir)"],
                "schema_files": schema_files[:20], "introspection": introspection,
                "playground_enabled": playground, "query_limiting_detected": limiting,
                "findings": findings, "maps_to_probe": "graphql-cop (run externally against the /graphql endpoint)"}

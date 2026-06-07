"""Client-side exposure extractor — secrets that leak into the browser bundle.

The Next.js/Vite footgun: any `NEXT_PUBLIC_*` / `VITE_*` var is inlined into the
client bundle, and a server-only secret referenced from a client component ships
to every visitor. Cheap static scan, high signal.
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext

PUBLIC_ENV = re.compile(r"\b(NEXT_PUBLIC_\w+|VITE_\w+|REACT_APP_\w+|GATSBY_\w+|EXPO_PUBLIC_\w+|PUBLIC_\w{2,})\b")
SECRETISH = re.compile(r"SECRET|PRIVATE|TOKEN|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|CLIENT_SECRET|CREDENTIAL", re.I)
SERVER_SECRET = re.compile(r"process\.env\.([A-Z0-9_]*(?:SECRET|PRIVATE|TOKEN|PASSWORD|API_?KEY|ACCESS_?KEY)[A-Z0-9_]*)")

# VALUE-aware leak detection — hardens the name-based scan above so it survives a benign rename
# (the PTREQ0013000 #3 gap: a real key carried in a non-secret-named public var slips the name scan).
# We match distinctive secret SHAPES, not var names. AppSync's `da2-` key has NO scanner rule at all,
# so we always flag it; the generic shapes (which trivy/gitleaks already catch) are only flagged when
# the file is client-reachable, to add the ships-to-browser angle without duplicating those scanners.
SECRET_SHAPES = [
    (re.compile(r"\bda2-[a-z0-9]{26}\b"), "AWS AppSync API key (da2-…)", True),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id (AKIA)", False),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key (AIza…)", False),
    (re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"), "Stripe live secret key (sk_live_…)", False),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"), "JWT (eyJ…)", False),
]
# CDK build-time injection: a CloudFormation output / SSM param / Secret wired INTO a public build
# var — e.g. CodeBuild `envFromCfnOutputs: { VITE_APPSYNC_API_KEY: appsyncApiKeyOutput }`. Invisible
# to every secret scanner because the value isn't in source; it's injected at build time (the exact
# mechanism that shipped the AppSync key to the browser in PTREQ0013000 #3).
CFN_TO_PUBLIC = re.compile(
    r"(?:envFromCfnOutputs|buildEnvironment|environmentVariables|partialBuildSpec)"
    r"[\s\S]{0,400}?((?:NEXT_PUBLIC_|VITE_|REACT_APP_|GATSBY_|EXPO_PUBLIC_)\w*)\s*[:=]\s*"
    r"(\w+Output\b|[\w.]+\.value\b|CfnOutput|StringParameter|(?:Fn\.)?importValue|Secret\b)", re.I)


class ClientExposureExtractor(Extractor):
    name = "client_exposure"
    category = "exposure"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        public_vars: set = set()
        public_secret_leaks = []      # public-prefixed AND secret-named → ships to client
        server_secret_in_client = []  # server secret referenced from a 'use client' file
        public_value_leaks = []       # secret-SHAPE literal in client-reachable code (rename-proof, #3)
        public_var_from_cfn = []      # CDK output/secret injected into a public build var (#3)

        for _p, rel, text in ctx.iter_code():
            for v in PUBLIC_ENV.findall(text):
                public_vars.add(v)
                if SECRETISH.search(v):
                    public_secret_leaks.append(f"{v}  ({rel})")
            if "use client" in text[:200] or "'use client'" in text[:200] or '"use client"' in text[:200]:
                for s in SERVER_SECRET.findall(text):
                    server_secret_in_client.append(f"{s}  ({rel})")
            client_reachable = bool(PUBLIC_ENV.search(text)) or "use client" in text[:400]
            for rx, label, always in SECRET_SHAPES:
                if (always or client_reachable) and rx.search(text):
                    public_value_leaks.append(f"{label}  ({rel})")
            for m in CFN_TO_PUBLIC.finditer(text):
                public_var_from_cfn.append(f"{m.group(1)} ← {m.group(2)}  ({rel})")

        nextcfg = (ctx.manifest("next.config.js") + ctx.manifest("next.config.mjs")
                   + ctx.manifest("next.config.ts"))
        sourcemaps = "productionBrowserSourceMaps: true" in nextcfg

        return {
            "public_env_vars": sorted(public_vars)[:40],
            "public_secret_leaks": sorted(set(public_secret_leaks)),     # HIGH if non-empty
            "server_secret_in_client_component": sorted(set(server_secret_in_client)),  # HIGH if non-empty
            "public_secret_value_leaks": sorted(set(public_value_leaks)),   # HIGH — value-detected, rename-proof
            "public_var_from_cfn_output": sorted(set(public_var_from_cfn)),  # HIGH — CDK build-injected to client
            "production_source_maps": sourcemaps,
            "note": "public_secret_leaks / server_secret_in_client_component / public_secret_value_leaks / "
                    "public_var_from_cfn_output ship secrets to the browser — treat as HIGH and confirm. "
                    "Value/CFN-injection detection survives a benign var rename (the #3 gap). Plain "
                    "NEXT_PUBLIC_* without a secret name/value/CFN-wire are usually fine.",
        }

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


class ClientExposureExtractor(Extractor):
    name = "client_exposure"
    category = "exposure"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        public_vars: set = set()
        public_secret_leaks = []      # public-prefixed AND secret-named → ships to client
        server_secret_in_client = []  # server secret referenced from a 'use client' file

        for _p, rel, text in ctx.iter_code():
            for v in PUBLIC_ENV.findall(text):
                public_vars.add(v)
                if SECRETISH.search(v):
                    public_secret_leaks.append(f"{v}  ({rel})")
            if "use client" in text[:200] or "'use client'" in text[:200] or '"use client"' in text[:200]:
                for s in SERVER_SECRET.findall(text):
                    server_secret_in_client.append(f"{s}  ({rel})")

        nextcfg = (ctx.manifest("next.config.js") + ctx.manifest("next.config.mjs")
                   + ctx.manifest("next.config.ts"))
        sourcemaps = "productionBrowserSourceMaps: true" in nextcfg

        return {
            "public_env_vars": sorted(public_vars)[:40],
            "public_secret_leaks": sorted(set(public_secret_leaks)),     # HIGH if non-empty
            "server_secret_in_client_component": sorted(set(server_secret_in_client)),  # HIGH if non-empty
            "production_source_maps": sourcemaps,
            "note": "public_secret_leaks and server_secret_in_client_component ship secrets to the browser — "
                    "treat as HIGH and confirm. Plain NEXT_PUBLIC_* without secret-ish names are usually fine.",
        }

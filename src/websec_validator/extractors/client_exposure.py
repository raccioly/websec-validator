"""Client-side exposure extractor — secrets that leak into the browser bundle.

The Next.js/Vite footgun: any `NEXT_PUBLIC_*` / `VITE_*` var is inlined into the
client bundle, and a server-only secret referenced from a client component ships
to every visitor. Cheap static scan, high signal.
"""

from __future__ import annotations

import base64
import json
import posixpath
import re

from .base import Extractor, RepoContext, is_test_file

# Browser-inlined env prefixes. `PUBLIC_*` is SvelteKit-only, so it is gated to svelte packages
# (handled below) — without that gate it matched a non-frontend Fastify backend service's
# `PUBLIC_*_SESSION_SECRET` (a real server secret correctly kept server-side) → false positive.
PUBLIC_ENV = re.compile(r"\b(NEXT_PUBLIC_\w+|VITE_\w+|REACT_APP_\w+|GATSBY_\w+|EXPO_PUBLIC_\w+)\b")
SVELTE_PUBLIC = re.compile(r"\b(PUBLIC_\w{2,})\b")
SECRETISH = re.compile(r"SECRET|PRIVATE|TOKEN|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|CLIENT_SECRET|CREDENTIAL", re.I)
# Tokens DESIGNED to ship to the browser (write-only analytics/error/feature-flag ingest keys). They
# match SECRETISH via "TOKEN"/"KEY" but are intended-public — report at INFO, never HIGH.
ANALYTICS_PUBLIC = re.compile(
    r"POSTHOG|USERTOUR|AMPLITUDE|MIXPANEL|SEGMENT|HEAP|HOTJAR|FULLSTORY|INTERCOM|"
    r"GOOGLE_ANALYTICS|\bGA_|\bGTM|GADS|SENTRY_DSN|DATADOG_(?:CLIENT|RUM|APPLICATION)|"
    r"LAUNCHDARKLY_CLIENT|STATSIG_CLIENT|_PUBLISHABLE_KEY|STRIPE_PUBLISHABLE", re.I)
# package.json that declares a frontend bundler ⇒ NEXT_PUBLIC_/VITE_/... names there really do ship.
FRONTEND_DEPS = re.compile(r'"(?:next|vite|react|react-dom|@sveltejs/kit|svelte|@angular/core|gatsby|nuxt|expo|@remix-run/\w+|astro|solid-js|@builder\.io/qwik)"')
SVELTE_DEPS = re.compile(r'"(?:svelte|@sveltejs/kit)"')
SERVER_SECRET = re.compile(r"process\.env\.([A-Z0-9_]*(?:SECRET|PRIVATE|TOKEN|PASSWORD|API_?KEY|ACCESS_?KEY)[A-Z0-9_]*)")

# VALUE-aware leak detection — hardens the name-based scan above so it survives a benign rename
# (the REF-PENTEST #3 gap: a real key carried in a non-secret-named public var slips the name scan).
# We match distinctive secret SHAPES, not var names — CLOUD-AGNOSTIC by design (AWS + Azure + GCP +
# generic), so the same value-leak detector works on a Next.js-on-Vercel, an Azure SWA, or a GCP
# Firebase app alike. AppSync's `da2-` key has NO scanner rule at all, so we always flag it; the
# generic shapes (which trivy/gitleaks already catch) are only flagged when the file is
# client-reachable, to add the ships-to-browser angle without duplicating those scanners.
SECRET_SHAPES = [
    # AWS
    (re.compile(r"\bda2-[a-z0-9]{26}\b"), "AWS AppSync API key (da2-…)", True),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id (AKIA)", False),
    # GCP / Google
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "Google API key (AIza…)", False),
    (re.compile(r"""["']type["']\s*:\s*["']service_account["']"""), "GCP service-account credential JSON", False),
    # Azure
    (re.compile(r"AccountKey=[A-Za-z0-9+/]{86}=="), "Azure Storage account key (AccountKey=…)", False),
    (re.compile(r"DefaultEndpointsProtocol=https;AccountName="), "Azure Storage connection string", False),
    (re.compile(r"[?&]sig=[A-Za-z0-9%/+]{43,}&se="), "Azure SAS token (sig=…&se=…)", False),
    # cloud-neutral
    (re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "Private-key PEM block (TLS / SSH / SA key)", False),
    (re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"), "Stripe live secret key (sk_live_…)", False),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"), "JWT (eyJ…)", False),
]
# --- Supabase (and Supabase-style) keys carry their trust tier IN the key. The **anon / publishable**
# key is DESIGNED to ship to the browser and is protected by Row-Level Security → intended-public (the
# generic-secret scanners flag it as a "JWT" false positive). The **service_role** key bypasses RLS and
# must NEVER be exposed → a real leak. We decode the JWT `role` claim (or read the `sb_publishable_` /
# `sb_secret_` prefix of the newer key format) to tell them apart — by VALUE, provider-agnostic. ---
_JWT_LITERAL = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}")
_SB_PUBLISHABLE = re.compile(r"\bsb_publishable_[A-Za-z0-9]{10,}\b")
_SB_SECRET = re.compile(r"\bsb_secret_[A-Za-z0-9]{10,}\b")


def _jwt_payload(tok: str) -> dict | None:
    try:
        seg = tok.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        d = json.loads(base64.urlsafe_b64decode(seg))
        return d if isinstance(d, dict) else None
    except Exception:
        return None


def _supabase_key_tiers(text: str) -> tuple[bool, bool]:
    """(anon_present, service_role_present) for Supabase-style keys in `text`. anon/publishable ⇒
    intended-public; service_role ⇒ must never ship. Only a JWT whose payload is clearly a Supabase
    key (role∈{anon,service_role} and iss mentions supabase or a project `ref` is present) counts —
    an arbitrary third-party JWT is left to the generic value-leak path."""
    anon = service = False
    for tok in _JWT_LITERAL.findall(text):
        d = _jwt_payload(tok)
        if not d:
            continue
        role = str(d.get("role", "")).lower()
        if role in ("anon", "service_role") and ("supabase" in str(d.get("iss", "")).lower() or d.get("ref")):
            anon = anon or role == "anon"
            service = service or role == "service_role"
    if _SB_PUBLISHABLE.search(text):
        anon = True
    if _SB_SECRET.search(text):
        service = True
    return anon, service


# CDK build-time injection: a CloudFormation output / SSM param / Secret wired INTO a public build
# var — e.g. CodeBuild `envFromCfnOutputs: { VITE_APPSYNC_API_KEY: appsyncApiKeyOutput }`. Invisible
# to every secret scanner because the value isn't in source; it's injected at build time (the exact
# mechanism that shipped the AppSync key to the browser in REF-PENTEST #3).
CFN_TO_PUBLIC = re.compile(
    r"(?:envFromCfnOutputs|buildEnvironment|environmentVariables|partialBuildSpec)"
    r"[\s\S]{0,400}?((?:NEXT_PUBLIC_|VITE_|REACT_APP_|GATSBY_|EXPO_PUBLIC_)\w*)\s*[:=]\s*"
    r"(\w+Output\b|[\w.]+\.value\b|CfnOutput|StringParameter|(?:Fn\.)?importValue|Secret\b)", re.I)


class ClientExposureExtractor(Extractor):
    name = "client_exposure"
    category = "exposure"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        # Per-package frontend evidence: a `NEXT_PUBLIC_*` NAME only ships to a browser if its owning
        # package actually has a frontend bundler. In a monorepo the backend services reference these
        # names as server-side fallback keys — flagging them is the dominant client-exposure FP.
        pkg_frontend: dict = {}
        pkg_svelte: dict = {}
        for pj in ctx.glob("**/package.json"):
            d = posixpath.dirname(ctx.rel(pj).replace("\\", "/"))
            t = ctx.text(pj)
            pkg_frontend[d] = bool(FRONTEND_DEPS.search(t))
            pkg_svelte[d] = bool(SVELTE_DEPS.search(t))

        def _pkg_flag(rel: str, table: dict, default: bool) -> bool:
            parts = rel.replace("\\", "/").split("/")
            for i in range(len(parts) - 1, -1, -1):
                d = "/".join(parts[:i])
                if d in table:
                    return table[d]
            return default

        public_vars: set = set()
        public_secret_leaks = []      # public-prefixed AND secret-named, in a FRONTEND package → ships
        intended_public = []          # analytics/telemetry ingest tokens — INFO, designed to ship
        server_secret_in_client = []  # server secret referenced from a 'use client' file
        public_value_leaks = []       # secret-SHAPE literal in client-reachable code (rename-proof, #3)
        public_var_from_cfn = []      # CDK output/secret injected into a public build var (#3)
        supabase_anon = []            # Supabase anon/publishable key — INFO, intended-public (RLS-protected)
        supabase_service = []         # Supabase service_role key literal — HIGH, must never ship

        for _p, rel, text in ctx.iter_code():
            if is_test_file(rel):     # fixtures / stubbed env / negative-tests are not leaks
                continue
            sb_anon, sb_service = _supabase_key_tiers(text)
            if sb_anon:
                supabase_anon.append(rel)
            if sb_service:
                supabase_service.append(rel)
            frontend = _pkg_flag(rel, pkg_frontend, True)   # unknown package → don't suppress
            names = list(PUBLIC_ENV.findall(text))
            if _pkg_flag(rel, pkg_svelte, False):
                names += SVELTE_PUBLIC.findall(text)
            for v in names:
                public_vars.add(v)
                if not SECRETISH.search(v):
                    continue
                if ANALYTICS_PUBLIC.search(v):
                    intended_public.append(f"{v}  ({rel})")
                elif frontend:
                    public_secret_leaks.append(f"{v}  ({rel})")
            if "use client" in text[:200] or "'use client'" in text[:200] or '"use client"' in text[:200]:
                for s in SERVER_SECRET.findall(text):
                    server_secret_in_client.append(f"{s}  ({rel})")
            client_reachable = bool(PUBLIC_ENV.search(text)) or "use client" in text[:400]
            for rx, label, always in SECRET_SHAPES:
                if (always or client_reachable) and rx.search(text):
                    # a Supabase anon/publishable key is a JWT by shape but intended-public — don't
                    # double-report it here as a value leak (it's surfaced at INFO below instead).
                    if label.startswith("JWT") and sb_anon and not sb_service:
                        continue
                    public_value_leaks.append(f"{label}  ({rel})")
            for m in CFN_TO_PUBLIC.finditer(text):
                public_var_from_cfn.append(f"{m.group(1)} ← {m.group(2)}  ({rel})")

        nextcfg = (ctx.manifest("next.config.js") + ctx.manifest("next.config.mjs")
                   + ctx.manifest("next.config.ts"))
        sourcemaps = "productionBrowserSourceMaps: true" in nextcfg

        return {
            "public_env_vars": sorted(public_vars)[:40],
            "public_secret_leaks": sorted(set(public_secret_leaks)),     # HIGH if non-empty
            "intended_public_analytics": sorted(set(intended_public))[:40],  # INFO — designed to ship
            "server_secret_in_client_component": sorted(set(server_secret_in_client)),  # HIGH if non-empty
            "public_secret_value_leaks": sorted(set(public_value_leaks)),   # HIGH — value-detected, rename-proof
            "public_var_from_cfn_output": sorted(set(public_var_from_cfn)),  # HIGH — CDK build-injected to client
            "intended_public_supabase": sorted(set(supabase_anon)),  # INFO — anon/publishable key, RLS-protected
            "supabase_service_role_in_client": sorted(set(supabase_service)),  # HIGH — service_role key must never ship
            "production_source_maps": sourcemaps,
            "note": "public_secret_leaks / server_secret_in_client_component / public_secret_value_leaks / "
                    "public_var_from_cfn_output ship secrets to the browser — treat as HIGH and confirm. "
                    "Name-based leaks are gated to packages with a frontend bundler (a backend service's "
                    "NEXT_PUBLIC_*/PUBLIC_* fallback-key reference is not a browser leak); analytics ingest "
                    "tokens (PostHog/Usertour/…) are reported separately at INFO (designed to ship). "
                    "Value/CFN-injection detection survives a benign var rename (the #3 gap).",
        }

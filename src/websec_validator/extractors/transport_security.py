"""Transport / browser-hardening header baseline — CSP and HSTS (pen-test classes #3, #4).

The ENABLING condition for the man-in-the-browser class: with no strict Content-Security-Policy, a
supply-chain / injected script can execute and rewrite any on-screen value (see client_integrity.py).
And HSTS applied to only SOME responses (commonly /api but not the HTML/document) leaves the
first-load page surface downgradeable.

This is a framework-agnostic BASELINE audit — it runs on any web surface (React/Vue/Svelte/Angular/
htmx/server-rendered/plain HTML), keyed off header strings and the common middlewares (helmet,
Next.js headers(), SvelteKit/Express/FastAPI/Django security middleware), never an app category. It
emits LOW-confidence architectural leads ("verify these headers"); the SINK-gated escalation (a
money/credential sink with no strict CSP → HIGH) lives in client_integrity.py so the two don't
double-count. Two documented gotchas are carried in the remediation so teams don't mis-cut-over:
`strict-dynamic` IGNORES host allowlists (an allowlist gives false comfort), and a report-only
rollout UNDER-reports cascading failures (the first block masks the rest).
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext

CSP_ANY = re.compile(r"Content-Security-Policy|contentSecurityPolicy|helmet[\s\S]{0,40}?\bcsp\b"
                     r"|useCspNonce|cspDirectives", re.I)
CSP_SCRIPT_SELF = re.compile(r"script-src[^;'\"]*'self'", re.I)
CSP_NONCE = re.compile(r"'nonce-|nonce-\$\{|\bstrict-dynamic\b", re.I)
CSP_UNSAFE = re.compile(r"'unsafe-(?:inline|eval)'", re.I)
INLINE_HANDLER = re.compile(r"\son(?:click|load|error|mouseover|submit)\s*=\s*['\"]", re.I)

HSTS_ANY = re.compile(r"Strict-Transport-Security|helmet[\s\S]{0,40}?\bhsts\b|\bhsts\s*[:=]"
                      r"|max-age=\d+[\s\S]{0,40}?includeSubDomains", re.I)
HSTS_SUBDOMAINS = re.compile(r"includeSubDomains", re.I)
HSTS_PRELOAD = re.compile(r"\bpreload\b", re.I)

# A file that looks like it serves the API surface (vs the HTML/document/app shell). Used only to
# spot the "HSTS on /api but not the page" partial-coverage smell — heuristic, framed as "verify".
API_SCOPED = re.compile(r"(?:^|/)(?:api|routes?|server|lambda|handler|functions?|controllers?)(?:/|\.|$)", re.I)
HTML_SURFACE = re.compile(r"\.(?:html|tsx|jsx|vue|svelte|astro)$|_document|app/layout|index\.html", re.I)
# HTML built/served in CODE (a Worker / server-rendered app emitting template-literal HTML) — so CSP
# applies even with no frontend framework. This is the gap that missed a Cloudflare Worker's CSP.
HTML_CONTENT = re.compile(r"<!DOCTYPE\s+html|<html[\s>]|text/html|res\.send\(\s*[`'\"]\s*<|c\.html\(", re.I)
FRONTEND_FW = {"react", "next", "nextjs", "vue", "nuxt", "svelte", "sveltekit", "angular", "astro", "remix", "solid"}
# Cookie hardening — "report the PASS" (HttpOnly+Secure+SameSite ✓ builds trust + is a regression
# assertion) and flag the gap. Flags are matched per cookie-setting file (lenient — a positive lead).
SET_COOKIE = re.compile(r"set-?cookie|res\.cookie\(|cookies\.set\(|\.setCookie\(|c\.cookie\(", re.I)
CK_HTTPONLY = re.compile(r"httponly", re.I)
# `secure` set literally OR via the idiomatic conditional (`secure: isProduction()`, `secure: !dev`,
# `secure: process.env.NODE_ENV === 'production'`, `secure: config.secureCookies`) — the conditional
# forms were read as "Secure missing" before (the conditional `secure: isProduction()` FP).
CK_SECURE = re.compile(
    r";\s*secure\b|\bsecure\s*[:=]\s*true|\bsecure\s*:\s*!|"
    r"\bsecure\s*:\s*(?:is[A-Z]\w*|process\.env|config\.|env\.|ctx\.|opts?\.|options\.|settings\.|"
    r"[A-Za-z_$][\w$.]*\s*[=!]==|[A-Za-z_$][\w$.]*\s*\?|[A-Za-z_$][\w$.]*\([^)]*\))", re.I)
CK_SAMESITE = re.compile(r"samesite", re.I)


class TransportSecurityExtractor(Extractor):
    name = "transport_security"
    category = "exposure"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        frameworks = {f.lower() for f in (facts.get("stack") or {}).get("frameworks", [])}
        has_routes = bool((facts.get("routes") or {}).get("endpoints"))

        csp_present = csp_self = csp_nonce = csp_unsafe = False
        hsts_present = hsts_sub = hsts_preload = False
        html_surface = bool(frameworks & FRONTEND_FW)
        inline_handlers = []
        sets_cookie = ck_httponly = ck_secure = ck_samesite = False
        hsts_files, hsts_api_only, hsts_html = [], True, False

        # config manifests carry headers too (next.config, vercel.json, netlify.toml, _headers)
        manifests = "\n".join(ctx.manifest(n) for n in
                              ("next.config.js", "next.config.mjs", "next.config.ts", "vercel.json",
                               "netlify.toml", "public/_headers", "static/_headers", "nginx.conf"))

        for _p, rel, text in ctx.iter_code():
            if HTML_SURFACE.search(rel) or HTML_CONTENT.search(text):
                html_surface = True
            blob = text
            if CSP_ANY.search(blob):
                csp_present = True
                if CSP_SCRIPT_SELF.search(blob):
                    csp_self = True
                if CSP_NONCE.search(blob):
                    csp_nonce = True
                if CSP_UNSAFE.search(blob):
                    csp_unsafe = True
            if INLINE_HANDLER.search(blob) and len(inline_handlers) < 15:
                inline_handlers.append(rel)
            if HSTS_ANY.search(blob):
                hsts_present = True
                hsts_files.append(rel)
                if HSTS_SUBDOMAINS.search(blob):
                    hsts_sub = True
                if HSTS_PRELOAD.search(blob):
                    hsts_preload = True
                if HTML_SURFACE.search(rel):
                    hsts_html = True
                elif not API_SCOPED.search(rel):
                    hsts_api_only = False   # a non-API, non-HTML place (e.g. global edge middleware)
            if SET_COOKIE.search(blob):
                sets_cookie = True
                ck_httponly = ck_httponly or bool(CK_HTTPONLY.search(blob))
                ck_secure = ck_secure or bool(CK_SECURE.search(blob))
                ck_samesite = ck_samesite or bool(CK_SAMESITE.search(blob))

        if CSP_ANY.search(manifests):
            csp_present = True
            if CSP_SCRIPT_SELF.search(manifests):
                csp_self = True
            if CSP_NONCE.search(manifests):
                csp_nonce = True
            if CSP_UNSAFE.search(manifests):
                csp_unsafe = True
        if HSTS_ANY.search(manifests):
            hsts_present, hsts_api_only = True, False   # edge config = applies broadly
            if HSTS_SUBDOMAINS.search(manifests):
                hsts_sub = True
            if HSTS_PRELOAD.search(manifests):
                hsts_preload = True

        strict_csp = bool(csp_present and csp_self and csp_nonce and not csp_unsafe)
        web_surface = html_surface or has_routes
        findings = []

        if html_surface:
            if not csp_present:
                findings.append({"severity": "LOW", "kind": "no-csp", "attack_class": "missing-csp",
                                 "detail": "No Content-Security-Policy found on a web/HTML surface. CSP is the control "
                                           "that stops an injected / supply-chain script from executing (the enabling "
                                           "condition for man-in-the-browser tampering of any on-screen value). Add a "
                                           "nonce-based strict CSP: `script-src 'self' 'nonce-<per-request>' "
                                           "'strict-dynamic'`, object-src 'none'. Roll out REPORT-ONLY first with a "
                                           "violation-report collector, soak, then enforce."})
            elif not strict_csp:
                why = ("allows 'unsafe-inline'/'unsafe-eval' in script-src" if csp_unsafe
                       else "is not a strict `script-src 'self'` + nonce / strict-dynamic policy")
                findings.append({"severity": "LOW", "kind": "weak-csp", "attack_class": "missing-csp",
                                 "detail": f"A CSP is present but {why}. Tighten to a nonce-based strict policy. Two "
                                           "gotchas: `strict-dynamic` IGNORES host allowlists (so an allowlist gives "
                                           "false comfort — drop it once nonces are in), and a report-only rollout "
                                           "UNDER-reports cascading failures (the first block masks the rest), so fix "
                                           "iteratively before enforcing."})
            if inline_handlers:
                findings.append({"severity": "LOW", "kind": "inline-event-handlers", "attack_class": "missing-csp",
                                 "detail": f"Inline event handlers (onclick=…/onerror=…) in "
                                           f"{', '.join(sorted(set(inline_handlers))[:4])} are blocked by a strict CSP "
                                           "and force `unsafe-inline` if kept — migrate to addEventListener so a strict "
                                           "policy is actually adoptable."})

        if web_surface:
            if not hsts_present:
                findings.append({"severity": "LOW", "kind": "no-hsts", "attack_class": "incomplete-hsts",
                                 "detail": "No Strict-Transport-Security header found. Apply HSTS at the edge to ALL "
                                           "responses (`max-age>=31536000; includeSubDomains; preload` where the domain "
                                           "model allows) so the first-load page can't be downgraded over plaintext."})
            else:
                gaps = []
                if not hsts_sub:
                    gaps.append("includeSubDomains")
                if not hsts_preload:
                    gaps.append("preload")
                if hsts_present and hsts_api_only and html_surface and not hsts_html:
                    findings.append({"severity": "LOW", "kind": "partial-hsts", "attack_class": "incomplete-hsts",
                                     "detail": "HSTS appears to be set on API/route responses but NOT on the "
                                               "HTML/document/app surface — partial HSTS leaves the first-load page "
                                               "downgradeable. Apply it UNIFORMLY at the edge to every response, not "
                                               "just /api. VERIFY against the live document response."})
                if gaps:
                    findings.append({"severity": "LOW", "kind": "hsts-scope", "attack_class": "incomplete-hsts",
                                     "detail": f"HSTS is present but missing {', '.join(gaps)} — add where the domain "
                                               "model allows (don't preload a domain whose subdomains aren't all HTTPS)."})

        # 0.6.2: report the cookie-hardening PASS (✓ builds trust + is a regression assertion), or flag the gap.
        passes, cookie_security = [], None
        if sets_cookie:
            cookie_security = {"httponly": ck_httponly, "secure": ck_secure, "samesite": ck_samesite}
            if ck_httponly and ck_secure and ck_samesite:
                passes.append("cookies set HttpOnly + Secure + SameSite (checked ✓)")
            else:
                miss = [n for n, ok in (("HttpOnly", ck_httponly), ("Secure", ck_secure),
                                        ("SameSite", ck_samesite)) if not ok]
                findings.append({"severity": "LOW", "kind": "cookie-flags", "attack_class": "insecure-cookie",
                                 "detail": f"A cookie is set without {', '.join(miss)} — an auth/session cookie should be "
                                           "HttpOnly (no JS read), Secure (HTTPS-only), and SameSite=Lax/Strict (CSRF). "
                                           "Verify against the live Set-Cookie."})

        return {
            "web_surface": web_surface, "html_surface": html_surface,
            "csp_present": csp_present, "strict_csp": strict_csp, "csp_has_unsafe": csp_unsafe,
            "hsts_present": hsts_present, "hsts_includes_subdomains": hsts_sub, "hsts_preload": hsts_preload,
            "hsts_files": sorted(set(hsts_files))[:20],
            "inline_event_handlers": sorted(set(inline_handlers)),
            "cookie_security": cookie_security,
            "passes": passes,
            "findings": findings,
            "note": ("CSP/HSTS baseline audit — these are the enabling controls for the client trust boundary. "
                     "LOW/architectural: verify against the LIVE response headers (a static scan can't see the edge/CDN "
                     "layer)." if web_surface else "No web surface detected — CSP/HSTS baseline N/A."),
        }

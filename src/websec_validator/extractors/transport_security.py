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

from .base import Extractor, RepoContext, is_script_file, is_test_file

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
# A construct that SERVES bytes over HTTP (vs merely building an HTML string and writing it to a file).
# This is what separates a real browser-facing surface from a Python/CLI report generator — the latter
# emits `<!DOCTYPE html>` into a file with no serving verb, so it must NOT trigger CSP/clickjacking leads.
SERVE_VERB = re.compile(
    r"new\s+Response\s*\(|res\.(?:send|write|end|render|type)\b|reply\.(?:send|type|code|header)"
    r"|HttpResponse\s*\(|make_response\s*\(|self\.wfile\.write|start_response|sendFile|context\.res\b"
    r"|addEventListener\(\s*['\"]fetch|export\s+default\s*\{[^}]*\bfetch\b", re.I)
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

# CORS misconfiguration — the high-impact form is an Allow-Origin that REFLECTS the request Origin (or
# `*`) TOGETHER with Allow-Credentials:true, which lets any site read authenticated responses.
CORS_REFLECT = re.compile(
    r"Access-Control-Allow-Origin['\"]?\s*[,:][^,\n)]{0,60}(?:req\.|request\.|headers?\.origin|get\s*\(\s*['\"]origin|\borigin\b)"
    r"|cors\s*\(\s*\{[^}]*origin\s*:\s*true|origin\s*:\s*(?:true|function|\(origin)|reflectOrigin|originReflect", re.I)
CORS_WILDCARD = re.compile(r"Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*['\"]|\borigin\s*:\s*['\"]\*['\"]", re.I)
CORS_CREDS = re.compile(r"Access-Control-Allow-Credentials['\"]?\s*[,:]\s*['\"]?true|credentials\s*:\s*true", re.I)
# an external <script src="https://…"> with no Subresource-Integrity (supply-chain: a CDN compromise
# runs arbitrary JS in your origin). Only meaningful in code that emits HTML.
EXT_SCRIPT = re.compile(r"<script\b[^>]*\ssrc\s*=\s*['\"]https?://[^'\"]+['\"][^>]*>", re.I)
SRI_OK = re.compile(r"\bintegrity\s*=", re.I)
# a Next.js config that defines security headers via headers()
NEXT_HEADERS_FN = re.compile(r"async\s+headers\s*\(|\bheaders\s*\(\s*\)\s*\{|key\s*:\s*['\"](?:Content-Security-Policy|X-Frame-Options|Strict-Transport-Security|X-Content-Type-Options)['\"]", re.I)
NEXT_CSP = re.compile(r"Content-Security-Policy", re.I)
NEXT_XFO = re.compile(r"X-Frame-Options|frame-ancestors", re.I)

# Clickjacking defence — X-Frame-Options OR a CSP `frame-ancestors` directive OR helmet's frameguard.
# Framework-agnostic baseline (parallels CSP/HSTS): if a web surface sets NEITHER, the app is framable
# and vulnerable to UI-redress. `frame-ancestors` is the modern control, XFO the legacy fallback.
CLICKJACK_GUARD = re.compile(r"X-Frame-Options|frame-ancestors|frameguard\b|frameGuard\b|xFrameOptions", re.I)
# Anti-CSRF plumbing — a token library / middleware / the token field itself. Presence (anywhere in the
# repo) says the team is handling CSRF; absence on a COOKIE-auth app with no SameSite is the lead.
CSRF_LIB = re.compile(
    r"\bcsurf\b|csrf-csrf|@fastify/csrf|\blusca\b|edge-csrf|next-csrf|\bcsrf_?token\b|csrfToken|xsrf|"
    r"CsrfViewMiddleware|csrf_protect|protect_from_forgery|X-CSRF-Token|X-XSRF-TOKEN|SameSite\s*=\s*Strict", re.I)


class TransportSecurityExtractor(Extractor):
    name = "transport_security"
    category = "exposure"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        frameworks = {f.lower() for f in (facts.get("stack") or {}).get("frameworks", [])}
        has_routes = bool((facts.get("routes") or {}).get("endpoints"))

        csp_present = csp_self = csp_nonce = csp_unsafe = False
        hsts_present = hsts_sub = hsts_preload = False
        clickjack_guard = False        # X-Frame-Options / CSP frame-ancestors / helmet frameguard anywhere
        csrf_plumbing = False          # a CSRF token lib / middleware / field present anywhere in the repo
        server_actions = False         # Next.js `'use server'` — Server Actions carry a built-in Origin CSRF check
        html_surface = bool(frameworks & FRONTEND_FW)
        serves_html = bool(frameworks & FRONTEND_FW)   # HTML actually SERVED over HTTP (vs an HTML string written to a file)
        inline_handlers = []
        sets_cookie = ck_httponly = ck_secure = ck_samesite = False
        hsts_files, hsts_api_only, hsts_html = [], True, False
        extra_findings: list = []     # CORS / SRI / next-config — emitted alongside the CSP/HSTS set

        # config manifests carry headers too (next.config, vercel.json, netlify.toml, _headers)
        manifests = "\n".join(ctx.manifest(n) for n in
                              ("next.config.js", "next.config.mjs", "next.config.ts", "vercel.json",
                               "netlify.toml", "public/_headers", "static/_headers", "nginx.conf"))

        for _p, rel, text in ctx.iter_code():
            if is_test_file(rel) or is_script_file(rel):
                continue
            if HTML_SURFACE.search(rel) or HTML_CONTENT.search(text):
                html_surface = True
                # a frontend file (.tsx/.vue/.html) IS the served shell; HTML in code counts only if a
                # serving verb (new Response / res.send / HttpResponse …) actually returns it over HTTP.
                if HTML_SURFACE.search(rel) or SERVE_VERB.search(text):
                    serves_html = True
            blob = text
            # CORS misconfig — reflected/wildcard Allow-Origin together with credentials = any site
            # reads authed responses (CWE-942). Server-side only.
            if CORS_CREDS.search(blob) and (CORS_REFLECT.search(blob) or CORS_WILDCARD.search(blob)):
                extra_findings.append({"severity": "HIGH", "kind": "cors-credentials-any-origin",
                                       "attack_class": "cors-misconfig", "file": rel,
                                       "detail": "CORS reflects the request Origin (or uses `*`) AND sets "
                                       "Allow-Credentials:true — any website can make credentialed cross-origin "
                                       "requests and READ the authenticated responses (CWE-942). Allow-list exact "
                                       "trusted origins; never reflect Origin or use `*` when credentials are on."})
            elif CORS_REFLECT.search(blob):
                extra_findings.append({"severity": "MEDIUM", "kind": "cors-reflects-origin",
                                       "attack_class": "cors-misconfig", "file": rel,
                                       "detail": "CORS appears to reflect the request Origin (echo-back / `origin:true`) "
                                       "rather than allow-listing exact origins. Safe only without credentials and with a "
                                       "strict allow-list — verify it can't be turned into a credentialed cross-origin read."})
            # external script with no SRI, in code that emits HTML
            if (HTML_CONTENT.search(blob) or HTML_SURFACE.search(rel)):
                for m in EXT_SCRIPT.finditer(blob):
                    if not SRI_OK.search(m.group(0)):
                        extra_findings.append({"severity": "MEDIUM", "kind": "external-script-no-sri",
                                               "attack_class": "subresource-integrity", "file": rel,
                                               "detail": "An external <script src=\"https://…\"> is loaded with no "
                                               "Subresource-Integrity (`integrity=`) hash / version pin — a CDN or "
                                               "package compromise runs arbitrary JS in this origin (CWE-829). Pin the "
                                               "version + add an SRI hash + `crossorigin`, or self-host the bundle."})
                        break
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
            if not clickjack_guard and CLICKJACK_GUARD.search(blob):
                clickjack_guard = True
            if not csrf_plumbing and CSRF_LIB.search(blob):
                csrf_plumbing = True
            if not server_actions and ("'use server'" in blob or '"use server"' in blob):
                server_actions = True

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
        if CLICKJACK_GUARD.search(manifests):
            clickjack_guard = True      # edge/CDN header config (next.config/vercel.json/_headers/nginx)

        # Monorepo-aware Next.js config header gap — `transport_security` previously only read the
        # ROOT next.config via manifests, so a `packages/web/next.config.ts` was invisible. Glob every
        # next.config.* and flag one with no security-header block (CSP + X-Frame-Options).
        for nc in (ctx.glob("**/next.config.js") + ctx.glob("**/next.config.mjs")
                   + ctx.glob("**/next.config.ts")):
            rel, txt = ctx.rel(nc), ctx.text(nc)
            if not NEXT_HEADERS_FN.search(txt):
                extra_findings.append({"severity": "MEDIUM", "kind": "nextjs-no-security-headers",
                                       "attack_class": "missing-csp", "file": rel,
                                       "detail": "This Next.js config defines no security-header block (`headers()`) — "
                                       "so no app-wide Content-Security-Policy, X-Frame-Options/frame-ancestors, HSTS, "
                                       "X-Content-Type-Options, or Referrer-Policy unless an upstream edge sets them. Add "
                                       "a `headers()` matcher (start CSP report-only) or document that nginx/CDN owns them."})
            elif not (NEXT_CSP.search(txt) and NEXT_XFO.search(txt)):
                miss = ", ".join(n for n, ok in (("CSP", NEXT_CSP.search(txt)),
                                                 ("X-Frame-Options/frame-ancestors", NEXT_XFO.search(txt))) if not ok)
                extra_findings.append({"severity": "LOW", "kind": "nextjs-partial-security-headers",
                                       "attack_class": "missing-csp", "file": rel,
                                       "detail": f"Next.js config has a headers() block but is missing {miss}. Add the "
                                       "clickjacking/XSS-defense headers (verify against the live response if the edge sets some)."})

        strict_csp = bool(csp_present and csp_self and csp_nonce and not csp_unsafe)
        # A SERVED web app has HTTP routes OR a recognized web/frontend framework. Without either, a
        # repo that merely emits an HTML string (a Python CLI / data tool writing a report) is NOT a
        # browser-facing surface — flagging CSP/HSTS/clickjacking on it is noise (real-repo FP:
        # a real CLI, a real repo). We accept a rare FN (a framework-less, route-less static
        # site) to kill the dominant non-web FP; the edge/CDN owns those headers anyway.
        served_web = has_routes or bool(frameworks) or serves_html
        html_surface = html_surface and served_web
        web_surface = served_web and (html_surface or has_routes)
        findings = list(extra_findings)

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

        # Clickjacking baseline (framework-agnostic, parallels CSP) — an HTML surface that sets NEITHER
        # X-Frame-Options NOR a CSP frame-ancestors directive is framable (UI-redress). Gated on
        # html_surface (like no-csp), NOT web_surface: a pure JSON API has no framable page. The
        # Next.js-config check above is stricter/per-config; this catches Express/Flask/Django/etc.
        if html_surface and not clickjack_guard:
            findings.append({"severity": "LOW", "kind": "no-clickjacking-protection", "attack_class": "clickjacking",
                             "detail": "No clickjacking defence found (no X-Frame-Options and no CSP `frame-ancestors`). "
                             "The app can be framed by any origin and used for UI-redress / clickjacking. Send "
                             "`X-Frame-Options: DENY` (or SAMEORIGIN) AND `frame-ancestors 'none'`/`'self'` in the CSP on "
                             "every HTML response at the edge. VERIFY against the live document response (a static scan "
                             "can't see the CDN layer)."})

        # CSRF baseline — a COOKIE/session-authenticated app whose state-changing routes rely on the
        # ambient cookie is CSRF-exposed unless it (a) uses an anti-CSRF token OR (b) sets SameSite.
        # Bearer-token-only APIs are exempt (no ambient credential to ride). Derives the auth model from
        # the auth extractor (runs earlier), so this stays a low-FP lead, not a blanket flag.
        auth = facts.get("auth") or {}
        cookie_auth = (str(auth.get("scheme", "")).startswith(("nextauth", "session", "hmac"))
                       or auth.get("token_location") == "cookie"
                       or bool(auth.get("cookie_names")))
        # NextAuth/Auth.js default the session cookie to SameSite=Lax (a source grep can't see the
        # framework default), and Next.js Server Actions carry a built-in Origin==Host CSRF check — so
        # neither is the classic ambient-cookie CSRF this flags (real-repo FPs: a real Next.js app, a real repo).
        nextauth_default = ("nextauth" in frameworks or str(auth.get("scheme", "")).startswith("nextauth"))
        if (web_surface and has_routes and cookie_auth and not csrf_plumbing and not ck_samesite
                and not nextauth_default and not server_actions):
            findings.append({"severity": "LOW", "kind": "no-csrf-protection", "attack_class": "csrf",
                             "detail": "This looks like a cookie/session-authenticated app with HTTP routes, but no "
                             "anti-CSRF token library/middleware (csurf/csrf-csrf/@fastify/csrf/Django/Rails) and no "
                             "`SameSite` cookie attribute were found — state-changing routes may be forgeable "
                             "cross-site (CSRF). Add an anti-CSRF token to write routes AND set session cookies "
                             "`SameSite=Lax`/`Strict`. VERIFY the auth model first: a Bearer-token-only API is exempt."})

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
            "clickjacking_protected": clickjack_guard, "csrf_plumbing_present": csrf_plumbing,
            "inline_event_handlers": sorted(set(inline_handlers)),
            "cookie_security": cookie_security,
            "passes": passes,
            "findings": findings,
            "note": ("CSP/HSTS baseline audit — these are the enabling controls for the client trust boundary. "
                     "LOW/architectural: verify against the LIVE response headers (a static scan can't see the edge/CDN "
                     "layer)." if web_surface else "No web surface detected — CSP/HSTS baseline N/A."),
        }

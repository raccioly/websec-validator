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
from .profiles import manifest_paths, node_metadata, service_for
from .syntax import call_expression, in_literal, js_functions, split_arguments, without_comments

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
HTML_SURFACE = re.compile(r"\.(?:html|vue|svelte|astro)$|index\.html", re.I)
# HTML built/served in CODE (a Worker / server-rendered app emitting template-literal HTML) — so CSP
# applies even with no frontend framework. This is the gap that missed a Cloudflare Worker's CSP.
HTML_CONTENT = re.compile(r"<!DOCTYPE\s+html|<html[\s>]|text/html|res\.send\(\s*[`'\"]\s*<|c\.html\(", re.I)
# A construct that SERVES bytes over HTTP (vs merely building an HTML string and writing it to a file).
# This is what separates a real browser-facing surface from a Python/CLI report generator — the latter
# emits `<!DOCTYPE html>` into a file with no serving verb, so it must NOT trigger CSP/clickjacking leads.
SERVE_VERB = re.compile(
    r"\b(?:new\s+Response|res\.(?:send|write|end|render|type)|reply\.(?:send|type|code|header)"
    r"|HttpResponse|make_response|self\.wfile\.write|start_response|sendFile|c\.html)\s*\(", re.I)
# React/JSX can render native views or be a reusable library. Browser renderer
# dependencies are separate evidence; neither dependency presence nor a DOM call
# proves that the repository is deployed as a website.
FRONTEND_FW = {"next", "nextjs", "vue", "nuxt", "svelte", "sveltekit", "angular", "astro", "remix", "solid"}
BROWSER_RENDERERS = {"react-dom", "react-native-web"}
BROWSER_DOM = re.compile(r"\bdocument\.(?:getElementById|querySelector(?:All)?|createElement|write)\s*\(")
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


def _literal(value: str) -> str | None:
    value = value.strip()
    if (len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]
            and "\\" not in value[1:-1] and value[0] not in value[1:-1]):
        return value[1:-1]
    return None


def _cookie_options(expression: str) -> dict | None:
    expression = expression.strip()
    if not expression.startswith("{") or not expression.endswith("}"):
        return None
    options = {}
    for field in split_arguments(expression[1:-1]):
        if not field:
            continue
        match = re.fullmatch(r"(?:([\w$]+)|['\"]([\w$]+)['\"])\s*:\s*(.+)", field, re.S)
        if not match or (match[1] or match[2]) in options:
            return None  # spreads, shorthand and conflicting keys cannot prove flags
        options[match[1] or match[2]] = match[3].strip()
    return options


def _header_cookie(value: str | None) -> tuple[str, dict]:
    flags = {key: None for key in ("httponly", "secure", "samesite")}
    if value is None:
        return "unknown", flags
    fields = [part.strip().lower() for part in value.split(";")]
    return fields[0].split("=", 1)[0], {
        "httponly": "httponly" in fields, "secure": "secure" in fields,
        "samesite": any(field in {"samesite=lax", "samesite=strict"} for field in fields)}


def _cookie_sites(source: str, rel: str, inventory: list) -> list[dict]:
    """Known cookie setters and Set-Cookie header calls, evaluated independently."""
    sites = []
    calls = re.compile(r"\b[\w$]+(?:\.[\w$]+)*\.(?:cookie|setCookie|set|append|setHeader|header)\s*\(")
    for match in calls.finditer(source):
        if in_literal(source, match.start()):
            continue
        expression = call_expression(source, match.start())
        if not expression.endswith(")"):
            continue
        callee = expression[:expression.find("(")].strip()
        args = split_arguments(expression[expression.find("(")+1:-1])
        header = bool(args and (_literal(args[0]) or "").lower() == "set-cookie")
        setter = callee.endswith((".cookie", ".setCookie", "cookies.set"))
        if not header and not setter:
            continue
        flags = {key: None for key in ("httponly", "secure", "samesite")}
        name = "unknown"
        if header:
            value = _literal(args[1]) if len(args) > 1 else None
            name, flags = _header_cookie(value)
        else:
            object_form = len(args) == 1 and args[0].strip().startswith("{")
            options = _cookie_options(args[0] if object_form else args[2] if len(args) > 2 else "{}")
            name = (_literal(options.get("name", "")) if object_form and options else
                    _literal(args[0]) if args else None) or "unknown"
            if options is not None:
                for flag, key in (("httponly", "httpOnly"), ("secure", "secure")):
                    value = options.get(key, "false")
                    flags[flag] = True if value == "true" else False if value == "false" else None
                value = options.get("sameSite")
                flags["samesite"] = (False if value is None or value == "false" else
                                     True if value == "true" or (_literal(value) or "").lower() in {"lax", "strict"} else
                                     False if (_literal(value) or "").lower() == "none" else None)
        sites.append({"file": rel, "line": source.count("\n", 0, match.start()) + 1,
                      "service_id": service_for(inventory, rel).get("id", "."), "name": name,
                      **flags, "verified": all(value is True for value in flags.values()),
                      "basis": "literal flags on this setter; dynamic values unverified"})
    # Header maps and subscript assignments were supported by the old broad
    # Set-Cookie signal. Preserve them without borrowing flags from other text.
    for key in re.finditer(r"(['\"])Set-Cookie\1\s*(?::|\]\s*=)", source, re.I):
        if key.start() and in_literal(source, key.start() - 1):
            continue
        before = source[max(0, key.start() - 160):key.start()]
        assignment = bool(re.search(r"\b[\w$.]+\.headers\s*\[\s*$", before))
        header_map = bool(re.search(r"\bheaders\s*:\s*\{[^{}]*$", before))
        if not assignment and not header_map:
            continue
        tail = source[key.end():].lstrip()
        literal = re.match(r'''(?:"[^"\\]*"|'[^'\\]*')(?=\s*(?:[,};\n]|$))''', tail)
        name, flags = _header_cookie(_literal(literal[0]) if literal else None)
        sites.append({"file": rel, "line": source.count("\n", 0, key.start()) + 1,
                      "service_id": service_for(inventory, rel).get("id", "."), "name": name,
                      **flags, "verified": all(value is True for value in flags.values()),
                      "basis": "Set-Cookie header map or assignment; dynamic values unverified"})
    return sites


class TransportSecurityExtractor(Extractor):
    name = "transport_security"
    category = "exposure"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        frameworks = {f.lower() for f in (facts.get("stack") or {}).get("frameworks", [])}
        has_routes = bool((facts.get("routes") or {}).get("endpoints"))
        renderers = set()
        for path in manifest_paths(ctx):
            if path.name == "package.json":
                renderers.update(node_metadata(ctx.text(path))["dependencies"] & BROWSER_RENDERERS)
        frontend_hint = bool(frameworks & FRONTEND_FW or renderers)

        csp_present = csp_self = csp_nonce = csp_unsafe = False
        hsts_present = hsts_sub = hsts_preload = False
        clickjack_guard = False        # X-Frame-Options / CSP frame-ancestors / helmet frameguard anywhere
        csrf_plumbing = False          # a CSRF token lib / middleware / field present anywhere in the repo
        server_actions = False         # Next.js `'use server'` — Server Actions carry a built-in Origin CSRF check
        html_surface = frontend_hint
        serves_html = frontend_hint
        inline_handlers = []
        sets_cookie = ck_httponly = ck_secure = ck_samesite = False
        hsts_files, hsts_api_only, hsts_html = [], True, False
        extra_findings: list = []     # CORS / SRI / next-config — emitted alongside the CSP/HSTS set
        cookie_sites = []
        default_auth_handlers: dict[str, set[str]] = {}
        inventory = (facts.get("stack") or {}).get("service_inventory", [])

        # config manifests carry headers too (next.config, vercel.json, netlify.toml, _headers)
        manifests = "\n".join(ctx.manifest(n) for n in
                              ("next.config.js", "next.config.mjs", "next.config.ts", "vercel.json",
                               "netlify.toml", "public/_headers", "static/_headers", "nginx.conf"))

        for _p, rel, text in ctx.iter_code():
            if is_test_file(rel) or is_script_file(rel):
                continue
            code = without_comments(text, _p.suffix)
            browser_dom = any(not in_literal(code, match.start()) for match in BROWSER_DOM.finditer(code))
            if browser_dom:
                html_surface = serves_html = True
            # Response prose and unrelated HTML strings cannot combine into a
            # browser surface. Require HTML evidence in the actual bounded call.
            response_html = any(
                not in_literal(code, match.start())
                and HTML_CONTENT.search(call_expression(code, match.start()))
                for match in SERVE_VERB.finditer(code))
            if HTML_SURFACE.search(rel) or response_html:
                html_surface = serves_html = True
            blob = text
            cookie_sites.extend(_cookie_sites(code, rel, inventory))
            # Auth.js/NextAuth's own default cookie policy is relevant only where
            # initialized, and never establishes flags for manually created cookies.
            imports = list(re.finditer(r"\bimport\s+NextAuth\s+from\s+['\"]next-auth['\"]", code))
            auth_import = any(not in_literal(code, item.start()) for item in imports)
            scopes = js_functions(code) if auth_import else []
            for init in re.finditer(r"\bNextAuth\s*\(", code):
                if (auth_import and not in_literal(code, init.start())
                        and not any(scope["start"] <= init.start() < scope["end"] for scope in scopes)):
                    call = call_expression(code, init.start())
                    options = _cookie_options(call[call.find("(") + 1:-1])
                    if options is not None and "cookies" not in options and not re.search(
                            r"\b(?:function|class|const|let|var)\s+NextAuth\b|\bNextAuth\s*=", code):
                        # Initialization alone does not own any HTTP route. Require
                        # a direct method export or an explicit handler re-export.
                        prefix = code[:init.start()]
                        binding = re.search(r"\b(export\s+)?const\s+([\w$]+)\s*=\s*$", prefix)
                        methods = set()
                        if binding:
                            name = binding[2]
                            if binding[1] and name in {"GET", "POST"}:
                                methods.add(name)
                            if len(re.findall(r"\b" + re.escape(name) + r"\s*=(?!=)", code)) == 1:
                                for export in re.finditer(r"\bexport\s*\{([^{}]+)\}\s*;?", code):
                                    if not in_literal(code, export.start()):
                                        for entry in split_arguments(export[1]):
                                            renamed = re.fullmatch(re.escape(name) + r"\s+as\s+(GET|POST)", entry)
                                            if renamed:
                                                methods.add(renamed[1])
                        elif re.search(r"\bexport\s+default\s*$", prefix) and re.search(
                                r"(?:^|/)pages/api/auth/", rel):
                            methods.update({"GET", "POST"})
                        default_auth_handlers.setdefault(rel, set()).update(methods)
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
        # Only HTTP routes or browser/serving hints enable the baseline. General
        # framework labels cannot turn a library's generated HTML into a website.
        served_web = has_routes or serves_html
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
        sets_cookie = bool(cookie_sites)
        ck_httponly = bool(cookie_sites) and all(row["httponly"] is True for row in cookie_sites)
        ck_secure = bool(cookie_sites) and all(row["secure"] is True for row in cookie_sites)
        ck_samesite = bool(cookie_sites) and all(row["samesite"] is True for row in cookie_sites)
        routes = (facts.get("routes") or {}).get("endpoints", [])
        nextauth_default = not cookie_sites and bool(routes) and all(
            row.get("method", "").upper() in default_auth_handlers.get(row.get("code_path"), set())
            and re.match(r"^/(?:api/)?auth(?:/|$)", row.get("path", "")) for row in routes)
        # A library mention or another service's Server Action does not establish
        # CSRF enforcement for an explicitly observed custom cookie.
        if cookie_sites and not ck_samesite:
            csrf_plumbing = False
            server_actions = False
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
            cookie_security = {key: (False if any(row[key] is False for row in cookie_sites) else
                                    None if any(row[key] is None for row in cookie_sites) else True)
                               for key in ("httponly", "secure", "samesite")}
            if ck_httponly and ck_secure and ck_samesite:
                passes.append("cookies set HttpOnly + Secure + SameSite (checked ✓)")
            else:
                for row in cookie_sites:
                    if row["verified"]:
                        continue
                    miss = [key for key in ("httponly", "secure", "samesite") if row[key] is not True]
                    findings.append({"severity": "LOW", "kind": "cookie-flags", "attack_class": "insecure-cookie",
                                 "file": row["file"], "line": row["line"], "service_id": row["service_id"],
                                 "detail": f"Cookie {row['name']} has missing, false or unverified {', '.join(miss)} flags on this setter — an auth/session cookie should be "
                                           "HttpOnly (no JS read), Secure (HTTPS-only), and SameSite=Lax/Strict (CSRF). "
                                           "Verify against the live Set-Cookie."})

        return {
            "web_surface": web_surface, "html_surface": html_surface,
            "browser_renderers": sorted(renderers),
            "surface_note": "Static browser/HTTP hints, not proof of deployment. React or JSX alone does not establish a browser renderer.",
            "csp_present": csp_present, "strict_csp": strict_csp, "csp_has_unsafe": csp_unsafe,
            "hsts_present": hsts_present, "hsts_includes_subdomains": hsts_sub, "hsts_preload": hsts_preload,
            "hsts_files": sorted(set(hsts_files))[:20],
            "clickjacking_protected": clickjack_guard, "csrf_plumbing_present": csrf_plumbing,
            "inline_event_handlers": sorted(set(inline_handlers)),
            "cookie_security": cookie_security,
            "cookie_occurrences": cookie_sites,
            "passes": passes,
            "findings": findings,
            "note": ("CSP/HSTS baseline audit — these are the enabling controls for the client trust boundary. "
                     "LOW/architectural: verify against the LIVE response headers (a static scan can't see the edge/CDN "
                     "layer)." if web_surface else "No web surface detected — CSP/HSTS baseline N/A."),
        }

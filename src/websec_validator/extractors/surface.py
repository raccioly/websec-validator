"""Attack-surface extractor — code-level dangerous sinks, user-control-aware.

Each signature embeds a user-input marker (`req.`/`request.`/string concat/
template interpolation/format) so a match means "dangerous op fed by something
that looks attacker-influenced", not merely "this function is used anywhere".
Signatures derived from the recon-engine research. Each class maps to the probe
that exercises it, so the briefing can point probes at the right files.
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext, is_client_file, is_script_file, is_test_file

# user-controlled markers (kept loose on purpose)
_U = r"(?:req\.|request\.|\+|`[^`]*\$\{|f['\"]|%\s*[\(%]|\.format\s*\(|searchParams|nextUrl|params\[)"

# SSRF is narrower than _U: it requires a REQUEST-DERIVED url, not any template literal. A hardcoded
# host with only an env/secret/config var interpolated (`api.telegram.org/bot${token}`), a loopback
# self-call, or a same-origin RELATIVE path (`/api/...`) is NOT SSRF. Validated on a real LLM-agent monorepo:
# the old `\bfetch\(\s*${anything}` matched browser fetches, build scripts, and adapters — ~95% FP.
_REQ_SRC = (r"(?:req\.(?:query|params|body|headers|originalUrl)|request\.(?:query|params|body|headers|json|args|GET|POST)"
            r"|searchParams|nextUrl|\.params\[|\.query\[|\.body\.|ctx\.(?:query|params|request|req)|\bbody\.\w|userInput|userProvided)")

# Log injection (CWE-117) — Veracode's #2 AI failure class. A user-controlled value CONCATENATED or
# interpolated into a logging call with no newline neutralization (log forging). LOW severity — not RCE.
# Server-only (added to _SERVER_REQUEST_CLASSES below). The load-bearing FP guard: no arm may cross a
# comma / `;` / `)`, so STRUCTURED/parametrized logging — `logger.info('u=%s', x)`, pino's object arg,
# `extra={...}` — where the value is a SEPARATE argument never matches; only value-in-arg-1 concatenation
# does. Bare `print()` is deliberately NOT a sink (the tool's own cli.py uses print()).
_LOG_SINK = (r"(?:console\.(?:log|info|warn|error|debug)|(?:logger|log|winston|pino|logging|_log|LOG)\."
             r"(?:info|warn|warning|error|debug|log|trace|fatal|verbose|http|exception|critical))")
_LOG_INJECTION = re.compile(
    _LOG_SINK + r"\s*\(\s*(?:"
    r"`[^`,;)]*\$\{[^}]*" + _REQ_SRC +                       # `...${req.query.x}...`  (JS template)
    r"|f['\"][^'\",;)]*\{[^}]*" + _REQ_SRC +                 # f"...{request.args...}..."  (Python)
    r"|['\"][^'\",;)]*['\"]\s*\+\s*[^,;)]*" + _REQ_SRC +     # "prefix " + req.query.x  (concat, no comma)
    r"|" + _REQ_SRC +                                        # log the raw user value as the first arg
    r")", re.I)

# class -> (probe it feeds, gating, compiled regex)
#   gating: None | "sql" | "nosql"  (datastore-dependent classes)
SINKS = {
    "ssrf": ("ssrf-probes", None, re.compile(
        r"(?:\bfetch|axios(?:\.\w+)?|got|node-fetch|superagent|needle|undici|requests\.\w+|httpx\.\w+|urllib\.request\.\w+)"
        r"\s*\(\s*[^)\n;]{0,160}?" + _REQ_SRC)),
    "command-injection": ("ssrf-probes", None, re.compile(
        r"(?:child_process\.exec|\bexecSync|\bexec|\bspawn|os\.system|subprocess\.(?:run|call|check_output|Popen))\s*\([^)]*"
        + _U + r"|shell\s*=\s*True")),
    "sql-injection": ("bola-write-verbs", "sql", re.compile(
        r"(?:\.query|\.execute|\.raw|cursor\.execute|sequelize\.query|knex\.raw)\s*\([^)]*(?:\$\{|\+|%\s*[\(%]|\.format\s*\(|f['\"])|(?:f['\"]|`)[^'\"`]*(?:SELECT|UPDATE|INSERT|DELETE)[^'\"`]*(?:['\"]|`).{0,200}?(?:\.query|\.execute|\.raw)\s*\(", re.IGNORECASE | re.DOTALL)),
    "nosql-injection": ("bola-write-verbs", "nosql", re.compile(
        r"\.(?:find|findOne|update|updateOne|deleteOne|aggregate)\s*\(\s*(?:req\.|request\.)|\$where")),
    "path-traversal": ("bola-write-verbs", None, re.compile(
        r"(?:fs\.(?:readFile|writeFile|createReadStream|unlink|readdir)|sendFile|os\.path\.join|\bopen|path\.(?:join|resolve))\s*\([^)]*"
        + _U)),
    "ssti": ("ssrf-probes", None, re.compile(
        r"(?:render_template_string|renderString|nunjucks\.renderString|ejs\.render|pug\.compile|Handlebars\.compile|new\s+Template|Template\s*\()\s*\([^)]*"
        + _U)),
    "open-redirect": ("bola-write-verbs", None, re.compile(
        r"(?:res\.redirect|HttpResponseRedirect|RedirectResponse|return\s+redirect|res\.setHeader\s*\(\s*['\"]Location)\s*\([^)]*"
        + _U)),
    "insecure-deserialization": ("bola-write-verbs", None, re.compile(
        r"pickle\.loads?\s*\(|cPickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader)|node-serialize.*unserialize\s*\(|\bunserialize\s*\(")),
    "xxe": ("ssrf-probes", None, re.compile(
        r"libxmljs\.parseXml\s*\(|lxml\.etree\.(?:parse|fromstring|XML)\s*\(|xml\.etree\.ElementTree\.(?:parse|fromstring)\s*\(|new\s+DOMParser")),
    "prototype-pollution": ("mass-assignment", None, re.compile(
        r"(?:_\.merge|_\.mergeWith|_\.defaultsDeep|Object\.assign)\s*\([^)]*(?:req\.|request\.)|\.update\s*\([^)]*request\.(?:json|get_json|form)")),
    # Mass-assignment via object SPREAD — `{...record, ...req.body}` (client overwrites ANY field) or
    # the shorthand `{...record, tier}` (a PRIVILEGED field pulled from a same-named var — the
    # tier-downgrade / role-escalation class). User-input marker is inline; the privileged-field list
    # gates the shorthand form so a benign `{...state, theme}` doesn't fire.
    "mass-assignment": ("mass-assignment", None, re.compile(
        r"\{\s*\.\.\.[\w.$]+\s*,\s*\.\.\.(?:(?:req\w*|request|ctx|c)\.(?:body|json|payload|data|params|query)"
        r"|body|reqBody|requestBody|userInput|updates|patch)\b"
        r"|Object\.assign\s*\(\s*[\w.$]+\s*,\s*(?:req|request|ctx|c)\.(?:body|json|payload|data)\b"
        # NB: `scope`/`scopes` intentionally dropped from the SHORTHAND arm — too common as a benign
        # internal field (`{...row, scope}`) to flag on the bare-identifier form (FP on a real LLM-agent monorepo).
        r"|\{\s*\.\.\.[\w.$]+[^{}]{0,80}?,\s*(?:role|roles|tier|plan|isAdmin|is_admin|admin|permissions?"
        r"|balance|credits|isOwner|isSuperuser|superuser)\s*[,}]")),
    "redos": ("ssrf-probes", None, re.compile(
        r"new\s+RegExp\s*\([^)]*(?:req\.|request\.|\+)|re\.(?:compile|match|search|fullmatch)\s*\([^,)]*(?:request\.|f['\"])")),
    "eval-injection": ("bola-write-verbs", None, re.compile(
        r"\beval\s*\([^)]*" + _U + r"|new\s+Function\s*\([^)]*" + _U)),
    # Var-arg SSRF: an http client called with a BARE identifier first-arg (not a string literal) —
    # e.g. `axios.get(mediaUrl, {…})` a file away from `req.query.url` (REF-PENTEST #1, which the
    # same-line `ssrf` class above misses). Emits the `ssrf-outbound-http` key probes.py waits for.
    # MED-FP by design (axios.get(someVar) is common) → kept LOW-confidence; promote when reachable
    # from a controller that reads req.query.
    "ssrf-outbound-http": ("ssrf-probes", None, re.compile(
        r"(?:axios(?:\.(?:get|post|put|delete|patch|request|head))?|got|node-fetch|needle|superagent|undici"
        r"|https?\.request|requests\.(?:get|post|put|patch|request)|httpx\.(?:get|post|request|AsyncClient))"
        r"\s*\(\s*[A-Za-z_$][\w$.]*\s*[,)]")),
    # OUTPUT-side disclosure — a DOCUMENTED EXCEPTION to the user-input-marker rule (this is a
    # response sink, not an input sink). A 500 handler echoing err.stack/err.message, or a
    # NODE_ENV!=='production' branch that spreads the stack, leaks internals (REF-PENTEST #7).
    "error-disclosure": ("error-disclosure-probe", None, re.compile(
        r"res\.(?:json|send)\s*\([^;]{0,200}\b(?:err|error|e|ex|exc)\.(?:stack|message)\b"
        r"|res\.status\(\s*\d+\s*\)\.(?:json|send)\s*\([^;]{0,200}\b(?:err|error|e)\.(?:stack|message)\b"
        r"|NODE_ENV\s*[!=]==?\s*['\"]production['\"][^;{}]{0,160}\b(?:stack|message)\b")),
    # Reflected / DOM / template XSS — a user-influenced value reaching an HTML sink with no output
    # encoding. CLIENT DOM sinks (innerHTML/outerHTML/insertAdjacentHTML/document.write/jQuery .html /
    # React dangerouslySetInnerHTML / Vue v-html) + SERVER template-escape-off (Jinja `|safe`,
    # mark_safe, Markup(), `{% autoescape false %}`, res.send of an interpolated HTML string). The
    # per-file sanitizer guard (_XSS_SANITIZER, applied in the loop) suppresses a file that runs
    # DOMPurify/sanitize-html/bleach/escape — so a sanitized render doesn't false-fire. Kept
    # LOW-confidence like every surface lead: "verify this value is escaped/sanitized before the sink."
    "xss": ("xss-verify", None, re.compile(
        r"\.(?:inner|outer)HTML\s*=\s*[^;=][^;]{0,140}?(?:\$\{|`|\+|req\.|request\.|props\.|params\b|state\.|location\.|searchParams|\.value\b)"
        r"|\.insertAdjacentHTML\s*\([^)]*(?:\$\{|`|\+|req\.|props\.|params\b|state\.|location\.)"
        r"|document\.write(?:ln)?\s*\([^)]*(?:\$\{|`|\+|req\.|location\.|params\b|search)"
        # dangerouslySetInnerHTML / v-html require a USER-INFLUENCED __html expr — a static string literal
        # (a service-worker registration snippet, an inline <style>) is not XSS (real-repo FP: a real app).
        r"|dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*(?![^}]*(?:DOMPurify|sanitiz))[^}]*(?:\$\{|`|\+|req\.|props\.|params|state\.|data\.|content|body|markdown|html\b|value)"
        r"|\bv-html\s*=\s*['\"]?(?:[\w.$]+|\{)"
        r"|\{%\s*autoescape\s+(?:false|off)|\|\s*safe\b|\bmark_safe\s*\(|\bMarkup\s*\("
        r"|res\.(?:send|write)\s*\(\s*[`'\"][^`'\"]*<[a-z][^`'\"]*\$\{[^}]*(?:req|request|params|query|body)\b")),
    # Log injection / log forging (CWE-117). LOW severity, server-only. No active probe — a manual-verify
    # lead ("log-forging-verify" is documentary; the probe field is cosmetic and never staged).
    "log-injection": ("log-forging-verify", None, _LOG_INJECTION),
}

# A file that neutralizes HTML before rendering — DOMPurify / sanitize-html / the `xss` lib / Python
# bleach / an explicit HTML-escape. Presence suppresses the file's xss lead (file-level, like the
# other surface FP guards): a sanitized render is the safe pattern, not the vulnerability.
_XSS_SANITIZER = re.compile(
    r"DOMPurify|sanitize-?html|sanitizeHtml|\bxss\s*\(|\bbleach\.|escapeHtml|escapeHTML|encodeHTML"
    r"|\bhtmlspecialchars\b|\bhe\.encode\b|\bxss-clean\b", re.I)


# SSRF-via-redirect (REF-PENTEST #1): axios/requests FOLLOW redirects by DEFAULT, so an outbound
# client on a variable URL re-validates only the FIRST hop unless it pins maxRedirects:0 or adds a
# per-hop guard. One of these present = the chain is guarded; absent next to an SSRF sink = the lead
# (allow-list on the input URL is necessary but never sufficient — a 302 to 169.254.169.254 wins).
REDIRECT_GUARD = re.compile(r"beforeRedirect|maxRedirects\s*:\s*0\b|allow_redirects\s*=\s*False"
                            r"|validateRedirect|isAllowed\w*Url|on[_-]?redirect|checkRedirect", re.I)

# Reverse-proxy PREFIX-ESCAPE (confused deputy, CWE-22/CWE-441): a Next.js-style proxy builds the
# upstream URL by joining USER-CONTROLLED catch-all segments after a fixed prefix —
# `fetch(`${base}/api/x/${endpoint.join('/')}`)` — and forwards a server-minted token. WHATWG URL
# normalizes `../`, so `/api/x/%2e%2e/%2e%2e/admin` resolves PAST the prefix to any upstream route
# with valid creds. The host is literal (not SSRF) but the per-prefix isolation is defeated.
# The join often lands on its own line (`const path = endpoint.join('/')`) then the fetch
# interpolates it — so detect FILE-LEVEL: catch-all segments joined with '/' AND an outbound call
# whose template URL interpolates a path segment after a slash.
PROXY_JOIN = re.compile(r"\.join\s*\(\s*['\"]/['\"]\s*\)")
PROXY_FETCH = re.compile(r"(?:fetch|axios(?:\.\w+)?|got|ky|undici|request)\s*\(\s*`[^`]*/\$\{", re.I)
# an explicit dot-segment / encoded-slash rejection or post-normalize prefix assertion = guarded
DOTSEG_GUARD = re.compile(
    r"includes\s*\(\s*['\"]\.\.|===\s*['\"]\.\.['\"]|['\"]\.\.['\"]\s*\)|%2e|%2f|decodeURIComponent"
    r"|\bnormalize\b|startsWith\s*\(\s*['\"]/[\w]|sanitiz|assertPath|safeJoin|\bresolve\b[^;]{0,40}startsWith", re.I)

# Host-header → redirect (open redirect / cache poisoning, CWE-601): a redirect Location/origin built
# from the attacker-controllable Host / X-Forwarded-Host header with no host allow-list comparison.
HOST_HEADER_READ = re.compile(
    r"(?:req|request|ctx)\.(?:headers?\s*[\[.]|get\s*\(\s*)['\"]?(?:x-forwarded-host|forwarded|host)\b"
    r"|headers\.get\s*\(\s*['\"](?:x-forwarded-host|host|forwarded)", re.I)
REDIRECT_SINK = re.compile(
    r"\.redirect\s*\(|NextResponse\.redirect|res\.setHeader\s*\(\s*['\"]Location|['\"]Location['\"]\s*[:,]|sendRedirect", re.I)
HOST_ALLOWLIST = re.compile(
    r"allowedHosts?|allow[_-]?list|publicOrigin|publicWebOrigin|trustedHosts?|isAllowedHost|whitelist|brandfolderHostnames", re.I)
# SSRF-hardening: an outbound client DELIBERATELY following redirects with no host allow-list /
# private-range deny — a 30x to an internal/metadata host is then fetched server-side (CWE-918),
# independent of whether the INITIAL url is user-tainted. Reaches worker/job scripts the route scan misses.
FOLLOW_REDIR = re.compile(r"follow_redirects\s*=\s*True|allow_redirects\s*=\s*True|maxRedirects\s*:\s*[1-9]", re.I)
OUTBOUND_CLIENT = re.compile(r"\b(?:requests\.\w+|httpx\.\w+|\bfetch\s*\(|axios|got\s*\(|node-fetch|urllib\.request)", re.I)
SSRF_PRIVATE_GUARD = re.compile(
    r"allow_redirects\s*=\s*False|follow_redirects\s*=\s*False|maxRedirects\s*:\s*0|169\.254|RFC1918|is_private|"
    r"ip_address|private_?range|block.?(?:internal|private)|allowedHosts?|allow[_-]?list", re.I)

# server-request sink classes — they assume the "user input" is an attacker over an HTTP request. On a
# repo with NO HTTP listener (a CLI / library / data tool: 0 routes AND no web framework), the input is
# an operator's argv/config, not an attacker, so they don't apply (real-repo FP: a real repo,
# several real repos). redirect/error-disclosure are likewise server-response classes.
_SERVER_REQUEST_CLASSES = {"ssrf", "ssrf-outbound-http", "command-injection", "path-traversal",
                           "open-redirect", "sql-injection", "nosql-injection", "ssti",
                           "eval-injection", "xxe", "redos", "error-disclosure",
                           # log-injection: a server handler logging request data — client/CLI/no-web-surface
                           # files (which don't take an HTTP request) must not fire (bug-135/140 lesson).
                           "log-injection"}
# a Python module that is an operator CLI (has an __main__ entrypoint / argparse / click) and imports NO
# web framework — its input is argv/stdin, not an HTTP request, so server-only sinks don't apply.
_PY_CLI = re.compile(r"if\s+__name__\s*==\s*['\"]__main__['\"]|\bargparse\.|click\.command|\btyper\.|sys\.argv", re.I)
_PY_WEB_FW = re.compile(r"\bfrom\s+flask|\bimport\s+flask|\bfrom\s+fastapi|\bimport\s+fastapi|\bfrom\s+django|"
                        r"\bfrom\s+aiohttp|\bfrom\s+starlette|\bfrom\s+sanic|\bfrom\s+tornado|Flask\s*\(|FastAPI\s*\(", re.I)


class SurfaceExtractor(Extractor):
    name = "surface"
    category = "sinks"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        datastores = set((facts.get("stack") or {}).get("datastores", []))
        has_sql = any("sql" in d or d in ("postgres", "mysql", "sqlite") for d in datastores)
        has_nosql = any(d in ("mongo", "dynamodb") for d in datastores)

        stack = (facts.get("stack") or {})
        frameworks = stack.get("frameworks") or []
        has_routes = bool((facts.get("routes") or {}).get("endpoints"))
        # No HTTP listener anywhere → the request-driven sink classes have no attacker in the loop.
        # Gated on `languages` being populated so it only fires on a REAL run (StackExtractor always
        # sets languages); a minimal fact dict without it isn't treated as "non-web".
        no_web_surface = bool(stack.get("languages")) and not has_routes and not frameworks

        found: dict = {k: [] for k in SINKS}
        counts: dict = {k: 0 for k in SINKS}
        ssrf_redirect: list = []    # SSRF sink in a file with NO per-hop redirect guard (#1)
        proxy_escape: list = []     # reverse-proxy prefix-escape (confined-deputy)
        host_redirect: list = []    # redirect built from the Host/X-Forwarded-Host header (open redirect)
        follows_redirect: list = []  # outbound client follows redirects with no allow-list (SSRF-hardening)
        for _p, rel, text in ctx.iter_code():
            # Test fixtures are never a runtime sink; SSRF + outbound-HTTP are SERVER-ONLY classes,
            # so client (.tsx/'use client') and build/CLI scripts can't host them (validated: these
            # were the entire ssrf false-positive set on a real LLM-agent monorepo).
            if is_test_file(rel):
                continue
            nonserver = is_client_file(rel, text) or is_script_file(rel)
            # a Python operator-CLI module (argv/click, no web framework) is not an HTTP handler
            if not nonserver and rel.endswith(".py") and _PY_CLI.search(text) and not _PY_WEB_FW.search(text):
                nonserver = True
            for cls, (_probe, gate, rx) in SINKS.items():
                if gate == "sql" and not has_sql:
                    continue
                if gate == "nosql" and not has_nosql:
                    continue
                # request-driven sink classes need an HTTP attacker: skip in client/script/CLI files,
                # and skip entirely on a repo with no web surface (no routes + no web framework).
                if cls in _SERVER_REQUEST_CLASSES and (nonserver or no_web_surface):
                    continue
                if rx.search(text):
                    # command-injection precision: an argv-list subprocess with shell=False is safe —
                    # the dangerous form is shell=True or a concatenated command string.
                    if (cls == "command-injection" and re.search(r"shell\s*=\s*False", text)
                            and not re.search(r"shell\s*=\s*True", text)):
                        continue
                    # xss precision: a file that sanitizes/encodes HTML (DOMPurify/bleach/escape) before
                    # the sink is the safe pattern — suppress its xss lead (file-level FP guard).
                    if cls == "xss" and _XSS_SANITIZER.search(text):
                        continue
                    counts[cls] += 1
                    if len(found[cls]) < 60:
                        found[cls].append(rel)
            if (len(ssrf_redirect) < 40 and not nonserver and not no_web_surface and not REDIRECT_GUARD.search(text)
                    and (SINKS["ssrf-outbound-http"][2].search(text) or SINKS["ssrf"][2].search(text))):
                ssrf_redirect.append(rel)
            # reverse-proxy prefix-escape: catch-all segments joined into a fixed-prefix upstream URL
            # with no dot-segment rejection (client .tsx excluded — the proxy is the server handler)
            if (len(proxy_escape) < 30 and not nonserver and not no_web_surface and PROXY_JOIN.search(text)
                    and PROXY_FETCH.search(text) and not DOTSEG_GUARD.search(text)):
                proxy_escape.append(rel)
            # host-header → redirect (open redirect via Host/X-Forwarded-Host). Server-only; needs a
            # redirect sink + a host-header read + no host allow-list in the file.
            if (len(host_redirect) < 30 and not nonserver and not no_web_surface and HOST_HEADER_READ.search(text)
                    and REDIRECT_SINK.search(text) and not HOST_ALLOWLIST.search(text)):
                host_redirect.append(rel)
            # SSRF-hardening: follows redirects with no allow-list / private-range deny. Worker/job
            # SCRIPTS are in scope here (they fetch server-side), so only client + tests are excluded.
            if (len(follows_redirect) < 30 and not is_client_file(rel, text) and not no_web_surface
                    and FOLLOW_REDIR.search(text) and OUTBOUND_CLIENT.search(text)
                    and not SSRF_PRIVATE_GUARD.search(text)):
                follows_redirect.append(rel)

        sinks = {k: {"probe": SINKS[k][0], "count": counts[k], "files": found[k]}
                 for k in SINKS if counts[k]}
        return {
            "sinks": sinks,
            "sink_counts": {k: counts[k] for k in SINKS if counts[k]},
            "ssrf_redirect_unguarded": ssrf_redirect,   # validate EVERY hop, not just the input URL (#1)
            "proxy_prefix_escape": proxy_escape,        # confined-deputy via `..` in catch-all path
            "host_header_redirect": host_redirect,      # open redirect via Host/X-Forwarded-Host
            "follows_redirect_no_allowlist": follows_redirect,  # SSRF-hardening (redirect-to-internal)
            "datastore_class": ("sql" if has_sql else ("nosql" if has_nosql else "unknown")),
            "note": "Each sink hit is user-input-gated (req./request./concat/interp), so these are "
                    "higher-confidence leads. Cross-reference the files with routes.targeting to pick "
                    "the endpoint to probe. On a NoSQL/JSON API, SQLi alerts from generic scanners are "
                    "usually false positives.",
        }

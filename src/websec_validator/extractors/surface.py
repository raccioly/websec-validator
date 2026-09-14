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
from .syntax import (without_comments, expression_end, call_expression, direct_call,
                     occurrence, python_shell_safe, server_file, split_arguments, direct_options, in_literal)
from .profiles import service_for, java_fixed_argv
from . import sql_flow

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
        r"(?:child_process\.exec|\bexecSync|\bexec|\bspawn|os\.system|os\.popen"
        r"|subprocess\.(?:run|call|check_output|Popen|getoutput|getstatusoutput))\s*\([^)]*"
        + _U + r"|shell\s*=\s*True")),
    "sql-injection": ("bola-write-verbs", "sql", re.compile(
        r"(?:\.query|\.execute|\.raw|cursor\.execute|sequelize\.query|knex\.raw)\s*\([^)]*(?:\$\{|\+|%\s*[\(%]|\.format\s*\(|f['\"])")),
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
    # actual HTML value is inspected below: only a whole-expression known sanitizer suppresses
    # that occurrence. Other controls remain unverified metadata beside the lead.
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

# Only a sanitizer applied to the whole value entering this sink establishes a control.
_XSS_SANITIZER = re.compile(r"DOMPurify|sanitize|bleach|escapeHtml|escapeHTML|encodeHTML|htmlspecialchars|he\.encode")
_HTML_CONTROLS = r"DOMPurify\.sanitize|sanitizeHtml|bleach\.clean|html\.escape|escapeHtml|escapeHTML|encodeHTML|htmlspecialchars|he\.encode|xss"
_COMMAND_CALL = re.compile(r"(?:child_process\.exec|execSync|exec|spawn|os\.(?:system|popen)|subprocess\.(?:run|call|check_output|Popen|getoutput|getstatusoutput))\s*\(")


def _literal(expression: str) -> bool:
    value = expression.strip()
    if len(value) < 2 or value[0] not in "\"'`" or value[-1] != value[0]:
        return False
    # A single quoted literal with no unescaped matching quote inside it.
    return not re.search(r"(?<!\\)" + re.escape(value[0]), value[1:-1]) and "${" not in value


def _xss_candidates(text: str):
    hits = {}
    for match in re.finditer(r"\.(?:inner|outer)HTML\s*=\s*(?!=)", text):
        end = expression_end(text, match.end())
        rhs = text[match.end():end].strip()
        if rhs and not _literal(rhs):
            hits[match.start()] = (text[match.start():end], rhs)
    for match in re.finditer(r"document\.write(?:ln)?\s*\(|\.insertAdjacentHTML\s*\(|\.html\s*\(", text):
        expression = call_expression(text, match.start())
        arg = expression[expression.find("(") + 1:-1].strip()
        if "insertAdjacentHTML" in expression:
            arg = arg.split(",", 1)[-1].strip()
        if arg and not _literal(arg):
            hits[match.start()] = (expression, arg)
    for match in re.finditer(r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*", text):
        end = expression_end(text, match.end())
        rhs = text[match.end():end].strip()
        if rhs and not _literal(rhs):
            hits[match.start()] = (text[match.start():end], rhs)
    for match in re.finditer(r"\bv-html\s*=\s*([\"'])(.*?)\1", text, re.S):
        if not _literal(match[2]):
            hits[match.start()] = (match[0], match[2])
    for match in re.finditer(r"\{@html\s+", text):
        end = expression_end(text, match.end())
        rhs = text[match.end():end].strip()
        if not _literal(rhs):
            hits[match.start()] = (text[match.start():end], rhs)
    # Retain server template escape-off and response patterns from the public signature map.
    for match in SINKS["xss"][2].finditer(text):
        if any(start <= match.start() < start + len(expr) for start, (expr, _) in hits.items()):
            continue
        if re.match(r"\{%|\||mark_safe|Markup|res\.", match[0]):
            expression = call_expression(text, match.start())
            hits[match.start()] = (expression, "")
    return sorted((start, expression, rhs) for start, (expression, rhs) in hits.items())


def _redirect_control(expression: str) -> bool:
    arguments = split_arguments(expression[expression.find("(") + 1:-1])
    options = direct_options(expression)
    if len(arguments) > 1 and arguments[-1].startswith("{"):
        options = direct_options("client(" + arguments[-1] + ")")
    if options.get("maxRedirects", "").strip() == "0":
        return True
    if any(options.get(key, "").strip() == "False" for key in ("allow_redirects", "follow_redirects")):
        return True
    # Callback names/return values alone do not stop axios redirects. The specific callback
    # must reject the destination and throw; complex callback/alias policies remain unverified.
    callback = options.get("beforeRedirect", "")
    match = re.match(r"\(?\s*(\w+)\s*\)?\s*=>\s*\{\s*if\s*\(\s*!", callback)
    return bool(match and re.search(r"\b" + re.escape(match[1]) + r"\.(?:href|host|hostname)\b", callback)
                and re.search(r"\)\s*(?:\{\s*)?throw\b", callback))


def _safe_host_redirect(text: str, start: int, expression: str) -> bool:
    # Narrow, single-assignment ternary binding: the exact redirected value must be constrained.
    prefix = text[:start]
    for match in re.finditer(r"(?:const|let)\s+(\w+)\s*=\s*(?:allowedHosts|trustedHosts)\.includes\((\w+)\)\s*\?\s*\2\s*:\s*(?:publicWebOrigin|publicOrigin)\s*;", prefix):
        if in_literal(prefix, match.start()):
            continue
        value = match[1]
        tail = prefix[match.end():]
        arguments = split_arguments(expression[expression.find("(") + 1:-1])
        target = arguments[-1].strip() if arguments else ""
        # The whole destination must be the guarded value. Merely mentioning it
        # beside a raw Host value (host + base) is not a validated derivation.
        exact_value = target == value
        fixed_template = bool(re.fullmatch(r"`https?://\$\{\s*" + re.escape(value)
                                           + r"\s*\}[^`$]*`", target))
        if ((exact_value or fixed_template)
                and not re.search(r"\b" + re.escape(value) + r"\s*=(?!=)|[{}]", tail)):
            return True
    return False


def _proxy_guard(text: str, start: int, expression: str) -> bool:
    prefix = text[:start]
    for match in re.finditer(r"const\s+(\w+)\s*=\s*(\w+)\.join\(\s*['\"]/['\"]\s*\)\s*;", prefix):
        value, segments = match[1], match[2]
        guard = re.compile(r"if\s*\(\s*" + re.escape(segments)
                           + r"\.includes\(\s*['\"]\.\.['\"]\s*\)\s*\)\s*(?:return|throw)\b[^;]*;\s*$")
        if (guard.search(prefix[:match.start()]) and prefix[match.end():].strip() in ("", "await")
                and re.search(r"\$\{\s*" + re.escape(value) + r"\s*\}", expression)):
            return True
    return False


# SSRF-via-redirect (REF-PENTEST #1): axios/requests FOLLOW redirects by DEFAULT, so an outbound
# client on a variable URL re-validates only the FIRST hop unless it pins maxRedirects:0 or adds a
# per-hop guard. Presence is unverified; _redirect_control checks the actual invocation.
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
# Host-header → redirect (open redirect / cache poisoning, CWE-601): a redirect Location/origin built
# from the attacker-controllable Host / X-Forwarded-Host header with no host allow-list comparison.
HOST_HEADER_READ = re.compile(
    r"(?:req|request|ctx)\.(?:headers?\s*[\[.]|get\s*\(\s*)['\"]?(?:x-forwarded-host|forwarded|host)\b"
    r"|headers\.get\s*\(\s*['\"](?:x-forwarded-host|host|forwarded)", re.I)
REDIRECT_SINK = re.compile(
    r"\.redirect\s*\(|NextResponse\.redirect|res\.setHeader\s*\(\s*['\"]Location|['\"]Location['\"]\s*[:,]|sendRedirect", re.I)
# SSRF-hardening: an outbound client DELIBERATELY following redirects with no host allow-list /
# private-range deny — a 30x to an internal/metadata host is then fetched server-side (CWE-918),
# independent of whether the INITIAL url is user-tainted. Reaches worker/job scripts the route scan misses.
FOLLOW_REDIR = re.compile(r"follow_redirects\s*=\s*True|allow_redirects\s*=\s*True|maxRedirects\s*:\s*[1-9]", re.I)
OUTBOUND_CLIENT = re.compile(r"\b(?:requests\.\w+|httpx\.\w+|\bfetch\s*\(|axios|got\s*\(|node-fetch|urllib\.request)", re.I)
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
        occurrences = []
        controls = []
        sql_budget = sql_flow.Budget()
        sql_analysis = {"candidate_files": 0, "nodes": 0, "errors": [], "unverified_queries": [],
                        "limitations": sql_flow.LIMITATIONS,
                        "limits": {"nodes_per_file": sql_flow.MAX_NODES, "scopes_per_file": sql_flow.MAX_SCOPES,
                                   "steps_per_file": sql_flow.MAX_STEPS, "bindings": sql_flow.MAX_BINDINGS,
                                   "occurrences_per_file": sql_flow.MAX_FINDINGS,
                                   "source_bytes_per_file": sql_flow.MAX_SOURCE_BYTES,
                                   "total_nodes": sql_flow.MAX_TOTAL_NODES, "total_steps": sql_flow.MAX_TOTAL_STEPS,
                                   "total_source_bytes": sql_flow.MAX_TOTAL_SOURCE_BYTES}}
        ssrf_redirect, proxy_escape, host_redirect, follows_redirect = [], [], [], []
        for _p, rel, raw in ctx.iter_code():
            if is_test_file(rel):
                continue
            text = without_comments(raw, _p.suffix.lower())
            service = service_for(stack.get("service_inventory", []), rel)
            local_datastores = set(service.get("datastores", datastores))
            local_sql = any("sql" in d or d in ("postgres", "mysql", "sqlite") for d in local_datastores)
            local_nosql = any(d in ("mongo", "dynamodb") for d in local_datastores)
            browser = not server_file(rel, text, is_client_file(rel, text))
            # Explicit request evidence overrides the coarse repository classification: an
            # unrecognized service/framework must not be hidden by another package's metadata.
            request_evidence = bool(re.search(_REQ_SRC, text))
            nonserver = browser or (is_script_file(rel) and not request_evidence)
            if (not request_evidence and rel.endswith(".py") and _PY_CLI.search(text)
                    and not _PY_WEB_FW.search(text)):
                nonserver = True
            if service:
                local_routes = any(service_for(stack["service_inventory"], r.get("code_path", "")).get("id") == service["id"]
                                   for r in (facts.get("routes") or {}).get("endpoints", []))
                local_no_web = bool(service.get("languages")) and not local_routes and not service.get("frameworks")
            else:
                local_no_web = no_web_surface
            no_request_surface = local_no_web and not request_evidence
            for cls, (_probe, gate, rx) in SINKS.items():
                if gate == "sql" and not local_sql and not request_evidence:
                    continue
                if gate == "nosql" and not local_nosql and not request_evidence:
                    continue
                if cls in _SERVER_REQUEST_CLASSES and (nonserver or no_request_surface):
                    continue
                if cls == "xss":
                    candidates = _xss_candidates(text)
                elif cls == "command-injection":
                    candidates = [(m.start(), call_expression(text, m.start()), "")
                                  for m in _COMMAND_CALL.finditer(text)
                                  if rx.search(call_expression(text, m.start()))]
                else:
                    candidates = [(m.start(), call_expression(text, m.start()), "") for m in rx.finditer(text)]
                seen = {}
                for start, expression, rhs in candidates:
                    control = "none observed"
                    if cls == "command-injection" and python_shell_safe(expression):
                        continue
                    if cls == "command-injection" and _p.suffix.lower() == ".java" and java_fixed_argv(expression):
                        continue
                    if cls == "xss" and rhs and direct_call(rhs, _HTML_CONTROLS, text[:start], program=text):
                        continue
                    if cls in ("ssrf", "ssrf-outbound-http") and REDIRECT_GUARD.search(text):
                        control = "unverified control: verify the redirect policy on this invocation"
                    if cls == "xss" and _XSS_SANITIZER.search(text):
                        control = "unverified control: sanitizer presence is not bound to this sink"
                    ordinal = seen.get(expression, 0)
                    seen[expression] = ordinal + 1
                    evidence = occurrence(text, start, expression, rel, cls, ordinal, control=control)
                    evidence["offset"] = start
                    if service:
                        evidence["service_id"] = service["id"]
                    occurrences.append(evidence)
                    if control.startswith("unverified"):
                        controls.append(evidence)
                    counts[cls] += 1
                    if rel not in found[cls] and len(found[cls]) < 60:
                        found[cls].append(rel)
            if _p.suffix.lower() == ".py":
                analysis = sql_flow.analyze(raw, sql_budget)
                sql_analysis["candidate_files"] += int(analysis["candidate"])
                sql_analysis["nodes"] += analysis["nodes"]
                for item in analysis["unverified_queries"]:
                    if len(sql_analysis["unverified_queries"]) < 50:
                        sql_analysis["unverified_queries"].append({"file": rel, **item})
                    else:
                        sql_analysis["unverified_queries_truncated"] = sql_analysis.get("unverified_queries_truncated", 0) + 1
                for error in analysis["errors"]:
                    if len(sql_analysis["errors"]) < 50:
                        sql_analysis["errors"].append({"file": rel, **error})
                    else:
                        sql_analysis["diagnostics_truncated"] = sql_analysis.get("diagnostics_truncated", 0) + 1
                seen_queries = {}
                for item in analysis["occurrences"]:
                    start, end = item["offset"], item["end"]
                    expression = raw[start:end]
                    ordinal = seen_queries.get(expression, 0)
                    seen_queries[expression] = ordinal + 1
                    # Legacy SQL regex starts at the receiver's dot, AST at its
                    # name. Match that exact call offset, not an enclosing call.
                    existing = next((row for row in occurrences if row["file"] == rel
                                     and row["sink_class"] == "sql-injection"
                                     and row.get("offset", -1) == item["legacy_offset"]), None)
                    evidence = existing or occurrence(raw, start, expression, rel, "sql-injection", ordinal)
                    evidence.update(source="Python request value reaches query text through bounded local assignment analysis",
                                    source_lines=item["source_lines"], assignment_lines=item["assignment_lines"],
                                    control_scope="unknown wrappers are not verified sanitizers; query bind values analyzed separately")
                    if existing is None:
                        evidence["offset"] = start
                        if service:
                            evidence["service_id"] = service["id"]
                        occurrences.append(evidence)
                        counts["sql-injection"] += 1
                        if rel not in found["sql-injection"] and len(found["sql-injection"]) < 60:
                            found["sql-injection"].append(rel)
            if not nonserver and not no_request_surface:
                outbound = []
                for kind in ("ssrf", "ssrf-outbound-http"):
                    outbound.extend(call_expression(text, m.start()) for m in SINKS[kind][2].finditer(text))
                if len(ssrf_redirect) < 40 and any(not _redirect_control(expr) for expr in outbound):
                    ssrf_redirect.append(rel)
                # A named path helper is not evidence that this proxy value was normalized.
                if len(proxy_escape) < 30 and PROXY_JOIN.search(text):
                    if any(not _proxy_guard(text, m.start(), call_expression(text, m.start()))
                           for m in PROXY_FETCH.finditer(text)):
                        proxy_escape.append(rel)
                if len(host_redirect) < 30 and HOST_HEADER_READ.search(text):
                    if any(not _safe_host_redirect(text, m.start(), call_expression(text, m.start()))
                           for m in REDIRECT_SINK.finditer(text)):
                        host_redirect.append(rel)
            if not browser and not no_request_surface and len(follows_redirect) < 30:
                # Check each outbound invocation separately; another safe client cannot bless it.
                if any(FOLLOW_REDIR.search(call_expression(text, m.start()))
                       and not _redirect_control(call_expression(text, m.start()))
                       for m in OUTBOUND_CLIENT.finditer(text)):
                    follows_redirect.append(rel)

        # The profile driver measures its named checks once during stack extraction.
        # Preserve its direct-language sink evidence in the shared findings contract.
        existing = {(item["file"], item.get("offset"), item["sink_class"]) for item in occurrences}
        for item in (stack.get("profiles") or {}).get("sink_occurrences", []):
            key = (item["file"], item.get("offset"), item["sink_class"])
            if key in existing:
                continue
            occurrences.append(item)
            cls = item["sink_class"]
            counts[cls] += 1
            if item["file"] not in found[cls] and len(found[cls]) < 60:
                found[cls].append(item["file"])
        sinks = {k: {"probe": SINKS[k][0], "count": counts[k], "files": found[k]}
                 for k in SINKS if counts[k]}
        sql_analysis["work"] = {"steps": sql_budget.steps, "source_bytes": sql_budget.source_bytes}
        return {
            **({"error": "Python query-flow candidate analysis incomplete; see sql_flow.errors"}
               if sql_analysis["errors"] else {}),
            "sql_flow": sql_analysis,
            "sinks": sinks,
            "sink_occurrences": occurrences,
            "unverified_controls": controls,
            "sink_counts": {k: counts[k] for k in SINKS if counts[k]},
            "ssrf_redirect_unguarded": ssrf_redirect,   # validate EVERY hop, not just the input URL (#1)
            "proxy_prefix_escape": proxy_escape,        # confined-deputy via `..` in catch-all path
            "host_header_redirect": host_redirect,      # open redirect via Host/X-Forwarded-Host
            "follows_redirect_no_allowlist": follows_redirect,  # SSRF-hardening (redirect-to-internal)
            "datastore_class": ("sql" if has_sql else ("nosql" if has_nosql else "unknown")),
            "note": "Source and sink hints are review leads, not verified exploitation. Direct signatures, "
                    "bounded Python query assignments and named language profiles have different limits. "
                    "Review each occurrence's provenance and service context; datastore labels alone do not establish safety.",
        }

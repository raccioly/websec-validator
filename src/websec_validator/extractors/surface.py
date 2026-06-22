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
}


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


class SurfaceExtractor(Extractor):
    name = "surface"
    category = "sinks"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        datastores = set((facts.get("stack") or {}).get("datastores", []))
        has_sql = any("sql" in d or d in ("postgres", "mysql", "sqlite") for d in datastores)
        has_nosql = any(d in ("mongo", "dynamodb") for d in datastores)

        found: dict = {k: [] for k in SINKS}
        counts: dict = {k: 0 for k in SINKS}
        ssrf_redirect: list = []    # SSRF sink in a file with NO per-hop redirect guard (#1)
        proxy_escape: list = []     # reverse-proxy prefix-escape (confined-deputy)
        for _p, rel, text in ctx.iter_code():
            # Test fixtures are never a runtime sink; SSRF + outbound-HTTP are SERVER-ONLY classes,
            # so client (.tsx/'use client') and build/CLI scripts can't host them (validated: these
            # were the entire ssrf false-positive set on a real LLM-agent monorepo).
            if is_test_file(rel):
                continue
            nonserver = is_client_file(rel, text) or is_script_file(rel)
            for cls, (_probe, gate, rx) in SINKS.items():
                if gate == "sql" and not has_sql:
                    continue
                if gate == "nosql" and not has_nosql:
                    continue
                if cls.startswith("ssrf") and nonserver:
                    continue
                if rx.search(text):
                    # command-injection precision: an argv-list subprocess with shell=False is safe —
                    # the dangerous form is shell=True or a concatenated command string.
                    if (cls == "command-injection" and re.search(r"shell\s*=\s*False", text)
                            and not re.search(r"shell\s*=\s*True", text)):
                        continue
                    counts[cls] += 1
                    if len(found[cls]) < 60:
                        found[cls].append(rel)
            if (len(ssrf_redirect) < 40 and not nonserver and not REDIRECT_GUARD.search(text)
                    and (SINKS["ssrf-outbound-http"][2].search(text) or SINKS["ssrf"][2].search(text))):
                ssrf_redirect.append(rel)
            # reverse-proxy prefix-escape: catch-all segments joined into a fixed-prefix upstream URL
            # with no dot-segment rejection (client .tsx excluded — the proxy is the server handler)
            if (len(proxy_escape) < 30 and not nonserver and PROXY_JOIN.search(text)
                    and PROXY_FETCH.search(text) and not DOTSEG_GUARD.search(text)):
                proxy_escape.append(rel)

        sinks = {k: {"probe": SINKS[k][0], "count": counts[k], "files": found[k]}
                 for k in SINKS if counts[k]}
        return {
            "sinks": sinks,
            "sink_counts": {k: counts[k] for k in SINKS if counts[k]},
            "ssrf_redirect_unguarded": ssrf_redirect,   # validate EVERY hop, not just the input URL (#1)
            "proxy_prefix_escape": proxy_escape,        # confined-deputy via `..` in catch-all path
            "datastore_class": ("sql" if has_sql else ("nosql" if has_nosql else "unknown")),
            "note": "Each sink hit is user-input-gated (req./request./concat/interp), so these are "
                    "higher-confidence leads. Cross-reference the files with routes.targeting to pick "
                    "the endpoint to probe. On a NoSQL/JSON API, SQLi alerts from generic scanners are "
                    "usually false positives.",
        }

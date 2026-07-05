"""Route / endpoint extractor — the spine of the attack surface.

Primary engine: **OWASP Noir** (owasp-noir/noir) — 50+ frameworks, real parsing
(Next.js App Router, Express, NestJS, Flask, FastAPI, Django, Rails, Go...),
emits method + path + typed params + code path. We shell out to it and parse its
JSON. If Noir isn't installed we fall back to a framework-aware regex pass so the
tool still produces something — but Noir is strongly preferred and the briefing
says so when it's missing.

We then DERIVE the high-value targeting signals that make probes precise:
  - write endpoints           → BOLA-write / mass-assignment targets
  - path-param endpoints      → IDOR / BOLA enumeration targets
  - url/domain-ish params     → SSRF candidates
  - redirect-ish params       → open-redirect candidates
  - file-upload params        → upload / path-traversal candidates
  - auth endpoints            → login surface
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from .base import SKIP_DIRS, Extractor, RepoContext, path_in_skip_dir

# Noir is a subprocess that scans the raw tree — it does NOT know the walker's SKIP_DIRS,
# so without this it grinds through (and emits routes from) build output (.next, cdk.out,
# dist), dependencies (node_modules, vendor), and NESTED WORKTREES (.claude/worktrees — a
# full copy of the repo → doubled routes). Pass the skip dirs as exclude globs (perf) AND
# post-filter Noir's output by code_path (the correctness guarantee).
_NOIR_SKIP_GLOBS = ",".join(f"**/{d}/**" for d in sorted(SKIP_DIRS))


def _in_skip_dir(code_path: str, root=None) -> bool:
    # Delegates to the shared, root-relative helper. Noir emits ABSOLUTE code_paths, so we MUST
    # pass the scan root — otherwise a repo under a skip-named ancestor (e.g. .claude/worktrees,
    # vendor/, target/) has EVERY route dropped (bug-005 recurrence; proven on a `target/` path).
    return path_in_skip_dir(code_path, root)

WRITE_VERBS = {"POST", "PUT", "PATCH", "DELETE"}
EXCLUDE_GLOBS = "*.test.ts,*.test.tsx,*.spec.ts,*.test.js,*.spec.js,*_test.go,*_test.py,test_*.py,*.stories.tsx"

# param-name heuristics → attack class
SSRF_NAMES = re.compile(r"^(url|uri|link|domain|host|endpoint|webhook|feed|rss|image|img|src|proxy|fetch|target|origin|site|address)s?$", re.I)
REDIRECT_NAMES = re.compile(r"^(redirect|redirect_?uri|next|return|return_?url|callback|continue|dest|destination|goto)s?$", re.I)
TRAVERSAL_NAMES = re.compile(r"^(file|filename|filepath|path|dir|folder|template|name|key|attachment|download|doc)s?$", re.I)

TEMPLATED = ("BASE_URL", "localhost", "127.0.0.1", "${", "{{")
ASSET_GLOB = re.compile(r"\*\.\w+")

# A route whose source file is a vendored/third-party API SPEC (OpenAPI/Swagger/GraphQL
# schema), not an app handler. Noir parses these and emits their paths as if the app
# served them — which on a repo that vendors e.g. a 16k-line swagger turns ~15 real
# findings into hundreds of phantom ones. We split these out as informational.
SPEC_PATH = re.compile(
    r"\.(?:ya?ml|graphql|gql|raml)$"                                  # spec file formats
    r"|(?:^|/)(?:node_modules|vendor|vendored|third[_-]?party|examples?|schemas?"
    r"|(?:docs?|documentation)[\w-]*)/"                               # vendor/docs/schema dirs
    r"|swagger|openapi|postman", re.I)         # postman_collection.json = an API spec, not a handler


def _is_spec_derived(code_path: str) -> bool:
    return bool(code_path) and bool(SPEC_PATH.search(code_path))


# A truly VENDORED spec lives under deps/build output; an app's OWN OpenAPI spec (a connexion / spec-first
# app like VAmPI, whose openapi3.yml IS the route list) sits in the source tree and IS implemented.
_VENDOR_DIR = re.compile(
    r"(?:^|/)(?:node_modules|vendor|vendored|third[_-]?party|\.venv|venv|site-packages|dist|build|\.next|out)/", re.I)


# --- Frontend API-CLIENT vs server HANDLER (real-repo FP in a combined frontend+backend monorepo,
# where Noir parsed the React app's axios API-client files (`src/api/*.ts`) and a Netlify
# `public/_redirects` as if they were SERVER endpoints, then every one flagged missing-auth. A
# frontend client CALLS the backend; it does not SERVE, so it has no auth guard and is not an endpoint.
# Server ROUTE DEFINITIONS — unambiguous receivers only. Deliberately NOT `api.`/`route.`/`server.`:
# `const api = axios.create(); api.get('/x')` is the idiomatic frontend CLIENT call, so `api.get`
# must NOT read as a server route (that was the bug that let the React api-client files survive).
SERVER_ROUTE_MARK = re.compile(
    r"\b(?:router|app|fastify|blueprint|bp)\s*\.\s*(?:get|post|put|patch|delete|use|all|options|route)\s*\("
    r"|@(?:Get|Post|Put|Patch|Delete|Controller)\("
    r"|@(?:app|router|bp|blueprint)\.(?:route|get|post|put|patch|delete)\b"
    r"|Deno\.serve|addEventListener\(\s*['\"]fetch|FastifyInstance"
    r"|export\s+(?:async\s+)?(?:function\s+)?(?:const\s+)?(?:GET|POST|PUT|PATCH|DELETE)\b"
    # serverless HANDLER conventions — a real server endpoint that may itself call fetch/axios, so it
    # must NOT be mistaken for a frontend client: Cloudflare Pages (onRequest*), Lambda/Netlify
    # (exports.handler / export const handler), Python Lambda (def handler / lambda_handler).
    r"|export\s+(?:async\s+)?(?:function\s+|const\s+)?onRequest\w*"
    r"|\bexports\.handler\b|export\s+(?:async\s+)?(?:function\s+|const\s+)?handler\b"
    r"|def\s+(?:handler|lambda_handler)\s*\(", re.I)
# A server FRAMEWORK import/construction — its presence means the file IS server-side even if it also
# calls an axios-ish instance (a route handler that forwards to another service), so don't drop it.
SERVER_IMPORT = re.compile(
    r"from\s+['\"](?:express|fastify|koa|@hapi/hapi|@nestjs/[\w-]+)['\"]|require\(\s*['\"](?:express|fastify|koa)['\"]"
    r"|from\s+(?:flask|fastapi|django|aiohttp|starlette)\b|import\s+(?:flask|fastapi)\b"
    r"|\bexpress\s*\(\s*\)|\bRouter\s*\(\s*\)|new\s+Hono\(|FastAPI\s*\(|Flask\s*\(", re.I)
# A frontend API CLIENT — an axios instance (imported or created) called by verb, RTK-Query/react-query,
# or an import of a local `./client` module. `import { api } from './client'; api.get(...)` is the tell.
CLIENT_API_MARK = re.compile(
    r"\bimport\s+axios|\baxios\.(?:create|get|post|put|patch|delete)\b|from\s+['\"]@tanstack"
    r"|useQuery\s*\(|useMutation\s*\(|createApi\s*\(|fetchBaseQuery|['\"]use client['\"]"
    r"|\b(?:api|apiClient|http|httpClient|client|axiosInstance|instance)\s*\.\s*(?:get|post|put|patch|delete)\s*\("
    r"|from\s+['\"][^'\"]*/client['\"]", re.I)
_NONCODE_ROUTE = re.compile(r"(?:^|/)_(?:redirects|headers)$|\.(?:toml|txt|md)$|(?:^|/)public/", re.I)


def _looks_nonserver_route(code_path: str, ctx) -> bool:
    """True if a Noir 'route' actually lives in a FRONTEND API client / static hosting config, not a
    server handler — so it must not become an endpoint (nor a missing-auth finding)."""
    if not code_path:
        return False
    from .base import is_client_file
    from pathlib import Path as _P
    try:
        rel = str(_P(code_path).resolve().relative_to(_P(ctx.root).resolve())).replace("\\", "/")
    except Exception:
        rel = code_path.replace("\\", "/")
    if _NONCODE_ROUTE.search(rel):
        return True                                  # _redirects / public/ / *.toml — hosting config
    if is_client_file(rel):
        return True                                  # .tsx/.jsx / components / 'use client'
    p = _P(code_path)
    try:
        text = ctx.text(p) if p.exists() else ""
    except Exception:
        text = ""
    # a file that makes OUTBOUND client calls, defines NO server route, and imports NO server framework
    # is an API client, not a handler.
    return bool(text and CLIENT_API_MARK.search(text)
                and not SERVER_ROUTE_MARK.search(text) and not SERVER_IMPORT.search(text))


def _clean_path(p: str) -> str:
    p = re.sub(r":(\w+)", r"{\1}", p)    # Express :id  -> {id}
    p = re.sub(r"\*(\w+)", r"{\1}", p)    # splat *key   -> {key}
    return p


def _is_noise(path: str) -> bool:
    if not path or not path.startswith("/"):
        return True
    if any(t in path for t in TEMPLATED):
        return True
    return bool(ASSET_GLOB.search(path))   # static-asset glob route (/*.png)


def _noir_scan(root: Path, extra_excludes: list | None = None) -> list | None:
    """Run Noir → list of endpoint dicts, or None if Noir unavailable/failed."""
    if not shutil.which("noir"):
        return None
    excl = ",".join([EXCLUDE_GLOBS, _NOIR_SKIP_GLOBS] + (list(extra_excludes) if extra_excludes else []))
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out = Path(tf.name)
    try:
        proc = subprocess.run(
            ["noir", "scan", str(root), "-f", "json", "-o", str(out),
             "--exclude-path", excl, "--no-log", "--no-color"],
            capture_output=True, text=True, timeout=300)
        if not out.exists():
            return None
        data = json.loads(out.read_text() or "{}")
        return data.get("endpoints", []) if isinstance(data, dict) else (data or [])
    except Exception:
        return None
    finally:
        try:
            out.unlink()
        except Exception:
            pass


def _normalize_noir(eps: list) -> tuple:
    """→ (app_routes, spec_derived_routes). Routes whose source file is a vendored API
    spec are split out so they don't generate phantom findings (B1)."""
    rows, spec, seen = [], [], set()
    for e in eps:
        if e.get("internal"):
            continue
        path = e.get("url") or e.get("path") or ""
        # Noir keeps Django <int:pk> / <str:name> notation — normalize to {pk}/{name}
        path = re.sub(r"<(?:[\w]+:)?([\w]+)>", r"{\1}", path)
        path = _clean_path(path)
        if _is_noise(path):
            continue
        method = (e.get("method") or "GET").upper()
        cp = (e.get("details", {}) or {}).get("code_paths") or [{}]
        code_path = cp[0].get("path", "")
        if (method, path, code_path) in seen:
            continue
        seen.add((method, path, code_path))
        row = {
            "method": method,
            "path": path,
            "params": [{"name": p.get("name", ""), "where": p.get("param_type", "")}
                       for p in (e.get("params") or [])],
            "technology": (e.get("details", {}) or {}).get("technology", ""),
            "code_path": code_path,
            "source": "noir",
        }
        (spec if _is_spec_derived(code_path) else rows).append(row)
    return rows, spec


# ---- generic router-call heuristic (ALWAYS runs — SUPPLEMENTS Noir + powers the fallback) ----
# Noir collapses hand-rolled routers (itty-router / Hono / Cloudflare Workers / custom dispatch) to
# ~1 endpoint; this fills the gap. Matches `<obj>.<verb>('/path', handler)` for ANY object name, and
# Hono's `<obj>.on('METHOD','/path')`. The leading-'/' on the path is the FP guard — so `arr.get('x')`
# / `el.on('click')` / `cache.get('k')` are NOT mistaken for routes.
ROUTER_CALL = re.compile(
    r"\b\w+\.(get|post|put|patch|delete|head|options|all)\s*\(\s*['\"`](/[^'\"`]*)['\"`]", re.I)
ROUTER_ON = re.compile(r"\b\w+\.on\s*\(\s*['\"]([A-Za-z]+)['\"]\s*,\s*['\"`](/[^'\"`]*)['\"`]")
# "handler-ish" signatures — ONLY for the coverage-confidence warning (handlers >> routes ⇒ discovery
# likely incomplete). Express (req,res), Hono/itty (c)=>, Workers fetch entrypoints.
HANDLER_SIG = re.compile(
    r"\(\s*req\s*,\s*res\b|\(\s*request\s*,\s*(?:res|reply|env|ctx|context)\b|\(\s*c\s*\)\s*=>"
    r"|async\s*\(\s*c\s*\)|\(\s*ctx\s*\)\s*=>|export\s+default\s*\{[^}]*\bfetch\b"
    r"|addEventListener\(\s*['\"]fetch['\"]|Deno\.serve\s*\(", re.I)

# Supabase Edge Functions: a supabase/functions/<name>/index.ts with a Deno.serve (or deno-std serve)
# handler is an HTTP endpoint at /functions/v1/<name>. Noir + the regex frameworks don't model
# Deno.serve, so without this every edge function is INVISIBLE (0 routes → no authz/tenant/probes).
_EDGE_INDEX = re.compile(r"supabase/functions/([^/]+)/index\.[tj]s$", re.I)
_DENO_METHOD = re.compile(r"req\.method\s*(?:!==?|===?)\s*['\"]([A-Za-z]+)['\"]")


def _supabase_edge_routes(ctx: RepoContext) -> list:
    rows = []
    for p in ctx.glob("supabase/functions/**/index.ts", 200) + ctx.glob("supabase/functions/**/index.js", 200):
        text = ctx.text(p)
        has_serve = "Deno.serve" in text or ("deno.land/std" in text and re.search(r"\bserve\s*\(", text))
        if not has_serve:
            continue
        m = _EDGE_INDEX.search(ctx.rel(p).replace("\\", "/"))
        if not m or m.group(1).startswith("_"):        # supabase/functions/_shared → helper, not a route
            continue
        methods = {mm.upper() for mm in _DENO_METHOD.findall(text)} - {"OPTIONS", "HEAD"}
        for method in (sorted(methods) or ["POST"]):    # Supabase invokes edge functions via POST
            rows.append({"method": method, "path": f"/functions/v1/{m.group(1)}", "params": [],
                         "technology": "supabase-edge", "code_path": ctx.rel(p), "source": "supabase-edge"})
    return rows


# AWS SAM / serverless — a template.yaml wires HTTP endpoints (Api/HttpApi events + Function URLs) to
# Lambda handlers. Noir doesn't model it AND routes.py used to EXCLUDE *.yaml as a "vendored spec", so
# a whole serverless backend went 0-routes/unprobed — incl. `FunctionUrlConfig: AuthType: NONE` PUBLIC
# endpoints serving sensitive data (real-repo FN: a real repo's dashboard, a real SAM backend's ~28
# handlers + AuthType:NONE LLM endpoints). Stdlib only — a bounded line/regex parse, not a YAML lib.
_SAM_FN = re.compile(r"Type:\s*AWS::Serverless::Function")
_SAM_HANDLER = re.compile(r"\bHandler:\s*([^\s#]+)")
_SAM_CODEURI = re.compile(r"\bCodeUri:\s*([^\s#]+)")
_SAM_GLOBAL_CODEURI = re.compile(r"Globals:[\s\S]{0,1200}?\bFunction:[\s\S]{0,800}?\bCodeUri:\s*([^\s#]+)")
_SAM_AUTHTYPE = re.compile(r"FunctionUrlConfig:[\s\S]{0,240}?AuthType:\s*([A-Za-z_]+)")
_SAM_API_EVENT = re.compile(r"Type:\s*(?:Api|HttpApi)\b([\s\S]{0,300}?)(?=Type:\s*\w|\Z)")
_SAM_PATH = re.compile(r"\bPath:\s*([^\s#]+)")
_SAM_METHOD = re.compile(r"\bMethod:\s*([^\s#]+)")
_HANDLER_EXTS = (".py", ".ts", ".js", ".mjs", ".tsx", ".rb", ".go")


def _resolve_sam_handler(ctx: RepoContext, tdir: str, codeuri: str, handler: str, relset: set) -> str:
    """Resolve a SAM Handler (`dir/file.export` or `pkg.module.func`) to a repo file path."""
    if not handler:
        return ""
    h = handler.strip().strip("'\"")
    mod = h.rsplit(".", 1)[0] if "/" in h else "/".join(h.split(".")[:-1] or [h])  # drop the export/func
    import posixpath as _pp
    prefixes = [_pp.join(tdir, codeuri) if codeuri else tdir, tdir, codeuri, ""]
    for pre in prefixes:
        for mod2 in (mod, mod.replace("dist/", "src/"), mod.replace("build/", "src/"), mod.replace("dist/", "")):
            base = _pp.normpath(_pp.join(pre, mod2)).lstrip("./") if pre else _pp.normpath(mod2).lstrip("./")
            for ext in _HANDLER_EXTS:
                if base + ext in relset:
                    return base + ext
    # fallback: any code file whose rel path ends with the full module + ext (avoids basename collisions)
    for mod2 in (mod, mod.replace("dist/", "src/"), mod.replace("dist/", "")):
        for r in relset:
            if any(r.endswith(mod2 + ext) for ext in _HANDLER_EXTS):
                return r
    return ""


def _sam_routes(ctx: RepoContext) -> list:
    import posixpath as _pp
    rows: list = []
    relset = {ctx.rel(p) for p in ctx.code_files}
    templates = ctx.glob("**/template.yaml", 40) + ctx.glob("**/template.yml", 40) + ctx.glob("**/sam.yaml", 20)
    for tmpl in templates[:40]:
        text = ctx.text(tmpl)
        if "AWS::Serverless::Function" not in text:
            continue
        tdir = _pp.dirname(ctx.rel(tmpl)).replace("\\", "/")
        gm = _SAM_GLOBAL_CODEURI.search(text)
        default_codeuri = gm.group(1).strip().strip("'\"") if gm else ""
        starts = [m.start() for m in _SAM_FN.finditer(text)]
        for i, s in enumerate(starts):
            block = text[s: starts[i + 1] if i + 1 < len(starts) else len(text)][:4000]
            hm = _SAM_HANDLER.search(block)
            handler = hm.group(1) if hm else ""
            cm = _SAM_CODEURI.search(block)
            codeuri = (cm.group(1).strip().strip("'\"") if cm else default_codeuri)
            code_path = _resolve_sam_handler(ctx, tdir, codeuri, handler, relset)
            seen_http = False
            for em in _SAM_API_EVENT.finditer(block):
                seg = em.group(1)
                pm, mm = _SAM_PATH.search(seg), _SAM_METHOD.search(seg)
                if not pm:
                    continue
                method = (mm.group(1).strip().strip("'\"").upper() if mm else "ANY")
                method = "GET" if method in ("ANY", "*") else method
                rows.append({"method": method, "path": pm.group(1).strip().strip("'\""), "params": [],
                             "technology": "aws-sam", "code_path": code_path, "source": "sam"})
                seen_http = True
            am = _SAM_AUTHTYPE.search(block)
            if am and not seen_http:                         # a Function URL (HTTP at /) with an explicit auth type
                rows.append({"method": "GET", "path": "/", "params": [], "technology": "aws-sam-funcurl",
                             "code_path": code_path, "source": "sam", "sam_auth_type": am.group(1)})
    return rows


def _router_calls(ctx: RepoContext) -> list:
    rows = []
    for _p, rel, text in ctx.iter_code():
        for verb, path in ROUTER_CALL.findall(text):
            rows.append({"method": "ANY" if verb.lower() == "all" else verb.upper(), "path": path,
                         "params": [], "technology": "router", "code_path": rel, "source": "router-heuristic"})
        for method, path in ROUTER_ON.findall(text):
            rows.append({"method": method.upper(), "path": path, "params": [],
                         "technology": "router", "code_path": rel, "source": "router-heuristic"})
    return rows


def _handler_signal_count(ctx: RepoContext) -> int:
    return sum(len(HANDLER_SIG.findall(text)) for _p, _rel, text in ctx.iter_code())


# ---- regex fallback (Noir absent — decorator/file frameworks the heuristic doesn't cover) ----

def _fallback(ctx: RepoContext) -> list:
    rows = []
    rows += _fallback_next_app_router(ctx)
    rows += _fallback_regex(ctx)
    rows += _router_calls(ctx)           # generic router calls (Express/itty/Hono/Workers)
    # clean + filter noise + de-dup on (method, path)
    seen, out = set(), []
    for r in rows:
        r["path"] = _clean_path(r["path"])
        if _is_noise(r["path"]):
            continue
        k = (r["method"], r["path"])
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def _fallback_next_app_router(ctx: RepoContext) -> list:
    rows = []
    # Handler exports in ALL Next App Router styles: `export async function GET`, `export const GET =`,
    # AND `export const { GET, POST } = makeRouteHandler(...)` (destructured factory re-export — Keystatic,
    # Auth.js, etc.). A route.ts IS a route by Next convention, so if none parse but it wires a route
    # handler, default to GET+POST rather than missing the endpoint (real-repo recall gap: a real Next.js app keystatic).
    method_rx = re.compile(r"export\s+(?:async\s+)?(?:function\s+|const\s+|let\s+)(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")
    destructured_rx = re.compile(r"export\s+const\s*\{\s*([^}]*)\}\s*=")
    verb_word = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")
    for p in ctx.glob("**/route.ts") + ctx.glob("**/route.js") + ctx.glob("**/route.tsx"):
        rel = ctx.rel(p)
        m = re.search(r"(?:^|/)(?:src/)?(?:app|pages)/(.*)/route\.[tj]sx?$", rel)
        if not m:
            continue
        seg = m.group(1)
        # strip a NESTED app/pages dir the outer match left in (a monorepo pkg named 'app' before the
        # real `src/app/` — e.g. a real Next.js app/app/src/app/api/... yielded '/src/app/api/...'); keep only the URL part
        seg = re.sub(r"^(?:src/)?(?:app|pages)/", "", seg)
        seg = re.sub(r"\(([^)]+)\)/?", "", seg)            # route groups (group)
        seg = re.sub(r"\[\.\.\.([^\]]+)\]", r"{\1}", seg)    # [...slug]
        seg = re.sub(r"\[([^\]]+)\]", r"{\1}", seg)          # [id]
        path = "/" + seg.strip("/")
        text = ctx.text(p)
        verbs = set(method_rx.findall(text))
        for dm in destructured_rx.finditer(text):
            verbs.update(verb_word.findall(dm.group(1)))
        if not verbs and re.search(r"RouteHandler|makeRoute\w*|createHandler|toNextJsHandler|\bhandlers?\b|NextResponse|new\s+Response", text):
            verbs = {"GET", "POST"}
        for verb in sorted(verbs):
            rows.append({"method": verb, "path": path, "params": [],
                         "technology": "js_nextjs", "code_path": rel, "source": "fallback"})
    return rows


def _fallback_regex(ctx: RepoContext) -> list:
    rows = []
    # `[^)]*?` (not `.*` with re.S) keeps the optional methods= group INSIDE this one route() call:
    # a greedy DOTALL `.*` reaches across the file to the LAST methods=[...], mis-assigning it to the
    # first route and silently swallowing every route in between (only routes after the final
    # methods=[...] survived). Staying within the call parens fixes both the mislabel and the drop.
    flask = re.compile(r"@\w+\.route\s*\(\s*['\"]([^'\"]+)['\"](?:[^)]*?methods\s*=\s*\[([^\]]*)\])?")
    fastapi = re.compile(r"@\w+\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)")
    for _p, rel, text in ctx.iter_code():
        for verb, path in fastapi.findall(text):
            rows.append({"method": verb.upper(), "path": path, "params": [],
                         "technology": "fastapi", "code_path": rel, "source": "fallback"})
        for path, methods in flask.findall(text):
            for verb in (re.findall(r"['\"](\w+)['\"]", methods) or ["GET"]):
                rows.append({"method": verb.upper(), "path": path, "params": [],
                             "technology": "flask", "code_path": rel, "source": "fallback"})
    return rows


def _derive(routes: list) -> dict:
    """Turn the route list into per-attack-class targeting the probes consume."""
    writes, idor, ssrf, redirect, upload, auth_eps = [], [], [], [], [], []
    for r in routes:
        sig = f"{r['method']} {r['path']}"
        if r["method"] in WRITE_VERBS:
            writes.append(sig)
        if "{" in r["path"] or any(p["where"] == "path" for p in r["params"]):
            idor.append(sig)
        if re.search(r"/(login|signin|sign-in|auth|token|session|oauth)\b", r["path"], re.I):
            auth_eps.append(sig)
        for p in r["params"]:
            nm = p["name"]
            if SSRF_NAMES.match(nm):
                ssrf.append(f"{sig}  (param: {nm})")
            elif REDIRECT_NAMES.match(nm):
                redirect.append(f"{sig}  (param: {nm})")
            elif p["where"] == "form" and TRAVERSAL_NAMES.match(nm):
                upload.append(f"{sig}  (param: {nm})")
    dedup = lambda xs: sorted(set(xs))
    return {"write_endpoints": dedup(writes), "idor_candidates": dedup(idor),
            "ssrf_candidates": dedup(ssrf), "open_redirect_candidates": dedup(redirect),
            "upload_candidates": dedup(upload), "auth_endpoints": dedup(auth_eps)}


class RoutesExtractor(Extractor):
    name = "routes"
    category = "surface"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        eps = _noir_scan(ctx.root, getattr(ctx, "excludes", None))
        if eps:                                    # noir ran AND found routes
            routes, spec_derived = _normalize_noir(eps)
            engine = "noir"
            # An app's OWN implemented OpenAPI spec (connexion / spec-first, e.g. VAmPI) IS its route
            # list — SPEC_PATH excludes it by the openapi/swagger filename, but when the spec is the ONLY
            # route source and not under a vendor/deps dir, promote it (else a whole spec-first API is
            # 0-routes/unprobed — caught by the proof harness: VAmPI 19 endpoints → 0).
            if not routes and spec_derived:
                own = [r for r in spec_derived
                       if not _VENDOR_DIR.search(str(r.get("code_path", "")).replace("\\", "/"))]
                if own:
                    routes = own
                    spec_derived = [r for r in spec_derived if r not in own]
                    engine = "noir (openapi-first: own spec is the route contract)"
        elif eps is not None:                      # noir ran but found ZERO — back it up with the regex
            fb = _fallback(ctx)                     # pass so a framework noir can't parse doesn't become a
            routes, spec_derived = fb, []           # silent blind spot (0 routes → no authz, no probes)
            engine = "noir (0 routes) → regex-fallback backstop" if fb else "noir (0 routes)"
        else:                                      # noir absent
            routes, spec_derived = _fallback(ctx), []
            engine = "regex-fallback (install OWASP Noir for full coverage: brew install noir)"
        # honor user --exclude against route code_paths too (Noir's own --exclude-path glob is
        # unreliable for bare dir names; this guarantees `--exclude <path>` drops those routes).
        if getattr(ctx, "excludes", None):
            routes = [r for r in routes if not ctx._excluded(r.get("code_path", ""))]
        # Noir doesn't honor SKIP_DIRS — drop any route it found under build output / deps /
        # nested worktrees (e.g. .claude/worktrees/* doubling the whole app). Pass ctx.root so
        # SKIP_DIRS is matched RELATIVE to the scan root (a skip-named ANCESTOR must not nuke
        # the whole route list).
        routes = [r for r in routes if not _in_skip_dir(r.get("code_path", ""), ctx.root)]
        # Drop routes that actually live in FRONTEND API-client code / static hosting config (Noir
        # can't tell a React axios client from a server handler in a combined frontend+backend repo).
        _client_routes = [r for r in routes if _looks_nonserver_route(r.get("code_path", ""), ctx)]
        _client_excluded = len(_client_routes)
        if _client_routes:
            _cr = {id(r) for r in _client_routes}
            routes = [r for r in routes if id(r) not in _cr]

        # P1: when NOIR produced the routes, SUPPLEMENT with the generic router-call heuristic — Noir
        # collapses hand-rolled routers (itty/Hono/Workers) to ~1 endpoint, so without this the entire
        # dynamic half no-ops. (The fallback path already includes the heuristic.) Dedupe on (method,path).
        if eps:
            existing = {(r["method"], r["path"]) for r in routes}
            _excl = getattr(ctx, "excludes", None)
            for r in _router_calls(ctx):
                r["path"] = _clean_path(r["path"])
                if _is_noise(r["path"]) or _in_skip_dir(r.get("code_path", ""), ctx.root):
                    continue
                if _excl and ctx._excluded(r.get("code_path", "")):
                    continue
                k = (r["method"], r["path"])
                if k not in existing:
                    existing.add(k)
                    routes.append(r)

        # Supabase Edge Functions (Deno.serve) — synthesize /functions/v1/<name> routes in EVERY
        # engine path (noir-found, noir-zero, noir-absent), since none of them model Deno.serve.
        edge_existing = {(r["method"], r["path"]) for r in routes}
        for r in _supabase_edge_routes(ctx):
            if getattr(ctx, "excludes", None) and ctx._excluded(r.get("code_path", "")):
                continue
            k = (r["method"], r["path"])
            if k not in edge_existing:
                edge_existing.add(k)
                routes.append(r)
                if engine.startswith("noir (0 routes)"):
                    engine = "noir (0 routes) → supabase-edge"

        # AWS SAM / serverless — Api/HttpApi events + Function URLs → real HTTP routes (none of the
        # engines above model template.yaml). Deduped on (method, path); a Function-URL AuthType is kept.
        sam_existing = {(r["method"], r["path"]) for r in routes}
        sam_public = 0
        for r in _sam_routes(ctx):
            if getattr(ctx, "excludes", None) and ctx._excluded(r.get("code_path", "")):
                continue
            k = (r["method"], r["path"])
            if k in sam_existing:
                continue
            sam_existing.add(k)
            routes.append(r)
            if str(r.get("sam_auth_type", "")).upper() == "NONE":
                sam_public += 1
            if engine.startswith(("noir (0 routes)", "regex-fallback")):
                engine += " + aws-sam"

        by_method: dict = {}
        by_tech: dict = {}
        for r in routes:
            by_method[r["method"]] = by_method.get(r["method"], 0) + 1
            by_tech[r["technology"]] = by_tech.get(r["technology"], 0) + 1
        # P1: surface-coverage confidence — many handler-ish fns but few routes ⇒ discovery likely
        # INCOMPLETE (hand-rolled / dynamic routing). An empty §3 then means "unmapped", not "clean".
        handler_sigs = _handler_signal_count(ctx)
        coverage_warning = None
        if handler_sigs >= 5 and len(routes) <= handler_sigs // 3:
            coverage_warning = (f"⚠ surface-coverage: mapped {len(routes)} route(s) but found ~{handler_sigs} "
                                "handler-ish function(s) — route discovery is likely INCOMPLETE (a hand-rolled or "
                                "dynamic router the engine can't follow). Treat empty §3 candidate lists as "
                                "\"couldn't map\", NOT \"nothing there\" — map routes by hand before trusting the probes.")
        out = {
            "engine": engine,
            "count": len(routes),
            "by_method": by_method,
            "by_technology": by_tech,
            "endpoints": routes,
            "targeting": _derive(routes),
            "handler_signals": handler_sigs,
            "coverage_warning": coverage_warning,
            "client_routes_excluded": _client_excluded,
            "serverless_public_endpoints": sam_public,   # Function URLs with AuthType: NONE (unauthenticated)
        }
        if spec_derived:
            from collections import Counter
            srcs = Counter(r["code_path"] for r in spec_derived)
            out["spec_derived_excluded"] = len(spec_derived)
            out["spec_derived_sources"] = [f"{n}× {f}" for f, n in srcs.most_common(8)]
            out["note"] = (f"⚠ {len(spec_derived)} routes came from vendored API SPEC files "
                           f"(OpenAPI/Swagger/GraphQL), not app handlers — EXCLUDED from the {len(routes)} "
                           f"app routes + all findings. Sources: {', '.join(f for f, _ in srcs.most_common(5))}.")
        return out

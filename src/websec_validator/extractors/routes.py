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
    r"|addEventListener\(\s*['\"]fetch['\"]", re.I)


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
    method_rx = re.compile(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")
    for p in ctx.glob("**/route.ts") + ctx.glob("**/route.js") + ctx.glob("**/route.tsx"):
        rel = ctx.rel(p)
        m = re.search(r"(?:^|/)(?:src/)?(?:app|pages)/(.*)/route\.[tj]sx?$", rel)
        if not m:
            continue
        seg = m.group(1)
        seg = re.sub(r"\(([^)]+)\)/?", "", seg)            # route groups (group)
        seg = re.sub(r"\[\.\.\.([^\]]+)\]", r"{\1}", seg)    # [...slug]
        seg = re.sub(r"\[([^\]]+)\]", r"{\1}", seg)          # [id]
        path = "/" + seg.strip("/")
        for verb in method_rx.findall(ctx.text(p)):
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

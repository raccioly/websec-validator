"""OpenAPI contract analysis — shadow endpoints + spec hygiene.

Two things, both static and both derived from artefacts websec already walks:

  1. **Shadow / undocumented endpoints** — routes that exist in CODE but are absent from the OpenAPI
     spec. Akto and friends find these by diffing observed TRAFFIC against the spec; doing it from
     SOURCE is strictly better (no traffic needed, and it catches an endpoint before it ever ships).
     An undocumented endpoint is a classic breach path: it skipped the review the documented ones got,
     and gateway/WAF policies keyed on the spec do not cover it. The reverse (in spec, not in code) is
     reported too — a stale contract misleads clients and security review alike.

  2. **Spec hygiene** — a checklist of contract-level weaknesses (operations with no `security`, plain
     `http://` servers, no security schemes declared at all).

DELIBERATELY NOT a 42Crunch-style precise 0-100 score. That number would have to come from a
regex-parsed YAML (websec ships zero runtime dependencies, so there's no YAML parser), and an
authoritative-looking score computed from a partial parse invites exactly the false confidence this
tool exists to prevent. A checklist that says what it checked — and admits when the parse was partial —
is the honest artefact. JSON specs are parsed fully; YAML gets a bounded regex pass, clearly labelled.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from .extractors.base import MAX_WALK_FILES, RepoContext

_SPEC_NAMES = re.compile(r"(openapi|swagger)[\w.-]*\.(json|ya?ml)$", re.I)
_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
# YAML fallback: a path key at 2-space indent under `paths:`, then method keys under it.
_YAML_PATH = re.compile(r"^\s{0,4}(/[^\s:]*)\s*:\s*$")
_YAML_METHOD = re.compile(r"^\s{2,8}(" + "|".join(_HTTP_METHODS) + r")\s*:\s*$", re.I)
_YAML_SECURITY = re.compile(r"^\s*security\s*:", re.M)
_YAML_SCHEMES = re.compile(r"^\s*(securitySchemes|securityDefinitions)\s*:", re.M)
_HTTP_SERVER = re.compile(r"url\s*:\s*[\"']?(http://[^\s\"',]+)", re.I)


def find_specs(target: Path, limit: int = 10, *, context: RepoContext | None = None) -> list:
    """Locate OpenAPI/Swagger specs in the repo (bounded, skips vendored/dep dirs)."""
    out = []
    ctx = context or RepoContext(Path(target))
    for p in ctx.glob("**/*", MAX_WALK_FILES):
        if not _SPEC_NAMES.search(p.name):
            continue
        if len(out) >= limit:
            ctx.glob_truncated.append({"pattern": "OpenAPI/Swagger specs", "limit": limit})
            break
        out.append(p)
    return out


def parse(path: Path, *, context: RepoContext | None = None) -> dict:
    """→ {ok, mode, paths:{path:[methods]}, ops_without_security, has_schemes, insecure_servers}.

    `ok=False` (with `reason`) when the file is NOT usable as a contract — unreadable, not valid
    JSON/YAML, or valid but not actually a spec (`{}`, a config that merely matched the filename).
    That distinction is load-bearing: a file we could not parse yields ZERO paths, and a zero-path
    "spec" silently becomes an authoritative empty contract — which makes every implemented route
    look undocumented (a flood of false shadow endpoints) or, on a repo with no routes, produces a
    false all-clear. No verdict is better than a wrong verdict, so callers must skip these."""
    res = {"file": str(path), "ok": False, "reason": "", "mode": "", "paths": {},
           "ops_without_security": [], "has_schemes": False, "insecure_servers": [],
           "global_security": False}
    path = Path(path).absolute()
    ctx = context or RepoContext(path.parent, walk=False)
    text = ctx.text(path)
    if not text:
        res["reason"] = "unreadable"
        return res
    if path.suffix.lower() == ".json":
        try:
            doc = json.loads(text)
        except ValueError:
            res["reason"] = "not valid JSON"
            return res
        if not isinstance(doc, dict):
            res["reason"] = "JSON is not an object"
            return res
        # must actually LOOK like a spec: a version marker, or a non-empty paths object.
        if not (doc.get("openapi") or doc.get("swagger") or (doc.get("paths") or {})):
            res["reason"] = "no `openapi`/`swagger` version key and no `paths` — not an API spec"
            return res
        res.update(mode="json", ok=True)
        comps = (doc.get("components") or {})
        res["has_schemes"] = bool(comps.get("securitySchemes") or doc.get("securityDefinitions"))
        res["global_security"] = bool(doc.get("security"))
        for s in (doc.get("servers") or []):
            u = str((s or {}).get("url", ""))
            if u.startswith("http://"):
                res["insecure_servers"].append(u)
        for p, item in (doc.get("paths") or {}).items():
            if not isinstance(item, dict):
                continue
            methods = [m for m in _HTTP_METHODS if m in item]
            res["paths"][p] = methods
            for m in methods:
                op = item.get(m) or {}
                # an operation is unauthenticated if it neither declares `security` nor inherits a
                # global one — or explicitly opts out with `security: []`
                sec = op.get("security", None)
                if sec == [] or (sec is None and not res["global_security"]):
                    res["ops_without_security"].append(f"{m.upper()} {p}")
        return res

    # YAML: bounded regex pass (no YAML parser in a zero-dependency tool) — PARTIAL by construction.
    # Same "is it really a spec?" gate as JSON: a `paths:` section or an openapi/swagger version key.
    # Without it we'd accept arbitrary YAML (or garbage) as an empty contract — see the docstring.
    if not (re.search(r"^\s{0,2}paths\s*:", text, re.M)
            or re.search(r"^\s*(openapi|swagger)\s*:", text, re.M)):
        res["reason"] = "no `paths:` section and no `openapi:`/`swagger:` key — not an API spec"
        return res
    res.update(mode="yaml-partial", ok=True)
    res["has_schemes"] = bool(_YAML_SCHEMES.search(text))
    res["insecure_servers"] = _HTTP_SERVER.findall(text)[:10]
    in_paths = False
    current = None
    for line in text.splitlines():
        if re.match(r"^\s{0,2}paths\s*:\s*$", line):
            in_paths = True
            continue
        if in_paths and re.match(r"^[A-Za-z]", line):        # dedented to a new top-level key
            in_paths = False
        if not in_paths:
            continue
        mp = _YAML_PATH.match(line)
        if mp:
            current = mp.group(1)
            res["paths"].setdefault(current, [])
            continue
        mm = _YAML_METHOD.match(line)
        if mm and current:
            res["paths"][current].append(mm.group(1).lower())
    return res


def _norm(p: str) -> str:
    """Normalize a path for comparison: {id}/:id/<id> → {}, strip trailing slash + basePath noise."""
    s = (p or "").strip()
    s = re.sub(r"\{[^}]*\}", "{}", s)
    s = re.sub(r":([A-Za-z_]\w*)", "{}", s)
    s = re.sub(r"<[^>]*>", "{}", s)
    s = s.rstrip("/") or "/"
    return s.lower()


def analyze(facts: dict, target, *, context: RepoContext | None = None) -> dict:
    """→ {specs:[…], shadow:[…], stale:[…], hygiene:[…], summary:{…}}."""
    ctx = context or RepoContext(Path(target), (facts.get("coverage") or {}).get("files", {}).get("excludes"))
    parsed = [parse(p, context=ctx) for p in find_specs(Path(target), context=ctx)]
    specs = [s for s in parsed if s["ok"]]
    # Files that LOOK like a spec by filename but aren't usable. Disclosed, never silently ignored —
    # if the only spec in a repo is unreadable, "0 undocumented endpoints" would be a false all-clear.
    unreadable = [{"file": s["file"], "reason": s["reason"]} for s in parsed if not s["ok"]]
    if not specs:
        return {"specs": [], "shadow": [], "stale": [], "hygiene": [], "unreadable": unreadable,
                "summary": {"specs": 0, "shadow": 0, "stale": 0, "unreadable": len(unreadable)}}

    # A spec that parses but declares NO paths (a stub with only a version/info block) cannot serve
    # as a contract: diffing against it makes every implemented route look undocumented. Treat it
    # like an unusable spec — disclose it, emit no verdict.
    pathless = [s for s in specs if not s["paths"]]
    specs = [s for s in specs if s["paths"]]
    for s_ in pathless:
        unreadable.append({"file": s_["file"], "reason": "parses, but declares no `paths` — cannot be "
                                                         "used as a contract to diff against"})
    if not specs:
        return {"specs": [], "shadow": [], "stale": [], "hygiene": [], "unreadable": unreadable,
                "summary": {"specs": 0, "shadow": 0, "stale": 0, "unreadable": len(unreadable)}}

    spec_ops: set = set()
    for s in specs:
        for p, methods in s["paths"].items():
            for m in (methods or [None]):
                spec_ops.add((m.upper() if m else "", _norm(p)))
    spec_paths = {p for _m, p in spec_ops}

    code_ops = []
    for ep in (facts.get("routes", {}) or {}).get("endpoints", []) or []:
        code_ops.append((str(ep.get("method", "")).upper(), _norm(ep.get("path", "")),
                         f"{ep.get('method')} {ep.get('path')}"))

    shadow = []
    for m, p, label in code_ops:
        if p in spec_paths and ((m, p) in spec_ops or not any(mm for mm, pp in spec_ops if pp == p)):
            continue                                          # documented (method-level or path-level)
        if p not in spec_paths:
            shadow.append(label)
        elif (m, p) not in spec_ops:
            shadow.append(f"{label}  (path documented, METHOD is not)")
    code_paths = {p for _m, p, _l in code_ops}
    stale = sorted({f"{m or 'ANY'} {p}" for m, p in spec_ops if p not in code_paths})

    hygiene = []
    for s in specs:
        name = Path(s["file"]).name
        if not s["has_schemes"]:
            hygiene.append(f"`{name}`: no security schemes declared "
                           "(`components.securitySchemes`) — the contract never says how to authenticate")
        if s["insecure_servers"]:
            hygiene.append(f"`{name}`: plaintext server URL(s): {', '.join(s['insecure_servers'][:3])}")
        if s["mode"] == "json" and s["ops_without_security"]:
            ops = s["ops_without_security"]
            hygiene.append(f"`{name}`: {len(ops)} operation(s) with no `security` and no global default "
                           f"— e.g. {', '.join(ops[:3])}")
    return {"specs": [{"file": s["file"], "mode": s["mode"], "paths": len(s["paths"])} for s in specs],
            "shadow": sorted(set(shadow)), "stale": stale, "hygiene": hygiene,
            "unreadable": unreadable,
            "summary": {"specs": len(specs), "shadow": len(set(shadow)), "stale": len(stale),
                        "unreadable": len(unreadable),
                        "partial_parse": any(s["mode"] == "yaml-partial" for s in specs)}}


def _unreadable_md(res: dict) -> str:
    bad = res.get("unreadable") or []
    if not bad:
        return ""
    rows = "\n".join(f"- `{Path(b['file']).name}` — {b['reason']}" for b in bad[:10])
    return ("\n**⚠ Spec file(s) found but NOT usable as a contract** — excluded from the diff, because "
            "treating an unparsed spec as an empty one would make every route look undocumented (or "
            "produce a false all-clear). Fix or remove these, then re-run:\n" + rows + "\n")


def render_md(res: dict, limit: int = 20) -> str:
    if not res.get("specs"):
        if res.get("unreadable"):
            return ("_No USABLE OpenAPI/Swagger spec — shadow-endpoint analysis was SKIPPED (no verdict "
                    "is better than a wrong one)._\n" + _unreadable_md(res))
        return "_No OpenAPI/Swagger spec found — nothing to diff the implemented routes against._"
    s = res["summary"]
    out = [f"Found **{s['specs']} spec(s)**. **{s['shadow']} undocumented endpoint(s)** in code · "
           f"{s['stale']} documented-but-absent."]
    if s.get("partial_parse"):
        out.append("\n_⚠ A YAML spec was parsed with a bounded regex (websec ships no YAML "
                   "dependency), so its operation-level results are PARTIAL — paths are reliable, "
                   "per-operation `security` is not checked for YAML._")
    if res["shadow"]:
        out.append("\n**⚠ Undocumented (shadow) endpoints — in code, absent from the spec.** These "
                   "skipped the review the documented ones got, and any gateway/WAF policy keyed on "
                   "the spec does not cover them:\n")
        out += [f"- `{x}`" for x in res["shadow"][:limit]]
    if res["stale"]:
        out.append("\n**Documented but not found in code** (stale contract — misleads clients and "
                   "reviewers):\n")
        out += [f"- `{x}`" for x in res["stale"][:limit]]
    if res["hygiene"]:
        out.append("\n**Contract hygiene:**\n")
        out += [f"- {h}" for h in res["hygiene"]]
    um = _unreadable_md(res)
    if um:
        out.append(um)
    return "\n".join(out)


# --- Spec-first apps: resolve an operation to the code that implements it ---------------------
# A connexion/spec-first API (VAmPI is the corpus example) has its OpenAPI document promoted to the
# route list, because the spec IS the route contract — without that promotion the whole API reads as
# zero routes. But the authz extractor then received the SPEC as each route's "handler file" and
# looked for `requireAuth`/`@login_required` inside YAML. A spec never contains those, so every
# route came back unguarded: on VAmPI that produced 12 missing-auth findings, of which the 6 whose
# handlers DO validate a token inline were false. Asserting "no auth guard found in handler
# openapi3.yml" is a statement about a file that is not a handler.
#
# Two signals recover the truth, in order of strength:
#   1. `operationId: api_views.users.me` — a dotted path to the implementing function. Resolved to a
#      real file, the existing guard detection runs against actual code.
#   2. `security:` on the operation — the contract's own auth declaration, used when (1) cannot be
#      resolved.
# When neither is available the caller must treat the route as NOT ANALYSED rather than unguarded.
_YAML_OPERATION_ID = re.compile(r"^\s*operationId\s*:\s*['\"]?([\w.\-/]+)['\"]?\s*$")
_YAML_SECURITY_KEY = re.compile(r"^\s*security\s*:\s*(\[\s*\])?\s*$")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def operation_map(path: Path, *, context: RepoContext | None = None) -> dict:
    """→ {(path, METHOD): {"operation_id": str|None, "declares_security": bool}}.

    JSON specs are parsed exactly. YAML uses a RELATIVE-indent walk (path shallower than method,
    method shallower than its keys) rather than fixed column counts, because real specs vary — the
    corpus spec puts operation keys at 6 spaces under one path and 8 under another. Anything the
    walk cannot place is simply absent from the result: a missing entry means "unknown", which the
    caller must not read as "unauthenticated".
    """
    try:
        text = context.text(path) if context is not None else path.read_text(errors="replace")
    except Exception:
        return {}
    if not text:
        return {}
    out: dict = {}
    stripped = text.lstrip()
    if stripped.startswith("{"):
        import json as _json
        try:
            doc = _json.loads(text)
        except Exception:
            return {}
        has_global = bool(doc.get("security"))
        for route, ops in (doc.get("paths") or {}).items():
            if not isinstance(ops, dict):
                continue
            for method, op in ops.items():
                if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                    continue
                declared = op.get("security", None)
                out[(route, method.upper())] = {
                    "operation_id": op.get("operationId"),
                    "declares_security": bool(declared) or (declared is None and has_global)}
        return out

    route = method = None
    route_indent = method_indent = -1
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = _indent(line)
        match = _YAML_PATH.match(line)
        if match:
            route, route_indent = match.group(1), indent
            method, method_indent = None, -1
            continue
        if route is None:
            continue
        if indent <= route_indent:          # dedented out of this path's block
            route, method = None, None
            continue
        match = _YAML_METHOD.match(line)
        if match and (method_indent < 0 or indent <= method_indent):
            method, method_indent = match.group(1).upper(), indent
            out.setdefault((route, method), {"operation_id": None, "declares_security": False})
            continue
        if method is None or indent <= method_indent:
            continue
        entry = out.setdefault((route, method), {"operation_id": None, "declares_security": False})
        match = _YAML_OPERATION_ID.match(line)
        if match:
            entry["operation_id"] = match.group(1)
        elif _YAML_SECURITY_KEY.match(line):
            # `security: []` is an explicit OPT-OUT, not a guard.
            entry["declares_security"] = not line.rstrip().endswith("[]")
    return out


def resolve_operation_file(operation_id: str, rel_paths) -> str:
    """`api_views.users.me` → `api_views/users.py` when that file exists in the walked repo.

    Matches the longest dotted prefix that maps to a real file, so the trailing function name is
    dropped without guessing how many trailing segments are attributes. Returns "" when nothing
    matches — the caller must then treat the route as unresolved, never as unguarded.
    """
    if not operation_id:
        return ""
    known = {str(p).replace("\\", "/") for p in rel_paths}
    parts = [p for p in re.split(r"[.\-/]", operation_id) if p]
    for cut in range(len(parts) - 1, 0, -1):
        stem = "/".join(parts[:cut])
        for suffix in (".py", ".js", ".ts", ".mjs", ".rb", ".go"):
            if stem + suffix in known:
                return stem + suffix
        for index in ("__init__.py", "index.js", "index.ts"):
            if f"{stem}/{index}" in known:
                return f"{stem}/{index}"
    return ""

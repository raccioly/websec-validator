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

_SPEC_NAMES = re.compile(r"(openapi|swagger)[\w.-]*\.(json|ya?ml)$", re.I)
_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
# YAML fallback: a path key at 2-space indent under `paths:`, then method keys under it.
_YAML_PATH = re.compile(r"^\s{0,4}(/[^\s:]*)\s*:\s*$")
_YAML_METHOD = re.compile(r"^\s{2,8}(" + "|".join(_HTTP_METHODS) + r")\s*:\s*$", re.I)
_YAML_SECURITY = re.compile(r"^\s*security\s*:", re.M)
_YAML_SCHEMES = re.compile(r"^\s*(securitySchemes|securityDefinitions)\s*:", re.M)
_HTTP_SERVER = re.compile(r"url\s*:\s*[\"']?(http://[^\s\"',]+)", re.I)


def find_specs(target: Path, limit: int = 10) -> list:
    """Locate OpenAPI/Swagger specs in the repo (bounded, skips vendored/dep dirs)."""
    out = []
    skip = {"node_modules", ".git", "dist", "build", "vendor", ".venv", "venv", "websec-out"}
    try:
        for p in Path(target).rglob("*"):
            if len(out) >= limit:
                break
            if not p.is_file() or not _SPEC_NAMES.search(p.name):
                continue
            if any(part in skip for part in p.parts):
                continue
            out.append(p)
    except OSError:
        pass
    return out


def parse(path: Path) -> dict:
    """→ {ok, mode, paths:{path:[methods]}, ops_without_security, has_schemes, insecure_servers}."""
    res = {"file": str(path), "ok": False, "mode": "", "paths": {}, "ops_without_security": [],
           "has_schemes": False, "insecure_servers": [], "global_security": False}
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return res
    if path.suffix.lower() == ".json":
        try:
            doc = json.loads(text)
        except ValueError:
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


def analyze(facts: dict, target) -> dict:
    """→ {specs:[…], shadow:[…], stale:[…], hygiene:[…], summary:{…}}."""
    specs = [parse(p) for p in find_specs(Path(target))]
    specs = [s for s in specs if s["ok"]]
    if not specs:
        return {"specs": [], "shadow": [], "stale": [], "hygiene": [],
                "summary": {"specs": 0, "shadow": 0, "stale": 0}}

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
            "summary": {"specs": len(specs), "shadow": len(set(shadow)), "stale": len(stale),
                        "partial_parse": any(s["mode"] == "yaml-partial" for s in specs)}}


def render_md(res: dict, limit: int = 20) -> str:
    if not res.get("specs"):
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
    return "\n".join(out)

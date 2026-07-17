"""Finding enrichment — reachability + exploitability, both DETERMINISTIC and OFFLINE.

Two enrichers run over the de-duplicated scanner findings (scanners.normalize_findings). Both are
STRICTLY ADDITIVE — they attach metadata and annotate the human-readable title, but NEVER change a
finding's severity, NEVER drop a finding, and NEVER add one. So they can only sharpen triage, never
reintroduce a false positive (the no-regression bar).

  - reachability : for a dependency CVE, is the vulnerable PACKAGE actually imported in first-party
                   source? "declared-only" (in the lockfile but never imported) is the industry's #1
                   noise class (Snyk/Endor/Semgrep converge here). Name-based + offline: a real
                   call-graph is out of model; this is the cheap, honest approximation.
  - exploitability : join each CVE against a LOCAL cache of FIRST.org EPSS (exploit probability) +
                   CISA KEV (known-exploited). The "priority score" commercial tools sell, minus the
                   cloud. Cache is refreshed by scripts/refresh-epss-kev.sh; absent cache → skipped.

Stdlib only. No network here — the EPSS/KEV *refresh* is a separate opt-in step; this module only
READS whatever cache is already on disk.
"""

from __future__ import annotations

import csv
import json
import os
import re
from pathlib import Path

from .extractors.base import RepoContext

# ── reachability ────────────────────────────────────────────────────────────────────────────────
# Ecosystems whose imports we can parse. A CVE in a go/cargo/etc. package is tagged "n/a" (we make
# NO reachability claim rather than a wrong one) — trivy's Result.Type feeds `ecosystem`.
_JS_ECO = {"npm", "yarn", "pnpm", "node-pkg", "nodejs"}
_PY_ECO = {"pip", "pypi", "python-pkg", "poetry", "pipenv"}

# JS/TS module specifiers: require('x') / from 'x' / import 'x' / import('x'). Relative ('./', '/')
# specifiers are dropped by the root extractor below.
_JS_SPEC = re.compile(r"""(?:require|import)\s*\(\s*['"]([^'"]+)['"]|from\s+['"]([^'"]+)['"]|import\s+['"]([^'"]+)['"]""")
# Python: `import a`, `import a.b`, `from a.b import` → root module `a`.
_PY_IMPORT = re.compile(r"^\s*import\s+([a-zA-Z0-9_][\w.]*)", re.M)
_PY_FROM = re.compile(r"^\s*from\s+([a-zA-Z0-9_][\w.]*)\s+import", re.M)

# PyPI distribution name → import name, for the common mismatches (the known hard case: a wrong
# "declared-only" here would only add a caveat, never hide a finding, but the map keeps the signal
# trustworthy). Partial by design.
_PY_ALIAS = {
    "pyyaml": "yaml", "beautifulsoup4": "bs4", "pillow": "pil", "scikit-learn": "sklearn",
    "opencv-python": "cv2", "python-dateutil": "dateutil", "msgpack-python": "msgpack",
    "protobuf": "google", "setuptools": "setuptools", "pyjwt": "jwt", "python-jose": "jose",
    "python-multipart": "multipart", "mysqlclient": "mysqldb", "psycopg2-binary": "psycopg2",
}


def _js_root(spec: str) -> str:
    """'@scope/name/sub' → '@scope/name'; 'name/sub' → 'name'; relative → ''."""
    s = (spec or "").strip()
    if not s or s.startswith((".", "/")):
        return ""
    if s.startswith("node:"):
        return ""
    parts = s.split("/")
    if s.startswith("@"):
        return "/".join(parts[:2]) if len(parts) >= 2 else parts[0]
    return parts[0]


def _import_roots(target: Path) -> tuple[set, set]:
    """(js_roots, py_roots): package/module roots imported anywhere in first-party source.

    Reuses RepoContext's single bounded walk (SKIP_DIRS-aware — node_modules/venv already excluded)."""
    js, py = set(), set()
    try:
        ctx = RepoContext(target)
    except Exception:
        return js, py
    for _p, rel, text in ctx.iter_code():
        low = rel.lower()
        if low.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
            for m in _JS_SPEC.finditer(text):
                root = _js_root(m.group(1) or m.group(2) or m.group(3) or "")
                if root:
                    js.add(root.lower())
        elif low.endswith(".py"):
            for rx in (_PY_IMPORT, _PY_FROM):
                for m in rx.finditer(text):
                    root = m.group(1).split(".")[0].strip().lower()
                    if root:
                        py.add(root)
    return js, py


def _py_candidates(pkg: str) -> set:
    """Import-name candidates for a PyPI distribution name (dash/underscore + known aliases)."""
    p = (pkg or "").strip().lower()
    if not p:
        return set()
    cands = {p, p.replace("-", "_"), p.replace("_", "-").replace("-", "_")}
    if p in _PY_ALIAS:
        cands.add(_PY_ALIAS[p])
    if p.startswith("python-"):
        cands.add(p[len("python-"):].replace("-", "_"))
    return {c for c in cands if c}


def enrich_reachability(findings: list, target: "Path | str | None") -> dict:
    """Tag each SCA/CVE finding with `reachability` ∈ {imported, no-import-found, n/a} and annotate
    the title for declared-only packages. ADDITIVE — severity/count unchanged. Returns a summary."""
    sca = [f for f in findings if f.get("category") == "sca" and f.get("pkg")]
    if not sca or not target:
        return {"analyzed": 0, "imported": 0, "declared_only": 0, "not_analyzed": 0}
    js_roots, py_roots = _import_roots(Path(target))
    imported = declared_only = not_analyzed = 0
    for f in sca:
        eco = (f.get("ecosystem") or "").lower()
        pkg = f.get("pkg", "")
        if eco in _JS_ECO:
            hit = _js_root(pkg).lower() in js_roots or pkg.lower() in js_roots
        elif eco in _PY_ECO:
            hit = bool(_py_candidates(pkg) & py_roots)
        else:
            f["reachability"] = "n/a"          # ecosystem we don't parse imports for → no claim
            not_analyzed += 1
            continue
        if hit:
            f["reachability"] = "imported"
            imported += 1
        else:
            f["reachability"] = "no-import-found"
            declared_only += 1
            if "declared-only" not in f.get("title", ""):
                f["title"] = f.get("title", "") + (
                    f" — declared-only (no import of `{pkg}` found in first-party source; "
                    "likely unreachable — verify before deprioritizing)")
    return {"analyzed": len(sca), "imported": imported,
            "declared_only": declared_only, "not_analyzed": not_analyzed}


# ── exploitability (EPSS + CISA KEV) ────────────────────────────────────────────────────────────
# Local cache location. Refreshed by scripts/refresh-epss-kev.sh (the only network step); this module
# is read-only/offline. Override with WEBSEC_ENRICH_DIR for tests / custom caches.
def _cache_dir() -> Path:
    env = os.environ.get("WEBSEC_ENRICH_DIR")
    if env:
        return Path(env)
    base = os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache")
    return Path(base) / "websec"


_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.I)


def _load_epss(cache: Path) -> dict:
    """{CVE: (epss_prob, percentile)} from the FIRST.org daily CSV (epss.csv[.gz] header lines start #)."""
    out: dict = {}
    f = cache / "epss.csv"
    if not f.is_file():
        return out
    try:
        with f.open(newline="") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if not row or row[0].startswith("#") or row[0].lower() == "cve":
                    continue
                if len(row) >= 3 and _CVE_RE.match(row[0]):
                    try:
                        out[row[0].upper()] = (float(row[1]), float(row[2]))
                    except ValueError:
                        continue
    except Exception:
        return {}
    return out


def _load_kev(cache: Path) -> set:
    """Set of KEV CVE ids from CISA known_exploited_vulnerabilities.json."""
    f = cache / "kev.json"
    if not f.is_file():
        return set()
    try:
        data = json.loads(f.read_text())
        return {v.get("cveID", "").upper() for v in (data.get("vulnerabilities") or [])
                if v.get("cveID")}
    except Exception:
        return set()


def enrich_exploitability(findings: list, cache_dir: "Path | str | None" = None) -> dict:
    """Join CVE findings against the local EPSS + KEV cache. Tags `epss`, `epss_pct`, `kev` and
    annotates the title. ADDITIVE — never changes severity. Skipped (available=False) if no cache."""
    cache = Path(cache_dir) if cache_dir else _cache_dir()
    epss, kev = _load_epss(cache), _load_kev(cache)
    if not epss and not kev:
        return {"available": False, "kev": 0, "high_epss": 0}
    kev_n = high_epss = 0
    for f in findings:
        cve = (f.get("cve") or f.get("key") or "").upper()
        if not _CVE_RE.match(cve):
            continue
        notes = []
        if cve in kev:
            f["kev"] = True
            kev_n += 1
            notes.append("⚠ CISA KEV: known exploited in the wild")
        if cve in epss:
            prob, pct = epss[cve]
            f["epss"] = round(prob, 5)
            f["epss_pct"] = round(pct, 5)
            if prob >= 0.5:
                high_epss += 1
                notes.append(f"EPSS {prob:.0%} (p{pct*100:.0f} — high exploit probability)")
            else:
                notes.append(f"EPSS {prob:.1%}")
        if notes and "EPSS" not in f.get("title", "") and "KEV" not in f.get("title", ""):
            f["title"] = f.get("title", "") + " — " + "; ".join(notes)
    return {"available": True, "kev": kev_n, "high_epss": high_epss}

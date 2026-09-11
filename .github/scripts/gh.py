"""Minimal GitHub REST client — stdlib only, matching the repo's zero-dependency stance."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

API = "https://api.github.com"


def _token() -> str:
    t = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not t:
        raise SystemExit("GH_TOKEN/GITHUB_TOKEN is not set")
    return t


DRY_RUN = os.environ.get("DRY_RUN") == "1"
MUTATING = {"POST", "PATCH", "PUT", "DELETE"}


def request(method: str, path: str, body=None, *, accept_status=()):
    url = path if path.startswith("http") else f"{API}{path}"
    if DRY_RUN and method in MUTATING:
        # Exercised locally against real PRs before this automation was ever given write scope.
        print(f"    [DRY_RUN] {method} {url} {json.dumps(body)[:160] if body else ''}")
        return 200, {"dry_run": True}
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {_token()}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "websec-validator-automation")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        payload = None
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {"raw": raw.decode("utf-8", "replace")}
        if e.code in accept_status:
            return e.code, payload
        raise SystemExit(f"{method} {url} -> {e.code}: {payload}")


def get(path, **kw):
    return request("GET", path, **kw)[1]


def _as_list(payload):
    """Some paginated endpoints return a bare array (`/pulls`), others wrap it in an object with a
    total_count (`/commits/{sha}/check-runs` -> {"check_runs": [...]}, `/actions/runs/{id}/jobs` ->
    {"jobs": [...]}). Extending a list with the dict yields its KEYS, which fails later with a
    confusing "string indices must be integers"."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for k, v in payload.items():
            if k != "total_count" and isinstance(v, list):
                return v
    raise SystemExit(f"unexpected paginated payload shape: {type(payload).__name__}")


def paged(path):
    """Follow pagination; GitHub caps per_page at 100."""
    sep = "&" if "?" in path else "?"
    url = f"{path}{sep}per_page=100"
    out = []
    while url:
        req = urllib.request.Request(url if url.startswith("http") else f"{API}{url}")
        req.add_header("Authorization", f"Bearer {_token()}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("User-Agent", "websec-validator-automation")
        with urllib.request.urlopen(req) as r:
            out.extend(_as_list(json.loads(r.read())))
            link = r.headers.get("Link", "")
        url = ""
        for part in link.split(","):
            if 'rel="next"' in part:
                url = part.split(";")[0].strip().strip("<>")
    return out

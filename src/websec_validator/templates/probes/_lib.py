"""Shared probe helpers — load THIS target's real surface from probe-context.json
(written by `websec run`) and auth/ids from environment variables.

Why env vars: recon gives you the real endpoints, auth scheme, and tenant key — but it
cannot mint live tokens or know real object ids. You (or your agent, against a TEST
instance) supply those:

    TARGET=http://localhost:3000          # base URL (or set target_base_url in probe-context.json)
    TOKEN_A=...  TOKEN_B=...               # bearer JWTs for two test accounts (different tenants)
    COOKIE_A=...  COOKIE_B=...             # OR session cookies (e.g. NextAuth) instead of bearer
    APIKEY=...                             # OR an API key
    OBJ_A=...  OBJ_B=...                   # a sample object id owned by each account/tenant
    GROUP_A=...  GROUP_B=...               # each account's tenant/group id (defaults to OBJ_* if unset)

Run only against a TEST instance you're authorized to probe. Never production.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def context() -> dict:
    p = _HERE / "probe-context.json"
    if not p.is_file():
        sys.exit("probe-context.json not found next to this probe — run `websec run <repo>` and use "
                 "the probes/ it stages (probe-context.json holds this app's real routes/auth).")
    return json.loads(p.read_text())


def base_url() -> str:
    u = os.environ.get("TARGET") or context().get("target_base_url", "")
    if not u or u.startswith("FILL"):
        sys.exit("Set TARGET=http://host:port (or fill target_base_url in probe-context.json).")
    return u.rstrip("/")


def auth_headers(role: str = "A") -> list:
    """Auth header for a role (A/B), adapting to whatever the operator supplied."""
    tok = os.environ.get(f"TOKEN_{role}")
    cookie = os.environ.get(f"COOKIE_{role}")
    apikey = os.environ.get("APIKEY")
    if tok:
        return ["-H", f"Authorization: Bearer {tok}"]
    if cookie:
        return ["-H", f"Cookie: {cookie}"]
    if apikey:
        return ["-H", f"X-API-Key: {apikey}"]
    return []  # unauthenticated


def require(*names: str) -> None:
    missing = [n for n in names if not os.environ.get(n)]
    if missing:
        sys.exit(f"This probe needs these env var(s): {', '.join(missing)}. See _lib.py for the list.")


def curl(method: str, url: str, headers=None, body=None, timeout: int = 20):
    """Returns (status_code, body_text). Never raises on HTTP errors."""
    cmd = ["curl", "-s", "-X", method, url, "-w", "\nHTTP_CODE:%{http_code}",
           "--max-time", str(timeout)] + (headers or [])
    if body is not None:
        cmd += ["-H", "content-type: application/json", "-d", json.dumps(body)]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    code = int(out.split("HTTP_CODE:")[-1].strip()) if "HTTP_CODE:" in out else 0
    return code, out.split("\nHTTP_CODE:")[0]


def tenant_key(default: str = "groupId") -> str:
    keys = context().get("tenant_keys") or []
    return keys[0] if keys else default


def write_endpoints() -> list:
    """[(METHOD, path), …] for this app's mutating routes, from probe-context.json."""
    out = []
    for ep in context().get("endpoints", {}).get("writes", []):
        parts = ep.split(" ", 1)
        if len(parts) == 2:
            out.append((parts[0], parts[1]))
    return out


def save(name: str, findings: list) -> Path:
    out = _HERE / f"{name}-findings.json"
    out.write_text(json.dumps(findings, indent=2) + "\n")
    return out

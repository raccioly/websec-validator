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
from urllib.parse import urlsplit

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
    guard_request(method, url)
    cmd = ["curl", "-q", "--noproxy", "*", "--proto", "=http,https", "-s", "-X", method, "--url", url, "-w", "\nHTTP_CODE:%{http_code}",
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
    out.write_text(json.dumps(_metadata_only(findings), indent=2) + "\n")
    return out


def guard_request(method: str, url: str) -> None:
    """Guard the actual transport URL, not merely an editable staging context."""
    try:
        parsed = urlsplit(url)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or "\\" in url or any(ord(c) < 33 for c in url)):
            raise ValueError
        parsed.port
    except ValueError:
        raise ValueError("probe requires an unambiguous HTTP(S) URL") from None
    if method.upper() not in {"GET", "HEAD", "OPTIONS"} and parsed.hostname.lower() not in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        raise ValueError("mutating probes require localhost; no request sent")


def _metadata_only(value):
    # Response text is arbitrary target-controlled data, including reflected test credentials.
    if isinstance(value, dict):
        return {k: _metadata_only(v) for k, v in value.items()
                if k not in {"preview", "body_preview", "sample_responses"}}
    if isinstance(value, list):
        return [_metadata_only(v) for v in value]
    return value


def shell_curl(args: list[str]) -> int:
    """Allow only the draft library's curl options; config/redirect/next options fail closed."""
    flags = {"-s", "--silent", "-I", "--head"}
    values = {"-X", "--request", "-H", "--header", "-d", "--data", "--data-raw", "--data-binary",
              "-F", "--form", "-o", "--output", "-w", "--write-out", "-m", "--max-time", "-D", "--dump-header"}
    method, explicit, body, urls, options = "GET", False, False, [], []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in values:
            if i + 1 >= len(args):
                raise ValueError("missing curl option value")
            value = args[i + 1]
            options.extend((arg, value))
            if arg in {"-X", "--request"}:
                method, explicit = value, True
            if arg in {"-d", "--data", "--data-raw", "--data-binary", "-F", "--form"}:
                body = True
            i += 2
            continue
        if arg in flags:
            options.append(arg)
            if arg in {"-I", "--head"} and not explicit:
                method = "HEAD"
        elif arg.startswith("-"):
            raise ValueError("unsupported curl option; review transport policy before changing drafts")
        else:
            urls.append(arg)
        i += 1
    if not urls:
        raise ValueError("missing probe URL")
    if body and not explicit:
        method = "POST"
    for url in urls:
        guard_request(method, url)
    command = ["curl", "-q", "--noproxy", "*", "--proto", "=http,https", *options]
    for url in urls:
        command.extend(("--url", url))
    return subprocess.run(command).returncode


if __name__ == "__main__":
    try:
        if sys.argv[1:2] != ["--curl"]:
            raise ValueError("use --curl for shell transport")
        sys.exit(shell_curl(sys.argv[2:]))
    except ValueError as error:
        sys.exit(str(error))

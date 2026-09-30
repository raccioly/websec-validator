"""Advisory release metadata: offline by default, never an installer.

The only persistent data is a validated release version and check timestamp.
This deliberately does not participate in scan evidence, completeness or gates.
"""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import re
import stat
import time

from . import __version__, output

HOST = "pypi.org"
PATH = "/simple/websec-validator/"
MAX_RESPONSE = 1024 * 1024
MAX_CACHE = 1024
CACHE_SECONDS = 24 * 60 * 60
SOCKET_TIMEOUT = 5
READ_SECONDS = 10
_VERSION = r"(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})"
_FILE = re.compile(r"websec[-_]validator-(" + _VERSION +
                   r")(?:\.tar\.gz|\.zip|-[A-Za-z0-9_.-]+\.whl)")
CONSENT = (
    "At the start of each security review, ask the user whether they want to check "
    "PyPI for a newer WebSec release. Respect their answer for that review. "
    "Only after approval, run `websec update-check --online` or call "
    "`websec_check_updates` with `online: true`. Checking does not install anything. "
    "If newer, offer an upgrade with separate approval; never automatically install, "
    "upgrade, switch revisions or refresh the agent plugin. A decline does not block review."
)


def _version(value):
    if isinstance(value, str) and re.fullmatch(_VERSION, value):
        return tuple(int(part) for part in value.split("."))
    return None


def _cache_path() -> Path:
    custom = os.environ.get("WEBSEC_UPDATE_HOME")
    if custom:
        base = Path(custom).expanduser()
        if not base.is_absolute():
            raise OSError("update cache base must be absolute")
        if any(part.lower() == ".local" for part in base.parts):
            raise OSError("private trees cannot hold release metadata")
        path = output.checked_path(base, "release.json")
    else:
        # Unlike an explicit base, implicit .cache parents must not be aliases.
        path = output.checked_path(Path.home(), ".cache/websec-validator/release.json")
    if any(part.lower() == ".local" for part in (*path.parts, *path.resolve().parts)):
        raise OSError("private trees cannot hold release metadata")
    return path


def _cached(now: int) -> dict | None:
    path = _cache_path()
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CACHE:
            raise ValueError("invalid release metadata cache")
        raw = handle.read(MAX_CACHE + 1)
    if len(raw) > MAX_CACHE:
        raise ValueError("release metadata cache too large")
    data = json.loads(raw)
    if (not isinstance(data, dict) or set(data) != {"latest_version", "checked_at"}
            or _version(data["latest_version"]) is None
            or type(data["checked_at"]) is not int
            or not 0 < data["checked_at"] <= now):
        raise ValueError("invalid release metadata cache")
    return data


def _latest(data: dict) -> str:
    if (not isinstance(data, dict) or data.get("name") != "websec-validator"
            or not isinstance(data.get("files"), list)):
        raise ValueError("invalid project metadata")
    versions = set()
    for item in data["files"]:
        if not isinstance(item, dict) or item.get("yanked") is not False:
            continue
        filename = item.get("filename")
        match = _FILE.fullmatch(filename) if isinstance(filename, str) else None
        if match:
            versions.add(match[1])
    if not versions:
        raise ValueError("no stable non-yanked release observed")
    return max(versions, key=_version)


def _fetch() -> str:
    # Direct stdlib HTTPS avoids ambient proxy configuration. No redirects, cookies,
    # authentication, arbitrary URL arguments or package downloads are supported.
    connection = http.client.HTTPSConnection(HOST, timeout=SOCKET_TIMEOUT)
    try:
        connection.request("GET", PATH, headers={
            "Accept": "application/vnd.pypi.simple.v1+json",
            "Accept-Encoding": "identity", "User-Agent": "websec-validator/update-check"})
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError("release metadata request unsuccessful")
        if response.getheader("Content-Encoding", "identity") != "identity":
            raise ValueError("unexpected metadata encoding")
        deadline = time.monotonic() + READ_SECONDS
        body = bytearray()
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError("metadata read deadline exceeded")
            chunk = response.read1(min(65536, MAX_RESPONSE + 1 - len(body)))
            body.extend(chunk)
            if len(body) > MAX_RESPONSE:
                raise ValueError("release metadata too large")
            if not chunk:
                break
        return _latest(json.loads(body))
    finally:
        connection.close()


def check(*, online: bool = False, installed_version: str = __version__) -> dict:
    """Read cached metadata, or explicitly check online. Errors remain advisory.

    `online=True` represents consent supplied by the CLI operator or MCP client;
    the server cannot independently attest that a human approved its client.
    """
    if type(online) is not bool:
        raise ValueError("online must be a boolean")
    installed = _version(installed_version)
    result = {"installed_version": installed_version if installed else "unknown/source",
              "latest_version": None, "checked_at": None, "status": "not_checked",
              "freshness": "not_checked", "error": None, "installation_performed": False}
    now = int(time.time())
    if online:
        try:
            data = {"latest_version": _fetch(), "checked_at": int(time.time())}
        except (OSError, ValueError, RecursionError, http.client.HTTPException):
            return {**result, "status": "unavailable", "error": "check_failed"}
        result["freshness"] = "online"
        try:
            path = _cache_path()
            output.write_text(path.parent, path.name, json.dumps(data) + "\n")
        except (OSError, ValueError):
            result["error"] = "cache_not_saved"
    else:
        try:
            data = _cached(now)
        except (OSError, ValueError):
            return {**result, "error": "cache_unavailable"}
        if data is None:
            return result
        result["freshness"] = "cached" if now - data["checked_at"] < CACHE_SECONDS else "stale"
    latest = _version(data["latest_version"])
    result.update(data)
    result["status"] = ("unknown_version" if installed is None else
                        "update_available" if latest > installed else
                        "current" if latest == installed else "ahead")
    return result


def advisory(result: dict | None = None) -> str:
    result = check() if result is None else result
    text = "WebSec release check: " + result["status"] + "."
    if result["latest_version"]:
        text += (f" Installed: {result['installed_version']}; observed stable release: "
                 f"{result['latest_version']}; checked at Unix time {result['checked_at']} "
                 f"({result['freshness']}).")
    if result["freshness"] != "online":
        text += " No online check was made now; cached metadata is not proof of the latest release."
    else:
        text += " This is a PyPI metadata observation, not installation or source-provenance verification."
    if result["error"]:
        text += " Metadata check/cache unavailable; continue the security review."
    if result["status"] in {"unknown_version", "ahead"}:
        text += " Inspect trusted engine/source provenance before suggesting a revision change."
    return text + "\n" + CONSENT

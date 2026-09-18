"""Where the running engine came from — local metadata only, no network.

A version string does not identify the engine. A stale wheel installed from /tmp, an
editable checkout with uncommitted edits, and a clean index install all report the same
`__version__`, so a review can cite a version that never matched the code that produced
it. This module answers the other half: *how* this copy was installed.

It reads PEP 610 `direct_url.json`, which packaging tools write when — and only when — a
distribution was installed from somewhere other than an index. Its absence is therefore
the positive signal for an index install, and nothing here reaches the network, so it
works in the offline core pass.

Concrete case this exists for: a pipx install pinned to
`file:///tmp/websec_validator-0.14.0-py3-none-any.whl` stayed two releases behind while
`pipx upgrade` reported "already at latest", because upgrade re-resolved the same file.
Nothing in the tool's own output disclosed that the engine was not from PyPI.
"""
from __future__ import annotations

import json
import sys
from importlib import metadata
from pathlib import Path

DIST = "websec-validator"


def _direct_url(dist) -> dict | None:
    try:
        raw = dist.read_text("direct_url.json")
    except Exception:
        return None
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def describe(dist_name: str = DIST) -> dict:
    """Classify this installation. Never raises: diagnostics must not break `doctor`."""
    result: dict = {"version": None, "source": "unknown", "detail": "",
                    "location": "", "trusted_index": None, "imported_from": ""}
    try:
        dist = metadata.distribution(dist_name)
    except Exception:
        result["detail"] = f"no installed metadata for {dist_name}; running from a source tree?"
        try:
            import websec_validator
            result["location"] = str(Path(websec_validator.__file__).resolve().parent)
        except Exception:
            pass
        result["source"] = "no-metadata"
        return result

    result["version"] = dist.version
    try:
        result["location"] = str(Path(str(dist.locate_file(""))).resolve())
    except Exception:
        pass

    # Which code is actually imported, versus which distribution the metadata describes.
    # These diverge whenever a source tree is ahead of the installed copy on sys.path, and
    # that is precisely when a cited version is wrong.
    try:
        import websec_validator
        result["imported_from"] = str(Path(websec_validator.__file__).resolve().parent)
    except Exception:
        result["imported_from"] = ""

    # An .egg-info beside a source tree is not an index install; setuptools writes it for a
    # local build. It has no direct_url.json, so the PEP 610 test alone would call it "index"
    # and stamp it trusted — a false clean signal, which is worse than none.
    meta_dir = ""
    try:
        meta_dir = Path(str(getattr(dist, "_path", "") or "")).name
    except Exception:
        meta_dir = ""
    if meta_dir.endswith(".egg-info") or meta_dir.endswith(".egg-link"):
        result["source"] = "source-tree"
        result["detail"] = (f"{meta_dir} beside a source tree — this is a local build, not an "
                            "index install, and its version tracks whatever the tree contains")
        result["trusted_index"] = False
        return result

    info = _direct_url(dist)
    if info is None:
        # PEP 610: absent means the installer resolved it from an index.
        result["source"] = "index"
        result["detail"] = "resolved from a package index (upgrades normally)"
        result["trusted_index"] = True
        return result

    url = str(info.get("url", ""))
    dir_info = info.get("dir_info") or {}
    result["trusted_index"] = False
    if isinstance(dir_info, dict) and dir_info.get("editable"):
        result["source"] = "editable"
        result["detail"] = (f"editable install of {url} — the version string does not "
                            "identify the working-tree contents")
    elif info.get("vcs_info"):
        vcs = info["vcs_info"]
        result["source"] = "vcs"
        result["detail"] = f"{vcs.get('vcs', 'vcs')} checkout of {url}@{vcs.get('commit_id', '?')[:12]}"
    elif url.startswith("file://"):
        result["source"] = "local-file"
        result["detail"] = (f"installed from {url} — `pipx upgrade` / `pip install -U` re-resolve "
                            "that path, not the index, so this copy can silently stay behind")
    else:
        result["source"] = "direct-url"
        result["detail"] = f"installed directly from {url}, bypassing the index"
    return result


def lines(dist_name: str = DIST) -> list[str]:
    """Human-readable provenance block for `doctor`."""
    info = describe(dist_name)
    label = {"index": "package index", "local-file": "LOCAL FILE", "editable": "EDITABLE",
             "vcs": "VCS checkout", "direct-url": "DIRECT URL",
             "no-metadata": "NO INSTALL METADATA"}.get(info["source"], info["source"])
    out = [f"  engine:   {info['location'] or 'unknown location'}",
           f"  source:   {label} — {info['detail']}",
           f"  python:   {sys.executable}"]
    imported = info.get("imported_from") or ""
    location = info.get("location") or ""
    if imported and location and not imported.startswith(location):
        out.append(f"  ⚠ importing {imported}, which is NOT inside the installed distribution "
                   f"at {location} — the reported version describes the install, not this code.")
    if info["trusted_index"] is False or info["source"] == "no-metadata":
        out.append("  ⚠ this engine did not come from an index; confirm it is the build you "
                   "intend before citing its version as evidence.")
    return out

"""Share-safe artifacts (#255): no absolute local path in anything a run writes.

Run artifacts are uploaded to code scanning, attached to pull requests and pasted into agent
prompts. An absolute path exposes the user name and the machine's directory layout, so every
artifact is written with:
  * paths under the scanned root made root-relative (`/home/u/app/src/a.js` → `src/a.js`) and the
    root itself replaced by its directory name;
  * paths under the run's output directory made relative to that directory;
  * `target_id` — a SHA-256 of the resolved root — so runs of the same checkout still match
    without carrying the path.
Values are rewritten only where the absolute prefix appears; nothing else in a string changes.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path


def target_id(root) -> str:
    resolved = os.path.realpath(str(Path(root).expanduser()))
    return "sha256:" + hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:32]


def _variants(path) -> list[str]:
    if not path:
        return []
    raw = str(path)
    variants = {raw.rstrip("/"), os.path.abspath(raw).rstrip("/"), os.path.realpath(raw).rstrip("/")}
    # macOS /private aliases, and osv's slash-less absolute paths
    variants |= {v[len("/private"):] for v in list(variants) if v.startswith("/private/")}
    variants |= {v.lstrip("/") for v in list(variants) if v.count("/") > 2}
    return sorted((v for v in variants if v and v != "/" and len(v) > 4), key=len, reverse=True)


class Scrubber:
    def __init__(self, root, out_dir=None):
        self.name = Path(os.path.realpath(str(root))).name or "."
        self.id = target_id(root)
        # The output directory first: it is often inside the root (./websec-out).
        rules = [(v, ".") for v in _variants(out_dir)] + [(v, self.name) for v in _variants(root)]
        # `prefix/` → relative (group 1 set); the bare prefix → its label. Bounded on both sides, so
        # `/a/app` never rewrites `/a/app2/x` and a slash-less variant never matches mid-path.
        self._compiled = [(re.compile(r"(?<![\w/.-])" + re.escape(prefix) + r"(?:(/)|(?![\w.-]))"), label)
                          for prefix, label in rules]

    def text(self, value: str) -> str:
        if not isinstance(value, str) or "/" not in value:
            return value
        for pattern, label in self._compiled:
            value = pattern.sub(lambda m: "" if m.group(1) else label, value)
        return value

    def obj(self, value):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.obj(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.obj(item) for item in value)
        if isinstance(value, dict):
            out = {self.text(k) if isinstance(k, str) else k: self.obj(v) for k, v in value.items()}
            if "target" in out and isinstance(value.get("target"), str) and os.path.isabs(value["target"]):
                out["target_id"] = self.id
            return out
        return value

    def json(self, value, **kwargs) -> str:
        kwargs.setdefault("indent", 2)
        return json.dumps(self.obj(value), **kwargs)

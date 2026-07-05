"""Baseline / diff — turn websec from a one-shot audit into a per-PR guardrail.

A tool that dumps the same 145 findings on every run gets ignored; one that says "this PR introduced
1 new SSRF lead" gets acted on. This module computes a stable per-finding fingerprint and diffs the
current ledger against a saved baseline (a prior findings-ledger.json) so CI can gate on ONLY the
newly-introduced findings.

The fingerprint is intentionally location + class + title (not evidence text, which can wobble), so a
finding survives cosmetic churn but a genuinely new sink in a new file reads as new. Stdlib only.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def fingerprint(f: dict) -> str:
    """Stable 16-hex id for a finding — attack_class + location + title. Same finding across runs →
    same fingerprint; a new sink in a new file → new fingerprint."""
    key = f"{f.get('attack_class','')}|{f.get('location','')}|{f.get('title','')}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def annotate(ledger: dict) -> dict:
    """Attach `fingerprint` to every finding in-place (so formats.py / diff can rely on it)."""
    for f in ledger.get("findings", []) or []:
        f.setdefault("fingerprint", fingerprint(f))
    return ledger


def load_baseline(path: Path) -> set[str]:
    """Read a prior findings-ledger.json (or a plain findings list) → set of fingerprints."""
    try:
        data = json.loads(Path(path).read_text())
    except Exception:
        return set()
    rows = data.get("findings", data) if isinstance(data, dict) else data
    out = set()
    for f in rows or []:
        out.add(f.get("fingerprint") or fingerprint(f))
    return out


def diff(ledger: dict, baseline_fps: set[str]) -> dict:
    """Mark each current finding new|unchanged (via baseline_state) and compute the fixed set.

    Returns {new: [...], unchanged: [...], fixed_count, new_count} and mutates each finding's
    `baseline_state`. `fixed` = baseline fingerprints no longer present (informational)."""
    annotate(ledger)
    current_fps = set()
    new, unchanged = [], []
    for f in ledger.get("findings", []) or []:
        fp = f["fingerprint"]
        current_fps.add(fp)
        if fp in baseline_fps:
            f["baseline_state"] = "unchanged"
            unchanged.append(f)
        else:
            f["baseline_state"] = "new"
            new.append(f)
    fixed = baseline_fps - current_fps
    return {"new": new, "unchanged": unchanged,
            "new_count": len(new), "unchanged_count": len(unchanged), "fixed_count": len(fixed)}


def gate_count(ledger: dict, threshold: str, new_only: bool = False) -> int:
    """How many findings are AT OR ABOVE `threshold` severity — the number a --fail-on gate trips on.
    With new_only, count only findings whose baseline_state == 'new' (requires a prior diff())."""
    floor = SEV_RANK.get(threshold.upper(), 99)
    n = 0
    for f in ledger.get("findings", []) or []:
        if new_only and f.get("baseline_state") != "new":
            continue
        if SEV_RANK.get(f.get("severity", "LOW"), 0) >= floor:
            n += 1
    return n

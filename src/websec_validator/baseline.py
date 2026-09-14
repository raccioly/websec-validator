"""Semantic finding identity and observation history. Disappearance is not proof of repair."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import re
from pathlib import Path

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 1, "INFO": 0}
FINGERPRINT_VERSION = 2


def legacy_fingerprint(f: dict) -> str:
    key = f"{f.get('attack_class','')}|{f.get('location','')}|{f.get('title','')}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _location(value) -> str:
    # Source line/column positions move with unrelated edits; route method/path remain meaningful.
    return re.sub(r":L?\d+(?::\d+)?$", "", str(value or "").replace("\\", "/"))


def identity(f: dict) -> dict:
    """Use structured rule/resource/sink identity, excluding title, severity and intelligence."""
    result = {"attack_class": f.get("attack_class", ""), "category": f.get("category", ""),
              "location": _location(f.get("location", ""))}
    aliases = {"rule_id": ("rule_id", "rule", "check_id"), "package": ("package", "pkg"),
               "cve": ("cve", "vulnerability_id"), "resource": ("resource", "resource_id"),
               "sink": ("semantic_id", "sink_id", "sink"), "symbol": ("symbol", "function"),
               "service": ("service", "service_id"), "method": ("method",), "parameter": ("parameter",)}
    for dest, keys in aliases.items():
        for key in keys:
            if f.get(key) is not None:
                result[dest] = f[key]
                break
    if f.get("file"):
        result["file"] = _location(f["file"])
    # Old scanner summaries only carried the CVE in prose. Extract its stable identifier, not title.
    if f.get("attack_class") == "cve" and "cve" not in result:
        match = re.search(r"\b(?:CVE-\d{4}-\d+|GHSA-[\w-]+)\b", str(f.get("title", "")), re.I)
        if match:
            result["cve"] = match.group().upper()
    return result


def fingerprint(f: dict) -> str:
    key = json.dumps(identity(f), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def annotate(ledger: dict) -> dict:
    for f in (ledger.get("findings", []) or []) + (ledger.get("acknowledged", []) or []):
        aliases = set(f.get("fingerprint_aliases", []))
        aliases.add(legacy_fingerprint(f))
        if f.get("fingerprint") and f.get("fingerprint_version") != FINGERPRINT_VERSION:
            aliases.add(f["fingerprint"])
        f["fingerprint"] = fingerprint(f)
        f["fingerprint_version"] = FINGERPRINT_VERSION
        f["fingerprint_aliases"] = sorted(aliases - {f["fingerprint"]})
        f["identity_precision"] = "semantic" if len(identity(f)) > 3 else "class-location"
    ledger["fingerprint_version"] = FINGERPRINT_VERSION
    return ledger


class Baseline(set):
    """Set-compatible baseline retaining prior observations for lifecycle comparisons."""
    def __init__(self, rows=()):
        super().__init__()
        self.records = {}
        self.errors = []
        self.aliases = {}
        self.ambiguous = set()
        for row in rows:
            if not isinstance(row, dict):
                continue
            row = dict(row)
            row["baseline_source_version"] = row.get("fingerprint_version", 1)
            annotate({"findings": [row]})
            fp = row["fingerprint"]
            if fp in self.records:
                self.ambiguous.add(fp)
                fp = legacy_fingerprint(row)
                self.ambiguous.add(fp)
            self.add(fp)
            self.records[fp] = row
            for alias in row["fingerprint_aliases"]:
                self.aliases[alias] = fp


def load_baseline(path: Path) -> Baseline:
    """Read an explicit regular artifact with bounded memory; failures remain visible."""
    result = Baseline()
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
                raise ValueError("baseline must be a regular file no larger than 16 MiB")
            raw = stream.read(16 * 1024 * 1024 + 1)
            if len(raw) > 16 * 1024 * 1024:
                raise ValueError("baseline exceeds 16 MiB")
        data = json.loads(raw)
        if isinstance(data, dict):
            rows = (data.get("findings") or []) + (data.get("acknowledged") or [])
        else:
            rows = data
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("baseline findings must be a list of records")
        return Baseline(rows)
    except (OSError, ValueError, TypeError) as error:
        result.errors.append(str(error))
        return result


def _coarse(finding: dict) -> str:
    return json.dumps({"attack_class": finding.get("attack_class"), "category": finding.get("category"),
                       "location": _location(finding.get("location")),
                       "resource": finding.get("resource", finding.get("resource_id"))}, sort_keys=True)


def _compatible_legacy(previous: dict, current: dict) -> bool:
    old, new = identity(previous), identity(current)
    return all(old[key] == new[key] for key in old.keys() & new.keys()
               if old[key] not in (None, ""))


def diff(ledger: dict, baseline_fps: set[str]) -> dict:
    annotate(ledger)
    records = getattr(baseline_fps, "records", {})
    alias_map = getattr(baseline_fps, "aliases", {})
    matched, new, unchanged, events = set(), [], [], []
    coarse_current, coarse_previous, alias_current = {}, {}, {}
    for row in (ledger.get("findings", []) or []) + (ledger.get("acknowledged", []) or []):
        coarse_current.setdefault(_coarse(row), []).append(row)
        for alias in row.get("fingerprint_aliases", []):
            alias_current.setdefault(alias, set()).add(row["fingerprint"])
    for fp, row in records.items():
        if row.get("baseline_source_version", 1) < FINGERPRINT_VERSION:
            coarse_previous.setdefault(_coarse(row), []).append(fp)
    unresolved = []
    for f in ledger.get("findings", []) or []:
        fp = f["fingerprint"]
        keys = [fp] + f.get("fingerprint_aliases", [])
        prior = fp if fp in baseline_fps and fp not in matched and fp not in getattr(baseline_fps, "ambiguous", set()) else None
        # V2 semantics take precedence. A coarse V1 alias must never override a changed sink ID.
        if prior is None:
            prior = next((key for key in keys[1:] if key in baseline_fps and key not in matched
                          and key not in getattr(baseline_fps, "ambiguous", set())
                          and len(alias_current.get(key, {fp})) == 1
                          and (not records or (records.get(key, {}).get("baseline_source_version", 2) < FINGERPRINT_VERSION
                                               and _compatible_legacy(records[key], f)))), None)
        if prior is None:
            prior = next((alias_map[key] for key in keys if key in alias_map and alias_map[key] not in matched
                          and len(alias_current.get(key, {fp})) == 1
                          and records.get(alias_map[key], {}).get("baseline_source_version", 2) < FINGERPRINT_VERSION
                          and _compatible_legacy(records[alias_map[key]], f)), None)
        if prior is None and _coarse(f) in coarse_previous:
            candidates = [candidate for candidate in coarse_previous[_coarse(f)]
                          if _compatible_legacy(records[candidate], f)]
            if len(candidates) == 1 and candidates[0] not in matched and len(coarse_current[_coarse(f)]) == 1:
                prior = candidates[0]
                events.append({"fingerprint": fp, "event": "legacy-identity-migrated", "previous": prior})
            else:
                unresolved.append({"fingerprint": fp, "reason": "ambiguous or incompatible legacy identity; retained as new", "candidates": candidates})
        if prior is None:
            f["baseline_state"] = "new"
            new.append(f)
            continue
        matched.add(prior)
        f["baseline_state"] = "unchanged"
        unchanged.append(f)
        previous = records.get(prior)
        if f.get("reopened_reason") or (previous and previous.get("status") == "acknowledged" and f.get("status") != "acknowledged"):
            f["baseline_state"] = "reopened"
            f.setdefault("reopened_reason", "previous acknowledgement is no longer active")
            events.append({"fingerprint": fp, "event": "reopened", "reason": f["reopened_reason"]})
        elif previous and (SEV_RANK.get(f.get("severity"), 0) > SEV_RANK.get(previous.get("severity"), 0)
                           or (f.get("kev") is True and previous.get("kev") is not True)):
            f["baseline_state"] = "changed"
        if previous:
            f["fingerprint_aliases"] = sorted(set(f["fingerprint_aliases"] + previous.get("fingerprint_aliases", [])))
            for field, kind in (("evidence", "evidence-changed"), ("severity", "severity-changed"),
                                ("kev", "kev-changed"), ("epss", "intelligence-changed"),
                                ("intelligence", "intelligence-changed")):
                if previous.get(field) != f.get(field):
                    events.append({"fingerprint": fp, "event": kind, "field": field,
                                   "previous": previous.get(field), "current": f.get(field)})
    # Acknowledged findings remain observed even though they are excluded from the active gate.
    for f in ledger.get("acknowledged", []) or []:
        for key in [f["fingerprint"]] + f.get("fingerprint_aliases", []):
            if key in baseline_fps:
                matched.add(key)
            elif key in alias_map:
                matched.add(alias_map[key])
    missing = sorted(set(baseline_fps) - matched)
    return {"new": new, "unchanged": unchanged, "new_count": len(new),
            "unchanged_count": len(unchanged), "events": events,
            "reopened_count": sum(f.get("baseline_state") == "reopened" for f in unchanged),
            "changed_count": sum(f.get("baseline_state") == "changed" for f in unchanged),
            "unresolved_migrations": unresolved, "baseline_errors": getattr(baseline_fps, "errors", []),
            "no_longer_observed": [{"fingerprint": fp, "state": "no-longer-observed",
                                     "previous": records.get(fp)} for fp in missing],
            "no_longer_observed_count": len(missing), "fixed_count": 0,
            "fixed_count_deprecated": "absence never verifies a fix; use build-bound repair evidence"}


def gate_count(ledger: dict, threshold: str, new_only: bool = False) -> int:
    floor = SEV_RANK.get(threshold.upper(), 99)
    return sum(1 for f in ledger.get("findings", []) or []
               if (not new_only or f.get("baseline_state") in ("new", "reopened", "changed"))
               and SEV_RANK.get(f.get("severity", "LOW"), 0) >= floor)

"""Machine-readable output formats — SARIF 2.1.0 + a stable JSON envelope.

Enterprise/CI consumers don't read Markdown. This module turns the findings ledger into the two
formats a pipeline actually ingests:

- **SARIF 2.1.0** (`to_sarif`) — the OASIS standard consumed by GitHub Code Scanning (inline PR-diff
  annotations + the Security tab), GitLab, Azure DevOps, VS Code's SARIF viewer, and DefectDojo. Each
  ledger finding maps to a `result`; each distinct attack class to a `rule` carrying its CWE/ASVS/
  OWASP citation. A stable `partialFingerprints` hash lets Code Scanning track a finding across runs
  (and powers our own baseline/diff — see baseline.py).
- **JSON envelope** (`to_json`) — a versioned, self-describing wrapper other tools can depend on
  without reverse-engineering the internal ledger shape.

Stdlib only (json) — no new runtime dependency, consistent with the zero-dep core.
"""

from __future__ import annotations

import re

# Bump on any BREAKING change to the FACTS.json / findings envelope / SARIF property shape. Downstream
# tools branch on this; the JSON Schemas in schemas/ are versioned in lockstep.
SCHEMA_VERSION = "1.0"

_TOOL_URI = "https://github.com/raccioly/websec-validator"

# ledger severity → SARIF result level (SARIF has only error/warning/note/none).
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "none"}
# …and a numeric security-severity (GitHub uses it to sort + colour the Security tab). CVSS-ish 0-10.
_SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "0.0"}

# A location string is a real file path (→ SARIF physicalLocation) vs. a prose placeholder like
# "(response headers)" / "set-password paths" / "client" that can't anchor to a file.
_PATHLIKE = re.compile(r"[\w./\\-]+\.[A-Za-z0-9]{1,6}$")


def _is_pathlike(loc: str) -> bool:
    loc = (loc or "").strip()
    return bool(loc) and not loc.startswith("(") and (bool(_PATHLIKE.search(loc)) or "/" in loc)


def _rule_id(attack_class: str) -> str:
    return f"websec/{attack_class or 'finding'}"


def to_sarif(ledger: dict, facts: dict | None = None, tool_version: str = "0") -> dict:
    """Render the findings ledger as a SARIF 2.1.0 log (a plain dict → json.dumps)."""
    findings = ledger.get("findings", []) or []
    facts = facts or {}

    # one rule per distinct attack class, carrying the standards citation + remediation
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings:
        ac = f.get("attack_class", "finding")
        rid = _rule_id(ac)
        std = f.get("standards", {}) or {}
        cwes = std.get("cwe", []) or []
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": "".join(w.capitalize() for w in re.split(r"[-_/]", ac)) or "Finding",
                "shortDescription": {"text": (cwes[0] if cwes else ac)},
                "fullDescription": {"text": f.get("remediation", "") or ac},
                "helpUri": _TOOL_URI,
                "properties": {
                    "attack_class": ac,
                    "cwe": cwes,
                    "asvs": std.get("asvs", ""),
                    "owasp_api": std.get("owasp_api", []),
                    "tags": ["security"] + ([c.split()[0] for c in cwes] if cwes else []),
                    # first CWE number → security-severity band feeds GitHub's ranking
                    "security-severity": _SECURITY_SEVERITY.get(f.get("severity", "LOW"), "3.0"),
                },
            }

        detail = ""
        for ev in f.get("evidence", []) or []:
            if ev.get("detail"):
                detail = ev["detail"]
                break
        msg = f.get("title", ac)
        if detail:
            msg += f"\n\n{detail}"
        if f.get("remediation"):
            msg += f"\n\nRemediation: {f['remediation']}"
        cal = f.get("calibrated") or {}
        if cal.get("p") is not None:
            msg += f"\n\nCalibrated P(real)={cal.get('p')} (basis={cal.get('basis')}, n={cal.get('n')})."

        result = {
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(f.get("severity", "LOW"), "note"),
            "message": {"text": msg},
            "partialFingerprints": {"websecFingerprintV1": f.get("fingerprint") or _fallback_fp(f)},
            "properties": {
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "category": f.get("category"),
                "calibrated": cal or None,
                "security-severity": _SECURITY_SEVERITY.get(f.get("severity", "LOW"), "3.0"),
            },
        }
        loc = f.get("location", "")
        if _is_pathlike(loc):
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": loc.replace("\\", "/")},
                    # recon is file-level (no reliable line) — anchor at line 1 so viewers render it
                    "region": {"startLine": 1},
                }
            }]
        else:
            result["properties"]["locationHint"] = loc or "(project-level)"
        if f.get("baseline_state"):
            result["baselineState"] = f["baseline_state"]   # new | unchanged | updated | absent
        results.append(result)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "websec-validator",
                "informationUri": _TOOL_URI,
                "version": str(tool_version),
                "rules": list(rules.values()),
            }},
            "properties": {
                "schema_version": SCHEMA_VERSION,
                "target": facts.get("target", ""),
                "total": ledger.get("total", len(results)),
                "by_severity": ledger.get("by_severity", {}),
            },
            "results": results,
        }],
    }


def _fallback_fp(f: dict) -> str:
    """A stable fingerprint if the ledger didn't carry one (baseline.fingerprint is the canonical impl)."""
    import hashlib
    key = f"{f.get('attack_class','')}|{f.get('location','')}|{f.get('title','')}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def to_json(ledger: dict, facts: dict | None = None, tool_version: str = "0", ts: str = "") -> dict:
    """A versioned, self-describing JSON envelope around the ledger (for non-GitHub CI / dashboards)."""
    facts = facts or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "websec-validator",
        "tool_version": str(tool_version),
        "generated": ts,
        "target": facts.get("target", ""),
        "summary": {
            "total": ledger.get("total", 0),
            "by_severity": ledger.get("by_severity", {}),
            "by_confidence": ledger.get("by_confidence", {}),
            "suppressed": ledger.get("suppressed", 0),
            "dynamic_included": ledger.get("dynamic_included", False),
        },
        "calibration": ledger.get("calibration", {}),
        "findings": ledger.get("findings", []),
    }

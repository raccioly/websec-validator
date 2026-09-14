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
from urllib.parse import quote
from .baseline import fingerprint, legacy_fingerprint

# Bump on any BREAKING change to the FACTS.json / findings envelope / SARIF property shape. Downstream
# tools branch on this; the JSON Schemas in schemas/ are versioned in lockstep.
SCHEMA_VERSION = "2.0"

_TOOL_URI = "https://github.com/raccioly/websec-validator"

# ledger severity → SARIF result level (SARIF has only error/warning/note/none).
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "none"}
# …and a numeric security-severity (GitHub uses it to sort + colour the Security tab). CVSS-ish 0-10.
_SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "0.0"}

# A location string is a real file path (→ SARIF physicalLocation) vs. a prose placeholder like
# "(response headers)" / "set-password paths" / "client" that can't anchor to a file.
_PATHLIKE = re.compile(r"[\w./\\-]+\.[A-Za-z0-9]{1,6}$")


def _is_pathlike(loc: str) -> bool:
    """True only for something that can anchor to a REPO FILE.

    A route path (`/api/platform-admin/secrets`, `GET /api/x`) contains "/" but matches no artifact,
    and emitting it as a physicalLocation gives GitHub Code Scanning a URI it cannot map — the result
    is dropped or unanchored instead of rendering as the intended locationHint. Require a real
    file-ish shape: not absolute-with-no-extension, and no "METHOD /path" prefix."""
    loc = (loc or "").strip()
    if not loc or loc.startswith("("):
        return False
    if re.match(r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ANY)\s+/", loc):
        return False                      # "GET /api/x" — a route, not a file
    if loc.startswith("/") and not _PATHLIKE.search(loc):
        return False                      # "/api/admin/users" — absolute route path, no extension
    return bool(_PATHLIKE.search(loc)) or "/" in loc


def _rule_id(attack_class: str) -> str:
    return f"websec/{attack_class or 'finding'}"


def _import_location(location: dict) -> dict:
    physical = {"artifactLocation": {"uri": quote(location["file"], safe="/")}}
    region = {native: location[field] for field, native in (("line", "startLine"), ("column", "startColumn"),
              ("end_line", "endLine"), ("end_column", "endColumn"))
              if type(location.get(field)) is int and location[field] > 0}
    if region:
        physical["region"] = region
    result = {"physicalLocation": physical}
    if location.get("message"):
        result["message"] = {"text": location["message"]}
    return result


def to_sarif(ledger: dict, facts: dict | None = None, tool_version: str = "0") -> dict:
    """Render the findings ledger as a SARIF 2.1.0 log (a plain dict → json.dumps)."""
    findings = ledger.get("findings", []) or []
    facts = facts or {}

    # one rule per distinct attack class, carrying the standards citation + remediation
    rules: dict[str, dict] = {}
    results: list[dict] = []
    # Acknowledged findings stay IN the SARIF log but carry a `suppressions` block (SARIF 2.1.0):
    # GitHub/viewers keep them visible + attributable but exclude them from active alert counts —
    # exactly "shown, not gating". `total` in properties already excludes them (ledger.total).
    _acked = [(f, True) for f in (ledger.get("acknowledged") or [])]
    for f, _is_suppressed in [(f, False) for f in findings] + _acked:
        ac = f.get("attack_class", "finding")
        native = f.get("sarif") or {}
        rid = f["rule_id"] if native else _rule_id(ac)
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
            if native:
                native_rule = native.get("rule") or {}
                rules[rid]["name"] = native_rule.get("name") or native.get("rule_id", rid)
                rules[rid]["shortDescription"] = {"text": native.get("rule_id", rid)}
                for key in ("shortDescription", "fullDescription", "help"):
                    value = native_rule.get(key)
                    if isinstance(value, dict) and isinstance(value.get("text"), str):
                        rules[rid][key] = {"text": value["text"]}
                rules[rid]["properties"].update({"native_rule_id": native.get("rule_id"),
                    "native_namespace": native.get("namespace"), "native_tool": native.get("tool"),
                    "native_rule_properties": native.get("rule_properties", {})})

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

        graph = f.get("graph") or {}
        radius = graph.get("blast_radius")
        if radius:
            msg += f"\n\nBlast radius: {radius} module(s) transitively depend on this code (graph-derived)."

        result = {
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(f.get("severity", "LOW"), "note"),
            "message": {"text": msg},
            "partialFingerprints": {"websecFingerprintV2": fingerprint(f),
                                    "websecFingerprintV1": legacy_fingerprint(f)},
            "properties": {
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                **({"native_confidence": f["native_confidence"]} if "native_confidence" in f else {}),
                **({"native_cwe": f["native_cwe"]} if "native_cwe" in f else {}),
                "category": f.get("category"),
                "calibrated": cal or None,
                "security-severity": _SECURITY_SEVERITY.get(f.get("severity", "LOW"), "3.0"),
                "blastRadius": radius if radius else None,
            },
        }
        loc = f.get("location", "")
        path, region = loc, {"startLine": 1}
        suffix = re.fullmatch(r"(.+?):L?(\d+)(?::(\d+))?", loc)
        if suffix and _is_pathlike(suffix[1]):
            path = suffix[1]
            region["startLine"] = max(1, int(suffix[2]))
            if suffix[3] and int(suffix[3]) > 0:
                region["startColumn"] = int(suffix[3])
        if _is_pathlike(f.get("file", "")):
            path = f["file"]
        if isinstance(f.get("line"), int) and not isinstance(f["line"], bool) and f["line"] > 0:
            region["startLine"] = f["line"]
        if _is_pathlike(path):
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": path.replace("\\", "/")},
                    "region": region,
                }
            }]
            if loc != path:
                result["properties"]["locationHint"] = loc
        else:
            result["properties"]["locationHint"] = loc or "(project-level)"
        if f.get("baseline_state"):
            state = f["baseline_state"]
            result["properties"]["lifecycleState"] = state
            result["baselineState"] = {"reopened": "updated", "changed": "updated"}.get(state, state)
        if _is_suppressed:
            result["suppressions"] = [{"kind": "external",
                                       "justification": f.get("ack_reason", "acknowledged")}]
        if native:
            # Producer suppressions/baseline states are preserved as evidence only;
            # copying them into active SARIF fields would silently suppress local alerts.
            result["properties"]["sarif"] = native
            result["properties"]["sarif_occurrences"] = f.get("sarif_occurrences", [native])
            result["properties"]["source_freshness"] = "unverified"
            result["kind"] = native.get("kind", "fail")
            result["level"] = native.get("level", result["level"])
            for key, value in native.get("partial_fingerprints", {}).items():
                result["partialFingerprints"].setdefault("producer/" + key, value)
            locations = [_import_location(location) for location in native.get("locations", []) if location.get("file")]
            if locations:
                result["locations"] = locations
            flows = {}
            for flow in native.get("code_flows", []):
                steps = [{"location": _import_location(step),
                          **{key: step[key] for key in ("executionOrder", "nestingLevel") if key in step}}
                         for step in flow.get("locations", []) if step.get("file")]
                if steps:
                    flows.setdefault(flow.get("flow_index", len(flows)), {"threadFlows": []})["threadFlows"].append({"locations": steps})
            if flows:
                result["codeFlows"] = list(flows.values())
            related = []
            for location in native.get("related_locations", []):
                if location.get("file"):
                    item = _import_location(location)
                    if type(location.get("id")) is int and location["id"] >= 0:
                        item["id"] = location["id"]
                    related.append(item)
            if related:
                result["relatedLocations"] = related
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
                "coverage": ledger.get("coverage", facts.get("coverage")),
            },
            "invocations": [{"executionSuccessful": (ledger.get("coverage") or facts.get("coverage") or {}).get("execution_complete", False)}],
            "results": results,
        }],
    }


def _fallback_fp(f: dict) -> str:
    """A stable fingerprint if the ledger didn't carry one (baseline.fingerprint is the canonical impl)."""
    from .baseline import fingerprint
    return fingerprint(f)


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
            "acknowledged": ledger.get("acknowledged_n", 0),
            "dynamic_included": ledger.get("dynamic_included", False),
        },
        "calibration": ledger.get("calibration", {}),
        "verification_context": ledger.get("verification_context", {}),
        "coverage": ledger.get("coverage", facts.get("coverage")),
        "findings": ledger.get("findings", []),
    }

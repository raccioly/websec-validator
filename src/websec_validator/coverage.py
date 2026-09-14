"""Execution evidence and explicit scope limits, independent of finding counts."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


def detector_revision() -> str:
    """Hash shipped implementation and rule/template data, including dirty edits."""
    root = Path(__file__).parent
    digest = hashlib.sha256()
    for directory, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d.casefold() != ".local" and d != "__pycache__")
        for name in sorted(files):
            path = Path(directory) / name
            if path.suffix in {".py", ".json", ".yaml", ".yml", ".md", ".sh", ".txt"} and not path.is_symlink():
                digest.update(path.relative_to(root).as_posix().encode() + b"\0")
                digest.update(path.read_bytes())
    return "sha256:" + digest.hexdigest()


def include_reads(cov: dict, ctx, *, input_prefix: str = "") -> None:
    """Merge a bounded auxiliary reader into the same analyzed input snapshot."""
    cov.setdefault("inputs", {}).update({input_prefix + key: value for key, value in ctx.input_hashes.items()})
    cov["analyzed_input_digest"] = _digest(cov["inputs"])
    files = cov.setdefault("files", {})
    files["read"] = len(cov["inputs"])
    files.setdefault("auxiliary_read_policies", {})[input_prefix] = source_read_policy(ctx)
    files.setdefault("auxiliary_source_bytes", {})[input_prefix] = ctx.cached_source_bytes
    for key in ("unreadable", "oversized", "byte_budget_exceeded"):
        files[key] = sorted(set(files.get(key, [])) | {input_prefix + path for path in getattr(ctx, key)})
        if getattr(ctx, key):
            add_gap({"coverage": cov}, key, "auxiliary input could not be read completely")


def source_read_policy(ctx) -> dict:
    from .extractors.base import MAX_BYTES
    return {"max_file_bytes": MAX_BYTES, "max_cached_raw_bytes_per_context": ctx.source_bytes_limit,
            "accounting": "successful cache entries; aliases share payload, separate read caps count separately"}


def _digest(inputs: dict) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()


def from_context(ctx, outcomes: dict) -> dict:
    """Snapshot after extractors finish so lazy reads and failures are represented."""
    gaps = []
    for key, outcome in outcomes.items():
        if outcome["outcome"] != "completed":
            gaps.append({"kind": "extractor", "detail": key, "execution": True})
    for key, rows in (("unreadable", ctx.unreadable), ("oversized", ctx.oversized),
                      ("byte_budget_exceeded", ctx.byte_budget_exceeded),
                      ("glob_limit", ctx.glob_truncated)):
        if rows:
            gaps.append({"kind": key, "detail": f"{len(rows)} affected file(s) or queries", "execution": True})
    if ctx.truncated:
        gaps.append({"kind": "file_limit", "detail": "file inventory or code selection capped", "execution": True})
    if ctx.unsupported_files:
        gaps.append({"kind": "unsupported_source", "detail": f"{len(ctx.unsupported_files)} source files", "execution": False})
    if ctx.excludes:
        gaps.append({"kind": "excluded_scope", "detail": "operator exclusions applied", "execution": False})
    if ctx.skip_counts:
        gaps.append({"kind": "walker_policy", "detail": "private, generated or disallowed files excluded from traversal", "execution": False})
    result = {
        "profile": "heuristic-static-recon", "execution_complete": not any(g["execution"] for g in gaps),
        "protection_complete": False,
        "limitation": "Completed execution does not prove absence of vulnerabilities or full framework coverage.",
        "detector_revision": detector_revision(), "analyzed_input_digest": _digest(ctx.input_hashes),
        "inputs": dict(sorted(ctx.input_hashes.items())),
        "extractors": outcomes, "scanners": {}, "gaps": gaps,
        "files": {"seen": ctx.files_seen, "scanned": len(ctx.code_files), "read": len(ctx.input_hashes),
                  "types": dict(ctx.file_types), "unreadable": list(ctx.unreadable),
                  "oversized": list(ctx.oversized), "unsupported": list(ctx.unsupported_files),
                  "byte_budget_exceeded": list(ctx.byte_budget_exceeded),
                  "source_bytes": ctx.cached_source_bytes, "read_policy": source_read_policy(ctx),
                  "truncated": bool(ctx.truncated), "inventory_truncated": ctx.walk_truncated,
                  "glob_truncated": list(ctx.glob_truncated), "excludes": list(ctx.excludes),
                  "include_fixtures": ctx.include_fixtures,
                  "skipped_counts": dict(ctx.skip_counts), "skipped_samples": list(ctx.skipped_files)},
    }
    result["scope_digest"] = _digest({"profile": result["profile"], "excludes": ctx.excludes,
                                      "read_policy": result["files"]["read_policy"],
                                      "include_fixtures": ctx.include_fixtures,
                                      "extractors": sorted(outcomes), "unsupported_types":
                                      sorted({Path(p).suffix for p in ctx.unsupported_files})})
    return result


def add_gap(facts: dict, kind: str, detail: str, *, execution: bool = True) -> None:
    cov = facts.setdefault("coverage", {"execution_complete": True, "gaps": [], "scanners": {}})
    gap = {"kind": kind, "detail": detail, "execution": execution}
    if gap not in cov["gaps"]:
        cov["gaps"].append(gap)
    if execution:
        cov["execution_complete"] = False


def add_profiles(facts: dict) -> None:
    analysis = (facts.get("stack") or {}).get("profiles") or {}
    cov = facts["coverage"]
    cov["profiles"] = analysis.get("profiles", [])
    cov["service_inventory"] = analysis.get("service_inventory", [])
    cov["profile_limitations"] = analysis.get("limitations", [])
    cov["profile_errors"] = analysis.get("errors", [])
    for error in cov["profile_errors"]:
        add_gap(facts, "profile_error", f"{error.get('file', '?')}: {error.get('check', '?')}: {error.get('error', 'analysis failed')}")
    unverified = sum(check.get("status") != "completed" for profile in cov["profiles"]
                     for check in profile.get("checks", []))
    if unverified:
        add_gap(facts, "profile_scope", f"{unverified} named checks require manual review or lack applicable input",
                execution=False)


def add_routes(facts: dict) -> None:
    """Preserve route-parser scope uncertainty separately from execution loss."""
    analysis = (facts.get("routes") or {}).get("django") or {}
    if not analysis:
        return
    if (not isinstance(analysis, dict)
            or any(not isinstance(analysis.get(key, []), list)
                   or any(not isinstance(row, dict) for row in analysis.get(key, []))
                   for key in ("routes", "candidates", "gaps", "errors"))):
        add_gap(facts, "route_error", "Route discovery returned malformed diagnostics")
        return
    facts["coverage"]["route_discovery"] = {"django": {
        "routes": len(analysis.get("routes", [])), "candidates": len(analysis.get("candidates", [])),
        "gaps": analysis.get("gaps", []), "errors": analysis.get("errors", []),
        "limits": analysis.get("limits", {}), "diagnostics_truncated": analysis.get("diagnostics_truncated", 0)}}
    for row in analysis.get("gaps", []):
        add_gap(facts, "route_scope", f"{row.get('file', '?')}: {row.get('kind', '?')}: {row.get('detail', '')}",
                execution=False)
    for row in analysis.get("errors", []):
        add_gap(facts, "route_error", f"{row.get('file', '?')}: {row.get('kind', '?')}: {row.get('detail', '')}")
    if analysis.get("diagnostics_truncated"):
        add_gap(facts, "route_diagnostics_truncated", "Django diagnostics exceeded the reporting budget")


def add_scanners(facts: dict, detected: dict, results: list, unified: dict | None, *,
                 scan: bool, only: list[str] | None = None, verify_secrets: bool = False) -> dict:
    from . import scanners
    cov = facts.setdefault("coverage", {"execution_complete": True, "gaps": [], "scanners": {}})
    installed = {s["key"] for s in detected.get("available", [])}
    relevant = installed | {s["key"] for s in detected.get("missing", [])}
    selected = set(only or [])
    registry = {s.key: s for s in scanners.REGISTRY}
    if scan and only is None:
        selected = {key for key in installed if registry[key].argv is not None
                    and (key not in scanners._OPT_IN_SCANNERS or verify_secrets)}
    by_key = {r["key"]: r for r in results}
    parse_failed = set((unified or {}).get("parse_failed", []))
    errors = set((unified or {}).get("scanner_errors", []))
    parsed = set((unified or {}).get("parse_attempted", []))
    for key in sorted(relevant | selected | set(by_key)):
        adapter = registry.get(key)
        result = by_key.get(key)
        runnable = bool(adapter and adapter.argv is not None)
        chosen = key in selected and scan
        outcome = "not_selected" if key in installed else "unavailable"
        if chosen:
            if key not in installed:
                outcome = "unavailable"
            elif not runnable:
                outcome = "unsupported_adapter"
            elif result is None:
                outcome = "not_run"
            elif result.get("status") == "timeout":
                outcome = "timeout"
            elif key in errors or result.get("status"):
                outcome = "error"
            elif key in parse_failed:
                outcome = "parse_failed"
            elif key not in parsed:
                outcome = "missing_output"
            else:
                outcome = "completed"
            if outcome != "completed":
                add_gap(facts, "scanner", f"{key}: {outcome}")
        cov["scanners"][key] = {"installed": key in installed, "runnable": runnable,
                                 "selected": chosen, "ran": result is not None, "outcome": outcome,
                                 "reported_version": (unified or {}).get("report_versions", {}).get(key),
                                 "version_verified": bool((unified or {}).get("report_versions", {}).get(key))}
        details = (unified or {}).get("report_details", {}).get(key, {})
        cov["scanners"][key]["report_details"] = details
        for policy in ("configuration_policy", "suppression_policy"):
            if result and policy in result:
                cov["scanners"][key][policy] = result[policy]
        if chosen and details.get("skipped_checks"):
            add_gap(facts, "scanner_scope", f"{key}: {details['skipped_checks']} checks suppressed by native scanner policy",
                    execution=False)
    cov["scope_digest"] = _digest({"profile": cov.get("profile"),
                                   "excludes": cov.get("files", {}).get("excludes", []),
                                   "include_fixtures": cov.get("files", {}).get("include_fixtures", False),
                                   "extractors": sorted(cov.get("extractors", {})), "scanners": sorted(selected)})
    return cov


def import_scope(imports: list[dict]) -> list[dict]:
    """Requested import policy and tool configuration, independent of changing result content."""
    scopes = [{"format": "sarif-2.1.0", "policy": report.get("scope", {}),
               "tools": report.get("tool_scope", [])} for report in imports]
    unique = {json.dumps(scope, sort_keys=True): scope for scope in scopes}
    return [unique[key] for key in sorted(unique)]


def add_imports(facts: dict, reports: list[dict]) -> dict:
    """Record explicitly requested artifact imports separately from executed scanners."""
    cov = facts.setdefault("coverage", {"execution_complete": True, "gaps": [], "scanners": {}})
    cov["imports"] = reports
    cov["import_scope"] = import_scope(reports)
    for report in reports:
        for gap in report.get("gaps", []):
            add_gap(facts, gap.get("kind", "sarif_input"), gap.get("detail", "import incomplete"),
                    execution=gap.get("execution") is not False)
        if (report.get("import_complete") is not True or report.get("execution_complete") is not True
                or report.get("analysis_outcome") != "completed"):
            add_gap(facts, "sarif_import", "Requested SARIF import or producer analysis did not complete: " + report.get("path", ""))
    if reports:
        add_gap(facts, "sarif_freshness", "Imported SARIF source freshness is unverified; producer success does not bind results to these analyzed inputs.", execution=False)
    cov["scope_digest"] = _digest({"analysis_scope": cov.get("scope_digest"), "imports": cov["import_scope"]})
    return cov


def render_md(facts: dict) -> str:
    cov = facts.get("coverage") or {}
    if not cov:
        return "\n> Coverage evidence unavailable for this legacy artifact.\n"
    status = "REQUESTED CHECKS COMPLETED" if cov.get("execution_complete") else "PARTIAL SCAN — REQUESTED CHECKS INCOMPLETE"
    counts = cov.get("files", {})
    lines = [f"\n> **{status}** — {counts.get('read', 0)} files read; {counts.get('scanned', 0)} code files selected.",
             "> Completion describes execution, not complete protection. See `coverage.json` for scope and limits."]
    if cov.get("imports"):
        lines.append(f"> SARIF imports: {len(cov['imports'])}; producer analysis and import outcomes recorded separately from scanners. Source freshness unverified; repair completion unsupported.")
    if counts.get("byte_budget_exceeded"):
        lines.append("> Source cache budget exhausted. Narrow the target or use explicit exclusions and review each resulting scope; unread inputs are not analyzed.")
    profiles = cov.get("profiles", [])
    if profiles:
        checked = sum(check.get("status") == "completed" for profile in profiles for check in profile.get("checks", []))
        lines.append(f"> Profiles: {len(profiles)} across {len(cov.get('service_inventory', []))} service boundaries; "
                     f"{checked} named checks completed. Profile limits remain explicit in coverage.")
    for gap in cov.get("gaps", []):
        from .briefing import _data
        lines.append(f"> - {_data(gap['kind'])}: {_data(gap['detail'])}")
    return "\n".join(lines) + "\n"


def add_dynamic(facts: dict, dynamic: dict) -> None:
    cov = facts.setdefault("coverage", {"execution_complete": False, "gaps": [], "scanners": {}})
    outcomes = {}
    for key in ("cross_tenant_bola", "unauth_reachability", "write_auth_enforcement", "forged_token_bypass"):
        row = dynamic.get(key)
        if not isinstance(row, dict):
            continue
        incomplete = bool(row.get("error") or row.get("inconclusive") or row.get("endpoints_over_cap")
                          or row.get("state") in {"not-tested", "inconclusive"})
        outcomes[key] = {"outcome": "inconclusive" if incomplete else "completed"}
        if incomplete:
            add_gap(facts, "dynamic", f"{key}: requested checks inconclusive or not tested")
    cov["dynamic"] = outcomes


def execution_errors(cov: dict) -> list[str]:
    """Cross-check a completion claim against its detailed execution evidence.

    Scope exclusions, unsupported languages and unselected tools are limitations, not failed
    execution. This validates internal consistency; it does not authenticate an operator's report.
    """
    if not isinstance(cov, dict):
        return ['coverage must be an object']
    errors = []
    if cov.get('execution_complete') is not True:
        errors.append('execution_complete is not true')
    gaps = cov.get('gaps', [])
    if not isinstance(gaps, list):
        errors.append('coverage gaps must be a list')
    else:
        for row in gaps:
            if not isinstance(row, dict) or type(row.get('execution')) is not bool:
                errors.append('coverage gap has no valid execution classification')
            elif row['execution']:
                errors.append('execution gap: ' + str(row.get('kind', 'unknown')))
    files = cov.get('files', {})
    if not isinstance(files, dict):
        errors.append('coverage files must be an object')
    else:
        for key in ('unreadable', 'oversized', 'glob_truncated', 'byte_budget_exceeded'):
            value = files.get(key, [])
            if not isinstance(value, list) or value:
                errors.append('source read loss or invalid evidence: ' + key)
        for key in ('truncated', 'inventory_truncated'):
            value = files.get(key, False)
            if value is not False:
                errors.append('source selection loss or invalid evidence: ' + key)
        policies = files.get('auxiliary_read_policies', {})
        consumed = files.get('auxiliary_source_bytes', {})
        if not isinstance(policies, dict) or not isinstance(consumed, dict):
            errors.append('auxiliary source byte accounting must be objects')
            policies, consumed = {}, {}
        checks = [(files.get('read_policy', {}), files.get('source_bytes'))]
        checks.extend((policies.get(key, {}), consumed.get(key)) for key in policies.keys() | consumed.keys())
        for policy, count in checks:
            if not isinstance(policy, dict):
                errors.append('source read policy must be an object')
                continue
            if count is not None and (type(count) is not int or count < 0):
                errors.append('invalid source byte accounting')
            for field in ('max_file_bytes', 'max_cached_raw_bytes_per_context'):
                if field in policy and (type(policy[field]) is not int or policy[field] < 0):
                    errors.append('invalid source read byte limit')
            limit = policy.get('max_cached_raw_bytes_per_context')
            if type(count) is int and type(limit) is int and count > limit:
                errors.append('source byte accounting exceeds the declared context budget')
    for group in ('extractors', 'dynamic'):
        outcomes = cov.get(group, {})
        if not isinstance(outcomes, dict):
            errors.append(group + ' outcomes must be an object')
            continue
        for key, row in outcomes.items():
            if not isinstance(row, dict) or row.get('outcome') != 'completed':
                errors.append(group + ' check incomplete: ' + str(key))
            if isinstance(row, dict) and (
                    ('error' in row and row['error'] is not None and row['error'] != '')
                    or ('errors' in row and (not isinstance(row['errors'], list) or row['errors']))):
                errors.append(group + ' reported errors or invalid diagnostics: ' + str(key))
    scanners = cov.get('scanners', {})
    if not isinstance(scanners, dict):
        errors.append('scanner outcomes must be an object')
    else:
        for key, row in scanners.items():
            if not isinstance(row, dict) or type(row.get('selected')) is not bool:
                errors.append('scanner selection evidence invalid: ' + str(key))
            elif row['selected'] and (row.get('ran') is not True or row.get('outcome') != 'completed'
                                       or row.get('installed') is not True or row.get('runnable') is not True):
                errors.append('selected scanner incomplete: ' + str(key))
            if isinstance(row, dict) and row.get('selected') is True and 'report_details' in row:
                details = row['report_details']
                if (not isinstance(details, dict)
                        or not isinstance(details.get('errors', []), list)
                        or details.get('errors')):
                    errors.append('selected scanner reported errors or invalid diagnostics: ' + str(key))
    imports = cov.get('imports', [])
    if not isinstance(imports, list):
        errors.append('imports must be a list')
    else:
        for report in imports:
            if (not isinstance(report, dict) or report.get('import_complete') is not True
                    or report.get('execution_complete') is not True or report.get('analysis_outcome') != 'completed'):
                errors.append('requested report import or producer analysis incomplete')
                continue
            gaps = report.get('gaps', [])
            if (not isinstance(gaps, list) or any(not isinstance(gap, dict)
                    or type(gap.get('execution')) is not bool or gap['execution'] for gap in gaps)):
                errors.append('import has execution gaps or invalid diagnostics')
    profile_errors = cov.get('profile_errors', [])
    if not isinstance(profile_errors, list) or profile_errors:
        errors.append('profile analysis failed or has invalid error evidence')
    route_discovery = cov.get('route_discovery', {})
    if not isinstance(route_discovery, dict):
        errors.append('route discovery outcomes must be an object')
    else:
        for engine, row in route_discovery.items():
            if not isinstance(row, dict):
                errors.append('invalid route discovery outcome: ' + str(engine))
                continue
            diagnostics = row.get('errors', [])
            if not isinstance(diagnostics, list) or diagnostics:
                errors.append('route analysis failed or has invalid error evidence: ' + str(engine))
            truncated = row.get('diagnostics_truncated', 0)
            if type(truncated) is not int or truncated != 0:
                errors.append('route analysis diagnostics truncated or invalid: ' + str(engine))
            scope = row.get('gaps', [])
            if not isinstance(scope, list) or any(not isinstance(gap, dict)
                    or ('execution' in gap and gap['execution'] is not False) for gap in scope):
                errors.append('route scope diagnostics must be objects: ' + str(engine))
            for key in ('routes', 'candidates'):
                if key in row and (type(row[key]) is not int or row[key] < 0):
                    errors.append('route analysis count invalid: ' + str(engine))
            limits = row.get('limits', {})
            if not isinstance(limits, dict) or any(type(value) is not int or value < 0 for value in limits.values()):
                errors.append('route analysis limits invalid: ' + str(engine))
    profiles = cov.get('profiles', [])
    if not isinstance(profiles, list):
        errors.append('profile checks must be a list')
    else:
        for profile in profiles:
            if not isinstance(profile, dict) or not isinstance(profile.get('checks', []), list):
                errors.append('invalid profile check evidence')
                continue
            for check in profile.get('checks', []):
                if (not isinstance(check, dict) or not isinstance(check.get('status'), str)
                        or check['status'] not in {'completed', 'manual', 'unknown', 'not-applicable', 'not_applicable'}):
                    errors.append('profile check failed or malformed')
    return list(dict.fromkeys(errors))

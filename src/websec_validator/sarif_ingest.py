"""Bounded offline SARIF 2.1.0 import. Report references are data, never read targets.

This consumes a documented subset, not the entire SARIF schema. Producer success
and suppressions are claims; neither source freshness nor repair is attested.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import posixpath
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .extractors.base import SKIP_DIRS, is_test_file, read_artifact

MAX_BYTES = 16 * 1024 * 1024
MAX_RUNS = 32
MAX_RESULTS = 20000
MAX_RULES = 1000
MAX_TRACE_STEPS = 100
MAX_DEPTH = 64
MAX_TEXT = 8192
MAX_EXPANDED_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_RETAINED_TRACE_STEPS = 5000
MAX_DIAGNOSTICS = 200
MAX_TOOL_COMPONENTS = 32
MAX_INVOCATIONS = 128


class Invalid(ValueError):
    pass


class Excluded(ValueError):
    pass


def _object(value, what):
    if not isinstance(value, dict):
        raise Invalid(what + " must be an object")
    return value


def _array(value, what):
    if not isinstance(value, list):
        raise Invalid(what + " must be an array")
    return value


def _text(value, what, *, empty=True):
    if not isinstance(value, str) or len(value) > MAX_TEXT or (not empty and not value):
        raise Invalid(what + " must be bounded text")
    # Remove terminal control characters. Text is evidence, never instructions.
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)


def _index(value, items, what):
    if type(value) is not int or not 0 <= value < len(items):
        raise Invalid(what + " is out of range")
    return items[value]


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("duplicate JSON object key")
        result[key] = value
    return result


def _depth(document):
    todo = [(document, 0)]
    while todo:
        value, depth = todo.pop()
        if depth > MAX_DEPTH:
            raise Invalid("JSON nesting limit exceeded")
        if isinstance(value, dict):
            todo.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            todo.extend((child, depth + 1) for child in value)


def _uri(value):
    if isinstance(value, str) and re.search(r"[\x00-\x1f\x7f]", value):
        raise Invalid("control character in artifact URI")
    value = _text(value, "artifact URI", empty=False)
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise Invalid("invalid percent escape in artifact URI")
    decoded = unquote(value, errors="strict").replace("\\", "/")
    if re.search(r"%[0-9a-fA-F]{2}", decoded) or any(ord(c) < 32 for c in decoded):
        raise Invalid("ambiguous encoded artifact URI")
    parsed = urlsplit(decoded)
    if parsed.scheme or parsed.netloc or decoded.startswith("/") or parsed.query or parsed.fragment:
        raise Invalid("absolute, remote or unmapped artifact URI")
    return decoded


def _path(location, run, seen=()):
    """Resolve in-report indexes/base IDs lexically. Never stat/open a source URI."""
    if len(seen) > 16:
        raise Invalid("artifact reference depth limit")
    location = _object(location, "artifact location")
    uri = location.get("uri")
    if "index" in location:
        marker = ("artifact", location["index"])
        if marker in seen:
            raise Invalid("cyclic artifact index")
        artifact = _index(location["index"], _array(run.get("artifacts", []), "artifacts"), "artifact index")
        indexed = _path(_object(artifact, "artifact").get("location"), run, seen + (marker,))
        if uri is None:
            return indexed
        direct = _path({key: value for key, value in location.items() if key != "index"}, run, seen)
        if direct != indexed:
            raise Invalid("artifact URI and index disagree")
        return direct
    if uri is None:
        raise Invalid("artifact location has no URI or index")
    path = _uri(uri)
    if "uriBaseId" in location:
        base_id = _text(location["uriBaseId"], "URI base ID", empty=False)
        marker = ("base", base_id)
        if marker in seen:
            raise Invalid("cyclic URI base ID")
        bases = _object(run.get("originalUriBaseIds", {}), "URI bases")
        if base_id not in bases:
            raise Invalid("unmapped URI base ID")
        base = _path(bases[base_id], run, seen + (marker,))
        path = posixpath.join(base, path)
    normalized = posixpath.normpath(path)
    if normalized == ".." or normalized.startswith("../") or normalized.startswith("/"):
        raise Invalid("artifact path escapes the source root")
    return normalized


def _location(value, run, excludes, include_fixtures):
    value = _object(value, "location")
    physical = value.get("physicalLocation")
    if physical is None:
        return {"file": "", "line": 0}
    physical = _object(physical, "physical location")
    path = _path(physical.get("artifactLocation"), run)
    if (any(part in SKIP_DIRS for part in path.split("/"))
            or any(ex and (ex in path or fnmatch.fnmatch(path, ex)) for ex in excludes)
            or (not include_fixtures and is_test_file(path))):
        raise Excluded("location omitted by selected source scope")
    if path in {"", "."}:
        raise Invalid("artifact URI does not identify a file")
    region = _object(physical.get("region", {}), "region")
    result = {"file": path, "line": 0}
    for native, field in (("startLine", "line"), ("startColumn", "column"),
                          ("endLine", "end_line"), ("endColumn", "end_column")):
        if native in region:
            number = region[native]
            if type(number) is not int or number <= 0:
                raise Invalid("invalid source region")
            result[field] = number
    if result.get("end_line", result["line"]) < result["line"]:
        raise Invalid("source region ends before it starts")
    if (result.get("end_line", result["line"]) == result["line"]
            and result.get("end_column", result.get("column", 1)) < result.get("column", 1)):
        raise Invalid("source region end column precedes its start")
    return result


def _rule(result, run):
    tool = _object(run.get("tool"), "tool")
    driver = _object(tool.get("driver"), "tool driver")
    reference = _object(result.get("rule", {}), "rule reference")
    for top, nested in (("ruleId", "id"), ("ruleIndex", "index")):
        if top in result and nested in reference and result[top] != reference[nested]:
            raise Invalid("duplicated rule reference fields disagree")
    component = driver
    if "toolComponent" in reference:
        selector = _object(reference["toolComponent"], "tool component reference")
        extensions = _array(tool.get("extensions", []), "tool extensions")[:MAX_TOOL_COMPONENTS - 1]
        if "index" in selector:
            component = _object(_index(selector["index"], extensions, "extension index"), "extension")
        else:
            matches = [item for item in [driver] + extensions if isinstance(item, dict)
                       and any(k in selector for k in ("name", "guid"))
                       and all(selector[k] == item.get(k) for k in ("name", "guid") if k in selector)]
            if len(matches) != 1:
                raise Invalid("ambiguous or missing tool component")
            component = matches[0]
        for key in ("name", "guid"):
            if key in selector and (_text(selector[key], "component selector " + key, empty=False) != component.get(key)):
                raise Invalid("tool component selector fields disagree")
    name = _text(component.get("name"), "component name", empty=False)
    rules = _array(component.get("rules", []), "rules")
    index = result.get("ruleIndex", reference.get("index"))
    rule_id = result.get("ruleId", reference.get("id"))
    definition = {}
    if index is not None:
        if type(index) is not int or index >= MAX_RULES:
            raise Invalid("rule index exceeds supported rule inventory")
        definition = _object(_index(index, rules, "rule index"), "rule definition")
        if rule_id is not None and rule_id != definition.get("id"):
            raise Invalid("rule ID and index disagree")
        rule_id = definition.get("id")
    elif rule_id is not None:
        matches = [item for item in rules[:MAX_RULES] if isinstance(item, dict) and item.get("id") == rule_id]
        if len(matches) > 1:
            raise Invalid("duplicate rule ID definitions")
        definition = matches[0] if matches else {}
    rule_id = _text(rule_id, "rule ID", empty=False)
    namespace = {"driver": _text(driver.get("name"), "driver name", empty=False),
                 "driver_guid": _text(driver.get("guid", ""), "driver GUID"),
                 "component": name, "component_guid": _text(component.get("guid", ""), "component GUID")}
    return rule_id, definition, component, namespace


def _message(value, rule, component):
    message = _object(value, "message")
    if "text" in message:
        text = _text(message["text"], "message text", empty=False)
    else:
        key = _text(message.get("id"), "message ID", empty=False)
        strings = _object(rule.get("messageStrings", {}), "rule messages")
        globals_ = _object(component.get("globalMessageStrings", {}), "global messages")
        template = _object(strings.get(key, globals_.get(key)), "message template")
        text = _text(template.get("text"), "message template text", empty=False)
    arguments = _array(message.get("arguments", []), "message arguments")
    if len(arguments) > 100:
        raise Invalid("message argument limit")
    arguments = [_text(item, "message argument") for item in arguments]
    def replace(match):
        index = int(match[1])
        if index >= len(arguments):
            raise Invalid("missing message argument")
        return arguments[index]
    # No Python formatting/evaluation: only SARIF's numbered argument substitution.
    return _text(re.sub(r"\{([0-9]{1,6})\}", replace, text), "expanded message") if arguments else text


def _maps(value, what):
    if len(_object(value, what)) > 128:
        raise Invalid(what + " count limit exceeded")
    return {key: _text(item, what) for key, item in _object(value, what).items()
            if _text(key, what + " key", empty=False)}


def _rule_metadata(rule):
    rule = _object(rule, "rule definition")
    data = {key: _text(rule[key], "rule " + key) for key in ("id", "name", "helpUri") if key in rule}
    for key in ("shortDescription", "fullDescription", "help"):
        if key in rule:
            message = _object(rule[key], "rule " + key)
            if "text" in message:
                data[key] = {"text": _text(message["text"], "rule " + key)}
    return data


def _invocation(invocation):
    invocation = _object(invocation, "invocation")
    if type(invocation.get("executionSuccessful")) is not bool:
        raise Invalid("invocation has no Boolean executionSuccessful")
    status = {"executionSuccessful": invocation["executionSuccessful"]}
    failed = not status["executionSuccessful"]
    for key in ("exitCode", "startTimeUtc", "endTimeUtc"):
        if key in invocation and isinstance(invocation[key], (str, int)) and not isinstance(invocation[key], bool):
            status[key] = invocation[key]
    for key in ("toolExecutionNotifications", "toolConfigurationNotifications"):
        notifications = _array(invocation.get(key, []), key)
        status[key] = []
        for notification in notifications:
            notification = _object(notification, "notification")
            level = notification.get("level", "warning")
            if not isinstance(level, str) or level not in {"error", "warning", "note", "none"}:
                raise Invalid("invalid notification level")
            failed |= level == "error"
            message = notification.get("message", {})
            entry = {"level": level}
            if isinstance(message, dict) and "text" in message:
                entry["message"] = _text(message["text"], "notification message")
            status[key].append(entry)
    return status, failed


def load_report(path: Path, target: Path, *, excludes=(), include_fixtures=False) -> dict:
    """Import only the explicit report. `target` labels scope; its source is not read.

    Failure results with native suppressions remain active. Pass/absent/notApplicable
    results are observations, never local acknowledgements or repair confirmation.
    """
    report = {"path": str(Path(path).absolute()), "sha256": None, "bytes": 0, "version": None,
              "target": str(Path(target).absolute()), "import_complete": True, "analysis_outcome": "unknown",
              "execution_complete": False, "source_freshness": "unverified", "runs": [], "tool_scope": [], "gaps": [],
              "location_binding": "producer-claimed; lexical validation only; filesystem containment unverified",
              "scope": {"excludes": list(excludes), "include_fixtures": bool(include_fixtures),
                        "path_policy": "relative source paths only; no inferred absolute-root remapping",
                        "suppression_policy": "native suppressions preserved; failures remain active"},
              "limits": {"bytes": MAX_BYTES, "runs": MAX_RUNS, "results": MAX_RESULTS,
                         "rules_per_component": MAX_RULES, "trace_steps_per_result": MAX_TRACE_STEPS, "depth": MAX_DEPTH,
                         "expanded_evidence_bytes": MAX_EXPANDED_BYTES, "output_bytes": MAX_OUTPUT_BYTES,
                         "retained_trace_steps": MAX_RETAINED_TRACE_STEPS},
              "counts": {"results_seen": 0, "findings": 0, "observations": 0, "excluded": 0, "rejected": 0,
                         "expanded_bytes": 0, "retained_trace_steps": 0, "metadata_truncated": 0, "diagnostics_omitted": 0},
              "source_references_read": False, "commands_executed": False, "references_fetched": False}
    output = {"findings": [], "observations": [], "report": report}
    def gap(detail, *, kind="sarif_input", execution=True, loss=True):
        entry = {"kind": kind, "detail": detail, "execution": execution}
        if entry not in report["gaps"]:
            if len(report["gaps"]) < MAX_DIAGNOSTICS:
                report["gaps"].append(entry)
            else:
                report["counts"]["diagnostics_omitted"] += 1
                report["import_complete"] = False
                report["gaps"][-1] = {"kind": "sarif_budget", "detail": "diagnostic count limit exceeded", "execution": True}
        if loss:
            report["import_complete"] = False
    def reserve(value):
        # Account for serialized duplication, not Python object references. A single
        # shared 8 KiB message can otherwise expand into gigabytes of output.
        size = len(json.dumps(value, separators=(",", ":")).encode())
        if report["counts"]["expanded_bytes"] + size > MAX_EXPANDED_BYTES:
            gap("global expanded evidence budget exceeded", kind="sarif_budget")
            report["counts"]["metadata_truncated"] += 1
            return False
        report["counts"]["expanded_bytes"] += size
        return True
    gap("Imported analyzer output does not attest the current source revision", kind="source_freshness", execution=False, loss=False)
    try:
        content = read_artifact(Path(path), max_bytes=MAX_BYTES)
        raw = content.encode("utf-8")
        report.update(sha256="sha256:" + hashlib.sha256(raw).hexdigest(), bytes=len(raw))
        document = json.loads(content, object_pairs_hook=_pairs,
                              parse_constant=lambda _: (_ for _ in ()).throw(Invalid("non-finite JSON number")))
        _depth(document)
        document = _object(document, "SARIF log")
        if document.get("version") != "2.1.0":
            raise Invalid("only SARIF 2.1.0 is supported")
        report["version"] = "2.1.0"
        runs = _array(document.get("runs"), "runs")
        if len(runs) > MAX_RUNS:
            gap("run count limit exceeded")
        total = 0
        identities = {}
        for run_index, run in enumerate(runs[:MAX_RUNS]):
            meta = {"index": run_index, "analysis_outcome": "unknown"}
            report["runs"].append(meta)
            try:
                run = _object(run, "run")
                driver = _object(_object(run.get("tool"), "tool").get("driver"), "driver")
                meta["tool"] = {key: _text(driver[key], "tool " + key) for key in ("name", "guid", "version", "semanticVersion", "informationUri") if key in driver}
                _text(driver.get("name"), "driver name", empty=False)
                invocations = run.get("invocations", [])
                if not isinstance(invocations, list):
                    gap(f"run {run_index}: invocations must be an array")
                    invocations = []
                if len(invocations) > MAX_INVOCATIONS:
                    gap(f"run {run_index}: invocation count limit exceeded")
                    invocations = invocations[:MAX_INVOCATIONS]
                extensions = _array(run["tool"].get("extensions", []), "extensions")
                if len(extensions) >= MAX_TOOL_COMPONENTS:
                    gap(f"run {run_index}: tool component count limit exceeded")
                for component in [driver] + extensions[:MAX_TOOL_COMPONENTS - 1]:
                    rules = _array(_object(component, "tool component").get("rules", []), "rules")
                    if len(rules) > MAX_RULES:
                        gap(f"run {run_index}: rule count limit exceeded")
                    catalog = []
                    for rule in rules[:MAX_RULES]:
                        try:
                            catalog.append(_rule_metadata(rule))
                        except (Invalid, ValueError, TypeError) as error:
                            gap(f"run {run_index}: invalid rule metadata: {error}")
                    scope = {"driver": driver["name"], "component": _text(component.get("name"), "component name", empty=False),
                                               "guid": _text(component.get("guid", ""), "component GUID"),
                                               "version": _text(component.get("semanticVersion", component.get("version", "")), "component version"),
                                               "rules": catalog,
                                               "rules_revision": "sha256:" + _hash(rules[:MAX_RULES]),
                                               "configuration_revision": "sha256:" + _hash([inv.get("ruleConfigurationOverrides", [])
                                                   for inv in invocations if isinstance(inv, dict)])}
                    if not reserve(scope):
                        scope["rules"] = []
                        scope["metadata_truncated"] = True
                    report["tool_scope"].append(scope)
                meta["automation_id"] = _text(_object(run.get("automationDetails", {}), "automation details").get("id", ""), "automation ID")
                if run.get("externalPropertyFileReferences") or document.get("inlineExternalProperties"):
                    gap(f"run {run_index}: externalized properties unsupported; references not loaded")
                meta["invocations"] = []
                failed = False
                for invocation in invocations:
                    try:
                        status, invocation_failed = _invocation(invocation)
                        failed |= invocation_failed
                        meta["invocations"].append(status)
                    except (Invalid, ValueError, TypeError) as error:
                        gap(f"run {run_index}: {error}")
                        failed = True
                        meta["invocations"].append({"executionSuccessful": None})
                meta["analysis_outcome"] = "failed" if failed else "completed" if invocations else "unknown"
                if meta["analysis_outcome"] != "completed":
                    gap(f"run {run_index}: analyzer outcome {meta['analysis_outcome']}", kind="sarif_analysis", loss=False)
                results = run.get("results")
                if results is None:
                    meta["analysis_outcome"] = "failed"
                    raise Invalid("results absent/null; analyzer results unavailable")
                results = _array(results, "results")
                report["counts"]["results_seen"] += len(results)
                remaining = max(0, MAX_RESULTS - total)
                if len(results) > remaining:
                    gap("result count limit exceeded")
                for result_index, result in enumerate(results[:remaining]):
                    total += 1
                    if report["counts"]["expanded_bytes"] >= MAX_EXPANDED_BYTES - 512:
                        gap("global expanded evidence budget exceeded", kind="sarif_budget")
                        report["counts"]["rejected"] += len(results[:remaining]) - result_index
                        break
                    try:
                        result = _object(result, "result")
                        rule_id, rule, component, namespace = _rule(result, run)
                        message = _message(result.get("message"), rule, component)
                        kind = result.get("kind", "fail")
                        if kind not in {"fail", "pass", "open", "review", "notApplicable", "informational"}:
                            raise Invalid("invalid result kind")
                        state = result.get("baselineState")
                        if state is not None and state not in {"new", "unchanged", "updated", "absent"}:
                            raise Invalid("invalid native baseline state")
                        default_level = _object(rule.get("defaultConfiguration", {}), "rule defaults").get("level", "warning") if kind == "fail" else "none"
                        level = result.get("level", default_level)
                        if level not in {"error", "warning", "note", "none"}:
                            raise Invalid("invalid result level")
                        if (kind == "fail") == (level == "none"):
                            raise Invalid("result kind and level disagree")
                        severity = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}[level]
                        properties = _object(rule.get("properties", {}), "rule properties")
                        score = properties.get("security-severity")
                        if score is not None:
                            try:
                                score = float(score) if not isinstance(score, bool) else math.nan
                            except (ValueError, TypeError):
                                score = math.nan
                            if not math.isfinite(score) or not 0 <= score <= 10:
                                raise Invalid("invalid reported security severity")
                            if kind == "fail":
                                severity = "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score > 0 else "INFO"
                        locations = []
                        native_locations = _array(result.get("locations", []), "result locations")
                        for location in native_locations[:100]:
                            try:
                                locations.append(_location(location, run, excludes, include_fixtures))
                            except Excluded:
                                gap("locations excluded by source scope", kind="sarif_scope", execution=False, loss=False)
                            except (Invalid, UnicodeError, ValueError) as error:
                                gap(f"run {run_index} result {result_index}: {error}")
                        if len(native_locations) > 100:
                            gap("primary location count limit exceeded")
                        if native_locations and not locations:
                            report["counts"]["excluded"] += 1
                            continue
                        primary = locations[0] if locations else {"file": "", "line": 0}
                        native_fps = _maps(result.get("partialFingerprints", {}), "partial fingerprint")
                        fingerprints = _maps(result.get("fingerprints", {}), "fingerprint")
                        stable = native_fps or fingerprints
                        identity = [namespace, rule_id, meta["automation_id"], primary["file"], stable]
                        basis = "producer-fingerprint" if stable else "report-local-occurrence"
                        if not stable:
                            identity += [report["sha256"], run_index, result_index]
                        identity_hash = _hash(identity)
                        occurrence = len(identities.get(identity_hash, [])) + 1
                        # A partial fingerprint is not necessarily unique (identical
                        # source lines can occur twice). Keep every reported site.
                        semantic_id = "sarif:" + identity_hash + (f":occurrence:{occurrence}" if occurrence > 1 else "")
                        suppressions = []
                        for suppression in _array(result.get("suppressions", []), "suppressions"):
                            suppression = _object(suppression, "suppression")
                            if suppression.get("kind") not in {"inSource", "external"}:
                                raise Invalid("invalid suppression kind")
                            if suppression.get("status", "accepted") not in {"accepted", "underReview", "rejected"}:
                                raise Invalid("invalid suppression status")
                            suppressions.append({key: _text(suppression[key], "suppression " + key) for key in ("kind", "status", "justification", "guid") if key in suppression})
                        if suppressions:
                            gap("Native suppressions preserved; failure findings remain active until locally acknowledged", kind="sarif_scope", execution=False, loss=False)
                        related = []
                        native_related = _array(result.get("relatedLocations", []), "related locations")
                        if len(native_related) > 100:
                            gap("related location count limit exceeded")
                        for location in native_related[:100]:
                            try:
                                item = _location(location, run, excludes, include_fixtures)
                                if type(location.get("id")) is int and location["id"] >= 0:
                                    item["id"] = location["id"]
                                if "message" in location:
                                    item["message"] = _message(location["message"], rule, component)
                                related.append(item)
                            except Excluded:
                                gap("related location excluded by source scope", kind="sarif_scope", execution=False, loss=False)
                            except (Invalid, ValueError, UnicodeError) as error:
                                gap(f"invalid related location: {error}")
                        trace = []
                        trace_count = 0
                        flows = _array(result.get("codeFlows", []), "code flows")
                        if len(flows) > 100:
                            gap("code flow count limit exceeded")
                        for flow_index, flow in enumerate(flows[:100]):
                            flow = _object(flow, "code flow")
                            threads = _array(flow.get("threadFlows", []), "thread flows")
                            if len(threads) > 100:
                                gap("thread flow count limit exceeded")
                            for thread_index, thread in enumerate(threads[:100]):
                                steps = []
                                for step in _array(_object(thread, "thread flow").get("locations", []), "thread locations"):
                                    trace_count += 1
                                    if trace_count > MAX_TRACE_STEPS:
                                        gap("trace step limit exceeded")
                                        break
                                    try:
                                        step = _object(step, "trace step")
                                        if "index" in step:
                                            step = _object(_index(step["index"], _array(run.get("threadFlowLocations", []), "shared trace locations"), "trace index"), "shared trace step")
                                            if "index" in step:
                                                raise Invalid("recursive shared trace reference unsupported")
                                        location = _object(step.get("location", {}), "trace location")
                                        item = _location(location, run, excludes, include_fixtures)
                                        if "message" in location:
                                            item["message"] = _message(location["message"], rule, component)
                                        for key in ("executionOrder", "nestingLevel"):
                                            if key in step and type(step[key]) is int and step[key] >= 0:
                                                item[key] = step[key]
                                        if report["counts"]["retained_trace_steps"] >= MAX_RETAINED_TRACE_STEPS:
                                            gap("global retained trace step limit exceeded", kind="sarif_budget")
                                            break
                                        if not reserve(item):
                                            break
                                        steps.append(item)
                                        report["counts"]["retained_trace_steps"] += 1
                                    except Excluded:
                                        gap("trace location excluded by source scope", kind="sarif_scope", execution=False, loss=False)
                                    except (Invalid, ValueError, UnicodeError) as error:
                                        gap(f"invalid trace location: {error}")
                                if steps:
                                    trace.append({"flow_index": flow_index, "thread_index": thread_index, "locations": steps})
                        namespace_id = _hash(namespace)[:16]
                        rule_metadata = _rule_metadata(rule) or {"id": rule_id}
                        if not reserve(rule_metadata):
                            rule_metadata = {"id": rule_id, "metadata_truncated": True}
                        native = {"report_sha256": report["sha256"], "run_index": run_index, "result_index": result_index,
                                  "tool": meta["tool"], "namespace": namespace, "rule_id": rule_id,
                                  "rule": rule_metadata,
                                  "rule_properties": {key: properties[key] for key in ("precision", "security-severity", "tags") if key in properties},
                                  "partial_fingerprints": native_fps, "fingerprints": fingerprints, "identity_basis": basis,
                                  "identity_occurrence": occurrence,
                                  "kind": kind, "level": level, "baseline_state": state, "suppressions": suppressions,
                                  "locations": locations, "related_locations": related, "code_flows": trace,
                                  "analysis_outcome": meta["analysis_outcome"], "source_freshness": "unverified",
                                  "location_binding": report["location_binding"]}
                        row = {"category": "sast", "severity": severity, "title": message, **primary,
                               "tools": ["sarif:" + namespace_id], "key": rule_id,
                               "rule_id": "sarif:" + namespace_id + ":" + rule_id,
                               "semantic_id": semantic_id, "sarif": native}
                        collection = "observations" if kind in {"pass", "notApplicable", "informational"} or state == "absent" else "findings"
                        if not reserve(row):
                            # Keep a compact primary finding if it still fits. Missing
                            # auxiliary evidence remains an explicit execution gap.
                            row["title"] = row["title"][:256]
                            row["sarif"] = {key: native[key] for key in ("report_sha256", "run_index", "result_index", "kind", "level",
                                "baseline_state", "identity_basis", "analysis_outcome", "source_freshness", "location_binding")}
                            row["sarif"]["metadata_truncated"] = True
                            if not reserve(row):
                                report["counts"]["rejected"] += len(results[:remaining]) - result_index
                                break
                        output[collection].append(row)
                        group = identities.setdefault(identity_hash, [])
                        group.append(row)
                        if stable and len(group) > 1:
                            # A producer fingerprint collision cannot identify a site
                            # across reports. Bind every collider, including the first,
                            # to this report so acknowledgements cannot change sites.
                            for colliding in group if len(group) == 2 else [row]:
                                payload = colliding["sarif"]
                                payload["identity_basis"] = "ambiguous-producer-fingerprint-report-bound"
                                colliding["semantic_id"] = "sarif:" + _hash([identity_hash, report["sha256"],
                                    payload["run_index"], payload["result_index"]])
                            gap("Colliding producer fingerprints are report-bound; cross-report acknowledgement migration unavailable",
                                kind="sarif_scope", execution=False, loss=False)
                        report["counts"][collection] += 1
                    except (Invalid, ValueError, TypeError, AttributeError, UnicodeError) as error:
                        report["counts"]["rejected"] += 1
                        gap(f"run {run_index} result {result_index}: {error}")
            except (Invalid, ValueError, TypeError, AttributeError, UnicodeError) as error:
                gap(f"run {run_index}: {error}")
        outcomes = [run["analysis_outcome"] for run in report["runs"]]
        report["analysis_outcome"] = "failed" if "failed" in outcomes else "completed" if outcomes and all(value == "completed" for value in outcomes) else "unknown"
        if not outcomes:
            gap("no analyzer invocation outcomes available", kind="sarif_analysis", loss=False)
    except (OSError, ValueError, TypeError, RecursionError, UnicodeError) as error:
        gap(str(error) or type(error).__name__)
    report["execution_complete"] = not any(gap["execution"] for gap in report["gaps"])
    # The entry budget prevents unbounded construction. This final hard ceiling
    # covers report framing and native run metadata not repeated per finding.
    if len(json.dumps(output, separators=(",", ":")).encode()) > MAX_OUTPUT_BYTES:
        report["counts"]["rejected"] += len(output["findings"]) + len(output["observations"])
        output["findings"], output["observations"] = [], []
        report["counts"]["findings"] = report["counts"]["observations"] = 0
        report["tool_scope"], report["runs"] = [], []
        gap("serialized output byte limit exceeded", kind="sarif_budget")
        report["execution_complete"] = False
    return output

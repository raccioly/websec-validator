"""Machine-readable repair plans and offline validation of operator-supplied verification evidence.

This module never executes a command or treats scanner disappearance as a verified repair.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import baseline, fixprompt
from .extractors.base import RepoContext

SCHEMA_VERSION = "1.0"
_CONTEXT_KEYS = ("application_id", "build_id", "source_digest")


def digest(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def scope_digest(coverage: dict) -> str:
    """Bind verification to the same detector and selected review scope, not universal coverage."""
    from .coverage import import_scope
    scope = {"profile": coverage.get("profile"), "detector_revision": coverage.get("detector_revision"),
             "excludes": (coverage.get("files") or {}).get("excludes", []),
             "include_fixtures": (coverage.get("files") or {}).get("include_fixtures", False),
             "review_policy": coverage.get("review_policy", []),
             "unsupported_types": sorted({Path(path).suffix for path in (coverage.get("files") or {}).get("unsupported", [])}),
             "extractors": sorted((coverage.get("extractors") or {}).keys()),
             "scanners": {key: {field: row.get(field) for field in ("reported_version", "version_verified", "rules_revision",
                                                                  "configuration_policy", "suppression_policy")}
                          for key, row in sorted((coverage.get("scanners") or {}).items()) if row.get("selected")}}
    if coverage.get("imports"):
        scope["imports"] = import_scope(coverage["imports"])
    for key in ("read_policy", "auxiliary_read_policies"):
        if key in (coverage.get("files") or {}):
            scope[key] = coverage["files"][key]
    return digest(scope)


def build(ledger: dict, *, application_id: str = "", build_id: str = "", source_digest: str = "") -> list:
    """Produce immutable plans bound to the original finding and reviewed vulnerable build."""
    baseline.annotate(ledger)
    context = dict(ledger.get("verification_context") or {})
    for key, value in (("application_id", application_id), ("build_id", build_id), ("source_digest", source_digest)):
        if value:
            context[key] = value
    prompts = {p["fingerprint"]: p for p in fixprompt.build(ledger, limit=len(ledger.get("findings", [])))}
    plans = []
    for finding in ledger.get("findings", []):
        plan = {"schema_version": SCHEMA_VERSION, "finding_id": finding["fingerprint"],
                "fingerprint_version": baseline.FINGERPRINT_VERSION,
                "fingerprint_aliases": finding.get("fingerprint_aliases", []),
                "original": {key: context.get(key, "") for key in _CONTEXT_KEYS},
                "original_scope_digest": scope_digest(ledger.get("coverage") or {}),
                "attack_class": finding.get("attack_class"),
                "affected": {"service": finding.get("service") or finding.get("service_id", ""),
                             "file": finding.get("file") or finding.get("location", ""),
                             "method": finding.get("method"), "location": finding.get("location")},
                "prerequisites": ["Confirm the finding on the original build and document intended policy.",
                                  "Use an authorized isolated fixture for tests that can change data.",
                                  "Capture positive and negative test artifacts for the fixed build."],
                "suggested_remediation": finding.get("remediation", ""),
                # Advisory disposition carried through so a plan consumer sees the same third axis
                # as the ledger. The prerequisites below are UNCHANGED by it: every plan still
                # requires confirming the finding on the original build, whatever the disposition.
                "triage": finding.get("triage") or fixprompt.disposition(finding.get("attack_class", "")),
                "verification": {"positive": "Authorized legitimate behavior still succeeds.",
                                 "negative": fixprompt._verify_for(finding.get("attack_class", "")),
                                 "rerun": "Same fixed source digest; required checks complete; finding no longer observed."},
                "prompt": prompts[finding["fingerprint"]]["prompt"]}
        if (ledger.get("coverage") or {}).get("imports"):
            plan["verification"]["limitations"] = ["Imported analysis has unverified source freshness; it cannot support verified repair completion."]
        plan["plan_id"] = digest(plan)
        plans.append(plan)
    return plans


def _valid_context(context) -> bool:
    return (isinstance(context, dict) and all(isinstance(context.get(key), str) and context[key]
                                            for key in _CONTEXT_KEYS)
            and bool(re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", context["source_digest"])))


def validate_verification(plan: dict, record: dict, rerun_ledger: dict, coverage: dict,
                          *, evidence_root: Path | None = None) -> dict:
    """Validate a claimed source transition using bound test artifacts and complete rerun evidence.

    Each test references a relative UTF-8 JSON artifact and its SHA256. The artifact contains
    application_id/build_id/source_digest, kind=positive|negative, status=passed, test_count>0,
    and failed=0, plus plan_id/finding_id/test_id. A negative control references a hashed ``before``
    artifact with the same test_id, failed>0 and original build context. These are operator-produced
    test reports, not independently executed tests.
    """
    errors = []
    # Validate every nested container consumed before the artifact reader's guarded section.
    # Invalid JSON-shaped evidence is a rejection, never a verifier crash or partial acceptance.
    def object_rows(value):
        return isinstance(value, list) and all(isinstance(row, dict) for row in value)

    def aliases(value):
        return isinstance(value, list) and all(isinstance(item, str) for item in value)

    shape_ok = all(isinstance(value, dict) for value in (plan, record, rerun_ledger, coverage))
    if shape_ok:
        shape_ok = (isinstance(plan.get("original", {}), dict) and isinstance(record.get("target", {}), dict)
                    and aliases(plan.get("fingerprint_aliases", []))
                    and isinstance(coverage.get("files", {}), dict)
                    and isinstance(coverage.get("extractors", {}), dict)
                    and isinstance(coverage.get("scanners", {}), dict))
    if shape_ok:
        shape_ok = (all(isinstance(row, dict) for row in coverage.get("scanners", {}).values())
                    and object_rows(coverage.get("imports", []))
                    and aliases(coverage.get("files", {}).get("unsupported", []))
                    and all(object_rows(rerun_ledger.get(key, [])) for key in ("findings", "acknowledged")))
    if shape_ok:
        shape_ok = all(aliases(row.get("fingerprint_aliases", []))
                       and isinstance(row.get("fingerprint", ""), str)
                       for row in rerun_ledger.get("findings", []) + rerun_ledger.get("acknowledged", []))
    if not shape_ok:
        return {"schema_version": SCHEMA_VERSION, "accepted": False, "state": "verification-rejected",
                "errors": ["invalid nested repair evidence structure"], "tests_executed_by_websec": False}
    if plan.get("schema_version") != SCHEMA_VERSION or not isinstance(plan.get("finding_id"), str) or not plan.get("finding_id"):
        errors.append("supported repair plan schema and finding identity are required")
    original = plan.get("original") or {}
    target = record.get("target") or {}
    unsigned_plan = {key: value for key, value in plan.items() if key != "plan_id"}
    if plan.get("plan_id") != digest(unsigned_plan) or record.get("plan_id") != plan.get("plan_id"):
        errors.append("plan identity/digest mismatch")
    if not _valid_context(original) or not _valid_context(target):
        errors.append("complete original and fixed application/build/source digest contexts are required")
    if record.get("original") != original:
        errors.append("record does not identify the original source transition")
    if target.get("application_id") != original.get("application_id"):
        errors.append("application identity changed")
    if target.get("source_digest") == original.get("source_digest"):
        errors.append("fixed source digest must differ from the vulnerable source")
    if rerun_ledger.get("verification_context") != target:
        errors.append("rerun context does not match the fixed build")
    if record.get("rerun_ledger_sha256") != digest(rerun_ledger):
        errors.append("rerun ledger digest mismatch")
    from .coverage import execution_errors
    errors.extend("coverage: " + error for error in execution_errors(coverage))
    if coverage.get("imports"):
        errors.append("unsupported repair evidence: imported analysis source freshness is unverified and unbound to the fixed inputs")
    inputs = coverage.get("inputs")
    analyzed_digest = ("sha256:" + hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()
                       if isinstance(inputs, dict) and inputs else "")
    if coverage != rerun_ledger.get("coverage") or coverage.get("analyzed_input_digest") != analyzed_digest:
        errors.append("coverage does not match the rerun artifact or analyzed input inventory digest")
    if (coverage.get("execution_complete") is not True or coverage.get("analyzed_input_digest") != target.get("source_digest")
            or scope_digest(coverage) != plan.get("original_scope_digest")):
        errors.append("rerun coverage is incomplete or not bound to the analyzed fixed inputs")
    observed = set()
    for row in (rerun_ledger.get("findings") or []) + (rerun_ledger.get("acknowledged") or []):
        observed.add(baseline.fingerprint(row))
        observed.update(row.get("fingerprint_aliases", []))
        if row.get("fingerprint"):
            observed.add(row["fingerprint"])
    if observed.intersection({plan.get("finding_id")} | set(plan.get("fingerprint_aliases", []))):
        errors.append("finding remains observed (including acknowledged findings)")
    if rerun_ledger.get("suppressed", 0):
        errors.append("rerun suppressions could hide the finding")
    if evidence_root is None:
        errors.append("test artifact evidence root is required")
    kinds = set()
    try:
        context = RepoContext(Path(evidence_root), walk=False) if evidence_root is not None else None

        def read_test(reference):
            path = Path(reference.get("artifact", ""))
            if context is None or path.is_absolute() or ".." in path.parts or str(path) == ".":
                raise ValueError("test artifact must be a relative contained file")
            content = context.text(context.root / path, max_bytes=1024 * 1024)
            if not content or hashlib.sha256(content.encode()).hexdigest() != reference.get("sha256"):
                raise ValueError("test artifact missing, unreadable or digest mismatch")
            artifact = json.loads(content)
            if (artifact.get("plan_id") != plan.get("plan_id") or artifact.get("finding_id") != plan.get("finding_id")
                    or not isinstance(artifact.get("test_id"), str) or not artifact["test_id"]):
                raise ValueError("test artifact is not bound to this plan, finding and named test")
            return artifact

        tests = record.get("tests", []) or []
        if not isinstance(tests, list) or len(tests) > 64:
            raise ValueError("test evidence must contain at most 64 artifacts")
        for test in tests:
            artifact = read_test(test)
            if any(artifact.get(key) != target.get(key) for key in _CONTEXT_KEYS):
                raise ValueError("test artifact is for another build or application")
            if (artifact.get("kind") not in ("positive", "negative") or artifact.get("status") != "passed"
                    or type(artifact.get("test_count")) is not int or artifact["test_count"] <= 0
                    or artifact.get("failed") != 0):
                raise ValueError("test artifact does not prove a passing nonempty control")
            if artifact["kind"] == "negative":
                before = read_test(artifact.get("before") or {})
                if (any(before.get(key) != original.get(key) for key in _CONTEXT_KEYS)
                        or before.get("test_id") != artifact["test_id"] or before.get("kind") != "negative"
                        or before.get("status") != "failed" or type(before.get("test_count")) is not int
                        or before["test_count"] <= 0 or type(before.get("failed")) is not int or before["failed"] < 1):
                    raise ValueError("negative control lacks a matching failed test on the original vulnerable build")
            kinds.add(artifact["kind"])
    except (OSError, ValueError, TypeError, AttributeError) as error:
        errors.append(str(error) or "invalid test artifact structure")
    if kinds != {"positive", "negative"}:
        errors.append("both positive and negative passing controls are required")
    return {"schema_version": SCHEMA_VERSION, "finding_id": plan.get("finding_id"),
            "plan_id": plan.get("plan_id"), "state": "verified-fixed" if not errors else "verification-rejected",
            "accepted": not errors, "errors": errors, "target": target,
            "evidence_basis": "operator-supplied build-bound test artifacts and complete rerun",
            "validation_limitations": ["Report consistency and binding checked; source rerun and test execution remain operator-attested."]
                + (["Coverage detail is partial; omitted checks and read-loss fields are not attested."]
                   if not all(key in coverage for key in ("gaps", "extractors", "scanners", "files"))
                   or not all(key in coverage.get("files", {}) for key in ("unreadable", "oversized", "truncated", "inventory_truncated", "glob_truncated")) else []),
            "tests_executed_by_websec": False}

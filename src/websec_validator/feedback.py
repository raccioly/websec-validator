"""Operator feedback on detector correctness — local-first, offline, redacted by default.

Answers a different question from `.websec-ignore`. An ignore entry means "stop showing
me this in this repository"; a feedback record means "this detector is wrong and upstream
should know". Conflating them would either silence findings the operator wanted reported
or report findings they merely wanted quiet, so the two never write to each other.

Redaction is metadata-only by default because a websec finding points at security-relevant
code: a hardcoded-secret finding's snippet IS the secret, and its title and location carry
route and file structure. The default record therefore carries classification and stable
identity only — no path, no route, no evidence prose, no source text. `include_snippet`
opts in to the contextual fields, and the CLI shows the operator the exact record first.

Nothing here performs network I/O. `issue_url` builds a link and returns it; sending is
the operator's explicit act in their own browser.
"""
from __future__ import annotations

import json
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "1.0"
FEEDBACK_FILENAME = "feedback.jsonl"
ISSUE_REPO = "raccioly/websec-validator"

VERDICTS = ("false-positive", "severity-wrong")
SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

MAX_REASON = 1000
MAX_RECORDS = 5000

# Structural/classification fields only. Every one is a detector property or a standards
# mapping; none carries target source, paths, routes or operator data.
_METADATA_FIELDS = (
    "attack_class", "category", "rule_id", "severity", "confidence",
    "identity_precision", "fingerprint", "fingerprint_version",
)
# Contextual fields — these can carry target structure or source text, so they are
# included only under an explicit opt-in.
_SNIPPET_FIELDS = ("title", "location", "file", "method", "evidence")


class FeedbackError(ValueError):
    """Operator-facing feedback failure; the CLI renders this as exit 2."""


def _extension(name) -> str:
    """Suffix only. `src/billing/secrets.py` -> `.py`: language without the path."""
    suffix = Path(str(name or "")).suffix
    return suffix if 0 < len(suffix) <= 12 else ""


def redact(finding: dict, *, include_snippet: bool = False) -> dict:
    """Project a ledger finding onto the shareable record body."""
    body: dict = {}
    for key in _METADATA_FIELDS:
        value = finding.get(key)
        if value is not None:
            body[key] = value
    aliases = finding.get("fingerprint_aliases")
    if isinstance(aliases, list) and aliases:
        body["fingerprint_aliases"] = [str(a) for a in aliases[:8]]
    standards = finding.get("standards")
    if isinstance(standards, dict):
        # CWE/ASVS/OWASP identifiers are public taxonomy, never target content.
        keep = {k: standards[k] for k in ("cwe", "asvs", "owasp_api") if standards.get(k)}
        if keep:
            body["standards"] = keep
    calibrated = finding.get("calibrated")
    if isinstance(calibrated, dict):
        body["calibrated"] = {k: calibrated[k] for k in ("p", "n", "basis") if k in calibrated}
    # Language without location: the extension is the useful signal for a detector bug.
    body["file_extension"] = _extension(finding.get("file"))
    if include_snippet:
        for key in _SNIPPET_FIELDS:
            value = finding.get(key)
            if value is not None:
                body[key] = value
    return body


def find_finding(ledger: dict, fingerprint: str) -> dict:
    """Resolve by V2 fingerprint, then by retained V1 alias. Ambiguity is never guessed."""
    if not fingerprint:
        raise FeedbackError("a --fingerprint is required to identify the finding")
    rows = list(ledger.get("findings") or []) + list(ledger.get("acknowledged") or [])
    exact = [f for f in rows if f.get("fingerprint") == fingerprint]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        raise FeedbackError(f"fingerprint {fingerprint} matches {len(exact)} findings in this ledger")
    aliased = [f for f in rows if fingerprint in (f.get("fingerprint_aliases") or [])]
    if len(aliased) == 1:
        return aliased[0]
    if len(aliased) > 1:
        # A V1 alias can legitimately fan out to several V2 identities; say so rather
        # than picking one, matching how `.websec-ignore` refuses ambiguous acks.
        raise FeedbackError(
            f"legacy fingerprint {fingerprint} is ambiguous across {len(aliased)} current findings; "
            "re-run and use the current fingerprint")
    raise FeedbackError(f"no finding with fingerprint {fingerprint} in this ledger")


def build_record(finding: dict, *, verdict: str, reason: str, envelope: dict | None = None,
                 run_id: str = "", expected_severity: str = "",
                 include_snippet: bool = False, now=None) -> dict:
    if verdict not in VERDICTS:
        raise FeedbackError(f"--verdict must be one of {', '.join(VERDICTS)}")
    reason = (reason or "").strip()
    if not reason:
        raise FeedbackError("--reason is required: state why the detector is wrong")
    if len(reason) > MAX_REASON:
        raise FeedbackError(f"--reason exceeds {MAX_REASON} characters")
    if verdict == "severity-wrong":
        if not expected_severity:
            raise FeedbackError("--expected-severity is required with --verdict severity-wrong")
        if expected_severity not in SEVERITIES:
            raise FeedbackError(f"--expected-severity must be one of {', '.join(SEVERITIES)}")
    elif expected_severity:
        raise FeedbackError("--expected-severity only applies to --verdict severity-wrong")

    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    record = {
        "schema_version": SCHEMA_VERSION,
        "recorded": stamp,
        "verdict": verdict,
        "reason": reason,
        "redaction": "with-context" if include_snippet else "metadata-only",
        "run_id": run_id or "",
        "tool_version": (envelope or {}).get("tool_version", ""),
        "finding": redact(finding, include_snippet=include_snippet),
    }
    if expected_severity:
        record["expected_severity"] = expected_severity
    return record


def append(path: Path, record: dict) -> Path:
    """Append one JSON line. Bounded so a scripted loop cannot grow the file forever."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            if sum(1 for line in handle if line.strip()) >= MAX_RECORDS:
                raise FeedbackError(
                    f"{path} already holds {MAX_RECORDS} records; archive it before adding more")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    return path


def issue_url(record: dict, repo: str = ISSUE_REPO) -> str:
    """Build a prefilled issue link. Returned as text; nothing is opened or sent."""
    finding = record.get("finding", {})
    verdict = record["verdict"]
    title = f"[{verdict}] {finding.get('attack_class') or 'finding'} ({finding.get('rule_id') or 'no rule id'})"
    body = (
        f"**Verdict:** {verdict}\n"
        f"**Reason:** {record['reason']}\n"
        f"**Redaction:** {record['redaction']}\n"
        f"**Tool version:** {record.get('tool_version') or 'unknown'}\n\n"
        "<details><summary>Redacted finding record</summary>\n\n```json\n"
        + json.dumps(record, indent=2, sort_keys=True)
        + "\n```\n</details>\n"
    )
    query = urllib.parse.urlencode({"title": title, "body": body, "labels": verdict})
    return f"https://github.com/{repo}/issues/new?{query}"

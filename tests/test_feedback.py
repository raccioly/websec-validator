"""Operator feedback records: redaction, fingerprint resolution, bounded append.

The leak tests are the point of this file. A websec finding points at security-relevant
code, so the default record must never carry target paths, routes, evidence prose or
source text out of the repository.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from websec_validator import feedback as fb

# Every string here is target-identifying and must not escape in a metadata-only record.
SECRET_ROUTE = "/internal/billing/{customer_id}"
SECRET_FILE = "src/billing/charge_secrets.py"
SECRET_TITLE = f"Missing authorization: GET {SECRET_ROUTE}"
SECRET_EVIDENCE = "no auth guard found in handler charge_secrets.py; AKIAIOSFODNN7EXAMPLE nearby"

FINDING = {
    "title": SECRET_TITLE,
    "category": "access-control",
    "attack_class": "missing-auth",
    "severity": "MEDIUM",
    "confidence": "MEDIUM",
    "location": SECRET_ROUTE,
    "evidence": [{"layer": "recon", "detail": SECRET_EVIDENCE}],
    "standards": {"cwe": ["CWE-862 Missing Authorization"], "asvs": "ASVS 4.0.3 V4.1.1",
                  "owasp_api": ["API1:2023 BOLA"], "sources": []},
    "remediation": "Add an auth guard.",
    "status": "open",
    "file": SECRET_FILE,
    "method": "GET",
    "service_id": "billing",
    "rule_id": "missing-route-guard",
    "fingerprint": "b0bd5e900126aed8",
    "fingerprint_version": 2,
    "fingerprint_aliases": ["968b511812bdc075"],
    "identity_precision": "semantic",
    "calibrated": {"p": 0.5, "ci": [0.0, 1.0], "n": 0, "basis": "prior (uncalibrated)"},
}
LEDGER = {"schema_version": "2.0", "findings": [FINDING]}
FIXED = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)


def _record(**kwargs):
    params = dict(verdict="false-positive", reason="behind an nginx auth_request",
                  envelope={"tool_version": "9.9.9"}, run_id="20260915-000000-aaaaaaaa", now=FIXED)
    params.update(kwargs)
    return fb.build_record(FINDING, **params)


class RedactionTests(unittest.TestCase):
    def test_metadata_only_record_leaks_no_target_identifier(self):
        blob = json.dumps(_record()) + fb.issue_url(_record())
        for secret in (SECRET_ROUTE, SECRET_FILE, SECRET_TITLE, SECRET_EVIDENCE,
                       "AKIAIOSFODNN7EXAMPLE", "charge_secrets", "billing"):
            self.assertNotIn(secret, blob, f"{secret!r} escaped in a metadata-only record")

    def test_metadata_only_keeps_the_fields_that_make_a_report_actionable(self):
        finding = _record()["finding"]
        self.assertEqual(finding["fingerprint"], "b0bd5e900126aed8")
        self.assertEqual(finding["rule_id"], "missing-route-guard")
        self.assertEqual(finding["attack_class"], "missing-auth")
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["file_extension"], ".py")
        self.assertEqual(finding["standards"]["asvs"], "ASVS 4.0.3 V4.1.1")
        # Provenance travels; ci is noise for a bug report and is dropped.
        self.assertEqual(finding["calibrated"], {"p": 0.5, "n": 0, "basis": "prior (uncalibrated)"})

    def test_extension_carries_language_without_path(self):
        self.assertEqual(fb._extension("src/billing/charge_secrets.py"), ".py")
        self.assertEqual(fb._extension("Dockerfile"), "")
        self.assertEqual(fb._extension(None), "")
        self.assertEqual(fb._extension("archive.tar.gz"), ".gz")

    def test_include_snippet_is_the_only_way_context_travels(self):
        record = _record(include_snippet=True)
        self.assertEqual(record["redaction"], "with-context")
        self.assertEqual(record["finding"]["location"], SECRET_ROUTE)
        self.assertEqual(record["finding"]["file"], SECRET_FILE)
        self.assertIn(SECRET_EVIDENCE, json.dumps(record["finding"]["evidence"]))
        # The opt-in is recorded, so a reader can tell which records were widened.
        self.assertEqual(_record()["redaction"], "metadata-only")


class VerdictTests(unittest.TestCase):
    def test_reason_is_required_and_bounded(self):
        for bad in ("", "   "):
            with self.assertRaises(fb.FeedbackError):
                _record(reason=bad)
        with self.assertRaises(fb.FeedbackError):
            _record(reason="x" * (fb.MAX_REASON + 1))

    def test_unknown_verdict_is_refused(self):
        with self.assertRaises(fb.FeedbackError):
            _record(verdict="looks-fine")

    def test_severity_wrong_requires_a_valid_expected_severity(self):
        with self.assertRaises(fb.FeedbackError):
            _record(verdict="severity-wrong")
        with self.assertRaises(fb.FeedbackError):
            _record(verdict="severity-wrong", expected_severity="SPICY")
        record = _record(verdict="severity-wrong", expected_severity="LOW")
        self.assertEqual(record["expected_severity"], "LOW")

    def test_expected_severity_is_refused_for_an_unrelated_verdict(self):
        with self.assertRaises(fb.FeedbackError):
            _record(verdict="false-positive", expected_severity="LOW")


class FalseNegativeTests(unittest.TestCase):
    """A miss has no fingerprint — the point is that nothing was reported."""

    def test_missed_record_has_no_finding_block(self):
        record = fb.build_missed_record(attack_class="sqli", reason="raw concat in reports",
                                        now=FIXED)
        self.assertEqual(record["verdict"], "false-negative")
        self.assertNotIn("finding", record)
        self.assertEqual(record["missed"]["attack_class"], "sqli")
        self.assertEqual(record["redaction"], "metadata-only")

    def test_only_the_extension_survives_a_supplied_filename(self):
        record = fb.build_missed_record(attack_class="sqli", reason="r",
                                        file_extension="src/billing/charge_secrets.py", now=FIXED)
        self.assertEqual(record["missed"]["file_extension"], ".py")
        self.assertNotIn("charge_secrets", json.dumps(record))

    def test_attack_class_and_reason_are_required_and_bounded(self):
        for kwargs in ({"attack_class": "", "reason": "r"},
                       {"attack_class": "sqli", "reason": "  "},
                       {"attack_class": "Not A Class", "reason": "r"},
                       {"attack_class": "sqli", "reason": "x" * (fb.MAX_REASON + 1)}):
            with self.subTest(**kwargs), self.assertRaises(fb.FeedbackError):
                fb.build_missed_record(now=FIXED, **kwargs)

    def test_finding_builder_refuses_the_false_negative_verdict(self):
        # The two record shapes must not be interchangeable.
        with self.assertRaises(fb.FeedbackError):
            _record(verdict="false-negative")

    def test_issue_title_says_not_reported(self):
        record = fb.build_missed_record(attack_class="sqli", reason="r", now=FIXED)
        self.assertIn("false-negative", fb.issue_url(record))
        self.assertIn("not+reported", fb.issue_url(record))


class ResolutionTests(unittest.TestCase):
    def test_resolves_by_current_fingerprint_and_by_retained_alias(self):
        self.assertIs(fb.find_finding(LEDGER, "b0bd5e900126aed8"), FINDING)
        self.assertIs(fb.find_finding(LEDGER, "968b511812bdc075"), FINDING)

    def test_acknowledged_findings_can_still_be_reported(self):
        # Suppressing a finding locally does not mean the detector was right about it.
        ledger = {"findings": [], "acknowledged": [FINDING]}
        self.assertIs(fb.find_finding(ledger, "b0bd5e900126aed8"), FINDING)

    def test_unknown_and_ambiguous_fingerprints_are_refused_not_guessed(self):
        with self.assertRaises(fb.FeedbackError):
            fb.find_finding(LEDGER, "0" * 16)
        with self.assertRaises(fb.FeedbackError):
            fb.find_finding(LEDGER, "")
        fanned = {"findings": [FINDING, {**FINDING, "fingerprint": "cafebabecafebabe"}]}
        with self.assertRaises(fb.FeedbackError) as caught:
            fb.find_finding(fanned, "968b511812bdc075")
        self.assertIn("ambiguous", str(caught.exception))


class AppendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "nested" / fb.FEEDBACK_FILENAME

    def test_append_creates_parents_and_writes_one_line_per_record(self):
        fb.append(self.path, _record())
        fb.append(self.path, _record(reason="second"))
        lines = self.path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[1])["reason"], "second")
        self.assertEqual(json.loads(lines[0])["run_id"], "20260915-000000-aaaaaaaa")

    def test_append_is_bounded_so_a_loop_cannot_grow_the_file_forever(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text('{"x":1}\n' * fb.MAX_RECORDS, encoding="utf-8")
        with self.assertRaises(fb.FeedbackError):
            fb.append(self.path, _record())


class IssueUrlTests(unittest.TestCase):
    def test_url_is_a_link_only_and_encodes_the_record(self):
        url = fb.issue_url(_record())
        self.assertTrue(url.startswith("https://github.com/raccioly/websec-validator/issues/new?"))
        self.assertIn("labels=false-positive", url)
        self.assertIn("missing-route-guard", url)  # url-encoded body carries the rule id

    def test_reason_is_escaped_rather_than_breaking_the_query(self):
        url = fb.issue_url(_record(reason="a&b=c #frag"))
        self.assertNotIn("a&b=c", url)
        self.assertIn("a%26b%3Dc", url)


if __name__ == "__main__":
    unittest.main()

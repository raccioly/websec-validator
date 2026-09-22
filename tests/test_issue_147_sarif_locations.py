"""Every SARIF result carries a location — GitHub Code Scanning rejects the file otherwise.

Issue #147: `upload-sarif` failed against Code Scanning because some results had no `locations`.
Code Scanning rejects the ENTIRE file in that case, so one unanchorable project-level finding
discarded every valid result alongside it. The scan itself was fine; only the upload failed, which
turned a green security posture into a red CI job for an unrelated reason.

@req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-007
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator import formats
from websec_validator.formats import _is_pathlike

FACTS = {"target": "t", "version": "0.0.0",
         "coverage": {"execution_complete": True, "gaps": [], "scanners": {}}}


def _finding(attack_class, location, file=None):
    row = {"title": f"{attack_class} finding", "attack_class": attack_class, "severity": "MEDIUM",
           "confidence": "MEDIUM", "location": location, "fingerprint": attack_class * 2,
           "standards": {"cwe": [], "asvs": "", "owasp_api": []},
           "remediation": "r", "status": "open", "category": "test",
           "evidence": [{"layer": "recon", "detail": "d"}],
           "calibrated": {"p": 0.5, "ci": [0.1, 0.9], "n": 10, "basis": "label"}}
    if file:
        row["file"] = file
    return row


def _sarif(findings):
    ledger = {"findings": findings, "total": len(findings), "by_severity": {}, "by_confidence": {}}
    return formats.to_sarif(ledger, FACTS, "0.0.0")


class PathlikeTests(unittest.TestCase):
    def test_extensionless_build_files_are_real_paths(self):
        """`Dockerfile` failed both the extension test and the "/" test, so it lost its location."""
        for name in ("Dockerfile", "Makefile", "Jenkinsfile", "Gemfile", "app/Dockerfile"):
            with self.subTest(name=name):
                self.assertTrue(_is_pathlike(name))

    def test_routes_and_prose_are_still_not_paths(self):
        for name in ("(response headers)", "set-password paths", "GET /api/x", "/api/admin/users"):
            with self.subTest(name=name):
                self.assertFalse(_is_pathlike(name))


class EveryResultHasALocationTests(unittest.TestCase):
    def test_project_level_findings_are_anchored_not_dropped(self):
        doc = _sarif([_finding("missing-csp", "(response headers)"),
                      _finding("password-policy", "set-password paths")])
        results = doc["runs"][0]["results"]
        self.assertEqual(len(results), 2)
        for result in results:
            with self.subTest(rule=result["ruleId"]):
                self.assertTrue(result.get("locations"), "Code Scanning rejects the whole upload")
                uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                self.assertTrue(uri)

    def test_the_conceptual_location_is_preserved_not_replaced(self):
        """Anchoring must not claim the finding lives in that file."""
        result = _sarif([_finding("missing-csp", "(response headers)")])["runs"][0]["results"][0]
        self.assertTrue(result["properties"]["projectLevel"])
        self.assertEqual(result["properties"]["locationHint"], "(response headers)")
        self.assertEqual(result["locations"][0]["properties"]["conceptualLocation"],
                         "(response headers)")
        self.assertTrue(result["locations"][0]["properties"]["anchoredAtRepositoryRoot"])

    def test_a_dockerfile_finding_anchors_to_the_real_file(self):
        result = _sarif([_finding("iac", "Dockerfile")])["runs"][0]["results"][0]
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                         "Dockerfile")
        self.assertNotIn("projectLevel", result["properties"])

    def test_ordinary_file_findings_are_unchanged(self):
        result = _sarif([_finding("xss", "app/x.js:12")])["runs"][0]["results"][0]
        physical = result["locations"][0]["physicalLocation"]
        self.assertEqual(physical["artifactLocation"]["uri"], "app/x.js")
        self.assertEqual(physical["region"]["startLine"], 12)
        self.assertNotIn("projectLevel", result["properties"])

    def test_a_mixed_report_has_no_unanchored_result(self):
        """The failing shape from the issue: valid results beside unanchorable ones."""
        doc = _sarif([_finding("xss", "app/x.js:3"), _finding("missing-csp", "(response headers)"),
                      _finding("iac", "Dockerfile"), _finding("incomplete-hsts", "(response headers)"),
                      _finding("password-policy", "set-password paths")])
        unanchored = [r for r in doc["runs"][0]["results"] if not r.get("locations")]
        self.assertEqual(unanchored, [], "one unanchored result discards the entire upload")

    def test_the_document_is_still_valid_sarif_json(self):
        doc = _sarif([_finding("missing-csp", "(response headers)")])
        json.dumps(doc)
        self.assertEqual(doc["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()


class FeedbackDiscoverabilityTests(unittest.TestCase):
    """Issue #141: the offline-verdict path was undiscoverable from the report itself.

    The report listed findings and nothing beside them said how to dispute one — so the calibration
    loop had no way to receive the data it needs most. Pinned here because it is the only place a
    real user is looking when they decide a finding is wrong.
    """

    def _report(self):
        from websec_validator import report
        ledger = {"findings": [_finding("xss", "app/x.js:3")], "total": 1,
                  "by_severity": {"MEDIUM": 1}, "by_confidence": {"MEDIUM": 1},
                  "calibration": {"caveat": "test caveat"}}
        return report.render(dict(FACTS), {}, [], None, [], "20260922-000000-test", ledger)

    def test_the_report_names_the_feedback_command(self):
        text = self._report()
        self.assertIn("websec feedback", text)
        self.assertIn("--verdict false-positive", text)
        self.assertIn("--fingerprint", text)

    def test_it_says_feedback_does_not_suppress(self):
        """The two paths must stay distinct, or a user silences what they meant to report."""
        text = self._report()
        self.assertIn(".websec-ignore", text)
        self.assertIn("does not suppress", text)

    def test_it_states_the_privacy_default_and_that_nothing_is_sent(self):
        text = self._report()
        self.assertIn("metadata-only", text)
        self.assertIn("sent anywhere", text)

    def test_it_explains_that_accepting_is_what_moves_the_number(self):
        text = self._report()
        self.assertIn("calibrate --review", text)
        self.assertIn("Nothing changes until", text)

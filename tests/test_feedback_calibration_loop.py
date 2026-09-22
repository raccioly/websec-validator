"""End-to-end: `websec feedback` → candidate → `websec calibrate --review/--accept`.

Also pins what must NOT change: feedback.jsonl keeps its schema, the ignore file is still never
written, and no probability moves before a human accepts.

@req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-009
"""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator import calibration, cli, coverage, feedback

LEDGER = {
    "schema_version": "2.0",
    "findings": [{
        "title": "SSRF: fetch(req.query.url)", "attack_class": "ssrf", "category": "attack-surface",
        "severity": "MEDIUM", "confidence": "LOW", "location": "app.ts", "file": "app.ts",
        "rule_id": "ssrf", "fingerprint": "feedfacecafe0001", "fingerprint_version": 2,
        "fingerprint_aliases": [], "identity_precision": "semantic", "status": "open",
        "calibrated": {"p": 0.25, "ci": [0.0, 1.0], "n": 0, "basis": "prior (uncalibrated)"},
        "standards": {"cwe": ["CWE-918 SSRF"]},
    }],
    "total": 1,
}


class LoopTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.run_dir = base / "out" / "runs" / "20260921-000000-test"
        self.run_dir.mkdir(parents=True)
        (self.run_dir / "findings-ledger.json").write_text(json.dumps(LEDGER))
        # The REAL detector revision: the stale guard compares the candidate's revision against
        # this build's, so a fabricated one here would (correctly) be refused as stale.
        self.revision = coverage.detector_revision()
        (self.run_dir / "coverage.json").write_text(json.dumps(
            {"detector_revision": self.revision, "analyzed_input_digest": "sha256:d0d0"}))
        self.out = base / "out"
        home = base / "calhome"
        for attr, value in (("LOCAL_PATH", home / "calibration-local.json"),
                            ("SYNTHETIC_PATH", home / "calibration-synthetic.json")):
            patcher = patch.object(calibration, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_cli(self, *args):
        buf = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(contextlib.redirect_stdout(buf))
            stack.enter_context(contextlib.redirect_stderr(buf))
            code = cli.main(list(args))
        return code, buf.getvalue()

    def report_fp(self, reason="the URL is a module-level constant"):
        return self.run_cli("feedback", "--verdict", "false-positive",
                            "--fingerprint", "feedfacecafe0001", "--reason", reason,
                            "--out", str(self.out),
                            "--ledger", str(self.run_dir / "findings-ledger.json"))

    def test_reporting_queues_a_candidate_and_says_so(self):
        code, output = self.report_fp()
        self.assertEqual(code, 0)
        self.assertIn("calibration candidate", output)
        self.assertIn("No probability changed", output)
        self.assertEqual(len(calibration.candidates()), 1)

    def test_feedback_jsonl_is_still_written_unchanged(self):
        self.report_fp()
        path = self.out / feedback.FEEDBACK_FILENAME
        record = json.loads(path.read_text().splitlines()[0])
        self.assertEqual(record["schema_version"], "1.0")
        self.assertEqual(record["verdict"], "false-positive")
        self.assertEqual(record["redaction"], "metadata-only")
        self.assertNotIn("file", record["finding"], "metadata-only must not carry the path")

    def test_feedback_still_never_writes_an_ignore_file(self):
        """Feedback reports a detector bug; suppression is a separate, local decision."""
        self.report_fp()
        for name in (".websec-ignore", "websec-ignore"):
            self.assertFalse((Path(self.tmp.name) / name).exists())
            self.assertFalse((self.out / name).exists())

    def test_the_probability_does_not_move_until_a_human_accepts(self):
        before = calibration.apply("ssrf", "LOW", calibration.load())
        self.report_fp()
        self.assertEqual(calibration.apply("ssrf", "LOW", calibration.load()), before)

    def test_review_lists_the_candidate_without_counting_it(self):
        self.report_fp()
        code, output = self.run_cli("calibrate", "--review")
        self.assertEqual(code, 0)
        self.assertIn("pending candidate", output)
        self.assertIn("ssrf|LOW", output)
        self.assertIn("none is counted until accepted", output)

    def test_accept_without_reason_exits_two(self):
        self.report_fp()
        cid = calibration.candidates()[0]["candidate_id"]
        code, output = self.run_cli("calibrate", "--accept", cid)
        self.assertEqual(code, 2)
        self.assertIn("requires --reason", output)

    def test_accept_with_reason_records_exactly_one_sample(self):
        self.report_fp()
        cid = calibration.candidates()[0]["candidate_id"]
        code, output = self.run_cli("calibrate", "--accept", cid,
                                    "--reason", "verified by hand: literal URL")
        self.assertEqual(code, 0)
        self.assertIn("accepted", output)
        overlay = json.loads(calibration.LOCAL_PATH.read_text())
        self.assertEqual(overlay["by_class_label"]["ssrf|LOW"], {"n": 1, "k": 0})
        self.assertEqual(calibration.candidates(), [])

    def test_a_candidate_from_another_detector_build_is_refused_at_the_cli(self):
        """The guard must hold through the CLI, not just in the library."""
        self.report_fp()
        cid = calibration.candidates()[0]["candidate_id"]
        overlay = json.loads(calibration.LOCAL_PATH.read_text())
        overlay["feedback_candidates"][cid]["detector_revision"] = "sha256:" + "0" * 64
        calibration.LOCAL_PATH.write_text(json.dumps(overlay))
        code, output = self.run_cli("calibrate", "--accept", cid, "--reason", "I am sure")
        self.assertEqual(code, 2)
        self.assertIn("STALE", output)

    def test_reject_discards_without_recording(self):
        self.report_fp()
        cid = calibration.candidates()[0]["candidate_id"]
        code, output = self.run_cli("calibrate", "--reject", cid)
        self.assertEqual(code, 0)
        self.assertIn("rejected", output)
        self.assertEqual(calibration.candidates(), [])
        overlay = json.loads(calibration.LOCAL_PATH.read_text())
        self.assertEqual(overlay.get("by_class_label", {}), {})

    def test_review_json_format_is_machine_readable(self):
        self.report_fp()
        code, output = self.run_cli("calibrate", "--review", "--format", "json")
        self.assertEqual(code, 0)
        payload = json.loads(output[output.index("{"):output.rindex("}") + 1])
        self.assertEqual(len(payload["candidates"]), 1)
        self.assertEqual(payload["candidates"][0]["attack_class"], "ssrf")
        self.assertIn("detector_revision", payload)

    def test_review_with_no_candidates_is_a_pass_not_an_error(self):
        code, output = self.run_cli("calibrate", "--review")
        self.assertEqual(code, 0)
        self.assertIn("no pending calibration candidates", output)

    def test_severity_wrong_reports_queue_no_candidate(self):
        code, output = self.run_cli(
            "feedback", "--verdict", "severity-wrong", "--fingerprint", "feedfacecafe0001",
            "--reason", "this should be HIGH", "--expected-severity", "HIGH",
            "--out", str(self.out), "--ledger", str(self.run_dir / "findings-ledger.json"))
        self.assertEqual(code, 0)
        self.assertNotIn("calibration candidate", output)
        self.assertEqual(calibration.candidates(), [])


if __name__ == "__main__":
    unittest.main()

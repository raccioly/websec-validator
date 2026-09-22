"""Operator feedback becomes a CANDIDATE, and only a human promotes it into a probability.

The gap this closes: feedback.jsonl was write-only — written by `websec feedback`, read by nothing,
so a false-positive report had zero effect on any future confidence. The gap it must NOT open:
an operator's verdict is evidence, not proof. A wrong label lowers P(real) for that bucket on every
future run of every project on the machine, permanently — bug-212 poisoned the overlay exactly that
way. So the bar (`evidence_verified` + `sample_id` + `provenance`) is enforced on the far side of an
explicit human acceptance, and there is no second, weaker door into a cell.

@req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-009
@req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-010
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator import calibration

REV = "sha256:" + "a" * 64
OTHER_REV = "sha256:" + "b" * 64


def _record(verdict="false-positive", attack_class="sqli", confidence="MEDIUM",
            fingerprint="fp0001", reason="the value is a literal, not request data"):
    return {"schema_version": "1.0", "recorded": "2026-09-21T10:00:00Z", "verdict": verdict,
            "reason": reason, "redaction": "metadata-only", "tool_version": "0.16.0",
            "finding": {"attack_class": attack_class, "confidence": confidence,
                        "fingerprint": fingerprint, "rule_id": attack_class}}


class _Overlay(unittest.TestCase):
    """Each test gets its own overlay; the real one is user-global and must never be touched.

    The SHIPPED table is also isolated. These tests assert how a candidate moves (or fails to move)
    a probability, which must hold whatever the shipped corpus currently measures — pinning them to
    it would make them fail every time the corpus is relabelled, which is a maintenance trap rather
    than a property of the code.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        home = Path(self.tmp.name)
        self.local = home / "calibration-local.json"
        for attr, value in (("LOCAL_PATH", self.local),
                            ("SYNTHETIC_PATH", home / "calibration-synthetic.json")):
            patcher = patch.object(calibration, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        shipped = patch.object(calibration, "load_shipped", lambda: None)
        shipped.start()
        self.addCleanup(shipped.stop)

    def overlay(self):
        return json.loads(self.local.read_text()) if self.local.exists() else {}


class CandidateTests(_Overlay):
    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-009
    def test_a_false_positive_report_changes_no_probability(self):
        before = calibration.apply("sqli", "MEDIUM", calibration.load())
        candidate = calibration.record_candidate(_record(), detector_revision=REV)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate["state"], "pending")
        after = calibration.apply("sqli", "MEDIUM", calibration.load())
        self.assertEqual(before, after, "a pending candidate must not move any number")
        self.assertEqual(self.overlay().get("by_class_label", {}), {})

    def test_candidate_carries_the_evidence_needed_to_review_it(self):
        candidate = calibration.record_candidate(
            _record(), detector_revision=REV, analyzed_input_digest="sha256:beef")
        self.assertEqual(candidate["attack_class"], "sqli")
        self.assertEqual(candidate["confidence"], "MEDIUM")
        self.assertEqual(candidate["detector_revision"], REV)
        self.assertEqual(candidate["analyzed_input_digest"], "sha256:beef")
        self.assertIs(candidate["is_real"], False)

    def test_reporting_the_same_finding_twice_does_not_duplicate(self):
        first = calibration.record_candidate(_record(), detector_revision=REV)
        second = calibration.record_candidate(_record(), detector_revision=REV)
        self.assertEqual(first["candidate_id"], second["candidate_id"])
        self.assertEqual(len(calibration.candidates()), 1)

    def test_the_same_finding_on_a_different_detector_is_a_different_claim(self):
        calibration.record_candidate(_record(), detector_revision=REV)
        calibration.record_candidate(_record(), detector_revision=OTHER_REV)
        self.assertEqual(len(calibration.candidates()), 2,
                         "a rule may have changed; the two reports are not the same claim")

    def test_only_false_positive_is_a_label(self):
        """severity-wrong disputes severity, not existence; false-negative has no finding at all."""
        for verdict in ("severity-wrong", "false-negative"):
            with self.subTest(verdict=verdict):
                self.assertIsNone(calibration.record_candidate(_record(verdict=verdict),
                                                               detector_revision=REV))
        self.assertEqual(calibration.candidates(), [])

    def test_a_record_without_a_scoreable_bucket_is_refused(self):
        for finding in ({"confidence": "MEDIUM"}, {"attack_class": "sqli"},
                        {"attack_class": "sqli", "confidence": "WOBBLY"}):
            with self.subTest(finding=finding):
                record = _record()
                record["finding"] = finding
                self.assertIsNone(calibration.record_candidate(record, detector_revision=REV))

    def test_malformed_input_is_refused_rather_than_stored(self):
        for junk in (None, "a string", 42, []):
            with self.subTest(junk=junk):
                self.assertIsNone(calibration.record_candidate(junk))


class ReviewGateTests(_Overlay):
    def setUp(self):
        super().setUp()
        self.candidate = calibration.record_candidate(_record(), detector_revision=REV)

    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-010
    def test_accepting_requires_a_reviewer_reason(self):
        result = calibration.review_candidate(self.candidate["candidate_id"], accept=True, reason="  ")
        self.assertFalse(result["ok"])
        self.assertIn("requires --reason", result["error"])
        self.assertEqual(self.overlay().get("by_class_label", {}), {},
                         "a refused acceptance must not write a cell")

    def test_accepting_a_stale_candidate_is_refused(self):
        """The detector that produced the finding no longer exists, so the claim is unverifiable."""
        result = calibration.review_candidate(self.candidate["candidate_id"], accept=True,
                                              reason="I am sure", current_revision=OTHER_REV)
        self.assertFalse(result["ok"])
        self.assertIn("STALE", result["error"])
        self.assertEqual(self.overlay().get("by_class_label", {}), {})
        self.assertEqual(len(calibration.candidates()), 1, "a refused candidate stays pending")

    def test_accepting_records_one_negative_sample_with_full_provenance(self):
        result = calibration.review_candidate(self.candidate["candidate_id"], accept=True,
                                              reason="confirmed: literal, no request data reaches it",
                                              current_revision=REV)
        self.assertTrue(result["ok"])
        overlay = self.overlay()
        self.assertEqual(overlay["by_class_label"]["sqli|MEDIUM"], {"n": 1, "k": 0})
        observation = next(iter(overlay["observations"].values()))
        self.assertIs(observation["is_real"], False)
        self.assertIs(observation["evidence_verified"], True)
        self.assertEqual(observation["provenance"]["kind"], "operator-review")
        self.assertIn("confirmed: literal", observation["provenance"]["reviewer_reason"])
        self.assertEqual(observation["provenance"]["detector_revision"], REV)

    def test_accepting_removes_it_from_the_pending_queue(self):
        calibration.review_candidate(self.candidate["candidate_id"], accept=True,
                                     reason="verified by hand", current_revision=REV)
        self.assertEqual(calibration.candidates(), [])

    def test_accepting_twice_cannot_double_count(self):
        cid = self.candidate["candidate_id"]
        calibration.review_candidate(cid, accept=True, reason="verified", current_revision=REV)
        again = calibration.review_candidate(cid, accept=True, reason="verified", current_revision=REV)
        self.assertFalse(again["ok"])
        self.assertEqual(self.overlay()["by_class_label"]["sqli|MEDIUM"]["n"], 1)

    def test_rejecting_discards_it_and_writes_nothing(self):
        result = calibration.review_candidate(self.candidate["candidate_id"], accept=False)
        self.assertTrue(result["ok"])
        self.assertEqual(result["candidate"]["state"], "rejected")
        self.assertEqual(calibration.candidates(), [])
        self.assertEqual(self.overlay().get("by_class_label", {}), {})

    def test_reviewing_an_unknown_candidate_is_an_error_not_a_silent_pass(self):
        result = calibration.review_candidate("nope", accept=True, reason="x")
        self.assertFalse(result["ok"])
        self.assertIn("no pending candidate", result["error"])

    def test_one_accepted_label_does_not_move_the_probability_below_min_n(self):
        """A single label must not become a number: MIN_N is the floor for a measured cell."""
        calibration.review_candidate(self.candidate["candidate_id"], accept=True,
                                     reason="verified", current_revision=REV)
        estimate = calibration.apply("sqli", "MEDIUM", calibration.load())
        self.assertEqual(estimate["basis"], "prior (uncalibrated)")
        self.assertEqual(estimate["n"], 0)

    def test_candidates_are_marked_stale_against_the_current_detector(self):
        self.assertFalse(calibration.candidates(REV)[0]["stale"])
        self.assertTrue(calibration.candidates(OTHER_REV)[0]["stale"])
        self.assertFalse(calibration.candidates()[0]["stale"], "no revision given ⇒ no claim")


class SyntheticSeparationTests(_Overlay):
    """Authored-pair precision is published beside P(real), never inside it."""

    PAIRS = [{"attack_class": "xss", "confidence": "LOW", "is_real": True, "sample_id": "p1"},
             {"attack_class": "xss", "confidence": "LOW", "is_real": False, "sample_id": "p2"}]

    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#SC-007
    def test_synthetic_table_never_reaches_apply(self):
        calibration.write_synthetic(calibration.fit_synthetic(self.PAIRS * 5))
        estimate = calibration.apply("xss", "LOW", calibration.load())
        self.assertEqual(estimate["basis"], "prior (uncalibrated)",
                         "authored pairs must not become the measured probability")
        self.assertEqual(estimate["n"], 0)

    def test_synthetic_table_is_a_separate_file_from_the_overlay(self):
        calibration.write_synthetic(calibration.fit_synthetic(self.PAIRS))
        self.assertNotEqual(calibration.SYNTHETIC_PATH, calibration.LOCAL_PATH)
        self.assertEqual((calibration.load() or {}).get("by_class_label", {}), {})

    def test_synthetic_table_carries_its_own_basis_and_caveat(self):
        table = calibration.fit_synthetic(self.PAIRS)
        self.assertEqual(table["meta"]["basis"], "synthetic-paired")
        caveat = table["meta"]["caveat"].lower()
        self.assertIn("regression precision", caveat)
        self.assertIn("not the rate in real code", caveat)
        self.assertIn("never_merged", table["meta"])

    def test_cells_count_correct_reports_the_same_way_the_measured_table_does(self):
        table = calibration.fit_synthetic(self.PAIRS)
        self.assertEqual(table["by_class_label"]["xss|LOW"]["n"], 2)
        self.assertEqual(table["by_class_label"]["xss|LOW"]["k"], 1)

    def test_unknown_labels_are_excluded(self):
        rows = self.PAIRS + [{"attack_class": "xss", "confidence": "LOW", "is_real": None}]
        self.assertEqual(calibration.fit_synthetic(rows)["by_class_label"]["xss|LOW"]["n"], 2)

    def test_load_synthetic_is_none_when_never_scored(self):
        self.assertIsNone(calibration.load_synthetic())


class ClaimspecUnaffectedTests(_Overlay):
    """The exported claimspec document must keep reporting only measured cells."""

    def test_accepted_feedback_appears_as_a_measured_bucket_not_a_new_field(self):
        candidate = calibration.record_candidate(_record(), detector_revision=REV)
        calibration.review_candidate(candidate["candidate_id"], accept=True,
                                     reason="verified", current_revision=REV)
        calibration.write_synthetic(calibration.fit_synthetic(
            [{"attack_class": "xss", "confidence": "LOW", "is_real": True, "sample_id": "p"}]))
        doc = calibration.to_claimspec(calibration.load())
        self.assertEqual(doc["measures"], "finding-real")
        self.assertNotIn("xss|LOW", doc["buckets"], "authored pairs must not leak into the export")


if __name__ == "__main__":
    unittest.main()


class ReviewedClassGateTests(unittest.TestCase):
    """A class earns a published cell only from REVIEWED labels, never from mere presence."""

    def _corpus(self, **truth):
        return [{"name": "X", "truth": [dict({"class": "sqli"}, **truth)]}]

    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-010
    def test_historical_wildcard_entries_do_not_make_a_class_researched(self):
        corpus = self._corpus(location_contains="*", is_real=None,
                              review_status="historical-class-level-unverified")
        self.assertEqual(calibration.reviewed_classes(corpus), set())

    def test_reviewed_status_without_an_explicit_boolean_is_not_enough(self):
        self.assertEqual(calibration.reviewed_classes(
            self._corpus(location_contains="app/views.py", is_real=None,
                         review_status="reviewed")), set())

    def test_an_explicit_boolean_without_reviewed_status_is_not_enough(self):
        self.assertEqual(calibration.reviewed_classes(
            self._corpus(location_contains="app/views.py", is_real=True)), set())

    def test_a_fully_reviewed_entry_qualifies(self):
        self.assertEqual(calibration.reviewed_classes(
            self._corpus(location_contains="app/views.py", is_real=True,
                         review_status="reviewed")), {"sqli"})

    def test_a_reviewed_negative_control_also_qualifies(self):
        self.assertEqual(calibration.reviewed_classes(
            self._corpus(location_contains="app/safe.py", is_real=False,
                         review_status="reviewed")), {"sqli"})

    def test_every_shipped_truth_entry_is_reviewed_and_binds_a_location(self):
        """The corpus was relabelled on 2026-09-22; unreviewed wildcards must not come back."""
        corpus = json.loads(
            (Path(__file__).resolve().parents[1] /
             "src/websec_validator/corpus.json").read_text())
        self.assertTrue(calibration.reviewed_classes(corpus))
        for app in corpus:
            for truth in app["truth"]:
                with self.subTest(app=app["name"], cls=truth["class"]):
                    self.assertEqual(truth["review_status"], "reviewed")
                    self.assertIsInstance(truth["is_real"], bool)
                    self.assertNotIn(truth["location_contains"], ("", "*"),
                                     "a wildcard cannot separate a real vuln from an FP in the "
                                     "same class — that is what got the old labels quarantined")
                    self.assertTrue(truth.get("note"), "a label needs its reviewer's reasoning")

    def test_unreviewed_classes_are_excluded_from_published_cells(self):
        labels = [{"attack_class": "sqli", "confidence": "LOW", "is_real": True}] * 6
        table = calibration.fit(labels, ["X"], calibration.reviewed_classes(
            self._corpus(location_contains="*", is_real=None, review_status="historical")))
        self.assertEqual(table["by_class_label"], {}, "no reviewed class ⇒ no class-specific cell")
        self.assertEqual(table["by_label"]["LOW"]["n"], 6, "the label tier still counts them")

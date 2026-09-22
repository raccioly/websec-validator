"""The fitting objective is a strictly proper scoring rule — reported, never optimized.

Brier is checked against hand-computed values rather than a reimplementation, and the
propriety property itself is asserted: an honest estimate must beat an overconfident one
on the same labels. That property is the whole reason the constraint exists, so a future
change that swapped in an accuracy-shaped objective would fail here rather than silently
produce a more confident, less honest table.

"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator import calibration


def _table(p, n=50):
    """A single-cell table whose class+label bucket predicts `p` with enough samples to be used."""
    k = round(p * n)
    return {"meta": {"min_n": calibration.MIN_N, "caveat": "test"},
            "by_class_label": {f"sqli|MEDIUM": {"n": n, "k": k, "p": p, "ci": [0.0, 1.0]}},
            "by_label": {}, "prior": calibration.PRIOR}


def _labels(n_real, n_fake):
    return ([{"attack_class": "sqli", "confidence": "MEDIUM", "is_real": True}] * n_real
            + [{"attack_class": "sqli", "confidence": "MEDIUM", "is_real": False}] * n_fake)


class BrierTests(unittest.TestCase):
    def test_perfect_prediction_scores_zero(self):
        self.assertEqual(calibration.brier(_labels(10, 0), _table(1.0))["brier"], 0.0)

    def test_confidently_wrong_scores_one(self):
        self.assertEqual(calibration.brier(_labels(0, 10), _table(1.0))["brier"], 1.0)

    def test_hand_computed_value(self):
        # p=0.6 against 6 real + 4 fake: 6*(0.4^2) + 4*(0.6^2) = 0.96 + 1.44 = 2.4 over 10 = 0.24
        self.assertEqual(calibration.brier(_labels(6, 4), _table(0.6))["brier"], 0.24)

    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-011
    def test_rule_is_strictly_proper_honest_beats_overconfident(self):
        """The defining property: on labels that are 60% real, predicting 0.6 must beat 0.9 AND 0.3.

        This is what accuracy would get wrong — thresholding at 0.5, the 0.9 estimator scores
        identical accuracy to the 0.6 one while being far less honest.
        """
        labels = _labels(6, 4)
        honest = calibration.brier(labels, _table(0.6))["brier"]
        for dishonest_p in (0.9, 0.3, 1.0, 0.0):
            with self.subTest(p=dishonest_p):
                self.assertLess(honest, calibration.brier(labels, _table(dishonest_p))["brier"])

    def test_unmeasured_bucket_scores_the_prior_the_tool_would_have_emitted(self):
        """No cell for this class ⇒ apply() falls back to the prior, and brier must score THAT."""
        rows = [{"attack_class": "never-seen", "confidence": "HIGH", "is_real": True}] * 4
        # PRIOR['HIGH'] = 0.85 → (0.85-1)^2 = 0.0225
        self.assertEqual(calibration.brier(rows, _table(0.6))["brier"], 0.0225)

    def test_unknown_labels_are_excluded_not_guessed(self):
        rows = _labels(6, 4) + [{"attack_class": "sqli", "confidence": "MEDIUM", "is_real": None}] * 5
        score = calibration.brier(rows, _table(0.6))
        self.assertEqual(score["n"], 10)
        self.assertEqual(score["brier"], 0.24)

    def test_no_labels_returns_none_rather_than_a_fabricated_score(self):
        self.assertIsNone(calibration.brier([], _table(0.6)))
        self.assertIsNone(calibration.brier([{"attack_class": "sqli", "confidence": "LOW",
                                              "is_real": None}], _table(0.6)))

    def test_report_names_the_constraint_and_disclaims_runtime_effect(self):
        score = calibration.brier(_labels(1, 1), _table(0.5))
        self.assertEqual(score["rule"], calibration.SCORING_RULE)
        self.assertIn("no runtime behavior depends on it", score["note"])
        self.assertEqual(score["reference"]["always_0.5"], 0.25)


class ConstraintIsRecordedTests(unittest.TestCase):
    def test_constant_forbids_accuracy_shaped_objectives(self):
        rule = calibration.SCORING_RULE.lower()
        self.assertIn("strictly proper", rule)
        for forbidden in ("accuracy", "precision", "recall", "f1"):
            self.assertIn(forbidden, rule)

    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#SC-008
    def test_methodology_and_benchmarks_state_the_constraint(self):
        root = Path(__file__).resolve().parents[1]
        for doc in ("docs/METHODOLOGY.md", "BENCHMARKS.md"):
            with self.subTest(doc=doc):
                text = (root / doc).read_text().lower()
                self.assertIn("strictly proper", text)
                self.assertIn("brier", text)


if __name__ == "__main__":
    unittest.main()

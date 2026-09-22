"""The authored-pair harness scores real detectors and reports honestly when it cannot.

A harness that silently scored nothing would publish a perfect table — the exact dishonesty this
whole workstream exists to prevent — so a detector that fails to fire on a vulnerable variant is
recorded as an ERROR (a recall gap), never quietly dropped, and never counted as precision.

@req specs/002-calibration-honesty-and-structural-coverage/spec.md#SC-007
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator import calibration, synthetic


class ManifestTests(unittest.TestCase):
    def test_bundled_manifest_loads_and_is_well_formed(self):
        pairs = synthetic.load_pairs()
        self.assertGreaterEqual(len(pairs), 5)
        seen = set()
        for pair in pairs:
            with self.subTest(pair=pair.get("id")):
                for key in ("id", "attack_class", "confidence", "extractor",
                            "file", "vulnerable", "control"):
                    self.assertIn(key, pair)
                self.assertIn(pair["confidence"], calibration.PRIOR)
                self.assertNotIn(pair["id"], seen, "pair ids must be unique — they are sample ids")
                seen.add(pair["id"])
                self.assertNotEqual(pair["vulnerable"], pair["control"],
                                    "a pair whose halves are identical measures nothing")

    def test_missing_or_malformed_manifest_returns_empty_never_a_guess(self):
        self.assertEqual(synthetic.load_pairs(Path("/nonexistent/pairs.json")), [])
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            handle.write("{not json")
            broken = Path(handle.name)
        self.addCleanup(broken.unlink)
        self.assertEqual(synthetic.load_pairs(broken), [])


class EvaluateTests(unittest.TestCase):
    def test_every_bundled_pair_behaves_as_declared(self):
        """The bundled manifest must be green: a pair that does not hold is a false claim on disk."""
        result = synthetic.evaluate(synthetic.load_pairs())
        self.assertEqual(result["errors"], [], "bundled pairs must all hold")
        self.assertTrue(result["labels"])

    def test_vulnerable_variants_are_scored_as_correct_reports(self):
        labels = synthetic.evaluate(synthetic.load_pairs())["labels"]
        positives = [row for row in labels if row["sample_id"].endswith(":vulnerable")]
        self.assertTrue(positives)
        self.assertTrue(all(row["is_real"] is True for row in positives))

    def test_silent_controls_produce_no_label_because_precision_scores_reports(self):
        """A control that correctly stays silent made no report, so there is nothing to score."""
        labels = synthetic.evaluate(synthetic.load_pairs())["labels"]
        self.assertEqual([row for row in labels if row["sample_id"].endswith(":control")], [],
                         "every bundled control is expected to stay silent")

    def test_a_control_that_fires_is_scored_as_a_false_positive(self):
        noisy = [{"id": "noisy", "attack_class": "xss", "confidence": "LOW",
                  "extractor": "SurfaceExtractor", "file": "app.ts",
                  "vulnerable": "el.innerHTML = location.hash;",
                  "control": "el.innerHTML = location.search;"}]   # still a sink: must fire
        labels = synthetic.evaluate(noisy)["labels"]
        control = [row for row in labels if row["sample_id"].endswith(":control")]
        self.assertEqual(len(control), 1)
        self.assertIs(control[0]["is_real"], False)

    def test_a_missed_vulnerable_variant_is_an_error_not_a_silent_drop(self):
        missing = [{"id": "never-fires", "attack_class": "totally-made-up-class",
                    "confidence": "LOW", "extractor": "SurfaceExtractor", "file": "app.ts",
                    "vulnerable": "const x = 1;", "control": "const y = 2;"}]
        result = synthetic.evaluate(missing)
        self.assertEqual(result["labels"], [])
        self.assertEqual(len(result["errors"]), 1)
        self.assertIn("recall gap", result["errors"][0]["error"])

    def test_an_unresolvable_extractor_is_an_error_not_a_perfect_score(self):
        bogus = [{"id": "bad-extractor", "attack_class": "xss", "confidence": "LOW",
                  "extractor": "NoSuchExtractor", "file": "app.ts",
                  "vulnerable": "el.innerHTML = location.hash;", "control": "const y = 2;"}]
        result = synthetic.evaluate(bogus)
        self.assertEqual(result["labels"], [])
        self.assertTrue(result["errors"])

    def test_incomplete_declarations_are_errors(self):
        for pair in ({"id": "a", "confidence": "LOW", "extractor": "SurfaceExtractor"},
                     {"id": "b", "attack_class": "xss", "extractor": "SurfaceExtractor"},
                     {"id": "c", "attack_class": "xss", "confidence": "LOW"}):
            with self.subTest(pair=pair):
                self.assertTrue(synthetic.evaluate([pair])["errors"])

    def test_a_pair_missing_a_variant_is_an_error(self):
        result = synthetic.evaluate([{"id": "half", "attack_class": "xss", "confidence": "LOW",
                                      "extractor": "SurfaceExtractor", "file": "app.ts",
                                      "vulnerable": "el.innerHTML = location.hash;"}])
        self.assertTrue(any("missing control" in e.get("error", "") for e in result["errors"]))

    def test_empty_input_scores_nothing_and_claims_nothing(self):
        self.assertEqual(synthetic.evaluate([]), {"labels": [], "errors": [], "pairs": 0})


if __name__ == "__main__":
    unittest.main()

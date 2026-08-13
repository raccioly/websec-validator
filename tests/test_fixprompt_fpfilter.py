"""Per-finding fix prompts (P6) + the deterministic FP-exclusion pre-pass (P7)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator import fixprompt, fpfilter  # noqa: E402
from websec_validator.findings import REMEDIATION, STANDARDS  # noqa: E402


def _f(**kw):
    base = {"attack_class": "bola", "title": "t", "location": "src/a.js", "severity": "HIGH",
            "confidence": "MEDIUM", "remediation": "scope the query by owner",
            "standards": {"cwe": ["CWE-639 Authorization Bypass"]}, "evidence": []}
    base.update(kw)
    return base


class FixPromptTests(unittest.TestCase):
    def test_prompt_is_self_contained(self):
        p = fixprompt.build({"findings": [_f(evidence=[{"detail": "handler lacks an owner check"}])]})[0]
        txt = p["prompt"]
        for expected in ("src/a.js", "bola", "handler lacks an owner check",
                         "CWE-639", "scope the query by owner"):
            self.assertIn(expected, txt)

    def test_every_prompt_ends_with_a_verify_step(self):
        led = {"findings": [_f(attack_class=c) for c in ("bola", "sqli", "secret", "unknown-class")]}
        for p in fixprompt.build(led):
            self.assertIn("VERIFY:", p["prompt"], p["attack_class"])

    def test_class_specific_verification_beats_generic(self):
        sqli = fixprompt.build({"findings": [_f(attack_class="sqli")]})[0]["prompt"]
        self.assertIn("sqlmap", sqli)
        generic = fixprompt.build({"findings": [_f(attack_class="totally-unknown")]})[0]["prompt"]
        self.assertIn("regression test", generic)

    def test_secret_verification_demands_rotation_not_deletion(self):
        # deleting a committed key from HEAD does not un-leak it — the prompt must say so.
        txt = fixprompt.build({"findings": [_f(attack_class="secret")]})[0]["prompt"]
        self.assertIn("ROTATED", txt)
        self.assertIn("history", txt)

    def test_prompt_warns_against_fixing_a_false_positive(self):
        txt = fixprompt.build({"findings": [_f()]})[0]["prompt"]
        self.assertIn("false positive", txt)

    def test_calibration_included_only_when_measured(self):
        with_cal = fixprompt.build({"findings": [
            _f(calibrated={"p": 0.66, "n": 41, "basis": "class+label"})]})[0]["prompt"]
        self.assertIn("P(real)", with_cal)
        without = fixprompt.build({"findings": [_f(calibrated={"p": None, "n": 0})]})[0]["prompt"]
        self.assertNotIn("P(real)", without)

    def test_limit_and_empty(self):
        led = {"findings": [_f() for _ in range(30)]}
        self.assertEqual(len(fixprompt.build(led, limit=5)), 5)
        self.assertIn("No findings", fixprompt.render_md([]))


class FpFilterTests(unittest.TestCase):
    def test_low_signal_classes_are_tagged(self):
        flagged, reason = fpfilter.evaluate(_f(attack_class="redos"))
        self.assertTrue(flagged)
        self.assertIn("DoS", reason)

    def test_docs_and_test_locations_tagged(self):
        self.assertTrue(fpfilter.evaluate(_f(location="README.md"))[0])
        self.assertTrue(fpfilter.evaluate(_f(location="tests/app.test.js"))[0])

    def test_real_product_finding_not_tagged(self):
        flagged, reason = fpfilter.evaluate(_f(attack_class="bola", location="src/orders.js"))
        self.assertFalse(flagged)
        self.assertEqual(reason, "")

    def test_memory_safety_only_filtered_on_a_memory_safe_stack(self):
        f = _f(attack_class="memory-safety", location="src/a.js")
        self.assertTrue(fpfilter.evaluate(f, {"stack": {"languages": ["python", "node"]}})[0])
        # a C/C++ component in the stack ⇒ the class is real; must NOT be filtered
        self.assertFalse(fpfilter.evaluate(f, {"stack": {"languages": ["python", "c"]}})[0])

    def test_annotate_tags_but_never_drops(self):
        led = {"findings": [_f(attack_class="redos"), _f(attack_class="bola")]}
        counts = fpfilter.annotate(led, {})
        self.assertEqual(len(led["findings"]), 2)               # nothing removed
        self.assertTrue(led["findings"][0].get("likely_filtered"))
        self.assertNotIn("likely_filtered", led["findings"][1])
        self.assertEqual(counts, {"likely_filtered": 1, "kept": 1})

    def test_low_signal_classes_are_real_attack_classes(self):
        # a typo'd key would silently never fire (same guard as the DAST map)
        real = set(STANDARDS) | set(REMEDIATION)
        unknown = sorted(set(fpfilter._LOW_SIGNAL_CLASSES) - real)
        self.assertEqual(unknown, [], f"unknown attack classes in the filter map: {unknown}")

    def test_render_states_reasons_and_says_nothing_was_deleted(self):
        led = {"findings": [_f(attack_class="redos")]}
        fpfilter.annotate(led, {})
        md = fpfilter.render_md(led, {"likely_filtered": 1})
        self.assertIn("not deleted", md.lower().replace("**", ""))
        self.assertIn("redos", md)




class ProductLookalikeTests(unittest.TestCase):
    def test_product_dirs_beginning_with_a_test_word_are_not_filtered(self):
        # `is_test_file` matches a tests?/ segment; these are PRODUCT dirs that merely start with it
        for loc in ("src/testimonials/route.ts", "src/contest/api.ts", "src/latest/handler.ts"):
            flagged, _ = fpfilter.evaluate(_f(attack_class="bola", location=loc))
            self.assertFalse(flagged, loc)

    def test_real_test_files_are_still_filtered(self):
        for loc in ("tests/app.test.js", "src/__tests__/x.ts", "spec/models_spec.rb"):
            flagged, _ = fpfilter.evaluate(_f(attack_class="bola", location=loc))
            self.assertTrue(flagged, loc)

if __name__ == "__main__":
    unittest.main()

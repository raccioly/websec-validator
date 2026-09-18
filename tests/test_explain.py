"""`websec explain` — resolution, exit codes and the honesty caveats."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from websec_validator import cli, explain  # noqa: E402
from websec_validator.findings import STANDARDS  # noqa: E402


class ResolutionTests(unittest.TestCase):
    def test_every_shipped_attack_class_resolves(self):
        # explain must not claim knowledge it lacks, nor omit a class the tool emits.
        for name in explain.classes():
            with self.subTest(name=name):
                self.assertTrue(explain.describe(name)["ok"])
        self.assertEqual(set(explain.classes()), set(STANDARDS))

    def test_cwe_id_resolves_to_its_class(self):
        info = explain.describe("CWE-918")
        self.assertTrue(info["ok"])
        self.assertEqual(info["attack_class"], "ssrf")

    def test_ambiguous_cwe_is_refused_rather_than_guessed(self):
        shared = {}
        for name, (cwes, _a, _o) in STANDARDS.items():
            for cwe in cwes:
                shared.setdefault(cwe.split()[0], []).append(name)
        multi = next((c for c, names in shared.items() if len(names) > 1), None)
        if multi is None:
            self.skipTest("no CWE is currently cited by more than one class")
        info = explain.describe(multi)
        self.assertFalse(info["ok"])
        self.assertIn("name one", info["error"])

    def test_unknown_term_suggests_near_matches(self):
        info = explain.describe("sqli-injection")
        self.assertFalse(info["ok"])
        self.assertIn("Did you mean", info["error"])

    def test_empty_term_is_an_error_not_a_blank_answer(self):
        self.assertFalse(explain.describe("")["ok"])


class OutputTests(unittest.TestCase):
    def test_render_states_that_the_signals_are_separate(self):
        out = explain.render(explain.describe("bola"))
        self.assertIn("CWE-639", out)
        self.assertIn("unknown truth label is not a false positive", out)
        self.assertIn("How to confirm or refute it", out)

    def test_calibration_line_never_claims_an_unmeasured_estimate(self):
        info = explain.describe("bola")
        self.assertTrue(
            "no measured cell" in info["calibration"]
            or "p=" in info["calibration"]
            or "unavailable" in info["calibration"], info["calibration"])


class CliTests(unittest.TestCase):
    def test_known_class_exits_0_and_unknown_exits_2(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["explain", "ssrf"]), 0)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["explain", "not-a-class"]), 2)

    def test_missing_term_exits_2(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["explain"]), 2)

    def test_list_emits_every_class(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(cli.main(["explain", "--list"]), 0)
        self.assertEqual(len(buf.getvalue().split()), len(STANDARDS))

    def test_json_mode_is_machine_readable_and_keeps_the_exit_code(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["explain", "ssrf", "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(buf.getvalue())["attack_class"], "ssrf")


if __name__ == "__main__":
    unittest.main()

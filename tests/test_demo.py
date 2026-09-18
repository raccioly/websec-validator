"""`websec demo` — a real run against a bundled sample, contained and honest."""
from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from websec_validator import cli, demo  # noqa: E402


class SampleTests(unittest.TestCase):
    def test_sample_ships_as_txt_so_nothing_imports_or_lints_it(self):
        shipped = ROOT / "src" / "websec_validator" / "templates" / "demo"
        self.assertTrue(shipped.is_dir())
        self.assertEqual(sorted(p.name for p in shipped.iterdir()),
                         ["app.py.txt", "requirements.txt.txt"])
        self.assertFalse(list(shipped.glob("*.py")), "a .py here would be imported and linted")

    def test_sample_carries_no_credential_shaped_strings(self):
        # A fake secret inside an installed package is found by other people's secret
        # scanners pointed at site-packages. The sample plants injection classes instead.
        body = (ROOT / "src" / "websec_validator" / "templates" / "demo" / "app.py.txt").read_text()
        for marker in ("AKIA", "password", "secret", "api_key", "token", "BEGIN PRIVATE KEY"):
            self.assertNotIn(marker.lower(), body.lower(), f"{marker!r} would trip other scanners")

    def test_materialize_writes_only_inside_the_given_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = demo.materialize(Path(tmp))
            self.assertTrue(str(root).startswith(str(Path(tmp).resolve()))
                            or str(root).startswith(tmp))
            self.assertTrue((root / "src" / "app.py").is_file())
            self.assertTrue((root / "requirements.txt").is_file())


class RunTests(unittest.TestCase):
    def test_demo_finds_the_planted_classes_and_cleans_up(self):
        buf = io.StringIO()
        before = set(Path(tempfile.gettempdir()).glob("websec-demo-*"))
        with contextlib.redirect_stdout(buf):
            code = cli.main(["demo"])
        out = buf.getvalue()
        self.assertEqual(code, 0, out)
        for planted in ("missing-auth", "sqli", "command-injection", "ssrf"):
            self.assertIn(planted, out, f"{planted} was planted but not reported")
        after = set(Path(tempfile.gettempdir()).glob("websec-demo-*"))
        self.assertEqual(after - before, set(), "demo left a temp directory behind")

    def test_demo_says_a_finding_is_a_lead_not_a_vulnerability(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cli.main(["demo"])
        self.assertIn("lead to verify, not a confirmed vulnerability", buf.getvalue())
        self.assertIn("your project is untouched", buf.getvalue())

    def test_an_empty_result_is_reported_as_a_detector_bug_not_a_pass(self):
        # If the sample stops tripping the detectors that is a regression in the tool.
        # It must never read as a clean bill of health.
        with contextlib.redirect_stdout(io.StringIO()) as buf, \
             unittest.mock.patch("websec_validator.findings.build_ledger",
                                 return_value={"findings": []}):
            code = demo.run()
        self.assertEqual(code, 1)
        self.assertIn("bug in the detectors", buf.getvalue())


if __name__ == "__main__":
    import unittest.mock  # noqa: F401
    unittest.main()

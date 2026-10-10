"""Wiring regressions for the 0.22.0 defect sweep: CLI entry points that consume the new
gate/coverage/scanner signals. Each test failed before the wiring it pins.
"""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from websec_validator import cli, coverage, scanners  # noqa: E402

VULN = "import subprocess\n\ndef handler(request):\n    subprocess.call(request.args['cmd'], shell=True)\n"


def _main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as exit_:
            code = exit_.code
    return code, out.getvalue(), err.getvalue()


class GateOutsideGitTests(unittest.TestCase):
    def test_gate_outside_git_without_only_is_incomplete_not_a_pass(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "app.py").write_text(VULN)
            code, _, err = _main("gate", td, "--format", "json")
        self.assertEqual(code, cli.EXIT_INCOMPLETE)
        self.assertIn("no VCS", err)

    def test_gate_outside_git_with_only_still_runs(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "app.py").write_text("print('safe')\n")
            code, _, _ = _main("gate", td, "--only", "app.py", "--format", "json")
        self.assertEqual(code, cli.EXIT_OK)


class NoirFailureCoverageTests(unittest.TestCase):
    def test_failed_noir_is_a_visible_non_execution_gap(self):
        facts = {"routes": {"noir": {"state": "failed", "reason": "exit 1: segfault"}}}
        coverage.add_routes(facts)
        gaps = facts["coverage"]["gaps"]
        self.assertTrue(any(g["kind"] == "route_engine" and "segfault" in g["detail"] for g in gaps))
        self.assertTrue(facts["coverage"]["execution_complete"])

    def test_absent_noir_adds_no_gap(self):
        facts = {"routes": {"noir": {"state": "absent"}}}
        coverage.add_routes(facts)
        self.assertFalse(any(g["kind"] == "route_engine" for g in facts.get("coverage", {}).get("gaps", [])))


class DoctorRouteEngineTests(unittest.TestCase):
    def test_doctor_reports_a_broken_noir(self):
        broken = {"key": "noir", "name": "OWASP Noir", "category": "routes", "installed": True,
                  "version": None, "status": "broken", "note": "`noir --version` exited 1: boom",
                  "install": "brew install noir"}
        with patch.object(scanners, "check_route_engine", return_value=broken):
            code, out, _ = _main("doctor")
        self.assertEqual(code, 0)
        self.assertIn("route engine", out)
        self.assertIn("exited 1: boom", out)
        self.assertIn("falls back to regex", out)

    def test_doctor_lists_not_applicable_scanners_for_a_target(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "lib.rb").write_text("puts 'x'\n")
            with patch("shutil.which", side_effect=lambda b: "/usr/bin/" + b if b == "brakeman" else None):
                code, out, _ = _main("doctor", td)
        self.assertEqual(code, 0)
        self.assertIn("not applicable to this target", out)
        self.assertIn("Brakeman", out)


class DiffScopeArtifactTests(unittest.TestCase):
    def test_diff_scope_json_records_the_repo_prefix_key(self):
        with tempfile.TemporaryDirectory() as td:
            repo, out = Path(td) / "repo", Path(td) / "out"
            repo.mkdir()
            (repo / "app.py").write_text("print('x')\n")
            with patch("shutil.which", return_value=None):
                _main("run", str(repo), "--out", str(out), "--diff", "main")
            scope = json.loads(next(out.glob("runs/*/diff-scope.json")).read_text())
        self.assertIn("repo_prefix", scope)


if __name__ == "__main__":
    unittest.main()

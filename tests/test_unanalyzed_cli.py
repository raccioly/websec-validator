"""CLI surface for the "analyzed nothing" disclosure: default exit codes are UNCHANGED.

The design decision these pin (spec 002, D2): the warning is always visible, but failing is
opt-in. `--require-complete` deliberately stays silent here — nothing failed to execute; there
was nothing executable — so a separate flag exists rather than overloading it.

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

from websec_validator import cli, gate

ELIXIR = 'defmodule W do\n  def f(c, %{"id" => i}) do\n    q("SELECT * FROM u WHERE id = #{i}")\n  end\nend\n'


class _Run(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.out = self.base / "out"

    def run_cli(self, *args):
        buf = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("shutil.which", return_value=None))
            stack.enter_context(contextlib.redirect_stdout(buf))
            stack.enter_context(contextlib.redirect_stderr(buf))
            code = cli.main(["run", str(self.repo), "--out", str(self.out), *args])
        return code, buf.getvalue()

    def latest(self, name):
        attempt = max((self.out / "runs").iterdir(), key=lambda p: p.stat().st_mtime_ns)
        return json.loads((attempt / name).read_text())


class RequireAnalyzedTests(_Run):
    def test_default_run_over_unanalyzable_source_still_exits_zero_but_says_so(self):
        (self.repo / "worker.ex").write_text(ELIXIR)
        code, output = self.run_cli()
        self.assertEqual(code, 0, "the default must not start failing; disclosure is not a gate")
        self.assertIn("NO ANALYZABLE SOURCE", output)
        self.assertIn("NOT CHECKED", output)

    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-013
    def test_require_analyzed_refuses_to_report_it_as_a_pass(self):
        (self.repo / "worker.ex").write_text(ELIXIR)
        code, output = self.run_cli("--require-analyzed")
        self.assertEqual(code, 2)
        self.assertIn("--require-analyzed", output)
        self.assertEqual(self.latest("findings-ledger.json")["gate"]["verdict"], "no-analyzable-source")

    def test_require_complete_alone_stays_silent_because_nothing_failed_to_execute(self):
        """The two flags describe different failures and must not be conflated."""
        (self.repo / "worker.ex").write_text(ELIXIR)
        code, _ = self.run_cli("--require-complete")
        self.assertEqual(code, 0)
        self.assertTrue(self.latest("coverage.json")["execution_complete"])

    def test_fail_on_alone_does_not_catch_it(self):
        """Documents the hole that motivated the flag: no findings, so no threshold is crossed."""
        (self.repo / "worker.ex").write_text(ELIXIR)
        code, _ = self.run_cli("--fail-on", "low")
        self.assertEqual(code, 0)

    def test_require_analyzed_passes_on_an_analysable_repository(self):
        (self.repo / "app.py").write_text("import os\n")
        code, output = self.run_cli("--require-analyzed")
        self.assertEqual(code, 0)
        self.assertNotIn("NO ANALYZABLE SOURCE", output)

    def test_require_analyzed_passes_on_a_mixed_repository(self):
        (self.repo / "app.py").write_text("import os\n")
        (self.repo / "worker.ex").write_text(ELIXIR)
        code, _ = self.run_cli("--require-analyzed")
        self.assertEqual(code, 0, "python was analysed; this is a partial limit, not a blank scan")

    def test_require_analyzed_is_recorded_in_the_ledger_gate_block(self):
        (self.repo / "app.py").write_text("import os\n")
        self.run_cli("--require-analyzed")
        self.assertTrue(self.latest("findings-ledger.json")["gate"]["require_analyzed"])


class GateTextTests(unittest.TestCase):
    """The verdict is unchanged (test_gate_command pins it); only the sentence changes."""

    def _verdict(self, matched, missed):
        return gate.verdict({"findings": []},
                            {"analysis_scope": {"matched": matched, "missed": missed}}, "medium")

    def test_pass_over_zero_analyzed_files_is_not_worded_as_clean(self):
        result = self._verdict([], ["worker.ex"])
        self.assertTrue(result["passed"], "the verdict itself is deliberately unchanged")
        text = gate.render_text(result)
        self.assertIn("0 file(s) were analyzed", text)
        self.assertIn("NOT a clean result", text)

    def test_partial_scope_says_which_paths_were_skipped(self):
        text = gate.render_text(self._verdict(["a.py"], ["worker.ex"]))
        self.assertIn("1 requested path(s) never analyzed", text)

    def test_fully_analyzed_pass_keeps_the_original_terse_message(self):
        text = gate.render_text(self._verdict(["a.py"], []))
        self.assertEqual(text, "websec gate: pass (1 file(s) analyzed, threshold medium)")


class GateFailOnMissedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve() / "repo"
        self.repo.mkdir()
        (self.repo / "worker.ex").write_text(ELIXIR)
        (self.repo / "app.py").write_text("import os\n")

    def run_gate(self, *args):
        buf = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("shutil.which", return_value=None))
            stack.enter_context(contextlib.redirect_stdout(buf))
            stack.enter_context(contextlib.redirect_stderr(buf))
            code = cli.main(["gate", str(self.repo), *args])
        return code, buf.getvalue()

    def test_gate_default_passes_over_an_unanalyzable_path(self):
        code, output = self.run_gate("--only", "worker.ex")
        self.assertEqual(code, 0, "agent-loop default is unchanged")
        self.assertIn("NOT a clean result", output)

    def test_fail_on_missed_refuses_that_pass(self):
        code, output = self.run_gate("--only", "worker.ex", "--fail-on-missed")
        self.assertEqual(code, 1)
        self.assertIn("--fail-on-missed", output)

    def test_fail_on_missed_does_not_fire_when_everything_was_analyzed(self):
        code, _ = self.run_gate("--only", "app.py", "--fail-on-missed")
        self.assertEqual(code, 0)

    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-009
    def test_json_passed_value_is_unaffected_by_the_flag(self):
        """The flag changes the exit code, never the recorded verdict."""
        for args in (("--only", "worker.ex", "--format", "json"),
                     ("--only", "worker.ex", "--format", "json", "--fail-on-missed")):
            with self.subTest(args=args):
                _, output = self.run_gate(*args)
                payload = json.loads(output[output.index("{"):output.rindex("}") + 1])
                self.assertTrue(payload["passed"])
                self.assertEqual(payload["missed"], ["worker.ex"])


if __name__ == "__main__":
    unittest.main()

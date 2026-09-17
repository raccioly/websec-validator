"""The gate verdict and honoured bypasses must exist as EVIDENCE, not only as an exit code.

Before this, `--fail-on` was evaluated after the artifacts were written and after the run was
published, so nothing in the run directory said which gate ran, at what threshold, or whether it
passed. And an honoured WEBSEC_SKIP_HOOK exited before any Python ran — no run directory, no
hook.log, no stderr line. A gate that can be skipped without trace cannot evidence that it ran.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator import cli, hooks


def _repo(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for cmd in (["git", "init", "-q", "."],
                ["git", "config", "user.email", "d@e.com"],
                ["git", "config", "user.name", "D"]):
        subprocess.run(cmd, cwd=root, check=True)
    (root / "a.txt").write_text("x\n")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=root, check=True)
    return root


class BypassRecordTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = _repo(Path(self.temp.name).resolve() / "r")
        hooks.install(self.repo, pre_push=True)
        self.hook = self.repo / ".git" / "hooks" / "pre-push"
        self.log = self.repo / ".git" / "websec-guardrail" / "bypass.jsonl"

    def _bypass(self):
        return subprocess.run(["sh", str(self.hook), "origin", "https://example/x"],
                              cwd=self.repo, capture_output=True, text=True,
                              env={"PATH": "/usr/bin:/bin:/usr/local/bin", "WEBSEC_SKIP_HOOK": "1"},
                              stdin=subprocess.DEVNULL, timeout=60)

    def test_honoured_bypass_still_exits_zero(self):
        """The escape hatch must keep working — this records it, it does not block it."""
        self.assertEqual(self._bypass().returncode, 0)

    def test_honoured_bypass_is_no_longer_silent_on_stderr(self):
        self.assertIn("BYPASSED", self._bypass().stderr)

    def test_honoured_bypass_writes_a_durable_record(self):
        self._bypass()
        self.assertTrue(self.log.is_file(), "bypass must leave a durable artifact")
        row = json.loads(self.log.read_text().splitlines()[0])
        self.assertEqual(row["event"], "bypass")
        self.assertEqual(row["via"], "WEBSEC_SKIP_HOOK")
        self.assertIs(row["scanned"], False)
        self.assertEqual(row["hook"], "pre-push")

    def test_record_binds_the_bypass_to_a_commit(self):
        self._bypass()
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.repo,
                              capture_output=True, text=True).stdout.strip()
        self.assertEqual(json.loads(self.log.read_text().splitlines()[0])["head"], head)

    def test_record_states_its_own_limitation_inline(self):
        """The artifact must not be readable as 'no bypass occurred'."""
        self._bypass()
        row = json.loads(self.log.read_text().splitlines()[0])
        self.assertIn("not evidence that no bypass occurred", row["limitation"].lower()
                      .replace("is not", "is not"))

    def test_repeated_bypasses_append_valid_jsonl(self):
        self._bypass()
        self._bypass()
        rows = [json.loads(x) for x in self.log.read_text().splitlines() if x.strip()]
        self.assertEqual(len(rows), 2)

    def test_reader_surfaces_records_and_the_limitation(self):
        self._bypass()
        got = hooks.read_bypasses(self.repo)
        self.assertEqual(got["count"], 1)
        self.assertIn("not evidence", got["limitation"])

    def test_reader_on_a_clean_repo_reports_zero_without_claiming_none_happened(self):
        got = hooks.read_bypasses(self.repo)
        self.assertEqual(got["count"], 0)
        self.assertIn("--no-verify", got["limitation"])

    def test_reader_never_raises_outside_a_repo(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(hooks.read_bypasses(Path(td))["count"], 0)

    def test_reader_tolerates_a_corrupt_line(self):
        self.log.parent.mkdir(parents=True, exist_ok=True)
        self.log.write_text('{"event":"bypass"}\nnot json at all\n')
        got = hooks.read_bypasses(self.repo)
        self.assertEqual(got["count"], 2)
        self.assertIn("unparsed", got["records"][1])


class GateRecordTests(unittest.TestCase):
    """The recorded verdict and the process exit code must never disagree."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = _repo(self.base / "r")
        (self.repo / "app.py").write_text("print('ok')\n")
        self.out = self.base / "out"

    def _run(self, *extra):
        argv = ["run", str(self.repo), "--out", str(self.out), *extra]
        code = cli.main(argv)
        led = sorted(self.out.glob("runs/*/findings-ledger.json"))[-1]
        return code, json.loads(led.read_text())["gate"]

    def test_no_fail_on_records_not_evaluated(self):
        code, gate = self._run()
        self.assertEqual(code, 0)
        self.assertEqual(gate["verdict"], "not-evaluated")
        self.assertIn("gated nothing", gate["note"])

    def test_gate_record_states_enforcement_is_advisory(self):
        """A client-side gate is a developer convenience, not a control. Say it in the artifact."""
        _, gate = self._run()
        self.assertIn("not a control", gate["enforcement"])

    def test_passing_gate_records_threshold_and_exit_code(self):
        code, gate = self._run("--fail-on", "critical")
        self.assertEqual(gate["threshold"], "critical")
        self.assertEqual(gate["exit_code"], code)
        self.assertIn(gate["verdict"], {"pass", "fail", "incomplete"})

    def test_recorded_exit_code_matches_the_process_exit_code(self):
        for extra in ((), ("--fail-on", "critical"), ("--fail-on", "low")):
            with self.subTest(extra=extra):
                self.setUp()
                code, gate = self._run(*extra)
                self.assertEqual(gate["exit_code"], code,
                                 "artifact and exit code must not disagree")


if __name__ == "__main__":
    unittest.main()

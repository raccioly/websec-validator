"""`websec gate` — the in-loop check.

A finding surfaced after forty merges is a backlog item; the same finding surfaced on the edit that
caused it is a retry. This pins the properties that make that true: it sees UNCOMMITTED work, it is
fast, it writes nothing, and it never reports 'clean' for something it did not analyse.
"""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator import cli, gate

VULN = '''from flask import Flask, request
import subprocess
app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c1 " + host, shell=True)
'''
SAFE = "def add(a, b):\n    return a + b\n"


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve() / "r"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "src" / "safe.py").write_text(SAFE)
        (self.repo / "requirements.txt").write_text("flask==3.0.0\n")
        subprocess.run(["git", "init", "-q", "."], cwd=self.repo, check=True)
        # Pin ambient git settings (pattern from test_diffscope.py): a hostile global
        # config with commit.gpgsign=true fails these commits outright, and a global
        # core.hooksPath would redirect hook installs out of the fixture repo.
        for _k, _v in (("user.email", "d@e.com"), ("user.name", "D"),
                       ("commit.gpgsign", "false"), ("core.autocrlf", "false"),
                       ("core.hooksPath", ".git/hooks")):
            subprocess.run(["git", "-C", str(self.repo), "config", _k, _v], check=True)
        subprocess.run(["git", "add", "-A"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=self.repo, check=True)

    def _vuln(self):
        (self.repo / "src" / "app.py").write_text(VULN)

    def _run(self, *extra):
        return cli.main(["gate", str(self.repo), "--format", "json", *extra])

    def _out(self, capsys_buf):
        return json.loads(capsys_buf)

    # ---- the premise: UNCOMMITTED work is what an agent leaves behind ----
    def test_uncommitted_file_is_analyzed(self):
        """diffscope is three-dot base...HEAD and would see nothing here."""
        self._vuln()
        found = gate.working_tree_paths(self.repo)
        self.assertIn("src/app.py", found["paths"])
        self.assertEqual(found["source"], "working-tree")

    def test_uncommitted_vulnerability_blocks(self):
        self._vuln()
        self.assertEqual(self._run(), 1)

    def test_clean_tree_passes_and_says_why(self):
        code = self._run()
        self.assertEqual(code, 0)

    def test_deleted_files_are_not_analyzed(self):
        (self.repo / "src" / "safe.py").unlink()
        self.assertNotIn("src/safe.py", gate.working_tree_paths(self.repo)["paths"])

    def test_non_git_directory_is_reported_not_crashed(self):
        with tempfile.TemporaryDirectory() as td:
            got = gate.working_tree_paths(Path(td))
            self.assertEqual(got["source"], "not-a-git-repository")
            self.assertEqual(got["paths"], [])

    # ---- thresholds ----
    def test_default_threshold_catches_command_injection(self):
        """A HIGH default would look like it worked while missing the main case."""
        self._vuln()
        self.assertEqual(self._run(), 1)

    def test_critical_threshold_lets_a_medium_through(self):
        self._vuln()
        self.assertEqual(self._run("--fail-on", "critical"), 0)

    def test_min_confidence_can_filter_low_confidence_leads(self):
        self._vuln()
        self.assertEqual(self._run("--fail-on", "medium", "--min-confidence", "high"), 0)

    def test_ungradeable_confidence_is_never_silently_dropped(self):
        led = {"findings": [{"severity": "HIGH", "confidence": "UNKNOWN", "title": "t"}]}
        got = gate.verdict(led, {}, "medium", min_confidence="high")
        self.assertFalse(got["passed"], "an ungradeable confidence must not drop a finding")

    # ---- it must not behave like a review ----
    def test_gate_writes_nothing(self):
        self._vuln()
        before = {p for p in self.repo.rglob("*") if ".git" not in p.parts}
        self._run()
        after = {p for p in self.repo.rglob("*") if ".git" not in p.parts}
        self.assertEqual(before, after, "an in-loop check must not litter the tree")

    def test_verdict_states_it_is_not_a_review(self):
        self._vuln()
        got = gate.verdict({"findings": []}, {"analysis_scope": {"matched": ["a.py"], "missed": []}},
                           "medium")
        self.assertIn("not", got["scope_note"])
        self.assertIn("does not mean the repository is clean", got["scope_note"])

    def test_missed_paths_are_not_reported_as_clean(self):
        got = gate.verdict({"findings": []},
                           {"analysis_scope": {"matched": [], "missed": ["ghost.py"]}}, "medium")
        self.assertTrue(got["passed"])
        self.assertIn("NOT a clean result", got["missed_note"])

    # ---- the message the model gets back ----
    def test_block_message_is_actionable(self):
        result = gate.verdict(
            {"findings": [{"severity": "HIGH", "confidence": "HIGH", "title": "command-injection sink",
                           "file": "src/app.py", "line": 8, "remediation": "use an argument array"}]},
            {"analysis_scope": {"matched": ["src/app.py"], "missed": []}}, "medium")
        text = gate.render_text(result)
        self.assertIn("src/app.py:8", text)
        self.assertIn("use an argument array", text)
        self.assertIn("not a full review", text)

    def test_pass_message_says_how_much_was_looked_at(self):
        result = gate.verdict({"findings": []},
                              {"analysis_scope": {"matched": ["a.py", "b.py"], "missed": []}}, "medium")
        self.assertIn("2 file(s) analyzed", gate.render_text(result))

    def test_explicit_only_overrides_working_tree_discovery(self):
        self._vuln()
        self.assertEqual(cli.main(["gate", str(self.repo), "--only", "src/safe.py",
                                   "--format", "json"]), 0)

    def test_failed_git_status_is_not_reported_as_a_clean_tree(self):
        # `git status` failing left paths empty with source="working-tree", which is
        # exactly what a genuinely clean tree returns. The gate then passed having
        # analysed nothing — a silent pass inside the agent loop.
        real = gate._git

        def flaky(repo, *args):
            return None if args and args[0] == "status" else real(repo, *args)

        with patch.object(gate, "_git", flaky):
            discovered = gate.working_tree_paths(self.repo)
        self.assertEqual(discovered["source"], "working-tree-unavailable")
        self.assertIn("git status", discovered["note"])

    def test_unavailable_scope_exits_2_rather_than_passing(self):
        # A harness must not read "the gate could not determine what to analyse" as a pass.
        real = gate._git

        def flaky(repo, *args):
            return None if args and args[0] == "status" else real(repo, *args)

        err = io.StringIO()
        with patch.object(gate, "_git", flaky), contextlib.redirect_stderr(err):
            code = cli.main(["gate", str(self.repo), "--format", "json"])
        self.assertEqual(code, 2)
        self.assertIn("changed-file set is unknown", err.getvalue())

    def test_genuinely_clean_tree_still_passes(self):
        # The guard must not turn "nothing changed" into a failure. setUp already
        # commits the fixture, so the tree is clean here.
        discovered = gate.working_tree_paths(self.repo)
        self.assertEqual(discovered["source"], "working-tree")
        self.assertEqual(discovered["paths"], [])

    def test_bad_target_exits_2_not_1(self):
        """A harness must be able to tell a FAILED check from a BROKEN one."""
        self.assertEqual(cli.main(["gate", str(self.repo / "nope"), "--format", "json"]), 2)


if __name__ == "__main__":
    unittest.main()

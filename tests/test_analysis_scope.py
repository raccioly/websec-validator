"""Two-tier analysis scoping (`--only`), the basis of an in-loop security gate.

`--diff` scopes the REPORT, not the work: measured 42.2s vs 43.0s on a 320-file repo, because 99%
of the cost is extractors running over the whole tree. `--only` narrows what is READ AND MATCHED
(~13x faster) while the walk still covers the whole tree, so stack detection, ignore policy and
fixture classification are unchanged.

The safety constraint is empirical. The same three files copied into a bare directory produced
3 CRITICAL + 1 HIGH findings the full tree does not report — purely from losing path context and
the ignore policy, which made a detector's own pattern literals read as application code. Scoped
analysis must therefore run files IN PLACE and must never invent a finding the full tree lacks.
"""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator.extractors import run_all
from websec_validator.extractors.base import RepoContext
from websec_validator.findings import build_ledger


APP = '''from flask import Flask, request
import subprocess
app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c1 " + host, shell=True)
'''


def _tree(root: Path):
    """A fixture that actually trips detectors — an unguarded route with a shell sink. A parity
    test over a fixture that produces no findings proves nothing."""
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "src" / "app.py").write_text(APP)
    (root / "src" / "c.py").write_text("def add(x, y):\n    return x + y\n")
    (root / "requirements.txt").write_text("flask==3.0.0\n")
    (root / "pyproject.toml").write_text('[project]\nname = "demo"\nrequires-python = ">=3.11"\n')
    return root


class ScopeMechanicsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = _tree(Path(self.temp.name).resolve())

    def test_scope_narrows_what_is_analyzed(self):
        ctx = RepoContext(self.root, only=["src/app.py"])
        self.assertEqual([ctx.rel(p) for p in ctx.code_files], ["src/app.py"])

    def test_the_whole_tree_is_still_walked(self):
        """Classification depends on the full inventory even when analysis is narrowed."""
        ctx = RepoContext(self.root, only=["src/app.py"])
        self.assertEqual(len(ctx.code_files), 1)
        self.assertGreaterEqual(len(ctx.all_code_files), 2)

    def test_unscoped_context_is_unchanged(self):
        ctx = RepoContext(self.root)
        self.assertIsNone(ctx.scope)
        self.assertEqual(len(ctx.code_files), len(ctx.all_code_files))
        self.assertEqual(ctx.scope_requested, [])

    def test_a_requested_path_the_walker_never_selected_is_reported_missed(self):
        """'Never looked' must be distinguishable from 'analyzed and clean'."""
        ctx = RepoContext(self.root, only=["src/app.py", "src/nope.py"])
        self.assertEqual(ctx.scope_matched, ["src/app.py"])
        self.assertEqual(ctx.scope_missed, ["src/nope.py"])

    def test_scope_is_recorded_in_facts_with_its_caveat(self):
        facts = run_all(self.root, "t", only=["src/app.py", "src/ghost.py"])
        scope = facts["analysis_scope"]
        self.assertEqual(scope["matched"], ["src/app.py"])
        self.assertEqual(scope["missed"], ["src/ghost.py"])
        self.assertIn("not a clean result", scope["note"])

    def test_no_scope_key_when_unscoped(self):
        self.assertNotIn("analysis_scope", run_all(self.root, "t"))

    def test_leading_dot_slash_is_tolerated(self):
        ctx = RepoContext(self.root, only=["./src/app.py"])
        self.assertEqual(ctx.scope_matched, ["src/app.py"])

    def test_scope_cannot_reach_outside_the_walked_inventory(self):
        """A scope entry is a filter over what the walker already selected, never a way in."""
        ctx = RepoContext(self.root, only=["../../../etc/passwd", "/etc/passwd"])
        self.assertEqual(ctx.code_files, [])
        self.assertEqual(ctx.scope_matched, [])


class ScopeClassificationParityTests(unittest.TestCase):
    """Scoping must not change WHICH detectors run."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = _tree(Path(self.temp.name).resolve())

    def test_detected_stack_is_identical_when_scoped(self):
        full = run_all(self.root, "t")["stack"]
        scoped = run_all(self.root, "t", only=["src/c.py"])["stack"]
        self.assertEqual(sorted(full.get("languages", [])), sorted(scoped.get("languages", [])))
        self.assertEqual(sorted(full.get("frameworks", [])), sorted(scoped.get("frameworks", [])))

    def test_stack_survives_scoping_to_a_file_that_is_not_the_main_language(self):
        (self.root / "src" / "web.ts").write_text("Deno.serve((r) => new Response('x'));\n")
        full = run_all(self.root, "t")["stack"]
        scoped = run_all(self.root, "t", only=["src/c.py"])["stack"]
        self.assertIn("deno", full.get("frameworks", []))
        self.assertEqual(sorted(full.get("frameworks", [])), sorted(scoped.get("frameworks", [])),
                         "a scoped run must not conclude a Deno repo is not a Deno repo")


class ScopeFindingParityTests(unittest.TestCase):
    """THE no-regression bar: scoped analysis must never invent a finding the full tree lacks.

    Measured on this project at 320 files: 0 new and 0 lost for in-scope files."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = _tree(Path(self.temp.name).resolve())

    @staticmethod
    def _ids(ledger):
        return {(f.get("rule_id") or f.get("attack_class"), f.get("file"), f.get("severity"),
                 f.get("confidence")) for f in ledger["findings"]}

    def test_scoped_findings_are_a_subset_of_full_tree_findings(self):
        full = self._ids(build_ledger(run_all(self.root, "t"), None))
        targets = sorted({f[1] for f in full if f[1]})
        scoped = self._ids(build_ledger(run_all(self.root, "t", only=targets), None))
        self.assertEqual(scoped - full, set(),
                         "scoping invented a finding the full tree does not report")

    def test_in_scope_findings_are_not_lost(self):
        full = build_ledger(run_all(self.root, "t"), None)
        targets = sorted({f.get("file") for f in full["findings"] if f.get("file")})
        self.assertTrue(targets, "fixture must produce file-attributed findings to test parity")
        scoped = self._ids(build_ledger(run_all(self.root, "t", only=targets), None))
        in_scope = {f for f in self._ids(full) if f[1] in set(targets)}
        self.assertEqual(in_scope - scoped, set(), "a finding in scope was lost")

    def test_severity_is_not_inflated_by_scoping(self):
        """The bare-directory experiment produced CRITICALs from lost path context. Analyzing in
        place must keep severities identical."""
        full = build_ledger(run_all(self.root, "t"), None)
        by_file = {}
        for f in full["findings"]:
            by_file.setdefault(f.get("file"), []).append(f.get("severity"))
        targets = sorted(x for x in by_file if x)
        self.assertTrue(targets, "fixture must produce file-attributed findings to test parity")
        scoped = build_ledger(run_all(self.root, "t", only=targets), None)
        for f in scoped["findings"]:
            name = f.get("file")
            if name and name in by_file:
                self.assertIn(f.get("severity"), by_file[name],
                              f"severity changed under scoping for {name}")


if __name__ == "__main__":
    unittest.main()

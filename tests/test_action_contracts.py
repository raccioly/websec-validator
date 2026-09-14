"""Trusted action argv and exact-attempt artifact contracts, without installing tools."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from websec_validator import cli
spec = importlib.util.spec_from_file_location("websec_action", ROOT / "scripts/run-action.py")
action = importlib.util.module_from_spec(spec); spec.loader.exec_module(action)


class ActionContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.repo = self.root / "repo"; self.repo.mkdir()
        (self.repo / "app.py").write_text('print("safe")\n')
        self.out = self.root / "artifacts with spaces"; self.output = self.root / "github-output"
        self.env = {"WEBSEC_INPUT_PATH": str(self.repo), "WEBSEC_INPUT_OUT": str(self.out),
                    "WEBSEC_INPUT_SCAN": "false", "WEBSEC_INPUT_REQUIRE_COMPLETE": "true",
                    "WEBSEC_INPUT_FAIL_ON": "", "WEBSEC_INPUT_BASELINE": "", "WEBSEC_INPUT_SCANNERS": "",
                    "GITHUB_OUTPUT": str(self.output)}

    def run_action(self, main=cli.main, **env):
        self.output.unlink(missing_ok=True)
        with patch.dict(os.environ, {**self.env, **env}), patch("shutil.which", return_value=None), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return action.run(main)

    def outputs(self):
        return dict(line.split("=", 1) for line in self.output.read_text().splitlines())

    def test_incomplete_attempt_exports_its_own_sarif_and_preserves_previous_latest(self):
        self.assertEqual(self.run_action(), 0)
        old = self.outputs()["sarif_file"]
        self.assertEqual(self.run_action(WEBSEC_INPUT_SCAN="true", WEBSEC_INPUT_SCANNERS="semgrep"), 2)
        outputs = self.outputs()
        self.assertNotEqual(outputs["sarif_file"], old)
        self.assertEqual(outputs["execution_complete"], "false")
        self.assertEqual((self.out / "latest/results.sarif").resolve(), Path(old))
        current = json.loads(Path(outputs["sarif_file"]).read_text())
        self.assertFalse(current["runs"][0]["invocations"][0]["executionSuccessful"])

    def test_missing_envelope_never_uploads_old_latest(self):
        self.assertEqual(self.run_action(), 0)
        self.assertEqual(self.run_action(lambda _: 2), 2)
        self.assertFalse(self.output.exists())

    def test_command_substitution_and_spaces_are_literal_argv(self):
        captured = []
        def fake(args):
            captured.extend(args)
            return 2
        malicious = '$(printf DO_NOT_EXECUTE); repo " with spaces'
        self.assertEqual(self.run_action(fake, WEBSEC_INPUT_PATH=malicious), 2)
        self.assertEqual(captured[1], malicious)
        self.assertEqual(captured[captured.index("--out") + 1], str(self.out))
        self.assertIn("--require-complete", captured)

    def test_invalid_run_identity_and_escaping_artifact_parent_are_rejected(self):
        def forged(_):
            print(json.dumps({"generated": "../prior", "coverage": {"execution_complete": True}}))
            return 0
        self.assertEqual(self.run_action(forged), 2)
        self.assertFalse(self.output.exists())
        outside = self.root / "outside"; (outside / "current").mkdir(parents=True)
        (outside / "current/results.sarif").write_text("{}")
        self.out.mkdir(); (self.out / "runs").symlink_to(outside, target_is_directory=True)
        def escaped(_):
            print(json.dumps({"generated": "current", "coverage": {"execution_complete": True}}))
            return 0
        self.assertEqual(self.run_action(escaped), 2)
        self.assertFalse(self.output.exists())

    def test_invalid_inputs_do_not_run_and_workflow_has_no_shell_interpolation(self):
        def forbidden(_):
            self.fail("invalid input reached scanner")
        self.assertEqual(self.run_action(forbidden, WEBSEC_INPUT_SCAN="yes"), 2)
        self.assertEqual(self.run_action(forbidden, WEBSEC_INPUT_PATH="repo\nINJECTED=1"), 2)
        workflow = (ROOT / "action.yml").read_text()
        for line in workflow.splitlines():
            if line.strip().startswith("run:"):
                self.assertNotIn("${{", line)
        self.assertIn('pip install --disable-pip-version-check "$WEBSEC_ACTION_PATH"', workflow)
        self.assertNotIn("pipx install websec-validator", workflow)
        self.assertNotIn("/latest/results.sarif", workflow)
        self.assertIn("sarif_file: ${{ steps.scan.outputs.sarif_file }}", workflow)


if __name__ == "__main__":
    unittest.main()

"""Executable local guardrail policy, isolation, and hook composition contracts."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator import hooks

UNSAFE = 'from flask import Flask, request\napp=Flask(__name__)\n@app.route("/eval")\ndef evaluate():\n    return eval(request.args.get("code"))\n'


class HookContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hook contracts ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo with spaces"; self.repo.mkdir()
        self.git = self.root / "git metadata"; self.git.mkdir()
        self.bin = self.root / "bin"; self.bin.mkdir()
        fake = self.bin / "git"
        fake.write_text('#!/bin/sh\ncase "$*" in *--show-toplevel*) printf "%s\\n" "$AUDIT_ROOT";; *--absolute-git-dir*) printf "%s\\n" "$AUDIT_GIT";; *) exit 1;; esac\n')
        fake.chmod(0o755)
        self.env = {"PATH": str(self.bin) + ":/usr/bin:/bin", "AUDIT_ROOT": str(self.repo),
                    "AUDIT_GIT": str(self.git), "WEBSEC_HOOK_FAIL_ON": "low", "WEBSEC_HOOK_SCAN": "0",
                    "WEBSEC_HOOK_SCANNERS": "", "WEBSEC_SKIP_HOOK": "0"}
        self.guard = self.git / "websec-guardrail"
        (self.repo / "app.py").write_text('print("safe")\n')

    def run_hook(self, gate=True, **env):
        with patch.dict(os.environ, {**self.env, **env}), patch("shutil.which", return_value=None), contextlib.redirect_stderr(io.StringIO()):
            return hooks.run_guardrail(pre_push=gate)

    def test_failed_gate_retry_and_advisory_never_accept_findings(self):
        (self.repo / "app.py").write_text(UNSAFE)
        self.assertEqual(self.run_hook(False), 0)
        self.assertFalse((self.guard / "accepted-state.json").exists())
        self.assertEqual(self.run_hook(), 1)
        self.assertEqual(self.run_hook(), 1)
        ledger = json.loads((self.guard / "latest/findings-ledger.json").read_text())
        self.assertGreater(ledger["total"], 0)
        self.assertFalse((self.guard / "accepted-state.json").exists())

    def test_success_accepts_and_later_failure_preserves_baseline(self):
        self.assertEqual(self.run_hook(), 0)
        self.assertEqual(self.run_hook(), 0)
        accepted = (self.guard / "accepted-state.json").read_bytes()
        (self.repo / "app.py").write_text(UNSAFE)
        self.assertEqual(self.run_hook(), 1)
        self.assertEqual((self.guard / "accepted-state.json").read_bytes(), accepted)

    def test_threshold_and_scanner_policy_changes_cannot_reuse_accepted_debt(self):
        (self.repo / "app.py").write_text(UNSAFE)
        self.assertEqual(self.run_hook(WEBSEC_HOOK_FAIL_ON="high"), 0)
        self.assertEqual(self.run_hook(WEBSEC_HOOK_FAIL_ON="low"), 1)
        self.assertEqual(self.run_hook(WEBSEC_HOOK_FAIL_ON="high", WEBSEC_HOOK_SCAN="1", WEBSEC_HOOK_SCANNERS="semgrep"), 3)

    def test_pre_push_scans_dependencies_by_default(self):
        self.assertEqual(hooks._scan_mode(None, True), "deps")
        self.assertEqual(hooks._scan_mode("", True), "deps")
        self.assertEqual(hooks._scan_mode(None, False), "off")      # advisory post-commit stays fast
        self.assertEqual(hooks._scan_mode("0", True), "off")
        self.assertEqual(hooks._scan_mode("1", True), "all")
        captured = []
        def fake_invoke(root, guard, args):
            captured.append(args)
            return 2, None, {}
        env = dict(self.env); env.pop("WEBSEC_HOOK_SCAN")
        with patch.dict(os.environ, env, clear=False), patch.object(hooks, "_invoke", fake_invoke), \
             patch.object(hooks.shutil, "which", lambda name: "/bin/" + name if name == "osv-scanner" else None), \
             contextlib.redirect_stderr(io.StringIO()):
            os.environ.pop("WEBSEC_HOOK_SCAN", None)
            hooks.run_guardrail(pre_push=True)
        self.assertIn("--scan", captured[-1])
        self.assertEqual(captured[-1][captured[-1].index("--scanners") + 1], "osv-scanner")

    def test_missing_sca_tool_is_loud_and_never_reuses_a_scanned_baseline(self):
        env = dict(self.env); env.pop("WEBSEC_HOOK_SCAN")
        err = io.StringIO()
        with patch.dict(os.environ, env), patch("shutil.which", return_value=None), contextlib.redirect_stderr(err):
            os.environ.pop("WEBSEC_HOOK_SCAN", None)
            self.assertEqual(hooks.run_guardrail(pre_push=True), 0)
        self.assertIn("dependency scan SKIPPED", err.getvalue())
        state = json.loads((self.guard / "accepted-state.json").read_text())
        self.assertEqual(state["policy"]["scan_mode"], "deps-unavailable")

    def test_lock_and_invalid_policy_fail_gate_but_advisory_is_nonblocking(self):
        self.guard.mkdir(); (self.guard / "running.lock").mkdir()
        self.assertEqual(self.run_hook(), 2)
        self.assertEqual(self.run_hook(False), 0)
        (self.guard / "running.lock").rmdir()
        self.assertEqual(self.run_hook(WEBSEC_HOOK_FAIL_ON="invalid"), 2)

    def test_runtime_missing_fails_closed_and_preserves_foreign_hook(self):
        with patch.object(hooks, "_safe_pinned_python", return_value=""):
            script = hooks._script(True)
        process = subprocess.run(["/bin/sh", "-c", script], env={"PATH": "/missing"}, capture_output=True)
        self.assertEqual(process.returncode, 2)
        hook_dir = self.root / "hooks"; hook_dir.mkdir()
        hook = hook_dir / "pre-push"; hook.write_text("#!/bin/sh\nexit 7\n")
        hooks._write_hook(hook_dir, "pre-push", hooks._script(True))
        process = subprocess.run(["/bin/sh", str(hook)], env={"WEBSEC_SKIP_HOOK": "1"}, capture_output=True)
        self.assertEqual(process.returncode, 7)
        hooks._remove_hook(hook_dir, "pre-push")
        self.assertIn("exit 7", hook.read_text())

    def test_non_shell_hook_is_unchanged_and_target_package_cannot_execute(self):
        hook_dir = self.root / "hooks"; hook_dir.mkdir()
        hook = hook_dir / "pre-push"; original = "#!/usr/bin/env python3\nraise SystemExit(0)\n"; hook.write_text(original)
        with self.assertRaises(RuntimeError):
            hooks._write_hook(hook_dir, "pre-push", hooks._script(True))
        self.assertEqual(hook.read_text(), original)
        package = self.repo / "websec_validator"; package.mkdir()
        marker = self.root / "shadow-executed"
        (package / "__init__.py").write_text("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('executed')\n")
        script = self.root / "guard.sh"; script.write_text(hooks._script(True))
        process = subprocess.run(["/bin/sh", str(script)], cwd=self.repo,
            env={**os.environ, **self.env, "PYTHONPATH": str(self.repo)}, capture_output=True, timeout=30)
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        self.assertFalse(marker.exists())

    def test_run_pruning_is_reachable(self):
        for _ in range(7):
            self.assertEqual(self.run_hook(), 0)
        self.assertLessEqual(len(list((self.guard / "runs").iterdir())), 5)
        self.assertTrue((self.guard / "latest/findings-ledger.json").is_file())

    def test_existing_shebang_without_newline_remains_executable(self):
        hook_dir = self.root / "hooks"; hook_dir.mkdir()
        hook = hook_dir / "pre-push"; hook.write_text("#!/bin/sh")
        hooks._write_hook(hook_dir, "pre-push", hooks._script(True))
        process = subprocess.run([str(hook)], env={**os.environ, "WEBSEC_SKIP_HOOK": "1"}, capture_output=True)
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        self.assertEqual(hook.read_text().splitlines()[0], "#!/bin/sh")


if __name__ == "__main__":
    unittest.main()

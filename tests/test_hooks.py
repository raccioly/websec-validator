"""Tests for `websec hooks` — the git guardrail installer.

Covers marker-based install/uninstall (idempotent, preserves foreign hook content), pinned-interpreter
sanitization, pre-push vs post-commit variants, and an end-to-end run of the generated post-commit
hook in a real temp git repo against a fixture app.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from websec_validator import hooks                    # noqa: E402
from websec_validator.cli import main                 # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "py_app"
HAVE_GIT = shutil.which("git") is not None


def _init_repo(root: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "config", "core.hooksPath", ".git/hooks"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=root, check=True)


@unittest.skipUnless(HAVE_GIT, "git not available")
class HooksTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _init_repo(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def _hook(self, name: str) -> Path:
        return self.root / ".git" / "hooks" / name

    def test_install_post_commit(self):
        msg = hooks.install(self.root)
        self.assertIn("post-commit", msg)
        hook = self._hook("post-commit")
        self.assertTrue(hook.exists())
        body = hook.read_text()
        self.assertIn(hooks.MARKER_START, body)
        self.assertIn(hooks.MARKER_END, body)
        self.assertIn("websec_validator.cli", body)
        self.assertTrue(os.access(hook, os.X_OK))

    def test_install_pre_push_gate(self):
        hooks.install(self.root, pre_push=True)
        body = self._hook("pre-push").read_text()
        self.assertIn("--fail-on", body)

    def test_reinstall_idempotent(self):
        hooks.install(self.root)
        hooks.install(self.root)
        body = self._hook("post-commit").read_text()
        self.assertEqual(body.count(hooks.MARKER_START), 1)

    def test_appends_to_existing_hook(self):
        hook = self._hook("post-commit")
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text("#!/bin/sh\necho 'my own hook'\n")
        hooks.install(self.root)
        body = hook.read_text()
        self.assertIn("my own hook", body)
        self.assertIn(hooks.MARKER_START, body)

    def test_uninstall_preserves_foreign_content(self):
        hook = self._hook("post-commit")
        hook.parent.mkdir(parents=True, exist_ok=True)
        hook.write_text("#!/bin/sh\necho 'my own hook'\n")
        hooks.install(self.root)
        hooks.uninstall(self.root)
        body = hook.read_text()
        self.assertIn("my own hook", body)
        self.assertNotIn(hooks.MARKER_START, body)

    def test_uninstall_removes_pure_websec_hook(self):
        hooks.install(self.root)
        hooks.uninstall(self.root)
        self.assertFalse(self._hook("post-commit").exists())

    def test_status_reports(self):
        out = hooks.status(self.root)
        self.assertIn("post-commit", out)
        hooks.install(self.root)
        self.assertIn("✓", hooks.status(self.root))

    def test_pinned_python_sanitized(self):
        # A pinned interpreter path with shell metacharacters must never reach the script.
        real = sys.executable
        try:
            sys.executable = "/usr/bin/python3; rm -rf /"
            script = hooks._script(pre_push=False)
            self.assertNotIn("rm -rf /", script)
        finally:
            sys.executable = real

    def test_cli_wiring(self):
        self.assertEqual(main(["hooks", "install", "--path", str(self.root)]), 0)
        self.assertTrue(self._hook("post-commit").exists())
        self.assertEqual(main(["hooks", "status", "--path", str(self.root)]), 0)
        self.assertEqual(main(["hooks", "uninstall", "--path", str(self.root)]), 0)

    def test_end_to_end_post_commit_runs(self):
        # Copy the fixture app into the repo, install the hook, commit, and assert the guardrail ran.
        for f in FIXTURE.rglob("*"):
            if f.is_file():
                dst = self.root / f.relative_to(FIXTURE)
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(f.read_bytes())
        hooks.install(self.root)
        env = dict(os.environ)
        # Ensure the hook's interpreter can import websec_validator from source.
        env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
        subprocess.run(["git", "add", "-A"], cwd=self.root, check=True, env=env)
        r = subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=self.root,
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        guard = self.root / ".git" / "websec-guardrail"
        self.assertTrue((guard / "latest" / "findings-ledger.json").exists(),
                        f"guardrail did not run; hook.log: "
                        f"{(guard / 'hook.log').read_text() if (guard / 'hook.log').exists() else 'absent'}")


if __name__ == "__main__":
    unittest.main()

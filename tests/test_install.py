"""Tests for `websec install <host>` — the multi-host agent installer.

Covers: each host writes to the right place; skill vs block styles; idempotent re-install;
uninstall preserves surrounding content in shared files; path-safety; and the CLI wiring.
"""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from websec_validator import install                 # noqa: E402
from websec_validator.cli import main                # noqa: E402


class InstallTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    # --- skill-style hosts (own the whole file) ---

    def test_claude_writes_skill_file(self):
        msg = install.install("claude", project_dir=self.root)
        dest = self.root / ".claude/skills/security-pass/SKILL.md"
        self.assertTrue(dest.exists())
        body = dest.read_text()
        self.assertIn("name: security-pass", body)
        self.assertIn("websec run", body)
        self.assertIn("Claude Code skill", msg)

    def test_cursor_writes_mdc_with_frontmatter(self):
        install.install("cursor", project_dir=self.root)
        dest = self.root / ".cursor/rules/websec-validator.mdc"
        self.assertTrue(dest.exists())
        body = dest.read_text()
        self.assertTrue(body.startswith("---\n"))
        self.assertIn("alwaysApply: true", body)

    def test_skill_uninstall_deletes_file(self):
        install.install("claude", project_dir=self.root)
        dest = self.root / ".claude/skills/security-pass/SKILL.md"
        self.assertTrue(dest.exists())
        install.install("claude", project_dir=self.root, uninstall=True)
        self.assertFalse(dest.exists())

    # --- block-style hosts (marked region in a shared file) ---

    def test_gemini_writes_block(self):
        install.install("gemini", project_dir=self.root)
        dest = self.root / "GEMINI.md"
        body = dest.read_text()
        self.assertIn(install.MARKER_START, body)
        self.assertIn(install.MARKER_END, body)
        self.assertIn("websec run", body)

    def test_block_preserves_existing_content(self):
        dest = self.root / "AGENTS.md"
        dest.write_text("# My project rules\n\nAlways write tests.\n")
        install.install("generic", project_dir=self.root)
        body = dest.read_text()
        self.assertIn("# My project rules", body)
        self.assertIn("Always write tests.", body)
        self.assertIn(install.MARKER_START, body)

    def test_reinstall_is_idempotent(self):
        install.install("generic", project_dir=self.root)
        install.install("generic", project_dir=self.root)
        body = (self.root / "AGENTS.md").read_text()
        self.assertEqual(body.count(install.MARKER_START), 1)
        self.assertEqual(body.count(install.MARKER_END), 1)

    def test_block_uninstall_keeps_surrounding_content(self):
        dest = self.root / "AGENTS.md"
        dest.write_text("# Keep me\n")
        install.install("generic", project_dir=self.root)
        install.install("generic", project_dir=self.root, uninstall=True)
        body = dest.read_text()
        self.assertIn("# Keep me", body)
        self.assertNotIn(install.MARKER_START, body)

    def test_block_only_file_removed_on_uninstall(self):
        install.install("gemini", project_dir=self.root)
        dest = self.root / "GEMINI.md"
        self.assertTrue(dest.exists())
        install.install("gemini", project_dir=self.root, uninstall=True)
        self.assertFalse(dest.exists())

    # --- safety + errors ---

    def test_unknown_host_raises(self):
        with self.assertRaises(ValueError):
            install.install("notahost", project_dir=self.root)

    def test_status_lists_hosts(self):
        out = install.status(project_dir=self.root)
        for host in install.HOSTS:
            self.assertIn(host, out)
        install.install("gemini", project_dir=self.root)
        out2 = install.status(project_dir=self.root)
        self.assertIn("✓", out2)

    # --- CLI wiring ---

    def test_cli_install_and_uninstall(self):
        rc = main(["install", "gemini", "--project-dir", str(self.root)])
        self.assertEqual(rc, 0)
        self.assertTrue((self.root / "GEMINI.md").exists())
        rc = main(["install", "gemini", "--project-dir", str(self.root), "--uninstall"])
        self.assertEqual(rc, 0)
        self.assertFalse((self.root / "GEMINI.md").exists())

    def test_cli_status(self):
        rc = main(["install", "status", "--project-dir", str(self.root)])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()

"""PostToolUse agent-loop hook: block the loop on the edit that caused the finding.

The properties that matter: it must block only on real findings, it must NEVER block because it is
itself broken, it must not honour an env escape hatch the agent can set, and it must cost nothing
on edits no detector reads.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator import agenthook, hooks

VULN = '''from flask import Flask, request
import subprocess
app = Flask(__name__)

@app.route("/ping")
def ping():
    return subprocess.check_output("ping -c1 " + request.args.get("host"), shell=True)
'''


def _event(cwd, path, tool="Write"):
    return {"hook_event_name": "PostToolUse", "tool_name": tool, "cwd": str(cwd),
            "tool_input": {"file_path": str(path)}}


class AgentHookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve() / "r"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "requirements.txt").write_text("flask==3.0.0\n")
        (self.repo / "src" / "ok.py").write_text("def add(a, b):\n    return a + b\n")
        for cmd in (["git", "init", "-q", "."], ["git", "config", "user.email", "d@e.com"],
                    ["git", "config", "user.name", "D"]):
            subprocess.run(cmd, cwd=self.repo, check=True)
        subprocess.run(["git", "add", "-A"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=self.repo, check=True)

    def _vuln(self):
        p = self.repo / "src" / "app.py"
        p.write_text(VULN)
        return p

    def test_vulnerable_write_blocks_the_loop(self):
        self.assertEqual(agenthook.run(_event(self.repo, self._vuln()), env={}), 2)

    def test_safe_write_passes_silently(self):
        self.assertEqual(agenthook.run(_event(self.repo, self.repo / "src" / "ok.py"), env={}), 0)

    def test_unanalyzable_suffix_is_skipped_entirely(self):
        """A markdown edit must not pay for a scan."""
        doc = self.repo / "notes.md"
        doc.write_text("# hi\n")
        with patch.object(agenthook, "_repo_root") as spy:
            self.assertEqual(agenthook.run(_event(self.repo, doc), env={}), 0)
            spy.assert_not_called()

    def test_block_message_reaches_stderr_for_the_model(self):
        from io import StringIO
        buf = StringIO()
        with patch.object(sys, "stderr", buf):
            agenthook.run(_event(self.repo, self._vuln()), env={})
        text = buf.getvalue()
        self.assertIn("command-injection", text)
        self.assertIn("src/app.py", text)
        self.assertIn("false positive", text, "the model needs a way to disagree")

    def test_threshold_is_configurable_by_env(self):
        self.assertEqual(agenthook.run(_event(self.repo, self._vuln()),
                                       env={"WEBSEC_GATE_FAIL_ON": "critical"}), 0)

    # ---- it must never block because IT is broken ----
    def test_internal_error_fails_open_not_closed(self):
        """A check that blocks every edit when broken gets uninstalled, and then there is no check."""
        self._vuln()
        with patch("websec_validator.recon.build_facts", side_effect=RuntimeError("boom")):
            self.assertEqual(agenthook.run(_event(self.repo, self.repo / "src" / "app.py"), env={}), 0)

    def test_internal_error_is_loud_about_not_having_checked(self):
        from io import StringIO
        buf = StringIO()
        self._vuln()
        with patch("websec_validator.recon.build_facts", side_effect=RuntimeError("boom")), \
             patch.object(sys, "stderr", buf):
            agenthook.run(_event(self.repo, self.repo / "src" / "app.py"), env={})
        self.assertIn("NOT blocking", buf.getvalue())
        self.assertIn("not security-checked", buf.getvalue())

    def test_malformed_event_does_not_crash(self):
        for bad in ({}, {"tool_input": None}, {"tool_input": {}}, {"tool_input": {"file_path": ""}}):
            self.assertEqual(agenthook.run(bad, env={}), 0)

    def test_file_outside_the_repo_is_not_gated(self):
        with tempfile.TemporaryDirectory() as other:
            stray = Path(other) / "x.py"
            stray.write_text(VULN)
            self.assertEqual(agenthook.run(_event(self.repo, stray), env={}), 0)

    def test_no_env_escape_hatch_the_agent_could_set(self):
        """The git guardrail honours WEBSEC_SKIP_HOOK; this must not — the agent can set env vars."""
        self.assertEqual(agenthook.run(_event(self.repo, self._vuln()),
                                       env={"WEBSEC_SKIP_HOOK": "1"}), 2)
        self.assertNotIn("WEBSEC_SKIP_HOOK",
                         Path(agenthook.__file__).read_text().split('"""', 2)[2])


class AgentHookInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.settings = self.root / ".claude" / "settings.json"

    def test_install_creates_the_posttooluse_entry(self):
        hooks.install_agent_hook(self.root)
        data = json.loads(self.settings.read_text())
        group = data["hooks"]["PostToolUse"][0]
        self.assertEqual(group["matcher"], "Write|Edit|MultiEdit")
        self.assertIn("websec", group["hooks"][0]["command"])

    def test_install_preserves_the_users_own_settings(self):
        self.settings.parent.mkdir(parents=True)
        self.settings.write_text(json.dumps({"permissions": {"allow": ["Bash(ls:*)"]},
                                             "hooks": {"PostToolUse": [
                                                 {"matcher": "Read",
                                                  "hooks": [{"type": "command", "command": "mine"}]}]}}))
        hooks.install_agent_hook(self.root)
        data = json.loads(self.settings.read_text())
        self.assertEqual(data["permissions"]["allow"], ["Bash(ls:*)"])
        commands = [h["command"] for g in data["hooks"]["PostToolUse"] for h in g["hooks"]]
        self.assertIn("mine", commands, "the user's own hook must survive")

    def test_install_is_idempotent(self):
        hooks.install_agent_hook(self.root)
        second = hooks.install_agent_hook(self.root)
        self.assertEqual(second["action"], "replaced")
        data = json.loads(self.settings.read_text())
        ours = [g for g in data["hooks"]["PostToolUse"] if hooks._is_ours(g)]
        self.assertEqual(len(ours), 1, "re-install must not duplicate the entry")

    def test_uninstall_removes_only_our_entry(self):
        self.settings.parent.mkdir(parents=True)
        self.settings.write_text(json.dumps({"hooks": {"PostToolUse": [
            {"matcher": "Read", "hooks": [{"type": "command", "command": "mine"}]}]}}))
        hooks.install_agent_hook(self.root)
        hooks.install_agent_hook(self.root, uninstall=True)
        data = json.loads(self.settings.read_text())
        commands = [h["command"] for g in data["hooks"]["PostToolUse"] for h in g["hooks"]]
        self.assertEqual(commands, ["mine"])

    def test_unparseable_settings_is_refused_not_clobbered(self):
        self.settings.parent.mkdir(parents=True)
        self.settings.write_text("{ not json")
        got = hooks.install_agent_hook(self.root)
        self.assertFalse(got["ok"])
        self.assertEqual(self.settings.read_text(), "{ not json",
                         "a settings file we cannot parse must never be overwritten")

    def test_status_reports_installation(self):
        self.assertFalse(hooks.agent_hook_status(self.root)["installed"])
        hooks.install_agent_hook(self.root)
        self.assertTrue(hooks.agent_hook_status(self.root)["installed"])


class PluginHookManifestTests(unittest.TestCase):
    def test_plugin_ships_a_hooks_manifest(self):
        root = Path(__file__).resolve().parents[1]
        data = json.loads((root / "hooks" / "hooks.json").read_text())
        group = data["hooks"]["PostToolUse"][0]
        self.assertEqual(group["matcher"], "Write|Edit|MultiEdit")
        self.assertEqual(group["hooks"][0]["command"], "websec-agent-hook")

    def test_console_script_is_declared(self):
        root = Path(__file__).resolve().parents[1]
        self.assertIn("websec-agent-hook", (root / "pyproject.toml").read_text())


if __name__ == "__main__":
    unittest.main()

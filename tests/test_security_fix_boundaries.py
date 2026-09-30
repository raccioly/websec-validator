"""Security findings: contained writes, safe Git, data-only imports and honest gate outcomes."""
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
from websec_validator import agenthook, attribution, cli, diffscope, feedback, gate, hooks, init_scope, recon, synthetic
from websec_validator.extractors.base import RepoContext, MAX_BYTES
from websec_validator.extractors.dependencies import _pip_private_index, DependenciesExtractor
from websec_validator import registry


class OwnedFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.repo = self.base / "repo"
        self.repo.mkdir()
        (self.repo / "app.py").write_text("x = 1\n")
        self.outside = self.base / "outside"
        self.outside.mkdir()
        self.sentinel = self.outside / "sentinel.json"
        self.sentinel.write_text('{"foreign": true}\n')


class ContainedWriterTests(OwnedFixture):
    def test_feedback_default_base_alias_is_rejected_but_explicit_selection_works(self):
        sentinel = self.outside / "feedback.jsonl"
        sentinel.write_text("keep\n")
        alias = self.base / "websec-out"
        alias.symlink_to(self.outside, target_is_directory=True)
        argv = ["feedback", "--verdict", "false-negative", "--attack-class", "xss", "--reason", "supported pattern was not detected"]
        with patch.object(Path, "cwd", return_value=self.base), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(argv), 2)
            self.assertEqual(sentinel.read_text(), "keep\n")
            self.assertEqual(cli.main([*argv, "--out", str(alias)]), 0)
        self.assertEqual(len(sentinel.read_text().splitlines()), 2)

    def test_implicit_recon_output_directory_alias_is_not_operator_selection(self):
        sentinel = self.outside / "FACTS.json"
        sentinel.write_text("keep")
        (self.base / "websec-out").symlink_to(self.outside, target_is_directory=True)
        with patch.object(Path, "cwd", return_value=self.base), patch.object(cli.recon, "build_facts", return_value={}), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["recon", str(self.repo)]), 2)
        self.assertEqual(sentinel.read_text(), "keep")

    def test_implicit_agent_parent_alias_rejected_on_install_uninstall_and_status(self):
        (self.repo / ".claude").symlink_to(self.outside, target_is_directory=True)
        before = self.sentinel.read_bytes()
        for uninstall in (False, True):
            self.assertFalse(hooks.install_agent_hook(self.repo, uninstall=uninstall)["ok"])
        self.assertIn("error", hooks.agent_hook_status(self.repo))
        self.assertEqual(self.sentinel.read_bytes(), before)
        self.assertFalse((self.outside / "settings.json").exists())

    def test_agent_leaf_alias_and_broken_alias_are_rejected(self):
        directory = self.repo / ".claude"
        directory.mkdir()
        for target in (self.sentinel, self.outside / "absent"):
            path = directory / "settings.json"
            path.symlink_to(target)
            self.assertFalse(hooks.install_agent_hook(self.repo)["ok"])
            self.assertFalse(hooks.agent_hook_status(self.repo)["installed"])
            path.unlink()
        self.assertEqual(self.sentinel.read_text(), '{"foreign": true}\n')
        self.assertFalse((self.outside / "absent").exists())

    def test_explicit_settings_alias_remains_operator_capability(self):
        alias = self.repo / "custom.json"
        alias.symlink_to(self.sentinel)
        self.assertTrue(hooks.install_agent_hook(self.repo, settings_path=alias)["ok"])
        data = json.loads(self.sentinel.read_text())
        self.assertTrue(data["foreign"])
        self.assertTrue(hooks.install_agent_hook(self.repo, settings_path=alias, uninstall=True)["ok"])
        self.assertTrue(json.loads(self.sentinel.read_text())["foreign"])

    def test_standalone_writers_refuse_leaf_and_broken_aliases(self):
        for name, writer in (
                ("FACTS.json", lambda p: recon.write_facts({}, p)),
                ("feedback.jsonl", lambda p: feedback.append(p, {"safe": True})),
                (".websec-ignore", lambda p: init_scope.write(p.parent, {"entries": []}, force=True))):
            for target in (self.sentinel, self.outside / "absent"):
                with self.subTest(name=name, target=target):
                    path = self.repo / name
                    path.symlink_to(target)
                    with self.assertRaises(OSError):
                        writer(path)
                    path.unlink()
        self.assertEqual(self.sentinel.read_text(), '{"foreign": true}\n')
        self.assertFalse((self.outside / "absent").exists())

    def test_explicit_output_base_alias_and_force_preserve_legitimate_workflows(self):
        alias = self.base / "selected"
        alias.symlink_to(self.outside, target_is_directory=True)
        path = recon.write_facts({"ok": True}, alias / "FACTS.json")
        self.assertTrue(json.loads(path.read_text())["ok"])
        feedback.append(alias / "feedback.jsonl", {"n": 1})
        feedback.append(alias / "feedback.jsonl", {"n": 2})
        self.assertEqual(len((self.outside / "feedback.jsonl").read_text().splitlines()), 2)
        proposal = {"entries": []}
        self.assertTrue(init_scope.write(self.repo, proposal)["written"])
        self.assertFalse(init_scope.write(self.repo, proposal)["written"])
        self.assertTrue(init_scope.write(self.repo, proposal, force=True)["written"])

    def test_atomic_writer_does_not_truncate_hardlink_peer_and_append_refuses_it(self):
        peer = self.repo / "FACTS.json"
        os.link(self.sentinel, peer)
        recon.write_facts({"ok": True}, peer)
        self.assertEqual(self.sentinel.read_text(), '{"foreign": true}\n')
        os.link(self.sentinel, self.repo / "feedback.jsonl")
        with self.assertRaises(feedback.FeedbackError):
            feedback.append(self.repo / "feedback.jsonl", {})


class SyntheticBoundaryTests(OwnedFixture):
    def pair(self, filename="src/app.ts", extractor="SurfaceExtractor"):
        return {"id": "test", "file": filename, "extractor": extractor,
                "attack_class": "xss", "confidence": "LOW",
                "vulnerable": "el.innerHTML = location.hash;", "control": "const y = 2;"}

    def test_invalid_manifest_is_rejected_before_any_materialization(self):
        for filename in (str(self.sentinel), "../outside/sentinel.json", "a/../../outside/x", "C:/x.py", "a\\..\\x.py", ".LOCAL/x.py"):
            with self.subTest(filename=filename), patch.object(synthetic.tempfile, "TemporaryDirectory", side_effect=AssertionError("no sandbox yet")):
                result = synthetic.evaluate([self.pair(), self.pair(filename)])
                self.assertTrue(result["errors"])
                self.assertEqual(result["labels"], [])
        self.assertEqual(self.sentinel.read_text(), '{"foreign": true}\n')

    def test_direct_helper_rejects_unknown_extractor_before_creating_files(self):
        with patch.object(synthetic.tempfile, "TemporaryDirectory", side_effect=AssertionError("no sandbox yet")):
            with self.assertRaises(ValueError):
                synthetic._findings_for("x = 1", str(self.sentinel), "NoSuchExtractor")
            with self.assertRaises(ValueError):
                synthetic._findings_for("x = 1", "app.py", "RepoContext")

    def test_nested_legitimate_pair_still_scores(self):
        result = synthetic.evaluate([self.pair()])
        self.assertEqual(result["errors"], [])
        self.assertEqual(len(result["labels"]), 1)


class IndexPrivacyTests(OwnedFixture):
    def marker(self, value):
        (self.repo / "pip.conf").write_text("[global]\nindex-url = " + value + "\n")
        return _pip_private_index(RepoContext(self.repo))

    def test_credentials_and_url_components_are_never_retained(self):
        secret = "REFLECTED_TEST_SECRET"
        marker = self.marker(f"https://user:{secret}@packages.example/simple?key={secret}#{secret}")
        self.assertEqual(marker, "private-or-unknown-index:packages.example")
        self.assertNotIn(secret, marker)
        (self.repo / "requirements.txt").write_text("private-widget==1.0\n")
        facts = {"dependencies": DependenciesExtractor().extract(RepoContext(self.repo), {})}
        self.assertNotIn(secret, json.dumps(facts))

    def test_exact_public_index_is_only_public_control(self):
        for url in ("https://pypi.org/simple", "https://PYPI.ORG:443/simple/"):
            self.assertEqual(self.marker(url), "")
        (self.repo / "pip.conf").write_text("[global]\nextra-index-url = https://pypi.org/simple\n    https://PYPI.ORG:443/simple/\n")
        self.assertEqual(_pip_private_index(RepoContext(self.repo)), "")
        for url in ("https://pypi.org.attacker.example/simple", "https://private.example/pypi.org/simple",
                    "https://pypi.org@private.example/simple", "https://private.example/?x=pypi.org",
                    "https://pypi.org/simple?token=secret", "http://pypi.org/simple", "https://[", "${INDEX_URL}", ""):
            self.assertTrue(self.marker(url), url)

    def test_private_extra_index_and_unreadable_config_suppress(self):
        (self.repo / "pip.conf").write_text("[global]\nextra-index-url = https://pypi.org/simple\n    https://user:secret@private.example/simple\n")
        self.assertTrue(_pip_private_index(RepoContext(self.repo)))
        (self.repo / "pip.conf").write_text("[global]\nindex-url = https://pypi.org/simple\nextra-index-url = https://user:secret@private.example/simple\n")
        self.assertTrue(_pip_private_index(RepoContext(self.repo)))
        for name in ("INDEX-URL", "index_url", "--extra_index_url"):
            (self.repo / "pip.conf").write_text("[global]\n" + name + " = https://private.example/pypi.org\n")
            self.assertTrue(_pip_private_index(RepoContext(self.repo)))
        (self.repo / "pip.conf").write_text("not a valid pip configuration\n")
        self.assertTrue(_pip_private_index(RepoContext(self.repo)))
        (self.repo / "pip.conf").write_text("x" * (MAX_BYTES + 1))
        self.assertTrue(_pip_private_index(RepoContext(self.repo)))


class GateCompletenessTests(OwnedFixture):
    def test_findings_and_incomplete_execution_keep_findings_exit_priority(self):
        result = {"passed": False, "blocking_count": 1, "execution_complete": False}
        with patch.object(gate, "evaluate", return_value=result), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["gate", str(self.repo), "--only", "app.py", "--format", "json"]), 1)

    def invoke(self, *extra):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()), patch("shutil.which", return_value=None):
            rc = cli.main(["gate", str(self.repo), "--format", "json", *extra])
        return rc, json.loads(output.getvalue())

    def test_oversized_source_never_counts_as_analyzed_or_passes(self):
        (self.repo / "app.py").write_text("x" * (MAX_BYTES + 1))
        rc, result = self.invoke("--only", "app.py")
        self.assertEqual(rc, 3)
        self.assertFalse(result["passed"])
        self.assertFalse(result["execution_complete"])
        self.assertIn("app.py", result["matched"])
        self.assertNotIn("app.py", result["analyzed"])
        self.assertIn("INCOMPLETE", gate.render_text(result))

    def test_truncated_discovery_propagates_to_cli(self):
        with patch.object(gate, "working_tree_paths", return_value={"paths": ["app.py"], "source": "working-tree", "truncated": True}):
            rc, result = self.invoke()
        self.assertEqual(rc, 3)
        self.assertFalse(result["execution_complete"])

    def test_incomplete_agent_edit_blocks_without_changing_crash_fail_open(self):
        (self.repo / "app.py").write_text("x" * (MAX_BYTES + 1))
        event = {"tool_name": "Write", "cwd": str(self.repo), "tool_input": {"file_path": str(self.repo / "app.py")}}
        output = io.StringIO()
        with patch.object(agenthook, "_repo_root", return_value=self.repo), contextlib.redirect_stderr(output):
            self.assertEqual(agenthook.run(event, env={}), 2)
        self.assertIn("INCOMPLETE", output.getvalue())

    def test_complete_safe_edit_and_optional_graph_loss_still_pass(self):
        rc, result = self.invoke("--only", "app.py")
        self.assertEqual(rc, 0)
        self.assertTrue(result["execution_complete"])
        self.assertIn("app.py", result["analyzed"])
        facts = {"analysis_scope": {"matched": ["app.py"]}, "coverage": {
            "execution_complete": True, "inputs": {"app.py": "hash"}, "gaps": [{"kind": "graph", "execution": False}]}}
        self.assertTrue(gate.verdict({"findings": []}, facts, "medium")["passed"])

    def test_read_failure_extractor_failure_and_budget_losses_fail_closed(self):
        for gap in ("unreadable", "extractor", "byte_budget_exceeded"):
            facts = {"coverage": {"execution_complete": True, "gaps": [{"kind": gap, "execution": True}]}}
            self.assertFalse(gate.verdict({"findings": []}, facts, "medium")["passed"])


class GitHelperIsolationTests(OwnedFixture):
    def git(self, *args, **kwargs):
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True, text=True, **kwargs).stdout

    def setUp(self):
        super().setUp()
        self.git("init", "-q")
        for key, value in (("user.name", "Test"), ("user.email", "test@example.com"), ("core.hooksPath", ".git/hooks"), ("commit.gpgsign", "false"), ("core.autocrlf", "false")):
            self.git("config", key, value)
        self.git("add", "app.py")
        self.git("commit", "-qm", "base")
        (self.repo / "app.py").write_text("x = 2\n")
        self.git("add", "app.py")
        self.git("commit", "-qm", "change")
        self.marker = self.base / "helper-ran"
        helper = self.base / "helper.sh"
        helper.write_text('#!/bin/sh\nprintf ran > "' + str(self.marker) + '"\n')
        helper.chmod(0o700)
        for key in ("core.fsmonitor", "gpg.program", "gpg.ssh.program", "diff.test.textconv", "diff.external"):
            self.git("config", key, str(helper))
        for key in ("filter.evil.clean", "filter.evil.process"):
            self.git("config", key, str(helper))
        (self.repo / ".gitattributes").write_text("*.py diff=test filter=evil\n")
        (self.repo / "app.py").write_text("x = 3\n")
        self.git("config", "log.showSignature", "true")

    def test_metadata_and_diff_do_not_execute_checkout_helpers(self):
        got = attribution.build(self.repo, env={})
        self.assertEqual(got["assurance"], "vcs-observed")
        self.assertIn("commit", got["vcs"])
        self.assertIn("app.py", diffscope.compute(self.repo, "HEAD~1")["files"])
        self.assertEqual(gate.working_tree_paths(self.repo)["source"], "working-tree")
        self.assertEqual(agenthook._repo_root(self.repo), self.repo)
        self.assertFalse(self.marker.exists())

    def test_inherited_git_selector_cannot_redirect_metadata(self):
        expected = self.git("rev-parse", "HEAD").strip()
        with patch.dict(os.environ, {"GIT_DIR": str(self.outside), "GIT_WORK_TREE": str(self.outside), "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_VALUE_0": "unexpected"}):
            self.assertEqual(attribution._git(self.repo, "rev-parse", "HEAD").strip(), expected)

    def test_signature_observation_never_calls_verification_commands(self):
        calls = []
        def metadata(target, *args):
            calls.append(args)
            if args == ("rev-parse", "HEAD"):
                return "a" * 40
            if args == ("cat-file", "commit", "HEAD"):
                return "tree abc\ngpgsig -----BEGIN PGP SIGNATURE-----\n fake\n\nmessage"
            return "true" if args == ("rev-parse", "--is-inside-work-tree") else ""
        with patch.object(attribution, "_git", side_effect=metadata):
            self.assertEqual(attribution._vcs(self.repo)["signature"], "unchecked")
        self.assertFalse(any("verify-commit" in args or "--format=%G?" in args for args in calls))


if __name__ == "__main__":
    unittest.main()

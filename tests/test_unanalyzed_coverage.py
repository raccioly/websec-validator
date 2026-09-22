"""A scan that analyzed nothing must never read as a clean result.

The regression these pin: `SOURCE_EXT` was written as `CODE_EXT | {...}` whose members CODE_EXT
later absorbed entirely except `.scala`, so the walker's "unsupported source" arm was reachable
for exactly one language. A deliberately vulnerable Elixir application therefore produced
`unsupported: []`, `gaps: []`, `execution_complete: true` and the headline
"REQUESTED CHECKS COMPLETED — 0 files read" — confident, wrong, and silent.

The invariant tests below fail if any future edit re-couples the two sets, which is the specific
way this broke the first time.

"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator import coverage
from websec_validator.extractors import base as ebase
from websec_validator.extractors.base import (CODE_EXT, SOURCE_EXT, UNANALYZED_SOURCE_EXT,
                                              UNANALYZED_LANG, RepoContext, unanalyzed_languages)

VULNERABLE_ELIXIR = '''
defmodule MyAppWeb.UserController do
  @secret_key "EXAMPLE-NOT-A-REAL-CREDENTIAL"
  def show(conn, %{"id" => id}) do
    Ecto.Adapters.SQL.query(MyApp.Repo, "SELECT * FROM users WHERE id = #{id}", [])
  end
  def export(conn, %{"filename" => f}) do
    System.cmd("sh", ["-c", "tar czf /tmp/out.tgz #{f}"])
  end
end
'''


class ExtensionSetInvariantTests(unittest.TestCase):
    """The shape of the bug, pinned so it cannot silently return."""

    def test_unanalyzed_set_is_disjoint_from_code_ext(self):
        overlap = CODE_EXT & UNANALYZED_SOURCE_EXT
        self.assertEqual(overlap, set(),
                         f"a suffix cannot be both analysable and unanalysable: {sorted(overlap)}")

    def test_source_ext_is_a_strict_superset_covering_many_languages(self):
        """The original defect was this difference collapsing to a single extension."""
        difference = SOURCE_EXT - CODE_EXT
        self.assertEqual(difference, UNANALYZED_SOURCE_EXT)
        self.assertGreater(len(difference), 20,
                           "the unsupported-source signal is near-dead; it must cover real languages")
        for suffix in (".ex", ".exs", ".erl", ".clj", ".scala", ".lua", ".pl"):
            self.assertIn(suffix, difference)

    def test_every_unanalyzed_suffix_has_a_human_readable_language(self):
        unnamed = UNANALYZED_SOURCE_EXT - set(UNANALYZED_LANG)
        self.assertEqual(unnamed, set(), f"a gap cannot name these suffixes: {sorted(unnamed)}")

    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-008
    def test_no_unanalyzed_suffix_is_actually_read_by_an_explicit_glob(self):
        """Absent from CODE_EXT does NOT mean unanalysed — extractors also glob by name.

        `.sql` is the live example: `schemas.py` and `stack.py` glob `**/*.sql` for CREATE TABLE
        and RLS-policy analysis, so calling it unanalysed would put a FALSE statement into the
        coverage manifest. Caught here by reading the extractor sources rather than by memory,
        so a new glob for a currently-unanalysed suffix fails this test instead of shipping a lie.
        """
        import re
        globbed = set()
        for source in (Path(ebase.__file__).parent).glob("*.py"):
            for pattern in re.findall(r'glob\(\s*"([^"]+)"', source.read_text()):
                suffix = Path(pattern).suffix.lower()
                if suffix and "*" not in suffix:
                    globbed.add(suffix)
        self.assertIn(".sql", globbed, "sanity: the scanner should find the known .sql globs")
        conflict = UNANALYZED_SOURCE_EXT & globbed
        self.assertEqual(conflict, set(),
                         f"these suffixes ARE read by an explicit glob and must not be reported "
                         f"as having no analyzer: {sorted(conflict)}")

    def test_language_counts_are_grouped_and_ordered_by_volume(self):
        got = unanalyzed_languages(["a.ex", "b.ex", "c.exs", "d.clj"])
        self.assertEqual(got, {"elixir": 3, "clojure": 1})
        self.assertEqual(list(got), ["elixir", "clojure"])

    def test_unknown_and_non_source_suffixes_are_not_counted(self):
        self.assertEqual(unanalyzed_languages(["README.md", "data.json", "app.py", "x.bin"]), {})


class _Repo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, name, text=""):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def coverage_for(self):
        ctx = RepoContext(self.root)
        list(ctx.iter_code())   # the walk populates the counters coverage reads
        return coverage.from_context(ctx, {})


class UnanalyzedSourceCoverageTests(_Repo):
    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-007
    def test_vulnerable_elixir_app_is_reported_as_unanalyzed_not_clean(self):
        self.write("mix.exs", "defmodule M do end")
        self.write("lib/user_controller.ex", VULNERABLE_ELIXIR)
        cov = self.coverage_for()
        files = cov["files"]
        self.assertEqual(files["scanned"], 0)
        self.assertEqual(len(files["unsupported"]), 2, "both .ex/.exs files must be listed")
        self.assertEqual(files["unanalyzed_languages"], {"elixir": 2})
        self.assertTrue(files["no_analyzable_source"])
        kinds = {g["kind"] for g in cov["gaps"]}
        self.assertIn("unsupported_source", kinds)
        self.assertIn("language_without_analyzer", kinds)

    def test_the_gaps_are_scope_limits_not_execution_failures(self):
        """Nothing failed to run — so execution_complete must stay true and the flags stay honest."""
        self.write("lib/a.ex", VULNERABLE_ELIXIR)
        cov = self.coverage_for()
        self.assertTrue(cov["execution_complete"])
        self.assertFalse(cov["protection_complete"])
        for gap in cov["gaps"]:
            self.assertFalse(gap["execution"], f"{gap['kind']} must not claim execution loss")
        self.assertEqual(coverage.execution_errors(cov), [])

    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-012
    def test_the_gap_names_the_language_and_denies_a_clean_reading(self):
        self.write("lib/a.ex", "x")
        gap = next(g for g in self.coverage_for()["gaps"] if g["kind"] == "language_without_analyzer")
        self.assertIn("elixir", gap["detail"])
        self.assertIn("not a clean result", gap["detail"])

    def test_analysable_repository_raises_no_language_gap(self):
        self.write("app.py", "import os\n")
        cov = self.coverage_for()
        self.assertFalse(cov["files"]["no_analyzable_source"])
        self.assertEqual(cov["files"]["unanalyzed_languages"], {})
        self.assertNotIn("language_without_analyzer", {g["kind"] for g in cov["gaps"]})

    def test_docs_and_config_only_repository_is_not_flagged_as_a_language_gap(self):
        """The signal must stay about SOURCE, or it becomes noise and gets ignored."""
        for name in ("README.md", "config.json", "ci.yml", "notes.txt", "data.csv"):
            self.write(name, "x")
        cov = self.coverage_for()
        self.assertEqual(cov["files"]["unanalyzed_languages"], {})
        self.assertFalse(cov["files"]["no_analyzable_source"])
        self.assertNotIn("language_without_analyzer", {g["kind"] for g in cov["gaps"]})

    def test_mixed_repository_reports_the_gap_without_claiming_nothing_was_analyzed(self):
        self.write("app.py", "import os\n")
        self.write("lib/worker.ex", VULNERABLE_ELIXIR)
        cov = self.coverage_for()
        self.assertEqual(cov["files"]["scanned"], 1)
        self.assertFalse(cov["files"]["no_analyzable_source"], "python WAS analysed")
        self.assertEqual(cov["files"]["unanalyzed_languages"], {"elixir": 1})
        self.assertIn("language_without_analyzer", {g["kind"] for g in cov["gaps"]})

    def test_empty_repository_is_not_flagged(self):
        cov = self.coverage_for()
        self.assertFalse(cov["files"]["no_analyzable_source"])


class HeadlineTests(_Repo):
    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#SC-005
    def test_headline_leads_with_the_limit_not_with_completion(self):
        self.write("lib/a.ex", VULNERABLE_ELIXIR)
        facts = {"coverage": self.coverage_for()}
        rendered = coverage.render_md(facts)
        self.assertIn("NO ANALYZABLE SOURCE", rendered)
        self.assertNotIn("REQUESTED CHECKS COMPLETED", rendered)
        self.assertIn("NOT CHECKED, not secure", rendered)
        self.assertIn("elixir", rendered)

    def test_analysable_repository_keeps_the_original_headline(self):
        self.write("app.py", "import os\n")
        rendered = coverage.render_md({"coverage": self.coverage_for()})
        self.assertIn("REQUESTED CHECKS COMPLETED", rendered)
        self.assertNotIn("NO ANALYZABLE SOURCE", rendered)

    def test_mixed_repository_keeps_completion_but_discloses_the_partial_limit(self):
        self.write("app.py", "import os\n")
        self.write("lib/a.ex", VULNERABLE_ELIXIR)
        rendered = coverage.render_md({"coverage": self.coverage_for()})
        self.assertIn("REQUESTED CHECKS COMPLETED", rendered)
        self.assertIn("Partially outside coverage", rendered)
        self.assertIn("elixir", rendered)


class ThinLanguageTests(unittest.TestCase):
    """A language CODE_EXT accepts but that has no injection/secret/authz rule."""

    def test_swift_is_thin_because_no_profile_gives_it_a_sink_check(self):
        cov = {"service_inventory": [{"languages": ["swift"]}]}
        self.assertEqual(coverage.thin_languages(cov), {"swift"})

    def test_languages_with_real_sink_rules_are_not_thin(self):
        for lang in ("java", "csharp", "go", "ruby", "php"):
            with self.subTest(lang=lang):
                self.assertEqual(coverage.thin_languages({"service_inventory": [{"languages": [lang]}]}), set())

    def test_first_class_languages_are_not_thin(self):
        """Python/Node/TS depth lives in the main extractors, not in a named profile."""
        cov = {"service_inventory": [{"languages": ["python", "node", "typescript"]}]}
        self.assertEqual(coverage.thin_languages(cov), set())

    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#SC-009
    def test_gap_is_added_for_a_thin_language_and_is_a_scope_limit(self):
        facts = {"coverage": {"execution_complete": True, "gaps": [], "scanners": {},
                              "service_inventory": [{"languages": ["swift"]}]},
                 "stack": {"profiles": {"profiles": [], "service_inventory": [{"languages": ["swift"]}],
                                        "limitations": [], "errors": []}}}
        coverage.add_profiles(facts)
        gap = next(g for g in facts["coverage"]["gaps"] if g["kind"] == "thin_language_coverage")
        self.assertFalse(gap["execution"])
        self.assertIn("swift", gap["detail"])
        self.assertIn("not evidence of absence", gap["detail"])
        self.assertTrue(facts["coverage"]["execution_complete"])

    def test_no_thin_gap_for_an_ordinary_python_project(self):
        facts = {"coverage": {"execution_complete": True, "gaps": [], "scanners": {}},
                 "stack": {"profiles": {"profiles": [], "service_inventory": [{"languages": ["python"]}],
                                        "limitations": [], "errors": []}}}
        coverage.add_profiles(facts)
        self.assertNotIn("thin_language_coverage", {g["kind"] for g in facts["coverage"]["gaps"]})


class InventoryAttributionTests(unittest.TestCase):
    """An empty route table must not blame route discovery for a language we never read."""

    def test_empty_routes_name_the_missing_analyzer_when_known(self):
        from websec_validator import inventory
        md = inventory.render_md({"endpoints": []},
                                 coverage={"files": {"unanalyzed_languages": {"elixir": 2}}})
        self.assertIn("no analyzer for elixir", md)
        self.assertNotIn("route discovery failed", md)

    def test_empty_routes_keep_the_original_wording_without_a_language_gap(self):
        from websec_validator import inventory
        md = inventory.render_md({"endpoints": []}, coverage={"files": {}})
        self.assertIn("route discovery failed", md)

    def test_signature_stays_backwards_compatible(self):
        from websec_validator import inventory
        self.assertIn("route discovery failed", inventory.render_md({"endpoints": []}))


if __name__ == "__main__":
    unittest.main()

"""Unit tests for the bot-PR classifier.

Fixtures marked REAL are copied verbatim from this repo's own open pull requests — the classifier
was wrong twice in ways only real payloads exposed (a blanket .github/ hold silently disabled
dependabot, whose whole job is editing .github/workflows/; and the 27 duplicate test_hooks PRs all
read as "purely additive" and would have merged each other into conflict).

Run:  python -m unittest discover -s .github/scripts -p 'test_*.py'
"""

import unittest

import triage


def f(name, status="modified", additions=1, deletions=0):
    return {"filename": name, "status": status, "additions": additions, "deletions": deletions}


class ParseBumpTests(unittest.TestCase):
    def test_real_dependabot_titles(self):
        cases = [
            ("chore(deps): Bump pypa/gh-action-pypi-publish from 1.14.0 to 1.14.2", "patch"),
            ("chore(deps): Bump actions/checkout from 7.0.0 to 7.0.1", "patch"),
            # REAL: dependabot writes bare major tags for actions. A 3-component parse drops this,
            # and it is precisely the case that must never auto-merge.
            ("chore(deps): Bump actions/setup-python from 6 to 7", "major"),
        ]
        for title, want in cases:
            with self.subTest(title=title):
                self.assertEqual(triage.parse_bump(title)[0], want)

    def test_minor_and_v_prefix_and_prerelease(self):
        self.assertEqual(triage.parse_bump("Bump x from 1.2.0 to 1.3.0")[0], "minor")
        self.assertEqual(triage.parse_bump("Bump x from v1.0.0 to v2.0.0")[0], "major")
        self.assertEqual(triage.parse_bump("Bump x from 1.0.0 to 1.0.1-rc1")[0], "patch")

    def test_unparseable_returns_none(self):
        self.assertEqual(triage.parse_bump("chore: tidy up")[0], None)
        self.assertEqual(triage.parse_bump("Bump x from latest to newest")[0], None)


class DependabotVerdictTests(unittest.TestCase):
    def test_real_patch_bump_merges(self):
        v, why = triage.verdict("app/dependabot", "Bump actions/checkout from 7.0.0 to 7.0.1",
                                [f(".github/workflows/ci.yml", additions=1, deletions=1),
                                 f(".github/workflows/publish.yml", additions=1, deletions=1)])
        self.assertEqual(v, "merge", why)

    def test_real_major_bump_holds(self):
        v, why = triage.verdict("app/dependabot", "Bump actions/setup-python from 6 to 7",
                                [f(".github/workflows/ci.yml", additions=1, deletions=1)])
        self.assertEqual(v, "hold")
        self.assertIn("major", why)

    def test_not_a_pure_pin_swap_holds(self):
        # A "bump" that adds net lines is editing workflow logic, not swapping a pin.
        v, why = triage.verdict("app/dependabot", "Bump actions/checkout from 7.0.0 to 7.0.1",
                                [f(".github/workflows/ci.yml", additions=30, deletions=1)])
        self.assertEqual(v, "hold")
        self.assertIn("pure pin swap", why)

    def test_path_outside_its_ecosystems_holds(self):
        v, why = triage.verdict("app/dependabot", "Bump x from 1.0.0 to 1.0.1",
                                [f("src/websec_validator/cli.py", additions=1, deletions=1)])
        self.assertEqual(v, "hold")
        self.assertIn("outside", why)


class JulesVerdictTests(unittest.TestCase):
    def test_known_noise_outranks_additive(self):
        # REAL shape of all 27 duplicates: one added line, nothing deleted. Reads as "purely
        # additive" and must still be held for the triage workflow to close.
        v, why = triage.verdict("app/google-labs-jules", "Fix flaky git hooks test",
                                [f("tests/test_hooks.py", additions=1)])
        self.assertEqual(v, "hold")
        self.assertIn("known-noise", why)

    def test_additive_test_only_merges(self):
        v, why = triage.verdict("app/google-labs-jules", "test: cover os.popen sink",
                                [f("tests/test_pentest_regressions.py", additions=12)])
        self.assertEqual(v, "merge", why)

    def test_test_edit_that_deletes_lines_holds(self):
        v, why = triage.verdict("app/google-labs-jules", "test: relax assertion",
                                [f("tests/test_pentest_regressions.py", additions=2, deletions=3)])
        self.assertEqual(v, "hold")
        self.assertIn("detection contract", why)

    def test_deleted_test_file_holds(self):
        v, why = triage.verdict("app/google-labs-jules", "chore: drop test",
                                [f("tests/test_recon.py", status="removed", additions=0, deletions=90)])
        self.assertEqual(v, "hold")

    def test_docs_only_merges(self):
        v, _ = triage.verdict("app/google-labs-jules", "docs: sync counts",
                              [f("README.md", additions=3, deletions=2), f("docs/METHODOLOGY.md")])
        self.assertEqual(v, "merge")

    def test_instruction_files_are_config_not_docs(self):
        for name in ("AGENTS.md", "CLAUDE.md"):
            with self.subTest(name=name):
                v, why = triage.verdict("app/google-labs-jules", "docs: tweak", [f(name)])
                self.assertEqual(v, "hold")

    def test_source_always_holds(self):
        v, why = triage.verdict("app/google-labs-jules", "fix: regex",
                                [f("src/websec_validator/extractors/surface.py", additions=1)])
        self.assertEqual(v, "hold")
        self.assertIn("protected path", why)

    def test_jules_may_not_touch_the_automation(self):
        v, why = triage.verdict("app/google-labs-jules", "ci: tweak",
                                [f(".github/workflows/ci.yml", additions=1)])
        self.assertEqual(v, "hold")

    def test_mixed_tests_and_source_holds(self):
        v, _ = triage.verdict("app/google-labs-jules", "fix + test",
                              [f("tests/test_x.py"), f("src/websec_validator/cli.py")])
        self.assertEqual(v, "hold")

    def test_binary_payload_holds(self):
        # REAL: PR #73 carried noir_1.3.0_amd64.deb plus 13 scratch test_repro*.py files.
        v, why = triage.verdict("app/google-labs-jules", "fix sqli",
                                [f("tests/test_x.py"), f("noir_1.3.0_amd64.deb")])
        self.assertEqual(v, "hold")

    def test_too_many_files_holds(self):
        v, why = triage.verdict("app/google-labs-jules", "big",
                                [f(f"tests/test_{i}.py") for i in range(triage.MAX_FILES + 1)])
        self.assertEqual(v, "hold")
        self.assertIn("limit", why)

    def test_unknown_author_gets_the_conservative_path(self):
        v, _ = triage.verdict("some-human", "fix", [f("src/websec_validator/cli.py")])
        self.assertEqual(v, "hold")


class DuplicateDetectionTests(unittest.TestCase):
    def test_changelog_churn_does_not_distinguish_two_prs(self):
        self.assertEqual(triage.dup_key(["tests/test_hooks.py", "CHANGELOG.md"]),
                         triage.dup_key(["tests/test_hooks.py"]))

    def test_differently_worded_same_change_groups_together(self):
        # REAL titles from #94 and #74 — wildly different wording, identical change.
        a = triage.dup_key(["tests/test_hooks.py"])
        b = triage.dup_key(["CHANGELOG.md", "tests/test_hooks.py"])
        self.assertEqual(a, b)

    def test_different_changes_do_not_group(self):
        self.assertNotEqual(triage.dup_key(["tests/test_hooks.py"]),
                            triage.dup_key(["tests/test_recon.py"]))

    def test_known_noise_only_matches_the_exact_class(self):
        self.assertIsNotNone(triage.is_known_noise(["tests/test_hooks.py", "CHANGELOG.md"]))
        # test_hooks bundled with a real source fix is NOT noise — those carry independent value.
        self.assertIsNone(triage.is_known_noise(
            ["tests/test_hooks.py", "src/websec_validator/extractors/surface.py"]))


if __name__ == "__main__":
    unittest.main()

"""Unit tests for the release train's version arithmetic."""

import unittest

import release


class BumpLevelTests(unittest.TestCase):
    def test_feat_is_minor(self):
        self.assertEqual(release.bump_level(["fix: x", "feat(recon): y"]), "minor")

    def test_breaking_is_minor_not_major_on_a_0x_project(self):
        # Bumping MAJOR would assert 1.0 on the project's behalf — a product decision, not a cron
        # job's. On 0.x, a break moves MINOR.
        self.assertEqual(release.bump_level(["fix!: drop flag"]), "minor")
        self.assertEqual(release.bump_level(["chore: x\n\nBREAKING CHANGE: y"]), "minor")

    def test_fixes_only_is_patch(self):
        self.assertEqual(release.bump_level(["fix: a", "docs: b", "ci: c"]), "patch")

    def test_no_commits_is_patch(self):
        self.assertEqual(release.bump_level([]), "patch")


class NextVersionTests(unittest.TestCase):
    def test_patch_and_minor(self):
        self.assertEqual(release.next_version("0.12.0", "patch"), "0.12.1")
        self.assertEqual(release.next_version("0.12.3", "minor"), "0.13.0")

    def test_minor_resets_patch(self):
        self.assertEqual(release.next_version("1.4.9", "minor"), "1.5.0")

    def test_parse_rejects_junk(self):
        with self.assertRaises(ValueError):
            release.parse("not-a-version")
        self.assertEqual(release.parse("v1.2.3"), (1, 2, 3))

    def test_ordering_is_numeric_not_lexicographic(self):
        # "0.9.0" > "0.12.0" as strings; the tuple comparison the propose path relies on must not.
        self.assertLess(release.parse("0.9.0"), release.parse("0.12.0"))


class ReleaseSubjectTests(unittest.TestCase):
    def test_recognises_the_release_commit(self):
        self.assertEqual(release.release_version_from_subject("release: v0.13.0"), "0.13.0")
        self.assertEqual(release.release_version_from_subject("release: 0.13.0 (#123)"), "0.13.0")

    def test_ignores_everything_else(self):
        # Keying the tag on this subject — rather than on a version mismatch — is what stops a
        # hand-edited or already-bumped pyproject from triggering a surprise publish to PyPI.
        for s in ("fix: thing", "release notes for v1.0.0", "chore: prep release", "feat: v2 api"):
            with self.subTest(s=s):
                self.assertIsNone(release.release_version_from_subject(s))


if __name__ == "__main__":
    unittest.main()


class PrepareTests(unittest.TestCase):
    def setUp(self):
        import release_prepare
        self.rp = release_prepare

    def test_sets_only_the_first_version_line(self):
        src = '[project]\nname = "x"\nversion = "0.12.0"\n\n[tool.other]\nversion = "9.9.9"\n'
        out = self.rp.set_pyproject_version(src, "0.13.0")
        self.assertIn('version = "0.13.0"', out)
        self.assertIn('version = "9.9.9"', out)   # unrelated pin untouched

    def test_missing_version_line_fails_loudly(self):
        with self.assertRaises(SystemExit):
            self.rp.set_pyproject_version('[project]\nname = "x"\n', "0.13.0")

    def test_closes_the_unreleased_section(self):
        src = "# Changelog\n\n## [Unreleased]\n\n### Fixed\n- a thing\n\n## [0.11.0] — 2026-01-01\n"
        out = self.rp.close_changelog(src, "0.12.0", "2026-09-11")
        self.assertIn("## [Unreleased]\n\n## [0.12.0] — 2026-09-11", out)
        self.assertIn("- a thing", out)

    def test_closing_twice_is_a_no_op(self):
        src = "# Changelog\n\n## [Unreleased]\n\n## [0.12.0] — 2026-09-11\n"
        self.assertEqual(self.rp.close_changelog(src, "0.12.0", "2026-09-12"), src)

    def test_missing_unreleased_fails_loudly(self):
        with self.assertRaises(SystemExit):
            self.rp.close_changelog("# Changelog\n", "0.12.0", "2026-09-11")


class LinkRefTests(unittest.TestCase):
    def setUp(self):
        import release_prepare
        self.rp = release_prepare
        self.base = "https://github.com/raccioly/websec-validator"

    def _refs(self, prev="v0.12.0"):
        return f"[Unreleased]: {self.base}/compare/{prev}...HEAD\n[0.11.0]: {self.base}/compare/v0.10.0...v0.11.0\n"

    def test_repoints_unreleased_and_adds_this_version(self):
        out = self.rp.update_link_refs(self._refs(), "0.13.0", "")
        self.assertIn(f"[Unreleased]: {self.base}/compare/v0.13.0...HEAD", out)
        self.assertIn(f"[0.13.0]: {self.base}/compare/v0.12.0...v0.13.0", out)
        self.assertIn("[0.11.0]:", out)          # existing refs preserved

    def test_is_idempotent(self):
        once = self.rp.update_link_refs(self._refs(), "0.13.0", "")
        self.assertEqual(self.rp.update_link_refs(once, "0.13.0", ""), once)

    def test_changelog_without_link_refs_is_left_alone(self):
        src = "# Changelog\n\n## [Unreleased]\n"
        self.assertEqual(self.rp.update_link_refs(src, "0.13.0", ""), src)

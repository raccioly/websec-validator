"""Diff scoping — changed files + exact hunk line ranges (the line-in-diff validation LLM reviewers skip)."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator import diffscope  # noqa: E402


def _repo():
    d = Path(tempfile.mkdtemp())
    subprocess.run(["git", "init", "-q", str(d)], check=True)
    for k, v in (("user.email", "t@t"), ("user.name", "t")):
        subprocess.run(["git", "-C", str(d), "config", k, v], check=True)
    return d


def _commit(d, msg="c"):
    subprocess.run(["git", "-C", str(d), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(d), "commit", "-qm", msg], check=True)


@unittest.skipUnless(shutil.which("git"), "git required")
class ComputeTests(unittest.TestCase):
    def test_changed_files_and_added_hunk_ranges(self):
        d = _repo()
        (d / "a.txt").write_text("l1\nl2\nl3\n")
        _commit(d, "base")
        (d / "a.txt").write_text("l1\nl2\nl3\nNEW4\nNEW5\n")   # append 2 lines
        (d / "b.txt").write_text("brand new\n")
        _commit(d, "change")
        scope = diffscope.compute(d, "HEAD~1")
        self.assertIsNone(scope["error"])
        self.assertEqual(set(scope["files"]), {"a.txt", "b.txt"})
        self.assertEqual(scope["files"]["a.txt"], [(4, 5)])     # exactly the appended lines
        self.assertEqual(scope["files"]["b.txt"], [(1, 1)])

    def test_pure_deletion_contributes_no_added_lines(self):
        d = _repo()
        (d / "a.txt").write_text("l1\nl2\nl3\n")
        _commit(d, "base")
        (d / "a.txt").write_text("l1\n")                        # delete 2 lines, add none
        _commit(d, "delete")
        scope = diffscope.compute(d, "HEAD~1")
        self.assertEqual(scope["files"].get("a.txt"), [])       # file changed, but no added ranges

    def test_accepts_two_and_three_dot_ref_forms(self):
        d = _repo()
        (d / "a.txt").write_text("x\n")
        _commit(d, "base")
        (d / "a.txt").write_text("x\ny\n")
        _commit(d, "change")
        for ref in ("HEAD~1", "HEAD~1..HEAD", "HEAD~1...HEAD"):
            self.assertEqual(set(diffscope.compute(d, ref)["files"]), {"a.txt"}, ref)

    def test_unknown_ref_is_a_clean_error_not_an_exception(self):
        d = _repo()
        (d / "a.txt").write_text("x\n")
        _commit(d)
        scope = diffscope.compute(d, "nope-not-a-ref")
        self.assertIn("unknown git ref", scope["error"])
        self.assertEqual(scope["files"], {})

    def test_non_git_directory_is_a_clean_error(self):
        d = Path(tempfile.mkdtemp())
        scope = diffscope.compute(d, "main")
        self.assertIsNotNone(scope["error"])
        self.assertEqual(scope["files"], {})

    def test_empty_ref_rejected(self):
        self.assertIn("empty", diffscope.compute(Path(tempfile.mkdtemp()), "  ")["error"])


class ScopingTests(unittest.TestCase):
    SCOPE = {"base": "main", "error": None, "files": {"src/new.js": [(10, 12), (20, 20)]}}

    def test_in_scope_file_matching(self):
        self.assertEqual(diffscope.in_scope("src/new.js", self.SCOPE), "in-changed-file")
        self.assertEqual(diffscope.in_scope("src/old.js", self.SCOPE), "untouched")
        self.assertEqual(diffscope.in_scope("", self.SCOPE), "untouched")

    def test_in_scope_strips_line_suffix_and_leading_dotslash(self):
        self.assertEqual(diffscope.in_scope("src/new.js:42", self.SCOPE), "in-changed-file")
        self.assertEqual(diffscope.in_scope("./src/new.js", self.SCOPE), "in-changed-file")

    def test_line_in_hunk_validates_exact_ranges(self):
        self.assertTrue(diffscope.line_in_hunk("src/new.js", 11, self.SCOPE))
        self.assertTrue(diffscope.line_in_hunk("src/new.js", 20, self.SCOPE))
        self.assertFalse(diffscope.line_in_hunk("src/new.js", 13, self.SCOPE))   # between hunks
        self.assertFalse(diffscope.line_in_hunk("src/other.js", 11, self.SCOPE))

    def test_annotate_tags_every_finding_without_dropping_any(self):
        ledger = {"findings": [{"location": "src/new.js"}, {"location": "src/old.js"},
                               {"location": "(response headers)"}]}
        counts = diffscope.annotate(ledger, self.SCOPE)
        self.assertEqual(len(ledger["findings"]), 3)            # additive: nothing dropped
        self.assertEqual([f["diff_state"] for f in ledger["findings"]],
                         ["in-changed-file", "untouched", "untouched"])
        self.assertEqual(counts, {"in_changed_file": 1, "untouched": 2, "changed_files": 1})

    def test_render_reports_error_and_empty_states(self):
        self.assertIn("UNSCOPED", diffscope.render_md({"error": "not a git repository"}, {}))
        self.assertIn("No files changed",
                      diffscope.render_md({"base": "main", "error": None, "files": {}}, {}))
        md = diffscope.render_md(self.SCOPE, {"in_changed_file": 1, "untouched": 0, "changed_files": 1})
        self.assertIn("src/new.js", md)
        self.assertIn("10–12", md)


if __name__ == "__main__":
    unittest.main()

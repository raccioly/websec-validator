"""Tests for the derived test floor.

The floor exists to catch coverage removal, so these mostly assert that it FAILS when it
should. A floor that only ever passes is the bug it is meant to prevent.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_floor  # noqa: E402


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          capture_output=True, text=True)


def _repo(root: Path) -> Path:
    """A hermetic fixture repo — same pinning as tests/test_gate_and_bypass_record.py.

    An opinionated global config otherwise reaches in: commit.gpgsign=true fails the
    commits with no secret key, autocrlf rewrites line endings, and a global
    core.hooksPath runs someone else's hooks inside our fixture.
    """
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q", ".")
    for key, value in (("user.email", "d@e.com"), ("user.name", "D"), ("commit.gpgsign", "false"),
                       ("core.autocrlf", "false"), ("core.hooksPath", ".git/hooks")):
        _git(root, "config", key, value)
    return root


def _suite_file(root: Path, name: str, count: int) -> Path:
    body = ["import unittest", "", f"class {name.title().replace('_', '')}(unittest.TestCase):"]
    body += [f"    def test_{i}(self):\n        self.assertTrue(True)" for i in range(count)]
    path = root / "tests" / f"{name}.py"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(body) + "\n", encoding="utf-8")
    return path


def _commit(root: Path, message: str) -> None:
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", message)


def _run(root: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(Path(test_floor.__file__).resolve()),
                           "--repo", str(root), "--base-ref", "base", *extra],
                          capture_output=True, text=True)


class CountTests(unittest.TestCase):
    """In-process counting. `count_tests` is the primitive; production always calls it
    through a subprocess, so these tests have to undo the sys.modules pollution that the
    subprocess isolation normally hides — two fixtures with the same module names in
    different temp dirs otherwise make unittest reject the second."""

    def setUp(self):
        self._before = set(sys.modules)
        self.addCleanup(self._purge)

    def _purge(self):
        for name in set(sys.modules) - self._before:
            sys.modules.pop(name, None)

    def test_counts_loaded_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _suite_file(root, "test_alpha", 3)
            _suite_file(root, "test_beta", 4)
            self.assertEqual(test_floor.count_tests(root / "tests"), 7)

    def test_unimportable_module_raises_instead_of_counting_one(self):
        # The whole point: a 50-test file that stops importing becomes a single
        # _FailedTest. Counting it as 1 would silently lower the bar on the base side.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _suite_file(root, "test_alpha", 50)
            (root / "tests" / "test_alpha.py").write_text(
                "import a_module_that_does_not_exist_xyz\n", encoding="utf-8")
            with self.assertRaises(test_floor.DiscoveryError) as caught:
                test_floor.count_tests(root / "tests")
            self.assertIn("not trustworthy", str(caught.exception))


class TrailerTests(unittest.TestCase):
    def test_reads_only_a_real_trailer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _repo(Path(tmp))
            _suite_file(root, "test_alpha", 1)
            _commit(root, "plain subject with no trailer")
            self.assertIsNone(test_floor.removal_reason(root))
            _suite_file(root, "test_beta", 1)
            _commit(root, "drop dead tests\n\nTest-Removal: the feature was deleted in 0.9\n")
            self.assertEqual(test_floor.removal_reason(root), "the feature was deleted in 0.9")


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = _repo(Path(self.temp.name) / "repo")
        _suite_file(self.root, "test_alpha", 5)
        _suite_file(self.root, "test_beta", 5)
        _commit(self.root, "baseline")
        _git(self.root, "branch", "base")

    def test_adding_tests_passes(self):
        _suite_file(self.root, "test_gamma", 3)
        _commit(self.root, "add tests")
        result = _run(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("test_count=13", result.stdout)
        self.assertIn("test_floor=10", result.stdout)

    def test_equal_count_passes(self):
        self.assertEqual(_run(self.root).returncode, 0)

    def test_removing_tests_fails(self):
        (self.root / "tests" / "test_beta.py").unlink()
        _commit(self.root, "remove a suite")
        result = _run(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("fell from 10 to 5", result.stdout)
        self.assertIn("Test-Removal", result.stdout)

    def test_neutering_a_suite_in_place_fails(self):
        # The subtler removal: the file stays, the cases go.
        _suite_file(self.root, "test_beta", 1)
        _commit(self.root, "gut the suite but keep the file")
        result = _run(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("fell from 10 to 6", result.stdout)

    def test_declared_removal_is_allowed_and_announced(self):
        (self.root / "tests" / "test_beta.py").unlink()
        _commit(self.root, "drop obsolete suite\n\nTest-Removal: covered feature was removed\n")
        result = _run(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("allowed by Test-Removal", result.stdout)

    def test_unimportable_head_fails_rather_than_reporting_a_tiny_count(self):
        (self.root / "tests" / "test_beta.py").write_text("import nope_xyz\n", encoding="utf-8")
        _commit(self.root, "break an import")
        result = _run(self.root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("discovery failed", result.stdout + result.stderr)

    def test_missing_base_warns_without_failing(self):
        # A base that cannot be resolved is not evidence of removal; the suite still runs.
        result = subprocess.run(
            [sys.executable, str(Path(test_floor.__file__).resolve()), "--repo", str(self.root),
             "--base-ref", "no-such-ref"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("floor not enforced", result.stdout)

    def test_base_worktree_is_removed_and_head_is_untouched(self):
        before = _git(self.root, "worktree", "list").stdout
        head_before = _git(self.root, "rev-parse", "HEAD").stdout
        _run(self.root)
        self.assertEqual(_git(self.root, "worktree", "list").stdout, before)
        self.assertEqual(_git(self.root, "rev-parse", "HEAD").stdout, head_before)
        self.assertEqual(_git(self.root, "status", "--porcelain").stdout, "")


if __name__ == "__main__":
    unittest.main()

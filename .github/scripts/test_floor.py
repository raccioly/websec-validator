#!/usr/bin/env python3
"""Derive the test floor from the base commit instead of a checked-in constant.

The floor guards one failure mode: a change that makes CI pass by REMOVING coverage.
A hardcoded `MIN_TESTS` did that, but it is a single counter every branch adding tests
must edit, so two branches that each add N tests both bump it by N and merge cleanly
while being jointly wrong. That happened: two branches each added 2 tests, both moved
1241 -> 1243, the rebase was clean because the values matched, and the floor ended two
below the real suite. No conflict, no error, two tests deletable unnoticed.

So there is no stored number here. The baseline is counted from the base commit at CI
time, which makes it impossible for two branches to disagree about it.

Counting uses the unittest LOADER, not a run: discovery imports the test modules but
executes no tests, so the baseline costs an import pass rather than a second suite.
Both sides are counted the same way so the comparison is apples-to-apples.

The trap this must not fall into: a module that fails to import does not vanish from
discovery, it becomes a single `_FailedTest`. A 50-test file that stops importing would
read as 1 test. On the BASE side that silently lowers the bar; on the HEAD side it looks
like catastrophic deletion. Either way the number is a lie, so any discovery error is a
hard failure rather than a count.

Each tree is counted in its own subprocess. Both trees hold modules with identical names,
so counting them in one process makes unittest reject the second ("incorrectly imported
from ... Is this module globally installed?") once the first has populated sys.modules.
Separate processes also keep any module-level side effects in the test files out of the
counter.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# A deliberate removal is legitimate; a silent one is not. This trailer on the HEAD
# commit allows the count to drop, and leaves the reason in the history where review
# can see it. It cannot be set by accident.
TRAILER = re.compile(r"^Test-Removal:\s*(?P<reason>\S.*)$", re.MULTILINE)


class DiscoveryError(RuntimeError):
    """Discovery produced an unloadable module, so no count from it is trustworthy."""


def _iter(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _iter(item)
        else:
            yield item


def count_tests(tests_dir: Path) -> int:
    """Load `tests_dir` and count test cases. Raises if anything failed to import.

    top_level_dir is the tests directory itself, matching how CI invokes the suite
    (`unittest discover -s tests`). `tests/` is not a package, so treating the repo
    root as the top level makes discovery fail outright.
    """
    loader = unittest.TestLoader()
    suite = loader.discover(str(tests_dir), top_level_dir=str(tests_dir))
    broken = [str(t) for t in _iter(suite) if type(t).__name__ == "_FailedTest"]
    # loader.errors is populated for discovery-level failures that never became tests.
    if broken or getattr(loader, "errors", None):
        raise DiscoveryError(
            "test discovery failed, so the count is not trustworthy: "
            + "; ".join(broken + [str(e).splitlines()[-1] for e in (loader.errors or [])][:5]))
    return suite.countTestCases()


def count_in_subprocess(tests_dir: Path) -> int:
    """Count `tests_dir` in a fresh interpreter. See the module docstring for why.

    PYTHONDONTWRITEBYTECODE: importing the modules would otherwise drop a `__pycache__`
    into the tree being measured. In the base worktree that is merely litter that
    `worktree remove --force` has to clear, but in the checkout it makes the working
    tree dirty — a measurement must not modify what it measures.
    """
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                             "--count-only", str(tests_dir)],
                            capture_output=True, text=True, env=env)
    if result.returncode != 0:
        raise DiscoveryError((result.stdout + result.stderr).strip().splitlines()[-1]
                             if (result.stdout + result.stderr).strip() else "counter failed")
    return int(result.stdout.strip())


def count_at_ref(repo: Path, ref: str, tests_subdir: str = "tests") -> int:
    """Count the suite as it exists at `ref`, via a throwaway detached worktree.

    A worktree rather than `git stash` or a checkout: the working tree may belong to a
    parallel session, and this must never mutate it.
    """
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp) / "base"
        subprocess.run(["git", "-C", str(repo), "worktree", "add", "--detach", "--quiet",
                        str(target), ref], check=True, capture_output=True, text=True)
        try:
            return count_in_subprocess(target / tests_subdir)
        finally:
            subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(target)],
                           check=False, capture_output=True)


def resolve_base(repo: Path, base_ref: str, head_ref: str = "HEAD") -> str | None:
    """Merge-base of head and base_ref; None when it cannot be determined."""
    for args in (["merge-base", head_ref, base_ref], ["rev-parse", f"{base_ref}^{{commit}}"]):
        result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    return None


def removal_reason(repo: Path, ref: str = "HEAD") -> str | None:
    result = subprocess.run(["git", "-C", str(repo), "log", "-1", "--format=%B", ref],
                            capture_output=True, text=True)
    if result.returncode != 0:
        return None
    found = TRAILER.search(result.stdout)
    return found.group("reason").strip() if found else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="repository root")
    parser.add_argument("--tests", default="tests", help="tests directory, relative to the root")
    parser.add_argument("--base-ref", help="ref to derive the floor from")
    parser.add_argument("--count-only", help="print the test count for this directory and exit")
    args = parser.parse_args(argv)

    if args.count_only:
        try:
            print(count_tests(Path(args.count_only)))
        except (DiscoveryError, ImportError) as error:
            print(f"discovery failed: {error}", file=sys.stderr)
            return 1
        return 0
    if not args.base_ref:
        parser.error("--base-ref is required unless --count-only is given")

    repo = Path(args.repo).resolve()
    try:
        head = count_in_subprocess(repo / args.tests)
    except DiscoveryError as error:
        print(f"::error::{error}")
        return 1

    base_sha = resolve_base(repo, args.base_ref)
    if base_sha is None:
        # A missing base is not evidence of removal. Say so and let the run proceed;
        # the suite still has to pass, it just has nothing to be compared against.
        print(f"::warning::no base commit for '{args.base_ref}' (shallow clone or first commit) "
              f"— floor not enforced this run; collected {head} tests")
        print(f"test_count={head}")
        return 0

    try:
        base = count_at_ref(repo, base_sha, args.tests)
    except (DiscoveryError, subprocess.CalledProcessError) as error:
        detail = error.stderr.strip() if isinstance(error, subprocess.CalledProcessError) else error
        print(f"::error::could not count tests at base {base_sha[:12]}: {detail}")
        return 1

    print(f"collected {head} tests; base {base_sha[:12]} has {base} (floor derived, not stored)")
    print(f"test_count={head}")
    print(f"test_floor={base}")

    if head >= base:
        return 0

    reason = removal_reason(repo)
    if reason:
        print(f"::notice::test count dropped {base} -> {head}, allowed by Test-Removal: {reason}")
        return 0
    print(f"::error::test count fell from {base} to {head} against {base_sha[:12]} — coverage was removed.")
    print("::error::Restore the tests. If the removal is deliberate, put a "
          "'Test-Removal: <reason>' trailer on the commit so the drop is reviewable.")
    return 1


if __name__ == "__main__":
    sys.exit(main())

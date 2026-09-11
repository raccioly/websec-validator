"""Version arithmetic for the weekly release train. Pure functions + a small CLI, so the bump
decision is unit-tested rather than improvised in YAML.

Release model:
  1. Weekly, if anything merged since the last tag, this proposes a version bump as a PULL REQUEST.
     Nothing publishes without a human merging it — PyPI releases are public and immutable.
  2. Merging that PR puts a `release: vX.Y.Z` commit on main, which is what the tag workflow keys on.

The tag is NOT created by a version mismatch alone. Keying on the release commit subject means a
version bumped by hand, or one already sitting un-tagged in the tree, never triggers a surprise
publish.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib

RELEASE_SUBJECT = re.compile(r"^release:\s*v?(\d+\.\d+\.\d+)\b")


def current_version(path="pyproject.toml") -> str:
    with open(path, "rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def parse(v: str) -> tuple[int, int, int]:
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)$", v.lstrip("v"))
    if not m:
        raise ValueError(f"not a semver: {v!r}")
    return tuple(int(x) for x in m.groups())  # type: ignore[return-value]


def bump_level(subjects) -> str:
    """'minor' if anything since the last tag adds a feature or breaks, else 'patch'.

    The project is 0.x, so a break moves the MINOR component — bumping major would assert 1.0 on the
    project's behalf, which is a product decision and not one a cron job should make.
    """
    for s in subjects:
        if "BREAKING CHANGE" in s or re.match(r"^\w+(\([^)]*\))?!:", s):
            return "minor"
        if re.match(r"^feat(\([^)]*\))?:", s, re.I):
            return "minor"
    return "patch"


def next_version(current: str, level: str) -> str:
    major, minor, patch = parse(current)
    if level == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def release_version_from_subject(subject: str) -> str | None:
    m = RELEASE_SUBJECT.match(subject.strip())
    return m.group(1) if m else None


def _git(*args) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout.strip()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["propose", "tag-version"])
    ap.add_argument("--force-level", choices=["patch", "minor"])
    args = ap.parse_args()

    if args.command == "tag-version":
        subject = _git("log", "-1", "--pretty=%s")
        ver = release_version_from_subject(subject)
        if not ver:
            print(f"head commit is not a release commit ({subject!r}) — nothing to tag")
            print("should_tag=false")
            return 0
        declared = current_version()
        if ver != declared:
            print(f"::error::release commit says v{ver} but pyproject declares {declared}")
            return 1
        existing = _git("tag", "--list", f"v{ver}")
        if existing:
            print(f"v{ver} already tagged — nothing to do")
            print("should_tag=false")
            return 0
        print(f"version={ver}")
        print("should_tag=true")
        return 0

    # propose
    try:
        last_tag = _git("describe", "--tags", "--abbrev=0")
    except subprocess.CalledProcessError:
        last_tag = ""
    rng = f"{last_tag}..HEAD" if last_tag else "HEAD"
    subjects = [s for s in _git("log", rng, "--pretty=%s").splitlines() if s.strip()]
    # A previous release PR that is still open would otherwise be proposed again every week.
    subjects = [s for s in subjects if not RELEASE_SUBJECT.match(s)]

    print(f"last_tag={last_tag or '(none)'}")
    print(f"commits_since_tag={len(subjects)}")
    if not subjects:
        print("should_release=false")
        return 0

    cur = current_version()
    level = args.force_level or bump_level(subjects)
    if last_tag and parse(cur) > parse(last_tag):
        # pyproject is already ahead of the newest tag: a previous cycle bumped the version but the
        # release never went out. Bumping again would silently skip that version number entirely
        # (0.12.0 sat un-tagged here while the naive arithmetic proposed 0.13.0). Ship what the tree
        # already declares instead.
        nxt, level = cur, "already-bumped"
    else:
        nxt = next_version(cur, level)
    print(f"current={cur}")
    print(f"level={level}")
    print(f"next={nxt}")
    print(f"needs_bump={'false' if nxt == cur else 'true'}")
    print("should_release=true")
    return 0


if __name__ == "__main__":
    sys.exit(main())

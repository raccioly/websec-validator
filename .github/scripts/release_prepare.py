"""Apply a release to the working tree: set pyproject's version and close the changelog section.

Separate from release.py's arithmetic so the file surgery can be tested on fixtures. Both edits are
idempotent-ish and fail loudly rather than writing something half-formed — a malformed version line
would reach PyPI, where releases cannot be replaced.
"""

from __future__ import annotations

import datetime as dt
import re
import sys
from pathlib import Path


def set_pyproject_version(text: str, version: str) -> str:
    # Only the [project] version — a dependency pin like `version = "1.2.3"` elsewhere must not move.
    out, n = re.subn(r'(?m)^(version\s*=\s*)"[^"]+"', rf'\1"{version}"', text, count=1)
    if n != 1:
        raise SystemExit("::error::could not find a single version = \"...\" line in pyproject.toml")
    return out


def close_changelog(text: str, version: str, today: str) -> str:
    if f"## [{version}]" in text:
        return text  # already closed by a previous run
    marker = "## [Unreleased]"
    if marker not in text:
        raise SystemExit("::error::CHANGELOG.md has no '## [Unreleased]' section to close")
    return text.replace(marker, f"{marker}\n\n## [{version}] — {today}", 1)


def main() -> int:
    version = sys.argv[1]
    today = sys.argv[2] if len(sys.argv) > 2 else dt.date.today().isoformat()

    p = Path("pyproject.toml")
    p.write_text(set_pyproject_version(p.read_text(), version))

    c = Path("CHANGELOG.md")
    c.write_text(close_changelog(c.read_text(), version, today))

    print(f"prepared release {version} ({today})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

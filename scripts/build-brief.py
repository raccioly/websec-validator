"""Render the reviewed HTML with installed Chrome, or check its committed PDF binding.

Maintenance tooling only: stdlib; --check needs no browser or network. Hashes catch
forgotten rebuilds, not inaccurate prose or a deliberately fabricated manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

REPO = Path(__file__).resolve().parent.parent
FILES = ("docs/websec-explained.html", "docs/websec-explained.pdf", "scripts/build-brief.py")
MANIFEST = "docs/websec-explained.manifest.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def regular_destination(root: Path, relative: str) -> Path:
    """Allow an explicitly selected root, but no aliases below it."""
    path = root
    for part in Path(relative).parts:
        path /= part
        if path.is_symlink():
            raise ValueError(f"aliased publication path: {relative}")
    if path.exists() and not stat.S_ISREG(path.stat().st_mode):
        raise ValueError(f"not a regular file: {relative}")
    return path


def pdf_pages(pdf: bytes) -> int:
    # Known Chrome output only; pdfinfo and visual review are the rendering authority.
    pages = len(re.findall(rb"/Type\s*/Page\b", pdf))
    if not pdf.startswith(b"%PDF-") or not pdf.rstrip().endswith(b"%%EOF") or pages != 8:
        raise ValueError("brief must be a complete eight-page Chrome PDF")
    return pages


def snapshot(root: Path) -> dict:
    paths = [regular_destination(root, name) for name in FILES]
    html = paths[0].read_text(encoding="utf-8")
    version = re.search(r"Technical Brief · v(\d+\.\d+\.\d+)", html)
    if not version:
        raise ValueError("missing brief snapshot version")
    pages = pdf_pages(paths[1].read_bytes())
    return {"schema_version": 1, "brief_version": version[1], "pages": pages,
            "sha256": {name: digest(path) for name, path in zip(FILES, paths)}}


def check(root: Path = REPO) -> None:
    manifest = regular_destination(root, MANIFEST)
    recorded = json.loads(manifest.read_text(encoding="utf-8"))
    if recorded != snapshot(root):
        raise ValueError("stale brief artifact: rebuild PDF and manifest, then review all pages")


def replace_owned(path: Path, data: bytes) -> None:
    # mkstemp creates an exclusive file, unlike predictable intermediate filenames.
    fd, name = tempfile.mkstemp(prefix=".brief-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(name, 0o644)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def build(chrome: str | None) -> None:
    source, output, _ = [regular_destination(REPO, name) for name in FILES]
    manifest = regular_destination(REPO, MANIFEST)
    html = source.read_text(encoding="utf-8")
    # The brief deliberately contains no scripts or resources, including CSS imports.
    if (re.search(r"<\s*(?:script|iframe|object|embed|base)\b|@import", html, re.I)
            or re.search(r"(?:src|href)\s*=\s*['\"](?!#)[^'\"]+", html, re.I)
            or re.search(r"url\(\s*['\"]?(?!#)", html, re.I)):
        raise ValueError("brief must remain self-contained and script-free")
    binary = chrome or shutil.which("google-chrome") or shutil.which("chromium")
    if not binary:
        candidate = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        binary = str(candidate) if candidate.is_file() else None
    if not binary:
        raise ValueError("Chrome not found; pass --chrome with an installed browser path")
    with tempfile.TemporaryDirectory(prefix="websec-brief-") as owned:
        temp = Path(owned)
        subprocess.run([binary, "--headless", "--disable-background-networking",
                        "--disable-component-update", "--disable-sync", "--no-first-run",
                        "--no-default-browser-check", "--metrics-recording-only",
                        f"--user-data-dir={temp / 'profile'}", "--no-pdf-header-footer",
                        f"--print-to-pdf={temp / 'brief.pdf'}", source.as_uri()],
                       check=True, timeout=60, capture_output=True)
        rendered = (temp / "brief.pdf").read_bytes()
        pdf_pages(rendered)  # Refuse bad/overflow output before replacing the published file.
        replace_owned(output, rendered)
    current = snapshot(REPO)
    replace_owned(manifest, (json.dumps(current, indent=2) + "\n").encode())
    check()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="offline freshness verification")
    parser.add_argument("--chrome", help="installed Chrome/Chromium executable (build only)")
    args = parser.parse_args()
    try:
        if args.check:
            check()
        else:
            build(args.chrome)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"brief: {exc}\n")
    print("Brief HTML/PDF/renderer binding verified; prose and layout require review.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

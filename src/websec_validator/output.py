"""Contained local writes. Explicit bases may be aliases; children must not be.

Like run reservation, this assumes an operator-controlled, stable directory tree.
Atomic replacement prevents truncating a hard-linked destination as a side effect.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile


def checked_path(base: Path, relative: str | Path) -> Path:
    base = Path(base).expanduser().resolve()
    rel = Path(relative)
    if rel.is_absolute() or not rel.parts or any(p in {"..", "."} for p in rel.parts):
        raise OSError("output must be a contained relative path")
    path = base
    for index, part in enumerate(rel.parts):
        path = path / part
        if path.is_symlink():
            raise OSError("output children must not be symlinks")
        if path.exists():
            mode = path.lstat().st_mode
            expected = stat.S_ISREG if index == len(rel.parts) - 1 else stat.S_ISDIR
            if not expected(mode):
                raise OSError("output has an unexpected file type")
    path.resolve().relative_to(base)
    return path


def write_text(base: Path, relative: str | Path, content: str) -> Path:
    path = checked_path(base, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    path = checked_path(base, relative)
    fd, name = tempfile.mkstemp(prefix=".websec-write-", dir=path.parent)
    temporary = Path(name)
    try:
        if path.exists():
            os.fchmod(fd, stat.S_IMODE(path.stat().st_mode))
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            handle.write(content)
        os.replace(temporary, path)
    finally:
        if fd is not None:
            os.close(fd)
        temporary.unlink(missing_ok=True)
    return path

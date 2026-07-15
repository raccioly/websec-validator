"""Recon entry point — thin wrapper over the extractor framework.

All the real work lives in extractors/. This module just exposes the stable
build_facts / write_facts / detect_stack API the CLI depends on.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import extractors
from .extractors.base import RepoContext
from .extractors.stack import StackExtractor


def build_facts(root: Path, version: str, excludes: list | None = None,
                include_fixtures: bool = False) -> dict:
    return extractors.run_all(root, version, excludes, include_fixtures=include_fixtures)


def write_facts(facts: dict, out: Path) -> Path:
    out.write_text(json.dumps(facts, indent=2))
    return out


def detect_stack(root: Path) -> dict:
    """Lightweight stack-only detection for scanner relevance (CLI doctor)."""
    return StackExtractor().extract(RepoContext(Path(root)), {})

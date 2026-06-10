"""Extractor registry + the run_all driver.

Order matters: stack runs first (later extractors read facts['stack']), then the
surface/authz extractors. Adding a new dimension = drop a module here and append
it to REGISTRY — that's the whole extension model.
"""

from __future__ import annotations

from pathlib import Path

from .auth import AuthExtractor
from .authz import AuthzExtractor
from .base import MAX_FILES, Extractor, RepoContext
from .client_exposure import ClientExposureExtractor
from .client_integrity import ClientIntegrityExtractor
from .graphql import GraphQLExtractor
from .iac_ci import IacCiExtractor
from .integrations import IntegrationsExtractor
from .pii_exposure import PiiExposureExtractor
from .policy_consistency import PolicyConsistencyExtractor
from .routes import RoutesExtractor
from .schemas import SchemasExtractor
from .stack import StackExtractor
from .surface import SurfaceExtractor
from .tenant import TenantExtractor
from .upload_security import UploadSecurityExtractor

# Order matters: stack first (others read facts['stack']); authz after routes
# (reads facts['routes']).
REGISTRY: list[Extractor] = [
    StackExtractor(),
    RoutesExtractor(),
    AuthExtractor(),
    AuthzExtractor(),
    TenantExtractor(),
    PolicyConsistencyExtractor(),
    SurfaceExtractor(),
    UploadSecurityExtractor(),
    SchemasExtractor(),
    IacCiExtractor(),
    ClientExposureExtractor(),
    ClientIntegrityExtractor(),
    PiiExposureExtractor(),
    GraphQLExtractor(),
    IntegrationsExtractor(),
]


def run_all(root: Path, version: str, excludes: list | None = None) -> dict:
    """Walk the repo once, run every extractor, return the merged FACTS dict."""
    ctx = RepoContext(root, excludes)
    facts: dict = {
        "tool": "websec-validator",
        "version": version,
        "target": str(root.resolve()),
        "files_scanned": len(ctx.code_files),
        # PARTIAL-scan guard: the walker stops at MAX_FILES (filesystem order), so on a very large
        # monorepo recon may miss files. Surface it loudly rather than implying full coverage.
        "files_truncated": bool(getattr(ctx, "truncated", False)),
        "file_cap": MAX_FILES,
    }
    for ext in REGISTRY:
        try:
            facts[ext.name] = ext.extract(ctx, facts)
        except Exception as e:  # one extractor must never sink the whole run
            facts[ext.name] = {"error": f"{type(e).__name__}: {e}"}
    return facts

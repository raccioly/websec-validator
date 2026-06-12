"""Extractor framework — the backbone of the recon engine.

Each extractor reads a shared, walked-once RepoContext and returns its slice of
FACTS. Extractors are deterministic (no LLM, no network to the target) and
degrade gracefully — a missing tool or unrecognized framework yields partial
facts, never a crash. This is what lets the engine scale to a big monorepo and
still say something useful.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "dist", "build", ".next", ".nuxt", "venv",
             ".venv", "__pycache__", ".mypy_cache", ".pytest_cache", "coverage",
             ".turbo", "out", "target", ".gradle", "vendor", "site-packages",
             ".terraform", "security", ".websec-out", "websec-out", ".cache",
             ".svelte-kit", "storybook-static", ".serverless", ".aws-sam", "cdk.out", ".sst", ".amplify",
             # agent tooling + editor dirs + worktree copies — not the target app
             ".wolf", ".claude", ".worktrees", ".idea", ".vscode", ".agent", ".agents"}
CODE_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go", ".rb",
            ".java", ".php", ".prisma",
            # Managed-cloud surfaces: AppSync GraphQL SDL (@aws_* auth directives) + VTL
            # resolvers (where realtime/subscription authz actually lives, or is missing).
            # REF-PENTEST #2/#5 lived in these file types — previously invisible to every
            # iter_code()-based extractor. routes.py SPEC_PATH still splits .graphql/.gql out
            # of the route list so SDL doesn't generate phantom endpoints.
            ".graphql", ".gql", ".vtl"}
MAX_FILES = 12000
MAX_BYTES = 2_000_000


def path_in_skip_dir(path: str, root: "Path | str | None" = None) -> bool:
    """True if `path` lies under a SKIP_DIR segment, measured RELATIVE to the scan root.

    Checking the ABSOLUTE path's segments is the bug-005/bug-066 trap: when the scanned repo
    itself lives under a skip-named ancestor (e.g. `.claude/worktrees/<id>`, `vendor/`,
    `target/`, `~/.cache`), a segment ABOVE the root matches and the WHOLE tree — every route,
    every finding — is silently dropped. Noir + the static scanners emit ABSOLUTE paths, so any
    traversal that post-filters their output MUST strip the root prefix first (the walker already
    does, via relative_to). Fail OPEN (keep the item) when the path can't be made relative — a
    silent drop is the dangerous direction for a security tool. `root=None` preserves the legacy
    raw-segment behavior for already-relative inputs.
    """
    p = (path or "").replace("\\", "/")
    if not p:
        return False
    if root is not None:
        try:
            p = Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
        except (ValueError, OSError):
            if Path(p).is_absolute():
                return False  # absolute but outside the root → don't risk a false drop
            # else: already a root-relative path → check its segments as-is below
    return any(part in SKIP_DIRS for part in p.split("/"))


class RepoContext:
    """Walk the tree once; cache file text; serve cheap queries to every extractor."""

    def __init__(self, root: Path, excludes: list | None = None):
        self.root = root
        self.excludes = [e for e in (excludes or []) if e]   # user --exclude paths/globs
        self._text: dict[Path, str] = {}
        self.code_files: list[Path] = []
        self.stack: dict = {}          # filled by StackExtractor, read by the rest
        self._walk()

    def _excluded(self, rel: str) -> bool:
        return any(ex in rel or fnmatch.fnmatch(rel, ex) for ex in self.excludes)

    def _walk(self) -> None:
        n = 0
        self.truncated = False          # set when MAX_FILES is hit → recon is PARTIAL, surface it
        for p in self.root.rglob("*"):
            if n >= MAX_FILES:
                self.truncated = True   # rglob order is filesystem-dependent → which files drop is
                break                   # nondeterministic; the consumer MUST know coverage is partial
            # match SKIP_DIRS against parts RELATIVE to the scan root — otherwise a
            # repo located under e.g. ~/.cache or any dir named like a skip-dir would
            # have its whole tree skipped.
            if p.is_dir() or any(part in SKIP_DIRS for part in p.relative_to(self.root).parts):
                continue
            if self.excludes and self._excluded(str(p.relative_to(self.root))):
                continue
            if p.suffix.lower() in CODE_EXT:
                self.code_files.append(p)
                n += 1

    def rel(self, p: Path) -> str:
        try:
            return str(p.relative_to(self.root))
        except ValueError:
            return str(p)

    def text(self, p: Path) -> str:
        if p not in self._text:
            try:
                self._text[p] = "" if p.stat().st_size > MAX_BYTES else p.read_text(errors="ignore")
            except Exception:
                self._text[p] = ""
        return self._text[p]

    def iter_code(self):
        """Yield (path, relpath, text) for every cached code file."""
        for p in self.code_files:
            yield p, self.rel(p), self.text(p)

    def manifest(self, name: str) -> str:
        f = self.root / name
        try:
            return f.read_text(errors="ignore") if f.is_file() else ""
        except Exception:
            return ""

    def glob(self, pattern: str, limit: int = 2000) -> list[Path]:
        """rglob filtered against SKIP_DIRS (for file-based framework detection)."""
        out = []
        for p in self.root.rglob(pattern):
            if any(part in SKIP_DIRS for part in p.relative_to(self.root).parts):
                continue
            out.append(p)
            if len(out) >= limit:
                break
        return out

    def exists(self, *names: str) -> bool:
        return any((self.root / n).exists() for n in names)


class Extractor:
    """Base class. Subclasses set `name`/`category` and implement extract()."""

    name: str = "extractor"
    category: str = "misc"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:  # pragma: no cover
        """Return this extractor's slice of FACTS. `facts` holds prior extractors'
        results (stack runs first), so later extractors can branch on them."""
        raise NotImplementedError

"""Extractor framework — the backbone of the recon engine.

Each extractor reads a shared, walked-once RepoContext and returns its slice of
FACTS. Extractors are deterministic (no LLM, no network to the target) and
degrade gracefully — a missing tool or unrecognized framework yields partial
facts, never a crash. This is what lets the engine scale to a big monorepo and
still say something useful.
"""

from __future__ import annotations

from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "dist", "build", ".next", ".nuxt", "venv",
             ".venv", "__pycache__", ".mypy_cache", ".pytest_cache", "coverage",
             ".turbo", "out", "target", ".gradle", "vendor", "site-packages",
             ".terraform", "security", ".websec-out", "websec-out", ".cache",
             ".svelte-kit", "storybook-static", ".serverless",
             # agent tooling + editor dirs + worktree copies — not the target app
             ".wolf", ".claude", ".worktrees", ".idea", ".vscode", ".agent", ".agents"}
CODE_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go", ".rb",
            ".java", ".php"}
MAX_FILES = 12000
MAX_BYTES = 2_000_000


class RepoContext:
    """Walk the tree once; cache file text; serve cheap queries to every extractor."""

    def __init__(self, root: Path):
        self.root = root
        self._text: dict[Path, str] = {}
        self.code_files: list[Path] = []
        self.stack: dict = {}          # filled by StackExtractor, read by the rest
        self._walk()

    def _walk(self) -> None:
        n = 0
        for p in self.root.rglob("*"):
            if n >= MAX_FILES:
                break
            if p.is_dir() or any(part in SKIP_DIRS for part in p.parts):
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
            if any(part in SKIP_DIRS for part in p.parts):
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

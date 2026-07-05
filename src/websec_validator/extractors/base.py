"""Extractor framework — the backbone of the recon engine.

Each extractor reads a shared, walked-once RepoContext and returns its slice of
FACTS. Extractors are deterministic (no LLM, no network to the target) and
degrade gracefully — a missing tool or unrecognized framework yields partial
facts, never a crash. This is what lets the engine scale to a big monorepo and
still say something useful.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "dist", "build", ".next", ".nuxt", "venv",
             ".venv", "__pycache__", ".mypy_cache", ".pytest_cache", "coverage",
             ".turbo", "out", "target", ".gradle", "vendor", "site-packages",
             ".terraform", "security", ".websec-out", "websec-out", ".cache",
             ".svelte-kit", "storybook-static", ".serverless", ".aws-sam", "cdk.out", ".sst", ".amplify",
             ".wrangler", ".vercel",   # Cloudflare / Vercel dev-build caches (bundled output → phantom routes)
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


# --- file-class helpers -------------------------------------------------------------------------
# Many sink/exposure extractors over-report because iter_code() walks the WHOLE tree — tests,
# build/CI scripts, and browser code get scanned as if they were deployed server request handlers.
# A test fixture's fake secret, an `e2e/*.spec.ts` relative fetch, a `scripts/deploy.mjs` outbound
# call — none are a runtime attack surface. These centralize the classification so every extractor
# decides the same way (validated against a real LLM-agent monorepo: the dominant client-exposure / ssrf /
# pii false-positive driver). Each extractor opts in to whichever classes it should skip.
_TEST_FILE = re.compile(
    r"(?:^|/)(?:tests?|__tests__|__mocks__|spec|specs|e2e|cypress|fixtures?|mocks?|stories|testdata|testing)/"
    r"|\.(?:test|spec|stories|e2e|cy)\.[cm]?[jt]sx?$"
    # Python test conventions (pytest / unittest): test_*.py, *_test.py, conftest.py — anywhere in the
    # tree, NOT just under a tests/ dir. Without this, root-level `test_curl.py` doing requests.get()
    # false-fires SSRF as if it were a production handler (real-repo FP: a real repo).
    r"|(?:^|/)test_[^/]*\.py$|(?:^|/)[^/]*_test\.py$|(?:^|/)conftest\.py$"
    r"|(?:^|/)[\w.-]*\.config\.[cm]?[jt]sx?$"          # vite/vitest/jest/playwright/next/... .config.*
    r"|(?:^|/)(?:playwright|vitest|jest|cypress)\.[\w.]*$", re.I)
# build / ops / CLI scripts run by an operator or CI, not reachable from an inbound HTTP request.
# Broadened from real-repo FPs (a real app research/, a real repo live/, a real repo) — a doc/data
# generator, a research notebook, a local backtest, or a CLI updater is operated by a human, so its
# "user input" (argv/config/a file it reads) is not an attacker over HTTP: server-only sinks don't apply.
_SCRIPT_FILE = re.compile(
    r"(?:^|/)(?:scripts?|bin|\.bin|ops|operations|migrations?|seeds?|tools?|tooling|research|"
    r"examples?|samples?|benchmarks?|notebooks?|codemods?|generators?|datagen|[\w-]*backtests?)/", re.I)
# browser / client-side code. SSRF and server-secret-exposure are server-only classes; a `.tsx`
# React component, a hook, or a `'use client'` module runs in the visitor's browser to the app's OWN
# origin, so an outbound fetch there is same-origin, not an SSRF/exfil sink.
_CLIENT_FILE = re.compile(r"\.(?:tsx|jsx)$|(?:^|/)(?:components?|hooks?|contexts?|widgets?|ui)/", re.I)


def is_test_file(rel: str) -> bool:
    return bool(_TEST_FILE.search((rel or "").replace("\\", "/")))


def is_script_file(rel: str) -> bool:
    return bool(_SCRIPT_FILE.search((rel or "").replace("\\", "/")))


def is_client_file(rel: str, text: str = "") -> bool:
    rel = (rel or "").replace("\\", "/")
    if _CLIENT_FILE.search(rel):
        return True
    head = text[:300]
    return "'use client'" in head or '"use client"' in head


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

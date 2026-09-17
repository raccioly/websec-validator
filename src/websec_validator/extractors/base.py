"""Extractor framework — the backbone of the recon engine.

Each extractor reads a shared, walked-once RepoContext and returns its slice of
FACTS. Extractors are deterministic (no LLM, no network to the target) and
degrade gracefully — a missing tool or unrecognized framework yields partial
facts, never a crash. This is what lets the engine scale to a big monorepo and
still say something useful.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import stat
from functools import lru_cache
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "dist", "build", ".next", ".nuxt", "venv",
             ".venv", "__pycache__", ".mypy_cache", ".pytest_cache", "coverage",
             ".turbo", "out", "target", ".gradle", "vendor", "site-packages",
             ".terraform", "security", ".websec-out", "websec-out", ".cache",
             ".svelte-kit", "storybook-static", ".serverless", ".aws-sam", "cdk.out", ".sst", ".amplify",
             ".wrangler", ".vercel",   # Cloudflare / Vercel dev-build caches (bundled output → phantom routes)
             # agent tooling + editor dirs + worktree copies — not the target app
             ".wolf", ".claude", ".worktrees", ".idea", ".vscode", ".agent", ".agents",
             ".codex", ".local"}
CODE_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go", ".rb",
            ".java", ".php", ".cs", ".rs", ".kt", ".kts", ".swift", ".m", ".mm",
            ".c", ".h", ".cpp", ".hpp", ".prisma", ".vue", ".svelte", ".mts", ".cts",
             ".html", ".htm", ".jinja", ".jinja2", ".j2",
            # Managed-cloud surfaces: AppSync GraphQL SDL (@aws_* auth directives) + VTL
            # resolvers (where realtime/subscription authz actually lives, or is missing).
            # REF-PENTEST #2/#5 lived in these file types — previously invisible to every
            # iter_code()-based extractor. routes.py SPEC_PATH still splits .graphql/.gql out
            # of the route list so SDL doesn't generate phantom endpoints.
            ".graphql", ".gql", ".vtl"}
MAX_FILES = 12000
MAX_BYTES = 2_000_000
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_WALK_FILES = 120_000
MAX_SKIP_SAMPLES = 200
# Report known source types that the built-in code extractors do not inspect.
# Config, documentation and binary assets are not presumed to be source code.
SOURCE_EXT = CODE_EXT | {".vue", ".svelte", ".mts", ".cts", ".html", ".htm",
                         ".cs", ".rs", ".kt", ".kts", ".swift", ".scala", ".c", ".h", ".cpp", ".hpp"}


def _glob_matches(relative: Path, pattern: str) -> bool:
    """Path.rglob semantics, including zero or many directories for **."""
    names = relative.parts
    parts = ("**", *pattern.split("/"))

    @lru_cache(maxsize=None)
    def match(i: int, j: int) -> bool:
        if j == len(parts):
            return i == len(names)
        if parts[j] == "**":
            return match(i, j + 1) or (i < len(names) and match(i + 1, j))
        return (i < len(names) and fnmatch.fnmatchcase(names[i], parts[j])
                and match(i + 1, j + 1))

    return match(0, 0)


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

    def __init__(self, root: Path, excludes: list | None = None, include_fixtures: bool = False,
                 *, expected_root: tuple[Path, int, int] | None = None, walk: bool = True,
                 only: list | None = None):
        # Keep the caller's spelling for returned paths (macOS /var aliases
        # /private/var), with a separate canonical root for containment.
        self.root = Path(root).absolute()
        self._resolved_root = self.root.resolve()
        self._root_identity = self._identity(self.root.stat())
        if expected_root is not None:
            selected_path, selected_dev, selected_ino = expected_root
            # Compare the already approved canonical spelling WITHOUT resolving
            # it again: a replacement symlink would otherwise redefine the grant.
            if (self._resolved_root != selected_path
                    or self._root_identity != (selected_dev, selected_ino)):
                raise ValueError("repository root changed after authorization")
        self.excludes = [e for e in (excludes or []) if e]
        self.include_fixtures = bool(include_fixtures)
        self._text: dict[tuple[Path, int], str] = {}
        self._text_metadata: dict[tuple[Path, int], dict] = {}
        self.source_bytes_limit = MAX_SOURCE_BYTES
        self.cached_source_bytes = 0
        self.byte_budget_exceeded: list[str] = []
        self.input_hashes: dict[str, str] = {}
        self.oversized: list[str] = []
        self.unreadable: list[str] = []
        self.unsupported_files: list[str] = []
        self.glob_truncated: list[dict] = []
        self.skipped_files: list[dict] = []
        self.skip_counts: dict[str, int] = {}
        self._skip_seen: set[tuple[str, str]] = set()
        self.files_seen = 0
        self.file_types: dict[str, int] = {}
        self.walk_truncated = False
        self.truncated = False
        self._files: list[Path] = []
        # Lexical spellings only, bounded by the walked inventory. This is not
        # an authorization cache: resolved targets and file state are rechecked.
        self._relative_files: dict[Path, Path] = {}
        self.code_files: list[Path] = []
        # TWO-TIER ANALYSIS SCOPE (`only`). The tree is ALWAYS walked in full — walking is cheap
        # (~0.3s on a 315-file repo) while reading and matching is not, and the walk is what
        # establishes stack detection, ignore policy, fixture classification and glob discovery.
        # `only` restricts which files are READ AND MATCHED; `all_code_files` keeps the full
        # inventory for classification consumers.
        #
        # Files are analyzed IN PLACE against the real root. Measured: the same three files copied
        # to a bare directory produced 3 CRITICAL + 1 HIGH findings that the full tree does not
        # report, purely from losing path context and the ignore policy (a detector's own pattern
        # literals read as application code once the path changes). Never copy, reroot or stage.
        self.all_code_files: list[Path] = []
        self.scope: set[str] | None = None
        if only:
            self.scope = {Path(str(p)).as_posix().lstrip("./") for p in only if str(p).strip()}
        self.scope_requested: list[str] = sorted(self.scope) if self.scope else []
        self.scope_matched: list[str] = []
        self.scope_missed: list[str] = []
        self.stack: dict = {}
        if walk:
            self._walk()
            self._apply_scope()

    @staticmethod
    def _identity(info: os.stat_result) -> tuple[int, int]:
        return info.st_dev, info.st_ino

    def _excluded(self, rel: str) -> bool:
        # Preserve the CLI's historical substring-or-glob semantics. Apply them
        # to both the alias and its resolved target so a symlink cannot unexclude.
        return any(ex in rel or fnmatch.fnmatch(rel, ex) for ex in self.excludes)

    def _skip(self, path: Path, reason: str) -> None:
        rel = self.rel(path)
        key = (rel, reason)
        if key in self._skip_seen:
            return
        self._skip_seen.add(key)
        self.skip_counts[reason] = self.skip_counts.get(reason, 0) + 1
        if len(self.skipped_files) < MAX_SKIP_SAMPLES:
            self.skipped_files.append({"path": rel, "reason": reason})

    def _allowed(self, path: Path, *, traversal: bool = False,
                 directory: bool = False) -> tuple[Path, Path, os.stat_result] | None:
        """One policy for enumeration, explicit reads, manifests and existence.

        Direct reads may inspect intentional agent config under .claude. Both
        modes always enforce root containment, .local privacy and exclusions.
        Directory symlinks are never traversed; regular in-root file aliases work.
        """
        path = Path(path)
        path = path if path.is_absolute() else self.root / path
        try:
            relative = self._relative_files.get(path)
            if relative is None:
                relative = path.relative_to(self.root)
        except ValueError:
            self._skip(path, "outside_root")
            return None
        if ".." in relative.parts:
            self._skip(path, "outside_root")
            return None
        if any(part.casefold() == ".local" for part in relative.parts):
            self._skip(path, "private")
            return None
        if self._excluded(relative.as_posix()):
            self._skip(path, "excluded")
            return None
        if traversal and any(part in SKIP_DIRS for part in relative.parts):
            self._skip(path, "skip_directory")
            return None
        try:
            resolved = path.resolve(strict=True)
            target = resolved.relative_to(self._resolved_root)
            if any(part.casefold() == ".local" for part in target.parts):
                self._skip(path, "private")
                return None
            if self._excluded(target.as_posix()):
                self._skip(path, "excluded")
                return None
            if traversal and any(part in SKIP_DIRS for part in target.parts):
                self._skip(path, "skip_directory")
                return None
            info = resolved.stat()
        except ValueError:
            self._skip(path, "outside_root")
            return None
        except FileNotFoundError:
            return None  # optional manifests commonly do not exist
        except (OSError, RuntimeError):
            self._skip(path, "unreadable")
            if self.rel(path) not in self.unreadable:
                self.unreadable.append(self.rel(path))
            return None
        if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
            self._skip(path, "non_regular")
            return None
        if directory and path.is_symlink():
            self._skip(path, "directory_symlink")
            return None
        return path, resolved, info

    def _walk_error(self, error: OSError) -> None:
        path = Path(error.filename) if error.filename else self.root
        self._skip(path, "unreadable")
        if self.rel(path) not in self.unreadable:
            self.unreadable.append(self.rel(path))

    def _walk(self) -> None:
        # Prune before descending: rglob plus post-filtering still enumerates
        # ignored dependency trees and private directories. Sorted traversal
        # also makes capped scans reproducible for an unchanged checkout.
        for directory, dirs, files in os.walk(self.root, topdown=True,
                                              followlinks=False, onerror=self._walk_error):
            parent = Path(directory)
            dirs[:] = [name for name in sorted(dirs)
                       if self._allowed(parent / name, traversal=True, directory=True)]
            for name in sorted(files):
                self.files_seen += 1
                if self.files_seen > MAX_WALK_FILES:
                    self.walk_truncated = self.truncated = True
                    return
                path = parent / name
                allowed = self._allowed(path, traversal=True)
                if allowed is None:
                    continue
                self._files.append(path)
                self._relative_files[path] = path.relative_to(self.root)
                suffix = path.suffix.lower()
                self.file_types[suffix or "<none>"] = self.file_types.get(suffix or "<none>", 0) + 1
                if suffix in CODE_EXT:
                    if len(self.code_files) >= MAX_FILES:
                        self.truncated = True
                    else:
                        self.code_files.append(path)
                elif suffix in SOURCE_EXT:
                    self.unsupported_files.append(self.rel(path))

    def _apply_scope(self) -> None:
        """Keep the full inventory, then narrow what will actually be analyzed."""
        self.all_code_files = list(self.code_files)
        if self.scope is None:
            return
        kept = [p for p in self.code_files if self.rel(p) in self.scope]
        self.scope_matched = sorted(self.rel(p) for p in kept)
        # A requested path that the walker never selected (excluded, generated, unsupported suffix,
        # nonexistent, or outside the root) is a SCOPE MISS, not an empty clean result. The caller
        # must be able to tell "analyzed and found nothing" from "never looked".
        self.scope_missed = sorted(self.scope - set(self.scope_matched))
        self.code_files = kept

    def rel(self, path: Path) -> str:
        relative = self._relative_files.get(path)
        if relative is not None:
            return relative.as_posix()
        try:
            return Path(path).relative_to(self.root).as_posix()
        except ValueError:
            return str(path)

    def _open_file(self, resolved: Path, expected: os.stat_result) -> int:
        """Open a validated regular file, anchoring each component on POSIX.

        Resolve first to permit safe file symlinks, then open the resolved path
        with O_NOFOLLOW on every component. A renamed parent or swapped alias
        therefore cannot redirect a read outside the selected root. This is not
        a snapshot: concurrent writes to the same inode can still change bytes.
        Platforms without dir_fd/O_NOFOLLOW use identity checks and require a
        stable checkout during the scan for equivalent containment guarantees.
        """
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
        anchored = (os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW")
                    and hasattr(os, "O_DIRECTORY"))
        if anchored:
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            directory_fd = os.open(self._resolved_root, directory_flags)
            try:
                if self._identity(os.fstat(directory_fd)) != self._root_identity:
                    raise OSError("scan root changed during read")
                parts = resolved.relative_to(self._resolved_root).parts
                for component in parts[:-1]:
                    next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
                    os.close(directory_fd)
                    directory_fd = next_fd
                fd = os.open(parts[-1], flags | os.O_NOFOLLOW, dir_fd=directory_fd)
            finally:
                os.close(directory_fd)
        else:
            fd = os.open(resolved, flags)
        try:
            actual = os.fstat(fd)
            if not stat.S_ISREG(actual.st_mode) or self._identity(actual) != self._identity(expected):
                raise OSError("file changed during read")
            if not anchored and resolved.resolve(strict=True) != resolved:
                raise OSError("file path changed during read")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def text(self, path: Path, *, max_bytes: int = MAX_BYTES) -> str:
        allowed = self._allowed(path)
        if allowed is None:
            return ""
        path, resolved, info = allowed
        # Custom readers may tighten the shared limit, never relax it.
        cap = max(0, min(max_bytes, MAX_BYTES))
        key = (resolved, cap)
        if key not in self._text:
            reason, content = None, None
            try:
                if info.st_size > cap:
                    reason = "oversized"
                elif info.st_size > self.source_bytes_limit - self.cached_source_bytes:
                    reason = "byte_budget_exceeded"
                else:
                    remaining = self.source_bytes_limit - self.cached_source_bytes
                    with os.fdopen(self._open_file(resolved, info), "rb") as stream:
                        content = stream.read(min(cap, remaining) + 1)
                    if len(content) > cap:
                        reason = "oversized"
                    elif len(content) > remaining:
                        reason = "byte_budget_exceeded"
                if reason:
                    self._text[key] = ""
                    self._text_metadata[key] = {"error": reason}
                else:
                    self._text[key] = content.decode("utf-8", errors="ignore")
                    self._text_metadata[key] = {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}
                    self.cached_source_bytes += len(content)
            except (OSError, ValueError):
                self._text[key] = ""
                self._text_metadata[key] = {"error": "unreadable"}
        # Cache sharing must not erase lexical inputs from the analyzed digest.
        # Empty successful files have a hash; cached failures never fabricate one.
        metadata = self._text_metadata[key]
        if "sha256" in metadata:
            self.input_hashes[self.rel(path)] = metadata["sha256"]
        else:
            reason = metadata["error"]
            failures = getattr(self, reason)
            if self.rel(path) not in failures:
                failures.append(self.rel(path))
            self._skip(path, reason)
        return self._text[key]

    def iter_code(self):
        """Yield (path, relpath, text) for every selected code file (honours the analysis scope)."""
        for path in self.code_files:
            yield path, self.rel(path), self.text(path)

    def iter_all_code(self, suffixes: tuple = ()):
        """Yield (path, relpath, text) over the WHOLE tree, ignoring the analysis scope.

        For CLASSIFICATION probes only — the ones that decide which stack/frameworks a repo has and
        therefore which detectors run. Scoping those would let a scoped run of one file silently
        change the detected stack. Pass `suffixes` to keep the cost proportionate: a probe that only
        applies to TS/JS must not read every Python file in the tree to answer."""
        for path in (self.all_code_files or self.code_files):
            if suffixes and path.suffix.lower() not in suffixes:
                continue
            yield path, self.rel(path), self.text(path)

    def manifest(self, name: str) -> str:
        return self.text(self.root / name)

    def glob(self, pattern: str, limit: int = 2000) -> list[Path]:
        """Recursive file glob over the shared, policy-filtered inventory.

        limit=1 is an existence predicate used by stack detection, so additional
        matches do not represent lost analysis. Larger caps record truncation.
        """
        if limit <= 0:
            return []
        out = []
        for path in self._files:
            relative = self._relative_files.get(path)
            if relative is None:
                relative = path.relative_to(self.root)
            if not _glob_matches(relative, pattern):
                continue
            if self._allowed(path, traversal=True) is None:
                continue
            if len(out) >= limit:
                cap = {"pattern": pattern, "limit": limit}
                if limit > 1 and cap not in self.glob_truncated:
                    self.glob_truncated.append(cap)
                break
            out.append(path)
        return out

    def exists(self, *names: str) -> bool:
        return any(self._allowed(self.root / name) is not None for name in names)


def read_artifact(path: Path, max_bytes: int = 16 * 1024 * 1024) -> str:
    """Read an explicitly selected artifact as bounded regular UTF-8 data.

    Artifact inputs have their own selected directory scope and a larger cap
    than source files; they must never be used for implicit target discovery.
    """
    path = Path(path).absolute()
    ctx = RepoContext(path.parent, walk=False)
    allowed = ctx._allowed(path)
    if allowed is None:
        raise ValueError("artifact must be a readable regular file within its selected directory")
    _, resolved, info = allowed
    if info.st_size > max_bytes:
        raise ValueError("artifact exceeds the byte limit")
    with os.fdopen(ctx._open_file(resolved, info), "rb") as stream:
        content = stream.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise ValueError("artifact exceeds the byte limit")
    return content.decode("utf-8")


class Extractor:
    """Base class. Subclasses set `name`/`category` and implement extract()."""

    name: str = "extractor"
    category: str = "misc"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:  # pragma: no cover
        """Return this extractor's slice of FACTS. `facts` holds prior extractors'
        results (stack runs first), so later extractors can branch on them."""
        raise NotImplementedError

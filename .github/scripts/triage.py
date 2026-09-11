"""Classification logic for the bot-PR automation — pure functions, stdlib only, no network.

Kept out of the workflow YAML on purpose: this is the part that decides what merges without a human
looking at it, so it has to be unit-testable against real PR payloads. See test_triage.py.

Two consumers:
  * auto_merge.yml  — decides whether a green bot PR may merge itself (`verdict`)
  * bot_triage.yml  — decides whether a freshly opened PR is a known-noise duplicate (`dup_key`,
                      `is_known_noise`)

Design stance: the default is HOLD. Every rule here is an allowlist; anything unrecognised falls
through to a human. For a repo whose tests ARE the detection contract, a wrongly-merged PR is much
more expensive than a wrongly-held one.
"""

from __future__ import annotations

import re

# Files that carry no semantic weight for duplicate detection — a bot rewriting the changelog does
# not make two PRs different.
NOISE_FILES = frozenset({"CHANGELOG.md", ".websec-ignore", ".docguardignore"})

# Anything under these never auto-merges, whatever else is in the PR.
HELD_PREFIXES = (
    "src/",            # the product
    ".github/",        # CI, release, and this automation itself
    ".claude-plugin/", # plugin manifests consumers install from
    "skills/",         # shipped skill text
    ".wolf/",          # assistant memory
    ".claude/",
)
HELD_EXACT = frozenset({
    "pyproject.toml", "setup.py", "setup.cfg", "MANIFEST.in",  # packaging → PyPI
    "Dockerfile", "action.yml", "action.yaml", ".dockerignore",
    # Instruction files: they steer coding agents, so they are config, not prose.
    "AGENTS.md", "CLAUDE.md", "GEMINI.md", "CONVENTIONS.md",
})

DOC_PREFIXES = ("docs/", "docs-canonical/", "docs-implementation/")

# Binary or vendored payloads have no business in a bot PR (PR #73 carried a 30MB .deb).
BINARY_RE = re.compile(
    r"\.(deb|rpm|apk|zip|tar|gz|tgz|xz|whl|so|dylib|dll|exe|bin|jar|png|jpe?g|gif|pdf|ico|woff2?)$",
    re.I,
)

MAX_FILES = 25  # a bot PR wider than this is a refactor in disguise

# Dependabot's entire remit in this repo is bumping SHA-pinned actions and the Docker base image,
# which live under .github/workflows/ and action.yml — i.e. inside HELD_PREFIXES. Holding those for
# a human would make dependabot automation pointless, so it gets its own allowlist, narrowed to the
# paths its two configured ecosystems can actually touch. Nothing else may ride along.
DEPENDABOT_ALLOWED_PREFIXES = (".github/workflows/",)
DEPENDABOT_ALLOWED_EXACT = frozenset({
    "action.yml", "action.yaml", "Dockerfile", ".github/dependabot.yml",
})
# A SHA-pin bump is a pure line swap (+1 -1 per occurrence, as every real dependabot PR in this repo
# shows). Anything that adds or removes net lines is not the edit dependabot claims to be making.
DEPENDABOT_MAX_LINES = 20


def significant(filenames) -> frozenset:
    """The file set that identifies a PR's intent, ignoring bookkeeping churn."""
    return frozenset(f for f in filenames if f not in NOISE_FILES)


def dup_key(filenames) -> frozenset:
    """Two PRs with the same key are the same change. Deliberately file-overlap based: bot PR titles
    for one fix vary wildly ('Fix flaky git hooks test' / 'fix(tests): pin core.hooksPath' / ...),
    so title normalisation does not group them."""
    return significant(filenames)


def is_known_noise(filenames) -> str | None:
    """Recognise PR classes that are reliably re-generated noise. Returns a reason, or None."""
    sig = significant(filenames)
    if sig == frozenset({"tests/test_hooks.py"}):
        return (
            "test_hooks.py-only change — the underlying defect (bug-217: the suite was not hermetic "
            "against an ambient core.hooksPath) is fixed on main, and CI now has a `hermeticity` leg "
            "that reproduces it"
        )
    return None


def _is_doc(f: str) -> bool:
    return f.endswith(".md") or f.startswith(DOC_PREFIXES)


def _is_test(f: str) -> bool:
    return f.startswith("tests/")


def _held_reason(f: str) -> str | None:
    if f.startswith(HELD_PREFIXES):
        return f"touches {f} (protected path)"
    if f in HELD_EXACT:
        return f"touches {f} (packaging/instruction file)"
    if BINARY_RE.search(f):
        return f"contains a binary or vendored artifact ({f})"
    return None


def parse_bump(title: str):
    """('major'|'minor'|'patch'|None, from, to) from a dependabot title.

    Handles the partial-version form dependabot uses for action major tags ('from 6 to 7'), which a
    naive 3-component semver parse drops on the floor — and that form is precisely a major bump.
    """
    m = re.search(r"\bfrom\s+v?(\d[\w.\-+]*)\s+to\s+v?(\d[\w.\-+]*)", title, re.I)
    if not m:
        return None, None, None
    a, b = m.group(1), m.group(2)

    def parts(v):
        out = []
        for chunk in v.split("+")[0].split("-")[0].split(".")[:3]:
            if not chunk.isdigit():
                return None
            out.append(int(chunk))
        return (out + [0, 0, 0])[:3] if out else None

    pa, pb = parts(a), parts(b)
    if pa is None or pb is None:
        return None, a, b
    if pb[0] != pa[0]:
        return "major", a, b
    if pb[1] != pa[1]:
        return "minor", a, b
    if pb[2] != pa[2]:
        return "patch", a, b
    return None, a, b


def verdict(author: str, title: str, files) -> tuple[str, str]:
    """('merge'|'hold', reason). `files` is the GitHub pulls/{n}/files payload: dicts with
    'filename', 'status', 'additions', 'deletions'.

    Path rules are author-scoped on purpose. A blanket .github/ hold reads as the safe default but
    silently disables dependabot entirely, since bumping SHA-pinned actions IS an edit to
    .github/workflows/. Each bot gets the narrow allowlist matching the job it was given.
    """
    names = [f["filename"] for f in files]

    if not names:
        return "hold", "no files reported"
    if len(names) > MAX_FILES:
        return "hold", f"{len(names)} files changed (limit {MAX_FILES})"

    # Precedence: a known-noise PR is closed by the triage workflow, never merged. Without this the
    # 27 test_hooks-only PRs all read as "purely additive" and would merge each other into conflict.
    noise = is_known_noise(names)
    if noise:
        return "hold", f"known-noise class — {noise}"

    # removeprefix, not lstrip: lstrip("app/") strips a CHARACTER SET and mangles any login starting
    # with a/p/-. It happens to work on these two logins; it will not on the next one.
    author = author.lower().removeprefix("app/")

    if author.startswith("dependabot"):
        for n in names:
            if not (n.startswith(DEPENDABOT_ALLOWED_PREFIXES) or n in DEPENDABOT_ALLOWED_EXACT):
                return "hold", f"{n} is outside dependabot's configured ecosystems"
            if BINARY_RE.search(n):
                return "hold", f"contains a binary artifact ({n})"
        level, a, b = parse_bump(title)
        if level is None:
            return "hold", f"could not determine bump level from title: {title!r}"
        if level == "major":
            return "hold", f"major bump {a} → {b} — majors raise runtime floors without failing install"
        adds = sum(f.get("additions", 0) for f in files)
        dels = sum(f.get("deletions", 0) for f in files)
        if adds != dels:
            return "hold", f"+{adds}/-{dels} is not a pure pin swap — dependabot PRs replace lines 1:1"
        if adds > DEPENDABOT_MAX_LINES:
            return "hold", f"{adds} changed lines exceeds the {DEPENDABOT_MAX_LINES}-line pin-swap budget"
        return "merge", f"{level} bump {a} → {b} ({adds} line(s) swapped across {len(names)} file(s))"

    # Every other bot: docs, or purely-additive tests. Protected paths are absolute.
    for n in names:
        r = _held_reason(n)
        if r:
            return "hold", r

    sig = [n for n in names if n not in NOISE_FILES]
    if not sig:
        return "hold", "changelog-only change with no accompanying fix"

    if all(_is_doc(n) for n in sig):
        return "merge", f"docs-only ({len(sig)} file(s))"

    if all(_is_test(n) for n in sig):
        touched = [f for f in files if f["filename"] not in NOISE_FILES]
        for f in touched:
            if f.get("status") in ("removed", "renamed"):
                return "hold", f"{f['filename']} was {f['status']} — removes existing coverage"
            if f.get("deletions", 0) > 0:
                return (
                    "hold",
                    f"{f['filename']} deletes/rewrites {f['deletions']} line(s) — an edit to an "
                    f"existing assertion is a change to the detection contract",
                )
        return "merge", f"tests-only and purely additive (+{sum(f.get('additions', 0) for f in touched)})"

    return "hold", "mixes tests/docs with other paths — needs a human"

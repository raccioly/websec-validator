"""Drift guards for the user documentation tree (docs/, README, translations).

Hand-written reference pages rot the moment the code moves: a flag is renamed, a subcommand is
added, a language profile ships, and the page keeps describing the old tool. These tests bind the
pages to the code they describe, so the drift fails CI instead of reaching a reader:

* every argparse subcommand has a section in docs/reference/cli.md, and every long option is named;
* every `websec ...` command shown in a docs code block is a real subcommand with real options;
* the language matrix names every language/profile id the code knows about;
* relative links (and their #anchors) resolve, and every page is reachable from the docs hub;
* docs carry no hard-coded release pins, which a release would silently strand;
* translations declare that English is authoritative and the version they were translated from.

They check that the docs are *valid*, not that every sentence is true; prose still needs review.
"""

from __future__ import annotations

import argparse
import re
import shlex
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from websec_validator.cli import build_parser  # noqa: E402
from websec_validator.extractors import base, profiles  # noqa: E402

DOCS = REPO / "docs"
CLI_MD = DOCS / "reference" / "cli.md"
LANG_MD = DOCS / "reference" / "languages.md"
HUB = DOCS / "README.md"
I18N = DOCS / "i18n"
# Snapshot-bound review records and dated migration notes are linked from their own index pages,
# and each translated page is linked from its translated README; none of them is part of the
# reader-facing tree the hub must enumerate.
HUB_EXEMPT = ("security-review/", "MIGRATING-", "i18n/")


def _subparsers(parser: argparse.ArgumentParser) -> dict[str, argparse.ArgumentParser]:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action.choices)
    return {}


def _long_options(parser: argparse.ArgumentParser) -> set[str]:
    return {o for a in parser._actions for o in a.option_strings if o.startswith("--") and o != "--help"}


def _command_tree() -> dict[tuple[str, ...], argparse.ArgumentParser]:
    """Map ('run',), ('intel', 'refresh') … to their parsers."""
    tree: dict[tuple[str, ...], argparse.ArgumentParser] = {}

    def walk(parser, prefix):
        for name, sub in _subparsers(parser).items():
            tree[prefix + (name,)] = sub
            walk(sub, prefix + (name,))

    walk(build_parser(), ())
    return tree


def _user_docs() -> list[Path]:
    """Reader-facing Markdown: the docs tree, the root README and the contributor guide."""
    pages = [p for p in DOCS.rglob("*.md")]
    return sorted(pages + [REPO / "README.md", REPO / "CONTRIBUTING.md"])


def _code_blocks(text: str, langs=("bash", "sh", "shell", "console", "")) -> list[str]:
    blocks = []
    for m in re.finditer(r"^```([\w-]*)[^\n]*\n(.*?)^```", text, re.M | re.S):
        if m.group(1).lower() in langs:
            blocks.append(m.group(2))
    return blocks


def _websec_invocations(block: str) -> list[str]:
    """Logical `websec …` command lines in a shell block (continuations joined, comments dropped)."""
    joined = re.sub(r"\\\n\s*", " ", block)
    out = []
    for line in joined.splitlines():
        line = line.strip()
        line = re.sub(r"^\$\s+", "", line)
        if not re.match(r"websec(\s|$)", line):
            continue
        out.append(line.split(" #", 1)[0].strip())
    return out


def _slug(heading: str) -> str:
    """GitHub's heading-anchor algorithm (lowercase, drop punctuation, spaces to hyphens)."""
    text = re.sub(r"<[^>]+>", "", heading)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = text.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


def _anchors(path: Path) -> set[str]:
    seen: dict[str, int] = {}
    anchors = set()
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"^```.*?^```", "", text, flags=re.M | re.S)  # headings inside code are not headings
    for m in re.finditer(r"^#{1,6}\s+(.+?)\s*#*\s*$", text, re.M):
        slug = _slug(m.group(1))
        n = seen.get(slug, 0)
        anchors.add(slug if n == 0 else f"{slug}-{n}")
        seen[slug] = n + 1
    anchors.update(re.findall(r'<a\s+(?:name|id)="([^"]+)"', text))
    return anchors


def _links(text: str) -> list[str]:
    text = re.sub(r"^```.*?^```", "", text, flags=re.M | re.S)
    text = re.sub(r"`[^`\n]*`", "", text)
    return re.findall(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)", text)


class CliReferenceTests(unittest.TestCase):
    def setUp(self):
        self.text = CLI_MD.read_text(encoding="utf-8")

    def test_every_subcommand_has_a_section(self):
        for path in _command_tree():
            level = "##" if len(path) == 1 else "###"
            heading = f"{level} `websec {' '.join(path)}`"
            self.assertRegex(self.text, rf"(?m)^{re.escape(heading)}\s*$",
                             f"docs/reference/cli.md has no section `{heading}`")

    def test_every_long_option_is_documented(self):
        for path, parser in _command_tree().items():
            for option in _long_options(parser):
                self.assertIn(f"`{option}", self.text,
                              f"`websec {' '.join(path)} {option}` is missing from docs/reference/cli.md")

    def test_no_section_for_a_command_that_does_not_exist(self):
        known = {" ".join(p) for p in _command_tree()}
        for m in re.finditer(r"(?m)^#{2,3} `websec ([a-z][\w-]*(?: [a-z][\w-]*)?)`\s*$", self.text):
            self.assertIn(m.group(1), known, f"cli.md documents a non-existent command `websec {m.group(1)}`")


class DocumentedCommandsAreRealTests(unittest.TestCase):
    """A command copied from the docs must at least parse: real subcommand, real options."""

    def test_every_websec_command_in_a_code_block_parses(self):
        tree = _command_tree()
        global_opts = _long_options(build_parser())
        problems = []
        for page in _user_docs() + sorted(REPO.glob("README.*.md")):
            text = page.read_text(encoding="utf-8")
            for block in _code_blocks(text):
                for line in _websec_invocations(block):
                    try:
                        tokens = shlex.split(line)
                    except ValueError:
                        tokens = line.split()
                    words = [t for t in tokens[1:] if not t.startswith("-")]
                    if not words and all(t in global_opts | {"--help", "-h"} for t in tokens[1:]):
                        continue
                    # Placeholder-only lines (`websec <command> --help`) document the shape, not a command.
                    if words and words[0].startswith("<"):
                        continue
                    first = words[0] if words else ""
                    # A bare path defaults to `run` (`websec ./my-app`).
                    if first and (first[0] in "./~$\"'" or "/" in first) and (first,) not in tree:
                        path = ("run",)
                    else:
                        path = (first,)
                        if path not in tree:
                            problems.append(f"{page.relative_to(REPO)}: unknown subcommand in `{line}`")
                            continue
                        if len(words) > 1 and (first, words[1]) in tree:
                            path = (first, words[1])
                    allowed = _long_options(tree[path]) | global_opts
                    for tok in tokens[1:]:
                        if tok.startswith("--"):
                            opt = tok.split("=", 1)[0]
                            if opt not in allowed and opt != "--help":
                                problems.append(f"{page.relative_to(REPO)}: `websec {' '.join(path)}` "
                                                f"has no option {opt} (in `{line}`)")
        self.assertEqual(problems, [], "\n".join(problems))


class LanguageMatrixTests(unittest.TestCase):
    def setUp(self):
        self.text = LANG_MD.read_text(encoding="utf-8")

    def _assert_named(self, ids, what):
        missing = sorted(i for i in ids if f"`{i}`" not in self.text)
        self.assertEqual(missing, [], f"docs/reference/languages.md does not name these {what}: {missing}")

    def test_analysed_languages_are_listed(self):
        self._assert_named(set(profiles._LANG.values()), "analysed languages (profiles._LANG)")

    def test_named_profiles_are_listed(self):
        self._assert_named({spec[0] for spec in profiles._SPECS}, "named profiles (profiles._SPECS)")

    def test_recognised_but_unanalysed_languages_are_listed(self):
        self._assert_named(set(base.UNANALYZED_LANG.values()), "unanalysed languages (base.UNANALYZED_LANG)")


class LinkIntegrityTests(unittest.TestCase):
    def test_relative_links_and_anchors_resolve(self):
        broken = []
        for page in _user_docs() + sorted(I18N.rglob("*.md")):
            for target in _links(page.read_text(encoding="utf-8")):
                if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):  # http:, https:, mailto: …
                    continue
                file_part, _, anchor = target.partition("#")
                dest = page if not file_part else (page.parent / file_part).resolve()
                rel = page.relative_to(REPO)
                if not dest.exists():
                    broken.append(f"{rel}: missing target {target}")
                    continue
                if anchor and dest.suffix == ".md" and anchor not in _anchors(dest):
                    broken.append(f"{rel}: no heading for #{anchor} in {dest.relative_to(REPO)}")
        self.assertEqual(broken, [], "\n".join(broken))

    def test_absolute_repo_links_in_the_readme_resolve(self):
        # README links are absolute so they also work on PyPI, where relative links do not resolve;
        # that takes them out of the relative-link check above, so bind them to the tree here.
        prefix = r"https://github\.com/raccioly/websec-validator/(?:blob|tree)/main/"
        missing = []
        for page in [REPO / "README.md"] + sorted(I18N.rglob("*.md")):
            for m in re.finditer(prefix + r"([^)#\s\"]+)(?:#([^)\s\"]+))?", page.read_text(encoding="utf-8")):
                dest = REPO / m.group(1)
                if not dest.exists():
                    missing.append(f"{page.relative_to(REPO)}: {m.group(1)}")
                elif m.group(2) and dest.suffix == ".md" and m.group(2) not in _anchors(dest):
                    missing.append(f"{page.relative_to(REPO)}: no heading #{m.group(2)} in {m.group(1)}")
        self.assertEqual(missing, [], "\n".join(missing))

    def test_docs_urls_in_shipped_code_resolve(self):
        # The CLI and skills point users at docs pages; moving a page must not strand those pointers.
        pattern = re.compile(r"github\.com/raccioly/websec-validator/(?:blob|tree)/main/([\w./-]+)")
        missing = []
        for root in ("src", "skills", "hooks"):
            for path in sorted((REPO / root).rglob("*")):
                if path.suffix not in {".py", ".md", ".json", ".sh"} or not path.is_file():
                    continue
                for m in pattern.finditer(path.read_text(encoding="utf-8", errors="replace")):
                    if not (REPO / m.group(1).rstrip(".")).exists():
                        missing.append(f"{path.relative_to(REPO)}: {m.group(1)}")
        self.assertEqual(missing, [], "\n".join(missing))

    def test_every_docs_page_is_reachable_from_the_hub(self):
        hub_targets = {(HUB.parent / t.partition("#")[0]).resolve()
                       for t in _links(HUB.read_text(encoding="utf-8")) if not re.match(r"^\w+:", t)}
        orphans = []
        for page in sorted(DOCS.rglob("*.md")):
            rel = page.relative_to(DOCS).as_posix()
            if page == HUB or rel.startswith(HUB_EXEMPT):
                continue
            if page.resolve() not in hub_targets:
                orphans.append(rel)
        self.assertEqual(orphans, [], f"docs pages not linked from docs/README.md: {orphans}")


class NoStrandedPinsTests(unittest.TestCase):
    """A pinned release in a guide is correct for one release and wrong forever after.

    Guides show placeholders (`<reviewed-commit-sha>`) instead; dated records such as the
    migration notes and the changelog are allowed to name the versions they are about.
    """

    PIN = re.compile(r"websec-validator\s*==\s*\d|websec-validator@v?\d+\.\d+|"
                     r"raccioly/websec-validator@v?\d+\.\d+|^\s*rev:\s*v?\d+\.\d+", re.M)

    def test_no_release_pins_in_guides(self):
        pinned = []
        for page in sorted(DOCS.rglob("*.md")):
            rel = page.relative_to(DOCS).as_posix()
            if rel.startswith(HUB_EXEMPT):
                continue
            for block in _code_blocks(page.read_text(encoding="utf-8"),
                                      langs=("bash", "sh", "shell", "yaml", "yml", "json", "toml", "")):
                for m in self.PIN.finditer(block):
                    pinned.append(f"{rel}: {m.group(0).strip()}")
        self.assertEqual(pinned, [], "use a placeholder such as <reviewed-commit-sha>:\n" + "\n".join(pinned))


class TranslationTests(unittest.TestCase):
    BANNER = re.compile(r"English[^\n]*authoritative[^\n]*v\d+\.\d+\.\d+|"
                        r"v\d+\.\d+\.\d+[^\n]*English[^\n]*authoritative", re.I)

    def _translations(self):
        return sorted(I18N.rglob("*.md")) if I18N.exists() else []

    def test_translations_exist_and_declare_their_source(self):
        pages = self._translations()
        self.assertTrue(pages, "no translations under docs/i18n/")
        for page in pages:
            head = "\n".join(page.read_text(encoding="utf-8").splitlines()[:15])
            self.assertRegex(head, self.BANNER,
                             f"{page.relative_to(REPO)} must state, in English, that English is "
                             "authoritative and which release it was translated from")

    def test_readme_links_every_translated_readme(self):
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        for page in self._translations():
            if page.name == "README.md":
                rel = page.relative_to(REPO).as_posix()
                self.assertIn(rel, readme, f"README.md does not link the translation {rel}")


if __name__ == "__main__":
    unittest.main()

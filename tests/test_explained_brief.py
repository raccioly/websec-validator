"""The technical brief (docs/websec-explained.html) must not drift from the tree it describes.

The brief is a public, self-contained HTML document that quotes concrete numbers: extractor
and sink counts, corpus pins, proof results, field-review totals, CI facts. Prose rots
silently; a number that was true at 0.17.1 reads as a lie two releases later. So every
number the brief states is re-derived here from its source of truth and compared. If the
code changes and the page does not, this file fails, and the fix is to update the page.

Two numbers are deliberately checked as floors rather than equalities: the test count and
the file count. The suite only grows between releases (the derived test floor in CI enforces
that), so a stated count that is at or below the real one is honest ("at the time of
writing"); a stated count ABOVE the real one would be the lie.

The page is parsed lexically (stdlib html.parser) — no external dependency, per the
project's zero-runtime-dependency rule, which the brief itself asserts.
"""
from __future__ import annotations

import json
import re
import unittest
from html.parser import HTMLParser
from pathlib import Path

from websec_validator import attest, calibration, cli, scanners
from websec_validator.extractors import REGISTRY
from websec_validator.extractors.surface import SINKS

REPO = Path(__file__).resolve().parent.parent
BRIEF = REPO / "docs" / "websec-explained.html"
PKG = REPO / "src" / "websec_validator"

# The version the brief was written at. It is NOT required to equal pyproject's current
# version — the weekly release-propose workflow bumps pyproject without touching docs, and a
# hard equality would fail every release PR. It IS required to be a version that shipped.
STATED_VERSION = "0.17.1"


class _Text(HTMLParser):
    """Collect visible text and the sink chips; drop <style> and comments."""

    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self.chips: list[str] = []
        self._skip = False
        self._in_chip = False

    def handle_starttag(self, tag, attrs):
        if tag == "style":
            self._skip = True
        if tag == "span" and ("class", "chip") in attrs:
            self._in_chip = True

    def handle_endtag(self, tag):
        if tag == "style":
            self._skip = False
        if tag == "span":
            self._in_chip = False

    def handle_data(self, data):
        if self._skip:
            return
        self.parts.append(data)
        if self._in_chip:
            self.chips.append(data.strip())


def _load() -> tuple[str, list[str]]:
    p = _Text()
    p.feed(BRIEF.read_text(encoding="utf-8"))
    return " ".join(" ".join(p.parts).split()), p.chips


TEXT, CHIPS = _load()


def _has(fragment: str) -> bool:
    return fragment in TEXT


class BriefIsSelfContained(unittest.TestCase):
    def test_no_scripts_and_no_external_requests(self):
        raw = BRIEF.read_text(encoding="utf-8")
        self.assertNotIn("<script", raw)
        self.assertIsNone(re.search(r'(?:src|href)="https?://', raw), "the brief must not load remote resources")

    def test_stated_version_shipped_and_is_current_in_masthead(self):
        changelog = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"## [{STATED_VERSION}]", changelog)
        self.assertTrue(_has(f"Technical Brief · v{STATED_VERSION}"))
        releases = len(re.findall(r"^## \[\d+\.\d+", changelog, flags=re.M))
        self.assertTrue(_has("twenty-seven releases"), "release count wording drifted")
        self.assertEqual(releases, 27)
        breaking = changelog.count("### Changed — BREAKING")
        self.assertEqual(breaking, 1, "the brief says 'one breaking change'")


class BriefMatchesDetectionPipeline(unittest.TestCase):
    def test_extractor_count_and_names(self):
        self.assertEqual(len(REGISTRY), 22)
        self.assertTrue(_has("Twenty-two extractors"))
        raw = BRIEF.read_text(encoding="utf-8")
        fig = raw[raw.index("Fig. 5") - 12000 : raw.index("Fig. 5")]
        for ex in REGISTRY:
            self.assertIn(f">{ex.name}<", fig, f"extractor {ex.name!r} missing from Fig. 5")

    def test_sink_classes(self):
        self.assertEqual(len(SINKS), 17)
        self.assertTrue(_has("seventeen sink classes"))
        self.assertEqual(sorted(CHIPS), sorted(SINKS.keys()))

    def test_exit_code_contract(self):
        self.assertEqual((cli.EXIT_OK, cli.EXIT_FINDINGS, cli.EXIT_USAGE, cli.EXIT_INCOMPLETE), (0, 1, 2, 3))
        for label in ("exit 3 · incomplete", "exit 2 · usage", "exit 1 · findings", "exit 0 · clean"):
            self.assertTrue(_has(label), label)

    def test_calibration_is_quarantined_at_runtime(self):
        shipped = json.loads((PKG / "calibration.json").read_text(encoding="utf-8"))
        self.assertEqual(shipped["meta"]["n_total"], 59)
        self.assertTrue(_has("59 historical samples"))
        loaded = calibration.load_shipped()
        self.assertIsInstance(loaded, dict)
        self.assertEqual(loaded["meta"].get("evidence_status"), "historical-quarantined")
        self.assertEqual(loaded["meta"].get("n_total"), 0)

    def test_attest_rows_and_empty_evidence(self):
        rows = attest._CONTROLS
        empty = sum(1 for r in rows if not r[3])
        self.assertEqual((len(rows), empty), (12, 5))
        self.assertTrue(_has("12 control rows; 5 carry an empty evidence list"))


class BriefMatchesEvidence(unittest.TestCase):
    def test_corpus_pins(self):
        corpus = json.loads((PKG / "corpus.json").read_text(encoding="utf-8"))
        self.assertEqual([a["name"] for a in corpus], ["VAmPI", "NodeGoat", "DVGA"])
        for app in corpus:
            self.assertTrue(_has(f"{app['name']} {app['revision'][:7]}"), app["name"])
            self.assertEqual(app["revision_provenance"]["retrieved_date"], "2026-09-12")
        self.assertTrue(_has("retrieved 2026-09-12"))

    def test_proof_numbers(self):
        proof = json.loads((REPO / "docs/security-review/public-proof-0.14.0.json").read_text(encoding="utf-8"))
        with_noir = proof["runs"]["with_noir"]["aggregate"]
        without = proof["runs"]["without_noir"]["aggregate"]
        self.assertEqual((with_noir["checks_passed"], with_noir["checks_total"]), (10, 10))
        self.assertEqual((without["checks_passed"], without["checks_total"]), (8, 10))
        self.assertEqual(with_noir["unknown_labels"], 7)
        self.assertTrue(_has("10/10 surface checks with Noir present and 8/10 without it, with 7 truth labels left unknown"))

    def test_public_review_totals_and_pins(self):
        review = (REPO / "docs/security-review/public-repository-review.md").read_text(encoding="utf-8")
        rows = re.findall(r"^\| \[([^\]]+)\]\([^)]+\) \| `([0-9a-f]{40})` \| (\d+) \|", review, flags=re.M)
        self.assertEqual(len(rows), 6, "six repositories")
        leads = sum(int(n) for _, _, n in rows)
        self.assertEqual(leads, 116)
        self.assertIn("zero verified critical", review)
        self.assertTrue(_has("Six public repositories, 116 leads, zero verified critical issues"))
        for name, sha, n in rows:
            self.assertTrue(_has(f"{sha[:7]} · {n}"), f"{name}: expected '{sha[:7]} · {n}' in Fig. 6")

    def test_precision_regression_tests(self):
        src = (REPO / "tests/test_public_precision.py").read_text(encoding="utf-8")
        n = len(re.findall(r"^\s*def test_", src, flags=re.M))
        self.assertEqual(n, 10)
        self.assertTrue(_has("3 → 10"))


class BriefMatchesSelfGuarding(unittest.TestCase):
    def test_required_checks(self):
        req = json.loads((REPO / ".github/required-checks.json").read_text(encoding="utf-8"))["required"]
        self.assertEqual(len(req), 5)
        self.assertIn("hermeticity (hostile git config)", req)
        self.assertIn("suite-integrity", req)
        self.assertEqual(sum(1 for r in req if r.startswith("tests (py3.")), 3)

    def test_ci_ceiling_and_hermeticity_keys(self):
        ci = (REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("MAX_SECONDS: 60", ci)
        self.assertTrue(_has("Why sixty seconds"))
        for key in ("core.hooksPath", "commit.gpgsign", "core.excludesFile", "init.defaultBranch trunk"):
            self.assertIn(key, ci, key)
        tag = (REPO / ".github/workflows/release-tag.yml").read_text(encoding="utf-8")
        self.assertIn("startsWith(github.event.head_commit.message, 'release:')", tag)
        publish = (REPO / ".github/workflows/publish.yml").read_text(encoding="utf-8")
        self.assertIn("id-token: write", publish)

    def test_suite_size_is_a_floor_not_a_lie(self):
        # Stated as "at the time of writing"; counted the way CI counts it (the unittest loader).
        loader = unittest.TestLoader()
        actual = loader.discover(str(REPO / "tests"), top_level_dir=str(REPO / "tests")).countTestCases()
        stated = re.search(r"([\d,]+) tests across (\d+) files", TEXT)
        self.assertIsNotNone(stated, "stat band wording drifted")
        stated_tests = int(stated.group(1).replace(",", ""))
        stated_files = int(stated.group(2))
        self.assertLessEqual(stated_tests, actual, "the brief claims more tests than exist")
        self.assertLessEqual(stated_files, len(list((REPO / "tests").glob("test_*.py"))))
        self.assertGreaterEqual(actual - stated_tests, 0)

    def test_docs_guarding_facts(self):
        cfg = json.loads((REPO / ".docguard.json").read_text(encoding="utf-8"))["validators"]
        self.assertTrue(_has(f"{sum(cfg.values())} of its {len(cfg)} validators on"))
        evidence = json.loads((REPO / ".docguard-evidence.json").read_text(encoding="utf-8"))["declarations"]
        self.assertEqual(len(evidence), 5)
        self.assertTrue(_has("Five sentences in the validation record are bound to JSON pointers"))
        canonical = json.loads((REPO / ".docguard.json").read_text(encoding="utf-8"))["requiredFiles"]["canonical"]
        self.assertEqual(sum(1 for c in canonical if c.startswith("docs-canonical/")), 4)
        field = (REPO / "tests/test_field_report_2026_09.py").read_text(encoding="utf-8")
        n_field = len(re.findall(r"^\s*def test_", field, flags=re.M))
        self.assertTrue(_has(f"They became {n_field} tests in one file"), f"field-report test count drifted (now {n_field})")
        self.assertIn("paired with a", field)
        pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("dependencies = []", pyproject)


class BriefMatchesSurfacesAndStandards(unittest.TestCase):
    def test_surfaces(self):
        self.assertEqual(len(scanners.REGISTRY), 11)
        self.assertTrue(_has("Eleven registry entries"))
        raw = (PKG / "mcp_server.py").read_text(encoding="utf-8")
        tools = sorted(set(re.findall(r'"(websec_[a-z_]+)"', raw)))
        self.assertEqual(tools, ["websec_briefing", "websec_findings", "websec_recon", "websec_sarif"])
        self.assertTrue(_has("Four read-only tools"))
        probes = list((PKG / "templates/probes").iterdir())
        self.assertEqual(len(probes), 24)
        self.assertTrue(_has("probes from 24 templates"))
        docker = (REPO / "Dockerfile").read_text(encoding="utf-8")
        for pin in ("NOIR_VERSION=1.0.0", "GITLEAKS_VERSION=8.30.1", "TRIVY_VERSION=0.74.0", "FROM python:3.14-slim"):
            self.assertIn(pin, docker, pin)
        self.assertTrue(_has("Noir 1.0.0, Gitleaks 8.30.1 and Trivy 0.74.0"))
        for sc in scanners.REGISTRY:  # every registry entry is named on the scanner page
            short = sc.name.split(" (")[0]
            self.assertTrue(_has(short), f"scanner {sc.name!r} missing from the brief")
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        for artifact in ("AGENT-BRIEFING.md", "FACTS.json", "findings-ledger.json", "results.sarif"):
            self.assertIn(f"`{artifact}`", readme, artifact)
            self.assertTrue(_has(artifact), artifact)
        hooks = (REPO / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
        self.assertIn("--require-complete", hooks)
        self.assertIn("high", hooks)

    def test_standards_map_and_cwe_count(self):
        method = (REPO / "docs/METHODOLOGY.md").read_text(encoding="utf-8")
        start = method.index("## Standards coverage")
        end = method.index("\n## ", start + 5)
        section = method[start:end]
        table_lines = [ln for ln in section.splitlines() if ln.startswith("|")]
        rows = len(table_lines) - 2  # header + separator
        self.assertTrue(_has(f"{rows}-row table"), f"the brief's standards-map row count drifted (now {rows})")
        cwes = set(re.findall(r"CWE-\d+", (PKG / "findings.py").read_text(encoding="utf-8")))
        self.assertTrue(_has(f"cites {len(cwes)} distinct CWEs"), f"CWE count drifted (now {len(cwes)})")


if __name__ == "__main__":
    unittest.main()

"""Tests for the reachability + exploitability enrichers (deterministic, offline, ADDITIVE)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from websec_validator import enrichment  # noqa: E402


def _repo(files: dict) -> Path:
    d = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return d


class ReachabilityTests(unittest.TestCase):
    def test_npm_imported_vs_declared_only(self):
        d = _repo({"src/a.js": "const _ = require('lodash');\nimport x from '@babel/parser';\n"})
        findings = [
            {"category": "sca", "pkg": "lodash", "ecosystem": "npm", "severity": "HIGH", "title": "lodash"},
            {"category": "sca", "pkg": "@babel/parser", "ecosystem": "npm", "severity": "LOW", "title": "babel"},
            {"category": "sca", "pkg": "moment", "ecosystem": "npm", "severity": "MEDIUM", "title": "moment"},
        ]
        summary = enrichment.enrich_reachability(findings, d)
        by = {f["pkg"]: f for f in findings}
        self.assertEqual(by["lodash"]["reachability"], "imported")
        self.assertEqual(by["@babel/parser"]["reachability"], "imported")   # scoped pkg root match
        self.assertEqual(by["moment"]["reachability"], "no-import-found")
        self.assertIn("declared-only", by["moment"]["title"])
        self.assertEqual(summary, {"analyzed": 3, "imported": 2, "declared_only": 1, "not_analyzed": 0})

    def test_pip_alias_and_dash_underscore(self):
        d = _repo({"app.py": "import yaml\nfrom dateutil import parser\nimport my_pkg\n"})
        findings = [
            {"category": "sca", "pkg": "PyYAML", "ecosystem": "pip", "severity": "HIGH", "title": "pyyaml"},
            {"category": "sca", "pkg": "python-dateutil", "ecosystem": "pip", "severity": "LOW", "title": "du"},
            {"category": "sca", "pkg": "my-pkg", "ecosystem": "pip", "severity": "LOW", "title": "mp"},
            {"category": "sca", "pkg": "unused-lib", "ecosystem": "pip", "severity": "LOW", "title": "ul"},
        ]
        enrichment.enrich_reachability(findings, d)
        by = {f["pkg"]: f["reachability"] for f in findings}
        self.assertEqual(by["PyYAML"], "imported")            # alias pyyaml→yaml
        self.assertEqual(by["python-dateutil"], "imported")   # python- prefix + dateutil
        self.assertEqual(by["my-pkg"], "imported")            # dash→underscore
        self.assertEqual(by["unused-lib"], "no-import-found")

    def test_unparsed_ecosystem_makes_no_claim(self):
        d = _repo({"main.go": "package main\n"})
        findings = [{"category": "sca", "pkg": "somelib", "ecosystem": "gomod",
                     "severity": "HIGH", "title": "somelib"}]
        enrichment.enrich_reachability(findings, d)
        self.assertEqual(findings[0]["reachability"], "n/a")   # never a false declared-only
        self.assertNotIn("declared-only", findings[0]["title"])

    def test_additive_never_changes_severity_or_count(self):
        d = _repo({"a.js": "// nothing imported\n"})
        findings = [{"category": "sca", "pkg": "moment", "ecosystem": "npm",
                     "severity": "CRITICAL", "title": "moment"}]
        enrichment.enrich_reachability(findings, d)
        self.assertEqual(len(findings), 1)                     # no drop / add
        self.assertEqual(findings[0]["severity"], "CRITICAL")  # severity untouched

    def test_non_sca_findings_ignored(self):
        d = _repo({"a.js": "x\n"})
        findings = [{"category": "secret", "title": "leaked key"}]
        summary = enrichment.enrich_reachability(findings, d)
        self.assertNotIn("reachability", findings[0])
        self.assertEqual(summary["analyzed"], 0)


class ExploitabilityTests(unittest.TestCase):
    def _cache(self, epss_rows="", kev_ids=()):
        d = Path(tempfile.mkdtemp())
        if epss_rows:
            (d / "epss.csv").write_text("cve,epss,percentile\n" + epss_rows)
        if kev_ids:
            (d / "kev.json").write_text(json.dumps(
                {"vulnerabilities": [{"cveID": c} for c in kev_ids]}))
        return d

    def test_kev_and_high_epss_annotated(self):
        cache = self._cache("CVE-2021-23337,0.9,0.99\nCVE-2000-1,0.01,0.1\n", ["CVE-2021-23337"])
        findings = [
            {"category": "sca", "cve": "CVE-2021-23337", "severity": "HIGH", "title": "lodash"},
            {"category": "sca", "cve": "CVE-2000-1", "severity": "LOW", "title": "old"},
        ]
        summary = enrichment.enrich_exploitability(findings, cache)
        self.assertTrue(summary["available"])
        self.assertEqual(summary["kev"], 1)
        self.assertEqual(summary["high_epss"], 1)
        by = {f["cve"]: f for f in findings}
        self.assertTrue(by["CVE-2021-23337"]["kev"])
        self.assertEqual(by["CVE-2021-23337"]["epss"], 0.9)
        self.assertIn("KEV", by["CVE-2021-23337"]["title"])
        self.assertNotIn("kev", by["CVE-2000-1"])              # low finding not KEV
        self.assertEqual(by["CVE-2000-1"]["severity"], "LOW")  # severity untouched

    def test_absent_cache_skips_gracefully(self):
        empty = Path(tempfile.mkdtemp())
        findings = [{"category": "sca", "cve": "CVE-2021-23337", "severity": "HIGH", "title": "x"}]
        summary = enrichment.enrich_exploitability(findings, empty)
        self.assertFalse(summary["available"])
        self.assertNotIn("epss", findings[0])                  # nothing added, no crash

    def test_non_cve_keys_ignored(self):
        cache = self._cache("CVE-2021-23337,0.9,0.99\n")
        findings = [{"category": "secret", "key": "aws-key", "title": "secret"}]
        enrichment.enrich_exploitability(findings, cache)
        self.assertNotIn("epss", findings[0])




class NoImportsReadableTests(unittest.TestCase):
    def test_unreadable_tree_makes_no_reachability_claim(self):
        # If no import can be read at all, claiming "no import found" would silently de-prioritise
        # EVERY CVE — including CRITICAL/KEV ones — as likely-unreachable.
        findings = [{"category": "sca", "pkg": "lodash", "ecosystem": "npm",
                     "severity": "CRITICAL", "title": "lodash"}]
        summary = enrichment.enrich_reachability(findings, "/nonexistent-path-xyz-123")
        self.assertEqual(findings[0]["reachability"], "n/a")
        self.assertNotIn("declared-only", findings[0]["title"])
        self.assertEqual(summary["declared_only"], 0)

if __name__ == "__main__":
    unittest.main()

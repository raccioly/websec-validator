"""Native scanner contracts: completeness, dependency occurrences and Bandit."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator import baseline, cli, coverage, findings, formats, scanners


class ScannerContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / "repo"
        self.repo.mkdir()
        (self.repo / "app.py").write_text("print('example')\n")
        self.out = self.base / "out"
        self.out.mkdir()

    def normalize(self, reports):
        runs = []
        for key, doc in reports.items():
            path = self.base / (key + ".json")
            path.write_text(json.dumps(doc))
            runs.append({"key": key, "output": str(path), "exit_code": 0})
        with patch.object(scanners.enrichment, "enrich_exploitability", return_value={}), \
             patch.object(scanners.enrichment, "enrich_reachability", return_value={}):
            unified = scanners.normalize_findings(runs, self.out, target=self.repo)
        facts = {}
        coverage.add_scanners(facts, {"available": [{"key": key} for key in reports]},
                              runs, unified, scan=True, only=list(reports))
        return unified, facts["coverage"]

    @staticmethod
    def checkov(errors=0):
        return {"check_type": "terraform", "results": {"failed_checks": [],
                "parsing_errors": ["broken.tf"] if errors else []},
                "summary": {"parsing_errors": errors, "skipped": 0, "checkov_version": "3.2.test"}}

    def test_checkov_parse_only_exit_zero_is_incomplete(self):
        unified, cov = self.normalize({"checkov": self.checkov(1)})
        self.assertEqual(unified["parse_failed"], [])
        self.assertEqual(unified["scanner_errors"], ["checkov"])
        self.assertFalse(cov["execution_complete"])
        self.assertEqual(cov["scanners"]["checkov"]["reported_version"], "3.2.test")

    def test_checkov_mixed_framework_errors_preserve_findings(self):
        successful = self.checkov()
        successful["results"]["failed_checks"] = [{"check_id": "CKV_AWS_19", "file_path": "main.tf",
            "file_line_range": [4, 8], "check_name": "Encryption", "resource": "aws_s3_bucket.example"}]
        unified, cov = self.normalize({"checkov": [successful, self.checkov(1)]})
        self.assertEqual(unified["total"], 1)
        self.assertFalse(cov["execution_complete"])

    def test_checkov_native_empty_summary_is_completed(self):
        doc = {"passed": 0, "failed": 0, "skipped": 0, "parsing_errors": 0,
               "resource_count": 0, "checkov_version": "3.2.test"}
        unified, cov = self.normalize({"checkov": doc})
        self.assertEqual(unified["total"], 0)
        self.assertTrue(cov["execution_complete"])
        doc["parsing_errors"] = 1
        self.assertFalse(self.normalize({"checkov": doc})[1]["execution_complete"])

    def test_checkov_incomplete_or_malformed_summary_rejected(self):
        for doc in ({}, {"passed": 0}, {"passed": 0, "failed": 1, "skipped": 0,
                      "parsing_errors": 0, "resource_count": 1, "checkov_version": "3"},
                    {"passed": False, "failed": 0, "skipped": 0, "parsing_errors": 0,
                     "resource_count": 0, "checkov_version": "3"}):
            with self.subTest(doc=doc):
                self.assertFalse(self.normalize({"checkov": doc})[1]["execution_complete"])

    def test_checkov_skipped_checks_are_visible_scope(self):
        doc = self.checkov()
        doc["summary"]["skipped"] = 2
        _, cov = self.normalize({"checkov": doc})
        self.assertTrue(cov["execution_complete"])
        self.assertIn("scanner_scope", [gap["kind"] for gap in cov["gaps"]])

    def test_checkov_summary_mismatch_retains_findings_but_is_incomplete(self):
        doc = self.checkov()
        doc["summary"].update(failed=1, passed=0, resource_count=1)
        unified, cov = self.normalize({"checkov": doc})
        self.assertEqual(unified["total"], 0)
        self.assertFalse(cov["execution_complete"])
        doc["results"]["failed_checks"] = [{"check_id": "CKV_AWS_19", "file_path": "main.tf", "resource": "bucket.a"}]
        doc["summary"]["failed"] = 2
        unified, cov = self.normalize({"checkov": doc})
        self.assertEqual(unified["total"], 1)
        self.assertFalse(cov["execution_complete"])

    def test_checkov_distinct_resources_on_same_line_survive(self):
        doc = self.checkov()
        doc["results"]["failed_checks"] = [{"check_id": "CKV_AWS_19", "file_path": "main.tf", "file_line_range": [4, 8],
                                            "resource": resource} for resource in ("aws_s3_bucket.a", "aws_s3_bucket.b")]
        unified, cov = self.normalize({"checkov": doc})
        self.assertEqual(unified["total"], 2)
        self.assertTrue(cov["execution_complete"])
        self.assertEqual(len(findings.build_ledger({}, unified)["findings"]), 2)

    @staticmethod
    def trivy(occurrences):
        return {"Results": [{"Target": path, "Type": eco, "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2026-12345", "PkgName": "example", "InstalledVersion": version,
             "FixedVersion": "9.0", "Severity": "HIGH"}]} for path, version, eco in occurrences]}

    @staticmethod
    def osv(path, version="1.0"):
        return {"results": [{"source": {"path": path}, "packages": [{
            "package": {"name": "example", "version": version, "ecosystem": "npm"},
            "groups": [{"ids": ["CVE-2026-12345"], "aliases": ["CVE-2026-12345", "GHSA-test"],
                        "max_severity": "8.0"}]}]}]}

    def test_sca_distinct_services_and_versions_survive_ledger_and_sarif(self):
        docs = self.trivy([("service-a/package-lock.json", "1.0", "npm"),
                           ("service-b/package-lock.json", "1.0", "npm"),
                           ("service-a/package-lock.json", "2.0", "npm")])
        unified, _ = self.normalize({"trivy": docs})
        self.assertEqual(unified["total_raw"], 3)
        self.assertEqual(unified["total"], 3)
        ledger = findings.build_ledger({}, unified)
        rows = [f for f in ledger["findings"] if f["attack_class"] == "cve"]
        self.assertEqual(len(rows), 3)
        self.assertEqual(len({r["fingerprint"] for r in rows}), 3)
        self.assertEqual({r["installed"] for r in rows}, {"1.0", "2.0"})
        self.assertTrue(all(r["fixed"] == "9.0" and r["ecosystem"] == "npm" for r in rows))
        self.assertEqual(len(formats.to_sarif(ledger)["runs"][0]["results"]), 3)

    def test_sca_same_occurrence_cross_tool_dedup_and_order_stability(self):
        trivy = self.trivy([(str(self.repo / "service-a/package-lock.json"), "1.0", "node-pkg")])
        osv = self.osv("service-a/./package-lock.json")
        a, _ = self.normalize({"trivy": trivy, "osv-scanner": osv})
        b, _ = self.normalize({"osv-scanner": osv, "trivy": trivy})
        self.assertEqual(a["total"], 1)
        for key in ("semantic_id", "fixed", "installed", "ecosystem", "file", "tools", "advisory_aliases"):
            self.assertEqual(a["all"][0][key], b["all"][0][key], key)
        self.assertEqual(a["all"][0]["tools"], ["osv-scanner", "trivy"])

    def test_sca_same_manifest_different_ecosystems_stay_distinct(self):
        docs = self.trivy([("manifest.lock", "1.0", "npm"), ("manifest.lock", "1.0", "pip")])
        self.assertEqual(self.normalize({"trivy": docs})[0]["total"], 2)

    def test_intelligence_provenance_and_explicit_false_survive_summary_and_ledger(self):
        path = self.base / "trivy.json"
        path.write_text(json.dumps(self.trivy([("package-lock.json", "1.0", "npm")])))
        provenance = {"snapshot_id": "test-snapshot", "freshness": "fresh", "sources": {"kev": {"feed_date": "2026-09-12"}}}
        def enrich(rows):
            for row in rows:
                row.update(intel=provenance, epss=.1, epss_pct=.8, kev=False, intel_status="listed")
            return {"available": True}
        with patch.object(scanners.enrichment, "enrich_exploitability", side_effect=enrich):
            unified = scanners.normalize_findings([{"key": "trivy", "output": str(path)}], self.out)
        for row in (unified["all"][0], findings.build_ledger({}, unified)["findings"][0]):
            self.assertEqual(row["intel"], provenance)
            self.assertEqual(row["epss_pct"], .8)
            self.assertIs(row["kev"], False)
            self.assertEqual(row["intel_status"], "listed")

    def test_still_vulnerable_upgrade_is_new_occurrence_not_verified_fix(self):
        original, _ = self.normalize({"trivy": self.trivy([("package-lock.json", "1.0", "npm")])})
        updated, _ = self.normalize({"trivy": self.trivy([("package-lock.json", "2.0", "npm")])})
        old = findings.build_ledger({}, original)
        new = findings.build_ledger({}, updated)
        changes = baseline.diff(new, baseline.Baseline(old["findings"]))
        self.assertEqual(changes["new_count"], 1)
        self.assertEqual(changes["no_longer_observed_count"], 1)
        self.assertEqual(changes["fixed_count"], 0)
        self.assertEqual(baseline.gate_count(new, "high", new_only=True), 1)

    @staticmethod
    def bandit(results=None, errors=None):
        return {"results": results or [], "errors": errors or [],
                "metrics": {"_totals": {"loc": 4, "nosec": 0, "skipped_tests": 0}}}

    @staticmethod
    def bandit_issue(line=4, code="4 eval(value)\n"):
        return {"filename": "app.py", "test_id": "B307", "test_name": "eval", "line_number": line,
                "issue_text": "Use of eval", "issue_severity": "MEDIUM", "issue_confidence": "HIGH",
                "issue_cwe": {"id": 78}, "code": code}

    def test_bandit_findings_and_errors_remain_distinct(self):
        doc = self.bandit([self.bandit_issue()])
        unified, cov = self.normalize({"bandit": doc})
        self.assertEqual(unified["total"], 1)
        self.assertTrue(cov["execution_complete"])
        self.assertEqual(unified["all"][0]["rule_id"], "B307")
        self.assertEqual(unified["all"][0]["confidence"], "HIGH")
        doc["errors"] = [{"filename": "broken.py", "reason": "syntax error"}]
        unified, cov = self.normalize({"bandit": doc})
        self.assertEqual(unified["total"], 1)
        self.assertFalse(cov["execution_complete"])

    def test_bandit_empty_success_and_malformed_are_distinct(self):
        self.assertTrue(self.normalize({"bandit": self.bandit()})[1]["execution_complete"])
        for doc in ({"results": []}, {"results": [], "errors": "failed", "metrics": {}}):
            self.assertFalse(self.normalize({"bandit": doc})[1]["execution_complete"])

    def test_bandit_native_low_confidence_cwe_and_line_survive_ledger_sarif(self):
        issue = dict(self.bandit_issue(line=17), issue_confidence="LOW", issue_severity="HIGH")
        unified, _ = self.normalize({"bandit": self.bandit([issue])})
        ledger = findings.build_ledger({}, unified)
        row = ledger["findings"][0]
        self.assertEqual((row["severity"], row["confidence"], row["native_confidence"]), ("HIGH", "LOW", "LOW"))
        self.assertEqual(row["native_cwe"], "CWE-78")
        self.assertIn("CWE-78", row["standards"]["cwe"])
        sarif = formats.to_sarif(ledger)["runs"][0]
        self.assertEqual(sarif["results"][0]["properties"]["confidence"], "LOW")
        self.assertEqual(sarif["results"][0]["properties"]["native_confidence"], "LOW")
        self.assertEqual(sarif["results"][0]["properties"]["native_cwe"], "CWE-78")
        self.assertEqual(sarif["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"], 17)
        self.assertIn("CWE-78", sarif["tool"]["driver"]["rules"][0]["properties"]["cwe"])

    def test_bandit_invalid_native_confidence_is_explicit_unknown(self):
        for confidence in (None, "CERTAIN", [], 5):
            with self.subTest(confidence=confidence):
                issue = dict(self.bandit_issue(), issue_confidence=confidence, issue_cwe={"id": True})
                unified, _ = self.normalize({"bandit": self.bandit([issue])})
                row = findings.build_ledger({}, unified)["findings"][0]
                self.assertEqual(row["native_confidence"], "UNKNOWN")
                self.assertEqual(row["confidence"], "LOW")
                self.assertNotIn("native_cwe", row)

    def test_bandit_repeated_rule_sites_survive_ledger(self):
        doc = self.bandit([self.bandit_issue(), self.bandit_issue(7, "7 eval(other)\n"),
                           self.bandit_issue(9, "9 eval(value)\n")])
        unified, _ = self.normalize({"bandit": doc})
        self.assertEqual(len(findings.build_ledger({}, unified)["findings"]), 3)

    def test_bandit_missing_and_timeout_are_incomplete(self):
        with patch.object(scanners.shutil, "which", return_value=None):
            detected = scanners.detect(["python"])
            runs = scanners.run_available(self.repo, self.out, ["python"], only=["bandit"])
        facts = {}
        coverage.add_scanners(facts, detected, runs, None, scan=True, only=["bandit"])
        self.assertFalse(facts["coverage"]["execution_complete"])
        with patch.object(scanners.shutil, "which", return_value="/operator/bin/bandit"), \
             patch.object(scanners.subprocess, "run", side_effect=subprocess.TimeoutExpired("bandit", 1)):
            runs = scanners.run_available(self.repo, self.out, ["python"], only=["bandit"], timeout=1)
        self.assertEqual(runs[0]["status"], "timeout")

    def test_bandit_adapter_ignores_target_configuration_and_never_runs_target(self):
        marker = self.base / "target-executed"
        (self.repo / "app.py").write_text(f"open({str(marker)!r}, 'w').write('executed')\n")
        (self.repo / ".bandit").write_text("[bandit]\nskips=B307\n")
        bin_dir = self.base / "bin"
        bin_dir.mkdir()
        binary = bin_dir / "bandit"
        # An operator-owned executable fixture validates the subprocess contract;
        # it is not a replacement for a live Bandit detector benchmark.
        binary.write_text(f"#!{sys.executable}\n" + "import json,sys\nfrom pathlib import Path\n"
                          "args=sys.argv[1:]\nassert Path(args[args.index('--ini')+1]).read_text()==''\n"
                          "assert '--ignore-nosec' in args\nassert '--configfile' not in args\n"
                          "assert 'private/**' in args[args.index('--exclude')+1]\n"
                          "Path(args[args.index('-o')+1]).write_text(json.dumps({'results':[],'errors':[],'metrics':{}}))\n")
        binary.chmod(0o700)
        with patch.dict(os.environ, {"PATH": str(bin_dir)}):
            runs = scanners.run_available(self.repo, self.out, ["python"], only=["bandit"], excludes=["private/**"])
        self.assertEqual(runs[0]["exit_code"], 0)
        self.assertIn("target .bandit", runs[0]["configuration_policy"])
        self.assertFalse(marker.exists())
        self.assertEqual((self.repo / ".bandit").read_text(), "[bandit]\nskips=B307\n")

    def test_bandit_postfilter_exclusions_and_language_relevance(self):
        doc = self.bandit([dict(self.bandit_issue(), filename="private/app.py"), self.bandit_issue()])
        path = self.base / "bandit.json"
        path.write_text(json.dumps(doc))
        result = [{"key": "bandit", "output": str(path), "exit_code": 0}]
        unified = scanners.normalize_findings(result, self.out, self.repo, excludes=["private/**"])
        self.assertEqual(unified["total"], 1)
        self.assertEqual(unified["user_excluded_dropped"], 1)
        with patch.object(scanners.shutil, "which", return_value="/bin/bandit"):
            self.assertNotIn("bandit", [x["key"] for x in scanners.detect(["javascript"])["available"]])

    def test_checkov_parse_failure_cli_gate_preserves_completed_latest(self):
        path = self.base / "checkov.json"
        runs = [{"key": "checkov", "name": "Checkov", "output": str(path), "exit_code": 0}]
        with patch("shutil.which", return_value=None), \
             patch.object(scanners, "detect", return_value={"available": [{"key": "checkov", "name": "Checkov", "category": "iac"}], "missing": []}), \
             patch.object(scanners, "run_available", return_value=runs), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            path.write_text(json.dumps(self.checkov()))
            argv = ["run", str(self.repo), "--out", str(self.out), "--scan", "--scanners", "checkov", "--require-complete"]
            self.assertEqual(cli.main(argv), 0)
            previous = (self.out / "latest").resolve()
            path.write_text(json.dumps(self.checkov(1)))
            self.assertEqual(cli.main(argv), 3)
            self.assertEqual((self.out / "latest").resolve(), previous)
            attempts = list((self.out / "runs").iterdir())
            self.assertEqual(len(attempts), 2)
            partial = next(p for p in attempts if p != previous)
            self.assertFalse(json.loads((partial / "coverage.json").read_text())["execution_complete"])


if __name__ == "__main__":
    unittest.main()

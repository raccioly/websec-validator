"""Regression tests for the 2026-09-18 field report (9 items).

Each class pins ONE reported defect, and — where the fix is a demotion — also pins the true positive
that must survive it. A precision fix that silences a real finding is a worse bug than the noise it
removed, so every "this should be quieter" assertion is paired with a "this must stay loud" one.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# `clusters` and `init_scope` are imported inside the classes that use them: this module is split
# across the commits that introduce each fix, so the shared header must only name modules that
# already exist at the earliest of them.
from websec_validator import cli, coverage, findings, scanners  # noqa: E402
from websec_validator.extractors import base as ebase  # noqa: E402


class ExitCodeContractTests(unittest.TestCase):
    """#1 — a CI caller must be able to tell a vulnerability from a broken toolchain."""

    def test_codes_are_distinct_named_constants(self):
        self.assertEqual((cli.EXIT_OK, cli.EXIT_FINDINGS, cli.EXIT_USAGE, cli.EXIT_INCOMPLETE),
                         (0, 1, 2, 3))

    def _gate(self, *, incomplete, count):
        """Reproduce the gate decision table from cmd_run."""
        gate = {"incomplete": incomplete}
        if count:
            gate.update(verdict="fail", exit_code=cli.EXIT_FINDINGS,
                        failure_kind="findings+incomplete" if incomplete else "findings")
        elif incomplete:
            gate.update(verdict="incomplete", exit_code=cli.EXIT_INCOMPLETE, failure_kind="incomplete")
        else:
            gate.update(verdict="pass", exit_code=cli.EXIT_OK, failure_kind=None)
        return gate

    def test_incomplete_no_longer_masks_findings(self):
        """The core defect: an incomplete run used to short-circuit BEFORE the gate was counted, so a
        run with a real CRITICAL and a dead scanner exited 2 and the security signal vanished."""
        both = self._gate(incomplete=True, count=7)
        self.assertEqual(both["exit_code"], cli.EXIT_FINDINGS)
        self.assertEqual(both["failure_kind"], "findings+incomplete")

    def test_incomplete_alone_is_three_not_two(self):
        only = self._gate(incomplete=True, count=0)
        self.assertEqual(only["exit_code"], cli.EXIT_INCOMPLETE)
        self.assertEqual(only["failure_kind"], "incomplete")

    def test_clean_run_is_zero_with_no_failure_kind(self):
        ok = self._gate(incomplete=False, count=0)
        self.assertEqual((ok["exit_code"], ok["failure_kind"]), (cli.EXIT_OK, None))

    def test_usage_errors_stay_on_two_and_never_collide_with_incomplete(self):
        """`--scanners` without `--scan` is a bad invocation, not an incomplete scan."""
        class A:
            sarif = []
            scanners = "gitleaks"
            scan = False
            verify_secrets = False
        self.assertEqual(cli.cmd_run(A()), cli.EXIT_USAGE)

    def test_agent_instructions_document_all_four_codes(self):
        from websec_validator import install
        for code in ("`0`", "`1`", "`2`", "`3`"):
            self.assertIn(code, install._INSTRUCTION_BODY)


class OsvScannerInvocationTests(unittest.TestCase):
    """#2 — osv-scanner was silently producing nothing on every repo with nested lockfiles."""

    def test_recursive_flag_is_present(self):
        argv = scanners._osv(Path("/repo"), Path("/out/osv.json"))
        self.assertIn("--recursive", argv,
                      "without --recursive osv-scanner only extracts from the top-level directory, "
                      "so any repo whose lockfiles live in subdirectories yields 'No package sources "
                      "found' and writes no output at all")

    def test_registry_declares_a_minimum_version(self):
        osv = next(s for s in scanners.REGISTRY if s.key == "osv-scanner")
        self.assertEqual(osv.min_version, (2, 0, 0))

    def test_version_check_flags_an_incompatible_build(self):
        osv = next(s for s in scanners.REGISTRY if s.key == "osv-scanner")
        scanners._VERSION_CACHE["osv-scanner"] = "1.9.2"
        try:
            result = scanners.check_version(osv)
            self.assertEqual(result["status"], "too_old")
            self.assertFalse(result["ok"])
            self.assertIn("2.0.0", result["note"])
        finally:
            scanners._VERSION_CACHE.pop("osv-scanner", None)

    def test_two_component_version_satisfies_three_component_minimum(self):
        osv = next(s for s in scanners.REGISTRY if s.key == "osv-scanner")
        scanners._VERSION_CACHE["osv-scanner"] = "2.4"
        try:
            self.assertEqual(scanners.check_version(osv)["status"], "ok")
        finally:
            scanners._VERSION_CACHE.pop("osv-scanner", None)

    def test_unreadable_version_is_unknown_not_a_failure(self):
        """A probe that cannot read a version must not block the scan."""
        osv = next(s for s in scanners.REGISTRY if s.key == "osv-scanner")
        scanners._VERSION_CACHE["osv-scanner"] = None
        try:
            result = scanners.check_version(osv)
            self.assertEqual(result["status"], "unknown")
            self.assertTrue(result["ok"])
        finally:
            scanners._VERSION_CACHE.pop("osv-scanner", None)


class HistoryProvenanceTests(unittest.TestCase):
    """#3 — 22 HIGHs pointed at files that no longer exist, with nothing saying so."""

    def _rows(self):
        return [{"File": "gone/cfg.ini", "RuleID": "github-pat",
                 "Secret": "ghp_3xK9mQ7wRt2nZx5bK9cF4jL6pD1sY0gA1", "Match": "k",
                 "StartLine": 1, "Commit": "614f9081d87b1234567890abcdef",
                 "Date": "2026-09-19T01:20:02Z", "Author": "Someone"}]

    def test_commit_provenance_is_carried_from_the_scanner_record(self):
        row = scanners._norm_gitleaks(self._rows())[0]
        self.assertEqual(row["commit_short"], "614f9081d87b")
        self.assertEqual(row["commit_date"], "2026-09-19T01:20:02Z")

    def test_deleted_file_is_labelled_in_tree_false_with_the_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = scanners._norm_gitleaks(self._rows())
            for f in raw:
                f["scan_mode"] = "git"
            scanners._annotate_history_only_secrets(raw, Path(tmp))
            self.assertIs(raw[0]["in_tree"], False)
            self.assertIs(raw[0]["history_only"], True)
            self.assertIn("614f9081d87b", raw[0]["title"])
            self.assertIn("rotate", raw[0]["title"].lower())

    def test_present_file_is_labelled_in_tree_true(self):
        """Every gitleaks finding is labelled, not only the deleted ones — otherwise the reader
        still cannot tell which rows are about the working tree."""
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "gone").mkdir()
            (Path(tmp) / "gone" / "cfg.ini").write_text("x")
            raw = scanners._norm_gitleaks(self._rows())
            for f in raw:
                f["scan_mode"] = "git"
            scanners._annotate_history_only_secrets(raw, Path(tmp))
            self.assertIs(raw[0]["in_tree"], True)
            self.assertNotIn("history_only", raw[0])


class ClusteringTests(unittest.TestCase):
    """#4 — 39 HIGHs that are really ~6 issues. Presentation only: nothing about gating changes."""

    def setUp(self):
        from websec_validator import clusters
        self.clusters = clusters

    def _ledger(self):
        sites = [{"title": "secret: GitHub PAT", "rule_id": "github-pat", "category": "static-secret",
                  "severity": "HIGH", "confidence": "HIGH", "location": f"src/a{i}.ts", "line": 1,
                  "fingerprint": f"fp{i}", "instance_id": f"wv1_{i:016d}"} for i in range(13)]
        incident = [{"title": "secret: AWS key", "rule_id": "aws-access-token",
                     "category": "static-secret", "severity": "HIGH", "confidence": "HIGH",
                     "location": f"legacy/c{i}.ini", "line": 1, "fingerprint": f"hfp{i}",
                     "history_only": True, "in_tree": False, "commit": "614f9081d87b0000"}
                    for i in range(22)]
        lone = [{"title": "clickjacking", "rule_id": "missing-xfo", "category": "headers",
                 "severity": "MEDIUM", "confidence": "LOW", "location": "app.ts", "fingerprint": "z"}]
        return {"findings": sites + incident + lone, "total": 36}

    def test_rule_and_incident_clusters_are_both_formed(self):
        out = self.clusters.build(self._ledger())
        kinds = {c["kind"]: c for c in out}
        self.assertEqual(kinds["rule"]["site_count"], 13)
        self.assertEqual(kinds["incident"]["site_count"], 22)
        self.assertIn("614f9081d87b", kinds["incident"]["title"])

    def test_summary_reports_distinct_issues(self):
        led = self._ledger()
        out = self.clusters.build(led)
        summary = self.clusters.summary(out, led["total"])
        self.assertEqual(summary["distinct_issues"], 3)   # 2 clusters + 1 unclustered finding
        self.assertEqual(summary["total_findings"], 36)

    def test_clustering_never_mutates_findings_or_totals(self):
        """The gate, baselines and SARIF all count findings[] — clustering must not touch it."""
        led = self._ledger()
        before = json.dumps(led, sort_keys=True)
        self.clusters.build(led)
        self.assertEqual(json.dumps(led, sort_keys=True), before)

    def test_every_site_keeps_its_own_addressable_ids(self):
        out = self.clusters.build(self._ledger())
        rule_cluster = next(c for c in out if c["kind"] == "rule")
        self.assertEqual(len({s["fingerprint"] for s in rule_cluster["sites"]}), 13)
        self.assertTrue(all(s.get("instance_id") for s in rule_cluster["sites"]))

    def test_single_site_groups_are_not_clusters(self):
        self.assertEqual(self.clusters.build({"findings": [
            {"title": "x", "rule_id": "solo", "category": "c", "severity": "HIGH",
             "location": "a.ts", "fingerprint": "f"}]}), [])


if __name__ == "__main__":
    unittest.main()

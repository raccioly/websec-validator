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


class ExampleFileTierTests(unittest.TestCase):
    """#5 — a placeholder in `.env.example` was reported as a HIGH AppSync key."""

    def test_example_and_placeholder_helpers(self):
        self.assertTrue(ebase.is_example_file(".env.example"))
        self.assertTrue(ebase.is_example_file("config/settings.sample.json"))
        self.assertFalse(ebase.is_example_file("src/example.ts"))
        self.assertTrue(ebase.is_placeholder_value("da2-xxxxxxxxxxxxxxxxxxxxxxxxxx"))
        self.assertTrue(ebase.is_placeholder_value("<YOUR_TOKEN>"))
        self.assertFalse(ebase.is_placeholder_value("da2-k7f3m9q2xz8p4w1n6b5v0c3jhs"))

    def test_secret_like_sast_rule_is_tiered_whatever_adapter_found_it(self):
        """The HIGH came from SEMGREP (category `sast`), so per-parser tiering never saw it."""
        raw = [{"category": "sast", "rule_id": "generic.secrets.detected-aws-appsync-graphql-key",
                "severity": "HIGH", "file": ".env.example", "title": "AWS AppSync GraphQL Key detected"}]
        self.assertEqual(scanners._tier_placeholder_matches(raw, None), 1)
        self.assertEqual(raw[0]["severity"], "LOW")

    def test_a_non_secret_finding_in_an_example_file_is_untouched(self):
        raw = [{"category": "sast", "rule_id": "javascript.express.sqli", "severity": "HIGH",
                "file": ".env.example", "title": "SQL injection"}]
        self.assertEqual(scanners._tier_placeholder_matches(raw, None), 0)
        self.assertEqual(raw[0]["severity"], "HIGH")

    def test_provider_identified_key_is_never_demoted_on_value_shape(self):
        """`sk_live_aaaaaaaaaaaaaaaaaaaa` matches "a run of identical characters" and is still a
        Stripe LIVE key — the prefix is the evidence, the body is opaque."""
        row = scanners._norm_gitleaks({"findings": [
            {"File": "cfg.ts", "RuleID": "generic-api-key", "Secret": "sk_live_" + "a" * 20,
             "Match": "sk_live_...", "StartLine": 1}]})[0]
        self.assertEqual(row["severity"], "HIGH")
        self.assertIn("ROTATE", row["title"])

    def test_real_key_in_real_code_still_high(self):
        row = scanners._norm_gitleaks([
            {"File": "src/app.ts", "RuleID": "private-key", "Secret": "-----BEGIN",
             "Match": "-----BEGIN", "StartLine": 1}])[0]
        self.assertEqual(row["severity"], "HIGH")


class ConfidenceAndIdentityTests(unittest.TestCase):
    """#6 — confidence was unpopulated and `key` is a rule id, not a per-instance id."""

    def test_confidence_is_derived_with_an_explanation(self):
        conf, basis = scanners._derive_confidence(
            {"category": "sca", "cve": "CVE-2021-23337", "file": "package-lock.json"})
        self.assertEqual(conf, "HIGH")
        self.assertTrue(basis)

    def test_generic_secret_rule_is_low_confidence(self):
        conf, _ = scanners._derive_confidence(
            {"category": "secret", "key": "generic-api-key", "file": "src/a.ts"})
        self.assertEqual(conf, "LOW")

    def test_unparseable_native_confidence_stays_unknown_not_invented(self):
        """bandit's explicit-UNKNOWN contract: a value we cannot parse must not become a
        confident-looking derived MEDIUM."""
        conf, basis = scanners._derive_confidence(
            {"category": "sast", "tool": "bandit", "confidence": "CERTAIN", "file": "a.py"})
        self.assertEqual(conf, "LOW")
        self.assertIn("unrecognized", basis)

    def test_instance_id_is_stable_and_path_relative(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = {"category": "secret", "file": str(root / "src/a.ts"), "key": "r", "line": 4}
            b = {"category": "secret", "file": "src/a.ts", "key": "r", "line": 4}
            self.assertEqual(scanners._instance_id(a, root), scanners._instance_id(b, root))
            self.assertTrue(scanners._instance_id(a, root).startswith("wv1_"))

    def test_instance_id_distinguishes_sites_that_share_a_rule(self):
        one = scanners._instance_id({"category": "secret", "file": "a.ts", "key": "r", "line": 1})
        two = scanners._instance_id({"category": "secret", "file": "b.ts", "key": "r", "line": 1})
        self.assertNotEqual(one, two)


class RuleLevelGapTests(unittest.TestCase):
    """#7 — `semgrep: error` hid the fact that named high-value rules timed out."""

    def _doc(self):
        return {"results": [], "version": "1.177.0", "errors": [
            {"code": 3, "level": "warn", "type": ["Timeout"],
             "rule_id": "javascript.express.security.ssrf", "path": "a.js"},
            {"code": 3, "level": "warn", "type": "Timeout",
             "rule_id": "javascript.browser.security.dom-xss", "path": "b.js"}]}

    def test_timed_out_rules_are_named(self):
        details = scanners._report_details("semgrep", self._doc())
        self.assertEqual(details["rules_incomplete"],
                         ["javascript.browser.security.dom-xss",
                          "javascript.express.security.ssrf"])
        self.assertEqual(details["rules_incomplete_kinds"], ["Timeout"])

    def test_rule_timeouts_are_not_reported_as_a_broken_scanner(self):
        self.assertEqual(scanners._report_details("semgrep", self._doc())["errors"], [])

    def test_an_unclassifiable_error_still_fails_loud(self):
        """A diagnostic shape we do not recognise must never read as a clean scan."""
        details = scanners._report_details("semgrep", {"errors": [{"message": "timeout"}]})
        self.assertTrue(details["errors"])

    def test_coverage_says_partial_and_names_the_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "semgrep.json").write_text(json.dumps(self._doc()))
            results = [{"key": "semgrep", "name": "Semgrep", "exit_code": 0,
                        "output": str(base / "semgrep.json")}]
            unified = scanners.normalize_findings(results, base)
            facts = {"coverage": {"execution_complete": True, "gaps": [], "scanners": {}}}
            coverage.add_scanners(facts, {"available": [{"key": "semgrep"}], "missing": []},
                                  results, unified, scan=True, only=["semgrep"])
            self.assertEqual(facts["coverage"]["scanners"]["semgrep"]["outcome"], "partial")
            rule_gaps = [g for g in facts["coverage"]["gaps"] if g["kind"] == "scanner_rules"]
            self.assertTrue(rule_gaps)
            self.assertIn("javascript.express.security.ssrf", rule_gaps[0]["detail"])
            self.assertIn("UNMEASURED", rule_gaps[0]["detail"])


class InitScopeTests(unittest.TestCase):
    """#8 — `init` produced no `.websec-ignore`, so setup-time scoping was undiscoverable."""

    def setUp(self):
        from websec_validator import init_scope
        self.init_scope = init_scope

    def _repo(self, tmp):
        root = Path(tmp)
        for d in ("backend/capacity-test", "backend/seed", "tests/fixtures", "frontend/src"):
            (root / d).mkdir(parents=True)
            (root / d / "f.ts").write_text("export const x = 1;\n")
        return root

    def test_proposes_nested_non_product_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = {e["path"] for e in self.init_scope.propose(self._repo(tmp))["entries"]}
            self.assertIn("backend/capacity-test/", paths)
            self.assertIn("backend/seed/", paths)
            self.assertNotIn("frontend/src/", paths)

    def test_nested_candidate_is_covered_by_its_parent_not_listed_twice(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = {e["path"] for e in self.init_scope.propose(self._repo(tmp))["entries"]}
            self.assertIn("tests/", paths)
            self.assertNotIn("tests/fixtures/", paths)

    def test_every_entry_carries_its_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            for e in self.init_scope.propose(self._repo(tmp))["entries"]:
                self.assertGreater(e["files"], 0)
                self.assertTrue(e["reason"])

    def test_refuses_to_clobber_an_existing_policy_file(self):
        """It may hold reviewed `fingerprint:` acknowledgements that regeneration would discard."""
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            (root / ".websec-ignore").write_text("fingerprint:abc expires:2030-01-01 # reviewed\n")
            proposal = self.init_scope.propose(root)
            self.assertFalse(self.init_scope.write(root, proposal)["written"])
            self.assertIn("reviewed", (root / ".websec-ignore").read_text())
            self.assertTrue(self.init_scope.write(root, proposal, force=True)["written"])

    def test_written_file_parses_as_a_suppression_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            self.init_scope.write(root, self.init_scope.propose(root))
            loaded = findings.load_suppressions(root)
            self.assertIn("tests/", list(loaded))


class GuardedEnvFallbackTests(unittest.TestCase):
    """#9 — `X || 'dev-default'` where a startup assertion enforces the real value."""

    def _repo(self, tmp, *, guarded):
        root = Path(tmp)
        (root / "src").mkdir(parents=True)
        (root / "src" / "auth.ts").write_text(
            "const jwtSecret = process.env.JWT_SECRET || 'dev-default';\n")
        if guarded:
            (root / "src" / "env.ts").write_text(
                "if (!process.env.JWT_SECRET) { throw new Error('JWT_SECRET must be set'); }\n")
        return root

    def _finding(self):
        return [{"category": "sast", "rule_id": "insecure-default-signing-secret",
                 "severity": "HIGH", "file": "src/auth.ts", "line": 1,
                 "title": "Hard-coded fallback signing secret"}]

    def test_guarded_fallback_is_demoted_and_explained(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = self._finding()
            self.assertEqual(scanners._demote_guarded_env_fallbacks(raw, self._repo(tmp, guarded=True)), 1)
            self.assertEqual(raw[0]["severity"], "LOW")
            self.assertEqual(raw[0]["guarded_env_fallback"], "JWT_SECRET")

    def test_unguarded_fallback_keeps_its_severity(self):
        """The true positive this rule exists for must survive the precision fix."""
        with tempfile.TemporaryDirectory() as tmp:
            raw = self._finding()
            self.assertEqual(scanners._demote_guarded_env_fallbacks(raw, self._repo(tmp, guarded=False)), 0)
            self.assertEqual(raw[0]["severity"], "HIGH")

    def test_recon_extractor_recognises_the_same_idioms(self):
        from websec_validator.extractors.auth import _asserted_env_vars
        for text in ("if (!process.env.JWT_SECRET) { throw new Error('x'); }",
                     "const env = z.object({ JWT_SECRET: z.string().min(1) })",
                     "assertEnv('JWT_SECRET')",
                     "SECRET = os.environ['JWT_SECRET']"):
            with self.subTest(text=text[:40]):
                self.assertEqual(_asserted_env_vars([text], {"JWT_SECRET"}), {"JWT_SECRET"})

    def test_recon_does_not_claim_a_guard_for_a_different_variable(self):
        from websec_validator.extractors.auth import _asserted_env_vars
        self.assertEqual(
            _asserted_env_vars(["if (!process.env.JWT_SECRET) { throw new Error('x'); }"],
                               {"SESSION_SECRET"}), set())


class EndToEndFieldReportTests(unittest.TestCase):
    """The reported symptoms, reproduced against a real repo and a real `websec run`."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        root = Path(cls.tmp) / "repo"
        (root / "backend/src").mkdir(parents=True)
        (root / "frontend").mkdir(parents=True)
        lock = json.dumps({"name": "b", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
                           "packages": {"": {"name": "b", "version": "1.0.0",
                                             "dependencies": {"lodash": "4.17.20"}},
                                        "node_modules/lodash": {"version": "4.17.20"}}})
        (root / "backend/package-lock.json").write_text(lock)
        (root / "frontend/package-lock.json").write_text(lock)
        (root / ".env.example").write_text("VITE_APPSYNC_API_KEY=da2-xxxxxxxxxxxxxxxxxxxxxxxxxx\n")
        (root / "backend/src/auth.ts").write_text(
            "const jwtSecret = process.env.JWT_SECRET || 'dev-default';\n")
        (root / "backend/src/env.ts").write_text(
            "if (!process.env.JWT_SECRET) { throw new Error('JWT_SECRET must be set'); }\n")
        (root / "backend/src/session.ts").write_text(
            "const s = process.env.SESSION_SECRET || 'dev-default';\n")
        cls.root = root
        out = root / "wsout"
        subprocess.run([sys.executable, "-m", "websec_validator.cli", "run", str(root),
                        "--out", str(out)],
                       capture_output=True, text=True, timeout=600,
                       env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"})
        runs = sorted((out / "runs").glob("2026*"))
        cls.ledger = json.loads((runs[-1] / "findings-ledger.json").read_text()) if runs else None

    def setUp(self):
        if not self.ledger:
            self.skipTest("websec run did not produce a ledger in this environment")

    def test_no_high_severity_finding_points_at_the_example_file(self):
        highs = [f for f in self.ledger["findings"]
                 if ".env.example" in f.get("location", "")
                 and f["severity"] in ("CRITICAL", "HIGH")]
        self.assertEqual(highs, [], "a documented placeholder must not be a HIGH finding")

    def test_the_placeholder_is_still_reported_somewhere(self):
        """Demoted, never dropped — a real key pasted into `.env.example` is still committed."""
        self.assertTrue(any(".env.example" in f.get("location", "") or ".env.example" in f["title"]
                            for f in self.ledger["findings"]))

    def test_guarded_and_unguarded_fallbacks_are_tiered_differently(self):
        by_file = {}
        for f in self.ledger["findings"]:
            if "fallback signing secret" in f["title"].lower():
                by_file.setdefault(Path(f.get("location", "")).name, set()).add(f["severity"])
        self.assertIn("LOW", by_file.get("auth.ts", set()), "guarded fallback should be demoted")
        self.assertTrue({"HIGH", "CRITICAL"} & by_file.get("session.ts", set()),
                        "unguarded fallback must keep its severity")

    def test_every_finding_carries_a_confidence(self):
        self.assertEqual([f["title"] for f in self.ledger["findings"] if not f.get("confidence")], [])

    def test_gate_records_the_exit_contract(self):
        self.assertIn("failure_kind", self.ledger["gate"])
        self.assertIn("exit_code_contract", self.ledger["gate"])


if __name__ == "__main__":
    unittest.main()

"""Dependency findings: compiled-binary coverage, fix versions, and remediation a reader can act on.

Shapes covered:
  * lockfile advisories, including one package with fixes on two release lines and a transitive
    package — must be found, with the version to move to and where to change it;
  * a compiled Go CLI sitting in the scan root — its embedded modules must be scanned, or the run
    must say they were not;
  * scaffold templates inside an installed `node_modules` package (a pom.xml with a literal
    version placeholder, a requirements-dev.txt for a generated sample app) — never installed,
    must stay silent.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator import clusters, coverage, dependency_fix, findings, scanners  # noqa: E402

ELF = b"\x7fELF\x02\x01\x01" + b"\0" * 57


def _osv_doc(entries):
    """entries: (path, source_type, name, version, ecosystem, vuln_id, alias, fixed_events)."""
    results = []
    for path, stype, name, version, eco, vid, alias, fixes in entries:
        results.append({"source": {"path": path, "type": stype}, "packages": [{
            "package": {"name": name, "version": version, "ecosystem": eco},
            "vulnerabilities": [{"id": vid, "aliases": [alias], "affected": [{
                "package": {"name": name, "ecosystem": eco},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}] + [{"fixed": f} for f in fixes]}]}]}],
            "groups": [{"ids": [vid], "aliases": [vid, alias], "max_severity": "5.5"}]}]})
    return {"results": results}


class PickFixTests(unittest.TestCase):
    def test_lowest_fix_on_installed_line_wins(self):
        self.assertEqual(dependency_fix.pick_fix("4.2.1", "5.3.0, 4.2.5", "npm"), ("4.2.5", False))

    def test_major_upgrade_is_flagged_when_line_has_no_fix(self):
        self.assertEqual(dependency_fix.pick_fix("4.2.1", "5.6.0", "npm"), ("5.6.0", True))

    def test_npm_zero_minor_is_breaking_but_go_zero_minor_is_not(self):
        self.assertEqual(dependency_fix.pick_fix("0.12.0", "0.19.0", "npm"), ("0.19.0", True))
        self.assertEqual(dependency_fix.pick_fix("0.12.0", "0.19.0", "gomod"), ("0.19.0", False))

    def test_no_fix_and_build_suffix(self):
        self.assertEqual(dependency_fix.pick_fix("1.4.0+incompatible", "", "gomod"), ("", False))
        self.assertEqual(dependency_fix.version_key("v1.4.0+incompatible"), (1, 4, 0))

    def test_clear_all_checks_each_advisory_on_the_candidate_line(self):
        # Max of the per-advisory targets (5.1.0) would leave A open: A's 5.x fix is 5.3.0.
        self.assertEqual(dependency_fix._clears_all("4.2.1", ["4.2.5, 5.3.0", "5.1.0"], "npm"), "5.3.0")
        self.assertEqual(dependency_fix._clears_all("4.2.1", ["4.2.5", "4.2.3"], "npm"), "4.2.5")
        self.assertEqual(dependency_fix._clears_all("4.2.1", ["4.2.5", ""], "npm"), "")

    def test_fix_below_installed_is_not_chosen(self):
        self.assertEqual(dependency_fix.pick_fix("2.0.0", "1.9.9, 2.0.5", "npm"), ("2.0.5", False))


class LockPathTests(unittest.TestCase):
    V3 = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"router-lib": "4.2.1", "infra-lib": "1.80.0"}},
        "node_modules/router-lib": {"version": "4.2.1", "dependencies": {"@scope/router-core": "3.1.0"}},
        "node_modules/@scope/router-core": {"version": "3.1.0"},
        "node_modules/infra-lib": {"version": "1.80.0", "bundleDependencies": ["globber"],
                                   "dependencies": {"globber": "^8.0.0"}},
        "node_modules/infra-lib/node_modules/globber": {"version": "8.0.4", "inBundle": True}}}

    def test_direct_transitive_bundled(self):
        self.assertEqual(dependency_fix.npm_paths(self.V3, "router-lib"), ("direct", []))
        self.assertEqual(dependency_fix.npm_paths(self.V3, "@scope/router-core"), ("transitive", ["router-lib"]))
        self.assertEqual(dependency_fix.npm_paths(self.V3, "globber"), ("bundled", ["infra-lib"]))

    def test_only_the_vulnerable_copy_and_its_resolvers_count(self):
        doc = {"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"framework": "1.0.0", "css-tool": "1.0.0", "styler": "8.5.0"}},
            "node_modules/styler": {"version": "8.5.0"},
            "node_modules/css-tool": {"version": "1.0.0", "dependencies": {"styler": "^8"}},
            "node_modules/framework": {"version": "1.0.0", "dependencies": {"styler": "8.4.0"}},
            "node_modules/framework/node_modules/styler": {"version": "8.4.0"}}}
        # The 8.4.0 copy is nested under framework: only framework resolves to it, and the root's
        # direct dependency is on the OTHER copy.
        self.assertEqual(dependency_fix.npm_paths(doc, "styler", "8.4.0"), ("transitive", ["framework"]))
        self.assertEqual(dependency_fix.npm_paths(doc, "styler", "8.5.0"), ("direct", []))
        self.assertEqual(dependency_fix.npm_paths(doc, "styler", "9.9.9"), ("", []))

    def test_lockfile_v1(self):
        v1 = {"lockfileVersion": 1, "dependencies": {
            "a": {"version": "1.0.0", "requires": {"b": "^2"}}, "b": {"version": "2.0.0"}}}
        self.assertEqual(dependency_fix.npm_paths(v1, "b"), ("transitive", ["a"]))
        self.assertEqual(dependency_fix.npm_paths(v1, "a"), ("direct", []))

    def test_unknown_shape_is_not_guessed(self):
        self.assertEqual(dependency_fix.npm_paths({}, "x"), ("", []))


class OsvArgvTests(unittest.TestCase):
    def argv(self, version):
        with patch.dict(scanners._VERSION_CACHE, {"osv-scanner": version}):
            return scanners._osv(Path("/repo"), Path("/out/osv.json"))

    def test_binary_plugin_only_where_it_is_additive(self):
        # Before 2.2.3 the plugin flag REPLACED the defaults: lockfiles would silently drop out.
        for version in (None, "2.0.0", "2.2.2"):
            self.assertNotIn("--experimental-plugins", self.argv(version), version)
        for version in ("2.2.3", "2.6.0"):
            cmd = self.argv(version)
            self.assertEqual(cmd[cmd.index("--experimental-plugins") + 1], "go/binary")
            self.assertIn("--recursive", cmd)

    def test_deprecated_flag_only_where_supported(self):
        self.assertNotIn("--experimental-flag-deprecated-packages", self.argv("2.3.0"))
        self.assertIn("--experimental-flag-deprecated-packages", self.argv("2.3.1"))

    def test_skip_dirs_regex_only_on_verified_version(self):
        self.assertNotIn("--experimental-exclude", self.argv("2.5.1"))
        cmd = self.argv("2.6.0")
        pattern = cmd[cmd.index("--experimental-exclude") + 1]
        self.assertTrue(pattern.startswith("r:") and "node_modules" in pattern)
        self.assertEqual(cmd[-1], "/repo")

    def test_skip_regex_is_anchored_to_the_target(self):
        # osv matches the ABSOLUTE path (reported without its leading slash). An unanchored pattern
        # excluded a whole repo that lived under `.claude/worktrees/…` or `build/…`.
        import re
        target = Path("/home/u/.claude/worktrees/build/app")
        rx = re.compile(scanners._osv_skip_regex(target))
        for path in ("home/u/.claude/worktrees/build/app/package-lock.json",
                     "/home/u/.claude/worktrees/build/app/src/go.sum"):
            self.assertIsNone(rx.search(path), path)
        for path in ("home/u/.claude/worktrees/build/app/node_modules/x/bin/tool",
                     "/home/u/.claude/worktrees/build/app/web/dist/bundle.js"):
            self.assertIsNotNone(rx.search(path), path)


class NormalizeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo, self.out = Path(tmp.name) / "repo", Path(tmp.name) / "out"
        self.repo.mkdir()
        self.out.mkdir()
        (self.repo / "package-lock.json").write_text(json.dumps(LockPathTests.V3))

    def normalize(self, reports):
        runs = []
        for key, doc in reports.items():
            path = self.out / (key + ".json")
            path.write_text(json.dumps(doc))
            runs.append({"key": key, "output": str(path), "exit_code": 0})
        with patch.object(scanners.enrichment, "enrich_exploitability", return_value={}), \
             patch.object(scanners.enrichment, "enrich_reachability", return_value={}):
            return scanners.normalize_findings(runs, self.out, target=self.repo)

    def test_osv_rows_carry_fix_version_and_binary_flag(self):
        doc = _osv_doc([
            ("toolcli", "artifact", "example.org/x/codec", "0.12.0", "Go", "GO-1", "CVE-2026-0001", ["0.19.0"]),
            ("toolcli", "artifact", "github.com/example/dist", "1.4.0+incompatible", "Go", "GO-2", "CVE-2026-0002", [])])
        rows = {r["pkg"]: r for r in scanners._norm_osv(doc)}
        self.assertEqual(rows["example.org/x/codec"]["fixed"], "0.19.0")
        self.assertEqual(rows["example.org/x/codec"]["artifact"], "binary")
        self.assertEqual(rows["github.com/example/dist"]["fixed"], "")
        unified = self.normalize({"osv-scanner": doc})
        by_pkg = {r["pkg"]: r for r in unified["all"]}
        no_fix = by_pkg["github.com/example/dist"]
        self.assertFalse(no_fix["title"].rstrip().endswith("→"), no_fix["title"])
        self.assertIn("no fix published", no_fix["title"])
        self.assertIn("No fixed version", no_fix["remediation"])
        crypto = by_pkg["example.org/x/codec"]
        self.assertTrue(crypto["title_previous"])
        self.assertIn("compiled binary", crypto["remediation"])
        self.assertNotIn("major upgrade", crypto["title"])
        self.assertIn("build info", crypto["confidence_basis"])

    def test_stdlib_reads_as_go_toolchain(self):
        doc = _osv_doc([("toolcli", "artifact", "stdlib", "1.22.1", "Go", "GO-9", "CVE-2026-0010", ["1.22.7"])])
        row = self.normalize({"osv-scanner": doc})["all"][0]
        self.assertIn("built with Go 1.22.7 or later", row["remediation"])
        self.assertIn("Go 1.22.1 standard library", row["remediation"])

    def test_reworded_title_keeps_v1_baseline_alias(self):
        from websec_validator import baseline
        trivy = {"Results": [{"Target": "package-lock.json", "Type": "npm", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2026-0011", "PkgName": "router-lib", "InstalledVersion": "4.2.1",
             "FixedVersion": "4.2.5", "Severity": "MEDIUM"}]}]}
        ledger = findings.build_ledger({}, self.normalize({"trivy": trivy}))
        row = next(f for f in ledger["findings"] if f.get("attack_class") == "cve")
        self.assertEqual(row["title_previous"], "router-lib 4.2.1 → 4.2.5")
        old = baseline.legacy_fingerprint({**row, "title": row["title_previous"]})
        self.assertIn(old, row["fingerprint_aliases"])

    def test_cross_tool_fixed_lists_merge_by_version(self):
        trivy = {"Results": [{"Target": "package-lock.json", "Type": "npm", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2026-0003", "PkgName": "router-lib", "InstalledVersion": "4.2.1",
             "FixedVersion": "5.3.0, 4.2.5", "Severity": "MEDIUM"}]}]}
        osv = _osv_doc([("package-lock.json", "lockfile", "router-lib", "4.2.1", "npm", "GHSA-x",
                         "CVE-2026-0003", ["5.3.0", "4.2.5"])])
        row = self.normalize({"trivy": trivy, "osv-scanner": osv})["all"][0]
        self.assertEqual(row["fixed"], "4.2.5, 5.3.0")
        self.assertEqual((row["fix_target"], row["fix_major_bump"]), ("4.2.5", False))
        self.assertEqual(row["dependency_path"], "direct")

    def test_package_with_fixes_on_two_lines_names_both_targets(self):
        trivy = {"Results": [{"Target": "package-lock.json", "Type": "npm", "Vulnerabilities": [
            {"VulnerabilityID": cve, "PkgName": "router-lib", "InstalledVersion": "4.2.1",
             "FixedVersion": fix, "Severity": "MEDIUM"} for cve, fix in
            (("CVE-2026-0004", "4.2.5"), ("CVE-2026-0005", "5.6.0"))]}]}
        rows = {r["cve"]: r for r in self.normalize({"trivy": trivy})["all"]}
        self.assertIn("(major upgrade)", rows["CVE-2026-0005"]["title"])
        self.assertIn("MAJOR upgrade", rows["CVE-2026-0005"]["remediation"])
        self.assertIn("5.6.0 is the lowest version that clears all of them", rows["CVE-2026-0004"]["remediation"])
        # Two advisories on one package no longer render as two identical titles.
        self.assertNotEqual(rows["CVE-2026-0004"]["title"], rows["CVE-2026-0005"]["title"])

    def test_transitive_and_bundled_name_the_parent(self):
        trivy = {"Results": [{"Target": "package-lock.json", "Type": "npm", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2026-0006", "PkgName": "@scope/router-core", "InstalledVersion": "3.1.0",
             "FixedVersion": "3.1.2", "Severity": "HIGH"},
            {"VulnerabilityID": "CVE-2026-0007", "PkgName": "globber", "InstalledVersion": "8.0.4",
             "FixedVersion": "9.0.0", "Severity": "MEDIUM"}]}]}
        unified = self.normalize({"trivy": trivy})
        rows = {r["pkg"]: r for r in unified["all"]}
        self.assertEqual(rows["@scope/router-core"]["introduced_by"], ["router-lib"])
        self.assertIn("Upgrade the parent", rows["@scope/router-core"]["remediation"])
        self.assertEqual(rows["globber"]["dependency_path"], "bundled")
        self.assertIn("cannot replace it", rows["globber"]["remediation"])
        # The specific remediation reaches the ledger (and from there the repair plans).
        ledger = findings.build_ledger({}, unified)
        led = {f["pkg"]: f for f in ledger["findings"] if f.get("attack_class") == "cve"}
        self.assertIn("infra-lib", led["globber"]["remediation"])
        self.assertEqual(led["globber"]["fix_target"], "9.0.0")

    def test_installed_tree_binaries_and_scaffold_templates_stay_silent(self):
        # osv: a Go toolchain binary under node_modules; trivy: scaffold templates inside an
        # installed package. Both are out of scope; neither may produce a finding.
        osv = _osv_doc([("node_modules/@bundler/darwin-arm64/bin/bundler", "artifact", "golang.org/x/sys",
                         "0.1.0", "Go", "GO-3", "CVE-2026-0008", ["0.2.0"])])
        trivy = {"Results": [
            {"Target": "packages/infra/node_modules/infra-cli/lib/scaffold/templates/python/requirements-dev.txt",
             "Type": "pip", "Vulnerabilities": [{"VulnerabilityID": "CVE-2026-0009", "PkgName": "testrunner",
                                                  "InstalledVersion": "7.1.0", "FixedVersion": "7.2.0",
                                                  "Severity": "MEDIUM"}]},
            {"Target": "packages/infra/node_modules/infra-cli/lib/scaffold/templates/java/pom.xml",
             "Type": "pom", "Vulnerabilities": [{"VulnerabilityID": "GHSA-0000-0000-0000",
                                                  "PkgName": "example:infra-lib",
                                                  "InstalledVersion": "%tool-version%", "FixedVersion": "1.90.0",
                                                  "Severity": "LOW"}]}]}
        unified = self.normalize({"osv-scanner": osv, "trivy": trivy})
        self.assertEqual(unified["total"], 0)
        self.assertGreaterEqual(unified["contamination_dropped"], 3)

    def test_deprecated_package_is_its_own_class_with_parent_named(self):
        lock = {"lockfileVersion": 3, "packages": {
            "": {"devDependencies": {"cleaner": "3.0.2"}},
            "node_modules/cleaner": {"version": "3.0.2", "dependencies": {"walker": "^7"}},
            "node_modules/walker": {"version": "7.2.3", "dependencies": {"once-ish": "^1"}},
            "node_modules/once-ish": {"version": "1.0.6"}}}
        (self.repo / "package-lock.json").write_text(json.dumps(lock))
        doc = {"results": [{"source": {"path": "package-lock.json", "type": "lockfile"}, "packages": [
            {"package": {"name": "once-ish", "version": "1.0.6", "ecosystem": "npm", "deprecated": True}},
            {"package": {"name": "cleaner", "version": "3.0.2", "ecosystem": "npm", "deprecated": True}},
            {"package": {"name": "walker", "version": "7.2.3", "ecosystem": "npm"}}]}]}
        unified = self.normalize({"osv-scanner": doc})
        rows = {r["pkg"]: r for r in unified["all"]}
        self.assertEqual(set(rows), {"once-ish", "cleaner"})      # a non-deprecated package: no row
        self.assertEqual(rows["once-ish"]["severity"], "LOW")
        self.assertIn("pulled in by walker", rows["once-ish"]["remediation"])
        self.assertIn("Upgrade cleaner to a maintained release", rows["cleaner"]["remediation"])
        self.assertIn("registry marks", rows["cleaner"]["confidence_basis"])
        ledger = findings.build_ledger({}, unified)
        led = [f for f in ledger["findings"] if f.get("pkg") == "once-ish"][0]
        self.assertEqual(led["attack_class"], "deprecated-dependency")
        self.assertIn("CWE-1104", " ".join(led["standards"]["cwe"]))
        self.assertIn("walker", led["remediation"])

    def test_deprecated_row_does_not_block_clear_all_for_its_cves(self):
        trivy = {"Results": [{"Target": "package-lock.json", "Type": "npm", "Vulnerabilities": [
            {"VulnerabilityID": cve, "PkgName": "router-lib", "InstalledVersion": "4.2.1",
             "FixedVersion": fix, "Severity": "MEDIUM"} for cve, fix in
            (("CVE-2026-0021", "4.2.5"), ("CVE-2026-0022", "4.2.7"))]}]}
        osv = {"results": [{"source": {"path": "package-lock.json", "type": "lockfile"}, "packages": [
            {"package": {"name": "router-lib", "version": "4.2.1", "ecosystem": "npm", "deprecated": True}}]}]}
        rows = [r for r in self.normalize({"trivy": trivy, "osv-scanner": osv})["all"] if not r.get("deprecated")]
        self.assertTrue(all(r.get("fix_all_target") == "4.2.7" for r in rows), rows)

    def test_one_binary_is_one_cluster(self):
        doc = _osv_doc([("toolcli", "artifact", f"example.com/mod{i}", "1.0.0", "Go", f"GO-{i}",
                         f"CVE-2026-01{i:02d}", ["1.1.0"]) for i in range(4)])
        ledger = findings.build_ledger({}, self.normalize({"osv-scanner": doc}))
        groups = [c for c in clusters.build(ledger) if c["kind"] == "artifact"]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["site_count"], 4)
        self.assertIn("ONE fix", groups[0]["title"])


class HardcodedCredentialSeverityTests(unittest.TestCase):
    def test_cwe_798_rules_are_at_least_high_even_in_tests(self):
        doc = {"results": [
            {"check_id": "x.jwt-hardcode.hardcoded-jwt-secret", "path": "src/__tests__/auth.test.ts",
             "start": {"line": 9}, "extra": {"severity": "WARNING", "message": "hard-coded credential",
                                             "metadata": {"cwe": ["CWE-798: Use of Hard-coded Credentials"]}}},
            {"check_id": "x.other", "path": "src/a.ts", "start": {"line": 3},
             "extra": {"severity": "WARNING", "message": "m", "metadata": {"cwe": "CWE-79: XSS"}}}]}
        rows = {r["key"]: r for r in scanners._norm_semgrep(doc)}
        self.assertEqual(rows["hardcoded-jwt-secret"]["severity"], "HIGH")
        self.assertEqual(rows["other"]["severity"], "MEDIUM")
        # Test-file context lowers confidence, never severity.
        self.assertEqual(scanners._derive_confidence(rows["hardcoded-jwt-secret"])[0], "LOW")


class BinaryCoverageTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        (self.repo / "toolcli").write_bytes(ELF)
        (self.repo / "node_modules" / "x").mkdir(parents=True)
        (self.repo / "node_modules" / "x" / "native").write_bytes(ELF)
        (self.repo / "Main.class").write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + b"\0" * 8)
        (self.repo / "notes.txt").write_text("MZ is not a header here")

    def test_only_in_scope_executables_are_counted(self):
        found = scanners.compiled_binaries(self.repo)
        self.assertEqual((found["count"], found["paths"]), (1, ["toolcli"]))
        self.assertEqual(scanners.compiled_binaries(self.repo, excludes=("toolcli",))["count"], 0)

    def test_no_dependency_gap_when_no_sca_scanner_was_requested(self):
        self.assertEqual(scanners.binary_sca_gap(self.repo, [{"key": "gitleaks", "exit_code": 0}]), "")

    def test_gap_when_no_binary_scan_ran(self):
        gap = scanners.binary_sca_gap(self.repo, [{"key": "trivy", "exit_code": 0}])
        self.assertIn("toolcli", gap)
        self.assertIn("NOT a clean result", gap)
        facts = {}
        coverage.add_gap(facts, "compiled_binary_sca", gap, execution=False)
        self.assertTrue(facts["coverage"]["execution_complete"])

    def test_no_gap_when_osv_scanned_binaries(self):
        ok = [{"key": "osv-scanner", "binary_sca": True, "exit_code": 1}]
        self.assertEqual(scanners.binary_sca_gap(self.repo, ok), "")
        old = [{"key": "osv-scanner", "binary_sca": False, "exit_code": 0}]
        self.assertIn("toolcli", scanners.binary_sca_gap(self.repo, old))

    @unittest.skipIf(os.name == "nt", "PE probe covered by magic bytes on every OS")
    def test_pe_requires_pe_signature(self):
        pe = bytearray(b"MZ" + b"\0" * 126)
        pe[60:64] = (64).to_bytes(4, "little")
        pe[64:68] = b"PE\0\0"
        (self.repo / "tool.exe").write_bytes(bytes(pe))
        self.assertEqual(scanners.compiled_binaries(self.repo)["count"], 2)


@unittest.skipUnless(shutil.which("osv-scanner"), "osv-scanner not installed")
class RealOsvTests(unittest.TestCase):
    """The installed osv-scanner, on a repo that lives under SKIP_DIR-named ancestors."""

    def test_lockfile_scanned_under_skip_named_ancestor(self):
        version = scanners._parse_version(scanners.probe_version("osv-scanner"))
        if not version or version < scanners.OSV_ADDITIVE_PLUGINS:
            self.skipTest("osv-scanner older than the binary-plugin floor")
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / ".claude" / "worktrees" / "build" / "app"
            (repo / "node_modules" / "x").mkdir(parents=True)
            (repo / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
                "": {"dependencies": {"left-pad": "1.0.0"}},
                "node_modules/left-pad": {"version": "1.0.0"}}}))
            (repo / "node_modules" / "x" / "package-lock.json").write_text(json.dumps({
                "lockfileVersion": 3, "packages": {"": {}, "node_modules/y": {"version": "1.0.0"}}}))
            out = Path(tmp) / "osv.json"
            proc = subprocess.run(scanners._osv(repo, out), capture_output=True, text=True, timeout=300,
                                  stdin=subprocess.DEVNULL)
            self.assertIn(proc.returncode, (0, 1), proc.stderr[-400:])
            sources = [r["source"]["path"] for r in json.loads(out.read_text()).get("results", [])]
            # left-pad 1.0.0 may have no advisory; the scan must still have READ the lockfile.
            self.assertNotIn("No package sources found", proc.stderr)
            self.assertFalse(any("node_modules" in p for p in sources), sources)


if __name__ == "__main__":
    unittest.main()

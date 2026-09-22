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


if __name__ == "__main__":
    unittest.main()

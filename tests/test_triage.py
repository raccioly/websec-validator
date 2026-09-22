"""Disposition — the third axis — is advisory, safe by default, and never gates.

A finding already says how bad it is if real (severity) and whether it IS real (calibrated.p).
It never said whether an agent can act alone, so that was carried implicitly: every repair plan
demands a human confirm the finding, which is safe but tells an agent nothing about the difference
between a missing `nosniff` header and a missing authorization decision.

The two properties that must hold forever:
  * agent-fixable requires a MECHANICAL verification — if a fix cannot be demonstrated, an agent
    cannot know it worked, so a human must look however local the edit was.
  * nothing gates on this field. A wrong disposition must cost a wasted review, never a shipped
    vulnerability or an unattended change to a security control.

@req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-012
@req specs/002-calibration-honesty-and-structural-coverage/spec.md#SC-009
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator import explain, findings, fixprompt, gate, repairs

# explain.STANDARDS is the authoritative class registry (73); findings.REMEDIATION (63)
# is only the classes with bespoke remediation text, so sink classes like `sqli` are absent.
ALL_CLASSES = set(explain.STANDARDS) | set(findings.REMEDIATION)


class PolicyShapeTests(unittest.TestCase):
    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-012
    def test_agent_fixable_always_has_a_mechanical_verification(self):
        """The load-bearing invariant: no mechanical check ⇒ an agent cannot know the fix worked."""
        for key in fixprompt._AGENT_FIXABLE:
            with self.subTest(attack_class=key):
                self.assertIn(key, fixprompt._VERIFY,
                              f"{key} is agent-fixable but has no specific verification; it would "
                              "fall back to the generic 'write a regression test', which is not a "
                              "mechanical check")
                self.assertNotEqual(fixprompt._VERIFY[key], fixprompt._GENERIC_VERIFY)

    def test_no_class_is_both_agent_fixable_and_human_required(self):
        overlap = set(fixprompt._AGENT_FIXABLE) & set(fixprompt._HUMAN_REASONS)
        self.assertEqual(overlap, set(), f"contradictory policy for: {sorted(overlap)}")

    def test_unknown_classes_default_to_human_required(self):
        for unknown in ("", "   ", "not-a-real-class", "SQLI", None):
            with self.subTest(attack_class=unknown):
                result = fixprompt.disposition(unknown)
                self.assertEqual(result["disposition"], "human-required")

    def test_an_unclassified_class_says_so_rather_than_inventing_a_reason(self):
        result = fixprompt.disposition("brand-new-detector-class")
        self.assertIn("no disposition policy", result["reason"])

    def test_every_shipped_attack_class_resolves(self):
        """Total function: a detector cannot produce a finding the policy cannot disposition."""
        for attack_class in ALL_CLASSES:
            with self.subTest(attack_class=attack_class):
                result = fixprompt.disposition(attack_class)
                self.assertIn(result["disposition"], ("agent-fixable", "human-required"))
                self.assertTrue(result["reason"])
                self.assertEqual(result["basis"], "attack-class policy")

    def test_the_dangerous_classes_are_never_agent_fixable(self):
        """Authorization, secrets and injection must always require a human."""
        for attack_class in ("missing-auth", "bola", "missing-rls", "secret", "cve", "sqli", "xss",
                             "command-injection", "mass-assignment", "rls-context", "csrf",
                             "auth-backdoor", "excessive-agency", "llm-prompt-injection"):
            with self.subTest(attack_class=attack_class):
                self.assertEqual(fixprompt.disposition(attack_class)["disposition"], "human-required")

    def test_agent_fixable_is_limited_to_header_flag_and_config_shaped_fixes(self):
        """A guard on scope creep: this set should stay small and mechanically checkable."""
        self.assertLessEqual(len(fixprompt._AGENT_FIXABLE), 12)
        for key in fixprompt._AGENT_FIXABLE:
            self.assertIn(key, ALL_CLASSES, f"{key} is not a real attack class")

    def test_every_human_reason_names_a_real_attack_class(self):
        unknown = set(fixprompt._HUMAN_REASONS) - ALL_CLASSES
        self.assertEqual(unknown, set(), f"policy references non-existent classes: {sorted(unknown)}")

    def test_every_known_class_has_a_specific_reason_not_the_generic_fallback(self):
        """The fallback is a safety net for NEW classes, not a substitute for policy."""
        generic = [c for c in sorted(ALL_CLASSES)
                   if fixprompt.disposition(c)["reason"] == fixprompt._DEFAULT_HUMAN_REASON]
        self.assertEqual(generic, [], f"these shipped classes have no stated reason: {generic}")

    def test_the_advisory_disclaimer_is_carried_on_every_result(self):
        for attack_class in ("missing-csp", "missing-auth", "unknown-thing"):
            with self.subTest(attack_class=attack_class):
                advisory = fixprompt.disposition(attack_class)["advisory"].lower()
                self.assertIn("propose", advisory)
                self.assertIn("nothing gates", advisory)


class CatalogTests(unittest.TestCase):
    def test_catalog_publishes_the_rule_and_both_sides(self):
        catalog = fixprompt.disposition_catalog()
        self.assertIn("mechanical verification", catalog["rule"])
        self.assertEqual(set(catalog["agent_fixable"]), set(fixprompt._AGENT_FIXABLE))
        self.assertEqual(set(catalog["human_required"]), set(fixprompt._HUMAN_REASONS))
        self.assertEqual(catalog["default"]["disposition"], "human-required")

    def test_catalog_shows_the_verification_that_justifies_each_agent_fixable_class(self):
        """Published so a reader can ARGUE with it, not just observe the behaviour."""
        for key, row in fixprompt.disposition_catalog()["agent_fixable"].items():
            with self.subTest(attack_class=key):
                self.assertEqual(row["verify"], fixprompt._VERIFY[key])

    def test_catalog_is_json_serialisable(self):
        json.dumps(fixprompt.disposition_catalog())


class LedgerIntegrationTests(unittest.TestCase):
    def test_build_ledger_attaches_a_triage_block_to_every_finding(self):
        facts = {"target": "t", "surface": {}, "routes": {}, "authz": {}, "auth": {},
                 "coverage": {"execution_complete": True, "gaps": [], "scanners": {}}}
        ledger = findings.build_ledger(facts, None)
        for finding in ledger["findings"]:
            self.assertIn("triage", finding)
            self.assertIn(finding["triage"]["disposition"], ("agent-fixable", "human-required"))
        self.assertIn("by_disposition", ledger)

    def test_repair_plan_carries_the_disposition_without_relaxing_prerequisites(self):
        ledger = {"findings": [{
            "title": "missing csp", "attack_class": "missing-csp", "severity": "LOW",
            "confidence": "LOW", "location": "headers", "fingerprint": "a" * 16,
            "remediation": "add the header", "status": "open",
            "triage": fixprompt.disposition("missing-csp")}]}
        plan = repairs.build(ledger)[0]
        self.assertEqual(plan["triage"]["disposition"], "agent-fixable")
        joined = " ".join(plan["prerequisites"]).lower()
        self.assertIn("confirm the finding on the original build", joined,
                      "an agent-fixable disposition must not remove the confirmation step")

    def test_repair_plan_derives_a_disposition_when_the_ledger_predates_the_field(self):
        ledger = {"findings": [{"title": "t", "attack_class": "missing-auth", "severity": "HIGH",
                                "confidence": "LOW", "location": "/x", "fingerprint": "b" * 16,
                                "remediation": "r", "status": "open"}]}
        self.assertEqual(repairs.build(ledger)[0]["triage"]["disposition"], "human-required")


class NeverGatesTests(unittest.TestCase):
    """The safety property: a wrong disposition costs a review, never a shipped vulnerability."""

    def _finding(self, attack_class, severity="HIGH"):
        return {"title": "t", "attack_class": attack_class, "severity": severity,
                "confidence": "HIGH", "location": "app.py", "file": "app.py",
                "fingerprint": attack_class, "triage": fixprompt.disposition(attack_class)}

    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#SC-009
    def test_an_agent_fixable_finding_still_blocks_the_gate(self):
        ledger = {"findings": [self._finding("missing-csp", "HIGH")]}
        facts = {"analysis_scope": {"matched": ["app.py"], "missed": []}}
        self.assertFalse(gate.verdict(ledger, facts, "medium")["passed"])

    def test_the_verdict_is_identical_with_and_without_the_field(self):
        facts = {"analysis_scope": {"matched": ["app.py"], "missed": []}}
        for attack_class in ("missing-csp", "missing-auth", "sqli"):
            with self.subTest(attack_class=attack_class):
                with_field = self._finding(attack_class)
                without = {k: v for k, v in with_field.items() if k != "triage"}
                a = gate.verdict({"findings": [with_field]}, facts, "medium")
                b = gate.verdict({"findings": [without]}, facts, "medium")
                self.assertEqual(a["passed"], b["passed"])
                self.assertEqual(a["blocking_count"], b["blocking_count"])

    def test_disposition_does_not_appear_in_the_gate_payload(self):
        ledger = {"findings": [self._finding("missing-csp")]}
        facts = {"analysis_scope": {"matched": ["app.py"], "missed": []}}
        payload = json.dumps(gate.verdict(ledger, facts, "medium"))
        self.assertNotIn("agent-fixable", payload)
        self.assertNotIn("disposition", payload)

    def test_fpfilter_ignores_disposition(self):
        from websec_validator import fpfilter
        for attack_class in ("missing-csp", "missing-auth"):
            with self.subTest(attack_class=attack_class):
                filtered, _ = fpfilter.evaluate(self._finding(attack_class), {})
                bare = {k: v for k, v in self._finding(attack_class).items() if k != "triage"}
                self.assertEqual(filtered, fpfilter.evaluate(bare, {})[0])


class SarifUnchangedTests(unittest.TestCase):
    def test_sarif_output_does_not_carry_the_advisory_field(self):
        """SARIF is a shared interchange format; an internal advisory axis does not belong in it."""
        from websec_validator import formats
        facts = {"target": "t", "version": "0.0.0",
                 "coverage": {"execution_complete": True, "gaps": [], "scanners": {}}}
        ledger = {"findings": [{"title": "t", "attack_class": "missing-csp", "severity": "LOW",
                                "confidence": "LOW", "location": "h", "fingerprint": "c" * 16,
                                "standards": {}, "remediation": "r", "status": "open",
                                "triage": fixprompt.disposition("missing-csp")}],
                  "total": 1, "by_severity": {}, "by_confidence": {}}
        payload = json.dumps(formats.to_sarif(ledger, facts, "0.0.0"))
        self.assertNotIn("agent-fixable", payload)
        self.assertNotIn("triage", payload)


if __name__ == "__main__":
    unittest.main()

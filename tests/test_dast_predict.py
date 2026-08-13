"""DAST prediction — the alerts a dynamic scan WILL raise, and the classes it structurally can't."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator import dast_predict  # noqa: E402
from websec_validator.findings import REMEDIATION, STANDARDS  # noqa: E402


def _ledger(*classes):
    return {"findings": [{"attack_class": c, "location": f"src/{c}.js", "severity": "MEDIUM"}
                         for c in classes]}


class VocabularyGuardTests(unittest.TestCase):
    """The mapping is keyed on attack_class — a typo'd key would SILENTLY never fire. Lock it down."""

    def test_every_mapping_key_is_a_real_attack_class(self):
        real = set(STANDARDS) | set(REMEDIATION)
        unknown = sorted((set(dast_predict._DAST_MAP) | set(dast_predict._BLIND_SPOTS)) - real)
        self.assertEqual(unknown, [], f"mapping keys not in the real attack-class vocabulary: {unknown}")

    def test_no_class_is_both_predicted_and_blind(self):
        overlap = sorted(set(dast_predict._DAST_MAP) & set(dast_predict._BLIND_SPOTS))
        self.assertEqual(overlap, [], f"a class cannot be both scanner-findable and a blind spot: {overlap}")


class PredictionTests(unittest.TestCase):
    def test_predicts_passive_header_alerts(self):
        p = dast_predict.predict({}, _ledger("missing-csp", "clickjacking"))
        alerts = {r["alert_id"] for r in p["predicted"]}
        self.assertIn("10038 / 10055", alerts)     # CSP
        self.assertIn("10020", alerts)             # anti-clickjacking
        self.assertEqual(p["summary"]["predicted_alerts"], 2)

    def test_predicts_active_injection_alerts(self):
        p = dast_predict.predict({}, _ledger("sqli"))
        r = p["predicted"][0]
        self.assertIn("SQL Injection", r["alert"])
        self.assertIn("sqlmap", r["scanner"])

    def test_authz_classes_are_blind_spots_not_predictions(self):
        p = dast_predict.predict({}, _ledger("bola", "mass-assignment"))
        self.assertEqual(p["predicted"], [])                       # no scanner finds these
        classes = {b["attack_class"] for b in p["blind_spots"]}
        self.assertEqual(classes, {"bola", "mass-assignment"})
        md = dast_predict.render_md(p)
        self.assertIn("will NOT find these", md)                   # the honest half is rendered

    def test_sources_are_deduped_and_carried(self):
        led = {"findings": [{"attack_class": "missing-csp", "location": "a.js", "severity": "LOW"},
                            {"attack_class": "missing-csp", "location": "a.js", "severity": "LOW"},
                            {"attack_class": "missing-csp", "location": "b.js", "severity": "LOW"}]}
        p = dast_predict.predict({}, led)
        self.assertEqual(len(p["predicted"]), 1)                   # one alert class
        self.assertEqual(p["predicted"][0]["sources"], ["a.js", "b.js"])

    def test_graphql_introspection_predicted_from_facts_without_a_finding(self):
        facts = {"graphql": {"present": True, "introspection_enabled": True, "endpoint": "/graphql"}}
        p = dast_predict.predict(facts, {"findings": []})
        self.assertEqual(len(p["predicted"]), 1)
        self.assertEqual(p["predicted"][0]["attack_class"], "graphql")
        self.assertIn("/graphql", p["predicted"][0]["sources"])

    def test_unmapped_class_is_silently_ignored(self):
        p = dast_predict.predict({}, _ledger("sast"))              # generic bucket → no claim
        self.assertEqual(p["predicted"], [])
        self.assertEqual(p["blind_spots"], [])

    def test_scanner_caveats_warn_about_the_redirect_fp(self):
        # bug-208 generalized: the same urlopen/curl default that fooled websec fools ZAP/Nuclei, so
        # a predicted-alert list must also say which scan answers NOT to trust.
        md = dast_predict.render_md(dast_predict.predict({}, _ledger("missing-csp")))
        self.assertIn("not to trust", md.lower())
        self.assertIn("FOLLOW redirects", md)
        self.assertIn("307", md)

    def test_caveats_present_even_for_a_blind_spot_only_ledger(self):
        md = dast_predict.render_md(dast_predict.predict({}, _ledger("bola")))
        self.assertIn("not to trust", md.lower())

    def test_empty_ledger_renders_gracefully(self):
        md = dast_predict.render_md(dast_predict.predict({}, None))
        self.assertIn("Nothing predicted", md)


if __name__ == "__main__":
    unittest.main()

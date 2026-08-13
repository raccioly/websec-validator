"""Close the calibration loop with a REAL scan — a ZAP/DAST report confirms/refutes static findings.

These tests exercise the PURE label-derivation only; they never call calibration.record_samples, so
they cannot touch the user-global overlay.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator import dast_ingest, dast_predict  # noqa: E402


def _ledger(*pairs):
    return {"findings": [{"attack_class": c, "confidence": conf, "location": f"src/{c}.js"}
                         for c, conf in pairs]}


def _zap(*plugin_ids):
    return {"site": [{"@name": "https://app",
                      "alerts": [{"pluginid": p, "alert": f"alert-{p}"} for p in plugin_ids]}]}


class ReportParsingTests(unittest.TestCase):
    def test_parses_zap_shape(self):
        got = dast_ingest.parse_report(_zap("10038", "40018"))
        self.assertEqual(got["plugin_ids"], {"10038", "40018"})

    def test_parses_generic_alerts_shape(self):
        got = dast_ingest.parse_report({"alerts": [{"id": "10020", "name": "Anti-clickjacking"}]})
        self.assertIn("10020", got["plugin_ids"])

    def test_sarif_shape_does_not_crash(self):
        got = dast_ingest.parse_report({"runs": [{"results": [{"ruleId": "ssrf-detect"}]}]})
        self.assertEqual(got["plugin_ids"], set())          # SARIF ids aren't ZAP plugin ids
        self.assertIn("ssrf-detect", got["names"])

    def test_garbage_report_is_safe(self):
        for junk in ({}, {"site": None}, {"alerts": None}, []):
            self.assertEqual(dast_ingest.parse_report(junk)["plugin_ids"], set())

    def test_bundled_alert_ids_split_into_each_real_plugin_id(self):
        # missing-csp is declared as "10038 / 10055" — BOTH must resolve back to the class.
        m = dast_ingest._alertid_to_class()
        self.assertIn("missing-csp", m.get("10038", set()))
        self.assertIn("missing-csp", m.get("10055", set()))

    def test_one_plugin_id_can_confirm_several_classes(self):
        # regression: ZAP 90020 is the signature of BOTH command-injection and eval-injection. A
        # scalar dict inversion dropped one of them silently — the value must be a SET.
        m = dast_ingest._alertid_to_class()
        self.assertEqual(m.get("90020"), {"command-injection", "eval-injection"})
        res = dast_ingest.derive_labels(
            _ledger(("command-injection", "HIGH"), ("eval-injection", "HIGH")), _zap("90020"))
        self.assertTrue(all(lab["is_real"] for lab in res["labels"]))   # BOTH confirmed
        self.assertEqual(len(res["confirmed"]), 2)


class LabelDerivationTests(unittest.TestCase):
    def test_scanner_raised_alert_confirms_the_static_finding(self):
        res = dast_ingest.derive_labels(_ledger(("missing-csp", "MEDIUM")), _zap("10038"))
        self.assertEqual(res["labels"], [{"attack_class": "missing-csp", "confidence": "MEDIUM",
                                          "is_real": True}])
        self.assertEqual(len(res["confirmed"]), 1)

    def test_silence_refutes_only_when_the_scan_proves_it_ran_those_rules(self):
        # A passive-only report (10038 = CSP header) is the most common ZAP CI config and CANNOT
        # raise SQLi. Treating its silence as proof marked every active-class finding a false
        # positive — permanently, in the cross-repo overlay. It must be left UNJUDGED.
        res = dast_ingest.derive_labels(_ledger(("sqli", "HIGH")), _zap("10038"))
        self.assertEqual(res["refuted"], [])
        self.assertEqual([u["attack_class"] for u in res["unjudged"]], ["sqli"])
        self.assertEqual(res["labels"], [])                  # nothing written to calibration
        self.assertFalse(res["active_rules_evidenced"])

    def test_silence_does_refute_once_active_rules_are_evidenced(self):
        # a report containing ANY active alert (40018) proves active scanning ran, so silence on
        # another active class IS meaningful.
        res = dast_ingest.derive_labels(_ledger(("xss", "HIGH")), _zap("40018", "10038"))
        self.assertTrue(res["active_rules_evidenced"])
        self.assertEqual([r["attack_class"] for r in res["refuted"]], ["xss"])
        self.assertEqual(res["labels"][0]["is_real"], False)

    def test_empty_or_failed_report_judges_nothing(self):
        for report in ({"site": [{"alerts": []}]}, {}, {"alerts": []}):
            res = dast_ingest.derive_labels(_ledger(("sqli", "HIGH"), ("missing-csp", "LOW")), report)
            self.assertEqual(res["labels"], [], report)
            self.assertEqual(res["refuted"], [], report)

    def test_blind_spot_findings_are_never_scored(self):
        # THE critical guard: a scanner's silence on BOLA/mass-assignment means NOTHING. Scoring
        # those as false positives would corrupt calibration and hide real authz bugs.
        res = dast_ingest.derive_labels(
            _ledger(("bola", "MEDIUM"), ("mass-assignment", "HIGH"), ("missing-auth", "HIGH")),
            _zap("10038"))
        self.assertEqual(res["labels"], [])                 # nothing scored
        self.assertEqual(res["skipped_blind"], 3)

    def test_mixed_ledger_splits_correctly(self):
        # passive-only report: CSP is confirmed, sqli can't be judged (no active evidence), bola is
        # a blind spot. Only the confirmed one is written to calibration.
        res = dast_ingest.derive_labels(
            _ledger(("missing-csp", "MEDIUM"), ("sqli", "HIGH"), ("bola", "MEDIUM")), _zap("10038"))
        self.assertEqual({c["attack_class"] for c in res["confirmed"]}, {"missing-csp"})
        self.assertEqual({u["attack_class"] for u in res["unjudged"]}, {"sqli"})
        self.assertEqual(res["refuted"], [])
        self.assertEqual(res["skipped_blind"], 1)
        self.assertEqual(len(res["labels"]), 1)             # only the confirmed one

    def test_unmapped_class_is_ignored_entirely(self):
        res = dast_ingest.derive_labels(_ledger(("sast", "LOW")), _zap("10038"))
        self.assertEqual(res["labels"], [])
        self.assertEqual(res["skipped_blind"], 0)           # not a blind spot either — just unmapped

    def test_labels_are_shaped_for_record_samples(self):
        res = dast_ingest.derive_labels(_ledger(("clickjacking", "MEDIUM")), _zap("10020"))
        for lab in res["labels"]:
            self.assertEqual(set(lab), {"attack_class", "confidence", "is_real"})

    def test_every_predictable_class_is_ingestible(self):
        # any class we PREDICT in §4b with numeric ZAP ids must be resolvable on the way back in,
        # otherwise the predict→scan→calibrate loop silently breaks for it.
        m = dast_ingest._alertid_to_class()
        ingestible = set().union(*m.values()) if m else set()
        for cls, (_s, _a, aid, _w) in dast_predict._DAST_MAP.items():
            if any(p.strip().isdigit() for p in str(aid).replace(",", "/").split("/")):
                self.assertIn(cls, ingestible, f"{cls} predicted but not ingestible")


if __name__ == "__main__":
    unittest.main()

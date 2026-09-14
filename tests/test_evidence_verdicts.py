"""Evidence controls: failures and status differences must never become ground truth."""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator import calibration, dast_ingest, dynamic


ROUTE = "/groups/{groupId}/records"
FACTS = {"routes": {"endpoints": [{"method": "GET", "path": ROUTE}]}}
CFG = {"target": "http://localhost:4567", "application_id": "fixture", "build_id": "revision-1",
       "bola_controls": {
           "expected_policy": "tenant-isolated", "identity_path": "/identity",
           "identities": {"agentA": {"json_path": "id", "value": "A"},
                          "agentB": {"json_path": "id", "value": "B"}},
           "resources": {ROUTE: {"agentA": {"json_path": "items.0.id", "value": "PRIVATE-A"},
                                 "agentB": {"json_path": "items.0.id", "value": "PRIVATE-B"}}}}}


def mint(_cfg, role):
    letter = role[-1]
    return {"token": letter, "tenant": letter}


def private_fixture(method, url, token, **kwargs):
    if url.endswith("/identity"):
        return 200, json.dumps({"id": token})
    tenant = url.split("/groups/")[1].split("/")[0]
    if token is None:
        return 401, "denied"
    return 200, json.dumps({"items": [{"id": "PRIVATE-" + tenant}]})


class BolaEvidenceTests(unittest.TestCase):
    def run_bola(self, request, config=None, facts=None):
        with patch.object(dynamic, "mint", side_effect=mint), patch.object(dynamic, "_request", side_effect=request):
            return dynamic.cross_tenant_bola(CFG if config is None else config, FACTS if facts is None else facts)

    def test_failed_requests_never_claim_isolation(self):
        for code in (None, 500, 429):
            result = self.run_bola(lambda *a, **k: (code, "failure"))
            self.assertEqual(result["state"], "inconclusive")
            self.assertEqual(result["inconclusive"], 2)
            self.assertEqual(result["leaks"], [])
            self.assertNotIn("all isolated", result["summary"])

    def test_no_routes_is_not_tested(self):
        result = self.run_bola(private_fixture, facts={})
        self.assertEqual(result["state"], "not-tested")
        self.assertEqual(result["checks"], 0)
        self.assertNotIn("all isolated", result["summary"])

    def test_nonempty_public_body_without_controls_is_only_a_candidate(self):
        result = self.run_bola(lambda *a, **k: (200, '{"public": "hello"}'), config={"target": CFG["target"]})
        self.assertEqual(result["leaks"], [])
        self.assertEqual(result["inconclusive"], 2)
        self.assertEqual(calibration.samples_from_dynamic({"cross_tenant_bola": result}), [])

    def test_private_victim_marker_and_controls_confirm_real_leaks(self):
        result = self.run_bola(private_fixture)
        self.assertEqual(len(result["leaks"]), 2)
        self.assertEqual(result["state"], "confirmed-vulnerable")
        samples = calibration.samples_from_dynamic({"cross_tenant_bola": result})
        self.assertEqual(len(samples), 2)
        self.assertTrue(all(s["evidence_verified"] for s in samples))
        self.assertNotIn("PRIVATE-A", json.dumps(result))
        self.assertNotIn("PRIVATE-B", json.dumps(result))
        self.assertNotIn('"token"', json.dumps(result))

    def test_verified_marker_outweighs_soft_denial_text(self):
        def request(method, url, token, **kwargs):
            code, body = private_fixture(method, url, token)
            if code == 200 and "/groups/" in url:
                data = json.loads(body)
                data["user"] = None
                body = json.dumps(data)
            return code, body
        self.assertEqual(len(self.run_bola(request)["leaks"]), 2)

    def test_public_fixture_cannot_prove_bola(self):
        def request(method, url, token, **kwargs):
            return private_fixture(method, url, token or "A")
        self.assertEqual(self.run_bola(request)["leaks"], [])

    def test_wrong_identity_cannot_prove_bola(self):
        def request(method, url, token, **kwargs):
            if url.endswith("/identity"):
                return 200, '{"id": "A"}'
            return private_fixture(method, url, token)
        self.assertEqual(self.run_bola(request)["leaks"], [])

    def test_owner_must_see_victim_marker(self):
        config = copy.deepcopy(CFG)
        config["bola_controls"]["resources"][ROUTE]["agentB"]["value"] = "nonexistent"
        result = self.run_bola(private_fixture, config=config)
        self.assertEqual([r["direction"] for r in result["leaks"]], ["B→A"])

    def test_cross_tenant_denial_with_positive_controls_is_scoped_blocked(self):
        def request(method, url, token, **kwargs):
            if "/groups/" in url and token and f"/groups/{token}/" not in url:
                return 403, "denied"
            return private_fixture(method, url, token)
        result = self.run_bola(request)
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["blocked"], 2)
        self.assertEqual(calibration.samples_from_dynamic({"cross_tenant_bola": result}), [])

    def test_confirmation_requires_repeatable_read(self):
        counts = {}
        def request(method, url, token, **kwargs):
            if "/groups/" in url and token and f"/groups/{token}/" not in url:
                counts[(url, token)] = counts.get((url, token), 0) + 1
                if counts[(url, token)] > 1:
                    return 500, "failure"
            return private_fixture(method, url, token)
        self.assertEqual(self.run_bola(request)["leaks"], [])

    def test_missing_build_prevents_permanent_labels(self):
        config = copy.deepcopy(CFG)
        config.pop("build_id")
        result = self.run_bola(private_fixture, config=config)
        self.assertEqual(len(result["leaks"]), 2)
        self.assertEqual(calibration.samples_from_dynamic({"cross_tenant_bola": result}), [])


class StatusObservationTests(unittest.TestCase):
    def test_validation_status_is_not_missing_auth(self):
        facts = {"routes": {"endpoints": [{"method": "POST", "path": "/records"}]}}
        for code in (400, 422, 409, 415, 500, None):
            with patch.object(dynamic, "_request", return_value=(code, "invalid")):
                result = dynamic.write_auth_enforcement("http://localhost", facts)
            self.assertEqual(result["no_auth_gate"], [])
            self.assertEqual(result["executed_unauth"], [])
            self.assertEqual(result["results"][0]["state"], "inconclusive")
            self.assertEqual(calibration.samples_from_dynamic({"write_auth_enforcement": result}), [])

    def test_successful_write_is_a_candidate_not_proof(self):
        facts = {"routes": {"endpoints": [{"method": "POST", "path": "/records"}]}}
        with patch.object(dynamic, "_request", return_value=(201, '{"id":"sample"}')):
            result = dynamic.write_auth_enforcement("http://localhost", facts)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["executed_unauth"], [])
        self.assertEqual(calibration.samples_from_dynamic({"write_auth_enforcement": result}), [])

    def test_soft_denial_is_not_write_candidate(self):
        facts = {"routes": {"endpoints": [{"method": "POST", "path": "/records"}]}}
        with patch.object(dynamic, "_request", return_value=(200, '{"error":"unauthorized"}')):
            result = dynamic.write_auth_enforcement("http://localhost", facts)
        self.assertEqual(result["candidates"], [])

    def test_failed_unauth_gets_do_not_claim_all_gated(self):
        facts = {"routes": {"endpoints": [{"method": "GET", "path": "/records"}]}}
        for facts_to_test in (facts, {}):
            with patch.object(dynamic, "_request", return_value=(500, "failure")):
                result = dynamic.unauth_reachability("http://localhost", facts_to_test)
            self.assertFalse(result["authn_trustworthy"])
            self.assertNotIn("all gated", result["summary"])

    def test_forged_token_errors_are_not_rejections_or_confirmed_bypasses(self):
        facts = {"routes": {"endpoints": [{"method": "GET", "path": "/records"}]}}
        for code in (None, 500, 400, 404, 422):
            with patch.object(dynamic, "_request", side_effect=[(401, "denied"), (code, "failure")]):
                result = dynamic.forged_token_bypass("http://localhost", facts)
            self.assertTrue(result["inconclusive"])
            self.assertEqual(result["bypassed"], [])
            self.assertEqual(result["results"][0]["verdict"], "inconclusive")
            self.assertNotIn("all rejected", result["summary"])

    def test_status_difference_is_a_forged_token_candidate(self):
        facts = {"routes": {"endpoints": [{"method": "GET", "path": "/records"}]}}
        with patch.object(dynamic, "_request", side_effect=[(401, "denied"), (200, '{"ok":true}')]):
            result = dynamic.forged_token_bypass("http://localhost", facts)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["bypassed"], [])
        self.assertFalse(result["candidates"][0]["evidence_verified"])


class CalibrationProvenanceTests(unittest.TestCase):
    def test_unknown_corpus_findings_are_excluded(self):
        self.assertIsNone(calibration.is_real("xss", "/unknown", []))
        self.assertFalse(calibration.is_real("xss", "/safe", [{"class": "xss", "location_contains": "/safe", "is_real": False}]))
        table = calibration.fit([{"attack_class": "xss", "confidence": "HIGH", "is_real": None}], ["fixture"])
        self.assertEqual(table["by_label"], {})
        self.assertEqual(table["meta"]["n_total"], 0)
        self.assertEqual(table["meta"]["n_unknown"], 1)

    def test_legacy_history_retained_but_not_merged_as_verified(self):
        local = {"meta": {"samples": 8}, "by_label": {"HIGH": {"n": 8, "k": 8}}}
        merged = calibration._merge(None, local)
        self.assertEqual(merged["by_label"], {})
        self.assertEqual(merged["meta"]["legacy_uncertain_samples"], 8)
        self.assertEqual(calibration._upgrade_local(local)["legacy_uncertain"], local)
        self.assertEqual(local["by_label"]["HIGH"]["n"], 8)

    def test_reimport_deduplicates_verified_observation(self):
        context = {"application_id": "fixture", "build_id": "rev", "identity": "anonymous", "endpoint": "/", "method": "GET", "parameter": ""}
        samples = dast_ingest.derive_labels(
            {"dast_context": context, "findings": [{"attack_class": "missing-csp", "confidence": "HIGH"}]},
            {"dast_context": context, "alerts": [{"pluginid": "10038"}]})["labels"]
        with tempfile.TemporaryDirectory() as directory, patch.object(calibration, "LOCAL_PATH", Path(directory) / "overlay.json"):
            first = calibration.record_samples(samples)
            second = calibration.record_samples(samples)
            self.assertEqual(first["meta"]["samples"], 1)
            self.assertEqual(second["meta"]["samples"], 1)
            self.assertEqual(second["by_label"]["HIGH"], {"n": 1, "k": 1})
            self.assertEqual(len(second["observations"]), 1)

    def test_unproven_labels_are_pending_review(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(calibration, "LOCAL_PATH", Path(directory) / "overlay.json"):
            result = calibration.record_samples([{"attack_class": "xss", "confidence": "HIGH", "is_real": True}])
            self.assertEqual(result["meta"]["samples"], 0)
            self.assertEqual(len(result["legacy_uncertain"]["pending_review"]), 1)
            self.assertEqual(calibration.load()["meta"]["local_samples"], 0)


if __name__ == "__main__":
    unittest.main()

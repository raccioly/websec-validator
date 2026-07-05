"""Tests for the enterprise/CI surface — SARIF + JSON formatters, baseline/diff, MCP server.

Stdlib unittest only (no network). Consistent with the rest of the suite.
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from websec_validator import baseline, formats            # noqa: E402
from websec_validator import mcp_server as mcp            # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"

LEDGER = {
    "schema_version": "1.0", "total": 2, "suppressed": 0,
    "by_severity": {"HIGH": 1, "LOW": 1}, "by_confidence": {"LOW": 2},
    "findings": [
        {"title": "ssrf sink", "category": "attack-surface", "attack_class": "ssrf",
         "severity": "HIGH", "confidence": "LOW", "location": "src/api.js",
         "evidence": [{"layer": "recon", "detail": "outbound HTTP with a variable URL"}],
         "standards": {"cwe": ["CWE-918 SSRF"], "asvs": "ASVS V12.6", "owasp_api": ["API7:2023 SSRF"]},
         "remediation": "validate + allowlist", "status": "open",
         "calibrated": {"p": 0.5, "ci": [0.2, 0.8], "n": 10, "basis": "label"}},
        {"title": "no CSP", "category": "transport", "attack_class": "missing-csp",
         "severity": "LOW", "confidence": "LOW", "location": "(response headers)",
         "evidence": [], "standards": {"cwe": ["CWE-693"], "asvs": "", "owasp_api": []},
         "remediation": "add csp", "status": "open"},
    ],
}


class SarifTests(unittest.TestCase):
    def setUp(self):
        self.sarif = formats.to_sarif(LEDGER, {"target": "/x"}, "0.10.0")
        self.run = self.sarif["runs"][0]

    def test_envelope_shape(self):
        self.assertEqual(self.sarif["version"], "2.1.0")
        self.assertEqual(self.run["tool"]["driver"]["name"], "websec-validator")
        self.assertEqual(len(self.run["tool"]["driver"]["rules"]), 2)   # one rule per attack class
        self.assertEqual(len(self.run["results"]), 2)

    def test_severity_to_level(self):
        r0, r1 = self.run["results"]
        self.assertEqual(r0["ruleId"], "websec/ssrf")
        self.assertEqual(r0["level"], "error")   # HIGH → error
        self.assertEqual(r1["level"], "note")    # LOW → note

    def test_pathlike_vs_prose_location(self):
        r0, r1 = self.run["results"]
        self.assertEqual(r0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/api.js")
        self.assertNotIn("locations", r1)                       # prose location can't anchor to a file
        self.assertEqual(r1["properties"]["locationHint"], "(response headers)")

    def test_fingerprint_present(self):
        self.assertIn("websecFingerprintV1", self.run["results"][0]["partialFingerprints"])


class JsonEnvelopeTests(unittest.TestCase):
    def test_envelope(self):
        env = formats.to_json(LEDGER, {"target": "/x"}, "0.10.0", "ts-1")
        self.assertEqual(env["schema_version"], formats.SCHEMA_VERSION)
        self.assertEqual(env["tool"], "websec-validator")
        self.assertEqual(env["summary"]["total"], 2)
        self.assertEqual(len(env["findings"]), 2)


class BaselineTests(unittest.TestCase):
    def test_fingerprint_stable_and_distinct(self):
        f = {"attack_class": "ssrf", "location": "a.js", "title": "t"}
        self.assertEqual(baseline.fingerprint(f), baseline.fingerprint(dict(f)))
        self.assertNotEqual(baseline.fingerprint(f), baseline.fingerprint({**f, "location": "b.js"}))

    def test_diff_and_gate(self):
        led = {"findings": [
            {"attack_class": "ssrf", "location": "a.js", "title": "t", "severity": "HIGH"},
            {"attack_class": "xss", "location": "b.js", "title": "t2", "severity": "LOW"}]}
        base_fps = {baseline.fingerprint(led["findings"][0])}   # the ssrf one is known
        d = baseline.diff(led, base_fps)
        self.assertEqual((d["new_count"], d["unchanged_count"]), (1, 1))
        states = {f["title"]: f["baseline_state"] for f in led["findings"]}
        self.assertEqual(states, {"t": "unchanged", "t2": "new"})
        self.assertEqual(baseline.gate_count(led, "high"), 1)          # only the HIGH ssrf
        self.assertEqual(baseline.gate_count(led, "low"), 2)           # both are >= LOW
        self.assertEqual(baseline.gate_count(led, "high", new_only=True), 0)  # the new one is LOW


class McpServerTests(unittest.TestCase):
    def _cap(self):
        out = []
        mcp._write = lambda m: out.append(m)   # capture responses instead of writing to stdout
        return out

    def test_initialize(self):
        out = self._cap()
        mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(out[0]["result"]["protocolVersion"], mcp.PROTOCOL_VERSION)
        self.assertEqual(out[0]["result"]["serverInfo"]["name"], "websec-validator")

    def test_tools_list(self):
        out = self._cap()
        mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in out[0]["result"]["tools"]}
        self.assertEqual(names, {"websec_recon", "websec_findings", "websec_sarif", "websec_briefing"})

    def test_notification_gets_no_response(self):
        out = self._cap()
        mcp.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})   # no id
        self.assertEqual(out, [])

    def test_unknown_method_errors(self):
        out = self._cap()
        mcp.handle({"jsonrpc": "2.0", "id": 9, "method": "does/not/exist"})
        self.assertIn("error", out[0])

    def test_tool_call_recon_returns_facts(self):
        out = self._cap()
        mcp.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                    "params": {"name": "websec_recon", "arguments": {"path": str(FIX / "node_app")}}})
        facts = json.loads(out[0]["result"]["content"][0]["text"])
        self.assertEqual(facts["tool"], "websec-validator")
        self.assertIn("stack", facts)

    def test_tool_call_sarif_returns_valid_sarif(self):
        out = self._cap()
        mcp.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                    "params": {"name": "websec_sarif", "arguments": {"path": str(FIX / "node_app")}}})
        sarif = json.loads(out[0]["result"]["content"][0]["text"])
        self.assertEqual(sarif["version"], "2.1.0")

    def test_tool_call_unknown_tool_is_error(self):
        out = self._cap()
        mcp.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                    "params": {"name": "nope", "arguments": {}}})
        self.assertTrue(out[0]["result"]["isError"])


if __name__ == "__main__":
    unittest.main()

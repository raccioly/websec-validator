"""Tests for the MCP server — the transport-agnostic `process()` core and the stdlib HTTP transport."""

import json
import sys
import threading
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from websec_validator import mcp_server                # noqa: E402

FIXTURE = str(ROOT / "tests" / "fixtures" / "py_app")


class ProcessTests(unittest.TestCase):
    def test_initialize(self):
        msg = mcp_server.process({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(msg["id"], 1)
        self.assertEqual(msg["result"]["serverInfo"]["name"], "websec-validator")

    def test_notification_returns_none(self):
        self.assertIsNone(mcp_server.process(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_tools_list(self):
        msg = mcp_server.process({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        names = {t["name"] for t in msg["result"]["tools"]}
        self.assertIn("websec_recon", names)
        self.assertIn("websec_briefing", names)

    def test_unknown_method(self):
        msg = mcp_server.process({"jsonrpc": "2.0", "id": 3, "method": "no/such"})
        self.assertEqual(msg["error"]["code"], -32601)

    def test_tools_call_recon(self):
        msg = mcp_server.process({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                  "params": {"name": "websec_recon", "arguments": {"path": FIXTURE}}})
        text = msg["result"]["content"][0]["text"]
        self.assertIn("stack", json.loads(text))

    def test_tools_call_unknown_tool_is_error(self):
        msg = mcp_server.process({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                                  "params": {"name": "nope", "arguments": {}}})
        self.assertTrue(msg["result"]["isError"])

    def test_findings_tool_enriches_when_graph_present(self):
        import json as _json
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as td:
            target = Path(td)
            (target / "app.py").write_text("import os\n")
            gp = target / "graphify-out" / "graph.json"
            gp.parent.mkdir(parents=True, exist_ok=True)
            gp.write_text(_json.dumps({"nodes": [{"id": "app", "label": "app.py",
                                                  "source_file": "app.py"}], "links": []}))
            msg = mcp_server.process({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                                      "params": {"name": "websec_findings",
                                                 "arguments": {"path": str(target)}}})
            ledger = _json.loads(msg["result"]["content"][0]["text"])
            self.assertIn("graph_enrichment", ledger)


class HttpTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = mcp_server.make_http_server(
            port=0, token="test-mcp-token", allowed_roots=[FIXTURE])
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def _headers(self):
        return {"Content-Type": "application/json", "Authorization": "Bearer test-mcp-token",
                "Accept": "application/json, text/event-stream",
                "MCP-Protocol-Version": mcp_server.PROTOCOL_VERSION}

    def _rpc(self, payload: dict):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/", data=json.dumps(payload).encode(),
            headers=self._headers(), method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, (json.loads(r.read() or b"null"))

    def test_health(self):
        with urllib.request.urlopen(urllib.request.Request(
                f"http://127.0.0.1:{self.port}/health", headers=self._headers()), timeout=5) as r:
            body = json.loads(r.read())
        self.assertEqual(body["name"], "websec-validator")
        self.assertEqual(body["transport"], "http")

    def test_initialize_over_http(self):
        status, body = self._rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(status, 200)
        self.assertEqual(body["result"]["serverInfo"]["name"], "websec-validator")

    def test_tools_call_over_http(self):
        status, body = self._rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                  "params": {"name": "websec_recon", "arguments": {"path": FIXTURE}}})
        self.assertEqual(status, 200)
        self.assertIn("stack", json.loads(body["result"]["content"][0]["text"]))

    def test_notification_gets_202(self):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/",
            data=json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode(),
            headers=self._headers(), method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            self.assertEqual(r.status, 202)

    def test_malformed_json_is_parse_error(self):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/", data=b"{not json",
            headers=self._headers(), method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
            self.fail("expected HTTP 400")
        except urllib.error.HTTPError as e:
            with e:
                self.assertEqual(e.code, 400)
                self.assertEqual(json.loads(e.read())["error"]["code"], -32700)


if __name__ == "__main__":
    unittest.main()

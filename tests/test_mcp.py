"""Tests for the MCP server — the transport-agnostic `process()` core and the stdlib HTTP transport."""

import json
import sys
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
        # Grab a free port, then hand it to serve_http.
        probe = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        cls.port = probe.server_address[1]
        probe.server_close()
        cls.thread = threading.Thread(
            target=mcp_server.serve_http, kwargs={"host": "127.0.0.1", "port": cls.port}, daemon=True)
        cls.thread.start()
        cls._wait_ready()

    @classmethod
    def _wait_ready(cls):
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{cls.port}/health", timeout=1).read()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("HTTP server did not come up")

    def _rpc(self, payload: dict):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/", data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, (json.loads(r.read() or b"null"))

    def test_health(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=5) as r:
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
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            self.assertEqual(r.status, 202)

    def test_malformed_json_is_parse_error(self):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/", data=b"{not json",
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
            self.fail("expected HTTP 400")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)
            self.assertEqual(json.loads(e.read())["error"]["code"], -32700)


if __name__ == "__main__":
    unittest.main()

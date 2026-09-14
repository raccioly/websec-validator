"""HTTP MCP trust-boundary regressions against real, explicitly closed local servers."""

import http.client
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from websec_validator import mcp_server


class HttpSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.allowed = Path(cls.temp.name) / "allowed"
        cls.allowed.mkdir()
        (cls.allowed / "app.py").write_text("import flask\n")
        cls.outside = Path(cls.temp.name) / "outside"
        cls.outside.mkdir()
        (cls.allowed / "escape").symlink_to(cls.outside, target_is_directory=True)
        cls.server = mcp_server.make_http_server(
            port=0, token="private-test-token", allowed_roots=[cls.allowed])
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.temp.cleanup()

    def request(self, payload=None, *, method="POST", path="/mcp", headers=None, raw=None):
        supplied = {"Content-Type": "application/json", "Authorization": "Bearer private-test-token",
                    "Accept": "application/json, text/event-stream",
                    "MCP-Protocol-Version": mcp_server.PROTOCOL_VERSION}
        for key, value in (headers or {}).items():
            if value is None:
                supplied.pop(key, None)
            else:
                supplied[key] = value
        body = raw if raw is not None else json.dumps(payload or {
            "jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=supplied)
            response = conn.getresponse()
            data = response.read()
            return response.status, json.loads(data) if data else None
        finally:
            conn.close()

    def test_startup_requires_explicit_credentials_and_roots(self):
        with patch.dict(os.environ, {}, clear=True):
            for kwargs in ({}, {"token": ""}, {"token": "bad token"}, {"token": "é"},
                           {"token": "valid"}, {"token": "valid", "allowed_roots": []},
                           {"token": "valid", "allowed_roots": [""]},
                           {"token": "valid", "allowed_roots": [self.allowed / "absent"]}):
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    mcp_server.make_http_server(port=0, **kwargs)

    def test_token_environment_and_literal_localhost(self):
        with patch.dict(os.environ, {"WEBSEC_MCP_TOKEN": "from-environment"}):
            server = mcp_server.make_http_server("localhost", 0, allowed_roots=[self.allowed])
            try:
                self.assertEqual(server.server_address[0], "127.0.0.1")
            finally:
                server.server_close()

    def test_non_loopback_bindings_rejected_before_listen(self):
        for host in ("0.0.0.0", "::", "192.0.2.1", "example.com", "127.0.0.1.evil.example"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                mcp_server.make_http_server(host, 0, token="test", allowed_roots=[self.allowed])

    def test_authentication_required_for_tools_and_health(self):
        for auth in (None, "Bearer wrong", "Basic private-test-token"):
            for method, path in (("POST", "/mcp"), ("GET", "/health")):
                with self.subTest(auth=auth, method=method):
                    status, body = self.request(method=method, path=path, headers={"Authorization": auth})
                    self.assertEqual(status, 401)
                    self.assertNotIn("private-test-token", json.dumps(body))

    def test_foreign_origin_and_host_rejected_even_with_token(self):
        for headers in ({"Origin": "https://evil.example"}, {"Origin": "null"},
                        {"Origin": f"http://127.0.0.1:{self.port}/"},
                        {"Origin": "http://localhost:1"}, {"Host": "evil.example"},
                        {"Host": f"127.0.0.1:{self.port}@evil.example"}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request(headers=headers)[0], 403)
        self.assertEqual(self.request(headers={"Origin": f"http://127.0.0.1:{self.port}"})[0], 200)

    def test_scan_scope_rejected_before_dispatch(self):
        for args in ({}, {"path": ""}, {"path": "."}, {"path": str(self.outside)},
                     {"path": str(self.allowed / ".." / "outside")},
                     {"path": str(self.allowed / "escape")}, {"path": str(self.allowed / "absent")},
                     {"path": []}, []):
            with self.subTest(args=args), patch.dict(mcp_server.DISPATCH, {"websec_recon": lambda a: "UNSAFE"}):
                status, body = self.request({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                           "params": {"name": "websec_recon", "arguments": args}})
                self.assertEqual(status, 200)
                self.assertTrue(body["result"]["isError"])
                self.assertNotIn("UNSAFE", json.dumps(body))

    def test_allowed_scan_returns_facts(self):
        status, body = self.request({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                    "params": {"name": "websec_recon", "arguments": {"path": str(self.allowed)}}})
        self.assertEqual(status, 200)
        self.assertIn("stack", json.loads(body["result"]["content"][0]["text"]))

    def test_version_negotiation_and_unsupported_headers(self):
        for version in mcp_server.HTTP_PROTOCOL_VERSIONS:
            status, body = self.request({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                        "params": {"protocolVersion": version}})
            self.assertEqual(body["result"]["protocolVersion"], version)
        status, body = self.request({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                    "params": {"protocolVersion": "2099-01-01"}})
        self.assertEqual(body["result"]["protocolVersion"], mcp_server.PROTOCOL_VERSION)
        for version in ("nonsense", "2024-11-05", "2099-01-01"):
            self.assertEqual(self.request(headers={"MCP-Protocol-Version": version})[0], 400)
        self.assertEqual(self.request(headers={"MCP-Protocol-Version": None})[0], 200)

    def test_mcp_get_is_405_health_is_separate(self):
        self.assertEqual(self.request(method="GET")[0], 405)
        self.assertEqual(self.request(method="GET", path="/")[0], 405)
        self.assertEqual(self.request(method="GET", path="/health")[0], 200)
        self.assertEqual(self.request(path="/other")[0], 404)

    def test_foreign_preflight_cannot_enable_browser_access(self):
        self.assertEqual(self.request(method="OPTIONS", headers={"Origin": "https://evil.example"})[0], 403)
        self.assertEqual(self.request(method="OPTIONS")[0], 405)

    def test_malformed_bodies_do_not_kill_server(self):
        for raw in (b"{", b"\xff", b"[" * 2000, b"[]", b"null", b'"string"'):
            with self.subTest(raw=raw[:30]):
                self.assertEqual(self.request(raw=raw)[0], 400)
        self.assertEqual(self.request()[0], 200)

    def test_framing_and_content_limits(self):
        for value, status in (("-1", 400), ("invalid", 400), (str(mcp_server.HTTP_MAX_BODY + 1), 413),
                              ("9" * 5000, 413)):
            self.assertEqual(self.request(headers={"Content-Length": value})[0], status)
        self.assertEqual(self.request(headers={"Transfer-Encoding": "chunked"})[0], 400)
        self.assertEqual(self.request(headers={"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.request(headers={"Accept": "application/json"})[0], 406)

    def test_duplicate_sensitive_headers_rejected(self):
        for key, value, expected in (("Host", f"127.0.0.1:{self.port}", 403),
                                     ("Authorization", "Bearer private-test-token", 401),
                                     ("Origin", f"http://127.0.0.1:{self.port}", 403),
                                     ("Content-Length", "0", 400)):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
            try:
                conn.putrequest("POST", "/mcp", skip_host=True)
                headers = {"Host": f"127.0.0.1:{self.port}", "Authorization": "Bearer private-test-token",
                           "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                           "Content-Length": "0", "Origin": f"http://127.0.0.1:{self.port}"}
                for name, item in headers.items():
                    conn.putheader(name, item)
                conn.putheader(key, value)
                conn.endheaders()
                response = conn.getresponse()
                self.assertEqual(response.status, expected)
                response.read()
            finally:
                conn.close()

    def test_notifications_never_dispatch_tools(self):
        with patch.dict(mcp_server.DISPATCH, {"websec_recon": lambda a: self.fail("notification scanned")}):
            status, body = self.request({"jsonrpc": "2.0", "method": "tools/call",
                                        "params": {"name": "websec_recon", "arguments": {"path": str(self.allowed)}}})
            self.assertEqual(status, 202)
            self.assertIsNone(body)

    def test_worker_limit_rejects_excess_connections(self):
        # Occupy slots deterministically; real HTTP request must be refused before a worker starts.
        for _ in range(mcp_server.HTTP_MAX_REQUESTS):
            self.assertTrue(self.server._slots.acquire(timeout=5))
        try:
            self.assertEqual(self.request()[0], 503)
        finally:
            for _ in range(mcp_server.HTTP_MAX_REQUESTS):
                self.server._slots.release()
        self.assertEqual(self.request()[0], 200)

    def test_slow_unauthenticated_headers_have_absolute_receive_deadline(self):
        with patch.object(mcp_server, "HTTP_RECEIVE_TIMEOUT", 0.3), \
                patch.object(mcp_server, "HTTP_SOCKET_TIMEOUT", 0.15):
            server = mcp_server.make_http_server(port=0, token="test", allowed_roots=[self.allowed])
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            clients = []
            try:
                port = server.server_address[1]
                for _ in range(mcp_server.HTTP_MAX_REQUESTS):
                    client = socket.create_connection(("127.0.0.1", port), timeout=2)
                    clients.append(client)
                    client.sendall(f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Drip: ".encode())
                deadline = time.monotonic() + 0.65
                while time.monotonic() < deadline:
                    for client in clients:
                        try:
                            client.sendall(b"x")
                        except OSError:
                            pass
                    time.sleep(0.04)  # Each drip is comfortably inside the inactivity timeout.
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                try:
                    conn.request("GET", "/health", headers={"Authorization": "Bearer test"})
                    response = conn.getresponse()
                    self.assertEqual(response.status, 200)
                    response.read()
                finally:
                    conn.close()
            finally:
                for client in clients:
                    client.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_authorized_root_swap_rejected_before_resolve_and_before_recon(self):
        for stage in ("dispatch", "recon"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as td:
                parent = Path(td).resolve()
                selected = parent / "selected"
                selected.mkdir()
                outside = parent / "outside"
                outside.mkdir()
                (outside / "app.py").write_text("SYNTHETIC_OUTSIDE_SOURCE = True")

                def swap():
                    selected.rename(parent / "old-selected")
                    selected.symlink_to(outside, target_is_directory=True)

                if stage == "dispatch":
                    original = mcp_server.DISPATCH["websec_recon"]

                    def dispatch(arguments):
                        swap()
                        return original(arguments)

                    mutation = patch.dict(mcp_server.DISPATCH, {"websec_recon": dispatch})
                else:
                    original = mcp_server.recon.build_facts

                    def build(root, version, **kwargs):
                        swap()
                        return original(root, version, **kwargs)

                    mutation = patch.object(mcp_server.recon, "build_facts", side_effect=build)
                with mutation:
                    response = mcp_server.process(
                        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "websec_recon", "arguments": {"path": str(selected)}}},
                        allowed_roots=(selected,))
                self.assertTrue(response["result"]["isError"])
                self.assertIsNone(mcp_server._HTTP_ROOT.get())


if __name__ == "__main__":
    unittest.main()

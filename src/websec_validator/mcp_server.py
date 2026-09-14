"""websec-mcp — stdio and authenticated loopback HTTP (JSON-RPC 2.0, stdlib only).

Exposes websec-validator's deterministic recon as typed MCP tools, so ANY MCP client (Claude Code,
Cursor, Cline, Windsurf, Zed) can call it directly instead of shelling out to the CLI and parsing
stdout. Every tool is read-only, takes a repo path, and returns structured facts / findings / SARIF /
briefing — code-in, artifacts-out. No LLM, no network to the target, zero runtime dependencies: the
transport is raw JSON-RPC 2.0 framed as newline-delimited JSON per the MCP stdio spec.

Wire it into a client's MCP config as:  command="websec", args=["mcp"]   (or command="websec-mcp").
"""

from __future__ import annotations

import json
import hmac
import ipaddress
import os
import socket
import sys
import tempfile
import threading
from contextvars import ContextVar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__, briefing, findings, formats, probes, recon, scanners

PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = (PROTOCOL_VERSION, "2025-06-18", "2025-03-26", "2024-11-05")
HTTP_PROTOCOL_VERSIONS = SUPPORTED_PROTOCOL_VERSIONS[:-1]
HTTP_MAX_BODY = 1024 * 1024
HTTP_MAX_REQUESTS = 4
HTTP_SOCKET_TIMEOUT = 5
HTTP_RECEIVE_TIMEOUT = 10
_HTTP_ROOT: ContextVar[tuple[Path, int, int] | None] = ContextVar("mcp_http_root", default=None)

TOOLS = [
    {"name": "websec_recon",
     "description": "Map a repo's attack surface (read-only): stack, routes, auth/tenant model, "
                    "dangerous sinks, and derived IDOR/SSRF/upload/write targeting. Returns FACTS.json.",
     "inputSchema": {"type": "object", "properties": {
         "path": {"type": "string", "description": "Absolute path to the repository to scan."}},
         "required": ["path"]}},
    {"name": "websec_findings",
     "description": "Return the traceable findings ledger for a repo: each finding with severity, "
                    "confidence, CWE/ASVS/OWASP citation, remediation, and a calibrated P(real).",
     "inputSchema": {"type": "object", "properties": {
         "path": {"type": "string", "description": "Absolute path to the repository to scan."}},
         "required": ["path"]}},
    {"name": "websec_sarif",
     "description": "Return SARIF 2.1.0 for a repo (for GitHub Code Scanning / dashboards).",
     "inputSchema": {"type": "object", "properties": {
         "path": {"type": "string", "description": "Absolute path to the repository to scan."}},
         "required": ["path"]}},
    {"name": "websec_briefing",
     "description": "Return the AGENT-BRIEFING.md marching-orders document for a repo — detected "
                    "surface, access-control map, targeting, findings, method, and staged probes.",
     "inputSchema": {"type": "object", "properties": {
         "path": {"type": "string", "description": "Absolute path to the repository to scan."}},
         "required": ["path"]}},
]


def _resolve(path: str) -> Path:
    p = Path(path or "").expanduser().resolve()
    if not p.is_dir():
        raise ValueError(f"not a directory: {p}")
    expected = _HTTP_ROOT.get()
    if expected is not None:
        info = p.stat()
        if p != expected[0] or (info.st_dev, info.st_ino) != expected[1:]:
            raise ValueError("repository path changed after authorization")
    return p


def _facts(path: str) -> dict:
    return recon.build_facts(_resolve(path), __version__, expected_root=_HTTP_ROOT.get())


def tool_websec_recon(a: dict) -> str:
    return json.dumps(_facts(a.get("path", "")), indent=2)


def _ledger_for(path: str, apply_policy: bool) -> tuple[dict, dict]:
    """Build the ledger for a repo and apply optional graphify blast-radius enrichment (best-effort).

    apply_policy=True honors the repo's `.websec-ignore` suppressions + acknowledgements (as the
    findings tool does); False builds the raw ledger (as the SARIF tool does).
    """
    root = _resolve(path)
    facts = recon.build_facts(root, __version__, expected_root=_HTTP_ROOT.get())
    supp = findings.load_suppressions(root) if apply_policy else []
    acks = findings.load_acknowledgements(root) if apply_policy else []
    ledger = findings.build_ledger(facts, None, None, supp, acks)
    try:
        from . import graph_enrich
        graph_enrich.enrich_ledger(ledger, root)
    except Exception:
        pass  # enrichment is optional — a missing/bad graph must not fail the tool call
    return facts, ledger


def tool_websec_findings(a: dict) -> str:
    _, ledger = _ledger_for(a.get("path", ""), apply_policy=True)
    return json.dumps(ledger, indent=2)


def tool_websec_sarif(a: dict) -> str:
    facts, ledger = _ledger_for(a.get("path", ""), apply_policy=False)
    return json.dumps(formats.to_sarif(ledger, facts, __version__), indent=2)


def tool_websec_briefing(a: dict) -> str:
    root = _resolve(a.get("path", ""))
    facts = recon.build_facts(root, __version__, expected_root=_HTTP_ROOT.get())
    det = scanners.detect(facts["stack"]["languages"])
    chosen = probes.applicable(facts)
    with tempfile.TemporaryDirectory() as td:
        manifest = probes.stage(chosen, Path(td), facts)
    # pass a ledger so the briefing's DAST-prediction section (§4b) is populated here too
    ledger = findings.build_ledger(facts, None, None, findings.load_suppressions(root),
                                   findings.load_acknowledgements(root))
    return briefing.render(facts, det, [], manifest, None, ledger)


DISPATCH = {
    "websec_recon": tool_websec_recon,
    "websec_findings": tool_websec_findings,
    "websec_sarif": tool_websec_sarif,
    "websec_briefing": tool_websec_briefing,
}


def _msg(rid, result=None, error=None) -> dict:
    msg = {"jsonrpc": "2.0", "id": rid}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    return msg


def process(req: dict, *, allowed_roots: tuple[Path, ...] | None = None,
            protocol_versions: tuple[str, ...] = SUPPORTED_PROTOCOL_VERSIONS) -> dict | None:
    """Handle one JSON-RPC request/notification and RETURN the response message (or None for a
    notification, which gets no reply). Transport-agnostic: shared by the stdio and HTTP servers."""
    if (not isinstance(req, dict) or req.get("jsonrpc") != "2.0"
            or not isinstance(req.get("method"), str)
            or ("id" in req and (isinstance(req["id"], bool)
                                or not isinstance(req["id"], (int, str))))):
        return _msg(None, error={"code": -32600, "message": "invalid request"})
    method = req.get("method")
    rid = req.get("id")
    # A notification must never trigger an expensive tool call or receive a JSON-RPC reply.
    if "id" not in req:
        return None
    params = req.get("params", {})
    if not isinstance(params, dict):
        return _msg(rid, error={"code": -32602, "message": "params must be an object"})
    if method == "initialize":
        requested = params.get("protocolVersion", PROTOCOL_VERSION)
        if not isinstance(requested, str):
            return _msg(rid, error={"code": -32602, "message": "invalid protocolVersion"})
        negotiated = requested if requested in protocol_versions else protocol_versions[0]
        return _msg(rid, {"protocolVersion": negotiated,
                          "capabilities": {"tools": {"listChanged": False}},
                          "serverInfo": {"name": "websec-validator", "version": __version__}})
    if method in ("notifications/initialized", "initialized", "notifications/cancelled"):
        return None  # notification — no reply
    if method == "ping":
        return _msg(rid, {})
    if method == "tools/list":
        return _msg(rid, {"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name")
        if not isinstance(name, str) or name not in DISPATCH:
            return _msg(rid, {"content": [{"type": "text", "text": f"unknown tool: {name}"}], "isError": True})
        try:
            arguments = params.get("arguments", {})
            if not isinstance(arguments, dict):
                raise ValueError("arguments must be an object")
            if allowed_roots is not None:
                path = arguments.get("path")
                if not isinstance(path, str) or not path.strip() or not Path(path).is_absolute():
                    raise ValueError("an absolute repository path is required")
                resolved = Path(path).resolve()
                if not any(resolved.is_relative_to(root) for root in allowed_roots):
                    raise ValueError("repository path is outside the configured scan roots")
                if not resolved.is_dir():
                    raise ValueError("repository path must be an existing directory")
                info = resolved.stat()
                arguments = {**arguments, "path": str(resolved)}
                scope = _HTTP_ROOT.set((resolved, info.st_dev, info.st_ino))
                try:
                    text = DISPATCH[name](arguments)
                finally:
                    _HTTP_ROOT.reset(scope)
            else:
                text = DISPATCH[name](arguments)
            return _msg(rid, {"content": [{"type": "text", "text": text}]})
        except Exception as e:  # a tool error is reported to the model, not a protocol crash
            return _msg(rid, {"content": [{"type": "text", "text": f"error: {type(e).__name__}: {e}"}],
                             "isError": True})
    if rid is not None:
        return _msg(rid, error={"code": -32601, "message": f"method not found: {method}"})
    return None  # unknown notification → ignore


def _write(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def handle(req: dict) -> None:
    """stdio convenience: process one request and write any response to stdout."""
    msg = process(req)
    if msg is not None:
        _write(msg)


def serve(argv=None) -> int:
    """Read newline-delimited JSON-RPC from stdin, dispatch, write responses to stdout (MCP stdio)."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue  # malformed frame — skip rather than crash the server
        try:
            handle(req)
        except Exception as e:  # never let one bad request kill the loop
            if isinstance(req, dict) and req.get("id") is not None:
                _write(_msg(req.get("id"), error={"code": -32603, "message": f"internal error: {e}"}))
    return 0


class _BoundedHTTPServer(ThreadingHTTPServer):
    """Bound connections before spawning threads, including clients that stall before headers."""

    daemon_threads = True
    request_queue_size = HTTP_MAX_REQUESTS

    def __init__(self, *args, **kwargs):
        self._slots = threading.BoundedSemaphore(HTTP_MAX_REQUESTS)
        super().__init__(*args, **kwargs)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(HTTP_SOCKET_TIMEOUT)
        return request, address

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\n"
                                b"Connection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        # Client disconnects must not dump request context or local paths into logs.
        return


def make_http_server(host: str = "127.0.0.1", port: int = 8733, *,
                     token: str | None = None,
                     allowed_roots: list[Path | str] | tuple[Path | str, ...] | None = None):
    """Create a local, authenticated JSON-only Streamable HTTP server.

    Roots are explicitly granted by the operator at startup, never by MCP client roots. This is
    a stateless local integration: there are no SSE streams, sessions, or OAuth endpoints.
    """
    if host == "localhost":
        host = "127.0.0.1"  # Never rely on DNS for the local binding.
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("HTTP MCP host must be a loopback IP address or localhost") from None
    if not address.is_loopback:
        raise ValueError("HTTP MCP host must be a loopback IP address or localhost")
    token = os.environ.get("WEBSEC_MCP_TOKEN") if token is None else token
    if not isinstance(token, str) or not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ValueError("set WEBSEC_MCP_TOKEN to a nonempty token of visible ASCII characters")
    if not allowed_roots or isinstance(allowed_roots, (str, bytes, Path)):
        raise ValueError("HTTP MCP requires at least one explicit allowed scan root")
    if any(not isinstance(root, (str, Path)) or not str(root).strip() for root in allowed_roots):
        raise ValueError("every HTTP MCP allowed scan root must be a nonempty path")
    roots = tuple(Path(root).expanduser().resolve() for root in allowed_roots)
    if any(not root.is_dir() for root in roots):
        raise ValueError("every HTTP MCP allowed scan root must be an existing directory")
    expected_auth = ("Bearer " + token).encode("ascii")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self):
            super().setup()
            # An inactivity timeout alone can be defeated by dripping bytes forever.
            # This deadline covers the entire header/body receive phase, including
            # unauthenticated clients; it does not impose a deadline on recon work.
            self._receive_timer = threading.Timer(HTTP_RECEIVE_TIMEOUT, self._expire_receive)
            self._receive_timer.daemon = True
            self._receive_timer.start()

        def _expire_receive(self):
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        def finish(self):
            self._receive_timer.cancel()
            super().finish()

        def parse_request(self) -> bool:
            # Gate every method, including unsupported verbs, before dispatch or body reads.
            return super().parse_request() and self._trusted()

        def _send(self, code: int, payload: dict | None = None, **headers) -> None:
            body = json.dumps(payload).encode("utf-8") if payload is not None else b""
            self.close_connection = True
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.send_header("Cache-Control", "no-store")
            for name, value in headers.items():
                self.send_header(name.replace("_", "-"), value)
            self.end_headers()
            self.wfile.write(body)

        def _trusted(self) -> bool:
            # Exact authorities prevent Host-based DNS rebinding and ambiguous duplicate headers.
            authorities = self.server.allowed_authorities
            hosts = self.headers.get_all("Host", [])
            origins = self.headers.get_all("Origin", [])
            if (len(hosts) != 1 or hosts[0].lower() not in authorities
                    or len(origins) > 1
                    or (origins and origins[0] not in {"http://" + h for h in authorities})):
                self._send(403, {"error": "untrusted Host or Origin"})
                return False
            auth = self.headers.get_all("Authorization", [])
            if len(auth) != 1 or not hmac.compare_digest(auth[0].encode("utf-8"), expected_auth):
                self._send(401, {"error": "authentication required"}, WWW_Authenticate="Bearer")
                return False
            return True

        def do_GET(self):  # noqa: N802
            self._receive_timer.cancel()
            if self.path in ("/health", "/healthz"):
                self._send(200, {"name": "websec-validator", "version": __version__,
                                 "transport": "http", "protocolVersion": PROTOCOL_VERSION})
            elif self.path in ("/", "/mcp"):
                self._send(405, {"error": "SSE is not supported"}, Allow="POST")
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if self.path not in ("/", "/mcp"):
                self._send(404, {"error": "not found"})
                return
            versions = self.headers.get_all("MCP-Protocol-Version", [])
            if len(versions) > 1 or (versions and versions[0] not in HTTP_PROTOCOL_VERSIONS):
                self._send(400, {"error": "unsupported MCP protocol version"})
                return
            if self.headers.get_content_type() != "application/json":
                self._send(415, {"error": "Content-Type must be application/json"})
                return
            accepts = {item.strip().split(";", 1)[0] for item in self.headers.get("Accept", "").split(",")}
            if not {"application/json", "text/event-stream"}.issubset(accepts):
                self._send(406, {"error": "Accept must include application/json and text/event-stream"})
                return
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get_all("Transfer-Encoding") or len(lengths) != 1:
                self._send(400, {"error": "one Content-Length and no Transfer-Encoding required"})
                return
            if not lengths[0].isascii() or not lengths[0].isdigit():
                self._send(400, {"error": "invalid Content-Length"})
                return
            # Bound the decimal string before int conversion (including Python's digit limit).
            if len(lengths[0]) > 10 or int(lengths[0]) > HTTP_MAX_BODY:
                self._send(413, {"error": "request body too large"})
                return
            length = int(lengths[0])
            try:
                raw = self.rfile.read(length)
                self._receive_timer.cancel()
                if len(raw) != length:
                    self._send(400, {"error": "incomplete request body"})
                    return
                req = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeError, RecursionError):
                self._send(400, _msg(None, error={"code": -32700, "message": "parse error"}))
                return
            except TimeoutError:
                self._send(408, {"error": "request timed out"})
                return
            # An absent header uses the spec's 2025-03-26 compatibility default. No session state
            # is needed: all accepted versions support this single JSON response subset.
            if (isinstance(req, dict) and req.get("jsonrpc") == "2.0" and "method" not in req
                    and "id" in req and ("result" in req) != ("error" in req)):
                self._send(202)
                return
            msg = process(req, allowed_roots=roots, protocol_versions=HTTP_PROTOCOL_VERSIONS)
            if msg is None:
                self._send(202)
            else:
                self._send(400 if msg.get("error", {}).get("code") == -32600 else 200, msg)

        def do_DELETE(self):  # noqa: N802
            self._send(405, {"error": "sessions are not supported"}, Allow="POST")

        def do_OPTIONS(self):  # noqa: N802
            self._send(405, {"error": "method not supported"}, Allow="POST")

        do_PUT = do_OPTIONS
        do_PATCH = do_OPTIONS

        def log_message(self, *args):
            return

    class Server(_BoundedHTTPServer):
        address_family = socket.AF_INET6 if address.version == 6 else socket.AF_INET

    httpd = Server((host, port), Handler)
    actual_port = httpd.server_address[1]
    authority_host = f"[{address}]" if address.version == 6 else str(address)
    httpd.allowed_authorities = {f"{authority_host}:{actual_port}", f"localhost:{actual_port}"}
    return httpd


def serve_http(host: str = "127.0.0.1", port: int = 8733, *, token: str | None = None,
               allowed_roots: list[Path | str] | tuple[Path | str, ...] | None = None) -> int:
    """Run authenticated loopback HTTP; stdio remains the default for trusted local clients."""
    httpd = make_http_server(host, port, token=token, allowed_roots=allowed_roots)
    print(f"websec-mcp HTTP on loopback port {httpd.server_address[1]}"
          " (authenticated POST /mcp; GET /health)", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())

"""websec-mcp — Model Context Protocol server over stdio (JSON-RPC 2.0, stdlib only).

Exposes websec-validator's deterministic recon as typed MCP tools, so ANY MCP client (Claude Code,
Cursor, Cline, Windsurf, Zed) can call it directly instead of shelling out to the CLI and parsing
stdout. Every tool is read-only, takes a repo path, and returns structured facts / findings / SARIF /
briefing — code-in, artifacts-out. No LLM, no network to the target, zero runtime dependencies: the
transport is raw JSON-RPC 2.0 framed as newline-delimited JSON per the MCP stdio spec.

Wire it into a client's MCP config as:  command="websec", args=["mcp"]   (or command="websec-mcp").
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from . import __version__, briefing, findings, formats, probes, recon, scanners

PROTOCOL_VERSION = "2024-11-05"

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
    return p


def _facts(path: str) -> dict:
    return recon.build_facts(_resolve(path), __version__)


def tool_websec_recon(a: dict) -> str:
    return json.dumps(_facts(a.get("path", "")), indent=2)


def _ledger_for(path: str, apply_policy: bool) -> tuple[dict, dict]:
    """Build the ledger for a repo and apply optional graphify blast-radius enrichment (best-effort).

    apply_policy=True honors the repo's `.websec-ignore` suppressions + acknowledgements (as the
    findings tool does); False builds the raw ledger (as the SARIF tool does).
    """
    root = _resolve(path)
    facts = recon.build_facts(root, __version__)
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
    facts = recon.build_facts(root, __version__)
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


def process(req: dict) -> dict | None:
    """Handle one JSON-RPC request/notification and RETURN the response message (or None for a
    notification, which gets no reply). Transport-agnostic: shared by the stdio and HTTP servers."""
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        return _msg(rid, {"protocolVersion": PROTOCOL_VERSION,
                          "capabilities": {"tools": {"listChanged": False}},
                          "serverInfo": {"name": "websec-validator", "version": __version__}})
    if method in ("notifications/initialized", "initialized", "notifications/cancelled"):
        return None  # notification — no reply
    if method == "ping":
        return _msg(rid, {})
    if method == "tools/list":
        return _msg(rid, {"tools": TOOLS})
    if method == "tools/call":
        params = req.get("params", {}) or {}
        name = params.get("name")
        if name not in DISPATCH:
            return _msg(rid, {"content": [{"type": "text", "text": f"unknown tool: {name}"}], "isError": True})
        try:
            text = DISPATCH[name](params.get("arguments", {}) or {})
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


def serve_http(host: str = "127.0.0.1", port: int = 8733) -> int:
    """Serve MCP over HTTP (JSON-RPC POST) with only the stdlib — no starlette, no new dependency, so
    a team can point one URL at the recon tools.

    Trust boundary: the tools read local filesystem paths and run recon on them, so a client can scan
    any path on THIS host. It therefore binds to 127.0.0.1 by default; exposing it on a routable
    interface (--host 0.0.0.0) shares that capability with anyone who can reach the port — do that only
    on a trusted network. Still read-only: it never writes to or touches the target app.
    """
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, code: int, payload: dict, ctype: str = "application/json") -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802 — a tiny health endpoint for load balancers / `curl`
            if self.path in ("/", "/health", "/healthz"):
                self._send(200, {"name": "websec-validator", "version": __version__,
                                 "transport": "http", "protocolVersion": PROTOCOL_VERSION})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                req = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                self._send(400, _msg(None, error={"code": -32700, "message": "parse error"}))
                return
            try:
                msg = process(req)
            except Exception as e:
                rid = req.get("id") if isinstance(req, dict) else None
                self._send(200, _msg(rid, error={"code": -32603, "message": f"internal error: {e}"}))
                return
            # A notification (no response) still needs a valid HTTP reply — 202 Accepted, empty body.
            if msg is None:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._send(200, msg)

        def log_message(self, *args):  # keep stdout clean; the CLI prints its own startup line
            return

    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"websec-mcp HTTP on http://{host}:{port}  (POST JSON-RPC · GET /health)", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())

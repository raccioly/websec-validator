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


def tool_websec_findings(a: dict) -> str:
    facts = _facts(a.get("path", ""))
    root = _resolve(a["path"])
    ledger = findings.build_ledger(facts, None, None, findings.load_suppressions(root),
                                   findings.load_acknowledgements(root))
    return json.dumps(ledger, indent=2)


def tool_websec_sarif(a: dict) -> str:
    facts = _facts(a.get("path", ""))
    ledger = findings.build_ledger(facts, None, None, [])
    return json.dumps(formats.to_sarif(ledger, facts, __version__), indent=2)


def tool_websec_briefing(a: dict) -> str:
    root = _resolve(a.get("path", ""))
    facts = recon.build_facts(root, __version__)
    det = scanners.detect(facts["stack"]["languages"])
    chosen = probes.applicable(facts)
    with tempfile.TemporaryDirectory() as td:
        manifest = probes.stage(chosen, Path(td), facts)
    return briefing.render(facts, det, [], manifest, None)


DISPATCH = {
    "websec_recon": tool_websec_recon,
    "websec_findings": tool_websec_findings,
    "websec_sarif": tool_websec_sarif,
    "websec_briefing": tool_websec_briefing,
}


def _write(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _respond(rid, result=None, error=None) -> None:
    msg = {"jsonrpc": "2.0", "id": rid}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    _write(msg)


def handle(req: dict) -> None:
    """Handle one JSON-RPC request/notification. Notifications (no id) never get a response."""
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        _respond(rid, {"protocolVersion": PROTOCOL_VERSION,
                       "capabilities": {"tools": {"listChanged": False}},
                       "serverInfo": {"name": "websec-validator", "version": __version__}})
    elif method in ("notifications/initialized", "initialized", "notifications/cancelled"):
        return  # notification — no reply
    elif method == "ping":
        _respond(rid, {})
    elif method == "tools/list":
        _respond(rid, {"tools": TOOLS})
    elif method == "tools/call":
        params = req.get("params", {}) or {}
        name = params.get("name")
        if name not in DISPATCH:
            _respond(rid, {"content": [{"type": "text", "text": f"unknown tool: {name}"}], "isError": True})
            return
        try:
            text = DISPATCH[name](params.get("arguments", {}) or {})
            _respond(rid, {"content": [{"type": "text", "text": text}]})
        except Exception as e:  # a tool error is reported to the model, not a protocol crash
            _respond(rid, {"content": [{"type": "text", "text": f"error: {type(e).__name__}: {e}"}],
                           "isError": True})
    elif rid is not None:
        _respond(rid, error={"code": -32601, "message": f"method not found: {method}"})
    # else: unknown notification → ignore


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
                _respond(req.get("id"), error={"code": -32603, "message": f"internal error: {e}"})
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())

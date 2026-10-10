# MCP server reference

`websec mcp` exposes websec's deterministic recon as typed Model Context Protocol tools, so an MCP
client can call it directly instead of shelling out and parsing stdout. It runs over stdio by
default, or over authenticated loopback HTTP. It is implemented in
[`mcp_server.py`](../../src/websec_validator/mcp_server.py) with the standard library only.

## Quick start

Register the stdio server with your client using the common `mcpServers` shape:

```json
{
  "mcpServers": {
    "websec": { "command": "websec", "args": ["mcp"] }
  }
}
```

Then ask the agent to call `websec_findings` or `websec_briefing` with the absolute path of your
repository. Client-specific notes are under [Registering with clients](#registering-with-clients).

## Transports

### stdio

```bash
websec mcp
```

The `websec-mcp` console script, installed with the package, starts the same stdio server and takes
no arguments.

- Framing: newline-delimited JSON-RPC 2.0 on stdin and stdout. Blank lines and malformed frames are
  skipped; one bad request never stops the loop.
- Trust: the server runs with the launching user's permissions and can analyze any directory that
  user can read. There is no root restriction in stdio mode; the client process is the trust
  boundary.
- Exit: returns `0` when stdin closes.

### Loopback HTTP

```bash
export WEBSEC_MCP_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
websec mcp --http --allow-root /absolute/path/to/project
```

A stateless, JSON-only subset of the Streamable HTTP transport: no SSE streams, no sessions, no
OAuth. Startup requirements, each refused with exit `2` if unmet:

| Requirement | Rule |
|---|---|
| `WEBSEC_MCP_TOKEN` | Set, non-empty, visible ASCII only (no spaces or control characters). |
| `--allow-root PATH` | At least one, each an existing directory. Repeat for more projects. There is no default root; the server refuses to start without one. |
| `--host` | A loopback IP or `localhost` (default `127.0.0.1`). `localhost` is bound as `127.0.0.1` without a DNS lookup. Any non-loopback address is refused. |
| `--port` | Default `8733`. |

On startup it prints `websec-mcp HTTP on loopback port <port>` to stderr.

**Endpoints.**

| Method and path | Response |
|---|---|
| `POST /mcp` or `POST /` | JSON-RPC request; JSON response. Notifications and client responses get `202`. |
| `GET /health` or `GET /healthz` | `200` with `name`, `version`, `transport` and `protocolVersion`. Requires the same Host and bearer-token checks as `POST`. Reports liveness only, not that recon or authorization works. |
| `GET /mcp` or `GET /` | `405` (SSE is not supported). |
| `DELETE`, `OPTIONS`, `PUT`, `PATCH` | `405`. |
| Anything else | `404`. |

**Request checks**, applied before any body is read:

| Check | Rule | Failure |
|---|---|---|
| `Host` | Exactly one header, equal to `127.0.0.1:<port>` (or `[::1]:<port>` on IPv6) or `localhost:<port>`. Blocks DNS rebinding. | `403` |
| `Origin` | Optional. If present, exactly one, equal to `http://` plus an allowed `Host` value. | `403` |
| `Authorization` | Exactly one `Bearer <token>` header, compared in constant time. | `401` |
| `MCP-Protocol-Version` | Optional. If present, one of `2025-11-25`, `2025-06-18`, `2025-03-26`. | `400` |
| `Content-Type` | `application/json`. | `415` |
| `Accept` | Must include both `application/json` and `text/event-stream`. | `406` |
| Framing | Exactly one `Content-Length`, no `Transfer-Encoding`. | `400` |
| Body size | At most 1 MiB. | `413` |
| Body | Valid UTF-8 JSON. | `400` (JSON-RPC `-32700`) |

**Limits.** At most 4 requests are handled at once; further connections get `503` without
authentication or a worker. Each socket has a 5-second inactivity timeout, and receiving the whole
request (headers and body) has an absolute 10-second deadline, so a client cannot drip bytes
forever. Tool execution itself has no deadline. Every response closes the connection and sends
`Cache-Control: no-store`. Request logging is disabled, so paths and headers are not written to
logs.

**Allowed roots.** Roots are granted by the operator at startup, never by the client's MCP roots.
For every repository tool call:

- `path` must be an absolute path to an existing directory inside one of the `--allow-root`
  directories, after symlinks are resolved;
- the directory's identity (device and inode) is pinned for the call, so a directory swapped or
  renamed mid-call is rejected with `repository path changed after authorization`.

`websec_check_updates` takes no path and is not root-checked.

A quick manual check with `curl`:

```bash
curl -s http://127.0.0.1:8733/mcp \
  -H "Authorization: Bearer $WEBSEC_MCP_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

> [!WARNING]
> The HTTP transport is a single-user local integration. Do not publish it beyond the machine
> through a port forward or a reverse proxy: a proxy that rewrites `Host` to the loopback value
> would leave the token as the only barrier. For container use, see
> [integrations/README.md](../integrations/README.md).

## Protocol

| Method | Behaviour |
|---|---|
| `initialize` | Returns `protocolVersion`, `capabilities: {"tools": {"listChanged": false}}` and `serverInfo` (`name: "websec-validator"` and the version). The requested version is echoed if supported, otherwise the newest is returned. stdio supports `2025-11-25`, `2025-06-18`, `2025-03-26` and `2024-11-05`; HTTP supports all but `2024-11-05`. |
| `ping` | Returns `{}`. |
| `tools/list` | Returns the tool definitions below, with their input schemas. |
| `tools/call` | Runs a tool. The result is a single `text` content item. |
| `notifications/initialized`, `initialized`, `notifications/cancelled` | Accepted; no reply. |
| Any request without an `id` | Treated as a notification; no reply and no tool execution. |
| Unknown method | Error `-32601`. |

A malformed request (not JSON-RPC 2.0, missing `method`, or a non-string, non-integer `id`) gets
error `-32600`; non-object `params` gets `-32602`. A tool failure is not a protocol error: it
returns a normal result with `isError: true` and text such as `error: ValueError: not a directory:
...`, so the model can read it.

## Tools

All repository tools run **recon only**: no static scans, no network access, nothing written to
the repository or to `websec-out/`. (`websec_briefing` does run each installed scanner's version
probe so the briefing can list which tools are available.) Each call re-analyzes the repository;
nothing is cached between calls. For scanner results, baselines or gates, use [`websec run`](cli.md#websec-run).

| Tool | Arguments | Returns | `.websec-ignore` | Graph enrichment |
|---|---|---|---|---|
| `websec_recon` | `path` (string, required) | `FACTS.json` as JSON text: stack, routes, auth and tenant model, sinks, IDOR/SSRF/upload/write targeting. | n/a | no |
| `websec_findings` | `path` (string, required) | The findings ledger as JSON text, with severity, confidence, CWE/ASVS/OWASP citation, remediation and calibrated `P(real)` per finding. | applied | implicit graph, best effort |
| `websec_sarif` | `path` (string, required) | SARIF 2.1.0 as JSON text. | **not applied** (raw ledger) | implicit graph, best effort |
| `websec_briefing` | `path` (string, required) | `AGENT-BRIEFING.md` as Markdown. Probe templates are staged in a temporary directory that is deleted after the call. | applied | no |
| `websec_check_updates` | `online` (boolean, default `false`) | The `update-check` result as JSON plus an `advice` string. | n/a | n/a |

Notes:

- `path` is described in the schema as an absolute path. Over HTTP it must be absolute. Over stdio
  a relative path is resolved against the server's working directory; prefer absolute paths.
- `websec_sarif` deliberately builds the ledger without suppressions or acknowledgements, so it can
  contain findings that `websec_findings` and `websec run`'s `results.sarif` leave out or mark as
  suppressed.
- Graph enrichment reads `<path>/graphify-out/graph.json` if present; an unreadable graph never
  fails the call. See [configuration.md](configuration.md#graphify-graph-input).
- `websec_check_updates` accepts no other argument; an unknown key or a non-boolean `online` is an
  error. With `online: true` it contacts PyPI (see the next section).

## Registering with clients

The stdio form is the recommended one for local agents.

**Claude Code.** Add the server for a project with the CLI, or commit a `.mcp.json` at the
repository root using the common shape from [Quick start](#quick-start):

```bash
claude mcp add websec -- websec mcp
```

**Cursor.** Put the common shape in `.cursor/mcp.json` in the project, or `~/.cursor/mcp.json` for
all projects.

**Cline and Windsurf.** Both read the common `mcpServers` shape; consult your client's MCP docs for
where its settings file lives.

**Zed.** Zed configures MCP servers under its own settings key rather than `mcpServers`. Consult
Zed's MCP documentation and use `websec` with the argument `mcp` as the command.

**If `websec` is not found.** Desktop applications often start with a shorter `PATH` than your
shell. Use the absolute path of the executable (for example from `command -v websec`) as
`command`, or the `websec-mcp` console script with no arguments.

**HTTP clients.** If your client supports Streamable HTTP with custom headers, point it at
`http://127.0.0.1:8733/mcp` and send `Authorization: Bearer <token>`. Header and URL syntax differ
between clients; consult their MCP docs, and keep the token in your local secret environment rather
than in a committed config file.

Broader agent setup, including `websec install` and the agent-loop hook, is in
[ai-agents.md](../guides/ai-agents.md).

## Update-check approval rule

The `websec_check_updates` tool description, and the text `websec update-check` prints, carry this
rule verbatim (from `updates.CONSENT`):

> At the start of each security review, ask the user whether they want to check PyPI for a newer
> WebSec release. Respect their answer for that review. Only after approval, run
> `websec update-check --online` or call `websec_check_updates` with `online: true`. Checking does
> not install anything. If newer, offer an upgrade with separate approval; never automatically
> install, upgrade, switch revisions or refresh the agent plugin. A decline does not block review.

What the server does and does not guarantee:

- `online: false` (the default) reads only the local cache and makes no request.
- `online: true` sends one `GET` to `https://pypi.org/simple/websec-validator/` (no redirects,
  cookies or proxies), and stores only the observed version and check time. It installs nothing.
- The server cannot verify that a human approved the call; `online: true` represents consent
  supplied by the client. The rule above is how an agent should obtain it.
- The result never affects findings, coverage or any gate. A failed check returns
  `status: "unavailable"` and the review continues.

Cache location and validation are described in
[configuration.md](configuration.md#caches-and-local-state).

## See also

- [cli.md](cli.md#websec-mcp): command-line options for `websec mcp`
- [configuration.md](configuration.md#mcp-token-and-allowed-roots): token and root rules
- [ai-agents.md](../guides/ai-agents.md): using websec with AI coding agents
- [integrations/README.md](../integrations/README.md): container and integration notes

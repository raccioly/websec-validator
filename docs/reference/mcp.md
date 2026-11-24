# MCP server reference

`websec mcp` offers websec's deterministic recon as typed Model Context Protocol tools. An MCP
client can call the tools directly. It does not need to run a command and parse stdout. The server
runs over stdio by default, or over authenticated loopback HTTP. It is in
[`mcp_server.py`](../../src/websec_validator/mcp_server.py) and uses only the standard library.

## Quick start

Register the stdio server with your client. Use the common `mcpServers` shape:

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
- Trust: the server runs with the permissions of the user who starts it. It can analyze any
  directory that user can read. Stdio mode has no root restriction. The client process is the trust
  boundary.
- Exit: returns `0` when stdin closes.

### Loopback HTTP

```bash
export WEBSEC_MCP_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
websec mcp --http --allow-root /absolute/path/to/project
```

This is a stateless, JSON-only subset of the Streamable HTTP transport. It has no SSE streams, no
sessions and no OAuth. The server has these startup requirements. It refuses to start with exit `2`
if one is not met:

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

**Limits.** The server handles at most 4 requests at once. Further connections get `503` without
authentication or a worker. Each socket has a 5-second inactivity timeout. Receiving the whole
request (headers and body) has an absolute 10-second deadline, so a client cannot send bytes slowly
forever. Tool execution itself has no deadline. Every response closes the connection and sends
`Cache-Control: no-store`. Request logging is off, so the server does not write paths and headers
to logs.

**Allowed roots.** The operator grants roots at startup. The client's MCP roots never grant them.
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
> The HTTP transport is a single-user local integration. Do not expose it beyond the machine
> through a port forward or a reverse proxy. A proxy that rewrites `Host` to the loopback value
> leaves the token as the only barrier. For container use, see
> [integrations/README.md](../integrations/README.md).

## Protocol

| Method | Behavior |
|---|---|
| `initialize` | Returns `protocolVersion`, `capabilities: {"tools": {"listChanged": false}}` and `serverInfo` (`name: "websec-validator"` and the version). The requested version is echoed if supported, otherwise the newest is returned. stdio supports `2025-11-25`, `2025-06-18`, `2025-03-26` and `2024-11-05`; HTTP supports all but `2024-11-05`. |
| `ping` | Returns `{}`. |
| `tools/list` | Returns the tool definitions below, with their input schemas. |
| `tools/call` | Runs a tool. The result is a single `text` content item. |
| `notifications/initialized`, `initialized`, `notifications/cancelled` | Accepted; no reply. |
| Any request without an `id` | Treated as a notification; no reply and no tool execution. |
| Unknown method | Error `-32601`. |

A malformed request (not JSON-RPC 2.0, missing `method`, or a non-string, non-integer `id`) gets
error `-32600`. Non-object `params` gets `-32602`. A tool failure is not a protocol error. It
returns a normal result with `isError: true` and text such as `error: ValueError: not a directory:
...`, so the model can read it.

## Tools

All repository tools run **recon only**. They do no static scans and no network access. They write
nothing to the repository or to `websec-out/`. (`websec_briefing` does run each installed scanner's
version probe, so the briefing can list which tools are available.) Each call analyzes the
repository again. The server caches nothing between calls. For scanner results, baselines or gates,
use [`websec run`](cli.md#websec-run).

| Tool | Arguments | Returns | `.websec-ignore` | Graph enrichment |
|---|---|---|---|---|
| `websec_recon` | `path` (string, required) | `FACTS.json` as JSON text: stack, routes, auth and tenant model, sinks, IDOR/SSRF/upload/write targeting. | n/a | no |
| `websec_findings` | `path` (string, required) | The findings ledger as JSON text, with severity, confidence, CWE/ASVS/OWASP citation, remediation and calibrated `P(real)` per finding. | applied | implicit graph, best effort |
| `websec_sarif` | `path` (string, required) | SARIF 2.1.0 as JSON text. | **not applied** (raw ledger) | implicit graph, best effort |
| `websec_briefing` | `path` (string, required) | `AGENT-BRIEFING.md` as Markdown. Probe templates are staged in a temporary directory that is deleted after the call. | applied | no |
| `websec_check_updates` | `online` (boolean, default `false`) | The `update-check` result as JSON plus an `advice` string. | n/a | n/a |

Notes:

- The schema describes `path` as an absolute path. Over HTTP it must be absolute. Over stdio, the
  server resolves a relative path against its working directory. Use absolute paths.
- `websec_sarif` builds the ledger without suppressions or acknowledgements on purpose. It can
  contain findings that `websec_findings` and `websec run`'s `results.sarif` leave out or mark as
  suppressed.
- Graph enrichment reads `<path>/graphify-out/graph.json` if it is present. An unreadable graph
  never fails the call. See [configuration.md](configuration.md#graphify-graph-input).
- `websec_check_updates` accepts no other argument. An unknown key or a non-boolean `online` is an
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

**Cline and Windsurf.** Both read the common `mcpServers` shape. Read your client's MCP docs to find
its settings file.

**Zed.** Zed configures MCP servers under its own settings key, not `mcpServers`. Read Zed's MCP
documentation. Use `websec` with the argument `mcp` as the command.

**If `websec` is not found.** Desktop applications often start with a shorter `PATH` than your
shell. Use the absolute path of the executable as `command` (for example from `command -v websec`).
Or use the `websec-mcp` console script with no arguments.

**HTTP clients.** If your client supports Streamable HTTP with custom headers, point it at
`http://127.0.0.1:8733/mcp` and send `Authorization: Bearer <token>`. Header and URL syntax differ
between clients, so read their MCP docs. Keep the token in your local secret environment, not in a
committed config file.

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
  cookies or proxies). It stores only the observed version and check time. It installs nothing.
- The server cannot verify that a human approved the call. `online: true` represents consent that
  the client supplies. The rule above tells an agent how to obtain it.
- The result never affects findings, coverage or any gate. A failed check returns
  `status: "unavailable"` and the review continues.

Cache location and validation are described in
[configuration.md](configuration.md#caches-and-local-state).

## See also

- [cli.md](cli.md#websec-mcp): command-line options for `websec mcp`
- [configuration.md](configuration.md#mcp-token-and-allowed-roots): token and root rules
- [ai-agents.md](../guides/ai-agents.md): using websec with AI coding agents
- [integrations/README.md](../integrations/README.md): container and integration notes

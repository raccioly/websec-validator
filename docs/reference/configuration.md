# Configuration reference

Every place websec reads configuration from: files in your repository, explicit input files,
local caches, and environment variables. For each surface this page gives its location,
precedence, an example, and what happens when the input is missing or malformed.

websec has no global config file. Behaviour is set per run by [CLI options](cli.md), by the
repository's `.websec-ignore`, and by the few environment variables listed under
[Environment variables](cli.md#environment-variables).

| Surface | Where | Read by | Bad input means |
|---|---|---|---|
| [`.websec-ignore`](#websec-ignore) | `<target>/.websec-ignore` | `run`, `gate`, agent hook, `emit-context`, `dynamic`, MCP | Unreadable file: run incomplete. Bad lines: visible, never silently honoured. |
| [`dynamic-config.json`](#dynamic-configjson) | any path, via `dynamic --config` | `dynamic` | Missing or malformed file: exit 2. Failed login or controls: result `inconclusive`. |
| [Graphify graph](#graphify-graph-input) | `<target>/graphify-out/graph.json` or `run --graph` | `run`, MCP | Implicit: visible, non-blocking gap. Explicit: run incomplete. |
| [SARIF imports](#sarif-imports) | `run --sarif` | `run` | Run incomplete. |
| [Baseline ledger](#baseline-ledger) | `run --baseline` | `run` | Run incomplete. |
| [Named profiles](#named-profiles) | built in | `run`, `gate`, `capabilities` | Invalid analyzed configuration: execution error. |
| [Caches and local state](#caches-and-local-state) | per-user cache directories | various | Cache problems are reported; they do not fail a scan. |
| [Hook variables](#hook-environment-variables) | environment | git hooks, agent hook | Invalid git-hook values: hook execution incomplete. |
| [MCP token and roots](#mcp-token-and-allowed-roots) | `WEBSEC_MCP_TOKEN`, `mcp --allow-root` | `mcp --http` | Server refuses to start (exit 2). |

## `.websec-ignore`

A committed policy file that scopes findings out of the report or acknowledges specific ones.
`websec init` writes a starting version from the directories that exist in your repository.

**Location and precedence.** Only `<target>/.websec-ignore` is read, where `<target>` is the
directory you scan. A `.websec-ignore` in the current working directory is not read when it differs
from the target. The file is read through the same contained reader as source files, capped at
64 KiB. Its source, completeness and content digest are recorded in the ledger's `review_policy`.

**Grammar.** One entry per line. Everything after `#` is a comment, including on an entry line, so
a pattern cannot contain `#`. Blank lines are ignored. There are three kinds of entry:

| Entry | Effect |
|---|---|
| `<pattern>` | **Suppress**: matching findings leave the ledger and stop gating. Counted in the ledger's `suppressed` total. |
| `category:<name>` | **Suppress** every finding whose category equals `<name>` exactly (case-insensitive). Copy the name from a finding's `category` field: scanner findings are `static-secret`, `static-sca`, `static-sast` and `static-iac`; recon findings use names such as `supply-chain` or `graphql`. Write it without a space after the colon. |
| `fingerprint:<id> [expires:YYYY-MM-DD] # <reason>` | **Acknowledge** one finding: it stays visible in the `acknowledged` list, in REPORT.md and in SARIF (as a result with an `external` suppression), but leaves the gating total. |

**How a `<pattern>` matches.** Matching is case-insensitive. Since 0.22.0 a pattern line is one of
two kinds:

- A **path pattern** is any line that contains `/`, a glob character (`*`, `?`, `[`), or ends in a
  file extension such as `.js`. It is compared on whole path components against every path the
  finding names: its file, any `(path)` inside its location, and the location itself with a
  `:line[:col]` suffix and a leading `./` removed.
  - A leading `/` anchors the pattern at the target root (`/build/` is only the top-level `build/`).
  - Without a leading `/`, the pattern matches at any depth, including patterns with a slash in the
    middle: `api/routes.js` matches `services/api/routes.js`. This is a deliberate difference from
    `.gitignore`, where a middle slash anchors the pattern. A leading `**/` means the same as no
    slash.
  - A trailing `/` matches directories only, and a matched directory hides everything beneath it:
    `tests/` hides `tests/x.py` and `a/tests/x.py`, never `contests/x.py`.
  - Globs use `fnmatch` over component-aligned sub-paths, so `*` can still cross `/`:
    `services/api/*.js` matches `services/api/src/routes.js:13`.
- A **bare word** (anything else, such as `vendor` or `ssrf`) keeps the legacy behaviour: it matches
  as a substring of the finding's category, location or title.

**Legacy matching in this release.** Before 0.22.0 every pattern was matched as a substring of the
category, location and title, or as an `fnmatch` glob of the raw location. To avoid silently
un-suppressing anything, this release still hides a finding when **either** the new rule or the old
rule matches. A finding hidden only by the old rule is reported, not hidden quietly:

- one stderr warning per `.websec-ignore` line, naming how many findings it hid that way, a few
  examples, and the exact replacement line (for example `/contests/x.py` for a `tests/` line that
  hid `contests/x.py`, or `category:static-secret` for a bare `secret`);
- the ledger's `suppressed_legacy_substring` count, `suppressed_legacy[]` (each with
  `suppression.legacy_substring: true`, capped at 200 records) and `suppression_warnings[]`
  (`pattern`, `pattern_kind`, `hidden`, `replacement`, `examples`).

The legacy rule is a transition aid. Replace each flagged line with the suggested one, so your
policy does not depend on it.

> [!WARNING]
> This is close to, but not, gitignore syntax: a pattern without a leading `/` matches at any depth
> even when it contains a slash, and there is no `!` negation. Bare words are the risky kind: `test`
> hides any finding whose category, location *or title* contains "test", and every finding hidden
> only by a bare word is reported by the legacy warning. Prefer path patterns such as `tests/` or
> `examples/**`, or `category:<name>`.
> Suppression is scope, not a verdict: a real secret in a suppressed fixture is still committed.

**Acknowledgement states.** Each `fingerprint:` line gets a state, kept in the ledger's
`acknowledgement_history`:

| State | When | Acknowledges? |
|---|---|---|
| `active` | `expires:` date is today or later (the expiry day itself is included) | yes |
| `legacy-no-expiry` | no `expires:` token | yes |
| `expired` | `expires:` date has passed | no: the finding gates with `reopened_reason` |
| `malformed` | anything other than exactly one `expires:YYYY-MM-DD` token after the id | no |
| `missing-reason` | no text after `#` | no |

An acknowledgement matches the finding's current (V2) fingerprint or one of its legacy V1
aliases. A legacy alias that now matches more than one finding acknowledges none of them; each is
reopened with `ambiguous legacy acknowledgement`. If a fingerprint appears twice, the last line
wins.

**Example.**

```text
# scope: not our product
tests/
examples/**
category:supply-chain

# a reviewed, time-limited acceptance (prefer this over a broad path pattern)
fingerprint:b9c7f23e49bdab85 expires:2027-03-31  # confirmed FP: the scanner's own detection pattern
```

**What it does not do.** `.websec-ignore` filters findings; it does not stop files being read or
passed to scanners. To remove a path from analysis, use `--exclude` (recon and scanners) or `--only`
(analysis scope). Test, example and fixture code is already split out and demoted automatically;
`--include-fixtures` turns that off.

**Where it applies.** `run`, `gate`, the agent hook, `emit-context`, the `dynamic` ledger, and the
MCP tools `websec_findings` and `websec_briefing`. The MCP `websec_sarif` tool builds the raw
ledger **without** it (see [mcp.md](mcp.md#tools)).

**Failure behaviour.** Syntax problems never fail a run; a bad acknowledgement simply does not
acknowledge, and the finding carries the reason. An unreadable or out-of-scope file is recorded as
a `review_policy` execution gap, so a gated run exits 3.

**Export.** `websec init --claimspec PATH` writes the acknowledgements as a claimspec v1 `ignore`
document. Path and category patterns have no reason field and are omitted, as are `malformed` and
`missing-reason` entries (and reasons under 8 characters); the command reports every omission on
stderr.

Triage workflow: [triage-and-suppression.md](../guides/triage-and-suppression.md).

## `dynamic-config.json`

The input for `websec dynamic --config`: an authorized, isolated **test** instance and two test
identities in different tenants. Start from
[`dynamic-config.example.json`](../../dynamic-config.example.json); `dynamic-config.json` is listed
in the repository's `.gitignore` because it holds credentials.

**Location and precedence.** Any path, passed explicitly with `--config`. There is no default and no
environment-variable equivalent. It is ignored when `--unauth` is also given.

| Field | Required | Default | Meaning |
|---|---|---|---|
| `target` | yes | | Base URL. Not restricted to localhost; never use production. |
| `roles.agentA`, `roles.agentB` | yes | | Login bodies, sent as JSON exactly as written (keys starting with `_` are dropped). Use whatever fields the app expects, for example `email`/`password` or `username`/`password`. |
| `login_path` | no | `/api/auth/login` | Path that receives the login `POST`. Must return JSON; a redirect is reported as a configuration error, not followed. |
| `token_json_path` | no | `tokens.accessToken` | Dotted path to the bearer token in the login response. |
| `user_json_path` | no | `user` | Dotted path to the user object in the login response. |
| `tenant_field` | no | `groupIds` | Field on the user object holding the tenant id, a list (first element used) or a scalar. |
| `tenant_path_param` | no | `groupId` | The `{param}` in route templates that is the tenant boundary. Only `GET` routes whose **only** parameter is this one are tested, and side-effecting paths are skipped. |
| `application_id`, `build_id` | no | | The deployed application and build identity. Both are needed for a confirmed leak to carry provenance and become a calibration sample. |
| `bola_controls` | no | | Fixture controls that allow a result to be **confirmed**. Without them, results stay `inconclusive`. |

`bola_controls` fields:

| Field | Meaning |
|---|---|
| `expected_policy` | Must be `"tenant-isolated"`. |
| `identity_path` | A `GET` path that returns the caller's identity. Must start with a single `/`, contain no `{`, and not be side-effecting. |
| `identities.agentA`, `identities.agentB` | `{ "json_path": ..., "value": ... }` markers the identity endpoint must return for each role. Same `json_path`, different `value`. |
| `resources` | Keyed by route template exactly as recon reports it (for example `/groups/{groupId}/records`). Each holds an `agentA` and `agentB` marker identifying that role's private record. |

`json_path` is dotted; a numeric segment indexes a list (`items.0.id`). A marker matches only when
the value and its JSON type are equal.

**When a leak is confirmed.** For a route and direction, all of these must hold: both identity
checks return `200` with the declared markers; the owner reads its own marker; an anonymous read is
denied (`401`, `403` or `404`); and the attacker's read returns the victim's marker twice. Anything
less is reported as `blocked`, a `candidate`, or `inconclusive`, never as a confirmed leak.

**Failure behaviour.** A missing file, malformed JSON, or a config without `target` or `roles` exits
`2` with an error before any run directory is reserved. A failed login, two identities
in the same tenant, or a missing tenant id produces an `inconclusive` result with the reason in
`dynamic-findings.json`.

Walkthrough: [dynamic-testing.md](../guides/dynamic-testing.md).

## Graphify graph input

Optional blast-radius enrichment: each finding that maps to a node in a
[graphify](https://github.com/Graphify-Labs/graphify) knowledge graph gains a `graph` block (how much
of the app transitively depends on that code), and the ledger a `graph_enrichment` summary.

**Location and precedence.** `run --graph GRAPH.json` wins. Otherwise websec looks for
`<target>/graphify-out/graph.json`. An implicit graph under an `--exclude`d path is not read. The
MCP `websec_findings` and `websec_sarif` tools use the implicit graph only.

**Format.** Plain JSON, read with the standard library. The object must have a `nodes` list (each
node with an `id` and a `source_file`) and a `links` or `edges` list (each with `source`, `target`
and `relation`). Only dependency relations count: `calls`, `indirect_call`, `references`,
`imports`, `imports_from`, `re_exports`, `inherits`, `extends`, `implements`, `uses`, `mixes_in`,
`embeds`. The reverse walk stops at 20,000 nodes and says so.

The graph has its own read cap of 64 MiB (`graph_enrich.MAX_GRAPH_BYTES`), separate from the
2,000,000-byte per-source-file cap, and it does not draw on the source byte budget.

**Failure behaviour.**

| Case | Result |
|---|---|
| No implicit graph | Nothing happens. |
| Implicit graph unreadable, oversized, excluded or not a JSON object with `nodes` | A visible, non-execution coverage gap; the run still completes and `latest` advances. |
| Explicit `--graph` unreadable, oversized, excluded or invalid | An execution gap whose detail names the specific reason (`oversized: …`, `unreadable: …`, `excluded or out of scope: …`, `invalid: …`): the run is incomplete (exit 3 under a gate) and `latest` does not advance. |
| Explicit `--graph` path that does not exist | An execution gap (`not found: …`): the run is incomplete and `latest` does not advance. |
| Any exception during enrichment | Caught; recorded as a gap. Enrichment never crashes a run. |

## SARIF imports

`run --sarif REPORT` imports findings from another analyzer's SARIF 2.1.0 report without running
that analyzer.

**Rules.** Repeatable, at most 8 per run (more is a usage error, exit 2). The report's source
references are treated as data: websec never reads the files, executes the commands, or fetches the
URLs a report names. Only safe relative source paths are mapped. Native suppressions are kept as
metadata and failures stay active; acknowledge them locally with `fingerprint:` lines. Imported
findings carry `calibrated.basis: "unvalidated import"` and no `P(real)`.

| Limit | Value |
|---|---|
| Report size | 16 MiB |
| Runs per report | 32 |
| Results per report | 20,000 |
| Rules per tool component | 1,000 |
| Trace steps per result | 100 |
| JSON nesting depth | 64 |
| Expanded evidence per report | 8 MiB |
| Expanded evidence across all imports | 32 MiB |

**Failure behaviour.** A missing, malformed or over-limit report, or a producer run that did not
report completion, adds an execution gap: the run is incomplete. Every import also adds a
non-execution `sarif_freshness` gap, because a SARIF file does not prove which source revision it
describes. Details are written to `sarif-imports.json`.

```bash
websec run ./my-app --sarif ./codeql.sarif --sarif ./other.sarif --require-complete
```

## Baseline ledger

`run --baseline LEDGER.json` compares findings with a prior run.

**Format.** A `findings-ledger.json` from an earlier run (its `findings` and `acknowledged` lists
are read), or a JSON list of finding records. Must be a regular file of at most 16 MiB. Identities
use versioned semantic fingerprints; legacy V1 fingerprints are kept as migration aliases.

**Failure behaviour.** A missing, unreadable, oversized or malformed baseline adds an execution gap:
the run is incomplete. Disappearance from the current run means only "no longer observed", never
"fixed".

## Named profiles

Language profiles are built in and selected automatically from the files and manifests in the
target; there is nothing to configure. `websec capabilities` prints the current profiles, their
named checks and their limitations as JSON. Coverage records each selected check as completed,
unknown or manual. Invalid analyzed configuration is an execution error. Profile scope per language
is in [languages.md](languages.md).

```bash
websec capabilities
```

## Caches and local state

Everything websec keeps outside the run directory. None of it is uploaded.

| State | Location (first match wins) | Written by | Notes |
|---|---|---|---|
| Run artifacts | `--out DIR`, else `./websec-out` | `run`, `dynamic`, `feedback` | The implicit `./websec-out` must not be a symlink, and `DIR/runs` must be a real directory. |
| Threat-intelligence snapshot | `intel --cache-dir`, `$WEBSEC_ENRICH_DIR`, `$XDG_CACHE_HOME/websec`, `~/.cache/websec` | `intel refresh` | Holds `current.json`, `snapshots/<id>.json`, `last-refresh.json` and `refresh.lock`. Validated by content hash and schema on every read; this is not a publisher signature. `fresh` for 7 days, then `stale`. `run --scan` reads it offline for EPSS/KEV prioritization. |
| Release metadata | `$WEBSEC_UPDATE_HOME/release.json`, else `~/.cache/websec-validator/release.json` | `update-check --online` | Only `latest_version` and `checked_at`, at most 1 KiB. `WEBSEC_UPDATE_HOME` must be absolute and must not contain a `.local` component. An invalid cache yields `cache_unavailable` and the review continues. |
| Calibration overlay | `$WEBSEC_CALIBRATION_HOME`, else `~/.cache/websec-validator/` | `dynamic`, `feedback`, `calibrate` | `calibration-local.json` (your evidence-backed samples and pending candidates) and `calibration-synthetic.json`. Merged over the shipped table at runtime. |
| Proof corpus | `--workdir`, else `~/.cache/websec-corpus` | `proof`, `calibrate` | Cloned vulnerable applications. |
| Git guardrail state | `$GIT_DIR/websec-guardrail/` | git hooks | Recent runs, `accepted-state.json`, `hook.log`, `bypass.jsonl`, `running.lock`. |

Errors reading these caches are reported in the command's output; none of them fails a `websec
run`.

## Hook environment variables

Read when a hook runs, not when it is installed, so you can change them without reinstalling.

| Variable | Hook | Default | Invalid value |
|---|---|---|---|
| `WEBSEC_HOOK_FAIL_ON` | git pre-push | `high` | Hook execution incomplete; pre-push blocks. |
| `WEBSEC_HOOK_SCAN` | git hooks | unset (recon only) | Anything but `1` means recon only. |
| `WEBSEC_HOOK_SCANNERS` | git hooks | unset | Set without `WEBSEC_HOOK_SCAN=1`: hook execution incomplete. |
| `WEBSEC_SKIP_HOOK` | git hooks | unset | `1` skips one invocation and records it in `bypass.jsonl`. |
| `WEBSEC_GATE_FAIL_ON` | agent hook | `medium` | Falls back to `medium`. |
| `WEBSEC_GATE_MIN_CONFIDENCE` | agent hook | `low` | Falls back to no filtering. |

The accepted pre-push baseline is bound to the policy `{fail_on, scan, scanners}`; changing any of
these makes the next pre-push gate check all current findings again. The agent hook deliberately
ignores `WEBSEC_SKIP_HOOK`. See [pre-commit-and-git-hooks.md](../guides/ci/pre-commit-and-git-hooks.md).

## MCP token and allowed roots

Only the HTTP transport of `websec mcp` is configured; stdio needs nothing.

| Setting | Where | Rule |
|---|---|---|
| Bearer token | `WEBSEC_MCP_TOKEN` | Required. Non-empty, visible ASCII only (no spaces or control characters). Compared in constant time. |
| Allowed roots | `--allow-root PATH`, repeatable | At least one required. Each must be an existing directory. Tool calls must name an absolute path inside one of them. |
| Bind address | `--host`, `--port` | Loopback IP or `localhost` only; default `127.0.0.1:8733`. |

Any violation stops the server at startup with exit 2. Keep the token in your local secret
environment, not in a committed client config. Full details: [mcp.md](mcp.md).

## See also

- [cli.md](cli.md): every option and environment variable
- [mcp.md](mcp.md): MCP transports, tools and limits
- [outputs.md](outputs.md): what each artifact contains
- [triage-and-suppression.md](../guides/triage-and-suppression.md)
- [dynamic-testing.md](../guides/dynamic-testing.md)
- [monorepo.md](../guides/monorepo.md)

# Outputs

Every `websec run` writes a set of artifacts into its own run directory. This page lists each one:
when it is written, its format and schema, the fields that matter, and who consumes it. Names and
conditions are taken from the code that writes them (`cli.py`, `scanners.py`, `probes.py`) and
checked against real runs.

> [!WARNING]
> Artifacts can quote source evidence, file paths, routes and secret locations. Add `websec-out/` to
> the target repository's `.gitignore`, and treat uploaded artifacts with the same care as the source.

## Where artifacts land

```text
websec-out/
├── latest -> runs/20261010-102331-osixyn8w      # symlink to the last COMPLETED run
└── runs/
    ├── 20261010-102331-osixyn8w/                # one directory per attempt
    │   ├── AGENT-BRIEFING.md
    │   ├── FACTS.json
    │   └── …
    └── 20261010-104512-k3j9x2aa/                # a partial attempt keeps its own directory
```

- **Base directory.** `./websec-out` in the *current working directory*, not in the target. Choose
  another with `--out DIR`. An implicit `websec-out` that is a symlink is refused; pass `--out`
  deliberately if you need that.
- **One directory per attempt.** Each run reserves `websec-out/runs/<YYYYMMDD-HHMMSS>-<random>/`.
  Nothing from an earlier run is overwritten.
- **The `latest` pointer.** `latest` is a relative symlink to one run directory. It is replaced
  atomically, and only after a run whose execution completed (`coverage.execution_complete` is
  `true`) has written all of its artifacts. A partial attempt keeps its own directory and leaves
  `latest` on the previous completed run. Completed execution describes the requested checks, not
  complete protection against vulnerabilities.
- **Do not assume `latest` is the run you just started.** If your run was incomplete, `latest` still
  points at an older one. Scripts and agents should take the run directory from the console output
  or, in CI, from the GitHub Action's `run-directory` output. The instructions `websec install`
  writes for agents select the run from the current JSON output and reject stale `latest` or
  symlink aliases.
- **`websec dynamic`** reserves its own run directory under the same `runs/` and also advances
  `latest` when it completes. That directory holds the dynamic results, a rebuilt ledger, report and
  constitution, but no `AGENT-BRIEFING.md` or `results.sarif`. After a dynamic run, `latest` no
  longer points at a directory with a briefing.

Commands that write elsewhere or nothing:

| Command | Writes |
|---|---|
| `websec recon` (development) | `FACTS.json` directly into the output base directory, not into a run directory |
| `websec gate` | Nothing. No artifacts, no run directory, never advances `latest` or an accepted baseline |
| `websec demo` | A temporary directory only; never touches the current project |
| `websec emit-context`, `websec capabilities`, `websec explain` | Standard output only |

## Artifact index

| Artifact | Written when | Format | Schema | Main consumers |
|---|---|---|---|---|
| `AGENT-BRIEFING.md` | Every run | Markdown | — | Your AI coding agent |
| `REPORT.md` | Every run | Markdown | — | Humans; the immutable run record |
| `FACTS.json` | Every run | JSON, `schema_version: "2.0"` | [`facts.schema.json`](../../src/websec_validator/schemas/facts.schema.json) | Agents, MCP `websec_recon`, `websec dynamic`, custom tooling |
| `coverage.json` | Every run | JSON | [`coverage.schema.json`](../../src/websec_validator/schemas/coverage.schema.json) | CI gates, auditors, anyone deciding whether a clean run means anything |
| `findings-ledger.json` | Every run | JSON, `schema_version: "2.0"` | [`ledger.schema.json`](../../src/websec_validator/schemas/ledger.schema.json) | `--baseline`, `websec feedback`, `websec intel reassess`, `websec calibrate --ledger`, `websec attest`, dashboards |
| `findings.envelope.json` | Every run | JSON, `schema_version: "2.0"` | None shipped; wraps the ledger | Non-GitHub CI, dashboards |
| `results.sarif` | Every run, even with no findings | SARIF 2.1.0 | [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html) | GitHub Code Scanning, GitLab, Azure DevOps, DefectDojo, VS Code SARIF viewer |
| `attack-surface.json` | Every run | JSON | — | Planning; briefing §3a |
| `repair-plans.json` | Every run | JSON array | — | `websec repair-verify`, fix workflows |
| `CONSTITUTION.md` | Every run | Markdown | — | Agent and human: invariants to confirm or refute |
| `manifest.json` | Every run | JSON | — | Integrity checks, run indexing |
| `probes/` | Every run | Scripts + `probe-context.json` | — | Agent and human, against a TEST instance |
| `findings.json` | `--scan`, or `--sarif` without `--scan` | JSON array | — | Scanner-level triage |
| `scanners/<key>.json` | `--scan`, per executed scanner | Each scanner's native JSON | The scanner's own | Debugging a scanner adapter |
| `sarif-imports.json` | `--sarif REPORT` | JSON array | — | Provenance of imported analysis |
| `diff-scope.json` | `--diff REF` | JSON | — | PR reviewers, LLM reviewers |
| `sbom.cdx.json` / `sbom.spdx.json` | `--sbom` / `--sbom spdx`, Trivy installed | CycloneDX / SPDX JSON | The SBOM standard's | Supply-chain gates, downstream rescans |

The JSON Schemas ship inside the package under `websec_validator/schemas/`, so they match the
installed version.

## The briefing and the report

### `AGENT-BRIEFING.md`

The product: marching orders for your agent. Sections include what the app is (1), the tenant
boundary to confirm first (2), attack surface and targeting (3), the ranked attack-surface inventory
(3a), access control (3b), config/CI/client-side risks (3c), API-contract shadow endpoints (3e),
static findings (4), predicted DAST alerts and scanner blind spots (4b), pre-triage tags (4c), the
three axes of severity, likelihood and who acts (4d), staged probes (5), the phased pentest
runbook (5b), fix prompts (5c), how to verify and fix (6) and what to hand back (7). Point your
agent at it:

> Read `websec-out/runs/<run-id>/AGENT-BRIEFING.md` and follow it.

See [How it works](../concepts/how-it-works.md#aim-the-pentest-instead-of-competing-with-it) for
§4b and §5b.

### `REPORT.md`

The full human-readable record of the run: executive summary, the findings ledger with evidence
chain, standards and confidence (§1), the clustered view (§1a), acknowledged findings shown but not
gating (§1b), access control, attack surface, config/CI/client-side risks, staged probes and the
endpoint inventory. It leads with the coverage status: **REQUESTED CHECKS COMPLETED**, **PARTIAL
SCAN — REQUESTED CHECKS INCOMPLETE** or **NO ANALYZABLE SOURCE**.

### `CONSTITUTION.md`

The app's security invariants as Given/When/Then statements derived from the recon (for example
tenant isolation and secret hygiene). Each starts unchecked; the agent confirms or refutes it with a
probe. A confirmed dynamic missing-auth finding marks the authentication invariant violated. See
[METHODOLOGY: the security constitution](../METHODOLOGY.md#layer-3c--the-security-constitution).

## Structured recon

### `FACTS.json`

The full recon: one top-level key per extractor (`stack`, `routes`, `auth`, `authz`, `tenant`,
`password_policy`, `surface`, `upload_security`, `schemas`, `iac_ci`, `client_exposure`,
`client_integrity`, `transport_security`, `pii_exposure`, `graphql`, `integrations`,
`llm_security`, `crypto_usage`, `authz_dataflow`, `webext`, `agent_config`, `dependencies`), plus
`openapi` and an embedded `coverage` block. Required top-level fields: `tool`, `version`, `target`,
`stack`, `schema_version`, `coverage`.

Fields worth knowing:

- `stack.languages`, `stack.frameworks`, `stack.service_inventory`, `stack.profiles`: the detected
  stack and the named-profile results. See [Languages](languages.md).
- `routes.endpoints`, `routes.engine`, `routes.targeting` (write endpoints, IDOR, SSRF,
  open-redirect, upload and auth-endpoint candidates).
- `routes.fixture_endpoints`: test/example/fixture routes split out of the attack surface, kept
  visible rather than dropped. `--include-fixtures` treats them as product code.

### `coverage.json`

The execution and scope manifest. It is also embedded in `FACTS.json`, the ledger and the envelope.

| Field | Meaning |
|---|---|
| `execution_complete` | `true` when every requested check ran. Drives `latest` and exit code `3` |
| `protection_complete` | Always `false`. Completed execution is not protection |
| `limitation` | The statement above, in words |
| `gaps[]` | `{kind, detail, execution}`. `execution: true` means a requested check did not complete; `false` is a scope limit (`language_without_analyzer`, `thin_language_coverage`, `walker_policy`, `excluded_scope`, `profile_scope` and others) |
| `extractors` | Outcome per extractor |
| `scanners` | Per scanner: `installed`, `runnable`, `selected`, `ran`, `outcome`, `reported_version`, `version_verified` |
| `files` | `seen`, `scanned`, `read`, `unsupported`, `unanalyzed_languages`, `no_analyzable_source`, `skipped_counts`, caps and read losses |
| `profiles`, `service_inventory` | Named-check status per service |
| `route_discovery` | Django, Connexion and tRPC route-parser candidates and gaps |
| `detector_revision`, `analyzed_input_digest`, `scope_digest` | Hashes that bind the run to the detector code, the bytes read and the scope |
| `imports` | SARIF import outcomes, when `--sarif` is used |

How to use it to judge a clean run: [Languages: what a clean run means](languages.md#what-a-clean-run-means-for-your-stack).

### `attack-surface.json`

The ranked per-endpoint planning table behind briefing §3a. `endpoints[]` rows carry `method`,
`path`, `handler`, `service_id`, `technology`, `auth`, `params`, `sinks`, `risk`, `why` and
`is_write`. `summary` counts endpoints, unguarded endpoints and writes, high-risk sinks and IDOR
candidates.

## Findings

### `findings-ledger.json`

The traceable ledger: recon findings, scanner findings and imported SARIF, correlated into one
ranked set. Each finding (required: `title`, `attack_class`, `severity`, `confidence`, `location`)
can carry:

- `evidence`, `standards` (CWE, ASVS, OWASP API Top 10), `remediation`;
- `fingerprint` (version 2) and `fingerprint_aliases`, the stable identity used by
  `.websec-ignore` acknowledgements, baselines, SARIF and `websec feedback`;
- `calibrated`: `p`, `ci` (95% Wilson interval), `n`, `basis` and a `note` carrying the caveat. See
  [How it works: calibrated confidence](../concepts/how-it-works.md#calibrated-confidence);
- `triage`: the disposition (`agent-fixable` or `human-required`) with its reason;
- `baseline_state` with `--baseline`; `graph` with a knowledge graph (`--graph` or
  `graphify-out/graph.json`); `in_tree` and commit fields on secrets; `reachability` and EPSS/KEV
  data on dependency CVEs.

Top-level blocks: `total`, `by_severity`, `by_confidence`, `suppressed`, `acknowledged`,
`calibration`, `coverage`, `verification_context`, `attribution`, `clusters` and `cluster_summary`
(a presentation view; `total`, gate counts and per-site fingerprints are unchanged), and `gate`.

`gate` records the verdict that produced the exit code: `threshold`, `verdict` (`pass`, `fail`,
`incomplete`, `no-analyzable-source` or `not-evaluated`), `exit_code`, `failure_kind`
(`findings`, `incomplete`, `findings+incomplete` or `no-analyzable-source`), `count_at_or_above`,
`exit_code_contract` and an `enforcement` note that a client-side gate is advisory unless run as a
required status check.

### `findings.envelope.json`

A versioned, self-describing wrapper around the ledger for consumers that should not depend on its
internal shape: `schema_version`, `tool`, `tool_version`, `generated` (the run id), `target`,
`summary` (totals by severity and confidence, suppressed, acknowledged), `calibration`,
`verification_context`, `attribution`, `coverage` and `findings`. `websec run --format json` prints
the same envelope to standard output.

### `results.sarif`

SARIF 2.1.0, written on every run. Upload it to GitHub Code Scanning and each finding appears inline
on the pull-request diff and in the Security tab.

- `runs[0].invocations[0].executionSuccessful` mirrors `coverage.execution_complete`, so a partial
  run is visible to the consumer.
- Each result has `partialFingerprints.websecFingerprintV2`, so Code Scanning tracks it across runs.
- `properties.security-severity` is a numeric band GitHub uses to rank and colour alerts; CWE,
  ASVS and OWASP citations and the remediation travel with the rule.
- Acknowledged findings stay in the log with a `suppressions` entry, so they remain visible and
  attributable.
- Baseline lifecycle states use SARIF's `baselineState` values; richer lifecycle detail stays in
  `properties`.

`websec run --format sarif` also prints the log to standard output for piping.

### `findings.json`

Scanner results after normalization (`--scan`): each scanner's native JSON is parsed,
de-duplicated across tools by fingerprint (`cve|package|id`, `secret|file|rule|line`,
`iac|file|check`), ranked by severity and enriched with reachability and EPSS/KEV. A merged row
lists every tool that reported it in `tools`. With `--sarif` and no `--scan`, the file holds the
imported findings instead.

### `sarif-imports.json`

With `--sarif REPORT` (repeatable): one entry per imported report with its `report` provenance
(hashes, native tool and rule identities, limits, outcome), the mapped `findings` and
`observations`. Imported reports are never executed and referenced source is never loaded. Source
freshness stays unverified, and imported absence cannot verify a repair.

## Remediation and planning

### `repair-plans.json`

One plan per finding, binding the remediation to the original application, source digest, finding
and detector scope: `plan_id`, `finding_id`, `original`, `original_scope_digest`, `attack_class`,
`affected`, `prerequisites`, `suggested_remediation`, `triage`, `verification` (the positive and
negative evidence required) and `prompt`. `websec repair-verify` validates operator-supplied
evidence against a plan; it never executes commands. See the
[validated evidence examples](../security-review/examples/README.md).

### `diff-scope.json`

With `--diff REF`: `base`, `error`, `files` (changed files mapped to added or modified line ranges)
and `counts` (findings in changed files and hunks versus pre-existing ones). If the diff cannot be
computed, `error` is set and the run continues unscoped over the whole repository. That records a
`diff` execution gap, so the run is incomplete and `latest` does not advance.

### `probes/`

The probe drafts selected for this app, plus their context:

- `probe-context.json`: the app's real routes, auth location, sensitive fields, tenant keys and a
  `target_base_url` placeholder.
- Probe scripts (`.sh`, `.py`). `unauth-baseline` and `rate-limit-burst` are always staged; the
  rest (BOLA, mass assignment, JWT, SSRF, upload, webhook forgery and others) only when the recon
  supports them.
- `_lib.py` and `_lib.bash`: the shared transport. It refuses to send a mutating request to any
  host other than localhost.

Probes are drafts. The agent finalizes them against `probe-context.json`; you supply a TEST
instance and test credentials and approve each run. `websec run` stages them and never executes
them. See
[Dynamic testing](../guides/dynamic-testing.md).

## Supply chain and integrity

### `sbom.cdx.json` and `sbom.spdx.json`

`--sbom` (CycloneDX, the default) or `--sbom spdx` asks Trivy for an SBOM of the target. If Trivy is
not installed or the SBOM is invalid, the run records an `sbom` gap that counts as an execution gap:
the run is incomplete and `latest` does not advance.

### `manifest.json`

The run index: artifact names, detected scanners and scan results, SBOM status, attack-surface
summary, staged probes, the run timestamp, and `artifact_digests`: SHA-256 of `FACTS.json`,
`coverage.json`, the ledger, envelope, SARIF, `findings.json`, `repair-plans.json`,
`attack-surface.json`, `REPORT.md`, `AGENT-BRIEFING.md`, `diff-scope.json` and
`sarif-imports.json` when present. The digests detect later edits; they do not prove authorship,
and the manifest does not hash itself. They are meaningful alongside an external copy such as a CI
artifact.

## Versioned contract

`FACTS.json`, `findings-ledger.json` and `findings.envelope.json` carry `schema_version: "2.0"`.
JSON Schemas ship in the package: `schemas/facts.schema.json`, `schemas/ledger.schema.json` and
`schemas/coverage.schema.json`. Coverage is embedded in facts, ledger and envelope, and SARIF's
execution status reflects partial checks. Fingerprint V2 preserves V1 migration aliases. SARIF
lifecycle states use its legal enum and keep richer lifecycle metadata in properties.
`.websec-ignore` is read from the selected target by default, through the same contained read
policy; an unrelated working directory does not contribute implicit suppressions. The
[0.14.0 migration guide](../MIGRATING-0.14.0.md) explains the move to schema 2.0.

## See also

- [CLI reference](cli.md): `--out`, `--format`, `--scan`, `--sbom`, `--diff`, `--sarif`, `--baseline`, exit codes
- [Languages and frameworks](languages.md): reading `coverage.json` for your stack
- [GitHub Actions](../guides/ci/github-actions.md): uploading `results.sarif` and the `run-directory` output
- [Other CI systems](../guides/ci/other-ci.md): SARIF and the envelope outside GitHub
- [Triage and suppression](../guides/triage-and-suppression.md): fingerprints, acknowledgements, clusters, baselines
- [docs-canonical/ARCHITECTURE.md](../../docs-canonical/ARCHITECTURE.md#output-artifacts-websec-out): design intent for the output tree

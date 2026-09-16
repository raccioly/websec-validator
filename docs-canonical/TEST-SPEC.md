# Test Specification

<!-- docguard:version 0.9.0 -->
<!-- docguard:status approved -->
<!-- docguard:last-reviewed 2026-09-14 -->
<!-- docguard:owner @raccioly -->
<!-- docguard:quality negation-load off — the suite deliberately uses no third-party runner, no network, and no running app; the negations describe real, intentional test constraints. -->

> **Canonical document** — Design intent. This file declares what tests MUST exist.  
> Last updated: 2026-09-14

The suite uses stdlib `unittest` with synthetic fixtures and local loopback servers; it requires no
third-party runner, public network, external scanner, or running target app. Release CI also builds
and smoke-tests the installed wheel. The final 2026-09-14 source phase passed **1082 application tests** on
Python 3.14.7 (21.492s) and Python 3.12.14 (22.536s), plus **41 repository automation tests**.
CI enforces an application-test floor of **1083**. The package
has **22 registered extractors**, **17 sink classes**, **10 scanner entries** and **9 named profiles**.

```bash
python3 -m unittest discover -s tests
```

---

## Test Categories

| Category | Required | Applies To | Tool |
|----------|----------|-----------|------|
| Unit | ✅ Yes | extractors, findings ledger, calibration, scanners, probes | `unittest` |
| Regression | ✅ Yes | pen-test findings (REF-PENTEST) + every fixed bug — pinned so they can't silently come back | `unittest` |
| Hardening | ✅ Yes | CLI surface, dynamic-phase safety gates, partial-scan guard, edge/error paths | `unittest` |
| Coverage proxy | ✅ Yes | recon coverage vs the labeled vuln-app corpus (`websec proof`) | `proof.py` (network on first clone) |
| Local HTTP / contract / fault injection | ✅ Yes | MCP authentication/framing/deadlines, output schemas, CLI partial publication, repair evidence | `unittest` + loopback sockets |

## Coverage Rules

| Source Pattern | Required Test Pattern | Category |
|----------------|----------------------|----------|
| `src/websec_validator/extractors/*.py` | a recon/extractor assertion in `tests/test_recon.py` | Unit |
| `src/websec_validator/{findings,calibration,scanners,probes}.py` | exercised in `tests/test_recon.py` | Unit |
| a fixed bug / disproven pen-test finding | a dedicated case in `tests/test_pentest_regressions.py` | Regression |
| entitlement / licensing + WebExtension client-trust classes (`integrations`, `webext`) | a case in `tests/test_entitlement_webext.py` (incl. cross-provider genericity) | Unit / Regression |
| `src/websec_validator/{cli,dynamic}.py` + safety invariants | a case in `tests/test_hardening.py` | Hardening |

## Source-to-Test Map

| Source | Test file | Status |
|--------|-----------|--------|
| `src/websec_validator/extractors/` | `tests/test_recon.py`, `tests/test_pentest_regressions.py`, `tests/test_entitlement_webext.py` | ✅ |
| `src/websec_validator/extractors/base.py` | `tests/test_read_boundary.py`: escaping/in-root symlinks, private-tree pruning, exclusions, special files, caps and root replacement | ✅ |
| `src/websec_validator/mcp_server.py` | `tests/test_mcp.py`, `tests/test_mcp_security.py`: authentication, Host/Origin, framing, absolute deadlines, capacity and dispatch-to-read root swaps | ✅ |
| `src/websec_validator/coverage.py` | `tests/test_coverage.py`: extractor/scanner faults, missing tools, malformed/oversized reports, partial artifacts, atomic publication and repair verification | ✅ |
| `src/websec_validator/dynamic.py` | `tests/test_hardening.py`, `tests/test_evidence_verdicts.py`, `tests/test_dast_ingest.py`: candidates/unknowns, redirects, scoped labels and quarantine | ✅ |
| `src/websec_validator/repairs.py` | `tests/test_lifecycle.py`: identity migration, expiry/reopening, no-longer-observed semantics and bound before/after artifacts | ✅ |
| `src/websec_validator/extractors/profiles.py` | `tests/test_profiles.py`: named safe/unsafe checks, service boundaries and explicit config errors | ✅ |
| `src/websec_validator/intel.py` | `tests/test_intel.py`: validated dated snapshots, atomic failures and offline reassessment | ✅ |
| `src/websec_validator/research.py` | `tests/test_research.py`: data-only metadata validation and development/holdout metrics | ✅ |
| `src/websec_validator/proof.py` | `tests/test_proof_revisions.py`: pinned revisions, mismatch and unavailable diagnostics | ✅ |
| `src/websec_validator/cli.py` | `tests/test_workbench_cli.py`: bounded command inputs, new-only outputs and validated documentation examples | ✅ |
| `src/websec_validator/formats.py` | `tests/test_formats.py`, `tests/test_openapi.py`, `tests/test_graph_enrich.py`: schema 2.0, SARIF enums, scoped reads and distinct input origins | ✅ |

Boundary tests must include legitimate positive cases as well as rejected inputs. Fault tests must
show preserved partial evidence and failed execution gates; returning an empty result is insufficient.
Repair evidence tests must bind both original failures and fixed-build passing controls to the same
plan/finding/test and reject reuse, tampering, changed policy/scope, and missing artifacts.

Additional protocol and assurance contracts:

| Area | Regression evidence |
|---|---|
| Scanner diagnostics and identities | `test_scanner_contracts.py`: Checkov empty-success/error shapes and resource IDs, per-manifest/version CVEs, Bandit confidence/CWE/configuration, retained intelligence provenance |
| Imported SARIF | `test_sarif_ingest.py`, `test_sarif_workbench.py`: data-only parsing, safe lexical paths, reference contradictions, kind/level rules, output amplification bounds, collision identities, traces and strict CLI gates |
| Source budgets and privacy | `test_source_budget.py`: aggregate payload loss, alias hashes, per-read caps, explicit artifact privacy and repair-policy binding |
| Evidence consumers | `test_assurance_regressions.py`: contradictory completion metadata, per-feed rollback, publication locking and honest proof exits |
| Value-scoped controls | `test_remaining_control_scope.py`, `test_extension_controls.py`, `test_transport_pii_scope.py`: webhook/upload/hash/message controls, individual cookie setters and actual PII response projections |
| Public-source precision | `test_public_precision.py`: executable authentication decisions, browser-response file delivery, and exact numeric GitHub expressions paired with unsafe text controls |

Imported report tests must preserve usable sibling findings while reporting failures, keep report
hashes separate from source evidence, and prove no referenced source, network resource or command is
executed. Collision tests pair ambiguous report-bound IDs with unique-fingerprint continuity controls.
Synthetic control corpora measure supported patterns; they are not unseen-project precision/recall.

## Test Fixtures

| Fixture | What it is | Used by |
|---------|-----------|---------|
| `tests/fixtures/node_app/` | a deliberately-vulnerable Express sample app | extractor + regression assertions |
| `tests/fixtures/py_app/` | a deliberately-vulnerable Flask sample app | extractor + regression assertions |

The tool scans these fixtures as **test data**. Packaging excludes them, and `.docguardignore`
excludes them from documentation validation.

## Coverage Proxy — the Proof Harness

`websec proof` clones the vuln-app corpus (VAmPI, NodeGoat, DVGA) and scores whether recon surfaces
each app's documented attack surface — a deterministic, CI-trackable proxy. The corpus contributes
coverage checks across three apps — VAmPI (4), NodeGoat (4), DVGA (2), **10 in total** — which the
historical baseline reported **10/10**. A current result requires an executed run that records the pinned corpus and detector
revision; unit tests alone do not renew this result. The true
kill-criterion — does the briefing lift an agent's bug-finding vs a generic prompt? — is the manual
A/B in [`corpus/PROOF-PROTOCOL.md`](../corpus/PROOF-PROTOCOL.md).

## Recommended Test Patterns

| Pattern | Description | Priority |
|---------|-------------|----------|
| Regression guards | Pin every fixed bug / disproven finding with a dedicated case (the bulk of `tests/test_pentest_regressions.py`) | ⚠️ High |
| Individual extractors | Test each extractor directly against a fixture, not only end-to-end | ⚠️ High |
| Safety-gate assertions | Prove dynamic write probes refuse non-localhost; prove the core pass stays offline | ⚠️ High |
| Edge cases | Empty repo, missing files, partial-scan (file-cap) truncation, absent scanners | ✅ Medium |
| Error paths | One failing extractor must never sink the whole run | ✅ Medium |

## Framework and installer regression contracts

Django URL tests must pair local include/path resolution with dynamic roots, unknown prefixes,
cycles, unrelated bindings and resource caps. Service metadata tests must cover Rust workspaces
and separate native React from browser renderers, preserving mixed-service browser review.
Credential comparison tests pair literal presence/type checks with hardcoded, reversed and
unsafe-sibling comparisons, while keeping sampled text distinct from executable interpolation.

Installer tests must preserve foreign files and malformed/duplicate/reversed managed blocks byte
for byte, retain valid surrounding whitespace/CRLF, refresh historical generated skills, and refuse
special files. Execute the documented selector against real complete/partial CLI envelopes; prove
that absent/malformed envelopes, escaping paths and symlink aliases cannot select stale output.


Additional adoption checks must execute the documented isolated CLI argv with safe, HIGH-finding
and incomplete-read fixtures, proving target import shadowing does not execute. Test copying must
prune case-insensitive private paths and all symlinks before reading payload. Limited scalar
configuration checks must not be reported as full pre-commit/YAML/hosted-workflow validation.
Research CLI tests must cover catalog-only behavior, aggregate/all-proposal success, failure and
revision inconsistency, invalid combinations including empty explicit arguments, and output
non-overwrite. Output reservation must reject static nested symlinks before analysis or probes.


Assigned SQL regression tests must preserve Python request provenance through supported local
assignments, aliases, branch joins and matched tuple unpacking, while keeping bound scalar values
separate from query text. Assert distinct sites, bounded traces, parse/work losses and actual CLI
integration. Later loop iterations remain explicit review gaps; tests must not imply fixed-point
coverage or cross-function reachability.

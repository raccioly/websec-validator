# Implementation Plan: Complete retained security coverage

**Branch**: `codex/complete-reconciled-backlog` | **Date**: 2026-09-30 | **Spec**: [spec.md](spec.md)

## Summary

Audit all retained intents against current source, not closed PR state. Repair reproduced unsafe
over-suppression before widening coverage. Each detector fix needs paired regressions, unsafe
siblings, independent review and actual CLI/ledger validation. Historical measurements stay dated.

## Technical Context

Python 3.11+, stdlib-only runtime, no new database/store or runtime dependency. Existing artifact
files retain source/detector/report provenance. Optional analyzers are operator-trusted executables.
Test with unittest, owned temporary fixtures, isolated wheels and CI on supported Python versions.
Support macOS/Linux, optional Docker and stdio/loopback MCP. Preserve bounded readers/parser work
and disclose losses. Target code is never executed; default analysis is offline; writes stay local.
Scope: W01–W20 and spec 002 acceptance reconciliation, not general compiler/call-graph coverage.

## Constitution Check

The constitution is an unfilled template, not approved normative guidance. Apply AGENTS.md and
canonical contracts. Standing approval covers implementation, normal Git integration and releases,
not forced installations, public disclosure or live production tests. Gates pass before/after
design: zero runtime dependencies, shared intake, paired tests and honest evidence provenance.

## Project Structure

```text
src/websec_validator/extractors/  detectors and bounded syntax helpers
src/websec_validator/            calibration, CLI, coverage and artifact consumers
tests/                          paired source/ledger/boundary regressions
specs/001-continuous-security-improvement/
  plan.md research.md data-model.md quickstart.md contracts/ tasks.md
docs-canonical/                  reviewed intent
docs/security-review/            dated reconciliation/validation evidence
```

Reuse existing modules and small bounded helpers. Reject method-name wildcards, file-wide security
exemptions and target execution. Sequence overlapping source edits. Independent research/review
can run in parallel without source writes. No architectural complexity exception is needed.

## Delivery Gates

Paired red/green → independent review → full application/automation suites → DocGuard/evidence/
spec/PDF checks → isolated wheel → checked-head CI merge → new immutable release for package
changes → actual GitHub/PyPI artifact verification. Real Docker/pre-commit lifecycle evidence is
required before reporting those matrices executed; static inspection cannot substitute for it.

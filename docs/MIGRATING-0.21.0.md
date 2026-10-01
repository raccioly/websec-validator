# Migrating to 0.21.0

This release adds bounded source analysis and fixes precision/security boundaries. No new runtime
dependency, automatic update, target execution or artifact schema-major change is introduced.

## What may change in a scan

- Registered literal Connexion JSON and supported YAML now produce fallback routes without Noir.
  Tags/aliases/composition/references, dynamic registration and custom resolvers remain gaps. Handler
  auth evidence comes from the exact source operation, not OpenAPI security declarations.
- Supported FastAPI dependencies and mounted tRPC middleware chains receive operation-local review.
  Unknown short-circuit middleware and unresolved identity cannot borrow downstream guard credit.
- Django render responses are paired with the exact returned template/header object. A protected
  sibling cannot clear an unprotected view. CSP shape is not runtime nonce or deployment evidence.
- Flask SQLAlchemy columns and supported assigned SQL/command/upload flow retain real operation
  provenance. Variable names, prose, prefixes and unrelated helper checks no longer stand in for
  storage/guard evidence. Cross-function/unknown receivers remain review limits.
- Reviewed boolean calibration evidence is kept separate from unknown/unreviewed labels; candidate
  writes and Brier reporting do not imply a renewed production precision benchmark.
- Parser/work budgets now persist incomplete execution rather than silently dropping input. With
  completeness gating, an incomplete-only run exits 3; findings plus incomplete exits 1 and records
  both. Existing automation should preserve these outcomes, not accept older `latest` artifacts.

Review new findings and unknowns before updating a baseline. A disappeared lead is not proof of a
fixed vulnerability. Rerun against the exact intended source and compare scope/detector identity.

## Integrations and update consent

MCP capacity failures retain authentication and a bounded structured error. Core/bundled images have
native amd64/arm64 contract coverage and checksum-verified scanner archives; transitive dependencies
and all scanner adapters are not certified. Hook lifecycle checks execute only in disposable targets:
this release does not install consumer hooks or activate schedules.

An AI offers a release check and respects a decline. `websec update-check` is offline; `--online`
requires consent and checks metadata only. Checking never installs a package. Any upgrade is a separate
user-approved operation; explicitly refresh previously installed managed guidance afterward.

## Evidence that is not claimed

The offline captured-report harness in `scripts/compare-reports.py` binds declared provenance and
preserves TP/FP/unknown separately. No new competitor or manual agent A/B experiment has run.
Original Elixir source was recovered; the Swift coverage fixture is authored and does not reproduce
the unavailable original V9 application. Historical public proof/review scores retain their original
source revisions; the new release does not inherit them as current recall results.

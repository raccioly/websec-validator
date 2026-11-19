# Migrating to 0.21.0

This release adds bounded source analysis and fixes precision and security boundaries. It adds no new runtime
dependency, automatic update, target execution or artifact schema-major change.

## What may change in a scan

- Registered literal Connexion JSON and supported YAML now produce fallback routes without Noir.
  Tags, aliases, composition, references, dynamic registration and custom resolvers remain gaps. Handler
  auth evidence comes from the exact source operation, not from OpenAPI security declarations.
- Supported FastAPI dependencies and mounted tRPC middleware chains receive a review for each operation.
  Unknown short-circuit middleware and unresolved identity cannot borrow downstream guard credit.
- Django render responses are paired with the exact returned template/header object. A protected
  sibling cannot clear an unprotected view. The shape of a CSP is not evidence of a runtime nonce or a deployment.
- Flask SQLAlchemy columns and supported assigned SQL/command/upload flow keep real operation
  provenance. Variable names, prose, prefixes and unrelated helper checks no longer stand in for
  storage/guard evidence. Cross-function and unknown receivers remain review limits.
- Reviewed boolean calibration evidence is separate from unknown and unreviewed labels. Candidate
  writes and Brier reporting do not imply a renewed production precision benchmark.
- Parser and work budgets now persist incomplete execution. Before, websec silently dropped input. With
  completeness gating, a run that is only incomplete exits 3. A run with findings and incomplete execution exits 1 and records
  both. Existing automation must keep these outcomes and must not accept older `latest` artifacts.

Review new findings and unknowns before you update a baseline. A lead that disappeared is not proof of a
fixed vulnerability. Rerun against the exact intended source, and compare the scope and detector identity.

## Integrations and update consent

MCP capacity failures keep authentication and return a bounded structured error. The core and bundled images have
native amd64/arm64 contract coverage and checksum-verified scanner archives. Transitive dependencies
and all scanner adapters are not certified. Hook lifecycle checks run only in disposable targets.
This release does not install consumer hooks or activate schedules.

An AI offers a release check and respects a decline. `websec update-check` is offline. `--online`
requires consent and checks metadata only. A check never installs a package. Any upgrade is a separate
operation that the user approves. After an upgrade, refresh the managed guidance that you installed earlier.

## Evidence that is not claimed

The offline captured-report harness in `scripts/compare-reports.py` binds the declared provenance and
keeps TP, FP and unknown results separate. No new competitor or manual agent A/B experiment has run.
The original Elixir source was recovered. The Swift coverage fixture is authored and does not reproduce
the original V9 application, which is unavailable. Historical public proof and review scores keep their original
source revisions. The new release does not inherit them as current recall results.

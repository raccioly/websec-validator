# Tasks: Retained security coverage

**Input**: `spec.md`, `plan.md`, `research.md`, `data-model.md`, `contracts/analysis.md`.
Tests are required by FR-002. Starting source `2ee99673`; closed PRs are not delivery evidence.

## Phase 1 — Setup

- [x] T001 Audit W01–W20 independently and record reproductions in `research.md`.
- [x] T002 Review canonical/agent/methodology contracts and run baseline DocGuard; inspect `.gitignore` and `.dockerignore` before implementation.

## Phase 2 — Foundation

- [x] T003 Correct reviewed contract/lifecycle drift in `docs-canonical/`, `docs/METHODOLOGY.md`, `AGENTS.md`, `specs/002-calibration-honesty-and-structural-coverage/spec.md`, `.docguard-specs.json` and `CHANGELOG.md`.
- [x] T004 Preserve delivered W01/W07/W14/W15/W17 and record evidence in `docs/security-review/backlog-reconciliation.md`; keep the exact-head historical register intact.

## Phase 3 — US2: Framework enforcement and provenance (P1)

Independent test: endpoint-bound safe/no-op/unprotected sibling controls, no target execution.

- [ ] T005 [US2] Add failing FastAPI/tRPC auth controls in `tests/test_retained_frameworks.py` (W05).
- [ ] T006 [US2] Bind visible dependency/middleware enforcement to its endpoint in `src/websec_validator/extractors/authz.py` (W05).
- [ ] T007 [US2] Add source-registration/documentation-only/escaping/malformed Connexion controls in `tests/test_retained_frameworks.py` (W16/W20).
- [ ] T008 [US2] Resolve bounded import-bound Connexion registration without promoting unregistered docs in `src/websec_validator/extractors/routes.py` (W16/W20).
- [x] T009 [US2] Add paired assigned JS SQL/Python+JS command controls in `tests/test_retained_flows.py` (W04/W10).
- [x] T010 [US2] Implement bounded local assignment provenance and disclosed work limits in `src/websec_validator/extractors/surface.py` and shared flow helper (W04/W10).
- [ ] T011 [US2] Add paired UploadFile/db.Model controls in `tests/test_retained_frameworks.py` (W11/W13).
- [ ] T012 [US2] Implement bound Python upload/model evidence in `src/websec_validator/extractors/upload_security.py` and `schemas.py` (W11/W13).
- [ ] T013 [US2] Validate Django same-response observations and native/profile limits against `tests/test_django_urls.py`, `tests/test_profiles.py`, `src/websec_validator/extractors/transport_security.py`; add missing paired evidence without claiming deployment.

## Phase 4 — US1: Keep unsafe neighbors visible (P1)

Independent test: original reproducer no longer misclassified; real unsafe sibling still reported.

- [ ] T014 [US1] Add failing JWT/hash/upload/PII/literal/guard paired cases in `tests/test_retained_precision.py` (W08/W09/W12/W18/W19).
- [ ] T015 [US1] Scope direct JWT options/hash result use in `src/websec_validator/extractors/crypto_usage.py` (W09).
- [ ] T016 [US1] Scope filename storage/SVG acceptance in `src/websec_validator/extractors/upload_security.py` (W08).
- [ ] T017 [US1] Correct boolean and partial-removal PII output handling in `src/websec_validator/extractors/pii_exposure.py` (W12).
- [ ] T018 [US1] Correct literal regex/error expression matching in `src/websec_validator/extractors/surface.py` (W18).
- [ ] T019 [US1] Pair actual security invocation with executable catch returns in `src/websec_validator/extractors/llm_security.py` (W19).
- [x] T020 [US1] Add import-bound HTTP receiver controls and implementation in `tests/test_retained_flows.py` and `src/websec_validator/extractors/surface.py` (W03).

## Phase 5 — US4: Honest evidence (P1)

Independent test: provenance-specific tables remain separate; unknown labels never become truth.

- [ ] T021 [US4] Add mixed-reviewed/Brier write/original language fixture regressions in `tests/test_retained_calibration.py` and owned fixture directories.
- [x] T022 [US4] Finish class eligibility and every measurable-write scoring in `src/websec_validator/calibration.py`, `synthetic.py`, `cli.py`; reconcile spec 002 acceptance evidence.
- [ ] T023 [US4] Add reproducible per-tool comparison harness/raw unknown-labelled outcomes under `scripts/` and `tests/`; update `BENCHMARKS.md` without inventing unseen-project recall or agent benefit.

## Phase 6 — US3: Deliberate recurring integration (P2)

Independent test: actual supported integration lifecycle; static config tests alone insufficient.

- [ ] T024 [US3] Add one-shot CLI versus long-lived MCP health policy and packaging controls in `Dockerfile`, `docs/integrations/README.md`, `tests/test_container_contracts.py` (W02).
- [ ] T025 [US3] Pin and verify supported scanner archives/platforms and execute available image matrix using `Dockerfile` and `tests/test_container_contracts.py` (W06).
- [x] T026 [US3] Add remote-write/redirect/body/concurrency regressions then replace httpx race draft with bounded stdlib transport in `src/websec_validator/templates/probes/race-conditions.py` and `tests/test_probe_transport_boundaries.py` (W06).
- [ ] T027 [US3] Validate real disposable pre-commit lifecycle and controlled separate-engine/target CI using `docs/integrations/` and `tests/test_adoption_contracts.py`; record unavailable prerequisites as pending, not delivered.

## Phase 7 — Polish and release

- [ ] T028 Independently review each detector unit and run actual CLI/ledger controls; record evidence/limitations in `docs/security-review/backlog-reconciliation.md` (FR-002/SC-001).
- [ ] T029 Run focused/full application and automation suites, compileall, DocGuard/evidence/spec checks and isolated built-wheel validation; update `AGENTS.md` dated counts and `CHANGELOG.md`.
- [ ] T030 Run Spec Kit convergence after all implementation tasks; append newly found gaps to this task file only.
- [ ] T031 Review release docs/brief publication pair and migration contracts for new package behavior; regenerate and visually inspect PDF only when its source changes.
- [ ] T032 Commit coherent units, normal checked-head CI merge and immutable release; verify actual GitHub/PyPI artifacts (FR-006).
- [x] T033 Fix the reproduced MCP overload-close race without weakening the original 503 assertion;
  validate split-send and byte/absolute-time caps in `tests/test_mcp_security.py`, independently
  review `src/websec_validator/mcp_server.py`, and document the bounded accept-loop trade-off.

## Dependencies and execution order

T001–T004 precede stories. Prioritize unsafe auth/JWT overcredit among equal P1 stories. Each test
task precedes its source task. US1/US2 share surface/upload source and therefore execute sequentially.
US4 is independent after foundation; US3 follows safe transport boundaries. T028 applies after each
unit, not only at the end. T029–T032 require all relevant implementation/validation complete.

Parallel examples: US1 precision research and US2 framework research; US2 SQL and model test design;
US3 tooling inventory and US4 label audit. These are read-only independent work; overlapping source
writes are not parallel. Root owns implementation; independent agents own research/review only.

No task may be checked merely because a PR closed, a warning vanished, a table exists or a tool is
installed. Unrun platform matrices and manual agent A/B experiments remain explicitly pending.

### First implementation batch

FastAPI endpoint-local dependencies and JWT/literal/PII/fail-open pairs are implemented with an
actual subprocess CLI/ledger contract and independent negative-control review. T005/T006 remain
open for tRPC; T014/T015 remain open for principal/hash-purpose cases. Upload storage provenance
and the remaining full-task acceptance checks are not marked complete by these narrower fixes.

### Connexion registration checkpoint

Ten new tests cover literal JSON registrations, exact operation handlers, invalid ordering,
documentation-only Noir rows, malformed shapes, private/escaping paths, execution budgets and an
actual subprocess CLI ledger. Independent review confirms its four negative controls fixed.
T007/T008 remain open for deliberately unsupported YAML/dynamic composition: partial parsing is
disclosed and does not automatically manufacture deployed routes or guard evidence.

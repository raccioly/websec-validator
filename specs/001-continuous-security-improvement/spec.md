# Feature Specification: Continued security coverage after 0.14.0

**Feature Branch**: `codex/security-expansion-release` (specification only)
**Created**: 2026-09-14
**Status**: Prioritized remaining-work specification; implementation is not implied
**Input**: Finish and publish the current improvements, consolidate conflicting PR backlog, and
continue improving threat discovery and verified resolution across project styles.

## Delivered foundation

0.14.0 supplies bounded source/report reads, explicit coverage, semantic lifecycle/repair evidence,
MCP containment, optional scanner adapters, SARIF interoperability, named profiles, intelligence and
research commands, Django candidates, scoped Python query flow, and opt-in agent/hook/CI adoption.
The [migration guide](../../docs/MIGRATING-0.14.0.md) is the consumer contract. Previously reviewed
PR ideas must be checked against this foundation rather than applied as competing replacements.

The [overlap review](../../docs/security-review/upstream-overlap-review.md) records selected exact
heads and evidence. At the release review there were zero open GitHub issues and 53 open PRs;
51 overlapped tracked work. Recheck live counts/heads before acting. PR disposition and any retained
idea must have one traceable owner; closing a duplicate does not mean a new untested fix was merged.

## User Scenarios & Testing

### Story 1 — Keep genuine threats visible while reducing noise (P1)

An operator can distinguish unsafe flows from nearby safe code without blanket helper-name,
framework, type-annotation or file-wide suppressions.

**Acceptance scenarios**:

1. Generated upload keys with filename logs and SVG rejection/error text produce no invented
   unsafe-storage/acceptance claim, while actual filename-derived storage and positive SVG acceptance
   remain leads. Guards must bind to the operation and branch, including unsafe siblings.
2. HTTP client method calls such as `needle.get(request_value)` receive the same scoped request-source
   analysis as direct supported client calls. Safe literal targets and unrelated same-named methods
   remain controls; do not introduce an unrestricted method-name wildcard.
3. Explicit boolean/known projection PII responses can be classified without hiding raw entities,
   TypeScript-only `Omit` aliases, mutation, spreads or ambiguous helper results.
4. HIBP/avatar/cache/password-update metadata hashing is distinguished by actual input and purpose,
   while real credential/principal hashing in the same file stays visible. Unknown JWT options never
   become an algorithm policy merely because `options` or `config` appears elsewhere.

**Candidate ownership/tests**: upload_security, pii_exposure, crypto_usage, surface and focused paired
regression modules. Related reviewed intents: PRs #44/#82, #19/#68, #100/#97/#76/#57/#50/#17 and
HTTP-client family #96/#62/#47/#28. Reuse evidence; reassess each patch against current source.

### Story 2 — Expand framework and language coverage with explicit uncertainty (P1)

An operator sees what was resolved and what still needs review across Python/JS/mobile/native apps.

**Acceptance scenarios**:

1. JavaScript assigned SQL text receives bounded binding-aware flow analysis, with safe bound-value,
   reassignment, sibling-scope and distinct-site controls. Python loop/cross-function gaps remain
   explicit until an independently tested extension replaces them; no fixed-point claim by implication.
2. FastAPI dependency and tRPC base-procedure controls bind to the actual endpoint and visible
   enforcement. Imported names, comments, no-op definitions and protected siblings cannot guard it.
3. Flask-SQLAlchemy `db.Model` entities join the existing model inventory without confusing unrelated
   classes; FastAPI `UploadFile` filename/content_type flows gain scoped positive/negative cases.
4. Django template-to-response control mapping can retain a same-response CSP/header observation
   without claiming deployed protection. Unknown mounts, dynamic prefixes and view aliases preserve
   candidate status; template text alone cannot establish a response control.
5. Specialist reports and named native profiles expose limitations; adding per-language regexes cannot
   substitute for compile/runtime evidence that the tool has not collected.

**Candidate ownership/tests**: syntax/surface, authz/routes, schemas, upload_security, Django URL and
transport analysis. Related intents: #95/#45 (Python portion delivered), #93, #67, #71 and #40/#34
(spec-only route provenance must remain separate from implemented source routes).

### Story 3 — Reproducible recurring protection without silent trust changes (P2)

An operator can deliberately adopt local and CI reviews and understand version/feed freshness.

**Acceptance scenarios**:

1. A disposable validation environment runs the actual pre-commit install/staged/manual/pre-push
   lifecycle and parses the shipped configuration with the real supported framework. No dependency
   is added to the runtime package; integration tooling is explicit development infrastructure.
2. A controlled CI test verifies separate trusted engine and PR target checkouts, read-only privileges,
   current partial artifacts and failure propagation. No target setup scripts, hooks or local Action
   run as the engine. Schedules and hosted runs are activated only by an authorized operator.
3. Reviewed engine/scanner/feed revisions are recorded; missing required analyzers and stale/failed
   updates remain visible. A pinned weekly scan cannot claim new rules without a reviewed update.
4. Container scanner upgrades and health checks are tested as a separate packaging matrix with exact
   image/tool revisions. Pin-only and mixed upgrade PRs (#30/#92/#53 and related families) are not
   accepted merely because their source diff is small.

### Story 4 — Measure improvement and communicate public findings responsibly (P1)

An operator receives reproducible evidence rather than inflated benchmark or vulnerability claims.

**Acceptance scenarios**:

1. Each proof run records exact corpus/detector/package revisions, optional tool versions/availability,
   selected scope, skipped/unknown labels and raw sanitized results. Compare prior/current engines
   under the same environment before calling a changed score a regression or improvement.
2. Research proposals retain source/licensing attribution and disjoint development/holdout data.
   Authored synthetic success means eligible for human review, not independent production recall.
3. Public-project vulnerability escalation is limited to independently verified **critical** issues
   within authorized scope. A tool's CRITICAL label, source-only lead, candidate route, unsafe-looking
   sample or missing scan result is insufficient. Preserve counterevidence, including scoped controls.
4. Lower-severity or unverified public-project observations stay internal research/precision evidence.
   Do not create public issues, contact maintainers, publish exploit details or run live probes without
   explicit authorization. This policy does not suppress legitimate internal review findings.

## Functional Requirements

- **FR-001**: Preserve root containment, private-path pruning, stdlib-only runtime and data-only target
  analysis. New boundaries and resource caps must disclose partial results rather than silently pass.
- **FR-002**: Every detector change needs a reproduced failure plus safe and unsafe neighboring cases,
  an independent reviewer and a real CLI/ledger contract test where producer shapes change.
- **FR-003**: Maintain one actionable work item per unique intent, linked to exact PR head(s), evidence,
  disposition and this specification. Recheck main/PR state before integration; no overlapping blind merges.
- **FR-004**: Keep source hashes, detector revision, report hashes and operator test evidence distinct.
  Unknown observations cannot become verified fixes or suppression authorization.
- **FR-005**: New integrations are opt-in, bind trusted engine provenance, preserve foreign user files,
  and do not install software or activate schedules outside the operator's authorization.
- **FR-006**: Release via the CI-gated PR/tag/publish train; verify published artifacts separately from
  local wheel success. Update canonical docs, changelog, migration notes and actual test floor together.

## Success Criteria

- **SC-001**: Every accepted next change has an original reproducer, paired controls, ownership and a
  documented limitation. All relevant/full required checks pass without lowering the test floor.
- **SC-002**: All 53 reviewed PRs receive a traceable disposition after head revalidation; retained novel
  ideas map to a single spec item rather than duplicate unresolved implementation branches.
- **SC-003**: New benchmark claims include comparable raw evidence and explicit environment/scope;
  no historical score is presented as current without rerunning it.
- **SC-004**: No unverified or noncritical public-project lead is escalated as a confirmed public issue;
  no public contact or live testing occurs without explicit authorization.

## Edge Cases and Non-goals

Unknown loops, indirect wrappers, shadowed bindings, mixed services, ambiguous source locations,
unavailable analyzers, malformed reports, privacy paths, stale baselines and disappearing findings
must preserve uncertainty. Do not promise every project/style is covered, autonomous repair proof,
blind zero-day discovery, deployed authorization safety, or continuously refreshed intelligence from
an unchanged pinned engine. These limits are part of the product contract, not hidden omissions.

## Authoritative workstream and PR disposition register

This specification is the single open implementation backlog after release consolidation. The
[complete review data](../../docs/security-review/release-pr-triage.json) preserves each exact head,
base, diff digest, changed files, rationale and evidence. Classification counts are 31 superseded or
duplicate, 16 unsafe drafts with retained intents, 3 unique changes deferred, and 3 separate
upgrade/policy proposals transferred here. No PR is endorsed for blind merge. At this pre-release audit snapshot, closures were pending.
Each closure requires release merge, spec presence and a final unchanged-head check; GitHub PR
state records completion. Unresolved intent stays open here even after its draft PR is closed.

### W01 — credential-comparisons

PRs: #100, #97, #57.

Delivered per-comparison controls; preserve hardcoded, reversed and unsafe-sibling tests when reviewing later changes.

### W02 — container-health-and-selfscan

PRs: #99, #87, #86, #81, #75, #37, #36, #31, #27.

Decide short-lived CLI versus long-lived MCP health policy explicitly (#31); test selected modes, minimal image and self-scan intent without assuming HEALTHCHECK NONE creates health assurance.

### W03 — http-client-methods

PRs: #96, #62, #47, #28.

Story 1.2: bound HTTP client receivers, request arguments and safe literal/unrelated-method controls.

### W04 — assigned-sql-flow

PRs: #95, #54, #45.

Story 2.1: Python delivered; extend JS bindings only with paired source, reassignment and parameterized-query tests.

### W05 — framework-auth-composition

PRs: #93.

Story 2.2: verify actual FastAPI dependency/tRPC enforcement with no-op and sibling controls.

### W06 — container-scanner-compatibility

PRs: #92, #58, #18.

Story 3.4: verify exact Trivy archives/checksums/platforms and adapter contracts (#58/#92). Separately replace race-probe dependencies (#18) only with bounded stdlib bodies, redirect controls, timeouts and authorized-target tests.

### W07 — release-documentation

PRs: #91, #78, #70, #24, #20.

Superseded by reviewed release documentation; preserve actual version, score provenance and test-floor consistency.

### W08 — upload-key-svg-policy

PRs: #82, #65, #48, #42, #39, #33, #32, #29, #25, #22.

Story 1.1: bind key construction and SVG acceptance to actual operations, including rejection/logging controls.

### W09 — hash-purpose-and-jwt-binding

PRs: #76, #50, #17.

Story 1.4: purpose and JWT options must bind to each operation; no file-wide keyword exemptions.

### W10 — assigned-command-flow

PRs: #73.

Add bounded assigned-command source flow (#73), preserving safe argument vectors, literal commands, reassignment, separate functions and multiple sinks; do not treat every variable argument as tainted.

### W11 — python-upload-provenance

PRs: #71.

Story 2.3: Python UploadFile filename/content_type flows and safe storage/content-validation controls.

### W12 — pii-response-value-binding

PRs: #68, #19.

Story 1.3: actual boolean/projected values, raw entities, spreads, mutations and TypeScript-only aliases.

### W13 — flask-sqlalchemy-models

PRs: #67.

Story 2.3: db.Model import/receiver binding with unrelated Model classes as controls.

### W14 — setup-python-major-upgrade

PRs: #53.

Validate official v7 SHA consistently across CI/publish/composite callers, supported runners and input/output contracts (#53). Current release retains pinned v6; do not adopt the proposed floating composite ref.

### W15 — file-response-binding

PRs: #44.

Delivered scoped browser-response analysis; preserve commented HTML, nested headers and unrelated stream controls.

### W16 — documented-route-candidates

PRs: #40, #34.

Keep OpenAPI documentation candidates distinct from implemented routes; use bounded scoped readers and safe aliases/dynamic-reference controls.

### W17 — action-provenance

PRs: #30.

Delivered trusted engine checkout, environment argv, exact current artifacts and immutable pins; preserve hostile input/target tests.

### W18 — source-literal-precision

PRs: #23.

Reproduce static re.compile patterns containing self and quoted NODE_ENV prose (#23); inspect executable expression/literal binding, retain genuine dynamic regex and error-response siblings.

### W19 — llm-guard-binding

PRs: #21.

Reproduce Scanner/scan_dir pseudo-source and allowed:true catch text (#21); require actual failure-handling relationship, preserve unsafe named guards and separate-scope controls.

### W20 — Connexion spec-first route registration

No existing PR: resolve literal `connexion.App(specification_dir=...)` plus `add_api(...)`
registration through bounded contained OpenAPI reads, retaining documentation provenance. Add
VAmPI-shaped positive cases, unrelated receiver, dynamic spec path, escaping path and malformed
spec controls. Never execute application code or claim runtime routes from an unresolved spec.
The same pinned VAmPI snapshot produced zero fallback routes in both compared wheels when Noir
was absent; this is an uncovered framework pattern, not an established new regression.

### Exact reviewed heads

| PR | Head SHA | Workstream | Disposition |
|---|---|---|---|
| [#100](https://github.com/raccioly/websec-validator/pull/100) | `83158d0d2d224275138f6e56bac69e6ca5dc724a` | W01 | superseded or duplicate |
| [#99](https://github.com/raccioly/websec-validator/pull/99) | `544db70c4597e4f48fb650c7ed200fc3a79c7351` | W02 | superseded or duplicate |
| [#97](https://github.com/raccioly/websec-validator/pull/97) | `9cb26fc1f29b00da15ea39d926fb38a82e786c0c` | W01 | superseded or duplicate |
| [#96](https://github.com/raccioly/websec-validator/pull/96) | `4ec70a34dc670523c453e098bd167f591616ddf6` | W03 | superseded or duplicate |
| [#95](https://github.com/raccioly/websec-validator/pull/95) | `ada3d6e69d18b6935929f4918ff5f1610fa93f43` | W04 | superseded or duplicate |
| [#93](https://github.com/raccioly/websec-validator/pull/93) | `9617adb2582f958eb4341394471c6e9515415548` | W05 | unsafe proposal deferred to spec |
| [#92](https://github.com/raccioly/websec-validator/pull/92) | `c3a52a19cf2d0cc0e55029619a88b9a762ada675` | W06 | superseded or duplicate |
| [#91](https://github.com/raccioly/websec-validator/pull/91) | `aa202d6f19e8bc319fbc250ee5dff0b135563b96` | W07 | superseded or duplicate |
| [#87](https://github.com/raccioly/websec-validator/pull/87) | `a1657610ee71e115d089f8ee5eb3fd6d99282d20` | W02 | superseded or duplicate |
| [#86](https://github.com/raccioly/websec-validator/pull/86) | `e30fe1bf28a2adb65dcfacf8b5ae4e97e4272a03` | W02 | superseded or duplicate |
| [#82](https://github.com/raccioly/websec-validator/pull/82) | `1bc667fc82388a6f26bb0fbcd99cdc44d332dcfc` | W08 | unsafe proposal deferred to spec |
| [#81](https://github.com/raccioly/websec-validator/pull/81) | `ba2dda5513e0fd4cffa8a71ccc632bfa7ef4a27a` | W02 | superseded or duplicate |
| [#78](https://github.com/raccioly/websec-validator/pull/78) | `d007283e20d61b3725d4a65386b84f04d50731bb` | W07 | superseded or duplicate |
| [#76](https://github.com/raccioly/websec-validator/pull/76) | `0fe8cf95a8aee6ef961232a3bafa8de8508f6a9c` | W09 | unsafe proposal deferred to spec |
| [#75](https://github.com/raccioly/websec-validator/pull/75) | `af4cb6c926cb45a2060819ec6931e39cff939a42` | W02 | superseded or duplicate |
| [#73](https://github.com/raccioly/websec-validator/pull/73) | `9eec2932c92eba1e76f0bed09d84f1093a4c8bfb` | W10 | unsafe proposal deferred to spec |
| [#71](https://github.com/raccioly/websec-validator/pull/71) | `2e1250efc3112d6f31e07af3d9dee43b62098e44` | W11 | needed unique change |
| [#70](https://github.com/raccioly/websec-validator/pull/70) | `cc9244c8a571b5fbf4b2c9ff626207652dc4f266` | W07 | superseded or duplicate |
| [#68](https://github.com/raccioly/websec-validator/pull/68) | `759cc9ab6577a9275e0c3ec2e5ee4a3f9561c444` | W12 | unsafe proposal deferred to spec |
| [#67](https://github.com/raccioly/websec-validator/pull/67) | `3aa8abd58802344766fb3f5990187bfd9ef77ab4` | W13 | needed unique change |
| [#65](https://github.com/raccioly/websec-validator/pull/65) | `859ac3d7da300a1bde293b997277352197008bd7` | W08 | superseded or duplicate |
| [#62](https://github.com/raccioly/websec-validator/pull/62) | `6dc26df52d759474876564175c04518b12f6277e` | W03 | needed unique change |
| [#58](https://github.com/raccioly/websec-validator/pull/58) | `36e97f4768c81b2a65d98df81b7700b6b77cd300` | W06 | unrelated needs retaining |
| [#57](https://github.com/raccioly/websec-validator/pull/57) | `0f3d9f6064267400da89f8dd172b51c9dccf24af` | W01 | superseded or duplicate |
| [#54](https://github.com/raccioly/websec-validator/pull/54) | `9878e7ff70bca62f113e6567ba0b81b0498f434e` | W04 | superseded or duplicate |
| [#53](https://github.com/raccioly/websec-validator/pull/53) | `2a729d0cdde8fa057ac0ecf0979fe8d047022d42` | W14 | unrelated needs retaining |
| [#50](https://github.com/raccioly/websec-validator/pull/50) | `236ebf8dd7e308d75db5e590042b5c2e2b2f3942` | W09 | unsafe proposal deferred to spec |
| [#48](https://github.com/raccioly/websec-validator/pull/48) | `b8be9ac6de51c0736ba653aea050695ed7a184f7` | W08 | superseded or duplicate |
| [#47](https://github.com/raccioly/websec-validator/pull/47) | `c07d5930dd99f3876c57c63dd0fafacef31c5006` | W03 | superseded or duplicate |
| [#45](https://github.com/raccioly/websec-validator/pull/45) | `0d8328b039d4fd9f3fa221e4c16a63f896a64715` | W04 | superseded or duplicate |
| [#44](https://github.com/raccioly/websec-validator/pull/44) | `80ab27ec9c18423f309d51099516cf6cd0b09677` | W15 | superseded or duplicate |
| [#42](https://github.com/raccioly/websec-validator/pull/42) | `28955b7e35c8c6cdf59e9864309174dd35622330` | W08 | unsafe proposal deferred to spec |
| [#40](https://github.com/raccioly/websec-validator/pull/40) | `aeb82da038622719b3643f55ca437462fc09b9a4` | W16 | unsafe proposal deferred to spec |
| [#39](https://github.com/raccioly/websec-validator/pull/39) | `9dbc70fd6579f55b0e4aa0556ea42bf907d325bc` | W08 | unsafe proposal deferred to spec |
| [#37](https://github.com/raccioly/websec-validator/pull/37) | `d73859692fb898ea3e824431c1165f4be912dcc0` | W02 | superseded or duplicate |
| [#36](https://github.com/raccioly/websec-validator/pull/36) | `2f0ad5aa33e561e2304fefb062891ca8003558f2` | W02 | superseded or duplicate |
| [#34](https://github.com/raccioly/websec-validator/pull/34) | `3392b15c53a74534192d41840233f91a9d59a3b2` | W16 | unsafe proposal deferred to spec |
| [#33](https://github.com/raccioly/websec-validator/pull/33) | `b06c2b0726ca1f2c673e1867e14887154eef4f43` | W08 | superseded or duplicate |
| [#32](https://github.com/raccioly/websec-validator/pull/32) | `fe951bab419968e86920b630269f30350d61dd8e` | W08 | unsafe proposal deferred to spec |
| [#31](https://github.com/raccioly/websec-validator/pull/31) | `258ae5c5ed9b0e3460b8eb9b00b2d0c24a8aaa19` | W02 | unrelated needs retaining |
| [#30](https://github.com/raccioly/websec-validator/pull/30) | `27d6b4d17a0497d3e0d81fb197cffa6aafc573b4` | W17 | superseded or duplicate |
| [#29](https://github.com/raccioly/websec-validator/pull/29) | `de5c2da0027dbc767148e830df19c16da624f407` | W08 | superseded or duplicate |
| [#28](https://github.com/raccioly/websec-validator/pull/28) | `3c8cb62bd5d0dd4d82ea64d3b2ec9c7c75a3421f` | W03 | superseded or duplicate |
| [#27](https://github.com/raccioly/websec-validator/pull/27) | `83c20c633ce6154af1710656784f077167b87db7` | W02 | superseded or duplicate |
| [#25](https://github.com/raccioly/websec-validator/pull/25) | `6a0f293a2bdf0efe3427306499540261cac5e3e8` | W08 | superseded or duplicate |
| [#24](https://github.com/raccioly/websec-validator/pull/24) | `60bd6077691f665544675419e1cdd8e1d4b2ee74` | W07 | superseded or duplicate |
| [#23](https://github.com/raccioly/websec-validator/pull/23) | `706c5e61ed0751b4c41bebd2d315e95571642d74` | W18 | unsafe proposal deferred to spec |
| [#22](https://github.com/raccioly/websec-validator/pull/22) | `8985e24ae54845bbefe0c0dc99c4c16c3fdce933` | W08 | superseded or duplicate |
| [#21](https://github.com/raccioly/websec-validator/pull/21) | `a5a7e2537ea1d85d35fa7629dfe6be7e648e0d9f` | W19 | unsafe proposal deferred to spec |
| [#20](https://github.com/raccioly/websec-validator/pull/20) | `63f9427ad24b8deba986c6c897e12cdfd439d140` | W07 | superseded or duplicate |
| [#19](https://github.com/raccioly/websec-validator/pull/19) | `25662616011e064664cd42caa2a9a1778c0e1253` | W12 | unsafe proposal deferred to spec |
| [#18](https://github.com/raccioly/websec-validator/pull/18) | `4d78737e7b6f6d7b92d71962003ba5ff9c7d4a2e` | W06 | unsafe proposal deferred to spec |
| [#17](https://github.com/raccioly/websec-validator/pull/17) | `71b41eb860f5f6ad5f7ce1326f2e2ec99d4181b0` | W09 | unsafe proposal deferred to spec |

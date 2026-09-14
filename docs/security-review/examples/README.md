# Evidence contract examples

These are synthetic format fixtures. They do not report a tested application vulnerability or an
actual repair. The test suite validates the examples against the same APIs and CLI used by operators.
Do not ingest these fixtures into a real project's calibration history or reuse their IDs as evidence.

## Controlled dynamic checks

Copy the root [dynamic-config.example.json](../../../dynamic-config.example.json) to your gitignored
`dynamic-config.json`. Replace the target, credentials, application/build IDs, identity paths and
private resource markers with your authorized isolated test fixture. The shape is:

- `bola_controls.expected_policy`: `tenant-isolated`.
- `identity_path`: relative GET path that exposes the signed-in identity.
- `identities.agentA` / `agentB`: distinct `{json_path, value}` expectations.
- `resources[route_template].agentA` / `agentB`: distinct owner-only `{json_path, value}` markers.

Both legitimate identity/owner reads must succeed, anonymous access must deny the private data, and
cross-tenant disclosure must reproduce before the tool confirms a leak. Missing controls, failed
requests or generic success bodies remain inconclusive. Empty write requests can still mutate data.

```bash
websec dynamic --config dynamic-config.json --facts websec-out/latest/FACTS.json
```

## DAST context and explicit negatives

[dast-ledger.json](dast-ledger.json), [dast-positive.json](dast-positive.json), and
[dast-negative.json](dast-negative.json) share the exact `dast_context` tuple: application, build,
identity, origin, endpoint, HTTP method and parameter. A finding may override this context locally.
An empty parameter string explicitly means a parameterless check. Authenticated reports also need
`auth_verified: true`; matching an endpoint alone is insufficient.

The positive example names ZAP plugin `40018` and the exact `sqli` class. The separate negative
example uses a `checks` row with `pluginid`, `attack_class`, `completed: true`,
`coverage_complete: true`, `auth_verified: true`, and `outcome: "not-vulnerable"`.
These fields assert an actually completed scoped negative check. Do not manufacture them from an
empty report. Contradictory positives and negatives remain unjudged. For actual evidence, attach
verified context to your report and ledger before invoking `calibrate --ingest-dast`.

## Repair artifact triplet and rerun

The [repair](repair/) directory is a complete, internally consistent synthetic validation fixture:

- [plan.json](repair/plan.json): original finding, application/build/source, scope and plan identity.
- [record.json](repair/record.json): original-to-target transition, canonical rerun ledger hash and
  references to the positive/negative reports.
- [before.json](repair/before.json): original-build failed negative test.
- [negative.json](repair/negative.json): fixed-build passing negative test, linked to the hashed before report.
- [positive.json](repair/positive.json): fixed-build legitimate-behavior passing test.
- [rerun-ledger.json](repair/rerun-ledger.json): fixed context, analyzed-input digest and complete coverage.

Every report binds `plan_id`, `finding_id`, `test_id`, `application_id`, `build_id` and `source_digest`.
The negative before/after pair shares its test ID. Tests need positive counts and explicit failed
counts; changing bytes requires updating their SHA256 references. The rerun digest uses canonical
JSON through `repairs.digest`, and must match the ledger artifact supplied to the validator.

From the repository root:

```bash
websec repair-verify --plan docs/security-review/examples/repair/plan.json --record docs/security-review/examples/repair/record.json --rerun docs/security-review/examples/repair/rerun-ledger.json --evidence-root docs/security-review/examples/repair
```

The expected result is `accepted: true` with `tests_executed_by_websec: false`. This demonstrates
artifact validation only. For real work, start from the run's generated `repair-plans.json`, collect
actual original failure and fixed-build test reports, rerun the same detector/scope/policy, and select
one plan with `--plan-id` when the plan artifact contains multiple entries. Never copy these synthetic
passing reports into a real verification record.

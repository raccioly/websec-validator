# Retained-work reconciliation — 2026-09-30

Starting source `2ee99673`; this is an implementation ledger, not a vulnerability/recall benchmark.
The [research](../../specs/001-continuous-security-improvement/research.md) records independently
reproduced gaps. The [tasks](../../specs/001-continuous-security-improvement/tasks.md) own completion.

Delivered controls retained: W01 exact comparison operands (`test_crypto_comparisons.py`), W07
reviewed release/brief publication, W14 eight pinned setup-python v7 callers, W15 response-local
headers (`test_public_precision.py`) and W17 trusted-engine Action (`test_action_contracts.py`).
Other retained workstreams remain partial/planned until their paired tests and integration evidence
land. Exact historical PR heads/dispositions remain in the spec/register; no closed draft is reused
as implementation evidence. No new public-project vulnerability claim or disclosure is made.

## Whole-document review

Architecture, security, environment, test specification, AGENTS, local ignored CLAUDE and the full
methodology were read against current CLI/registry/coverage/transport/calibration contracts.
Corrected broad confidence and status-only dynamic claims, old CLI inventory, snapshot/current
measurement confusion and DocGuard no-matches interpretation. Historical dated test/proof records
remain intact. Reviewed markers record this actual review, not warning suppression.

DocGuard cannot infer every acceptance clause: spec 002 said implementations shipped while its
reviewed registry remained draft/planned. Current audit found untested acceptance gaps despite
passing focused tests. Approval is reconciled as approved; delivery remains in progress, not
verified/released. Generated observed fields are refreshed with `docguard specs --write`.

## Integration evidence limits

## First detector batch

The FastAPI unit passes ten tests, including two actual subprocess CLI runs that assert persisted
missing-auth ledger locations and exit status. Supported authentication evidence stays endpoint-local;
imported/no-op/mutated/wildcard dependencies, fixed credentials and disabled JWT verification do
not receive guard credit. Independent review supplied negative controls and confirmed their fixes.

The first precision unit adds per-call JWT options, primitive PII projections, all-known-field
literal removal, executable SVG acceptance and security-invocation-bound fail-open checks.
Unknown forms remain review leads or disclosed unsupported syntax, not a safety certificate.
Original partial-omit input remains covered as unsafe. At this checkpoint the complete application
suite passed 1736 tests and automation passed 57; these are regression results, not public-project
precision/recall measurements. tRPC, principal/hash-purpose and integration work are still pending.

### Environment limits

Second checkpoint: every declared truth row must be reviewed and boolean-labelled before a
class-specific corpus cell qualifies. Measurable corpus/authored/local tables report Brier scores;
merged metadata retains only source-scoped scores, explicitly not a score of merged predictions.
Original language fixtures and comparative measurements remain pending. Independent review and
88 focused tests pass; the full application suite passes 1744 tests.

The race draft now imports only stdlib/shared probe helpers. A real owned-loopback test observes
four concurrent POSTs, no followed 302, no inherited proxy and no reflected-secret artifact.
Concurrency is bounded to 1–16, payloads to 16 KiB, and socket I/O has a five-second timeout—not a
hard whole-request wall-clock deadline. Status-only observations do not validate business state.

The local Docker client has no available daemon; pre-commit is absent at baseline. Neither a
configuration-shaped test nor an installed client establishes an executed integration lifecycle.
Authored paired fixtures do not measure independent production precision. The separate manual
agent A/B protocol is still an experiment, not an implied result from unit tests.

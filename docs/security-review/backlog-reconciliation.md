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

## Assigned-flow evidence

Eleven paired tests and an actual subprocess CLI ledger contract cover retained JS SQL/command,
Python command and import-bound Needle method gaps. Python reuses the bounded query AST engine's
branch joins; JavaScript models simple local assignments with conservative branch may-taint.
Literal overwrites/bind parameters/sibling scopes/inert interpolation stay distinct. Dynamic
executables/interpreters, mutated runners and unknown shell options cannot borrow inert argv
credit. Repeated sink identities stay distinct; outer callee classification cannot invent a SQL
sink from a nested fixed query. Independent review confirmed its five negative controls fixed.

Source byte/node/event/scope/binding budgets are visible; exhaustion is an execution gap, not a
clean result. Loops, closure capture, destructuring, runtime dispatch and cross-function flow remain
unverified. These tests do not measure unseen-project recall. A full-suite checkpoint encountered
the existing MCP overload-close timing race; the exact isolated assertion passed unchanged and
the transport behavior was investigated separately. The reviewed assigned-flow checkpoint
subsequently passed all 1756 application tests with the original MCP assertion unchanged.

## MCP overload evidence

Owned-loopback reproduction established that closing an overloaded socket before a normal client
sends its body can reset TCP instead of delivering 503. The new split-header/body regression failed
before the fix; the original worker-limit assertion is preserved. Send rejection immediately, then
half-close and discard at most 8 KiB under an absolute 50 ms deadline. No worker, slot, authentication
or root permission is granted. This costs up to 50 ms of accept-loop time per rejection; oversized,
malformed and slower clients remain best-effort, not an unlimited graceful-close guarantee.

Independent review of the actual implementation found no defect in this bounded unit and observed
503 for 300/300 ordinary and 25/25 delayed-body requests. Full checkpoint: 1759 application tests,
57 automation tests, compileall and offline brief artifact binding pass. These are local regression
results, not a claim of broad MCP availability or throughput under arbitrary load.

## Connexion registration evidence

Ten new regressions map import-bound top-level literal local JSON contracts independently of Noir,
preserving `code_path` (registration), `spec_path` and original contract path across base-path mounting.
Unregistered Noir spec rows never become write targets. Authorization reads only the exact immutable
top-level operation body; unrelated registering-file guards and declared `security` cannot confer
protection. Unresolved handlers remain unanalysed with explicit reasons, not certified safe.

Paired malformed/declaration-order/private/escaping controls and an actual subprocess CLI artifact
test pass. Parser execution budgets enter coverage; supported-source uncertainty remains separate.
Independent review found and confirmed fixes for four integration/input gaps. Full checkpoint passes
1769 application tests. YAML, dynamic options, templates and cross-module composition remain manual
review gaps, not claimed completed acceptance or a new corpus measurement. This follows the
[Connexion registration API](https://connexion.readthedocs.io/en/stable/quickstart.html); source
registration alone does not establish deployed handlers or enforced authorization.

## Hash-purpose evidence

Six new paired regression methods bind actual supported digest values to local principal use.
Avatar/cache neighbors, inert strings/closures, literal identity text and boolean-valued comparisons
do not become principal hashes. Visible straight-line overwrites clear supported local provenance;
branch uncertainty conservatively retains may-flow. Python AST and JS source/event/scope limits
disclose failures rather than return a clean scan.

Exact password-update metadata suffixes do not hide real credential bytes or compound inputs.
A narrow supported SHA-1 hex/five-character-prefix/fixed HTTPS range lookup shape is distinct from
password storage, following the [HIBP API](https://haveibeenpwned.com/API/v3#PwnedPasswords).
Unknown/shadowed/reassigned/destructured/reflected crypto or fetch primitives, extra hash uses,
other hosts/prefixes and unsafe siblings retain leads. This is purpose evidence, not a guarantee
of correct breach matching, privacy under runtime mutation or principal secrecy reliance.

Independent review confirmed all supplied negative controls fixed; 77 focused root tests and
1775 full application tests pass. Unknown wrappers, loops and cross-function flow remain unverified.

## Flask model evidence

Supported visible top-level Flask-SQLAlchemy constructor/model bindings now inventory actual column
names, not comments, strings or method prose. Both ordinary app paths and `models/` paths preserve
that distinction. Unrelated or mutated receivers, late imports, overwritten columns and unused
nested model factories do not supply new model/field evidence. Imported extension objects and
runtime factories remain unresolved; legacy non-Flask model lanes have not become AST proofs.

Seven paired regression methods include a subprocess CLI facts contract whose target raises if
imported; recon succeeds without executing it. Independent review confirmed all three supplied
negative controls fixed; all 1782 application tests pass. Byte/node/aggregate budgets disclose
incomplete execution. This follows
the [Flask-SQLAlchemy model API](https://flask-sqlalchemy.palletsprojects.com/en/stable/models/);
inventory is not a claim about deployed models, database permissions or complete field coverage.

The local Docker client has no available daemon; pre-commit is absent at baseline. Neither a
configuration-shaped test nor an installed client establishes an executed integration lifecycle.
Authored paired fixtures do not measure independent production precision. The separate manual
agent A/B protocol is still an experiment, not an implied result from unit tests.

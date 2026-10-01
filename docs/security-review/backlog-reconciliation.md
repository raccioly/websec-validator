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

## Python upload evidence

Supported import-bound literal FastAPI route handlers with `UploadFile` or `Annotated[UploadFile,...]`
parameters now preserve local filename/content-type provenance into actual writes/decisions.
Metadata logs/returns and unused closures do not become storage; generated names and straight-line
overwrites remain separate from possible branch flow. This follows the
[FastAPI upload API](https://fastapi.tiangolo.com/tutorial/request-files/); caller declarations are
not evidence of content bytes. No target module or dependency is imported.

Validation credit is deliberately narrow: the same original full read, import-bound
`magic.from_buffer(...,mime=True)`, a literal supported-type rejection raising HTTP 415, and matching
stored bytes. Names, no-op/caught checks, partial/transformed/other bytes and unsupported branches
cannot establish that evidence. It does not certify polyglot rejection or safe serving. Thirteen
regressions include an actual subprocess CLI/ledger contract; source/node/binding/aggregate limits
disclose incomplete execution. Dynamic registration, collections, factories and cross-function
flow remain unverified rather than executed to discover runtime behavior.

One intermediate full run correctly refused changed detector revision because source was edited
while the research suite evaluated it. Its original integrity assertion was preserved; final full
validation passes all 1795 application tests against an unchanged detector revision. Independent
review confirms the supplied branch, stored-byte and shadowed-print controls fixed.

## tRPC composition evidence

Supported same-file `initTRPC.create()` procedure/router chains become HTTP targets only when a
visible import-bound Express app directly mounts the reviewed adapter with that router and a
literal base path. Unmounted/conditional/unused composition remains candidates with scope gaps.
Nested procedure names use transport dot segments; queries and mutations retain distinct methods.
This follows the [tRPC router](https://trpc.io/docs/server/routers) and
[Express adapter](https://trpc.io/docs/server/adapters/express) contracts, not runtime deployment.

Middleware hints are chain-local: a complete supported rejecting branch plus `next()` can supply
evidence only when earlier middleware is known to continue or has already rejected unauthenticated
context. Unknown/short-circuiting prefixes, names, no-op/caught checks, primitive mutation and sibling
guards cannot confer protection. The context supplier's identity/authentication remains unverified;
these source hints are not validated JWT or deployed authorization proof. Twelve methods include
subprocess CLI coverage/ledger artifacts; limits on bytes, bindings, depth and result count disclose
execution loss. Generic/input chains, imports across files and other adapters remain review gaps.
Independent review confirms all three supplied blockers fixed; final unchanged-source checkpoint
passes 1807 application tests. Unsupported generic instance composition has an explicit scope gap.

## Container checkpoint

Official release metadata independently confirms the checked-in Noir 1.0.0, Gitleaks 8.30.1 and
Trivy 0.74.0 amd64/arm64 filenames and digests. All archive bytes are checked before extraction
or package installation; an actual corrupted-byte subprocess control never invokes privileged
installation. Unsupported architectures and unreviewed archive-version overrides fail before
network access. The Python index is fixed; Semgrep/Checkov top-level versions are pinned, not apt
or every transitive dependency. No claim of complete reproducibility or upstream trust follows.

The one-shot image explicitly has no periodic healthcheck; optional in-container MCP transport
liveness is not scan or authentication assurance. The build context is allowlisted and private
trees excluded. Actual native core/bundled image execution now supplies the bounded T024/T025
acceptance evidence below; this is not complete scanner-adapter or database coverage.

The local Docker client has no available daemon; pre-commit was absent at baseline. Neither a
configuration-shaped test nor an installed client establishes an executed integration lifecycle.
Authored paired fixtures do not measure independent production precision. The separate manual
agent A/B protocol is still an experiment, not an implied result from unit tests.

### Executed container matrix

All four native jobs passed on 2026-10-01 in
[run 36817563117](https://github.com/raccioly/websec-validator/actions/runs/36817563117),
for PR head `89ede34473b4d0122c4ff6ef4eddf8851a3649ba`. Each built the reviewed engine,
asserted its runtime architecture, nonroot user, zero engine runtime requirements and disabled
periodic healthcheck, then executed an offline source-only fixture. Both bundled images executed
the five optional scanner version commands. These are local build image IDs, not published registry
manifests or a claim of byte-reproducible builds.

| Target | Architecture | Observed image SHA-256 |
|---|---|---|
| core | amd64 | `b52ab80de4a95773bbaf7f264feac721ebbb95245f9d1180db2831ac9095d34a` |
| core | arm64 | `370bc1a5ea0cd3d37dd1c9bc9ced067d4ce49a577b0088a71342f6044541e814` |
| bundled | amd64 | `428711270039d1b661e3134f7c6a31ef9c006917e13883addf85d8f4df1849c6` |
| bundled | arm64 | `d7e77f3ebc9c520e3d82ec6f1c8b71e9f8a6e3fc85f63f9d9d31e700b81e9575` |

### Adoption lifecycle checkpoint

The owned local test passed with pre-commit 4.6.2 in a disposable development environment. It
validated real installation, an actual rejected staged commit, clean-index/unsafe-unstaged restore,
manual and pre-push framework gates, no implicit baseline acceptance and foreign-hook restoration.
No user project hooks, global packages or scheduled consumer scans were changed. An actual push
to an owned local bare repository rejects unsafe working-tree input and accepts clean input;
no public-network push occurs. The normal application suite passes 1813
tests with this one development-only lifecycle skipped; the opt-in lifecycle passes separately.

All four hosted adoption jobs passed in
[run 36818626389](https://github.com/raccioly/websec-validator/actions/runs/36818626389)
at head `b383d2e221722d9beb73fff75618d170b045eaca`: the real framework lifecycle and actual
separate-engine composite Action for clean, unsafe and oversized owned hostile inert fixtures.
The Action asserts current-attempt outputs, expected findings/completeness and no target execution.
T027 is complete within this controlled integration scope, not a full consumer two-checkout or
scheduled deployment. The optional development dependency is not a WebSec runtime requirement.

## Final bounded precision evidence

Six additional methods extend the paired JWT/hash/upload/PII/literal/guard controls and include
actual subprocess CLI facts, execution completeness and findings-ledger artifacts. Client filename
flow is now tied to supported storage arguments, not intermediate variable spelling; old bare
assignments remain negative controls and their actual storage consumption remains positive.
Object-body metadata, literal overwrites and sibling scopes stay separate. The bounded local
assignment walker now reports expression truncation as execution loss rather than silent success.

PII projection credit requires literal keys, an unreplaced supported helper and its entire assigned
expression. Dynamic fields, spread keys, local helper implementations and raw-entity fallbacks
remain leads. Static Python f-strings without interpolation are inert. A caught nested try owns
its security invocation; an outer catch cannot borrow that call to manufacture fail-open evidence.
Unknown aliases/runtime storage, closure capture and complex rethrow/finally flow remain manual
review limits. Independent review supplied both whole-expression and expression-cap controls;
137 focused regression tests pass. These tests do not measure public-project precision or recall.

## Django same-response checkpoint

Seven new methods bind import-bound literal render/template evidence to the exact returned
response and latest same-receiver literal headers. Unrelated responses, shadowed/late imports,
mutated bindings, unknown branches/aliases and overwritten responses cannot lend protection.
Strict CSP is a supported directive shape, not valid runtime nonce generation or a deployment
certificate. An unverified sibling retains a response-specific lead even beside a protected view.
An actual subprocess CLI facts/ledger contract succeeds without executing a target that raises.
Byte/node/aggregate/observation limits disclose execution loss. The 61 focused Django response,
route, profile and public precision tests pass. Independent review supplied and confirmed fixes
for header/render expression mutation and actual unaliased module bindings. Final unchanged-source
validation passes all 1826 application tests with the original assertions preserved.
Existing native profile tests preserve manual C/C++ scope, unknown malformed configurations and
authored-only holdout limits; no new native vulnerability recall is implied.

## Registered YAML Connexion checkpoint

Ten additional methods exercise actual YAML text (not JSON merely renamed `.yaml`), exact source
registration/operation bodies and persisted subprocess CLI facts/ledger. The new stdlib parser is
a strict bounded data subset, separate from general informational OpenAPI partial parsing. Tags,
anchors/aliases, merges, duplicate keys, block routing identifiers, ambiguous plain scalars,
multi-document input and path/operation references cannot supply targets. Unknown composition
retains scope gaps; resource caps enter execution coverage. No constructors or target imports run.

The exact dotted Python operation supplier is preserved; slash/hyphen normalization and contract
security declarations cannot mark a handler guarded. Literal Flask config assignments do not
replace the Connexion registration primitive or provide authentication evidence. Independent
review supplied block-scalar, quoting/comment, document-marker and normalized-handler controls.
All 80 focused framework/OpenAPI/source tests pass. The unchanged-source full suite passes
1,836 tests with one optional development integration skipped.

## Language controls and captured-report comparison — 2026-10-01

Two new actual offline CLI fixture regressions persist honest Elixir/Swift coverage limits. The
Elixir source is recovered from PR 151 at `9f93abae0930523ffefb86da7a82be06a482336f`;
the Swift fixture is newly authored, not the unavailable original V9 application. See
`tests/fixtures/LANGUAGE-PROVENANCE.md`. Neither fixture is executed or establishes vulnerability recall.
Spec 002's original Swift replay evidence remains unavailable rather than silently satisfied.

`scripts/compare-reports.py` imports byte-bound WebSec/Semgrep/Bandit captures offline against
explicit reviewed positive/negative labels. Exact source/line/class matches, unknown contradictions,
per-tool denominators, deduplicated positive label hits and partial/unavailable/malformed statuses
are paired-tested. Messages/source excerpts are excluded; contained writers reject child aliases.
Capture execution and reviewer provenance remain declared, not authenticated. Fifteen focused
methods pass; real head-to-head and manual agent A/B experiments remain unrun. The reproducible
manifest contract is in `BENCHMARKS.md`.

Independent re-review reproduced the initial skipped-Bandit and malformed-diagnostic cases: they
now remain partial/malformed with null scores. Engine source, package and detector bindings are
separate and explicitly declared; grading policy and raw manifest bytes are hashed. The reviewer
reran all fifteen focused methods and found no further concrete blocker in this bounded review.

## 0.21.0 release validation — 2026-10-01

The frozen-source release suite passed **1,851 application tests in 49.410 seconds**, with one
optional lifecycle integration skipped. All **57 automation tests** passed; byte compilation,
33 technical-brief/artifact checks, five declared-evidence checks and the instruction audit passed
within their respective scopes. DocGuard has warnings, not a whole-document accuracy verdict.

An isolated locally built 0.21.0 wheel contains **125 source/data files matching this checkout** and
no `Requires-Dist`. Seven isolated commands (version/help/doctor/capabilities/explain/offline
update-check/source-only run) pass, with completed source-only execution. Local wheel SHA256:
`ebfd435ed93c929020bac276d62bf7a48a0b57d69f3103e7565cdd3470068fd3`.
This is not the future published wheel digest or proof of publication.

The v0.21.0 HTML/landing snapshot and generated eight-page PDF have current hash binding; all eight
rendered pages were inspected without clipping/overflow. New bounded framework/provenance and
integration claims are qualified. Historical proof/public-review dates and revisions remain intact.
DocGuard did not catch earlier brief drift because its marked-Markdown staleness and configured
metrics checks did not cover this HTML/PDF publication pair or all qualitative claims. Separate
fact tests and artifact binding now catch selected drift; accurate prose/layout still need review.

## Published artifact verification — 2026-10-01

[PR 178](https://github.com/raccioly/websec-validator/pull/178) was squash-merged at
`5603f471e38bf5cbb6abca9dc660524a05927108`, byte-identical in tree to the checked release head
`0580a7c7b6ecac8e50bebd90247218a3bc992842`. All thirteen exact-head CI/adoption/container checks
passed. The immutable `v0.21.0` tag resolves to that merge commit.

The [tag train](https://github.com/raccioly/websec-validator/actions/runs/36824050781) and
[PyPI publishing](https://github.com/raccioly/websec-validator/actions/runs/36824061736) succeeded.
The [GitHub Release](https://github.com/raccioly/websec-validator/releases/tag/v0.21.0) and
[PyPI 0.21.0](https://pypi.org/project/websec-validator/0.21.0/) exist and are not draft/prerelease/yanked.
The actual downloaded published wheel SHA256 matches PyPI:
`08eb6f503249f0228f7c0a15ac159a147991b5fd3e5204669c5ccb47a7adae66`.
Its 125 source/data members match the tagged checkout, metadata has no `Requires-Dist`, and all
seven isolated commands pass, including version0.21.0 and completed source-only recon. No global
installation was upgraded. Main CI and Pages deployment passed; the live brief manifest matches
the inspected local publication pair. This verifies publication separately from local wheel success.

Convergence found one secondary buildable US3/AC2 gap: the initial separate-target CI created data
in a distinct directory, not a second Git checkout. T035 adds an owned real clone/detached exact
commit and hostile template/hooks/fsmonitor controls. Local paired/CLI validation is recorded
separately; it does not change the published engine or claim an arbitrary public PR deployment.

The original [VAmPI configuration](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/config.py)
and [OpenAPI contract](https://github.com/erev0s/VAmPI/blob/f16052dce83f05847133ec98f01c5193a41de7d8/openapi_specs/openapi3.yml)
were read as data in an owned disposable directory: fourteen source routes, zero parser gaps/errors,
with no target import or execution. This is a source-registration reproduction, not a new full
corpus score, deployed-route check or vulnerability-recall measurement. Dynamic options/resolvers,
templates and cross-module registration remain manual scope; unsupported syntax never borrows
the informational YAML parser's partial route or security hints.

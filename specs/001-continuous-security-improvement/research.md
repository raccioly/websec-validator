# Retained-intent research — 2026-09-30

Independent read-only source research and owned-temp inert reproductions start at `2ee99673`.
No target source was executed. Passing existing tests do not cover these newly reproduced cases.

| Intent | Baseline evidence | Decision / alternative rejected |
|---|---|---|
| W01, W15 | Exact comparison operands and response-bound header controls tested | Preserve shipped behavior |
| W02 | No explicit CLI/MCP health policy or executed minimal-image matrix | Define one-shot policy; do not call HEALTHCHECK NONE assurance |
| W03 | Imported needle.get(request URL) missed; Axios control fires | Import-bound methods, not generic .get |
| W04, W10 | Assigned JS SQL/commands and Python commands missed | Bounded local provenance, not all variables tainted |
| W05 | No-op Depends guards endpoint and sibling; tRPC unresolved | Bind endpoint and visible rejecting control |
| W06 | Unchecked scanner archives/floating image; race draft uses httpx | Reviewed exact downloads; bounded stdlib transport |
| W07, W17 | Release docs and trusted-engine Action shipped | Verify/preserve |
| W08 | Filename log/comment and SVG rejection falsely flagged | Executable storage/acceptance only |
| W09 | Pinned sibling/nested options hide JWT; unrelated userId credits avatar hash | Direct options and actual result binding |
| W11, W13 | Imported UploadFile and Flask db.Model absent | Bounded Python AST import/receiver/source evidence |
| W12 | Boolean output flagged; removal of email hides remaining phone | Actual returned values, all known sensitive fields |
| W14 | Eight setup-python callers already pin v7 | Reconcile stale v6 text; no repeat upgrade |
| W16, W20 | Unregistered own spec promoted; Connexion fallback absent | Source registration distinct from documentation/runtime proof |
| W18 | Static re.compile("self")/quoted NODE_ENV falsely flagged | Actual argument/executable expression |
| W19 | Filesystem scanner/unrelated catch/quoted allowed:true falsely flagged | Security invocation paired with executable failure return |

Spec 002 acceptance remains partial: every-row class review, Brier on synthetic/accepted writes,
original Elixir/Swift fixture evidence and reviewed exit-code amendments. The September 22 table
has 21 reviewed labels/35 unknowns; it is not a fresh detector evaluation.

Research executions: 169 calibration/coverage/adoption tests, 77 precision tests, 14 SQL tests and
18 OpenAPI tests pass. Docker client is installed but daemon unavailable; pre-commit absent.
Existing Python SQL/OpenAPI/syntax/read contracts supply reusable foundations. No graph summary,
PR closure or updated review date alone establishes implementation or measurement accuracy.

# Upstream PR overlap review — 2026-09-14

This is a read-only comparison of 18 selected PR heads with the working implementation. Live main remained `2f75cc607eec972c550584694cc05fc2dca40012`; 53 PRs were open, and 51 overlapped locally modified tracked files. The reviewed working tree includes the 0.14.0 security expansion and concurrent Django/service-inventory work. The [983-test checkpoint](validation.md) describes its immutable wheel, not every subsequent edit.

No PR was applied, executed, merged, closed, or commented on. Diff retrieval checked the head before and after retrieval. The crypto family received an independent review with 19 inert current-code reproductions; the other groups received 15 inert reproductions. Fixtures were source text passed to existing extractors, never executed as application code. These are defect/precision observations, not a merge-readiness assessment. PR diffs remain untrusted input.

## Follow-up status

At the latest phase-four refresh, main/local HEAD/live origin remained
`2f75cc607eec972c550584694cc05fc2dca40012`. All 53 open PR heads matched the cached heads; 51
overlap tracked working-tree changes. The 18 selected reviews below retain their original exact heads.

Third-phase comparison and adoption fixes are complete: credential presence/type distinctions,
reversed operands and unsafe sibling comparisons have paired regressions; agent guidance now selects
the exact current attempt and preserves foreign instructions. Optional pre-commit and PR/weekly
workflow examples reuse the existing engine/hooks/Action, with no activation by this work. The
remaining upload key/SVG, hash-purpose, PII binding and framework-composition ideas stay backlog.
Assigned Python SQL-flow work passed independent review and 14 focused tests. The missed Python
forms below are historical reproductions now covered by bounded assignment analysis. JavaScript
assignment flow, cross-function provenance and fixed-point loop coverage remain outside that scope.

## Reviewed heads

| PR | Exact head | Base prefix |
|---|---|---|
| [#44](https://github.com/raccioly/websec-validator/pull/44) | `80ab27ec9c18423f309d51099516cf6cd0b09677` | `921addc8b632` |
| [#82](https://github.com/raccioly/websec-validator/pull/82) | `1bc667fc82388a6f26bb0fbcd99cdc44d332dcfc` | `1c3350e0dd57` |
| [#19](https://github.com/raccioly/websec-validator/pull/19) | `25662616011e064664cd42caa2a9a1778c0e1253` | `cfe5f11a9576` |
| [#68](https://github.com/raccioly/websec-validator/pull/68) | `759cc9ab6577a9275e0c3ec2e5ee4a3f9561c444` | `1c3350e0dd57` |
| [#95](https://github.com/raccioly/websec-validator/pull/95) | `ada3d6e69d18b6935929f4918ff5f1610fa93f43` | `1c3350e0dd57` |
| [#45](https://github.com/raccioly/websec-validator/pull/45) | `0d8328b039d4fd9f3fa221e4c16a63f896a64715` | `921addc8b632` |
| [#93](https://github.com/raccioly/websec-validator/pull/93) | `9617adb2582f958eb4341394471c6e9515415548` | `1c3350e0dd57` |
| [#30](https://github.com/raccioly/websec-validator/pull/30) | `27d6b4d17a0497d3e0d81fb197cffa6aafc573b4` | `f1d8ec278bab` |
| [#92](https://github.com/raccioly/websec-validator/pull/92) | `c3a52a19cf2d0cc0e55029619a88b9a762ada675` | `1c3350e0dd57` |
| [#53](https://github.com/raccioly/websec-validator/pull/53) | `2a729d0cdde8fa057ac0ecf0979fe8d047022d42` | `921addc8b632` |
| [#40](https://github.com/raccioly/websec-validator/pull/40) | `aeb82da038622719b3643f55ca437462fc09b9a4` | `921addc8b632` |
| [#34](https://github.com/raccioly/websec-validator/pull/34) | `3392b15c53a74534192d41840233f91a9d59a3b2` | `f1d8ec278bab` |
| [#100](https://github.com/raccioly/websec-validator/pull/100) | `83158d0d2d224275138f6e56bac69e6ca5dc724a` | Independently checked |
| [#97](https://github.com/raccioly/websec-validator/pull/97) | `9cb26fc1f29b00da15ea39d926fb38a82e786c0c` | Independently checked |
| [#76](https://github.com/raccioly/websec-validator/pull/76) | `0fe8cf95a8aee6ef961232a3bafa8de8508f6a9c` | Independently checked |
| [#57](https://github.com/raccioly/websec-validator/pull/57) | `0f3d9f6064267400da89f8dd172b51c9dccf24af` | Independently checked |
| [#50](https://github.com/raccioly/websec-validator/pull/50) | `236ebf8dd7e308d75db5e590042b5c2e2b2f3942` | Independently checked |
| [#17](https://github.com/raccioly/websec-validator/pull/17) | `71b41eb860f5f6ad5f7ce1326f2e2ec99d4181b0` | Independently checked |

Before any future integration, fetch/recompare the latest target and PR heads, preserve concurrent changes, resolve overlap deliberately, and rerun combined tests. An unchanged main does not make PRs based on older commits compatible with this working tree.

## Upload handling — #44 / #82

**Already covered:** generic `createReadStream`, object reads, local stream destinations, comments and unrelated headers no longer imply browser delivery or a protected browser response. `upload_security.py` now binds supported response operations and headers; `test_public_precision.py` has positive browser-response controls and safe local-read controls. #44's core intent is covered. Its extra hook-test change duplicates the existing global `core.hooksPath` isolation fix.

**Useful remaining evidence from #82:** current code emits `upload-key-from-filename` HIGH for a generated storage key when only a log template mentions the original filename:

```javascript
function upload(req) {
  const key = uuid();
  console.log(`Orig: ${req.file.originalname} -> ${key}`);
  s3.putObject({Key: key, Body: req.file.buffer});
}
```

Current code also emits `upload-accepts-svg` for an error string saying `image/svg+xml is unsupported`, and for an explicit rejection of that MIME type. An actual filename-derived key still produces the intended lead. Reuse the paired examples, but bind the key to its storage operation and SVG policy to a positive acceptance path. A substring/equality alone cannot distinguish rejection from acceptance. #82's arbitrary `.pipe(w)` receiver also lacks proof that `w` is a browser response.

Proposed bounded ownership: `extractors/upload_security.py` and new focused regression cases. Include generated key plus log, actual client-derived key, SVG rejection/allowance, and unsafe sibling handlers.

## PII response controls — #19 / #68

**Do not adopt the proposed blanket suppressions.** #19 credits names such as `sanitize`, `present`, `toJSON` and any nearby `.select`; #68 credits TypeScript `Omit`/`Pick`/`Exclude` and response variables named `ok`/`exists`. Names and type annotations do not establish what data reaches the response. TypeScript types are erased and do not change JavaScript runtime behavior. [TypeScript documentation](https://www.typescriptlang.org/docs/handbook/2/classes)

The current detector correctly retains a lead for `const dto: Omit<User,'email'|'phone'> = user; res.json(dto)`: the assignment still returns the original object. A supported explicit local projection, `const safe={id:user.id}; res.json(safe)`, produces no lead. Current response-bound checks preserve unsafe siblings instead of treating a file-wide helper as a sanitizer.

**Remaining precision candidates:** `const exists=true; res.json(exists)` in a file accepting an email still produces a raw-entity lead. Explicit rest destructuring that removes the only PII fields from a known local object also remains a lead. These justify small binding-aware boolean/projection improvements, with mutation/spread/alias and same-file unsafe controls. Do not accept arbitrary variables solely by name or arbitrary rest objects with unknown fields. #19 also adds an unrelated `CHANGELOG_UPDATE.txt`.

Proposed ownership: `extractors/pii_exposure.py`, paired tests extending response-scope coverage.

## SQL query construction — #95 / #45

**Already covered:** direct `db.execute(text(f'...{request.args["name"]}...'))` produces one SQL-injection occurrence, as does a direct interpolated query without `text`.

**Historical missed forms, corrected in the fourth phase:** assigning an interpolated Python query to `query` before `db.execute(text(query))`, or assigning `request.args['query']` before that sink, originally produced zero occurrences. Both now retain source/assignment provenance through the bounded Python analysis. Bound-parameter literal queries, unrelated debug interpolation and matched query/parameter tuple unpacking remain safe controls. Unknown later loop iterations are review gaps, not a claim of fixed-point analysis.

#95 treats any `text(variable)` as suspicious without tracking its origin. #45 connects SQL-looking interpolation to a later sink within 200 characters without binding the variable or function. Both can flag an unrelated or constant query. Prefer a bounded assignment/use analysis with request taint and explicit scope. `text()` supports bind parameters; it is neither automatically vulnerable nor an escaping operation for already interpolated SQL. [SQLAlchemy text documentation](https://docs.sqlalchemy.org/en/20/core/sqlelement.html#sqlalchemy.sql.expression.text)

Proposed ownership: `extractors/surface.py` plus the shared syntax helper only if needed, and dedicated assigned-query tests. Require positive assigned f-string/template and raw-request controls, safe bound parameters, reassignment, sibling functions and unrelated interpolation.

## Auth composition — #93

The current route report does not recognize `@app.get('/items', dependencies=[Depends(verify_admin)])` as a visible guard. The PR's FastAPI dependency examples are useful, but its test only searches the `GUARD` regex. FastAPI executes declared dependencies before a path operation; whether a dependency actually enforces auth still requires inspection. [FastAPI dependency decorators](https://fastapi.tiangolo.com/tutorial/dependencies/dependencies-in-path-operation-decorators/)

The proposed file-wide `protectedProcedure` / `privateProcedure` token is insufficient: tRPC base procedures are application-defined builders, and the protected behavior comes from attached middleware. [tRPC procedures](https://trpc.io/docs/server/procedures) Recognize an actual procedure/dependency binding and visible enforcement, with unknown external definitions reported as unverified. Imports, comments, names and protected siblings must not guard an unrelated route. This can extend current per-service and Fastify scope checks without weakening them.

Proposed ownership: `extractors/authz.py`, route support only where needed, endpoint-level positive and unsafe-sibling tests. This is a coverage candidate, not proof that the sample app is insecure.

## GitHub Actions and tool upgrades — #30 / #92 / #53

#30 and the pin-only part of #92 overlap the current composite Action hardening. The current Action uses the existing verified setup-python v6 SHA and a newer verified upload-SARIF v4 SHA. It also handles input arguments without shell interpolation, installs the trusted Action checkout, and publishes only the current attempt's artifacts; old pin-only PRs omit those fixes.

#92 additionally changes Docker scanner versions and repeats an existing hook-test fix. Treat container upgrades as a separate compatibility task; this review did not build containers or validate those scanner versions.

#53 proposes setup-python v7. Its workflow SHA corresponds to the official v7.0.0 release, but its composite Action uses floating `@v7`, losing the immutable pin. The release changes module packaging and removes an input; test supported runners and all call sites before adopting a consistent pinned upgrade. [Official v7 release](https://github.com/actions/setup-python/releases/tag/v7.0.0) Do not overwrite current Action security changes with a PR based on the old file.

## OpenAPI route inventory — #40 / #34

The route-source implementation in these two PRs is duplicated. Both recursively enumerate with `rglob`, then check skipped directories after traversal and read candidate files directly. That bypasses the new pruning, containment, private-path and read-budget policy. Malformed JSON falls into a simplistic YAML parser; broad exceptions hide failures. #40 also carries the already-fixed hook-test change.

Current `openapi.py` already performs bounded specification discovery/parsing and compares documented routes against source routes. `routes.py` excludes spec-derived Noir rows from source route evidence. Adding spec paths to the source route inventory would obscure undocumented/stale-route differences and could affect auth attribution. Reuse the bounded reader and keep a separately attributed **documented route candidate** inventory if that product need is confirmed. Add malformed/oversized/private/symlink controls and prove that a spec-only route is never labeled implemented or guarded.

## Crypto family — #100 / #97 / #76 / #57 / #50 / #17

Independent review grouped #100/#97/#57 around secret-header presence-check false positives. At review time, undefined/null/empty/typeof checks produced LOW leads, reversed comparisons could be missed, and a safe helper in a sibling scope could hide an unsafe comparison. The third-phase per-comparison implementation now handles supported null/empty/type checks, reversed operands and unsafe siblings. JavaScript `undefined` remains deliberately unverified because it can be shadowed; nonempty hardcoded credential comparisons remain leads. Triple f-string interpolation is covered, while ambiguous regex literals remain a stated lexical limitation.

Do not take #100/#97/#76's blanket quoted-right-hand-side exemption: hardcoded bearer credentials remain security-relevant comparisons. #57's narrower presence-only distinction is a better starting intent, still requiring operand and scope tests.

#76/#50/#17 broaden into hash purpose and JWT configuration. #76/#17's file-wide `options`/`config`/spread exemptions could hide an unrelated `jwt.verify(token, secret)` with no demonstrated algorithm restriction. #17's global pwned/reset/avatar/cache/redis exclusions could hide real credential or principal hashing when those words appear in a comment or sibling. #50 narrows hash arguments to simple names, losing nested `req.body.password`, bracket access and encoded password forms that current code detects. Its nearby-unrelated-password case and #17's Python reset-token case are already clear in current code.

Remaining current precision cases include hashing password-update metadata, an HIBP prefix, an avatar-only email and a cache-only user ID. Improve actual input/purpose binding, with mixed real credential uses in the same file. Preserve current scoped and PKCE behavior. Proposed ownership: `extractors/crypto_usage.py` plus dedicated comparison/hash/JWT paired regressions. None of these broad PRs is safe to apply as a whole based on this review.

## Next implementation priorities

1. Python assigned SQL flow is delivered; separately evaluate JavaScript assignment flow and unsupported interprocedural/loop cases with paired controls.
2. Correct upload key/SVG evidence and crypto comparison scope using the reproduced safe/unsafe pairs.
3. Improve response-value and framework guard binding incrementally; avoid broad name-based exemptions.

The later adoption slice now supplies current-envelope guidance, partial/provenance limits, preserved foreign instructions and inactive pre-commit/PR/weekly examples. It reuses the existing hooks/Action; nothing was activated automatically. This later implementation is separate from the original read-only PR review.

## Release consolidation of all 53 PRs

The [complete exact-head data](release-pr-triage.json) extends this selected-family review to all
53 open PRs. The [authoritative next-work specification](../../specs/001-continuous-security-improvement/spec.md)
contains every PR disposition and retained intent, including separate container/runner policy work.
At the pre-release audit snapshot, closures were pending release merge and live-head revalidation.
GitHub PR state records completion; none of the deferred gaps is claimed fixed by closing its draft.

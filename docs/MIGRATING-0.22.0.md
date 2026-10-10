# Migrating to 0.22.0

0.22.0 closes gaps where the tool reported success it had not earned: a subdirectory `--diff` or
`gate` run that passed everything, a `security/` directory that was never read, usage errors that
exited with the "findings" code. No new runtime dependency, no schema-major change, and no finding
that gated a `websec run` in 0.21.x stops gating it. Several runs that used to pass will now fail or report a gap —
that is the point of the release. Read the sections that match how you run websec.

## Exit codes now follow the documented contract everywhere

The contract has been `0` clean · `1` findings · `2` usage/configuration error · `3` incomplete since
0.17.0, but some paths did not follow it.

| Situation | 0.21.x | 0.22.0 |
|---|---|---|
| `run`/`recon`/`init`/`doctor`/`emit-context` target is not a directory | `1` | `2` |
| `dynamic` / `calibrate` argument errors (missing file, missing `--ledger`, …) | `1` | `2` |
| Malformed JSON passed to `--ingest`, `--ingest-dast`, `--ledger`, `dynamic --config` or `FACTS.json` | traceback, `1` | `2` with a message |
| `calibrate` fit that measured nothing (corpus not available) | `1` | `3` |
| `dynamic`: confirmed leak **and** inconclusive rows | `3` | `1` (definite fact wins), stderr note, `gate.failure_kind = findings+incomplete` |
| `dynamic`: every dynamic check passed but `FACTS.json` holds a static CRITICAL | `1` | `0` — `run` already gated it; counted in `gate.static_findings_not_gated` |
| `attest` with no published `latest` but some run attempts | silently projected the lexically last (possibly partial) attempt | `3`, asks for `--run` |
| `gate` outside a Git repository with no `--only` | `0` (checked nothing) | `3` — pass paths with `--only` |

**Action:** a CI step that treated any non-zero exit as "findings" is unaffected. A step that tested
`1` specifically now sees usage errors as `2`. A `dynamic` job that relied on static CRITICALs to fail
must gate on `websec run --fail-on critical` instead — which is where that gate belongs.

## Subdirectory scans now gate what changed

`websec run <subdir> --diff <base>` and `websec gate <subdir>` compared repository-root paths from Git
with target-relative finding paths, so every finding read as "untouched" and the gate passed.
Both now scope correctly from any subdirectory. A monorepo pipeline that scans one service per job
may start failing on findings it was always supposed to catch.

## `security/` directories are scanned

`security/` was on the walker's skip list (a leftover from guarding the tool's own early output
directory), so auth middleware and policy code under any `security/` directory was never read while
the run reported complete. It is now analysed; websec's own output directories are recognised by
their contents (a run directory or a `runs/` + `latest` store) instead of by name.

`build/`, `dist/`, `out/`, `target/`, `vendor/` and `coverage/` are still skipped, but analysable source
inside them is counted and reported as a `skipped_directory_code` coverage gap (non-execution) with
the directory names in `files.skipped_code_dirs`. Nothing fails because of it; it stops being silent.

**Action:** expect new findings in repositories with a `security/` directory. Triage them like any
first run; scope them with `.websec-ignore` only if that code is genuinely not your product.

## `.websec-ignore` path patterns match on path components

Path-like lines (containing `/`, a glob character or a `.ext`) now match whole path components of the
finding's path, with any `:line[:col]` suffix stripped. So `*.js` finally matches `src/file.js:13`, and
`/build/` anchors at the repository root. `category:` lines match the category exactly.

For this release nothing that was suppressed becomes unsuppressed: suppression is the union of the
new rule and the old substring rule. A finding hidden **only** by the old rule — `tests/` hiding
`contests/…`, or a bare word such as `test` hiding every title containing "test" — stays hidden, but:

- the run prints one stderr warning per such line, with the exact replacement to use;
- the ledger counts it in `suppressed_legacy_substring` and lists it in `suppressed_legacy[]` and
  `suppression_warnings[]`.

**Action:** run once, read the warnings, and replace each flagged line with the suggested pattern or
`category:` line. The legacy substring rule is a transition aid and may be removed in a future release.

Note that scanner findings are categorised `static-secret`, `static-sca`, `static-sast` and
`static-iac`; a `category:secret` line matches nothing.

## Fewer false "incomplete" runs

Several field-reported causes of exit `3` on healthy repositories are fixed: Checkov parse errors
from excluded paths, Semgrep partial parses of valid shell scripts, and the JavaScript source-flow
lane abandoning ordinary modules. Per-file analysis limits are now reported as named gaps
(`scanner_file_limits`, `source_flow_limit`) rather than as a failed tool. A `source_flow_limit`
still makes the run incomplete, because that file was not fully analysed. If you had added
`--exclude` entries or relaxed `--require-complete` to work around these, you can revert that.

`.websec-ignore` remains a findings filter; it does not change what scanners read. Use `--exclude`
to keep a directory away from the scanners.

## Other visible changes

- `websec emit-context` marks the route count as a floor and the auth scheme as an inference when
  route discovery is likely incomplete, and no longer reports `jwt (bearer)` without JWT evidence.
- `websec init` warns on directory globs and, given a prior ledger, proposes expiring
  `fingerprint:` acknowledgements for test-fixture secrets.

- `--only` accepts directories (component boundary: `src` does not select `src2/`). An entry that
  selects nothing becomes a `scope_missed` gap, and a run that analysed nothing in its requested scope
  prints **REQUESTED SCOPE NOT ANALYZED** instead of "REQUESTED CHECKS COMPLETED".
- An explicit `--graph` path that does not exist is an execution gap (`not found`). Graphs have their
  own 64 MiB read cap, so multi-megabyte graphify graphs now enrich findings instead of being
  rejected by the 2 MB source cap.
- A failing OWASP Noir is no longer reported as an absent one: the run says
  `OWASP Noir failed: <reason>`, records `routes.noir` and a `route_engine` gap, and `websec doctor`
  has a route-engine section.
- Brakeman is selected only when the scan root has an `app/` directory (Brakeman's own precondition);
  otherwise `doctor` lists it as not applicable, instead of the run recording a Brakeman error.
- The GitHub Action exposes an `exit-code` output.
- `websec feedback --file-extension` accepts `.ex`, `ex` or a filename, and refuses a value it cannot
  turn into an extension instead of recording an empty one.

## See also

- [Upgrading](upgrade.md) · [CHANGELOG](../CHANGELOG.md)
- [CLI reference: exit codes](reference/cli.md#exit-codes)
- [Triage and suppression](guides/triage-and-suppression.md)

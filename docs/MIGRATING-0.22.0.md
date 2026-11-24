# Migrating to 0.22.0

0.22.0 closes gaps where the tool reported success that it had not earned. Three examples: a subdirectory `--diff` or
`gate` run that passed everything, a `security/` directory that websec never read, and usage errors that
exited with the "findings" code. The release adds no new runtime dependency and no schema-major change. No finding
that gated a `websec run` in 0.21.x stops gating it. Several runs that used to pass now fail or report a gap.
That is the point of the release. Read the sections that match how you run websec.

## Exit codes now follow the documented contract everywhere

The contract has been `0` clean · `1` findings · `2` usage/configuration error · `3` incomplete since
0.17.0. Some paths did not follow it.

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
must gate on `websec run --fail-on critical` instead. That is where this gate belongs.

## Subdirectory scans now gate what changed

`websec run <subdir> --diff <base>` and `websec gate <subdir>` compared repository-root paths from Git
with target-relative finding paths. Every finding read as "untouched", and the gate passed.
Both commands now set the scope correctly from any subdirectory. A monorepo pipeline that checks one service per job
can start to fail on findings that it was always meant to catch.

## `security/` directories are scanned

`security/` was on the walker's skip list (a leftover from guarding the tool's own early output
directory). The run reported complete, but websec never read the auth middleware and policy code under any `security/` directory.
websec now analyzes `security/`. It recognizes its own output directories by
their contents (a run directory or a `runs/` + `latest` store) instead of by name.

websec still skips `build/`, `dist/`, `out/`, `target/`, `vendor/` and `coverage/`. It now counts analyzable source
inside them and reports it as a `skipped_directory_code` coverage gap (non-execution), with
the directory names in `files.skipped_code_dirs`. Nothing fails because of this gap. It is no longer silent.

**Action:** expect new findings in repositories that have a `security/` directory. Triage them like any
first run. Use `.websec-ignore` to scope them only if that code is not part of your product.

## `.websec-ignore` path patterns match on path components

Path-like lines (lines that contain `/`, a glob character or a `.ext`) now match whole path components of the
finding's path, with any `:line[:col]` suffix removed. So `*.js` now matches `src/file.js:13`, and
`/build/` anchors at the repository root. `category:` lines match the category exactly.

In this release, nothing that was suppressed becomes unsuppressed. Suppression is the union of the
new rule and the old substring rule. The old rule alone can hide a finding, as when `tests/` hides
`contests/…`, or a bare word such as `test` hides every title that contains "test". Such a finding stays hidden, and:

- the run prints one stderr warning for each such line, with the exact replacement to use;
- the ledger counts it in `suppressed_legacy_substring` and lists it in `suppressed_legacy[]` and
  `suppression_warnings[]`.

**Action:** run once, read the warnings, and replace each flagged line with the suggested pattern or
`category:` line. The legacy substring rule helps the transition. A future release may remove it.

Scanner findings use the categories `static-secret`, `static-sca`, `static-sast` and
`static-iac`. A `category:secret` line matches nothing.

## Fewer false "incomplete" runs

Users reported several causes of exit `3` on healthy repositories. This release fixes them: Checkov parse errors
from excluded paths, Semgrep partial parses of valid shell scripts, and the JavaScript source-flow
lane that abandoned ordinary modules. websec now reports per-file analysis limits as named gaps
(`scanner_file_limits`, `source_flow_limit`), not as a failed tool. A `source_flow_limit`
still makes the run incomplete, because websec did not fully analyze that file. If you added
`--exclude` entries or relaxed `--require-complete` to work around these causes, you can revert that.

`.websec-ignore` is still a findings filter. It does not change what scanners read. Use `--exclude`
to keep a directory away from the scanners.

## Other visible changes

- `websec emit-context` marks the route count as a floor and the auth scheme as an inference when
  route discovery is likely incomplete. It no longer reports `jwt (bearer)` without JWT evidence.
- `websec init` warns on directory globs. Given a prior ledger, it proposes expiring
  `fingerprint:` acknowledgements for test-fixture secrets.

- `--only` accepts directories (component boundary: `src` does not select `src2/`). An entry that
  selects nothing becomes a `scope_missed` gap. A run that analyzed nothing in its requested scope
  prints **REQUESTED SCOPE NOT ANALYZED**, not "REQUESTED CHECKS COMPLETED".
- An explicit `--graph` path that does not exist is an execution gap (`not found`). Graphs have their
  own 64 MiB read cap. Multi-megabyte graphify graphs now enrich findings, and the 2 MB source cap no longer
  rejects them.
- websec no longer reports a failing OWASP Noir as an absent one. The run says
  `OWASP Noir failed: <reason>` and records `routes.noir` and a `route_engine` gap. `websec doctor`
  has a route-engine section.
- websec selects Brakeman only when the root of the target has an `app/` directory (Brakeman's own precondition).
  Otherwise `doctor` lists Brakeman as not applicable, and the run does not record a Brakeman error.
- The GitHub Action exposes an `exit-code` output.
- `websec feedback --file-extension` accepts `.ex`, `ex` or a filename. It refuses a value that it cannot
  turn into an extension, and does not record an empty one.

## See also

- [Upgrading](upgrade.md) · [CHANGELOG](../CHANGELOG.md)
- [CLI reference: exit codes](reference/cli.md#exit-codes)
- [Triage and suppression](guides/triage-and-suppression.md)

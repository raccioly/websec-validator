# Triage and suppression

This guide explains how to work through a websec report: how to read clusters and priority
signals, and how to scope out, acknowledge or report findings without hiding anything a real leak
would need. It is the reference for the `.websec-ignore` file, `--exclude`, fixture auto-scoping,
baselines, `websec feedback` and `websec explain`.

One rule runs through all of it: **nothing disappears silently.** Every suppression is either
counted, kept visible with its reason, or recorded in the coverage manifest.

## The four outcomes

For every finding (or cluster of findings), pick one:

| Outcome | Mechanism | Finding afterwards |
|---|---|---|
| Real issue: fix it | change the code, re-run | `no-longer-observed` against a baseline (not proof of repair) |
| Not your product | path or `category:` line in `.websec-ignore`, or `--exclude` | dropped from the ledger and counted in `suppressed`, or never analysed (`--exclude`) |
| Reviewed false positive or accepted risk | `fingerprint:<fp> expires:<date>  # reason` in `.websec-ignore` | kept, shown as acknowledged, not gating until it expires |
| The detector is wrong | `websec feedback` (in addition to one of the above) | unchanged. Feedback never suppresses. |

## Read the report before you suppress anything

### One issue, N sites: clusters

The ledger carries a `clusters[]` list, and REPORT.md renders it as **§1a Clustered view**, which
groups findings two ways:

- **rule**: the same detector firing at several sites. One pattern, one fix, several places to
  apply it.
- **incident**: secrets whose files were removed from the working tree in the same commit. One
  deletion, one remediation (rotate), however many blobs it left behind.

Single-site groups are omitted. Each cluster takes the worst severity and confidence of its
members, lists every site with its own `fingerprint`, and carries a `gating_note`. The console and
`cluster_summary` report `distinct_issues` alongside the total.

Clusters are a **view, not a filter**. `total`, `--fail-on` counts, per-site fingerprints, SARIF
results and baselines are all unchanged, so every site still gates on its own. You acknowledge
sites, not clusters.

### Secrets say where they live

Every Gitleaks finding carries `in_tree`. A finding whose file is gone from the working tree is
labelled `in-tree: false`, marked `history_only`, and names the commit it was last seen in.
Deleting a file does not un-leak it, because the blob stays fetchable from the repository. The
remediation is to **rotate** the credential, and the report says so.

### Priority signals

All of these are additive. They annotate a finding but never change its severity, drop it or add
one, so they cannot reintroduce a false positive.

| Field | What it tells you |
|---|---|
| `severity` | How bad the finding is if real. The gate uses this field. |
| `calibrated` | Measured `P(real)` for this attack class and confidence, with a 95% interval and sample size `n`. Read the interval, not the point estimate. |
| `triage.disposition` | `agent-fixable` (local change with a mechanical verification) or `human-required`, with a per-class reason. Nothing gates on it. |
| `likely_filtered`, `filter_reason` | Classes a downstream reviewer would routinely drop (for example ReDoS, a bare open redirect, a missing rate limit). Tagged, never dropped. |
| `reachability` (dependency CVEs, `--scan`) | `imported`: an import of the package was found in first-party source. `no-import-found`: the title says "declared-only"; likely unreachable, verify. `n/a`: ecosystems whose imports are not parsed (Go, Rust and others), so no claim. Name-based, not a call graph. |
| `epss`, `epss_pct`, `kev` (`--scan`) | FIRST.org EPSS exploit probability and CISA KEV membership, joined from a local cache. Absent when no local snapshot exists; `websec intel refresh` downloads one (public feeds only, no project data sent). |

`--scan` runs both Trivy and OSV-Scanner when installed. The same CVE from both collapses to one
row with `tools: [osv-scanner, trivy]`.

To learn what a class means and how to confirm or refute it, offline:

```bash
websec explain bola
websec explain CWE-918
websec explain --list          # every attack class this build cites
```

## Scoping tools

### Fixture auto-scoping (on by default)

Test, example and fixture code is split away from your attack surface without being hidden:

- Fixture routes go to `FACTS.json` → `fixture_endpoints`. They are counted in the console and not
  probed.
- Under `--scan`, secrets that scanners find in test files are **demoted to LOW and annotated**,
  never dropped, because a real key pasted into a test is still a committed leak.
- Fixture package manifests do not drive framework detection, so a CLI that vendors an Express demo
  is not read as an Express app.

Recon findings inside test directories (for example a hard-coded fallback signing secret in
`tests/fixtures/`) are **not** demoted. Scope them explicitly if they are not your product. Pass
`--include-fixtures` to treat all fixture code as product code.

When most of a run's findings sit in test or example code and no `.websec-ignore` exists, websec
prints a one-line pointer to the suppression mechanism. It never edits your repository for you.

### `--exclude`

```bash
websec run . --exclude 'tests/**' --exclude 'examples/**'
```

`--exclude` (repeatable) removes a path from **both** recon and the static scanners (Gitleaks,
Trivy, Semgrep, Checkov, OSV-Scanner). Excluded files are never read. They are counted as
`excluded` in the coverage record, and the patterns are listed in `coverage.json` under
`files.excludes`. A pattern matches when it is a substring of the repository-relative path or a
glob that matches it. Use `--exclude` for content you never want read, such as generated code. Use
`.websec-ignore` for committed, reviewable policy.

### `websec init`

```bash
websec init --dry-run   # print the proposal; write nothing
websec init             # write .websec-ignore
websec init --force     # replace an existing file (it may hold reviewed acknowledgements)
```

`init` proposes conventional non-product directories (tests, fixtures, seed data, examples,
load-test harnesses, `third_party` and similar) that exist in your tree and hold files, each with
its file count. It also reports how much of the analysed surface the proposal covers. It refuses to
overwrite an existing `.websec-ignore` without `--force` (exit `2`). Directories the walker already
skips, such as `vendor` and `node_modules`, are not proposed.

## `.websec-ignore` reference

### Location

`.websec-ignore` is read from the **scanned target directory**, not the current working directory.
`websec run services/api` reads `services/api/.websec-ignore`, not the repository root's file. The
file is read under the same contained read policy as source, up to 64 KiB. A policy file that cannot
be fully read makes the requested execution incomplete and is recorded in `coverage.json` →
`review_policy`.

### Line kinds

`#` starts a comment that runs to the end of the line. Blank lines are ignored.

```text
# 1. Path patterns: DROP matching findings (this is not your product)
tests/
examples/**

# 2. Category: DROP every finding in a category (blunt; prefer paths)
category:graphql

# 3. Fingerprint acknowledgement: KEEP the finding, shown but not gating, until it expires
fingerprint:b9c7f23e49bdab85 expires:2026-12-31  # confirmed FP: the scanner's own detection pattern
```

| Line | Effect | Reason kept? |
|---|---|---|
| `<pattern>` | Matching findings are removed from the ledger. The number removed is reported as `suppressed`. | No. The comment is discarded. |
| `category:<name>` | Every finding whose `category` equals `<name>` exactly is removed. Copy the name from the ledger's `category` field: scanner findings are `static-secret`, `static-sca`, `static-sast` or `static-iac`; recon findings use names such as `supply-chain` or `graphql`. `category:secret` matches nothing. | No |
| `fingerprint:<fp> [expires:YYYY-MM-DD]  # reason` | The finding stays in the ledger under `acknowledged`, in REPORT.md §1b *Acknowledged (shown, not gating)*, and in SARIF as a suppressed result. It is excluded from the gating total. | Yes, and required |

This repository's own [.websec-ignore](../../.websec-ignore) is a worked example of path and
category scoping for a security tool whose source contains the patterns it detects.

### How path patterns match

Since 0.22.0, path patterns match on whole path components, close to `.gitignore`. Matching is
case-insensitive. A line is a **path pattern** when it contains `/`, a glob character (`*`, `?`,
`[`) or ends in a file extension such as `.js`. It is compared against every path the finding
names: its file, any `(path)` inside its location (recon findings write `VITE_KEY  (src/app.ts)`),
and the location itself with `:line[:col]` and a leading `./` removed.

- A leading `/` anchors the pattern at the scanned target's root.
- Without a leading `/`, the pattern matches at any depth, **even when it has a slash in the
  middle**. This is a deliberate difference from `.gitignore`. A leading `**/` means the same.
- A trailing `/` matches directories only. A matched directory hides everything beneath it.
- Globs use `fnmatch` on component-aligned sub-paths, so `*` can still cross `/`.

Any other line is a **bare word**, which keeps the old behaviour: a substring of the finding's
category, location or title.

The table shows what the new rule matches. Where it is narrower than the old rule, the difference
is still suppressed in this release, with a warning (see below).

| Pattern | Behaviour |
|---|---|
| `services/api/` | everything under that directory, at any depth |
| `services/api/**` | same, as a glob |
| `services/api/*.js` | matches `services/api/src/routes.js:13` (`*` crosses `/`; the `:13` is stripped first) |
| `/tests/` | only the top-level `tests/`, not `a/tests/` |
| `api/routes.js` | matches `services/api/routes.js`; a middle slash does not anchor |
| `tests/` | `tests/x.py` and `a/tests/x.py`, but not `contests/x.py`. In this release `contests/…` is **still suppressed** by the legacy rule, with a warning |
| `ssrf` | a bare word: any finding with "ssrf" in its category, location or title. Bare words are dangerous. |
| `!tests/fixtures/` | no negation. The line does not un-suppress anything. |

**Legacy matching during the transition.** So that upgrading never silently
un-suppresses a finding, a finding is still hidden when either the new rule or the old one (a
substring of category, location or title, or an `fnmatch` glob of the raw location) matches. A
finding hidden **only** by the old rule is surfaced:

- stderr prints one warning per `.websec-ignore` line, with how many findings it hid that way, up to
  three examples, and the exact replacement line, for example:

  ```text
  websec: .websec-ignore line 'tests/' hid 1 finding(s) only by legacy substring matching (path patterns now match whole path components, not substrings; e.g. contests/x.py:3). They stay suppressed in this release; to keep hiding exactly these, use: /contests/x.py
  ```

- the ledger counts them in `suppressed_legacy_substring`, lists them in `suppressed_legacy[]`
  (each with `suppression.legacy_substring: true`, at most 200 records), and groups them per line in
  `suppression_warnings[]` (`pattern`, `pattern_kind`, `hidden`, `replacement`, `examples`).

```bash
jq '.suppression_warnings[] | {pattern, hidden, replacement}' websec-out/latest/findings-ledger.json
```

If the warning names something you did mean to hide, add the replacement line. If not, the warning
has just shown you a finding your policy was hiding by accident.

Path and category suppressions apply to findings, not to recon. Routes and other facts in suppressed
paths still appear in `FACTS.json`. Use `--exclude` to stop a path being read at all.

### Acknowledgement states

Each `fingerprint:` line is parsed into a state. Only two states excuse a finding:

| State | When | Excuses the finding? |
|---|---|---|
| `active` | `expires:` date is today or later, reason present | yes, through the whole expiry day |
| `legacy-no-expiry` | no `expires:` token, reason present | yes, indefinitely. Prefer a date. |
| `expired` | expiry date has passed | no. The finding gates again with a `reopened_reason`. |
| `malformed` | anything other than exactly one `expires:YYYY-MM-DD` token after the fingerprint | no |
| `missing-reason` | nothing after `#` | no |

If the same fingerprint appears twice, the later line wins. Every entry, including the ones that
excuse nothing, is recorded in the ledger's `acknowledgement_history`:

```bash
jq '.acknowledgement_history[] | {fingerprint, state, expires, reason}' \
  websec-out/latest/findings-ledger.json
```

To export reviewed acknowledgements for an auditor as a claimspec v1 `ignore` document:

```bash
websec init --claimspec websec-acks.json     # or `-` for stdout
```

Path and category lines carry no reason, so they are omitted and counted rather than exported with
an invented one. The command prints whether the export is the complete policy.

### Where suppressed findings go

- **Path and category lines** remove the finding body from the ledger. What survives is the count
  (`suppressed` in the ledger, `N suppressed` in the console) and the policy file's source and
  content digest in `coverage.json` → `review_policy`. Use them for code that is genuinely not your
  product. A path line also hides findings in that path that do not exist yet.
- **Fingerprint acknowledgements** keep the full finding, its reason and its expiry. This is the
  right home for "this specific finding is a confirmed false positive".

## Fingerprints

A fingerprint is a 16-hex-character semantic identity built from the finding's attack class,
category, location (with any line number removed) and structured identifiers such as rule, package,
CVE, resource or sink. Title, severity and threat intelligence are excluded, so a fingerprint
survives line moves and title rewording. Older fingerprints are kept as `fingerprint_aliases`, and an
alias shared by several current findings is treated as ambiguous rather than allowed to hide them.

Find fingerprints in the ledger, or in each cluster's `sites` list:

```bash
jq -r '.findings[] | "\(.fingerprint)  \(.severity)  \(.location)  \(.title)"' \
  websec-out/latest/findings-ledger.json
```

## Baselines

`--baseline <prior findings-ledger.json>` compares the current run with an earlier ledger and labels
each finding:

| State | Meaning | Counts toward `--fail-on`? |
|---|---|---|
| `new` | not in the baseline | yes |
| `changed` | in the baseline, but severity went up or the CVE is newly in CISA KEV | yes |
| `reopened` | was acknowledged and is no longer, for example because the acknowledgement expired | yes |
| `unchanged` | same finding as before | no |
| `no-longer-observed` | in the baseline, absent now | n/a. Absence is not proof of repair. |

Acknowledged findings in the current run still count as observed, so they are never reported as
gone. A malformed or unreadable baseline makes the requested execution incomplete (exit `3`).

Local pre-push hooks keep their own accepted baseline under `.git/websec-guardrail/`. Only a
successful gate advances it. Advisory and failed runs never do.

## Reporting a wrong detector: `websec feedback`

`.websec-ignore` answers "stop showing me this here". `websec feedback` answers "this detector is
wrong and upstream should know". The two never write to each other.

```bash
# not a real issue
websec feedback --fingerprint <fp> --verdict false-positive \
  --reason "behind an nginx auth_request"

# real, but misrated
websec feedback --fingerprint <fp> --verdict severity-wrong \
  --expected-severity LOW --reason "only reachable from the admin VPN"

# something websec missed (no fingerprint)
websec feedback --verdict false-negative --attack-class ssrf \
  --file-extension user_controller.ex --reason "Req.get on a request param in an Elixir controller"
```

`--file-extension` accepts an extension (`.ex` or `ex`) or a file name such as
`user_controller.ex`, and keeps only the extension. A value from which no extension can be derived
is refused with exit `2` rather than recorded empty.

- **Offline.** Nothing is sent. The command appends a record to `feedback.jsonl` in the output
  directory (`websec-out/` by default, or `--out`) and prints a prefilled GitHub issue URL that you
  may open yourself.
- **Metadata-only by default.** The record carries classification and identity (attack class,
  category, rule, severity, confidence, fingerprint, standards, calibration, file extension). It
  carries no path, route, title or evidence. `--include-snippet` adds title, location, file, method
  and evidence. It shows you the exact record and asks before writing, and needs `--yes` when stdin
  is not a terminal.
- **Reads the latest ledger** (`websec-out/latest/findings-ledger.json`) unless you pass `--ledger`.
- **False positives become calibration candidates, not labels.** A `false-positive` verdict queues
  a pending candidate in your user-level calibration overlay (under `~/.cache/websec-validator/`
  unless `WEBSEC_CALIBRATION_HOME` is set). No probability changes until a reviewer promotes it:

  ```bash
  websec calibrate --review
  websec calibrate --accept <candidate-id> --reason "<why it is wrong>"
  websec calibrate --reject <candidate-id>
  ```

- **It does not suppress.** To silence the finding locally as well, add a `fingerprint:` line.

## In the agent loop

`websec gate` applies `.websec-ignore` exactly as `run` does. Path and category lines drop findings,
active acknowledgements move findings to `acknowledged`, and expired, malformed or reasonless
acknowledgements excuse nothing. A finding attributed to a repository file outside the requested
scope is reported under `outside_scope` and does not block. A finding that names no file still
blocks. See [AI agents](ai-agents.md).

## See also

- [Adopting websec in an existing project](existing-projects.md): where triage fits in a rollout.
- [Outputs reference](../reference/outputs.md): every ledger and coverage field.
- [Configuration reference](../reference/configuration.md): environment variables and files.
- [Methodology](../METHODOLOGY.md#layer-3--the-findings-ledger): how findings and confidence are built.

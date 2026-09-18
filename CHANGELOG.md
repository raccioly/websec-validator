# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `websec demo` scans a bundled sample app and summarises what it finds, so the output
  can be seen before pointing the tool at anything you care about. It is a real run
  through the same recon and ledger code as `websec run`, not a recorded transcript, and
  it writes only inside a temporary directory that it removes afterwards.

  The sample ships as `.txt` so nothing imports, lints or executes it, and it deliberately
  carries no credential-shaped strings — a planted fake credential inside an installed
  package gets flagged by other people's scanners pointed at site-packages. It plants
  injection and missing-auth classes instead. An empty result is reported as a detector
  bug and exits 1; it must never read as a clean bill of health.


### Added

- `websec explain <attack-class|CWE-id>` answers offline what a finding class means, what
  would confirm or refute it in your code, the remediation pattern, and whether a
  calibrated cell actually exists for it. A ledger entry names a class and cites a CWE but
  carries none of that, so an agent either trusts every lead or none. Resolves all 73
  shipped classes and by CWE id, refuses an ambiguous CWE rather than guessing, and
  suggests near matches for a typo. `--list` enumerates the classes. Built from the
  shipped STANDARDS/REMEDIATION/calibration data, so there is no second source of truth.
- `websec feedback --verdict false-negative --attack-class <class>` reports something the
  tool missed. It takes no fingerprint and reads no ledger — the report is that nothing was
  produced, so requiring the findings artifact would gate it on the very thing that is
  absent. Metadata-only by construction; a supplied filename contributes only its suffix.


### Fixed

- The test suite is now hermetic against a developer's global gitignore. Seven fixtures
  pinned `user.email`, `commit.gpgsign`, `core.autocrlf` and `core.hooksPath` but not
  `core.excludesFile`, so a global ignore listing `__pycache__/` hid untracked paths from
  `git status --porcelain` inside the fixture repo — one test passed locally and failed on
  CI for exactly that reason. The `hermeticity (hostile git config)` job now also
  manufactures a global gitignore, so the whole class is detectable rather than relying on
  a developer happening to have one.


### Added

- `websec doctor` now reports where the running engine came from, not just its version.
  A stale wheel installed from `/tmp`, an editable checkout, a source tree and a clean
  index install all print the same `__version__`, so a review can cite a version that
  never matched the code that produced it. Classification uses PEP 610 `direct_url.json`
  plus the metadata directory and makes no network call, so it works in the offline core
  pass. Anything that did not come from an index is flagged, and importing code from
  outside the installed distribution is called out separately.

  This exists because a `pipx` install pinned to `file:///tmp/websec_validator-0.14.0-py3-none-any.whl`
  stayed two releases behind while `pipx upgrade` reported "already at latest" — upgrade
  re-resolved the same file rather than the index, and nothing in the tool's own output
  disclosed that the engine was not from PyPI.


## [0.15.2] — 2026-09-18

Migration: **none required.** Two commands that exited 0 without doing their work now exit 2.

### Fixed

- A mistyped or unavailable subcommand no longer exits 0. `websec <word>` falls back to
  `run <word>` for point-and-go, but the fallback was unconditional, so any unknown word
  became a scan target: `websec gate --help` on a build without `gate` printed `run`'s help
  and exited 0, making a missing command indistinguishable from a present one. The fallback
  now requires the argument to be an existing path, and otherwise exits 2 with a near-match
  suggestion. `websec <existing-path>` is unchanged.
- `websec gate` no longer reports a pass when it could not determine what to analyse. If
  `git status` failed — timeout, `index.lock` contention, non-zero exit — the changed-file
  set came back empty and labelled `working-tree`, which is exactly what a genuinely clean
  tree returns, so the gate passed having analysed nothing. That state is now
  `working-tree-unavailable` and exits 2. A genuinely clean tree still passes.


## [0.15.1] — 2026-09-18

Migration: **none required.** No schema, contract or CLI surface changes.

### Changed

- The CI test floor is now derived from the base commit instead of stored as `MIN_TESTS`.
  A stored floor was a shared counter that every branch adding tests had to edit, so two
  branches adding the same number of tests bumped it identically and merged cleanly while
  being jointly wrong — which happened, leaving the floor two below the real suite with no
  conflict and no error. `.github/scripts/test_floor.py` counts the base commit's suite in a
  throwaway worktree and compares, so there is no number for two branches to disagree about.
  A deliberate removal is still allowed via a `Test-Removal: <reason>` commit trailer, which
  keeps the reason in the history. Discovery errors are a hard failure rather than a count,
  because an unimportable module collapses to a single `_FailedTest` and would otherwise
  understate a whole file.


### Fixed

- Calibration no longer claims corpus provenance it does not have. When no shipped
  `calibration.json` is available and the table is built only from the operator's own confirmed
  local samples, the caveat attached to every finding previously read "calibrated on a
  deliberately-vulnerable app corpus; skews optimistic on clean production code" — a provenance
  and a bias direction that describe the shipped corpus, not local data. That path now carries its
  own label plus `corpus: []` and `shipped_table: false`. Tables built from a shipped corpus are
  unchanged, including the personalization suffix when local samples are folded in.

- The Docker image builds again. `ARG TRIVY_VERSION` pinned 0.58.1, whose GitHub Release and
  assets have since been deleted upstream; the installer downloads release assets, so the build
  failed at that step. Pinned to 0.74.0, the current release. The git tag for 0.58.1 still
  resolves, which is why this looks fine until the asset fetch runs.


## [0.15.0] — 2026-09-16

Migration: **none required — every change is additive.** The ledger gains optional `attribution`
and `gate` objects, findings gain an optional `scan_mode`, facts gain an optional `analysis_scope`,
and `manifest.json` gains `artifact_digests`. No field was removed or made required and the envelope
stays at schema 2.0, so an existing consumer keeps working unchanged.

Security note: `--network` adds a new, opt-in, third-party egress path. It is off by default, sends
bare package names only, and suppresses names this repository publishes before any request. See
[SECURITY.md](docs-canonical/SECURITY.md#dependency-existence---network).

Not re-run for this release: the vuln-app corpus proof. The historical 10/10 result belongs to an
earlier detector revision and is not renewed by this version.

### Added

- `websec feedback` records an operator verdict that a detector is wrong — `false-positive` or
  `severity-wrong` — against a finding's fingerprint, appends it to `websec-out/feedback.jsonl`
  and prints a prefilled issue link. It is offline: the link is text, nothing is sent or opened.
  Records are **metadata-only** by default (stable identity, classification, calibration
  provenance, standards citations, file extension); titles, routes, paths and evidence prose are
  withheld because a finding can point at a secret. `--include-snippet` opts in, marks the record
  `with-context`, shows it before writing, and refuses without `--yes` outside a terminal.
  Feedback never suppresses — `.websec-ignore` remains the way to silence a finding locally.

### Added

- **`websec attest` projects an existing run into a per-control audit-evidence table.** It computes
  nothing: it reads the artifacts a run already wrote and reports which audit-relevant facts websec
  holds and which it does not. **Gaps are listed before evidence** in both the data and the
  rendering, because a table that leads with coverage invites absence to read as satisfaction; on a
  typical run 5 of 12 rows have no websec evidence at all, and the output says so plainly. Formats:
  human-readable, JSON, and an **unsigned in-toto Statement** — unsigned by design, because a
  websec-signed attestation would attest only that websec ran, whereas one signed with the
  organisation's own key and identity is verifiable.
  It renders no verdict, score, percentage or badge, and the word "compliant" appears in no output
  format; a test enforces that. Compliance is an attribute of an assessed entity determined by a
  qualified assessor, not a property a tool can confer. Approver independence, rollback and PCI
  6.4.2 runtime protection are declared non-goals **in the artifact**, and the output states that
  the local gate is bypassable and its bypass record is not exhaustive.
  Citations are exact and tested, because the obvious ones are wrong: EU DORA change management is
  Commission Delegated Regulation (EU) 2024/1774 Art. 17 (the RTS under DORA Art. 9(4)(e)), not
  DORA Art. 17, which is incident management; there is no SOX article for ITGC, whose domains come
  from SEC Release 33-8810 §II.A.2.d; and PCI DSS 6.2.3 permits automated review while 6.2.3.1 is
  conditional on choosing manual review, so websec is deliberately not offered against it.
- **`websec run --network` verifies that declared dependencies actually EXIST** — the AI
  slopsquat / hallucinated-dependency class, which no offline check can reach. Opt-in, like
  `--verify-secrets`: it sends bare package **names** — never versions, paths or repository
  identity — to `registry.npmjs.org` and `pypi.org` via HEAD requests that transfer zero body
  bytes, under the same host allowlist, redirect re-validation and bounded-read rules as the
  threat-feed refresh. 52 real dependencies resolve in ~2.8s at 8 workers and 20 requests/second.
  `--network-dry-run` prints the exact list and sends nothing.
  **Suppression happens offline, before any request**, because a private name that reaches a public
  registry cannot be un-sent — and a 404 on an internal name tells an attacker exactly which name
  to squat, so the check could otherwise create the dependency-confusion opportunity it exists to
  find. Names this repository publishes (resolved through the real workspace graph, not a
  spec-prefix guess), scopes bound to a private registry by `.npmrc`/`.yarnrc.yml`, and pip
  `index-url` overrides are all subtracted first. Verified on the monorepo where the naive version
  had a **100% false-positive rate**: the private `@repo/cdk-lib` — declared `"*"`, not
  `workspace:*`, so the existing prefix filter could not catch it — is now suppressed offline, and
  52 of 52 remaining names resolve with **0 false positives**.
  A 404 is split using offline lockfile evidence: a `resolved` URL plus an `integrity` hash proves
  the name once published, so it is reported as `dependency-unpublished-or-removed` — packages
  pulled for malware look exactly like this — rather than `dependency-nonexistent`. Different
  cause, different remediation.
  Findings are ledger-bound at MEDIUM severity and LOW confidence and are **not `--fail-on`
  eligible** unless `--fail-on-network` is given as a second, explicit decision: the UNKNOWN rate is
  non-deterministic and outside operator control (measured 0%, 0%, 0% and 4.5% across four
  identical runs), so gating would make registry availability a dependency of shipping. UNKNOWN is
  neither clean nor missing — it records a coverage gap and makes execution incomplete. Every
  result states that **a 200 is not evidence of safety**: a squatter who has already registered a
  hallucinated name also returns 200, which is the successful attack rather than the clean case.
- **`websec hooks install --agent` puts the gate inside the agent loop.** A `PostToolUse` hook on
  `Write|Edit|MultiEdit` runs `websec gate` on the file just written and exits 2 on a blocking
  finding, which stops the loop and shows the finding and its remediation to the model as a retry
  signal. Measured at 0.30s to block, 0.15s for an edit no detector reads. It is `PostToolUse` and
  not `PreToolUse` because at `PreToolUse` the file does not exist yet, so there is nothing to scan.
  The hook runs the gate **in-process**: as a subprocess, an exit code of 1 for "module not found"
  was indistinguishable from the gate's exit 1 for "blocking findings", so a broken check read as a
  finding. It **fails open, loudly** — a check that blocks every edit when broken gets uninstalled —
  and it deliberately does **not** honour `WEBSEC_SKIP_HOOK`, because the agent can set an
  environment variable. Installation is a structural merge into `.claude/settings.json` that
  preserves your own settings and hooks, is idempotent, and refuses to overwrite a settings file it
  cannot parse. The plugin ships `hooks/hooks.json` and a `websec-agent-hook` console script,
  verified from an isolated built wheel in a clean virtualenv. **This is developer ergonomics, not
  a compliance control**: settings files are editable, so only managed policy settings are
  unbypassable, and the install output says so.
- **`websec gate` — a fast scoped pass/fail for inside the agent loop.** Measured at **0.3s** on a
  one-file change. It analyses the files you just changed and exits 0 (pass) or 1 (blocking
  findings), with 2 reserved for a usage or target error so a harness can tell a failed check from
  a broken one. The default scope is the **working tree** — tracked modifications plus untracked
  files — because agent edits are uncommitted by definition and `diffscope`'s three-dot
  `base...HEAD` sees only committed work, returning nothing for the exact case this exists to catch.
  It writes nothing, publishes no run directory and never advances an accepted baseline: a fast
  scoped check is not a review, and the verdict says so inline. The default threshold is **medium,
  not high**, because command injection and SSRF on agent-written code are frequently rated MEDIUM
  and a HIGH default would look like it worked while missing the main case; `--min-confidence` is
  available for teams that measure the low-confidence leads as too noisy, and no confidence floor
  is applied by default because in the loop a false block costs one turn while a miss ships.
  Requested paths that were never analysed are reported as `missed`, never as a clean result.
- **`websec run --only PATH` narrows ANALYSIS, not just the report** — the basis of an in-loop
  security gate. `--diff` scopes what is *reported*: measured at 42.2s versus 43.0s for a full run
  on a 320-file repo, because 99% of the cost is extractors running over the whole tree. `--only`
  changes what is read and matched, measured at **4.3s versus 43s (about 13x)** for a one-file
  scope. It is two-tier by design: the tree is still walked in full, so stack detection, ignore
  policy, fixture classification and glob discovery are unchanged — a scoped run of one Python file
  in a Deno repo still detects Deno. Files are analyzed **in place**; copying them into a temporary
  tree was measured to manufacture 3 CRITICAL and 1 HIGH findings purely from losing path context
  and the ignore policy. A requested path the walker never selected is reported as `missed` in
  `analysis_scope`, never as a clean result. Verified on this repository: scoping to the 17 files
  carrying findings produced **0 new findings and 0 lost**, and a parity test now enforces that
  scoped findings are a subset of full-tree findings with unchanged severities.
- **Runs now record WHICH CHANGE they describe, graded by how much the evidence is worth.** A new
  `attribution` object carries the commit SHA, whether the tree was clean, branch, author/committer
  email, commit-signature status and key fingerprint; CI-minted context (provider, repository, run
  id, workflow ref, triggering actor) when a GitHub Actions or GitLab CI runner injected it; and a
  `corroborate_at` link telling an assessor where to check the claim against a system websec does
  not control. `assurance` is **computed** — `ci-minted` > `vcs-observed` > `self-asserted` > `none`
  — and is never accepted as input. `--actor` / `$WEBSEC_ACTOR` and agent model/harness/session are
  recorded under `declared` with an inline warning that they are unverified: a value the runner can
  set to any string is a label, not audit evidence. The object also states, in the artifact rather
  than only in the docs, that approver independence is **not** evidenced — that lives in a forge
  approval record, not a scan. `attribution` is a **sibling** of `verification_context`, never
  merged into it, because repairs compares that object by strict dict equality and an added key
  would invalidate every previously emitted repair plan.
- **The CI gate's verdict is now recorded as evidence, not only as an exit code.** `--fail-on` was
  evaluated *after* the artifacts were written and *after* the run was published, so nothing in the
  run directory said which gate ran, at what threshold, against which baseline, or whether it
  passed. The verdict is now computed before anything is written and stored on the ledger as
  `gate` — threshold, `new_only`, baseline identity, diff scoping, count at or above threshold,
  verdict (`pass` / `fail` / `incomplete` / `not-evaluated`) and exit code — so the artifact and
  the process exit code cannot disagree. The record states inline that a client-side gate is
  advisory unless run as a required status check: it cannot evidence that it ran for every change.
- `manifest.json` now records a sha256 of every artifact the run emitted. The input side was
  already content-addressed but the output side was not, so a finding could be deleted from a
  written ledger in a text editor with nothing to contradict it. This is integrity, not
  tamper-proofing — anyone who can edit an artifact can recompute the manifest — and the note
  beside the digests says exactly that.
- `websec repair-verify --out RESULT.json` persists the verification result. The bound
  original/target repair evidence is the strongest artifact websec produces and it previously
  existed only on stdout and as an exit code. The write refuses to overwrite an existing file, so a
  result can never clobber an input or prior evidence.
- **An honoured `WEBSEC_SKIP_HOOK` bypass now leaves a durable record.** The test was the first
  statement in the generated hook, before the interpreter was resolved and before any Python ran,
  so a skipped gate produced no run directory, no `hook.log` and no stderr line at all. The hook now
  appends a JSONL record (hook kind, HEAD, timestamp, `scanned: false`) to
  `$GIT_DIR/websec-guardrail/bypass.jsonl` and says so on stderr before exiting 0. The escape hatch
  still works — this records it, it does not block it. Every record and the `read_bypasses` reader
  carry the limitation inline: websec cannot observe `git push --no-verify`, an uninstalled hook or
  a deleted one, so **an empty bypass log is not evidence that no bypass occurred**.
- Agent-config detection now covers hosts beyond Claude Code: Cursor, VS Code, Gemini, Codex,
  Continue, OpenCode, Zed, Windsurf, Cline, Roo, Aider, Qwen and Warp. Committed literal
  credentials in an MCP `env`/`headers` block, unpinned MCP servers, non-vendor LLM base URLs and
  the hidden-unicode rules-file backdoor are found in those hosts' config and instruction files.
  This deliberately extends the named ALLOW-LIST, not the walker: a broad sweep over agent
  directories was measured against 1,515 agent files in 33 repositories and produced 0 true
  positives and 1 false positive, because those directories hold worktree copies and cached
  scanner output. The widened list finds 0 findings across 10 real repositories.
- The non-vendor base-URL check now runs over every allow-listed file rather than only the ones
  that parse as JSON. It is a text regex, and `.codex/config.toml`, `.windsurfrules` and the
  `*.md` instruction files are exactly where a committed third-party LLM endpoint hides.

### Fixed

- **Gitleaks now scans the working tree as well as git history, closing a false-clean.** The
  adapter only ever ran `gitleaks detect --source`, which reads the **commit graph only**, so a
  secret written but not yet committed was invisible to gitleaks on every target. Verified: an
  uncommitted `.env` holding a live-shape GitHub PAT yields 0 findings before the fix and 1 after.
  Trivy `fs` was the only working-tree secret path, so a run selecting `--scanners gitleaks`
  reported a clean tree that was not clean. Gitleaks now runs **two disjoint passes** — history
  (`gitleaks git`) and working tree (`gitleaks dir`) — because neither surface subsumes the other;
  history mode remains load-bearing for the HISTORY-ONLY "rotate, don't just delete" annotation.
  Each finding records `scan_mode` (`git`, `dir` or `git+dir`) through to the ledger, and a secret
  seen by both passes collapses to one finding, so recall rises without inflating counts.
  `--scanners gitleaks` selects both passes. On pre-8.19 gitleaks, which has no `git`/`dir`
  subcommands, a cached capability probe falls back to the legacy `detect` spellings; a failed
  probe assumes legacy rather than skipping the scan.
- Recon no longer enumerates `.codex/` as target application source. It was the one member of the
  agent-tooling family missing from the traversal skip set, so a repository using Codex could have
  findings raised against its own agent hooks configuration.


## [0.14.0] — 2026-09-14

Migration: [0.14.0 migration guide](docs/MIGRATING-0.14.0.md). Facts, ledger and envelope move to
schema 2.0; complete execution is distinct from complete protection.

### Security
- Reject nested output `runs` symlinks and non-directories before analysis or dynamic probes;
  preserve explicit operator-selected output-base aliases while retaining stable-tree assumptions.
- Refuse foreign agent skill files and ambiguous managed blocks before install/uninstall writes;
  preserve surrounding text, historical generated CRLF headers and existing user policy.
- Select agent-review artifacts from this invocation's JSON envelope, rejecting symlink aliases and
  stale `latest` fallback. Guidance preserves partial execution, provenance and evidence uncertainty
  and no longer silently installs or upgrades the engine.
- Evaluate credential equality at the comparison, including reversed operands; unrelated
  constant-time helpers cannot hide a raw comparison. Distinguish literal presence/type checks
  from nonempty hardcoded credentials, keeping timing behavior an unverified LOW advisory.
- Isolate hook imports from target source, preserve foreign shell hooks, and keep accepted gate
  baselines separate from advisory/failed attempts. Changed severity/scanner policy triggers a full gate.
- Pass Action inputs through environment/argv, install its trusted source checkout and upload only
  the current attempt's SARIF; incomplete execution cannot select an older `latest` artifact.
- Bound retained source payloads to 64 MiB per context, preserve hashes for every analyzed symlink
  alias, and keep `.local` private regardless of case. Byte-budget losses make execution incomplete;
  the payload budget is not a process-memory limit.
- Validate imported SARIF rule/component references, invocation outcomes, kind/level pairs and
  lexical paths; cap expanded traces and metadata as well as input bytes. Never load referenced
  source, remote properties, fixes or commands. Ambiguous producer fingerprints stay report-bound.
- Keep cookie flags attached to each setter and PII controls attached to the returned value;
  comments, sibling handlers, ambiguous spreads and unused helpers cannot establish protection.
- Scope unsafe decoder decisions to executable authentication code and nosniff checks to browser
  responses; ZIP error text and non-response file streams no longer create those leads. GitHub
  expression checks exempt only exact documented numeric identifiers, retaining text/unknown inputs.
- Reject contradictory repair/proof completion evidence, serialize intelligence publication and
  compare each feed's publication date before accepting an update or reassessment.
- Bind sanitizer, redirect, token-cap and approval evidence to individual expressions and values;
  comments, unrelated calls, hoisted no-op helpers and inverted/reassigned approvals no longer hide
  unsafe sinks. Add Vue/Svelte/HTML template and module-variant intake with distinct sink occurrences.
- Keep service-specific guard evidence, routes and inventory joins scoped to the matching service;
  same-path sibling endpoints and ambiguous dynamic observations cannot inherit another service's result.
- Constrain repository reads to the selected root, apply exclusions consistently, prune private
  `.local` and skipped trees, reject special files, and disclose read/cap losses. Safe in-root file
  symlinks remain supported; directory symlinks are not traversed. POSIX descriptor-relative reads
  and pinned root identity narrow replacement races; stable checkout assumptions still apply.
- Require bearer authentication for loopback-only MCP HTTP, validate Host/Origin and request framing,
  cap request bodies/workers, enforce an absolute receive deadline, and recheck approved root identity.
- Preserve uncertainty in dynamic/DAST/calibration evidence. Status-only candidates and scanner silence
  cannot become confirmed findings or false-positive labels; quarantine legacy unproven samples.

### Added
- Bounded Python request-to-query assignment analysis with aliases, branch joins, matched tuple
  unpacking and separate SQLAlchemy bound-value evidence. Parse/work limits and later-loop-iteration
  gaps stay visible; no target execution, cross-function or fixed-point coverage is claimed.
- Opt-in pre-commit manifest and local/PR/weekly CI examples around existing entrypoints, with
  isolated trusted engine execution, separate target checkout, read-only permissions and current
  attempt artifacts. No hooks or schedules are activated by the examples.
- `research catalog` and `research evaluate --suite control-scope` expose all three shipped
  proposals/24 authored cases, aggregate and individual metrics, consistent detector revision and
  explicit human-review-only eligibility; empty/failed/inconsistent suites cannot pass.
- Bounded, data-only Django URL parsing for supported local mounts and view references; unresolved
  dynamic mounts remain attributed candidates with explicit gaps, never executed Python settings.
  Converter parameters use the existing path-parameter contract through CLI targeting and inventory.
- Manifest-aware framework/package-manager inventory across service roots, including Rust workspaces;
  dependency metadata is a stack hint, not deployment proof. React/native JSX alone does not imply
  a browser renderer; mixed browser services retain header-review coverage.
- Offline SARIF 2.1.0 import through repeatable `--sarif REPORT`: native tool/rule namespaces,
  fingerprints, ordered traces, suppressions, status and report SHA provenance survive into artifacts.
  Source freshness remains unverified; imported absence cannot prove a repair.
- Optional Bandit execution with built-in configuration, target configuration discovery disabled,
  inline `nosec` ignored, and native confidence/CWE/location preserved independently of severity.
- Nine named language/configuration profiles with manifest service boundaries, explicit completed/
  unknown/manual checks and an offline `capabilities` catalog. Synthetic paired controls describe
  narrow supported syntax; native memory-safety remains manual.
- Validated, dated FIRST EPSS/CISA KEV snapshots through explicit `intel refresh`, offline status and
  known-CVE reassessment with stable IDs and reopening events. Core scans never refresh implicitly.
- Data-only research proposal evaluation with development/holdout metrics and human-review promotion;
  corpus commit pins and revision mismatch diagnostics improve reproducibility without renewing old scores.
- Execution and scope manifests in `coverage.json`, facts, ledger, envelope, SARIF, and reports;
  `--require-complete` and severity gates return exit 2 for incomplete requested execution.
- Unique run directories with atomic publication of only completed executions to `latest`.
- Versioned semantic finding identities, legacy aliases, acknowledgement expiry, lifecycle events,
  and build-bound repair plans with offline `repair-verify` evidence validation.

### Changed
- Preserve CVE occurrences by manifest, package ecosystem and installed version, including advisory
  aliases and explicit false KEV values. Checkov resource IDs distinguish same-line findings, and
  native error/summary contradictions remain incomplete even when a usable partial report exists.
- Facts/ledger/envelope schema version is 2.0. Baseline disappearance is “no longer observed”,
  with deprecated `fixed_count` remaining zero. New, reopened, and changed findings gate baselines.
- Ignore policy defaults to the target only. Explicit invalid baselines/graphs and invalid or oversized
  scanner output are visible incomplete checks. Full scanner rule namespaces and native occurrence IDs
  survive normalization and de-duplication.

## [0.13.0] — 2026-09-11

### Fixed
- **`command-injection` missed `os.popen`, and `shell=False` could hide always-shell sinks
  (issue #101).** Two false negatives in the same sink, both silent:
  - `os.popen` was absent from the sink alternation while `os.system` was present.
    `subprocess.Popen` does not cover it — that alternative requires the literal `subprocess.`
    prefix. Added, along with `subprocess.getoutput`/`getstatusoutput`.
  - the `shell=False` precision guard is **file-level**, so a single safe
    `subprocess.run(argv, shell=False)` anywhere in a module suppressed the whole file's
    command-injection finding — including a tainted `os.popen`/`os.system`, which take a command
    string, have no argv form, and cannot be made safe by any keyword argument. The guard now
    stands down when an always-shell sink is present, and is otherwise unchanged.

  Verified end-to-end: on a Flask route doing `os.popen("ping -c1 " + request.args["host"])`
  alongside one safe argv call, 0.12.0 reports no sinks at all; this reports `command-injection`.
  Coverage-only — no finding that was reported before is suppressed now.

## [0.12.0] — 2026-09-11

### Fixed (post-tag hardening, included in this release)
- **Test suite was not hermetic against ambient git config (bug-217).** `tests/test_hooks.py`
  resolved the hooks dir through `hooks._hooks_dir()`, which deliberately honours
  `core.hooksPath` so the guardrail lands in Husky's dir on projects that use one. With a
  **global** `core.hooksPath` set — as agent sandboxes and Husky users have — every install in
  that class wrote to the shared hooks dir instead of the temp repo, and
  `test_uninstall_removes_pure_websec_hook` **deleted the real hook there while still reporting
  `OK`**. `tests/test_diffscope.py` had the same class of defect via `commit.gpgsign=true`
  (commits failed outright) and `core.autocrlf` (line-ending rewrites under exact hunk-range
  assertions). Both now pin the git settings they depend on locally, `test_hooks` additionally
  neutralises `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` for the git processes it spawns, and a new
  `test_hooks_dir_never_escapes_the_temp_repo` asserts the containment invariant directly so the
  silent-escape mode fails loudly instead of passing green.
- **Repo automation.** Branch protection on `main` requiring five checks; a `hermeticity` CI leg
  that runs the suite under a hostile global git config and verifies it writes nothing outside its
  temp repos; a `suite-integrity` leg enforcing a test-count floor (a deleted test makes a suite
  greener *and* faster, so nothing else catches it); and bot-PR triage/auto-merge plus a weekly
  release train. None of this changes the shipped package.

**Aim the pentest, then prove the aim.** This round adds the planning layer that turns websec's recon
into a testing plan, closes the loop with real scans — and then hardens the result against a class of
defect found by dogfooding: a transport or protocol reality (a redirect, a dead socket, a scanner that
never ran) being silently converted into a security verdict.

### Added — the planning trio

- **§3a Attack-surface inventory** + `attack-surface.json` — one ranked row per endpoint (method/path →
  handler → auth verdict → path params → risk tags → sinks in that file → an explainable risk score
  with reasons). The "test in this order" table. Sink attribution is FILE-scoped and says so.
- **§4b DAST prediction** — the concrete scanner alert each static finding will raise (`missing-csp` →
  ZAP 10038/10055, `sqli` → ZAP 40018 / sqlmap, `ssrf` → Nuclei OAST…), *and* the blind spots no
  scanner can find (BOLA, missing-auth, mass-assignment, RLS, secrets, supply-chain) with why — so a
  clean scan is never mistaken for "safe". Plus "scan answers not to trust at face value".
- **§5b Pentest runbook** — a phased, pre-aimed plan (safe recon → authz with two identities →
  injection at sink-backed endpoints only), each item carrying a real target, a tool command and a
  confirm/disconfirm oracle. Phase 3 is gated behind an explicit authorization warning.
- **§5c Fix prompts** — one paste-ready instruction per finding, each ending in a class-specific
  VERIFY step (BOLA → re-run the two-identity probe; secret → ROTATE, deleting doesn't un-leak).
- **§4c FP pre-triage** — tags findings a reviewer/LLM-reviewer routinely filters, with the reason.
  Tags only; never drops.
- **§3e OpenAPI contract** — shadow (undocumented) endpoints diffed from SOURCE, stale spec entries,
  and contract hygiene. An unusable spec produces NO verdict rather than a wrong one.

### Added — integration & coverage

- `websec run --diff REF` — PR scoping with exact changed-hunk line ranges (`diff-scope.json`), and
  `--fail-on` narrows to changed files.
- `websec emit-context` — recon as a Claude Code SessionStart `additionalContext` envelope, so any
  agent starts pre-scoped.
- `websec calibrate --ingest-dast` — feed a real ZAP/Nuclei report back to confirm/refute predictions
  and personalise `P(real)`.
- **Reachability + EPSS/KEV enrichment** for dependency CVEs ("reachable AND exploitable"), with
  `scripts/refresh-epss-kev.sh`.
- `--sbom` (CycloneDX/SPDX), **osv-scanner** wired as a second SCA engine, **gosec**/**Brakeman**
  per-language SAST, opt-in **TruffleHog** `--verify-secrets`, MCP `env`/`headers` secret detection,
  and HISTORY-ONLY secret flagging.

### Fixed — verdict correctness (the headline)

- **Redirects are no longer followed when judging auth** (bug-208). A route answering `307 → /login`
  was scored as the login page's `200` and reported **OPEN-no-auth** — reported live on a real repo
  against `/api/platform-admin/secrets`. All three auth probes were affected.
- **A 200 that means "denied"** (`{"user":null,"error":"not authenticated"}`, a login/SPA shell) is no
  longer reported open (bug-210).
- **A crash mid-scan no longer aborts the run** — a failed body read kept the status (bug-209).
- **The forged-token probe is no longer dead on redirect-gated apps** and reports INCONCLUSIVE rather
  than a pass when nothing was testable (bug-210).
- **An unreachable target is no longer a clean bill of health** (bug-210).
- **`mint()` no longer follows a login redirect**, which could mint a bogus identity and run the whole
  BOLA matrix against two fake tenants (bug-210).
- **Write findings are no longer deleted by a GET's verdict** — dynamic correlation is method-exact
  (bug-211); and every "gated" verdict is recognised as protection, guarded by a drift test.
- **The calibration overlay can no longer be poisoned** by an untrustworthy run or by a passive-only
  scan's silence (bug-212).
- **`--diff --fail-on` now gates on access-control findings** (they carry a route path, so they were
  always "untouched"), the line-in-hunk validation actually runs, and git config can't empty the
  scope (bug-213).
- **The authenticated BOLA probe no longer fires side-effecting endpoints** like `/send-invoices`
  (bug-214); a 200 soft-deny is no longer a CRITICAL "leak"; IaC findings no longer collapse across
  resources; UNKNOWN severity can trip a gate.
- **`SIDE_EFFECTING` no longer over-matches**, which silently hid `/api/generated-content`,
  `/api/sender-profiles` and `/api/runners` from every probe (bug-216).
- Secrets in `.github/workflows/` and dependency manifests are no longer demoted as "documentation
  placeholders"; oversized files are disclosed; SARIF no longer emits route paths as unmappable
  artifact URIs; copy-paste commands are shell-safe (bug-215).

### Testing

413 → **551 tests**. The real-server probe tests were de-flaked (threading + socket close); several
tests that had asserted wrong behavior as correct were corrected. Self-scan ledger unchanged
throughout — every change strictly additive or a correction.


## [0.11.0] — 2026-07-11

Distribution & integration round — reach every agent host, run as a local guardrail, and compose with
a knowledge graph. Adapted from a review of [graphify](https://github.com/Graphify-Labs/graphify);
websec keeps its zero-runtime-deps guarantee throughout (stdlib-only HTTP + JSON graph parsing).

### Added

- **MCP over HTTP** (`websec mcp --http`). The MCP server gained an HTTP JSON-RPC transport alongside
  stdio, so a team can point one URL at the recon tools instead of every client spawning its own
  process. Built on the stdlib `http.server` — **no starlette, no new dependency** — with a
  `GET /health` endpoint and a `POST` JSON-RPC endpoint. Binds `127.0.0.1:8733` by default (the tools
  read local paths, so localhost-only unless `--host` is set on a trusted network); still read-only.
  The request handler was refactored into a transport-agnostic `process()` shared by both transports.
  11 new tests (incl. a live HTTP round-trip).

- **`BENCHMARKS.md`** — open, reproducible measurement methodology: coverage (`websec proof` 10/10),
  calibrated precision with Wilson 95% CIs from the labeled corpus (n=59), the zero-dependency /
  determinism guarantees, and a documented identical-conditions protocol for a future Semgrep/Bandit
  comparison (no head-to-head numbers are claimed until that harness is run). Adapted from graphify's
  benchmark discipline.

- **Blast-radius enrichment from a graphify knowledge graph** (`graph_enrich.py`, opt-in, zero new
  deps). If the scanned repo has `graphify-out/graph.json` (or `--graph <file>` is passed), each
  finding is tagged with how much of the app transitively **depends on** the vulnerable code —
  reverse-reachability over dependency edges (calls/imports/references/inherits/…). A SQLi in a
  leaf handler and the same SQLi in a shared helper imported by 40 modules stop looking equally
  urgent. Findings gain a `graph` block (`nodes`, `blast_radius`, `dependents` sample, `community`)
  and the ledger a `graph_enrichment` summary. Pure stdlib JSON (never imports tree-sitter, so the
  zero-runtime-deps guarantee holds), reverse-BFS bounded at 20k visits with disclosed truncation,
  and wrapped so a malformed/oversized graph can never fail a run. **Surfaced in every consumer**: a
  ranked "★ Blast radius" section in `AGENT-BRIEFING.md` (verify high-radius findings first), a
  per-finding blast-radius line in `REPORT.md`, and a `blastRadius` property + message note in SARIF
  (so GitHub Code Scanning sees it too). 14 new tests.

- **`websec hooks` — git guardrail** (`hooks.py`). Wires the baseline-diff into git so websec runs
  automatically per commit/push: `hooks install` writes an advisory **post-commit** hook (recon-only,
  ~1s, prints a `baseline: N new` heads-up, never blocks); `hooks install --pre-push` writes a
  blocking **pre-push gate** that fails the push when NEW findings at/above `WEBSEC_HOOK_FAIL_ON`
  (default `high`) are introduced. Marker-delimited install/uninstall (appends to and preserves an
  existing hook), interpreter pinned + allowlist-sanitized so it survives pipx/uv isolation without
  shell-injection risk, hooks dir resolved via `git rev-parse` (worktrees + core.hooksPath aware),
  and old guardrail runs pruned to the last 5. `WEBSEC_SKIP_HOOK=1` overrides. Stdlib only, 10 new
  tests incl. an end-to-end real-commit run. Adapted from graphify's hook installer.

- **`websec install <host>` — multi-host agent installer** (`install.py`). Teaches any of the core
  agent hosts to reach for websec-validator on a security review: `claude`, `codex`, `cursor`,
  `gemini`, `aider`, plus a `generic` `AGENTS.md` writer. Skill-style hosts (Claude, Cursor) get a
  dedicated skill/rule file; shared-instruction hosts (Codex/Gemini/Aider/generic) get an idempotent
  marked block injected into their standing-instructions file without clobbering the user's own
  content. `--user` installs home-wide, `--uninstall` removes cleanly, `websec install status` lists
  what's present. Closes the gap between the README's "any agent can act on it" and shipping only a
  Claude plugin. Stdlib only, path-safety-guarded, 12 new tests.

- **No-Row-Level-Security detection** (`missing-rls` class, in `schemas.py` + the ledger) — committed
  Postgres/Supabase DDL declares owner/tenant-scoped tables but ships **zero** `CREATE POLICY` /
  `ENABLE ROW LEVEL SECURITY` anywhere in the `.sql` corpus (the CVE-2025-48757 "Lovable" class).
  Ledger-only correlation of existing facts (**not** a new extractor, count unchanged). Heavily FP-guarded:
  fires only on an owner-column-bearing table, aggregates RLS tokens across all migrations, gates on a
  Postgres/Supabase stack, honors the truncation guard, strips SQL comments, and ships **MEDIUM/LOW**
  with an explicit "RLS may be dashboard-defined — verify" caveat (escalates to HIGH only when a Supabase
  anon key makes the tables directly browser-reachable). Distinct from the existing `rls-context` class.
- **`agent_config` extractor** (21st extractor) — scans the repo's OWN agent/MCP wiring as untrusted data
  (`.claude/settings.json`, `.mcp.json`, cursor/copilot rules, `CLAUDE.md`/`AGENTS.md`), mapped to the
  OWASP Top 10 for Agentic Applications. Five classes: invisible/bidi Unicode in a rules file
  (Rules-File-Backdoor), a pre-consent hook with a fetch-and-execute command **shape** (CVE-2025-59536
  class), blanket MCP auto-approval, a non-vendor `*_BASE_URL` override (key-exfil), and unpinned/remote
  MCP servers. It reads a fixed bounded allow-list directly off the root and **never executes** anything it
  finds. Tool-description *poisoning* (prose-grammar match) is intentionally deferred to keep the FP bar.
- **Log-injection (CWE-117) sink class** — the 17th `surface` sink. User input concatenated/interpolated
  into a logging call (`console`/`logger`/`logging`/`winston`/`pino`) with no CR/LF neutralization (log
  forging). **LOW** severity (not RCE). Structured/parametrized logging (`logger.info('u=%s', x)`, pino's
  object arg, `extra={…}`), bare `print()`, and client/CLI/no-web-surface files are all suppressed.
- **`dependencies` extractor** (22nd extractor) — offline supply-chain hygiene for the AI slopsquat /
  malicious-dep class Trivy can't see. Two ledger classes: a **malicious install/lifecycle script**
  (fetch-and-execute/eval body — the Shai-Hulud shape, MEDIUM) and **lockfile drift** (a manifest dep
  absent from an existing JSON lockfile's installed set, LOW). Unpinned/floating versions and
  dependency-confusion-shaped names are surfaced as **advisory facts only** (never routed to the ledger,
  so they can't inflate findings). Registry resolution / known-hallucinated-name / typosquat-distance are
  **deferred behind an opt-in `--network` step** — the default pass makes zero network calls.
- Metrics: **20 → 22 extractors** (`agent_config`, `dependencies`), **16 → 17 sink classes**
  (log-injection), **285 → 324 tests**. New finding classes: `missing-rls`, `log-injection`,
  `agent-config-hidden-unicode` / `agent-hook-autoexec` / `agent-mcp-autoapprove` /
  `agent-config-baseurl-override` / `agent-mcp-unpinned-server`, `malicious-install-script`,
  `lockfile-drift`. `schema_version` unchanged (`1.0`, additive facts). All findings flow through the
  existing calibrated-`P(real)` + de-dup + `.websec-ignore` machinery.
- Open-source hygiene surface: root `SECURITY.md` (GitHub-recognized security policy with
  private-reporting flow), `CONTRIBUTING.md` (ground rules + dev setup + PR checklist),
  `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), issue templates (bug / **false positive** /
  feature) + PR template, and Dependabot config (GitHub Actions + Docker base image).
- README status badges (CI, PyPI, Python, zero-deps, SARIF, license).
- PyPI metadata: trove classifiers and `[project.urls]` (homepage, docs, changelog, issues) —
  populates the sidebar on the PyPI project page from the next release.

- **Fixture/example code is scoped out of the attack surface.** Test/example/fixture routes are split
  out (kept in `FACTS.json` under `fixture_endpoints`, counted but not probed) so a project that
  vendors a demo app isn't profiled as if that demo were the product; secrets in fixture files are
  demoted to LOW and annotated rather than dropped. `--include-fixtures` treats all of it as product
  code. Fixture package manifests no longer drive framework detection. Also adds raw-server detection.

### Changed

### Fixed

- **`--exclude` now reaches every scanner** (bug-205). It was honored by trivy/semgrep but dropped by
  the gitleaks/checkov paths and the findings post-filter (which only excluded built-in `SKIP_DIRS`).
  Added a single post-filter choke point that applies every `--exclude` glob across all scanners, with
  a disclosed `user_excluded_dropped` hygiene counter.

### Removed

## [0.10.0] — 2026-07-03

Minor: the **browser-vuln trio** (XSS / clickjacking / CSRF) closes the classic-web-vuln gap, and a
new **enterprise / CI integration surface** turns websec from a CLI-a-human-runs into a truth source a
pipeline, dashboard, or any MCP agent can consume — SARIF, a `--fail-on` gate, git-diff baselining, a
GitHub Action, an MCP server, and versioned output schemas. All stdlib, zero new runtime deps.

### Added
- **SARIF 2.1.0 output** (`formats.py`) — every `run` writes `results.sarif` (one `rule` per attack
  class carrying its CWE/ASVS/OWASP citation; severity → error/warning/note; stable
  `partialFingerprints`). Drops into GitHub Code Scanning (inline PR annotations + Security tab),
  GitLab, Azure DevOps, VS Code, DefectDojo. `--format sarif` also emits it to stdout for piping.
- **CI gate** — `--fail-on {critical,high,medium,low}` exits 1 when a finding at/above that severity
  remains (report-only by default).
- **Baseline / diff** (`baseline.py`) — `--baseline <prior findings-ledger.json>` marks findings
  `new`/`unchanged`/`fixed` via a stable per-finding fingerprint (surfaced as SARIF `baselineState`);
  `--fail-on` then gates on **only the new** findings, so a legacy backlog doesn't block every PR.
- **Reusable GitHub Action** (`action.yml`) — composite action: install → run → upload SARIF, with
  `fail-on` / `baseline` / `scan` inputs.
- **MCP server** (`mcp_server.py`, `websec mcp` + a `websec-mcp` entry point) — Model Context Protocol
  over stdio (raw JSON-RPC 2.0, stdlib only) exposing `websec_recon` / `websec_findings` /
  `websec_sarif` / `websec_briefing` so Cursor/Cline/Windsurf/Zed can call recon as typed tools.
- **Versioned output contract** — `schema_version` on FACTS/ledger/envelope + published JSON Schemas
  (`schemas/facts.schema.json`, `schemas/ledger.schema.json`); a `findings.envelope.json` artifact.
- **JSON envelope output** (`--format json`) — a self-describing wrapper around the ledger for
  non-GitHub CI / dashboards.
- **Reflected / DOM / template XSS sink class** (`surface.py`, 16th sink class) — the classic
  browser-rendered vuln the recon layer previously deferred entirely to optional Semgrep. Detects
  DOM sinks (`innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write`/jQuery `.html()`), React
  `dangerouslySetInnerHTML`, Vue `v-html`, and server template-escape-off (Jinja `|safe`, `mark_safe`,
  `Markup(`, `{% autoescape false %}`, interpolated `res.send`/`res.write` HTML). A per-file sanitizer
  guard (DOMPurify / sanitize-html / bleach / `escapeHtml`) suppresses the lead so a sanitized render
  doesn't false-fire; kept LOW-confidence like every surface signal (`xss` → CWE-79/CWE-116, ASVS V5.3.3).
- **Framework-agnostic clickjacking baseline** (`transport_security.py`) — a web surface that sets
  neither `X-Frame-Options` nor a CSP `frame-ancestors` directive is framable (UI-redress). Previously
  clickjacking was only checked inside Next.js configs; now it parallels the CSP/HSTS baseline for
  Express/Flask/Django/any surface (`clickjacking` → CWE-1021/CWE-451, ASVS V14.4.7).
- **CSRF baseline** (`transport_security.py`) — a cookie/session-authenticated app with HTTP routes
  but no anti-CSRF token library/middleware (csurf/csrf-csrf/@fastify/csrf/Django/Rails) and no
  `SameSite` cookie attribute. Derived from the auth extractor so a Bearer-token-only API is exempt —
  low-FP by design (`csrf` → CWE-352, ASVS V4.2.2).

### Changed
- Metrics: 15 → **16 sink classes**, 238 → **285 tests**. New modules: `formats.py`, `baseline.py`,
  `mcp_server.py`, `schemas/`. New CLI: `--format`, `--fail-on`, `--baseline`, `websec mcp`.

### Added (coverage — false negatives the FP/FN audit surfaced)
- **AWS SAM / serverless route modeling** (`routes.py`) — a `template.yaml`'s `AWS::Serverless::Function`
  Api/HttpApi events and Function URLs are now mapped to routes (handler resolved to the source file,
  build-dir `dist/`→`src/` aware), so a serverless backend is no longer 0-routes/unprobed. A Function URL
  with `AuthType: NONE` emits an **unauthenticated-serverless-endpoint** finding (a public dashboard
  serving account/P&L/PII data is the risk). Stdlib-only line/regex parse — no YAML dependency. On the
  audit corpus this surfaced a public P&L dashboard and a 19-route backend that were previously invisible.
- **Broken-auth backdoor detector** (`auth.py`) — the total-auth-bypass bugs the route/guard model can't
  see because the endpoint *is* "guarded", just by something forgeable. Flags a **dev-token backdoor**
  (`token.startsWith('dev-')` deriving a principal), an **accept-any-credential** login (explicit
  accept-any/MVP intent, or a password-length-only check with no hash compare), and a **fail-open
  signature/secret verification** (`if(env.*_SECRET){ verify }` that silently skips when the secret is
  unset). New classes `auth-backdoor` (CRITICAL, CWE-288/798/287) and `fail-open-auth` (HIGH, CWE-636/325).
  On the audit corpus it caught a treasury API's `dev-*` bearer bypass, an accept-any-password login that
  self-elevates to admin, and a fail-open Stripe webhook verify — all previously missed.

### Fixed
Real-repo false-positive audit (ran recon against a diverse set of real GitHub repos — TS/Python
frontends, backends, CLIs, static sites):
- **Path-scoped standalone guard mounts** (`authz.py`) — `app.use('/api', requireAuth)` on its own
  line, with routers mounted on `/api` in later statements, is now recognized (resolving each router
  instance's import and respecting Express source order, so a router mounted *before* the guard — e.g.
  a public login route — stays unguarded). Cut a real backend's guarded-route false positives 63→5.
- **Frontend API-client files no longer parsed as server routes** (`routes.py`) — in a combined
  frontend+backend monorepo, a React axios client (`import {api} from './client'; api.get('/x')`) and
  static hosting config (`public/_redirects`) were emitted as endpoints and flagged missing-auth. Now
  dropped via a client-vs-handler discriminator that still keeps serverless handlers (Cloudflare Pages
  `onRequest*`, Lambda `handler`) even when they call axios/fetch. Cut a monorepo's missing-auth 185→3.
- **Python test files** (`test_*.py` / `*_test.py` / `conftest.py`) are now classified as tests
  (`base.py`), so a `test_curl.py` doing `requests.get()` no longer false-fires SSRF.
- **Browser-hardening findings gated on a served-web surface** (`transport_security.py`) — CSP / HSTS /
  clickjacking no longer fire on a non-web Python/CLI tool that merely builds an HTML string (a report
  generator); they require an HTTP-serving construct (`new Response` / `res.send` / a framework).

Second FP audit — a 15-agent adversarial workflow verified every finding across the corpus against the
real code and clustered the false positives; the dominant patterns are now fixed (corpus findings
308 → 191, −37%, with zero true-positive loss):
- **App-specific auth-wrapper recognition** (`authz.py`) — a handler wrapped in an application HOF that
  composes a known guard (`withDealAuth = withAuth(...)`, `withSuperAdmin`, `requireUserRecord`) is now
  credited (dynamic guard-alias resolver, generic-aware `withDealAuth<{…}>(`). Also recognizes Fastify
  `addHook('onRequest', auth)` / per-route `{preHandler: auth}` and a secret-bearer guard
  (`Bearer ${CRON_SECRET}`). Cut one real app's missing-auth 94→3 (total 111→18).
- **Request-driven sinks gated on a web surface** (`surface.py`) — SSRF / path-traversal /
  command-injection / open-redirect are suppressed on a repo with no HTTP listener (a CLI / library /
  data tool: `languages` analyzed, no routes, no framework) and in more script/CLI file classes
  (research/, tools/, notebooks/, a Python `__main__`/argparse module).
- **PKCE is not password hashing** (`crypto_usage.py`) — a `createHash('sha256')` over an OAuth PKCE
  `code_verifier` (RFC 7636) no longer false-fires weak-password-hash.
- **webhook-forgery requires receiver evidence** (`integrations.py`) — an OAuth authorization-code
  callback, a webhook-subscription-management CRUD route, or a GET stub at a webhook-ish path is no
  longer flagged unsigned; a weak path (`/callback`) now needs raw-body/event/signature evidence, and
  verification via an imported helper (`constructEvent`) counts. Cleared ~16 FPs; kept real leads.
- **CSRF credits framework defaults** (`transport_security.py`) — NextAuth/Auth.js (SameSite=Lax by
  default) and Next.js Server Actions (built-in Origin check) no longer trigger the no-SameSite CSRF lead.

## [0.9.1] — 2026-07-02

Patch: recognise a Supabase **anon/publishable** key (a JWT with `role: anon`, or an `sb_publishable_`
key) as **intended-public** — it's designed to ship to the browser and is protected by Row-Level
Security — so the generic secret scanners' "JWT token" hit on it is downgraded to INFO instead of
ranking as a HIGH secret above the real findings. A **service_role** key (bypasses RLS) is still
surfaced as a CRITICAL leak. 238 unit tests.

### Fixed
- **Supabase anon-key false positive** (`client_exposure.py`, `findings.py`) — decode the JWT `role`
  claim (or read the `sb_publishable_` / `sb_secret_` prefix) to classify the key by trust tier. Any
  scanner JWT finding (gitleaks/trivy/semgrep) on a file whose key is the anon/publishable key is
  reclassified to INFO; the anon key is listed at INFO (acknowledged-and-cleared) and a `service_role`
  key literal is raised to CRITICAL (`supabase_service_role_in_client`). Provider-agnostic by value —
  an arbitrary third-party JWT is left to the generic value-leak path.

## [0.9.0] — 2026-07-02

Licensed-app & browser-extension coverage. Recon now models manifest-less stacks (Deno/Supabase edge
functions + Chrome/WebExtension MV3 + `.sql` schemas) that a `package.json`-only scan saw as `stack: ?`,
and adds a 20th extractor plus three provider-agnostic finding classes for licensing/entitlement and
client-trust flaws. 232 unit tests.

### Added
- **WebExtension extractor** (`extractors/webext.py`, the 20th) — flags a **client-side entitlement gate**
  (a paid tier/level read from `chrome.storage.local`/`localStorage` and used as the only enforcement),
  **over-broad `host_permissions`** (`<all_urls>` / `*://*/*`), `world:"MAIN"` content scripts, and
  `onMessageExternal` handlers with no sender validation.
- **License/entitlement verification-trust findings** (`integrations.py`) — `entitlement-revocation-bypass`
  (HIGH: grants on a truthy `success`/`valid` alone, never inspecting refund/chargeback/dispute/cancel/
  status) and `missing-usage-cap` (no per-license seat/device/activation cap or rate limit). License/
  subscription providers (Gumroad/Stripe/Paddle/Lemon Squeezy/Keygen/…) are detected by API host even
  when called via a raw `fetch` (no npm SDK). Detection is provider-agnostic — matched on generic
  refund/cancel/seat/device/quota concepts as code, not any one provider's field names.
- **`entitlement-abuse` probe** — a seat/device-cap replay + revocation-bypass draft (`templates/probes/`).
- New attack classes with CWE/OWASP citations + remediations: `entitlement-revocation-bypass`,
  `missing-usage-cap`, `client-side-entitlement`, `excessive-permissions`, `extension-message-trust`.

### Changed
- **Stack detection** (`stack.py`) — file-extension fallback (a `.ts`/`.js`/`.py` repo with no manifest
  now reports a language) + detects **Deno**, **Supabase edge functions**, **WebExtension**
  (`manifest_version`), and a `.sql` schema → `postgres`, so `stack`/`datastores` are no longer `?`.
- **Route discovery** (`routes.py`) — synthesizes `POST /functions/v1/<name>` routes from `Deno.serve`
  handlers (Noir/the regex frameworks don't parse Deno), and counts `Deno.serve` as a handler signal.
- **Schema extractor** (`schemas.py`) — parses `CREATE TABLE` from `.sql` files (entities + ownership
  fields like `license_hash`), which were previously never read (`.sql` isn't in `CODE_EXT`).
- **Tenant candidates** (`tenant.py`) — adds per-license/per-device ownership keys (`license_hash`,
  `licenseKey`, `visitorId`, …) as BOLA-isolation candidates.

## [0.8.1] — 2026-06-23

Correctness/robustness patch. Merges the PR #8 review (3 reproduced regex/logic bugs on the always-on
run path — Flask route-fallback drop/mislabel, password-policy `re.I` lowercase false-negative, GHA
detail double-`github.`), then clears that PR's deferred backlog. 203 unit tests; no behavior change
beyond fixing the bugs.

### Fixed
- **Checkov findings were 100% discarded** (`scanners.py`) — Checkov writes `results_json.json` (not
  the `<key>.json` the tool recorded), had no `_count_findings` branch, and no parser. Added
  `_norm_checkov` (handles the single-object and per-framework-list shapes; null severity → MEDIUM),
  registered it, fixed the output path, and added a count branch. Verified live: 3 findings now flow
  through where 0 did.
- **Secret de-dup could hide a second real secret** (`scanners.py`) — the secret fingerprint omitted
  the line, so two distinct secrets matched by the same rule in one file collapsed to one row. Added
  `StartLine` to the trivy + gitleaks secret fingerprints (the safe direction: never hide a distinct
  secret; accept rare cross-tool duplicates).
- **gitignored-secret downgrade was a silent no-op** (`scanners.py`) — `git check-ignore` wants
  repo-relative paths and echoes the exact input, but `trivy fs` emits absolute paths, so nothing
  matched. `_gitignored` now normalizes to repo-relative and maps results back to the original strings.
- **`websec dynamic` robustness** (`dynamic.py`) — `mint()` crashed (`5[0]` `TypeError`) on a singular
  scalar tenant field and produced a single-char tenant for a scalar string (`_first_tenant` coerces to
  a list); and the cross-tenant LEAK verdict string-matched a 3-element empty-body allowlist that
  misclassified common empty wrappers (`{"items":[]}`, whitespace, paginated) as leaks (`_no_records`
  now tests JSON emptiness structurally, conservatively — never masks a real leak).

### Changed
- Docs test count synced to **203** (TEST-SPEC service-to-test map, ENVIRONMENT, README).

## [0.8.0] — 2026-06-22

Coverage release closing the deferred backlog from the 0.7.0 dogfooding pass — three new
broken-access-control / transport classes plus a `authz_dataflow` extractor, each gated tightly to
hold the line on precision (no ledger blow-up on the validation target). 15 new unit tests (196 total).

### Added
- **CORS misconfiguration** (`transport_security`) — flags an `Access-Control-Allow-Origin` that
  reflects the request `Origin` (or `*`) **together with** `Allow-Credentials: true` (HIGH — any site
  reads authenticated responses, CWE-942); reflect-without-allowlist alone is MEDIUM.
- **Next.js security-header gap, monorepo-aware** (`transport_security`) — globs every
  `**/next.config.{js,mjs,ts}` (not just the repo root) and flags a config with no `headers()` security
  block (missing CSP / X-Frame-Options / HSTS / nosniff).
- **External script without Subresource-Integrity** (`transport_security`) — an external
  `<script src="https://…">` in server-emitted HTML with no `integrity=` hash / version pin (CWE-829
  supply-chain).
- **Host-header → redirect** (`surface`) — a redirect `Location`/origin built from the
  attacker-controllable `Host`/`X-Forwarded-Host` header with no host allow-list (CWE-601).
- **SSRF-hardening: follows redirects with no allow-list** (`surface`) — an outbound client that
  deliberately follows redirects (`follow_redirects=True` / `maxRedirects>0`) with no host allow-list /
  private-range deny, **incl. Python worker/job scripts** the route scan never reached (CWE-918).
- **NEW `authz_dataflow` extractor** — authorization *correctness*, not just presence: **unsigned-cookie
  authorization** (an access decision keyed on a client-settable cookie with no signature check —
  CWE-565/602), **claim-keyed authorization** (an authz check comparing a user-influenceable JWT body
  claim — CWE-639/807), and **transaction-local RLS context** (`set_config('app.*', …, true)` emitted
  outside a transaction, so the RLS principal resets before the query — CWE-1188).

### Changed
- `findings` ledger cites the new CWE/OWASP classes (cors-misconfig, subresource-integrity,
  open-redirect via host header, cookie-authz, claim-authz, rls-context) with remediations.

## [0.7.0] — 2026-06-22

Self-improvement release driven by dogfooding on a large real-world LLM-agent monorepo: a 15-agent
verification pass adversarially confirmed every finding, then the verdicts were encoded back as
extractor fixes + two new detector families. The dominant false-positive clusters are gone (HIGH
178 → 15 on the validation target) and the previously-uncovered AI-agent + crypto surfaces are now
detected. **Two new extractors** (`llm_security`, `crypto_usage`); 40 new stdlib unit tests (181 total).

### Added
- **NEW LLM / AI-agent security extractor** (`extractors/llm_security.py`) — the OWASP LLM Top 10
  surface that was entirely uncovered: indirect **prompt injection** (untrusted RAG/tool/web content
  into a prompt with no sanitizer/fence, esp. "render this URL verbatim"), **insecure output
  handling** (model text → `JSON.parse`/tool-call dispatch), **excessive agency** (a state-changing
  agent tool with no human gate), **unbounded generation** (no `maxTokens`/timeout → cost DoS), and
  **guardrail fail-open**. Server-side, test/script-excluded, gated on a real LLM call site for
  precision. Surfaced in the briefing + ledger with LLM01/02/06/10 + CWE citations.
- **docker-compose host-exposure detector** (`extractors/iac_ci.py`): flags `docker.sock` mounts,
  `pid: host` / host-root bind mounts, `privileged: true`, host networking / dangerous `cap_add`, and
  plaintext secret env when a `secrets:` block exists — a whole compose class that had no parser.
- **Secret-suppression audit** (`extractors/iac_ci.py`): flags `.gitleaksignore`/`.trivyignore`/
  `.semgrepignore` entries that SILENCE a leak in a real `.env`/secrets/key file (a true positive
  being hidden, not rotated/purged) — the committed-`.env.prod` CRITICAL class.
- **Reverse-proxy prefix-escape detector** (`extractors/surface.py`): flags a confined-deputy proxy
  that joins user-controlled catch-all path segments after a fixed prefix and forwards a server-minted
  token with no `..`/encoded-slash rejection (`/api/x/%2e%2e/admin` normalizes past the prefix → any
  upstream route with valid creds). CWE-441/CWE-22.
- **NEW crypto-usage extractor** (`extractors/crypto_usage.py`): weak password hashing (fast/unsalted
  SHA-256/MD5 instead of argon2/scrypt/bcrypt — CWE-916/759, HIGH), `jwtVerify` without an
  `algorithms` allowlist (CWE-347, latent alg-confusion), and predictable principals (a tenant/user
  id derived as a public hash of an identity field — CWE-330).
- **Shared file-class helpers** (`extractors/base.py`): `is_test_file` / `is_script_file` /
  `is_client_file`, so sink/exposure extractors stop scanning test fixtures, build/CLI scripts, and
  browser code as if they were deployed server handlers (the dominant cross-cutting FP driver).
- `client_exposure`: an `intended_public_analytics` bucket (PostHog/Usertour/Segment/… write-only
  ingest tokens) reported at **INFO**, separated from real browser-secret leaks.

### Changed
- **Router-mount auth modeling** (`extractors/authz.py`): recognize Express
  `app.use('/prefix', authMiddleware(...), createXRouter())` mount-level auth and propagate it to the
  mounted router's files via a local-import-graph BFS (TS `.js`→`.ts` ESM resolution, inner
  `router.use` inheritance, test-harness mounts ignored). Also recognize custom auth helpers
  (`getRequestSessionAuth`-style) and one-hop delegated guards in thin Next.js route handlers.
- `surface` SSRF: require a **request-derived** URL (not any template literal), gate to server-side
  files, and skip same-origin relative / hardcoded-host+token fetches.
- `client_exposure`: gate name-based `NEXT_PUBLIC_*`/`VITE_*` leaks to packages that actually have a
  frontend bundler; `PUBLIC_*` is SvelteKit-gated.
- `iac_ci` GHA script-injection: position-aware — only flag untrusted context inside a `run:` step
  body (not `if:`/`env:`/`with:`); SHA/ref-typed contexts drop to LOW.
- `transport_security`: recognize the cookie `Secure` flag set conditionally (`secure: isProduction()`).
- `upload_security`: credit `Content-Disposition: attachment`; tighten the file-serve sink (no bare
  `getObject` / metrics `res.set` FP); broaden the allow-list to `ACCEPTED_*`.
- `pii_exposure`: count same-file call sites (a masker wired in its own module is not "dead");
  exclude secret-maskers from the PII category; dead-control downgraded HIGH→LOW.
- `routes`: exclude `postman_collection.json` from app routes (it's an API spec, not a handler).

### Fixed
- The dominant false-positive clusters, validated end-to-end against a real production LLM-agent
  monorepo: the FP-removal alone took the ledger **403 → 72** and **HIGH 178 → 8** (missing-auth
  292→30, ssrf 41→0, pii 8→0) with **no loss of the genuine findings**. With the new LLM /
  docker-compose / secret-suppression / proxy-escape / crypto detectors then adding real,
  previously-invisible findings, the end state is **128 findings / 15 HIGH** (CRITICAL 1) — noise
  gone, true coverage up. 181 stdlib unit tests pass.

### Removed

## [0.6.3] — 2026-06-19

Framing-only release: lead every agent-facing surface with a defensive scope-and-authorization
statement so a careful coding agent stops flagging a plain "security-review my repo" as suspicious.
No behavior change.

### Added
- **METHODOLOGY: "Why your agent might pause — and how to phrase the request"** — explains the
  dual-use false-positive (a careful agent stalling on a plain "security-review my repo") and the
  three levers that fix it (how you ask · what the tool tells the agent · provenance).

### Changed
- **Authorization-envelope framing across the agent-facing surfaces** — the skill `description`, the
  top of `SKILL.md`, the `AGENT-BRIEFING.md` header (`briefing.py`), the plugin/marketplace/PyPI/CLI
  descriptions, and all 22 staged probe templates now lead with a defensive scope-and-authorization
  statement (defensive · your OWN code · read-only by default · prod/third-party out of scope · human
  approves each probe). Reduces dual-use false-positive pauses. The README hero line now leads with a
  defensive, ownership-asserting phrasing and the PyPI install. **No behavior change** — wording/order
  only; the live-fire confirmation checkpoint is intentionally preserved.

## [0.6.2] — 2026-06-12

### Added
- **Report-the-passes for cookies (P3)** — `transport_security` now reports a cookie-hardening PASS
  (`HttpOnly + Secure + SameSite` present → ✓, surfaced in the briefing's §3c "report-the-pass / gap"
  line) and flags the gap as a new `insecure-cookie` finding (CWE-1004/614) when a flag is missing.
  Saying "checked ✓" builds trust and turns the control into a regression assertion.

## [0.6.1] — 2026-06-12

Precision fixes found by re-running 0.6.0 on the same Cloudflare Worker.

### Fixed
- **Skip `.wrangler` / `.vercel` dev-build caches** — these hold BUNDLED output, so the new router-call
  heuristic was emitting phantom duplicate routes from them (a real run dropped 62 → 47, all real now).
- **Mass-assignment now catches the shorthand `{...record, tier}`** (a privileged field pulled from a
  same-named var — the actual tier-downgrade / role-escalation form), gated on a privileged-field list
  so `{...state, theme}` and a literal `{...record, role:'x'}` stay silent.

## [0.6.0] — 2026-06-12

Field-feedback release from a real run on a Cloudflare Worker (hand-rolled router + HMAC cookies).
Fixes the route-discovery blind spot that silently no-op'd the whole dynamic half, plus auth-scheme,
CSP, secret-triage, and config gaps.

### Added
- **Generic router-call route discovery (P1)** — a `<obj>.<verb>('/path')` / `.on('METHOD','/path')`
  heuristic that ALWAYS supplements Noir (which collapses hand-rolled / itty-router / Hono / Workers
  routers to ~1 endpoint), with a leading-`/` FP guard, plus a surface-coverage warning when
  handler-ish functions outnumber mapped routes (an empty §3 then reads as "couldn't map").
- **HMAC-signed-cookie auth detection (P2)** — `crypto.subtle.sign/verify` + cookie usage → scheme
  `hmac-signed-cookie` (was misread as `api-key`).
- **CSP baseline for server-rendered / template-literal HTML (P3)** — `transport_security` now fires
  on Workers / SSR apps that build HTML in code, not just frontend frameworks.
- **Mass-assignment via object spread (P3)** — `{...record, ...req.body}` / `Object.assign(record,
  req.body)` (the tier-downgrade / privilege-escalation class) as a 15th surface sink.
- **Provider-prefix secret triage (P4)** — name a secret by prefix (`whsec_`/`sk_live_`/`gho_`/`SG.`/…),
  HIGH for real secrets vs LOW for sandbox (`sk_test_`) / publishable (`pk_live_`), with the
  rotate-FIRST remediation order (gitignoring a committed key doesn't scrub pushed history).
- **Managed-platform config parsing (P5)** — `wrangler`/`vercel`/`netlify`/`serverless` → framework +
  datastore (KV / D1→sqlite / R2 / Durable Objects) + cron triggers.

### Changed
- **Auth probes gated by detected scheme (P2)** — `forged-token` stages for any token/cookie auth
  (forges into bearer OR the signed cookie); `jwt-attacks` / `hs256-brute-force` only when JWT is
  actually present. `ALWAYS` trimmed to `unauth-baseline` + `rate-limit-burst`.
- **Cloudflare KV family + redis added to the NoSQL set (P6)** so classic SQLi alerts auto-down-rank
  on a KV-only app.

(135 tests; 16 extractors; 15 surface sink classes.)

## [0.5.0] — 2026-06-12

### Added
- **Client-trust-boundary detection group** — generalized the man-in-the-browser / display-integrity
  class beyond wallets to ANY security-critical sink value (crypto/bank address, IBAN/routing, 2FA/TOTP
  seed, recovery/mnemonic phrase, API/license key, webhook URL), detected by **data-flow role** and
  classified by **blast radius** (money/credential → HIGH severity, config → MEDIUM); confidence stays
  LOW (architectural, "verify the compensating controls"). Adds a **grindable safety-code / fingerprint**
  check (`weak-fingerprint`, CWE-331) and an **over-claimed "tamper-proof" control-framing** check
  (`overclaimed-control`, CWE-693).
- **`transport_security` extractor** (16th) — framework-agnostic CSP + HSTS baseline audit: missing/weak
  CSP (`missing-csp`), inline event handlers that force `unsafe-inline`, and missing/partial HSTS scope
  (`incomplete-hsts`, the "set on /api but not the HTML document" gap).
- **Cross-cloud secret-shape detection** in `client_exposure` — Azure (storage `AccountKey=`, SAS,
  connection string) and GCP (service-account JSON, PEM private key) value-shapes alongside AWS, so the
  ships-to-browser scan is cloud-agnostic (AWS/Azure/GCP).
- **Follow-up client-trust-boundary classes** — `client-tamper-vector` (#2: a security-critical value fed
  by an interceptable client fetch instead of server-rendered), `abusable-action-endpoint` (#5: outbound
  email/SMS/push handlers with no auth-gate or only IP-only rate-limiting), and `redundant-secret-fetch`
  (#6: the same secret-manager key pulled more than once per path). All LOW/architectural ("verify"), in
  `integrations` + `client_integrity`.
- 23 regression tests (103 → 126) covering the new groups + the false-positive fixes below.

### Changed
- AppSync introspection remediation now explains that **fronting AppSync with API Gateway is not a
  security fix** — it can't enforce GraphQL semantics and doesn't cover the separate realtime WebSocket
  endpoint; steer to engine-level controls and treat any gateway/WAF as defense-in-depth only.
- `client_integrity` severity now tracks the sink's **irreversibility** (money/credential = HIGH) instead
  of a fixed MEDIUM.

### Fixed
- **False-positive tuning from dogfooding on 5 real repos (68 → 11 new-group findings; 0 confirmed FPs left):**
  - `abusable-action-endpoint` now requires a real comms send-CALL inside a request-handler / serverless
    function (not a mere SDK import) and skips test/type/config/script files — was firing on dozens of
    non-handler files in a real-world app (config, repositories, tests, load tests).
  - `client_integrity` sinks (and the `weak-fingerprint` check) are gated to genuine frontend files, so a
    backend service / SDK model that merely references an `account`/`recipient` field is no longer flagged
    as a browser display; a backend HMAC truncation is no longer a "grindable safety code."
  - `SKIP_DIRS` now excludes `.aws-sam`, `cdk.out`, `.sst`, `.amplify` — stops scanning vendored build
    dependencies (was flagging third-party SDK code under an AWS SAM build dir).
  - client_integrity findings now carry their own `file` (correct location in the ledger, not always
    `sensitive_display[0]`).

### Removed

## [0.4.2] — 2026-06-10

Documentation-only release (no source change).

### Added
- DocGuard (Canonical-Driven Development) doc set: `docs-canonical/` (ARCHITECTURE, SECURITY, TEST-SPEC,
  ENVIRONMENT), `AGENTS.md`, `CHANGELOG.md`, `DRIFT-LOG.md`; `.docguard.json` + `.docguardignore`. Repo
  now passes `docguard guard` (86/86, 96/100 A+).

### Fixed
- README: corrected a stale test count (23 → 103); added Usage + License sections.

## [0.4.1] — 2026-06-10

### Fixed
- **CRITICAL recon false-negative**: a repo living under a skip-named *ancestor* directory had every
  route and finding silently dropped (the tool reported a vulnerable app as clean). Skip-dir matching
  is now relative to the scan root.
- HTTP 500 is no longer escalated to missing-auth (nor recorded as a confirmed oracle sample).
- Sink classes now cite their specific CWE (sqli / nosql / redos / eval) instead of a generic SAST label.

### Changed
- The full ranked static finding set flows into the ledger; walk-truncation is disclosed; webhook-forgery
  routed to the ledger. (+8 regression tests.)
- `.websec-ignore` skips the maintainer's gitignored `base-research/` on self-scan.

> 0.4.0 was tagged from a stale local `main` and shipped to PyPI without the `#1`/`#2` fixes already on
> `origin/main`; 0.4.1 rebases the retest work onto them and ships the complete set.

## [0.4.0] — 2026-06-10

### Added
- REF-PENTEST retest: four new detection classes and 15 extractor refinements.

### Fixed
- Two false positives the retest disproved: AppSync introspection **is** disablable engine-level, and
  AppSync `API_KEY`-default is anonymous-auth, **not** CSWSH.

## [0.3.0] — 2026-06-07

### Added
- Closed REF-PENTEST detection gaps; added the **man-in-the-browser / tamperable-display** class
  (`client_integrity`).
- AWS-CDK / managed-AppSync / VTL boundary parsing (`.graphql` / `.gql` / `.vtl`).

## [0.2.x] — 2026-05-30 → 2026-06-01

The initial public line. Highlights across 0.2.1–0.2.9:

### Added
- FACTS-driven probe bodies; auth-bypass probe; forged-token engine extended to cookie-only auth.
- PyPI publishing via Trusted Publishing (OIDC, tag-triggered semver releases).
- Static at-risk routes; non-web-app false-positive flagging.

### Changed
- `__version__` derived from package metadata (single source of truth: `pyproject.toml`).
- Secret-finding precision: generic/entropy rules tiered to MEDIUM; secrets in docs/example files tiered to LOW.

### Fixed
- Scanner-contamination and rate-limit fixes (agent-wallet dogfood).

[Unreleased]: https://github.com/raccioly/websec-validator/compare/v0.14.0...HEAD
[0.14.0]: https://github.com/raccioly/websec-validator/compare/v0.13.0...v0.14.0
[0.15.2]: https://github.com/raccioly/websec-validator/compare/v0.15.1...v0.15.2
[0.15.1]: https://github.com/raccioly/websec-validator/compare/v0.15.0...v0.15.1
[0.13.0]: https://github.com/raccioly/websec-validator/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/raccioly/websec-validator/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/raccioly/websec-validator/compare/v0.10.0...v0.11.0
[0.4.2]: https://github.com/raccioly/websec-validator/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/raccioly/websec-validator/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/raccioly/websec-validator/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/raccioly/websec-validator/compare/v0.2.9...v0.3.0
[0.2.x]: https://github.com/raccioly/websec-validator/releases

# FAQ

Short answers to the questions people ask before and after adopting `websec-validator`. It is for
developers, security reviewers and team leads deciding whether and how to use the tool. Each answer
links to the page with the full detail.

## What it is

### What is websec-validator, in one paragraph?

A local command-line tool that reads your repository, maps the attack surface it can see (stack,
routes, auth model, tenant boundary, dangerous sinks, configuration), optionally runs and
de-duplicates the static scanners you have installed, stages probe scripts tailored to what it found,
and writes `AGENT-BRIEFING.md`: a "here's what to test and how" handoff for your AI coding agent.
It does the deterministic half of a security review; you and your agent do the reasoning, testing
and fixing. See [How it works](concepts/how-it-works.md) and [METHODOLOGY.md](METHODOLOGY.md).

### Is there a hosted version or a website I log in to?

No. It is a local CLI (plus an optional local MCP server and Claude Code plugin). There is nothing to
host and no account. The project website is documentation only.

### Is it a DAST or penetration-testing tool?

Not by default. The core pass is static: it reads code and never touches a running application. It
prepares a pentest rather than performing one:

- The briefing predicts what a DAST scanner would report for each static finding and lists the
  classes scanners are blind to (BOLA, missing authorization, mass assignment and others), with a
  phased runbook aimed at specific endpoints.
- `probes/` contains drafts for you or your agent to run against a **TEST** instance you own.
- `websec dynamic` is an opt-in, separately invoked phase: read-only cross-tenant BOLA checks and
  unauthenticated reachability checks against a target URL you supply. Write-verb probes are refused
  unless the target is localhost.

See the [dynamic testing guide](guides/dynamic-testing.md).

### Does it need an LLM?

No. There is no LLM in the tool, and every extractor is deterministic: the same input gives the same
findings. The AI half of the workflow is your coding agent reading `AGENT-BRIEFING.md`. That also
means websec works with any agent, or with no agent at all.

## Privacy and safety

### Does it send my code anywhere?

No. The core pass reads your repository and writes artifacts to a local directory; it makes no
network requests of its own. Network use happens only on paths you opt into, and none of them sends
source code:

| Opt-in | What leaves the machine |
|---|---|
| `--scan` | Whatever each external scanner does by default (for example vulnerability-database downloads or rule fetches). |
| `--scan --verify-secrets` | Discovered candidate credentials, to their providers, via TruffleHog. |
| `--network` | Dependency **names** only, to `registry.npmjs.org` and `pypi.org`. `--network-dry-run` shows the list and sends nothing. |
| `websec intel refresh` | Nothing about your project; it downloads public EPSS and CISA KEV feeds. |
| `websec update-check --online` | Nothing about your project; it reads PyPI release metadata. |
| `websec dynamic` | HTTP requests to the TEST target you configure. |

`websec feedback` also sends nothing: it writes a local record and prints a GitHub issue link that you
can choose to open. The full table is in [Installation](installation.md#offline-and-air-gapped-use).

### Does it modify my repository or execute my code?

The core pass is read-only on the target and does not execute target code or import its settings. It
writes artifacts to `./websec-out/` in the directory you run it from (or `--out`); if that is your
repository root, add `websec-out/` to `.gitignore`, because the artifacts describe security-relevant
code. A few commands write into a repository, and only when you run them: `websec init` writes
`.websec-ignore`, `websec install <host>` writes agent instructions, and `websec hooks install` adds
git or agent hooks. External scanners under `--scan` are separate programs with their own behaviour;
websec does not sandbox them.

### Can I point it at production?

No. Static recon never needs a running app. The probes and `websec dynamic` are for a **test**
instance and test accounts that you own and supply. The briefing tells the agent that production and
third-party targets are out of scope, and write-verb probes are refused unless the target is
localhost. Running probes against systems you do not own or are not authorized to test is out of
scope for this tool.

## Results and trust

### Does a clean run mean my app is secure?

No. A run with no findings means websec did not find anything **in what it could analyze, with the
checks it has**. Known limits:

- **Coverage.** Some languages are recognised but not analyzed (for example Elixir or Scala);
  build, dependency and cache directories (`build`, `dist`, `vendor`, `node_modules` and similar) are
  skipped entirely, and code found inside some of them is counted as a `skipped_directory_code` gap;
  very large repositories can hit a file cap. All of these are recorded in `coverage.json`, which
  you should read before trusting a quiet result.
- **Depth.** Detectors are pattern- and syntax-based with bounded data flow. There is no
  whole-program call graph, and route discovery does not import settings or execute code, so unknown
  route mounts stay *candidates*.
- **Runtime.** Deployment configuration, dynamic behaviour and business logic are not visible to
  static analysis.
- **Wording.** The run banner says `REQUESTED CHECKS COMPLETED` when the checks you asked for ran.
  It prints alongside it: "Completion describes execution, not complete protection."

`--require-analyzed` turns "nothing could be analyzed" into exit `3` so a pipeline cannot read it as a
pass. See [Troubleshooting](troubleshooting.md#requested-checks-completed-but-part-of-the-code-was-not-analyzed).

### What does `P(real)` mean?

It is a calibrated estimate of how often findings like this one turned out to be real. websec labels
findings from a corpus of deliberately vulnerable apps, groups them by attack class and confidence,
and reports the measured rate with a 95% Wilson confidence interval and the sample size `n`. When a
bucket has too little data it falls back to the per-confidence aggregate, then to a clearly labelled
uncalibrated prior.

Read it with its caveats: the corpus is deliberately vulnerable, so rates skew **optimistic** for
clean production code, and small samples mean wide intervals. The interval is more informative than
the point estimate. Severity, analyzer confidence and `P(real)` are separate signals, and every
finding is a lead to verify, not a confirmed vulnerability. Details are in
[METHODOLOGY.md](METHODOLOGY.md) (Layer 3b) and [BENCHMARKS.md](../BENCHMARKS.md).

### Which languages and frameworks are supported?

See the [languages reference](reference/languages.md). Run `websec capabilities` for the offline
matrix of named profiles, their checks and their stated limitations in the version you have
installed. A language appearing there means specific named checks exist, not comprehensive coverage.
Source in languages without an analyzer is reported in `coverage.json` rather than silently treated
as clean.

### How is it different from Semgrep, Snyk or CodeQL?

It complements them rather than replacing them:

- With `--scan`, websec **runs** the scanners you have installed (Semgrep, Trivy, OSV-Scanner,
  Gitleaks, Checkov, and per-language tools) and de-duplicates their output into one ledger.
- With `--sarif <report>`, it **imports** existing SARIF 2.1.0 reports (for example from CodeQL)
  without re-running the analyzer, preserving each tool's own rule identities.
- What it adds is the layer around them: an attack-surface map, an access-control and tenant-boundary
  view, targeting for probes, citations, calibrated confidence, and a briefing an agent can act on.

There is no head-to-head precision or recall claim against other tools. [BENCHMARKS.md](../BENCHMARKS.md)
documents the comparison protocol and states that the comparison has not been run.

### A finding is wrong. How do I suppress it?

Use the narrowest tool that fits:

| Situation | Use |
|---|---|
| A whole directory is not your product (tests, fixtures, seed data) | `websec init` to scaffold `.websec-ignore` path entries, or `--exclude '<glob>'` per run |
| One specific finding is a confirmed false positive | A `fingerprint:<id>` line with a reason in `.websec-ignore`. The finding stays visible (and suppressed, not deleted, in SARIF) but stops gating. A line without a reason is ignored. |
| You want the detector fixed upstream | `websec feedback --fingerprint <id> --verdict false-positive --reason "…"`, then the false-positive issue template |

Suppression in `.websec-ignore` is auditable and never silent. See the
[triage and suppression guide](guides/triage-and-suppression.md).

## Using it

### Can I use it in CI?

Yes. Every run writes SARIF 2.1.0 for GitHub Code Scanning and other viewers. `--fail-on <severity>`
gates on findings, `--require-complete` gates on execution, `--diff <ref>` scopes a pull request to
changed files, and `--baseline` gates only on new, changed or reopened findings. Exit codes keep
"findings" (`1`), "usage error" (`2`) and "checks did not complete" (`3`) apart. A composite GitHub
Action is included. See [GitHub Actions](guides/ci/github-actions.md),
[other CI](guides/ci/other-ci.md) and [pre-commit and git hooks](guides/ci/pre-commit-and-git-hooks.md).

### Can I use it with Codex, Cursor, Gemini or other agents?

Yes. `AGENT-BRIEFING.md` is plain Markdown any agent can read. In addition:

- `websec install <host>` writes a standing instruction for `claude`, `cursor`, `codex`, `gemini`,
  `aider` or `generic` (an `AGENTS.md` block), per project or home-wide with `--user`.
- `websec mcp` runs an MCP server over stdio with typed tools (`websec_recon`, `websec_findings`,
  `websec_sarif`, `websec_briefing`, `websec_check_updates`) for MCP-capable clients.
- Claude Code users can install the plugin.

See the [AI agents guide](guides/ai-agents.md) and the [MCP reference](reference/mcp.md).

### Does it work on Windows?

CI runs on Linux only, and native Windows is untested. Use WSL. See
[Installation](installation.md#windows).

### Why is it stdlib-only, with zero runtime dependencies?

It is one of the project's stated guarantees ([SECURITY.md](../SECURITY.md),
[CONTRIBUTING.md](../CONTRIBUTING.md)): installing websec adds no third-party Python packages to your
environment, so the tool you run over your own code brings no dependency tree with it. External tools
are integrated by running them as separate processes when they are present, never by importing them.
`dependencies = []` in `pyproject.toml` is a ground rule for contributions.

### How do I keep it up to date?

`websec update-check` reads cached release metadata offline; `websec update-check --online` checks
PyPI after you approve it and installs nothing. Upgrade with your package manager. The CLI and the
Claude Code plugin update separately. See [Upgrade](upgrade.md).

## Project

### What license is it under?

MIT. See [LICENSE](../LICENSE).

### How do I report a bug or a security issue in websec itself?

Bugs, false positives and feature requests go through the GitHub issue templates. Vulnerabilities in
the tool go through private GitHub security advisories, not public issues. See
[Troubleshooting](troubleshooting.md#reporting-a-bug-or-a-false-positive) and
[SECURITY.md](../SECURITY.md).

### What is the "Guard family"?

Three tools by the same maintainer that each keep one kind of claim honest:
[DocGuard](https://github.com/raccioly/docguard) checks documentation against code,
[TestGuard](https://github.com/raccioly/testguard) checks that tests establish what they assert, and
websec-validator does the same for security findings by attaching evidence, a standard citation and a
calibrated probability to each one.

## See also

- [Quickstart](quickstart.md)
- [Glossary](glossary.md)
- [How it works](concepts/how-it-works.md)
- [Troubleshooting](troubleshooting.md)
- [METHODOLOGY.md](METHODOLOGY.md)

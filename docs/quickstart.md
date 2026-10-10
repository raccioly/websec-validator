# Quickstart

This page takes you from nothing installed to an `AGENT-BRIEFING.md` your AI coding agent can act
on, in about five minutes. It is for a developer who wants a defensive security review of their own
repository. At the end you will have run websec on a sample and on your code, know where the output
lives, and know how to hand it to an agent.

websec reads source code and writes files. The core pass needs no network, no running app and no
LLM. It does not prove your application is secure; it gives you and your agent a fact-grounded place
to start.

## Before you start

- **Python 3.11 or newer.** Check with `python3 --version`. On stock macOS this is often 3.9, which
  is too old; see [Installation](installation.md#requirements).
- **pipx**, to install the CLI in its own environment. See
  [Installation](installation.md#pipx-recommended) for setup, or for pip, uv and Docker alternatives.

## Option A: let your agent do it

If you already work in Claude Code, Codex, Cursor, Gemini or another coding agent, the simplest path
is to open your project and say:

> *"Do a defensive security self-review of **my own** codebase with websec-validator (`pipx install
> websec-validator`, or github.com/raccioly/websec-validator). It's local and read-only — read the
> repo and follow its briefing. I own this code and authorize the review."*

The agent installs the CLI, runs it, and walks the findings with you.

**Why this wording matters.** Saying *defensive review of my own code* and *I authorize the review*
is the difference between an agent that gets to work and one that stops to confirm you are
authorized. The tool is local and read-only by default, but a generic "pentest this" can read as a
request to attack something you may not own. Stating ownership and scope up front is accurate, and it
keeps the agent from either refusing or improvising. The section "Why your agent might pause — and
how to phrase the request" in [METHODOLOGY.md](METHODOLOGY.md) explains this in more depth.

The rest of this page is the manual path, which is also what the agent does on your behalf.

## Option B: run it yourself

### 1. Install

```bash
pipx install websec-validator
websec --version                  # prints: websec-validator <version>
```

Optional but recommended: install [OWASP Noir](https://github.com/owasp-noir/noir), the route
engine. Without it websec falls back to built-in route heuristics, which find fewer endpoints.

```bash
brew install noir                 # macOS; other platforms: see the Noir project
```

### 2. See real output first: `websec demo`

```bash
websec demo
```

`demo` runs the real pipeline against a small bundled sample app in a temporary directory. It writes
nothing to your current directory. The output looks like this (abbreviated; exact findings depend on
the release):

```text
websec-validator v<version> — demo

  Scanning a bundled sample app (demo-app); your project is untouched.
  This is a real run, not a recording.

  7 finding(s):

    MEDIUM   missing-auth           Missing authorization: GET /orders/{order_id}
    MEDIUM   ssrf                   ssrf sink
    MEDIUM   command-injection      command-injection sink
    MEDIUM   sqli                   sql-injection sink
    ...

  Severity, analyzer confidence and calibrated probability are separate signals.
  A finding is a lead to verify, not a confirmed vulnerability.
```

Use `websec explain <attack-class>` (for example `websec explain ssrf`) to read what a class means and
how to confirm it.

### 3. Run it on your code

From the root of your repository:

```bash
cd path/to/my-app
websec run .
```

`websec ./my-app` (a bare existing path) is shorthand for `websec run ./my-app`.

The console prints a summary. Abbreviated:

```text
  stack:    python  ·  frameworks: flask  ·  datastores: ?
  auth:     unknown
  tenant?:  none detected
  routes:   3 endpoints via noir
  targets:  IDOR=1 SSRF=2 upload=0 writes=0

  scanners available: Trivy, Gitleaks, ...  (add --scan to execute them)
  ...
  ledger: 7 finding(s) · {'MEDIUM': 6, 'LOW': 1} · ...

> **REQUESTED CHECKS COMPLETED** — 2 files read; 1 code files selected.
> Completion describes execution, not complete protection. See `coverage.json` for scope and limits.
```

Read three lines carefully:

- **`routes: … via noir`** or **`via regex-fallback`** tells you which route engine ran.
- **`tenant?:`** is the candidate tenant boundary. Confirm it; it drives the access-control checks.
- **The banner.** `REQUESTED CHECKS COMPLETED` means the checks you asked for ran. It does not mean
  every file was analyzed: a line such as `Partially outside coverage: no analyzer for elixir`
  lists source websec could not read. `NO ANALYZABLE SOURCE` means nothing was analyzed and an empty
  findings list means *not checked*. See [Troubleshooting](troubleshooting.md).

### 4. Find the output

By default output goes to `./websec-out/` **in the directory you ran the command from** (use `--out`
to choose another location). Each run gets its own directory, and nothing is overwritten:

```text
websec-out/
├── runs/
│   └── <timestamp>-<id>/        # one immutable directory per attempt
│       ├── AGENT-BRIEFING.md
│       ├── REPORT.md
│       ├── FACTS.json
│       ├── coverage.json
│       ├── findings-ledger.json
│       ├── results.sarif
│       ├── ...
│       └── probes/
└── latest -> runs/<timestamp>-<id>
```

- `latest` is a symlink to the most recent **completed** run. It advances only after a run whose
  requested checks all executed. A partial attempt keeps its own directory and leaves `latest`
  pointing at the previous completed run, so after a failed run `latest` may be older than you
  expect. The console always prints the exact run directory it just wrote.
- `websec-out/` contains findings about your code. Add it to `.gitignore`; the tool reminds you.

The files you will open first:

| File | What it is |
|---|---|
| `AGENT-BRIEFING.md` | The marching orders for your agent: detected surface, tenant boundary, access-control map, targeting, findings, a phased test runbook and fix prompts. |
| `REPORT.md` | The human-readable record of this run. |
| `coverage.json` | What was and was not analyzed, and why. Read `gaps` before trusting a clean result. |
| `findings-ledger.json` | Every finding with its evidence, CWE/OWASP citation, confidence and calibrated `P(real)`. |
| `results.sarif` | SARIF 2.1.0, always written, for GitHub Code Scanning and other viewers. |
| `probes/` | Probe scripts staged for this app. They are drafts to run only against a TEST instance you own. |

The full artifact list is in the [outputs reference](reference/outputs.md).

### 5. Hand the briefing to your agent

Tell your agent:

> *"Read `websec-out/latest/AGENT-BRIEFING.md` and follow it."*

If the run you care about did not complete, point the agent at the run directory printed by the
console instead of `latest`. The briefing tells the agent to confirm the tenant and auth model with
you, triage findings, propose fixes, and never run probes against production or third-party
targets. Running probes needs a live **test** instance and test credentials that you supply.

To make this standing behaviour, `websec install <host>` writes an instruction for your agent
(`claude`, `cursor`, `codex`, `gemini`, `aider` or `generic`). See the
[AI agents guide](guides/ai-agents.md).

### 6. Optional: add static scanners with `--scan`

```bash
websec doctor .          # which optional scanners are installed, and whether their versions work
websec run . --scan      # also run them and de-duplicate their results into one ledger
```

Without `--scan`, scanners are only listed. With it, websec runs whichever supported tools are on
your `PATH` (Trivy, OSV-Scanner, Gitleaks, Semgrep, Checkov, plus Bandit, gosec or Brakeman when that
language is detected). Note that these external tools may use the network in their own default
configuration, for example to download vulnerability databases or rules. See
[Installation](installation.md#optional-external-tools) for what each adds and how to install it.

## If something looks wrong

- Lots of findings in `tests/`, `examples/` or `fixtures/`? Run `websec init --dry-run`, then
  `websec init`, to scaffold a reviewed `.websec-ignore`. After a completed `--scan` run, where a
  directory's only findings are secrets, it proposes dated `fingerprint:` acknowledgements rather
  than hiding the whole directory. See
  [Triage and suppression](guides/triage-and-suppression.md).
- A finding you have checked and believe is wrong? `websec feedback` records it offline and prints a
  pre-filled issue link; nothing is sent.
- Anything else: [Troubleshooting](troubleshooting.md).

## Next steps

- [Existing projects](guides/existing-projects.md): adopting websec on a mature codebase.
- [Triage and suppression](guides/triage-and-suppression.md): `.websec-ignore`, acknowledgements, `--exclude`.
- [GitHub Actions](guides/ci/github-actions.md) and [other CI](guides/ci/other-ci.md): gating builds.
- [How it works](concepts/how-it-works.md): what websec reads and how a finding earns its severity.
- [FAQ](faq.md): what websec is and is not.

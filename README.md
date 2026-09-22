# websec-validator

[![CI](https://github.com/raccioly/websec-validator/actions/workflows/ci.yml/badge.svg)](https://github.com/raccioly/websec-validator/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/websec-validator)](https://pypi.org/project/websec-validator/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://pypi.org/project/websec-validator/)
[![Runtime deps: 0](https://img.shields.io/badge/runtime%20deps-0%20(stdlib%20only)-brightgreen)](#install)
[![SARIF 2.1.0](https://img.shields.io/badge/output-SARIF%202.1.0-orange)](#ci--enterprise-integration)
[![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

A senior pentester's "here's what to test and how" handoff — auto-generated from your repo, for your AI agent to execute.

<!-- docguard:quality negation-load off — "no LLM / no server / no running app / not a SaaS / never touches prod" is this tool's core positioning; defining it by contrast with the scanners-and-SaaS it deliberately is NOT is intentional, not a phrasing defect. -->

> Local-first security recon that **briefs your AI coding agent**. It does the deterministic
> half — read the repo, map the full attack surface, and stage a probe library tailored to what it
> found — then hands your agent (Claude Code, Codex, Gemini, Cursor) a marching-orders briefing.
> `websec run` needs nothing but the code; add `--scan` to also run and de-duplicate whichever
> static scanners you have installed. **Code in, artifacts out. No LLM in the tool, no server, no
> running app required.**

[![websec-validator demo](assets/demo.gif)](assets/demo.gif)

**New here?** Read the eight-page technical brief — what it reads, how a finding earns its severity,
what it refuses to say, and the field evidence:
**[raccioly.github.io/websec-validator](https://raccioly.github.io/websec-validator/websec-explained.html)**
· [PDF](https://raccioly.github.io/websec-validator/websec-explained.pdf). Every number in it is
asserted against this tree by `tests/test_explained_brief.py`, so it cannot drift silently.

It is *not* an autonomous scanner and *not* a SaaS. It's the missing front-half: the thing that
turns a repo into a precise, fact-grounded security brief an AI agent (with a human in the loop)
can act on — an auto-filled, repo-aware version of a senior pentester's "here's what to test and
how" handoff. How it works + the reasoning behind every check: [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md).

**Part of the Guard family**, three tools that each keep one kind of claim honest:
[**DocGuard**](https://github.com/raccioly/docguard) validates documentation against the code it
describes, [**TestGuard**](https://github.com/raccioly/testguard) checks that tests actually
establish what they assert, and websec-validator does the same for security findings — every
finding carries its evidence, its standard, and a calibrated probability that it is real.

## Getting Started — just point it at your repo

**Simplest: tell your AI agent.** In Claude Code (or any coding agent), open your project and say:

> *"Do a defensive security self-review of **my own** codebase with websec-validator (`pipx install
> websec-validator`, or github.com/raccioly/websec-validator). It's local and read-only — read the
> repo and follow its briefing. I own this code and authorize the review."*

It installs, runs, and walks the findings with you. There's nothing to host and no website — it's
local. (Phrasing it as a *defensive review of your own code* matters: it's the difference between an
agent that just gets to work and one that stops to confirm you're authorized — the tool is local and
read-only by default, but a generic "pentest this" can read as a request to attack something.) The
five ways to get there, all ending in the same `AGENT-BRIEFING.md` your agent acts on:

| Path | One-time setup | Then |
|---|---|---|
| **Tell your agent** (simplest) | — | say the line above |
| **CLI** (a terminal) | `pipx install websec-validator` | `websec run /path/to/your/app` |
| **Claude Code plugin** (slash) | `/plugin marketplace add raccioly/websec-validator`  →  `/plugin install websec-validator@websec-plugins` | invoke the **security-pass** skill, or just ask |
| **Any other agent** (Codex, Cursor, Gemini, Aider) | `pipx install websec-validator` | `websec install <host>` — see below |
| **Docker** (no install) | `docker build -t websec-validator .` | `docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/scan" websec-validator run /scan --out /scan/websec-out` |

**Teach any agent to use it — `websec install <host>`.** Point websec at whatever coding agent you
run and it writes the standing instruction (a skill file for Claude/Cursor, an idempotent marked
block in `AGENTS.md`/`GEMINI.md`/`CONVENTIONS.md` for Codex/Gemini/Aider/generic) so the agent knows
to run `websec` for a security review instead of improvising:

```bash
websec install codex          # or: claude · cursor · gemini · aider · generic
websec install cursor --user  # home-wide, applies to every repo
websec install status         # show what's installed
websec install codex --uninstall
```

Shared instructions preserve text outside a complete managed block. Install/uninstall refuses
ambiguous markers and foreign dedicated skill files; resolve ownership manually before retrying.
The generated instructions select `websec-out/runs/<generated>/` from the current JSON envelope,
keep incomplete results visible, and reject stale `latest` or symlink aliases. The engine and plugin
are separate trusted inputs; neither is silently upgraded by the skill.

➡️ **Want the reasoning behind every check?** Read **[docs/METHODOLOGY.md](docs/METHODOLOGY.md)** — what each test does and why.

## Install

```bash
pipx install websec-validator   # from PyPI
brew install noir               # OWASP Noir — the route engine (50+ frameworks); regex fallback if absent
websec --version
```

_For bleeding-edge (unreleased changes), install straight from source instead:_
`pipx install git+https://github.com/raccioly/websec-validator` (or from a clone: `pipx install .`).

Requires **Python 3.11+** (on stock macOS, `python3` is often 3.9 — use `pipx`, which picks a newer
interpreter, or install via Homebrew/pyenv). Zero Python runtime dependencies: it shells out to
scanners (Trivy, OSV-Scanner, Gitleaks, Semgrep/OpenGrep, Checkov, Prowler) and Noir **when present**,
plus **per-language SAST auto-selected by stack** — Bandit (Python), gosec (Go), Brakeman (Rails) —
each fired only when its language is detected. It reports what's missing and never hard-fails if a tool
is absent.

### Or run via Docker (scanners bundled, zero install)

No need to install Noir or the scanners separately — the image carries a working set
(arch-aware, amd64 + arm64):

```bash
docker build -t websec-validator .
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/scan" websec-validator run /scan --out /scan/websec-out
```

The image carries Noir + Trivy + Gitleaks + Semgrep + Checkov — not the full list above, so
OSV-Scanner, Prowler and the per-language SAST tools (Bandit, gosec, Brakeman) are absent and are
reported as missing rather than silently skipped. Mount your repo at `/scan`; artifacts land in
`/scan/websec-out`.

## Usage

```bash
websec run ./my-app                    # ← the one command: recon + stage tailored probes + emit the briefing
websec ./my-app                        # same thing — a bare path defaults to `run`
websec run ./my-app --scan             # …and also execute the available static scanners
websec run ./my-app --scan --sbom      # …and emit a CycloneDX SBOM (sbom.cdx.json) for CI/compliance
websec run ./my-app --format sarif     # SARIF 2.1.0 to stdout (for piping into CI); also always written to the run dir
websec run ./my-app --fail-on high     # exit 1 if any HIGH+ finding remains (a CI gate)
websec run ./my-app --diff main        # PR mode: scope to changed files + exact hunk line ranges
websec run ./my-app --scan --verify-secrets   # opt in to TruffleHog LIVE secret verification (egress!)
websec doctor ./my-app                 # (optional) which scanners are installed?
websec emit-context ./my-app           # print recon as a Claude Code SessionStart context envelope
websec mcp                             # run as an MCP server over stdio (typed recon tools for any MCP client)
```

Then point your agent at the output: **"Read `websec-out/AGENT-BRIEFING.md` and follow it."**

### Prime *any* agent before it writes a line — the deterministic pre-brief layer

Other AI security tools make the LLM do the review from scratch (nondeterministic, per-run cost, PR-locked). websec runs **first**, deterministically, and hands the agent a scoped attack-surface map — so it can sit *underneath* an LLM reviewer and make it sharper, cheaper, and lower-FP. `websec emit-context` prints a compact `## SECURITY CONTEXT` block wrapped in Claude Code's `SessionStart` `additionalContext` envelope. Wire it into `.claude/settings.json` so every session starts pre-scoped:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "websec emit-context \"$CLAUDE_PROJECT_DIR\"" } ] }
    ]
  }
}
```

Now the agent knows your routes, auth model, tenant boundary, unguarded write endpoints, and dangerous sinks *before its first turn* — no LLM, same output every run. (`--markdown` prints the raw block for other harnesses.)

> Start with **`run`**. The optional workbench commands below expose capabilities, explicit threat-feed refresh, offline reassessment and research evaluation; **`dynamic`** performs authorized live testing. `recon`/`proof`/`calibrate` remain development commands.

## Scoping & suppression — keep the signal about *your* code

Most real repos vendor an input corpus: `tests/`, `examples/`, `fixtures/` — sometimes whole demo apps with planted fake credentials. Those are **not your product's attack surface**, and websec scopes them out of the way by default without hiding anything a real leak would need:

- **Fixture/example code is auto-scoped.** Test/example/fixture routes are split out of the attack surface (kept in `FACTS.json` under `fixture_endpoints`, counted in the console, not probed). Secrets found in fixture files are **demoted to LOW and annotated** — never dropped, because a real key pasted into a test is still a committed leak. Fixture package manifests don't drive framework detection (so a CLI that vendors an Express demo isn't misread as an Express app). Pass **`--include-fixtures`** to treat all of it as product code.
- **`--exclude '<glob>'`** (repeatable) drops a path from **both** recon and the static scanners (gitleaks/trivy/semgrep/checkov/osv-scanner). e.g. `websec run . --exclude 'tests/**' --exclude 'examples/**'`.

> **Two SCA engines cross-check each other.** With `--scan`, both **Trivy** and **OSV-Scanner** run: the same CVE from both collapses to one row tagged `tools: [trivy, osv-scanner]` (agreement → higher confidence), while OSV's broader lockfile coverage catches CVEs Trivy misses. Every CVE then flows through the reachability + EPSS/KEV enrichment above.
- **`.websec-ignore`** (repo root) — a committed, gitignore-style config for persistent scoping, so you don't re-type flags every run or in CI. Two kinds of line:

  ```
  # 1. path globs / category — DROP the finding entirely (it isn't your product)
  tests/
  examples/**
  category:supply-chain

  # 2. fingerprint acknowledgement — KEEP the finding, shown but NOT gating.
  #    A reason is REQUIRED (a bare fingerprint line is ignored). The fingerprint
  #    is the stable id from findings-ledger.json.
  fingerprint:b9c7f23e49bdab85  # confirmed FP: this is the scanner's own detection pattern
  ```

  Path/category lines remove noise that isn't your code. **Fingerprint acks** are the clean home for "this specific finding is a confirmed false positive" — the finding stays in the report (section *1a. Acknowledged*) and in SARIF (as a suppressed result, so GitHub keeps it visible + attributable), but it's excluded from the gating total and won't trip `--fail-on`. Every suppression stays auditable; nothing disappears silently.

When most of a run's findings land in test/example code and there's no `.websec-ignore` yet, websec prints a one-line pointer to this section — it never edits your repo for you.

## Prioritization — reachable × exploitable (no cloud, no LLM)

A dependency CVE list is noise until you know *which ones matter*. With `--scan`, websec enriches every
dependency vulnerability along two deterministic, offline axes — the same "reachable AND exploitable"
signal commercial tools sell, minus the cloud:

- **Reachability** — is the vulnerable package actually **imported** in your first-party source, or just
  sitting in the lockfile? websec greps the real `import`/`require`/`from` sites and tags each CVE
  `imported` vs **`declared-only` (likely unreachable — verify)**. Declared-only vulns are the industry's
  #1 noise class (Snyk/Endor/Semgrep all converge here). Name-based and honest — a full call graph is out
  of model; unparsed ecosystems (Go, Rust…) are tagged `n/a` rather than guessed.
- **Exploitability** — each CVE is joined against a **local cache** of [FIRST.org EPSS](https://www.first.org/epss/)
  (exploit-probability) + [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  (known exploitation reports). These are prioritization inputs alongside application context.
  `websec intel refresh` explicitly downloads public feeds without sending project data. Snapshots
  record source hashes/dates and freshness; consumers remain offline. Legacy flat caches are unverified.

Both are **strictly additive**: they annotate and re-rank, but never change a finding's severity, drop
one, or add one — so they can only sharpen triage, never reintroduce a false positive.

## Aim the pentest instead of competing with it

Dynamic scanners re-discover at runtime, expensively, much of what is already visible in the source.
websec knows it statically, so it aims them:

- **§4b — what a DAST *will* report, before you run one.** Each static finding is mapped to the concrete
  scanner signature it produces (`missing-csp` → ZAP 10038/10055, `sqli` → ZAP 40018 / sqlmap, `ssrf` →
  Nuclei OAST…) with the source location that causes it. Fix those and the scan comes back clean on them
  — the run becomes *confirmation*, not discovery.
- **§4b also lists the blind spots.** BOLA, missing-auth, mass-assignment, RLS gaps, JWT alg-confusion,
  committed secrets, supply-chain — with *why* no scanner finds them. A clean scan is not "safe", and
  saying so is the point.
- **§5b — a phased, pre-aimed runbook.** Phase 1 safe recon → Phase 2 authz (two identities, the
  scanner-blind class) → Phase 3 injection, fired only at sink-backed endpoints and gated behind an
  explicit authorization warning. Every item names a real target and a confirm/disconfirm oracle.
- **Close the loop:** `websec calibrate --ingest-dast zap.json --ledger findings-ledger.json` feeds a real
  scan back — confirming or refuting each prediction — so `P(real)` personalizes to your app over time.
  Blind-spot classes are never scored: a scanner's silence there means nothing.

## What it extracts (22 deterministic extractors, no LLM)

| | Dimension | Notable output |
|---|---|---|
| stack | languages, frameworks, datastores | manifest-aware service inventory, including Rust workspaces; declared hints do not prove deployment |
| routes | every endpoint via **OWASP Noir** (+ Supabase-edge, **AWS SAM / Function-URL**, **raw `http.createServer`/`Bun.serve`/py `http.server`**) | method · path · typed params · code path · **AuthType:NONE public endpoints**; **fixture/example routes split out of the attack surface** |
| auth | scheme + login surface + **insecure-default signing secrets** + **broken-auth backdoors** | multi-scheme; flags a hard-coded `JWT_SECRET \|\| 'dev-secret'` fallback (forgeable JWT), a **`dev-`token / accept-any-password backdoor** (total bypass, CRITICAL), and a **fail-open** `if(env.SECRET)` signature check |
| **authz** | access-control map | guard coverage (incl. **router-mount auth**) + **write endpoints with no visible guard** + roles |
| **authz_dataflow** | authz *correctness* (does the guard trust the right thing?) | **unsigned-cookie authorization** · **claim-keyed authz** (user-influenceable JWT claim) · **transaction-local RLS context** (resets before the query) |
| tenant | multi-tenancy key candidates | the BOLA boundary, by frequency |
| **password_policy** | cross-route consistency **+ reuse/history** | complexity drift across routes **+ a set-password path that hashes without a reuse check** |
| surface | 17 sink classes **+ redirect-SSRF** | user-input-gated sinks (incl. **mass-assignment via object spread**, **reflected/DOM/template XSS** — `innerHTML`/`dangerouslySetInnerHTML`/`v-html`/`\|safe`, sanitizer-gated, and **log-injection** (CWE-117, structured-logging-suppressed)) + var-arg SSRF + error-disclosure + follows-redirects-without-per-hop-guard **+ reverse-proxy prefix-escape + host-header open-redirect + SSRF-redirect-hardening** |
| **upload_security** | unrestricted upload + unsafe serve | deny-list-only, stored-name-from-filename, trust-client-MIME, accept-SVG, **serve without `nosniff`** |
| schemas | data models + **privileged fields** | Pydantic/SQLAlchemy/Django/Prisma/Mongoose/TypeORM/Zod → `role`/`isAdmin`/`groupId` for mass-assignment targeting |
| iac_ci | IaC + CI/CD | GHA injection (**run:-position-aware**), unpinned actions, tfstate, CDK AppSync `API_KEY` anonymous-default-auth, **docker-compose host-takeover (docker.sock / pid:host / privileged) + `.gitleaksignore` secret-suppression audit** |
| client_exposure | browser leakage | public-var secrets by **name + value-shape (`da2-…`) + CDK build-injection**, server-secret-in-client, source maps |
| **client_integrity** | tamperable display (client trust boundary) + **WS auth model** | any security-critical sink value (address/IBAN/2FA-seed/API-key/webhook) the user reads or copies, without strict CSP / out-of-band anchor **+ client-tamper-vector, grindable-fingerprint, over-claimed-control, the CSWSH determinant** |
| **transport_security** | CSP + HSTS + **CORS** + **SRI** + **clickjacking** + **CSRF** baseline | missing/weak CSP, inline event handlers, partial HSTS, **CORS reflect-origin+credentials, external script without SRI, monorepo `next.config` header gap, framework-agnostic clickjacking (no X-Frame-Options / `frame-ancestors`), CSRF (cookie-auth + no token lib + no SameSite)** |
| **pii_exposure** | unmasked PII at the output boundary | `res.json(rawEntity)` with PII + **a masking control defined but with zero live call sites** (value-shape, not field-name) |
| graphql | GraphQL surface | introspection (**AppSync `introspectionConfig: DISABLED`-aware**) / playground / depth-limit **+ AppSync subscription-authz (cross-group BOLA)** |
| integrations | third-party + webhooks **+ outbound-action endpoints** | unsigned webhooks **+ email/SMS/push handlers with no auth or IP-only rate-limit + redundant secret-fetch** |
| **llm_security** | LLM / AI-agent surface (**OWASP LLM Top 10**) | indirect **prompt injection** (untrusted RAG/tool content → prompt) · **insecure output handling** (model text → tool dispatch) · **excessive agency** · **unbounded generation** (no maxTokens/timeout) · **guardrail fail-open** |
| **crypto_usage** | crypto-API correctness | **weak password hash** (fast/unsalted SHA-256/MD5) · `jwtVerify` without an `algorithms` allowlist · **predictable principal** (id = hash of email) · non-constant-time secret compare |
| **agent_config** | the repo's OWN agent/MCP wiring (**OWASP Agentic Top 10**) | reads `.claude/settings.json` · `.mcp.json` · cursor/copilot rules as untrusted data (never executed): **invisible/bidi Unicode** rules-backdoor · **fetch-and-execute hook** (CVE-2025-59536) · **blanket MCP auto-approve** · **`*_BASE_URL` override** (key-exfil) · **unpinned MCP server** · **committed secret in an MCP `env`/`headers` block** (value-shape, `${VAR}`-safe) |
| **dependencies** | offline supply-chain hygiene (AI slopsquat class) | **malicious install/lifecycle script** (fetch-and-exec `postinstall`) · **lockfile drift** (manifest dep absent from the lockfile) · unpinned + dependency-confusion names (advisory-only) · registry/typosquat resolution behind opt-in `--network` |

Plus **derived targeting** — IDOR / SSRF / open-redirect / upload / write / auth-endpoint
candidates — so probes get pointed at the *exact* endpoints, not fired blindly.

## What you get (`websec-out/`)

| Artifact | What it is |
|---|---|
| `AGENT-BRIEFING.md` | **The product.** Marching orders: detected surface, the access-control map, targeting, findings, the method, and the staged probe list. |
| `FACTS.json` | The full structured recon. |
| `findings.json` | Static scanner results, **de-duplicated across tools** and severity-ranked (with `--scan`). |
| `findings-ledger.json` / `REPORT.md` | The traceable ledger: each finding with an evidence chain, CWE/ASVS/OWASP-API citation, remediation, and a **calibrated `P(real)`** (measured real-vuln rate + 95% CI + sample size). |
| `results.sarif` | **SARIF 2.1.0** — always written. Drop it into **GitHub Code Scanning** (inline PR-diff annotations + the Security tab), GitLab, Azure DevOps, VS Code's SARIF viewer, DefectDojo. |
| `findings.envelope.json` | A **versioned, self-describing** JSON envelope (`schema_version`) around the ledger — for non-GitHub CI / dashboards that shouldn't reverse-engineer the internal shape. |
| `sbom.cdx.json` | A **CycloneDX SBOM** (with `--sbom`; `--sbom spdx` for SPDX) — the dependency inventory for SLSA / EO 14028 supply-chain gates, and the substrate a downstream scanner can rescan without re-walking the tree. |
| `attack-surface.json` | The ranked per-endpoint planning table (routes × auth × sinks × risk + the reasons) — briefing §3a. |
| `diff-scope.json` | With `--diff`: changed files + exact added/modified line ranges, so any reviewer can validate a finding sits on a changed line. |
| `probes/` | The probe scripts selected + staged for *this* app (BOLA, JWT, SSRF, mass-assignment…). |

## The flow

```
🔧 websec (deterministic)              🤖 your agent + 🧑 you
─────────────────────────────────      ─────────────────────────────────
1. recon → full attack surface     →   confirm the tenant boundary + auth model
2. de-dup scanners (--scan, opt-in)→   triage real-vs-noise
3. stage tailored probes           →   fill placeholders, run vs a TEST instance
4. emit AGENT-BRIEFING.md           →   propose fixes, re-run to confirm, report back
```

Static recon + briefing need **only the code**, and run without `--scan`. *Running* the probes needs a live test instance +
test credentials (the human supplies them) — the tool itself never touches a running app.

## CI / enterprise integration

The recon is the same either way — these just make the output consumable by pipelines, dashboards, and
non-Claude agents. All stdlib, no new dependency.

**SARIF → GitHub Code Scanning.** Every `run` writes `results.sarif` (SARIF 2.1.0). Upload it and each
finding lands **inline on the PR diff** and in the **Security tab**, ranked by a security-severity band,
with its CWE/ASVS/OWASP citation and remediation.

**Gate the build.** `--fail-on {critical,high,medium,low}` fails CI on matching findings;
`--require-complete` gates execution without a severity threshold. Extractor failures, source read
loss/caps, invalid scanner reports, timeouts, and explicitly selected missing scanners remain visible
in `coverage.json`; partial artifacts are preserved. Optional missing unselected scanners are reported
as unavailable. `--scanners` requires `--scan`.

**Exit codes tell you WHICH kind of failure.** "You have a vulnerability" and "my toolchain is
broken" need opposite responses — one blocks the merge, the other pages whoever owns the runner
image — so they never share a code:

| Code | Meaning | What to do |
|------|---------|------------|
| `0` | the gate ran and nothing met the threshold | ship (it does not prove protection) |
| `1` | findings at or above `--fail-on` | a fact about the code — fix the findings |
| `2` | usage/configuration error, or `websec doctor` found an incompatible scanner | nothing was scanned; fix the invocation or the toolchain |
| `3` | requested checks did not complete | the gate result is **not** a pass; read `coverage.gaps` for which check did not run |

A run that is **both** gate-failing and incomplete exits `1` — the definite fact wins — and says so
on stderr, because the finding count in that case is a floor, not a total. `gate.failure_kind` in the
ledger records the exact combination (`findings` · `incomplete` · `findings+incomplete`), so nothing
is lost by the collapse.

> **Upgrading:** exit `2` previously meant *incomplete execution*. It now means *usage/configuration
> error*, and incomplete is `3`. A CI job that tested for `2` to detect an incomplete run should test
> for `3` (or read `coverage.execution_complete`, which is unchanged).

**Naming a scanner requires it.** `--scanners` is not only a subset filter: a scanner you select but
have not installed is an incomplete run, not a clean one. `websec run . --scan --scanners trivy,osv-scanner
--require-complete` exits 3 with `trivy: unavailable` in `coverage.json`, so a CI job whose scanner
install failed fails instead of reporting zero findings from a scan that never ran.

**Presence is not compatibility — `websec doctor` version-checks.** A scanner can be installed,
detected, selected, run, and still produce nothing because its CLI does not match the invocation
websec builds; that silence is indistinguishable from a clean result. `doctor` now reports each
scanner's version, marks one that is too old for our invocation, and exits `2` when any selected
scanner is incompatible — so a CI preflight can gate on the toolchain before it trusts a scan.

**Scope the noise at setup, not after the first report.** `websec init` walks the repo, finds the
directories that are not your product (`backend/capacity-test/`, `seed/`, `fixtures/`, `vendor/` …),
and writes a `.websec-ignore` where every entry carries the file count that justifies it. It prints
every proposal before writing, supports `--dry-run`, and refuses to overwrite an existing policy file
without `--force` — that file may hold reviewed `fingerprint:` acknowledgements.

**One issue, N sites.** Thirteen findings from one `jwtSecret` pattern and twenty-two blobs from one
deleted-file incident are six issues, not thirty-five. The ledger carries a `clusters[]` view (and
REPORT.md a §1a section) that groups findings by rule, and history-only secrets by the commit that
removed them. It is a **view, not a filter**: `total`, `--fail-on` counts, per-site fingerprints,
SARIF results and baselines are all untouched, so every site still gates on its own.

**Secrets say where they live.** Every gitleaks finding carries `in_tree`; a finding whose file is
gone from the working tree is labelled `in-tree: false` with the commit it was last seen in. Deleting
a file does not un-leak it — the blob stays fetchable — so the remediation is *rotate*, and the report
says that instead of leaving you to run `git log`.

Every attempt receives a unique directory under `websec-out/runs/`. The atomic `latest` pointer
advances only after a completed execution has written its artifacts; a partial attempt retains its
own directory and leaves the previous completed scan selected. Completed execution describes the
requested checks, not complete protection against vulnerabilities.

**Reuse specialist analysis (0.14.0).** Import existing SARIF without executing
the analyzer or loading any source path/URL referenced by its report:

```bash
websec run ./my-app --sarif ./codeql.sarif --sarif ./other-analysis.sarif --require-complete
websec run ./my-python-app --scan --scanners bandit --fail-on high
```

SARIF 2.1.0 import preserves native tool/rule identities, traces and report hashes in
`sarif-imports.json` and the unified ledger. Safe relative paths are supported; unknown analyzer
execution, malformed references and caps are visible incomplete checks. Native suppressions remain
metadata until locally acknowledged. Source freshness stays unverified, and imported absence cannot
verify a repair. Unique producer fingerprints remain stable; collisions are deliberately report-bound.

Bandit is an optional preinstalled executable. The adapter uses built-in defaults, bypasses target
configuration and ignores `nosec`; its native confidence and CWE remain separate from severity.
Source-cache payloads have a 64 MiB per-context budget, with read loss visible in coverage. These
budgets constrain input retention, not the entire Python process's memory usage.

**Review changes against a baseline.** `--baseline <prior findings-ledger.json>` tracks new,
unchanged, changed, reopened, and no-longer-observed findings using versioned semantic identities.
New, changed, and reopened findings participate in the severity gate. Disappearance means only
“no longer observed”; it does not prove a repair. Expired or malformed dated acknowledgements reopen
for review. Legacy fingerprints remain migration aliases; ambiguous aliases cannot hide distinct
occurrences. A malformed or unreadable supplied baseline makes requested execution incomplete.

`repair-plans.json` binds each remediation plan to its original application, source digest, finding,
and detector scope. This command validates operator-supplied positive and negative reports:

```bash
websec repair-verify --plan plan.json --record record.json --rerun findings-ledger.json --evidence-root ./evidence
```

Verification requires a
hashed failing negative report for the original build. Reports must identify the same plan, finding,
test and intended build; the rerun must be complete with unchanged review scope. The command validates
artifacts offline and never executes their commands. Acceptance is evidence validation, not independent
execution of tests by websec. See the [validated evidence examples](docs/security-review/examples/README.md)
for exact dynamic, DAST and repair artifact fields.

**GitHub Action** ([`action.yml`](action.yml), 0.14.0): the action installs
its own trusted checkout, passes inputs as data and uploads the exact current attempt's SARIF,
including incomplete attempts. `require-complete` defaults to true; `scanners` names explicitly
required tools when `scan: true`. Outputs expose `run-directory`, `sarif-file` and `execution-complete`.
Keep the reviewed action checkout separate from untrusted target source. Pin a reviewed 0.14.0-or-later commit when adopting these changes; the historical v0.13.0 tag
does not include them.

**Audit evidence — `websec attest`.** Projects an existing run into a per-control evidence table.
It computes nothing and asserts nothing.

```bash
websec attest                      # latest run, human-readable
websec attest --format json
websec attest --format in-toto     # UNSIGNED Statement — sign it with your own key
```

**Gaps are listed before evidence**, in the data and in the output, because a table that leads with
coverage invites absence to read as satisfaction. On a typical run, 5 of 12 rows have no websec
evidence at all — most of these controls are organisational and the artifact says so.

It renders no verdict, score, percentage or badge, and the word "compliant" does not appear in any
output format (there is a test). Compliance is an attribute of an assessed *entity*, determined by a
qualified assessor and evidenced by their report — PCI SSC FAQ 1258: *"no single product can provide
PCI DSS compliance"*. Three things are declared non-goals in the artifact itself: approver
independence (it lives in the forge's approval record), rollback, and PCI 6.4.2 runtime protection.
The output also states that the local gate is bypassable and that its bypass record is not
exhaustive.

Citations are exact, because the obvious ones are wrong. EU DORA change management is **Commission
Delegated Regulation (EU) 2024/1774 Art. 17** (the RTS under DORA Art. 9(4)(e)); DORA Art. 17 itself
is incident management. There is **no SOX article** for ITGC — the domains come from SEC Release
33-8810 §II.A.2.d. PCI DSS **6.2.3 permits automated review**, and **6.2.3.1 is conditional** on
choosing manual review, so websec is deliberately not offered against it.

The in-toto Statement is unsigned by design: a websec-signed attestation would only attest that
websec ran. Sign it with your own key and identity and it becomes verifiable.

**Dependency existence — `websec run --network` (opt-in).** Offline checks cannot tell whether a
declared package actually exists, which is the AI-hallucinated-dependency surface.

```bash
websec run . --network-dry-run    # print the exact names that WOULD be sent; sends nothing
websec run . --network            # HEAD registry.npmjs.org / pypi.org; ~2.8s for 52 deps
```

Only bare package **names** are sent — never versions, paths or repository identity. Suppression is
applied **offline, before any request**: names this repo publishes (via the real workspace graph),
scopes bound to a private registry in `.npmrc`/`.yarnrc.yml`, and pip `index-url` overrides. A
private name that reaches a public registry cannot be un-sent, and a 404 on an internal name tells
an attacker which name to squat.

A 404 is split by offline lockfile evidence: `resolved` + `integrity` means the package once
existed, so it is `dependency-unpublished-or-removed` (a package pulled for malware looks exactly
like this) rather than `dependency-nonexistent`. Findings are MEDIUM/LOW-confidence and do **not**
fail `--fail-on` unless you also pass `--fail-on-network` — the UNKNOWN rate is outside your
control, so gating on it would make registry uptime a dependency of shipping. UNKNOWN is recorded
as a coverage gap, never as clean.

**A 200 is not evidence of safety.** A squatter who has already registered the hallucinated name
also returns 200 — that is the successful attack, not the clean case.

**Agent-loop gate — `websec gate` and `websec hooks install --agent`.** Scanning at the merge
request makes a finding a backlog item; scanning on the edit that caused it makes it a retry the
agent fixes immediately.

```bash
websec gate                          # the files you just changed, ~0.3s, exit 1 if blocking
websec gate --fail-on high           # default is medium (see below)
websec hooks install --agent         # PostToolUse hook: runs the gate on every file the agent writes
websec hooks status --agent
websec hooks uninstall --agent
```

`gate` scopes the **analysis**, not just the report: `--only` narrows what is read and matched
(~13x faster than a full pass), while the tree is still walked in full so stack detection, ignore
policy and fixture classification are unchanged. Its default scope is the **working tree** —
tracked modifications plus untracked files — because agent edits are uncommitted and a three-dot
`base...HEAD` diff would see nothing. It writes no artifacts, publishes no run directory and never
advances an accepted baseline.

The default threshold is **medium, not high**: command injection and SSRF on agent-written code are
frequently rated MEDIUM, so a HIGH default would miss the main case. `--min-confidence` filters
low-confidence leads for teams that measure them as noisy; there is no confidence floor by default,
because in the loop a false block costs one turn while a miss ships.

Three deliberate properties of the hook:

- It **fails open, loudly**. If the gate cannot run, the hook exits 0 and says on stderr that the
  edit was *not* security-checked. A check that blocks every edit when broken gets uninstalled, and
  then there is no check at all. A pass means "nothing blocking was found", never "this was verified".
- It does **not** honour `WEBSEC_SKIP_HOOK`, unlike the git guardrail below. The agent can set an
  environment variable in a Bash call, so an env escape hatch here would be one the agent operates.
- It is **developer ergonomics, not a compliance control.** Settings files are editable by the user
  and, in a repository the agent can write to, by the agent. Only managed policy settings deployed
  through device management are genuinely unbypassable. This hook catches mistakes early; it cannot
  evidence that it ran for every change, and should not be presented as though it could. For
  enforcement, run `websec run --fail-on …` as a required status check.

A scoped pass is a fast retry signal, not a review: it does not consult cross-file evidence outside
the scope, and a clean result does not mean the repository is clean. Keep running the full pass.

**Local guardrail — `websec hooks`.** Advisory and gating runs have separate responsibilities:

```bash
websec hooks install              # advisory post-commit; prints outcome and current artifact path
websec hooks install --pre-push   # severity gate (default high) plus complete-execution check
websec hooks status
websec hooks uninstall
```

A successful pre-push gate accepts a ledger under its severity/scanner policy. Advisory runs and
failed gates never advance that accepted baseline. The first gate, or a changed policy, checks all
current findings; later gates compare against the accepted ledger. Retrying an unchanged failed gate
continues to fail. `WEBSEC_HOOK_FAIL_ON` changes the threshold; `WEBSEC_HOOK_SCAN=1` executes scanners,
and `WEBSEC_HOOK_SCANNERS` selects required adapters. The default is recon-only.

Hooks launch isolated Python bound to the trusted installed package path, including editable source
installs. They preserve existing shell hooks and refuse automatic insertion into non-shell hooks.
`WEBSEC_SKIP_HOOK=1` is an explicit one-off override. Native hooks inspect the current working tree,
not immutable snapshots of every pushed Git object. A missing runtime or concurrent incomplete gate
blocks pre-push; post-commit remains advisory.

**MCP server (any agent, not just Claude Code).** `websec mcp` speaks the Model Context Protocol over
stdio, exposing typed tools — `websec_recon`, `websec_findings`, `websec_sarif`, `websec_briefing` — so
Cursor / Cline / Windsurf / Zed can call recon directly instead of shelling out and parsing stdout.
Register it in your MCP client:

```json
{ "mcpServers": { "websec": { "command": "websec", "args": ["mcp"] } } }
```

The optional HTTP transport is loopback-only and requires `WEBSEC_MCP_TOKEN` at startup:

```bash
# Supply WEBSEC_MCP_TOKEN through your local secret environment.
websec mcp --http --allow-root /absolute/path/to/project
```

Repeat `--allow-root` for additional projects; otherwise the startup directory is the allowed root.
JSON-RPC requests require the bearer token. Host/Origin validation, framing and body limits, bounded
workers, and an absolute receive deadline constrain the HTTP boundary. `GET /health` remains a
minimal liveness endpoint. Non-loopback binding is refused. Stdio uses the launching process's trust
and filesystem permissions.

**Blast-radius from a knowledge graph (opt-in, zero-dep).** If your repo has a
[`graphify`](https://github.com/Graphify-Labs/graphify) graph at `graphify-out/graph.json` (or you
pass `--graph <file>`), websec tags each finding with how much of the app **transitively depends on**
the vulnerable code — so a SQLi in a leaf handler and the same SQLi in a helper imported by 40
modules stop looking equally urgent:

```bash
websec run . --scan     # auto-detects graphify-out/graph.json if present
```

Each mapped finding gains a `graph` block (`blast_radius`, a `dependents` sample, `community`) in
`findings-ledger.json`, and the ledger a `graph_enrichment` summary. It reads the graph as plain
JSON — it never imports tree-sitter, so websec stays **stdlib-only, zero runtime deps** — and a
missing implicit graph is optional. Invalid implicit graphs produce a visible diagnostic; an explicitly
requested malformed, unreadable, excluded, or oversized graph makes requested execution incomplete.

**Versioned contract.** `FACTS.json`, `findings-ledger.json`, and `findings.envelope.json` all carry a
`schema_version: "2.0"`; JSON Schemas ship in the package (`schemas/facts.schema.json`,
`schemas/ledger.schema.json`, `schemas/coverage.schema.json`). Coverage is embedded in facts, ledger,
and envelope, with SARIF execution status reflecting partial checks. Fingerprint V2 preserves V1
migration aliases. SARIF lifecycle states use its legal enum and retain richer lifecycle metadata in
properties. `.websec-ignore` is read from the selected target by default, through the same contained
read policy; an unrelated working directory no longer contributes implicit suppressions.

## Named profiles and the research workbench

```bash
websec capabilities                                  # offline profile/check/limitation matrix
websec demo                                          # real scan of a bundled sample; writes nothing here
websec explain bola                                  # what a class means + how to confirm it
websec explain --list                                # every attack class this build cites
websec feedback --fingerprint <fp> --verdict false-positive \
  --reason "behind an nginx auth_request"            # report a wrong detector; metadata-only, sends nothing
websec intel status                                  # offline freshness and provenance
websec intel refresh                                 # explicit public FIRST/CISA downloads
websec intel reassess --ledger prior-ledger.json --out reassessment.json
websec research catalog                             # discover shipped suites without evaluating
websec research evaluate --suite control-scope --out suite-evaluation.json
websec research example --out proposal.json           # current detector-bound synthetic example
websec research evaluate --proposal proposal.json --out evaluation.json
```

`--out` writes a new JSON file and refuses existing files. Intel commands accept `--cache-dir`;
status and reassessment never fetch automatically. Reassessment updates known CVEs while preserving
source evidence and finding identities. Newly exploited or materially higher-risk acknowledged CVEs
can reopen for review. A detector change requests a source rescan; stale/unavailable intelligence
remains explicit and reassessment exits 2. Discovering new dependency CVEs requires a fresh inventory
and advisory scan; unchanged-source reassessment is not such a scan.

The capability matrix exposes nine bounded profiles:

| Profile | Named checks | Main limits |
|---|---|---|
| Java/Spring | Direct request-to-command/query syntax; literal Spring routes | No binding resolution, aliases or cross-function flow |
| .NET | Direct command/raw-query syntax; literal ASP.NET routes | No framework convention or route-group resolution |
| Go | Direct command/query arguments, including context variants | No indirect request aliases or full data flow |
| Ruby | Direct command/raw-query syntax with parameterized forms distinguished | No whole-Rails authorization or dynamic metaprogramming analysis |
| PHP | Direct command/query request reads | No whole-application flow analysis |
| Android | Explicit manifest cleartext setting | Network-security configuration, manifest merges and API levels need review |
| iOS | Explicit ATS exception keys | Scope and OS precedence need review; not proof of an insecure connection |
| Rust | Explicit reqwest invalid-certificate acceptance | Receiver/binding and runtime reachability remain unverified |
| C/C++ | Source inventory and manual memory-safety review | No automated memory-safety analysis |

Nearest manifest boundaries identify services and keep their route/datastore evidence separate.
Coverage records each selected check as completed, unknown or manual, with examined counts and
limitations. Invalid analyzed configuration is an execution error. A language label or a completed
no-match check does not mean comprehensive support or a secure service.

Research proposals are data-only, provenance-described candidates evaluated against an allowlist of
shipped detectors. Source snippets become disposable text fixtures and are never executed. Results
separate development/holdout TP/FN/TN/FP/unknown counts. Passing means **eligible for human review**,
not automatic detector promotion. The authored synthetic holdout is regression evidence, not a
statistically independent production benchmark or proof of competitor superiority.

## Proof harness

`websec proof` clones a vuln-app corpus (VAmPI, NodeGoat, DVGA) and scores whether recon surfaces
each app's documented attack surface — a deterministic, CI-trackable proxy (historical **10/10**, not rerun for this detector revision).
The real kill-criterion (does the briefing lift an agent's bug-finding vs a generic prompt?) is the
manual A/B in [`corpus/PROOF-PROTOCOL.md`](corpus/PROOF-PROTOCOL.md). Full methodology, calibrated
precision numbers, and the competitor-comparison protocol: [`BENCHMARKS.md`](BENCHMARKS.md).

## Calibrated confidence

`websec calibrate` runs the ledger against the labeled corpus, measures how often each
*(attack-class, confidence)* bucket is a **real** documented vuln, and writes `calibration.json`
(shipped + applied at runtime). Each finding then carries `P(real)` with a **95% Wilson confidence
interval** and the sample size `n` — so "MEDIUM" stops being a vibe and becomes "real ~57% of the
time on the historical corpus (CI 43–70%, n=51)". Unmatched findings now remain **unknown**,
unless explicit negative evidence labels them false. Historical measurements using unmatched-as-false
labels are not a fresh measurement of this detector revision. **Honest caveats:** the corpus is *deliberately
vulnerable*, so the rates skew **optimistic** for clean production code, and small samples mean
**wide intervals** — the CI is the headline, not the point estimate, and both tighten as the corpus
grows. With thin data a bucket falls back to the per-label aggregate, then to a clearly-flagged
uncalibrated prior. No ML, no deps — binomial proportion + Wilson interval; the structure upgrades to
isotonic regression if a large labeled set ever exists.

**Evidence controls learning.** Dynamic status codes and scanner silence are observations, not
truth labels. Only evidence-backed labels are admitted to the local calibration overlay; legacy
unproven samples are quarantined. Unknown-only input reports no successful measurement and leaves
existing fitted calibration unchanged. A DAST hit may confirm a scoped lead; absence from a report
cannot refute it. Manual labels should include reviewer/evidence provenance, not only a boolean.

**Shared format.** `websec calibrate --claimspec PATH` (or `-` for stdout) exports the table the
runtime actually uses — shipped corpus table plus your local overlay, merged — as a
[claimspec](https://github.com/raccioly/testguard/tree/main/spec) v1 `calibration` document, the
Guard-family interchange format. Nothing is lost in translation: the caveat, limitation, evidence
status, `minN` floor, the per-confidence backoff tier and the labelled uncalibrated prior all travel
with the numbers (`measures: finding-real`, `bucketBy: attackClass|confidence`). Each cell carries
raw `n` and `positives`, so a consumer can recompute `p` and the Wilson interval and merge two
tables by summing counts — the only merge the spec allows. `source.kind` says where the labels came
from: `human-label` for the shipped table, `tool-oracle` for an overlay-only table, `mixed` once
your samples are folded in. The writer refuses to export a cell whose stored numbers do not
reproduce from its counts rather than emit a document the spec validator would reject. The
internal `calibration.json` shape and the local overlay are unchanged.

## Dynamic phase (v2 — read-only so far)

When you have a *running TEST instance*, `websec dynamic` mints role tokens and runs the probes the
static recon pointed at. v1 is **read-only**: authenticated **cross-tenant BOLA** on the group-scoped
GET endpoints recon discovered.

```bash
cp dynamic-config.example.json dynamic-config.json    # TEST target + role creds (gitignored)
websec run ./my-app                                    # static recon → websec-out/latest/FACTS.json
websec dynamic --config dynamic-config.json --facts websec-out/FACTS.json
# → "14/14 cross-tenant GET reads blocked — all isolated"   (or 🚨 LEAK with the exact endpoint)
```

Never point it at production. Write-verb BOLA, JWT/auth attacks, and a ZAP/Nuclei two-role diff are
the next dynamic probes (explicitly gated — they mutate).

## Validated on

A production Next.js app, a large Express/AWS monorepo, and the VAmPI / NodeGoat / DVGA vuln-app
corpus — independently reproducing a hand-done pentest's findings (tenant boundary, SSRF, file
upload, cross-tenant BOLA, role/authz gaps).

## Tests

```bash
python3 -m unittest discover -s tests    # stdlib only; synthetic/local-loopback tests, no public network
```

## Releasing (maintainer)

The release train is PR-driven. Keep the version in `pyproject.toml` as the single source of truth,
add the matching dated changelog and migration guidance, and validate the combined release branch.
In the 0.x series, feature additions or incompatible contracts increment the minor version.

After reviewing current main and overlapping PRs, merge the approved release PR only after its
required CI checks pass. The resulting main commit subject must be `release: v0.16.0` for this
release. [release-tag.yml](.github/workflows/release-tag.yml) validates that subject against the
package version, creates the matching tag/GitHub Release, and explicitly dispatches
[publish.yml](.github/workflows/publish.yml) at that tag. A version edit alone does not publish.

The publish workflow builds and installs the wheel, verifies its version and smoke test, then uses
PyPI Trusted Publishing through the `pypi` environment. Verify the completed workflow, tag,
GitHub Release and PyPI artifact before reporting publication success. Do not bypass failed checks
with manual tags, and do not describe a locally built wheel as published.

The CLI and Claude plugin have separate delivery paths: the CLI uses PyPI semver releases; the
plugin uses reviewed Git content and explicit marketplace refresh. Plugin manifests deliberately
omit an independent version field. Check both sources when diagnosing stale instructions.

## Status / roadmap

Version 0.18.0 provides 22 recon extractors, eleven optional scanner entries, nine named profiles,
SARIF import/export, bounded source/query analysis, explicit coverage and lifecycle evidence,
intelligence/research commands, and opt-in agent/hook/CI adoption. It adds an in-loop security gate
(`websec gate` and a `PostToolUse` hook), analysis scoping with `--only`, an opt-in dependency
existence check (`--network`), run attribution with graded assurance, recorded gate verdicts and
hook bypasses, an audit-evidence projection (`websec attest`), and a claimspec export of the
calibration table (`websec calibrate --claimspec`). These are scoped review tools;
manual profiles, unknown routes, dynamic behavior and unsupported syntax remain limitations. The
in-loop gate is developer ergonomics, not a control, and `attest` reports evidence without
rendering a compliance verdict.

The [0.14.0 migration guide](docs/MIGRATING-0.14.0.md) explains schema 2.0 and gate/artifact
changes. 0.16.0 added the claimspec calibration export over 0.15.3 and needed no migration.
0.17.0 split the exit codes (`2` = usage error, `3` = incomplete run) — the one breaking change in the
project's history; CI scripts that tested for `2` as "incomplete" must test for `3`. 0.17.1 changed no
behaviour: it corrected only what the tool says about itself.
0.18.0 adds a measured `P(real)` from a relabelled corpus, and stops a scan that could read no
analyzable source from reporting as a completed clean run (`--require-analyzed`, exit 3).
The [remaining-work specification](specs/001-continuous-security-improvement/spec.md) consolidates
unresolved gaps and acceptance tests so overlapping old-base PRs do not become competing roadmaps.
Existing runtime probes are opt-in; their earlier isolated results are not current deployment proofs.

## Using it as a Claude Code skill / plugin

This repo **is** a Claude Code plugin. Install it once —

```
/plugin marketplace add raccioly/websec-validator
/plugin install websec-validator@websec-plugins
```

— and the bundled **security-pass** skill ([`skills/security-pass/SKILL.md`](skills/security-pass/SKILL.md))
lets you just ask, in plain English, for a security pass: it runs `websec`, reads the briefing, and
works the findings with you. For other agents the universal interface is unchanged: run the CLI, read
`AGENT-BRIEFING.md`.

**Install gotchas (field-tested):**

- The install id is `plugin@marketplace` — `websec-validator@websec-plugins` (the marketplace name
  from `.claude-plugin/marketplace.json`), **not** `@websec-validator` (the repo).
- The plugin only delivers the *instructions*; the actual scanning is a **separate Python CLI**
  (`websec`). The skill checks the selected engine's version/source and reports a missing engine;
  installation or upgrades require an operator-selected trusted source.
- **`/plugin …` only works in the terminal CLI.** In the Claude **app / Agent SDK** (no `/plugin`),
  configure it in `.claude/settings.json` instead:
  ```json
  {
    "extraKnownMarketplaces": {
      "websec-plugins": { "source": { "source": "github", "repo": "raccioly/websec-validator" } }
    },
    "enabledPlugins": { "websec-validator@websec-plugins": true }
  }
  ```
  This **registers + enables** the plugin but does **not** auto-fetch it — the first download still
  needs the CLI (`/plugin install websec-validator@websec-plugins`) once. (Project `.claude/settings.json`
  for a team; `~/.claude/settings.json` for just you.)

## Credits

Methodology + probe library are distilled from a real authenticated penetration-testing pass.
This tool productizes that hand-written methodology into something an AI agent can run on any repo.

## License

[MIT](LICENSE) © Ricardo Accioly

## Latest source review and adoption

Snapshot-bound review records live with the artefacts they describe rather than in this README, so
the numbers cannot drift out of date here:

- [**Validation record**](docs/security-review/validation.md) — dated results bound to exact
  detector revisions and test counts.
- [**Upstream overlap review**](docs/security-review/upstream-overlap-review.md) — selected open PRs
  compared at exact heads. No PR was merged as part of it; recompare both heads before integrating.
- [**Integration examples**](docs/integrations/README.md) — opt-in pre-commit, PR/weekly workflow and
  composite Action. They reuse the existing CLI and install nothing on their own.

Two standing limits worth knowing before you read any of them. Route discovery reports what it can
parse *without importing settings or executing your code*, so unknown mounts stay route **candidates**
carrying their uncertainty rather than becoming confirmed paths. And eligibility recorded in these
documents means human review — not installation, independent real-project validation, or measured
vulnerability recall.

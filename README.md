# websec-validator

[![CI](https://github.com/raccioly/websec-validator/actions/workflows/ci.yml/badge.svg)](https://github.com/raccioly/websec-validator/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/websec-validator)](https://pypi.org/project/websec-validator/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://pypi.org/project/websec-validator/)
[![Runtime deps: 0](https://img.shields.io/badge/runtime%20deps-0%20(stdlib%20only)-brightgreen)](#install)
[![SARIF 2.1.0](https://img.shields.io/badge/output-SARIF%202.1.0-orange)](https://github.com/raccioly/websec-validator/blob/main/docs/guides/ci/github-actions.md)
[![Docs](https://img.shields.io/badge/docs-guides%20%26%20reference-informational)](https://github.com/raccioly/websec-validator/blob/main/docs/README.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-lightgrey)](https://github.com/raccioly/websec-validator/blob/main/LICENSE)

**English** · [Português (Brasil)](https://github.com/raccioly/websec-validator/blob/main/docs/i18n/pt-BR/README.md) · [Español](https://github.com/raccioly/websec-validator/blob/main/docs/i18n/es/README.md) · [简体中文](https://github.com/raccioly/websec-validator/blob/main/docs/i18n/zh-CN/README.md)

A senior pentester's "here's what to test and how" handoff — auto-generated from your repo, for your AI agent to execute.

<!-- docguard:quality negation-load off — "no LLM / no server / no running app / not a SaaS / never touches prod" is this tool's core positioning; defining it by contrast with the scanners-and-SaaS it deliberately is NOT is intentional, not a phrasing defect. -->

> Local-first security recon that **briefs your AI coding agent**. It does the deterministic
> half — read supported source, map the visible attack surface, and stage a probe library tailored to what it
> found — then hands your agent (Claude Code, Codex, Gemini, Cursor) a marching-orders briefing.
> `websec run` needs nothing but the code; add `--scan` to also run and de-duplicate whichever
> static scanners you have installed. **Code in, artifacts out. No LLM in the tool; no server or
> running app required for the core pass.**

[![websec-validator demo](https://raw.githubusercontent.com/raccioly/websec-validator/main/assets/demo.gif)](https://github.com/raccioly/websec-validator/blob/main/assets/demo.gif)

**New here?** Read the eight-page technical brief — what it reads, how a finding earns its severity,
what it refuses to say, and the field evidence:
**[raccioly.github.io/websec-validator](https://raccioly.github.io/websec-validator/websec-explained.html)**
· [PDF](https://raccioly.github.io/websec-validator/websec-explained.pdf). The reviewed v0.21.0 snapshot
has selected fact assertions in `tests/test_explained_brief.py` and an HTML/PDF/renderer hash binding
in `tests/test_brief_artifacts.py`. Prose accuracy and rendered layout still require review;
see [rebuilding the brief](https://github.com/raccioly/websec-validator/blob/main/CONTRIBUTING.md#publishing-the-technical-brief).

It is *not* an autonomous scanner and *not* a SaaS. It's the missing front-half: the thing that
turns a repo into a precise, fact-grounded security brief an AI agent (with a human in the loop)
can act on. How it works and the reasoning behind every check:
[concepts](https://github.com/raccioly/websec-validator/blob/main/docs/concepts/how-it-works.md) ·
[methodology](https://github.com/raccioly/websec-validator/blob/main/docs/METHODOLOGY.md).

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

It installs, runs, and walks the findings with you. Phrasing it as a *defensive review of your own
code* matters: it's the difference between an agent that just gets to work and one that stops to
confirm you're authorized. Every path ends in the same `AGENT-BRIEFING.md` your agent acts on:

| Path | One-time setup | Then |
|---|---|---|
| **Tell your agent** (simplest) | — | say the line above |
| **CLI** (a terminal) | `pipx install websec-validator` | `websec run /path/to/your/app` |
| **Claude Code plugin** | `/plugin marketplace add raccioly/websec-validator`  →  `/plugin install websec-validator@websec-plugins` | invoke the **security-pass** skill, or just ask |
| **Any other agent** (Codex, Cursor, Gemini, Aider) | `pipx install websec-validator` | `websec install <host>` |
| **Docker** (no install) | `docker build -t websec-validator .` | `docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/scan" websec-validator run /scan --out /scan/websec-out` |

Already have a codebase with history, tests and fixtures? Follow
**[Adopting websec in an existing project](https://github.com/raccioly/websec-validator/blob/main/docs/guides/existing-projects.md)**:
scope out non-product code, run, triage, record a baseline, then turn on gating in phases.

## Install

```bash
pipx install websec-validator   # from PyPI; Python 3.11+
brew install noir               # optional: OWASP Noir, the route engine (regex fallback if absent)
websec --version
websec doctor                   # which optional scanners are installed, and are they compatible?
```

Zero Python runtime dependencies. External scanners (Trivy, OSV-Scanner, Gitleaks, Semgrep,
Checkov, and per-language Bandit/gosec/Brakeman) are used **when present** and run only with
`--scan`; Prowler is detected and reported, not executed. Every channel — pip, uv, Docker, source, offline/air-gapped — and per-OS scanner
setup: **[Installation](https://github.com/raccioly/websec-validator/blob/main/docs/installation.md)**.

## Usage

```bash
websec run ./my-app                    # recon + stage tailored probes + emit the briefing
websec ./my-app                        # same thing — a bare path defaults to `run`
websec run ./my-app --scan             # …and also execute the available static scanners
websec run ./my-app --fail-on high     # exit 1 if any HIGH+ finding remains (a CI gate)
websec run ./my-app --diff main        # PR mode: scope to changed files + exact hunk line ranges
websec gate                            # fast pass/fail on the files you just changed (agent loop)
websec install codex                   # teach an agent to use websec (claude · cursor · gemini · aider · generic)
websec mcp                             # typed recon tools for any MCP client, over stdio
```

Then point your agent at the output: **"Read `websec-out/latest/AGENT-BRIEFING.md` and follow it."**
Each attempt gets its own `websec-out/runs/<id>/` directory; `latest` moves only after a completed run.
Every subcommand and option: [CLI reference](https://github.com/raccioly/websec-validator/blob/main/docs/reference/cli.md).

## What you get (`websec-out/`)

| Artifact | What it is |
|---|---|
| `AGENT-BRIEFING.md` | **The product.** Marching orders: detected surface, the access-control map, targeting, findings, the method, and the staged probe list. |
| `FACTS.json` | The full structured recon. |
| `findings-ledger.json` / `REPORT.md` | The traceable ledger: each finding with an evidence chain, CWE/ASVS/OWASP-API citation, remediation, and a **calibrated `P(real)`** (measured real-vuln rate + 95% CI + sample size). |
| `results.sarif` | **SARIF 2.1.0** — always written. Drop it into GitHub Code Scanning, GitLab, Azure DevOps, VS Code's SARIF viewer, DefectDojo. |
| `coverage.json` | What ran, what was skipped and why — a clean result is only as good as its coverage. |
| `probes/` | The probe scripts selected and staged for *this* app (BOLA, JWT, SSRF, mass-assignment…). |

Plus SBOMs, an attack-surface table, diff scope and a versioned envelope:
[all outputs](https://github.com/raccioly/websec-validator/blob/main/docs/reference/outputs.md).

## Languages

| Support | Languages |
|---|---|
| **Deep, framework-aware analysis** — Django, Flask, FastAPI, Connexion, Express, Fastify, Next.js, tRPC, Supabase Edge, AWS SAM… | Python, JavaScript, TypeScript |
| **Named sink checks** — direct command/query syntax (plus literal Spring and ASP.NET routes) | Java, C#, Go, Ruby, PHP |
| **Configuration or manual checks only** — reported as a `thin_language_coverage` gap | Kotlin/Android, Swift and Objective-C/iOS, Rust, C/C++ |
| **Recognized, not analyzed** — reported as a coverage gap, never as clean | Elixir, Scala, Clojure, Erlang, Perl, Lua, Dart, shell, server-side templates and more |

Route discovery across many more frameworks comes from OWASP Noir when it is installed, and the
scanners are language-agnostic. A completed no-match check is not proof that a service is secure:
**[the full support matrix and what a clean run means for your stack](https://github.com/raccioly/websec-validator/blob/main/docs/reference/languages.md)**.

## Documentation

| Start here | Guides | Reference |
|---|---|---|
| [Docs hub](https://github.com/raccioly/websec-validator/blob/main/docs/README.md) | [Existing projects](https://github.com/raccioly/websec-validator/blob/main/docs/guides/existing-projects.md) | [CLI](https://github.com/raccioly/websec-validator/blob/main/docs/reference/cli.md) |
| [Quickstart](https://github.com/raccioly/websec-validator/blob/main/docs/quickstart.md) | [AI agents](https://github.com/raccioly/websec-validator/blob/main/docs/guides/ai-agents.md) | [Languages](https://github.com/raccioly/websec-validator/blob/main/docs/reference/languages.md) |
| [Installation](https://github.com/raccioly/websec-validator/blob/main/docs/installation.md) | [GitHub Actions](https://github.com/raccioly/websec-validator/blob/main/docs/guides/ci/github-actions.md) · [other CI](https://github.com/raccioly/websec-validator/blob/main/docs/guides/ci/other-ci.md) | [Configuration](https://github.com/raccioly/websec-validator/blob/main/docs/reference/configuration.md) |
| [Upgrading](https://github.com/raccioly/websec-validator/blob/main/docs/upgrade.md) | [Triage and suppression](https://github.com/raccioly/websec-validator/blob/main/docs/guides/triage-and-suppression.md) | [Outputs](https://github.com/raccioly/websec-validator/blob/main/docs/reference/outputs.md) |
| [Troubleshooting](https://github.com/raccioly/websec-validator/blob/main/docs/troubleshooting.md) · [FAQ](https://github.com/raccioly/websec-validator/blob/main/docs/faq.md) | [Dynamic testing](https://github.com/raccioly/websec-validator/blob/main/docs/guides/dynamic-testing.md) | [MCP server](https://github.com/raccioly/websec-validator/blob/main/docs/reference/mcp.md) |

## Status

The [changelog](https://github.com/raccioly/websec-validator/blob/main/CHANGELOG.md) records what each
release changed; [Upgrading](https://github.com/raccioly/websec-validator/blob/main/docs/upgrade.md)
indexes the migration notes — 0.14.0 (schema 2.0) and the 0.17.0 exit-code split
(`2` = usage error, `3` = incomplete run). Unresolved gaps and their acceptance tests live in the
[remaining-work specification](https://github.com/raccioly/websec-validator/blob/main/specs/001-continuous-security-improvement/spec.md).

These are scoped review tools: manual profiles, unknown routes, dynamic behavior and unsupported
syntax remain limitations. The in-loop gate is developer ergonomics, not a control, and `attest`
reports evidence without rendering a compliance verdict. Snapshot-bound evidence lives with the
artifacts it describes — the [validation record](https://github.com/raccioly/websec-validator/blob/main/docs/security-review/validation.md),
the [benchmarks](https://github.com/raccioly/websec-validator/blob/main/BENCHMARKS.md) and the
[proof protocol](https://github.com/raccioly/websec-validator/blob/main/corpus/PROOF-PROTOCOL.md) —
so the numbers cannot drift out of date here.

**Validated on** a production Next.js app, a large Express/AWS monorepo, and the VAmPI / NodeGoat /
DVGA vuln-app corpus — independently reproducing a hand-done pentest's findings (tenant boundary,
SSRF, file upload, cross-tenant BOLA, role/authz gaps). Route discovery reports what it can parse
*without importing settings or executing your code*, so unknown mounts stay route **candidates**
carrying their uncertainty; that is human review evidence, not measured vulnerability recall.

## Contributing

Bug reports, false-positive reports and detector proposals are the most valuable input this project
gets — see [CONTRIBUTING.md](https://github.com/raccioly/websec-validator/blob/main/CONTRIBUTING.md)
(including the maintainer release process) and the
[issue templates](https://github.com/raccioly/websec-validator/issues/new/choose). Report
vulnerabilities in websec itself privately: [SECURITY.md](https://github.com/raccioly/websec-validator/blob/main/SECURITY.md).

```bash
python3 -m unittest discover -s tests    # stdlib only; synthetic/local-loopback tests, no public network
```

## Credits

Methodology + probe library are distilled from a real authenticated penetration-testing pass.
This tool productizes that hand-written methodology into something an AI agent can run on any repo.

## License

[MIT](https://github.com/raccioly/websec-validator/blob/main/LICENSE) © Ricardo Accioly

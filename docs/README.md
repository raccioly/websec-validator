# websec-validator documentation

`websec` is a local-first security-recon CLI. It reads your repository, maps the attack surface it
can see, de-duplicates the static scanners you have installed, stages probes tailored to what it
found, and writes an `AGENT-BRIEFING.md` that an AI coding agent (with you in the loop) acts on.
No LLM in the tool, no server, and no running app for the core pass.

Start with the page that matches what you are trying to do.

**Read in:** English · [Português (Brasil)](i18n/pt-BR/README.md) · [Español](i18n/es/README.md) ·
[简体中文](i18n/zh-CN/README.md) (translations cover the README and quickstart; English is authoritative)

## Get started

| I want to… | Read |
|---|---|
| See real output in five minutes | [Quickstart](quickstart.md) |
| Install it (pipx, pip, uv, Docker, source, offline) and the optional scanners | [Installation](installation.md) |
| Add it to a repository that already exists | [Adopting in an existing project](guides/existing-projects.md) |
| Wire it into a new repository from the first commit | [New projects](guides/new-projects.md) |
| Upgrade, or understand a breaking change | [Upgrading](upgrade.md) |

## Guides

| Guide | What it covers |
|---|---|
| [Existing projects](guides/existing-projects.md) | Baseline → scope → first run → triage → baseline → phased gating, with a "tell your agent" prompt per step |
| [New projects](guides/new-projects.md) | Agent instructions, session context, the edit-time gate and the CI gate from day one |
| [Monorepos](guides/monorepo.md) | Service boundaries, per-service scoping, CI matrices |
| [Triage and suppression](guides/triage-and-suppression.md) | `.websec-ignore`, fingerprint acknowledgements, clusters, baselines, prioritisation, reporting a false positive |
| [AI agents](guides/ai-agents.md) | Claude Code (plugin, hooks), Codex, Cursor, Gemini CLI, Aider, any `AGENTS.md` host, MCP clients |
| [GitHub Actions](guides/ci/github-actions.md) | The composite Action, SARIF upload to Code Scanning, PR mode, exit codes |
| [Other CI systems](guides/ci/other-ci.md) | GitLab, Azure DevOps, Jenkins and generic pipelines; SBOM; SARIF import |
| [pre-commit and Git hooks](guides/ci/pre-commit-and-git-hooks.md) | The pre-commit framework hook and the native `websec hooks` guardrail |
| [Dynamic testing](guides/dynamic-testing.md) | Authorized, read-only probes against a TEST instance you own; closing the loop with a DAST run |

## Reference

| Page | What it covers |
|---|---|
| [CLI](reference/cli.md) | Every subcommand and option, exit codes, environment variables |
| [Languages and frameworks](reference/languages.md) | What is analysed deeply, what has named checks only, and what is recognised but not analysed |
| [Configuration](reference/configuration.md) | `.websec-ignore`, dynamic-test config, profiles, graph input, caches |
| [Outputs](reference/outputs.md) | Every artifact in `websec-out/`, its schema and its consumers |
| [MCP server](reference/mcp.md) | Tools, transports, authentication and client registration |

## Concepts and background

| Page | What it covers |
|---|---|
| [How it works](concepts/how-it-works.md) | The deterministic half vs the agent half, extractors, prioritisation, calibrated confidence |
| [Methodology](METHODOLOGY.md) | The long-form reasoning behind every check |
| [Glossary](glossary.md) | Terms used across these pages |
| [Integration examples](integrations/README.md) | Reviewed, opt-in pre-commit and workflow configurations |
| [Validation record](security-review/validation.md) | Dated results bound to exact detector revisions |

## Help

- [Troubleshooting](troubleshooting.md) — symptom, cause, fix.
- [FAQ](faq.md) — privacy, scope, comparisons, what a clean run means.
- Report a bug or a false positive through the
  [issue templates](https://github.com/raccioly/websec-validator/issues/new/choose); report a
  vulnerability in websec itself privately via [SECURITY.md](../SECURITY.md).
- Contributing, including how these docs are kept honest: [CONTRIBUTING.md](../CONTRIBUTING.md#writing-documentation).

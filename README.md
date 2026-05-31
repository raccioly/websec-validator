# websec-validator

> Local-first security recon that **briefs your AI coding agent**. It does the deterministic
> half — read the repo, run the scanners it finds, stage a probe library tailored to what it
> discovered — and hands your agent (Claude Code, Codex, Gemini, Cursor) a marching-orders
> briefing. **Code in, artifacts out. No LLM, no server, no running app required.**

It is *not* an autonomous scanner and *not* a SaaS. It's the missing front-half: the thing that
turns a repo into a precise, fact-grounded security brief that an AI agent (with a human in the
loop) can act on. Think of it as an auto-filled, repo-aware version of a senior pentester's
"here's what to test and how" handoff.

## Why this exists

The market is full of tools that either (a) bundle OSS scanners in a cloud dashboard (Aikido, Jit)
or (b) autonomously probe a *running* app (XBOW, ZeroPath, Shannon). What nobody ships is a
**local, no-account tool that reads your code, extracts the auth/tenant model, and emits a durable,
re-runnable probe suite tailored to your app** — handed to whatever coding agent you already use.
See [`MARKET-ANALYSIS-AND-VERDICT.md`](MARKET-ANALYSIS-AND-VERDICT.md) for the full landscape and
the gap this fills.

## Install

```bash
pipx install .          # or: pip install -e .
websec --version
```

Zero runtime dependencies. It shells out to scanners (Trivy, Gitleaks, Semgrep/OpenGrep, Checkov,
Prowler…) when they're on your PATH, and reports which are missing — it never installs or imports
them, and never hard-fails if one is absent.

## Use

```bash
websec doctor                 # which scanners are installed?
websec run ./my-app           # recon + stage tailored probes + emit the briefing
websec run ./my-app --scan    # …and also execute the available static scanners
```

Then point your AI coding agent at the output:

```
Read websec-out/AGENT-BRIEFING.md and follow it.
```

## What you get (`websec-out/`)

| Artifact | What it is |
|---|---|
| `AGENT-BRIEFING.md` | The marching orders for your agent — detected stack, auth/tenant candidates, static findings, the tailored probe list, and the method. **This is the product.** |
| `FACTS.json` | The structured recon: stack, route patterns, auth-scheme guess, tenant-key candidates, SSRF-candidate files. |
| `probes/` | The probe scripts selected and staged for *this* app's surface (BOLA, JWT, SSRF, mass-assignment, race, webhook-forgery…). Drafts the agent finalizes, then keeps as a regression suite. |
| `scanners/` | Raw scanner JSON (with `--scan`). |

## The flow

```
🔧 websec (deterministic, no LLM)          🤖 your AI agent + 🧑 you
────────────────────────────────────       ──────────────────────────────────
1. recon: stack, routes, auth, tenant   →   confirm THE tenant boundary
2. run static scanners (what's present) →   triage real-vs-noise
3. stage tailored probe templates       →   fill placeholders, run vs a TEST instance
4. emit AGENT-BRIEFING.md                →   propose fixes, re-run to confirm, hand back a report
```

**The seam that matters:** steps 1–4 need only the code — instant, reliable, zero-setup. *Running*
the probes (the agent's job) needs a **live test instance + test credentials**, which the human
supplies. The tool never touches a running app, so it stays deterministic and safe.

## What's in v1 — and what's not

- **In:** recon, scanner detection + execution, tailored probe staging, the briefing. Python + Node.
- **Not yet (v2):** cross-tool de-duplication of scanner findings; Docker-bundled scanners for
  reproducibility; the dynamic-running phase (ZAP/Nuclei as engines); optional model-SDK wiring
  (Bedrock/Anthropic/OpenAI/Gemini) for when no agent is driving.
- **Deliberately never:** an LLM inside the tool, a hosted server, or a dependency on your app
  running. Those keep it cheap, private, and trustworthy.

## Credits

The methodology and the probe library come from a real authenticated pentest pass — see
[`base-research/REPLICATION-PLAYBOOK.md`](base-research/REPLICATION-PLAYBOOK.md). This tool
productizes that hand-written pass into something an AI agent can run on any repo.

## Using it as a skill

[`skill/SKILL.md`](skill/SKILL.md) wraps this for Claude Code / the Agent SDK so the agent invokes
`websec` and follows the briefing automatically. For other agents, the universal interface is just:
run the CLI, read `AGENT-BRIEFING.md`.

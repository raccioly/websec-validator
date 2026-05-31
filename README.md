# websec-validator

> Local-first security recon that **briefs your AI coding agent**. It does the deterministic
> half — read the repo, map the full attack surface, run + de-duplicate the static scanners, and
> stage a probe library tailored to what it found — then hands your agent (Claude Code, Codex,
> Gemini, Cursor) a marching-orders briefing. **Code in, artifacts out. No LLM in the tool, no
> server, no running app required.**

It is *not* an autonomous scanner and *not* a SaaS. It's the missing front-half: the thing that
turns a repo into a precise, fact-grounded security brief an AI agent (with a human in the loop)
can act on — an auto-filled, repo-aware version of a senior pentester's "here's what to test and
how" handoff. Full landscape + why this niche is real: [`MARKET-ANALYSIS-AND-VERDICT.md`](MARKET-ANALYSIS-AND-VERDICT.md).

## Install

```bash
pipx install .            # or: pip install -e .
brew install noir         # OWASP Noir — the route engine (50+ frameworks); regex fallback if absent
websec --version
```

Zero Python runtime dependencies. It shells out to scanners (Trivy, Gitleaks, Semgrep/OpenGrep,
Checkov, Prowler) and Noir **when present**, reports what's missing, and never hard-fails if a tool
is absent.

## Use

```bash
websec doctor ./my-app        # which scanners are installed?
websec run ./my-app           # recon + de-dup scanners + stage tailored probes + emit the briefing
websec run ./my-app --scan    # …and actually execute the available static scanners
websec proof                  # score recon coverage against a known-vuln-app corpus (CI gate)
```

Then point your agent at the output: **"Read `websec-out/AGENT-BRIEFING.md` and follow it."**

## What it extracts (10 deterministic extractors, no LLM)

| | Dimension | Notable output |
|---|---|---|
| stack | languages, frameworks, datastores | monorepo-aware (aggregates every manifest) |
| routes | every endpoint via **OWASP Noir** | method · path · typed params · code path |
| auth | scheme + login surface | multi-scheme (primary jwt > passport), PyJWT/NextAuth/session aware |
| **authz** | access-control map | guard coverage + **write endpoints with no visible guard** + roles |
| tenant | multi-tenancy key candidates | the BOLA boundary, by frequency |
| surface | 12 user-input-gated sink classes | SSRF/SQLi/NoSQLi/traversal/SSTI/redirect/deser/XXE/proto-pollution/ReDoS/cmd/eval |
| iac_ci | IaC + CI/CD | GitHub Actions injection, unpinned actions, Dockerfile-root, tfstate |
| client_exposure | browser leakage | `NEXT_PUBLIC_*` secrets, server-secret-in-client, source maps |
| graphql | GraphQL surface | introspection / playground / missing depth-limit |
| integrations | third-party + webhooks | webhooks missing signature verification |

Plus **derived targeting** — IDOR / SSRF / open-redirect / upload / write / auth-endpoint
candidates — so probes get pointed at the *exact* endpoints, not fired blindly.

## What you get (`websec-out/`)

| Artifact | What it is |
|---|---|
| `AGENT-BRIEFING.md` | **The product.** Marching orders: detected surface, the access-control map, targeting, findings, the method, and the staged probe list. |
| `FACTS.json` | The full structured recon. |
| `findings.json` | Static scanner results, **de-duplicated across tools** and severity-ranked (with `--scan`). |
| `probes/` | The probe scripts selected + staged for *this* app (BOLA, JWT, SSRF, mass-assignment…). |

## The flow

```
🔧 websec (deterministic)              🤖 your agent + 🧑 you
─────────────────────────────────      ─────────────────────────────────
1. recon → full attack surface     →   confirm the tenant boundary + auth model
2. run + de-dup static scanners    →   triage real-vs-noise
3. stage tailored probes           →   fill placeholders, run vs a TEST instance
4. emit AGENT-BRIEFING.md           →   propose fixes, re-run to confirm, report back
```

Static recon + briefing need **only the code**. *Running* the probes needs a live test instance +
test credentials (the human supplies them) — the tool itself never touches a running app.

## Proof harness

`websec proof` clones a vuln-app corpus (VAmPI, NodeGoat, DVGA) and scores whether recon surfaces
each app's documented attack surface — a deterministic, CI-trackable proxy (currently **10/10**).
The real kill-criterion (does the briefing lift an agent's bug-finding vs a generic prompt?) is the
manual A/B in [`corpus/PROOF-PROTOCOL.md`](corpus/PROOF-PROTOCOL.md).

## Validated on

HugoCross (Next.js), `wu-whatsappinbox` (106-service Express/AWS monorepo), VAmPI, NodeGoat, DVGA —
independently reproducing a hand-done pentest's findings (tenant boundary, SSO-endpoint SSRF, media
upload, conversation-BOLA routes, roles).

## Tests

```bash
python3 -m unittest discover -s tests    # stdlib only, no Noir/network — 12 tests
```

## Status / roadmap

**Done:** 10-extractor recon, cross-tool de-dup, tailored probe staging, agent briefing, proof
harness, test suite. **Next:** Docker-bundled scanners (reproducibility), v2 dynamic-running phase
(ZAP/Nuclei engines + the two-role access-control diff), optional model-SDK adapters for
no-agent fallback.

## Using it as a skill

[`skill/SKILL.md`](skill/SKILL.md) wraps this for Claude Code / the Agent SDK so the agent invokes
`websec` and follows the briefing automatically. For other agents the universal interface is just:
run the CLI, read `AGENT-BRIEFING.md`.

## Credits

Methodology + probe library come from a real authenticated pentest pass
([`base-research/REPLICATION-PLAYBOOK.md`](base-research/REPLICATION-PLAYBOOK.md), not committed).
This tool productizes that hand-written pass into something an AI agent can run on any repo.

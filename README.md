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

### Or run via Docker (everything bundled, zero install)

No need to install Noir or any scanner — the image bundles them all (arch-aware, amd64 + arm64):

```bash
docker build -t websec-validator .
docker run --rm -v "$PWD:/scan" websec-validator run /scan --out /scan/websec-out
```

The image carries Noir + Trivy + Gitleaks + Semgrep + Checkov; mount your repo at `/scan` and the
artifacts land in `/scan/websec-out`.

## Use

```bash
websec doctor ./my-app        # which scanners are installed?
websec run ./my-app           # recon + de-dup scanners + stage tailored probes + emit the briefing
websec run ./my-app --scan    # …and actually execute the available static scanners
websec proof                  # score recon coverage against a known-vuln-app corpus (CI gate)
websec calibrate              # fit confidence calibration vs the labeled corpus → calibration.json
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
| `findings-ledger.json` / `REPORT.md` | The traceable ledger: each finding with an evidence chain, CWE/ASVS/OWASP-API citation, remediation, and a **calibrated `P(real)`** (measured real-vuln rate + 95% CI + sample size). |
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

## Calibrated confidence

`websec calibrate` runs the ledger against the labeled corpus, measures how often each
*(attack-class, confidence)* bucket is a **real** documented vuln, and writes `calibration.json`
(shipped + applied at runtime). Each finding then carries `P(real)` with a **95% Wilson confidence
interval** and the sample size `n` — so "MEDIUM" stops being a vibe and becomes "real ~57% of the
time on the corpus (CI 43–70%, n=51)". A finding that matches no documented vuln counts as a false
positive (the corpus is well-documented). **Honest caveats:** the corpus is *deliberately
vulnerable*, so the rates skew **optimistic** for clean production code, and small samples mean
**wide intervals** — the CI is the headline, not the point estimate, and both tighten as the corpus
grows. With thin data a bucket falls back to the per-label aggregate, then to a clearly-flagged
uncalibrated prior. No ML, no deps — binomial proportion + Wilson interval; the structure upgrades to
isotonic regression if a large labeled set ever exists.

## Dynamic phase (v2 — read-only so far)

When you have a *running TEST instance*, `websec dynamic` mints role tokens and runs the probes the
static recon pointed at. v1 is **read-only**: authenticated **cross-tenant BOLA** on the group-scoped
GET endpoints recon discovered.

```bash
cp dynamic-config.example.json dynamic-config.json    # TEST target + role creds (gitignored)
websec run ./my-app                                    # static recon → websec-out/FACTS.json
websec dynamic --config dynamic-config.json --facts websec-out/FACTS.json
# → "14/14 cross-tenant GET reads blocked — all isolated"   (or 🚨 LEAK with the exact endpoint)
```

Never point it at production. Write-verb BOLA, JWT/auth attacks, and a ZAP/Nuclei two-role diff are
the next dynamic probes (explicitly gated — they mutate).

## Validated on

HugoCross (Next.js), `wu-whatsappinbox` (106-service Express/AWS monorepo), VAmPI, NodeGoat, DVGA —
independently reproducing a hand-done pentest's findings (tenant boundary, SSO-endpoint SSRF, media
upload, conversation-BOLA routes, roles).

## Tests

```bash
python3 -m unittest discover -s tests    # stdlib only, no Noir/network — 20 tests
```

## Status / roadmap

**Done:** 11-extractor recon (incl. schema/entity → mass-assignment targeting), cross-tool de-dup,
tailored probe staging, agent briefing, traceable findings ledger with **calibrated confidence
(CJE — Wilson CIs)**, proof harness, test suite, **Docker bundle** (all scanners + Noir, arch-aware),
**dynamic phase v1** (authenticated read-only cross-tenant BOLA — validated live, reproduced a
hand-pentest's 14/14).
**Next:** dynamic write-verb BOLA + JWT/auth probes + ZAP/Nuclei two-role diff (gated, they mutate),
calibration on hand-labeled real repos (more representative base rate), ASVS index lookup, optional
model-SDK adapters for no-agent fallback.

## Using it as a skill

[`skill/SKILL.md`](skill/SKILL.md) wraps this for Claude Code / the Agent SDK so the agent invokes
`websec` and follows the briefing automatically. For other agents the universal interface is just:
run the CLI, read `AGENT-BRIEFING.md`.

## Credits

Methodology + probe library come from a real authenticated pentest pass
([`base-research/REPLICATION-PLAYBOOK.md`](base-research/REPLICATION-PLAYBOOK.md), not committed).
This tool productizes that hand-written pass into something an AI agent can run on any repo.

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

## Quickstart — just point it at your repo

**Simplest: tell your AI agent.** In Claude Code (or any coding agent), open your project and say:

> *"Install and run the security tool at github.com/raccioly/websec-validator on this repo, then follow its briefing."*

It installs, runs, and walks the findings with you. There's nothing to host and no website — it's
local. The four ways to get there, all ending in the same `AGENT-BRIEFING.md` your agent acts on:

| Path | One-time setup | Then |
|---|---|---|
| **Tell your agent** (simplest) | — | say the line above |
| **CLI** (a terminal) | `pipx install websec-validator` | `websec run /path/to/your/app` |
| **Claude Code plugin** (slash) | `/plugin marketplace add raccioly/websec-validator`  →  `/plugin install websec-validator@websec-plugins` | invoke the **security-pass** skill, or just ask |
| **Docker** (no install) | `docker build -t websec-validator .` | `docker run --rm -v "$PWD:/scan" websec-validator run /scan --out /scan/websec-out` |

➡️ **Want the reasoning behind every check?** Read **[docs/METHODOLOGY.md](docs/METHODOLOGY.md)** — what each test does and why.

## Install

```bash
pipx install websec-validator   # from PyPI
brew install noir               # OWASP Noir — the route engine (50+ frameworks); regex fallback if absent
websec --version
```

_Until the first PyPI release publishes (or for bleeding-edge), install straight from source instead:_
`pipx install git+https://github.com/raccioly/websec-validator` (or from a clone: `pipx install .`).

Requires **Python 3.11+** (on stock macOS, `python3` is often 3.9 — use `pipx`, which picks a newer
interpreter, or install via Homebrew/pyenv). Zero Python runtime dependencies: it shells out to
scanners (Trivy, Gitleaks, Semgrep/OpenGrep, Checkov, Prowler) and Noir **when present**, reports
what's missing, and never hard-fails if a tool is absent.

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
websec run ./my-app           # ← the one command: recon + stage tailored probes + emit the briefing
websec ./my-app               # same thing — a bare path defaults to `run`
websec run ./my-app --scan    # …and also execute the available static scanners
websec doctor ./my-app        # (optional) which scanners are installed?
```

Then point your agent at the output: **"Read `websec-out/AGENT-BRIEFING.md` and follow it."**

> That's the whole user surface: **`run`** (plus the optional, advanced **`dynamic`** live-probing step below). `recon`/`proof`/`calibrate` exist for developing the tool itself and are hidden from `--help` — you never need them.

## What it extracts (11 deterministic extractors, no LLM)

| | Dimension | Notable output |
|---|---|---|
| stack | languages, frameworks, datastores | monorepo-aware (aggregates every manifest) |
| routes | every endpoint via **OWASP Noir** | method · path · typed params · code path |
| auth | scheme + login surface | multi-scheme (primary jwt > passport), PyJWT/NextAuth/session aware |
| **authz** | access-control map | guard coverage + **write endpoints with no visible guard** + roles |
| tenant | multi-tenancy key candidates | the BOLA boundary, by frequency |
| surface | 12 user-input-gated sink classes | SSRF/SQLi/NoSQLi/traversal/SSTI/redirect/deser/XXE/proto-pollution/ReDoS/cmd/eval |
| schemas | data models + **privileged fields** | Pydantic/SQLAlchemy/Django/Prisma/Mongoose/TypeORM/Zod → `role`/`isAdmin`/`groupId` for mass-assignment targeting |
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

**It self-improves.** `websec dynamic` is an *oracle*: a write that executes unauthenticated is a
confirmed real vuln, and a recon-flagged endpoint that turns out auth-enforced is a confirmed false
positive. Every dynamic run folds those confirmed labels into a **local overlay** (`~/.cache/websec-validator/`,
gitignored, never shipped) that's merged on top of the public table — so the numbers **personalize to
your apps** the more you run it, with no extra step and nothing leaving your machine. To label by hand
instead, feed a `{attack_class, confidence, is_real}` file to `websec calibrate --ingest`.

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
python3 -m unittest discover -s tests    # stdlib only, no Noir/network — 23 tests
```

## Releasing (maintainer)

Published to PyPI via **Trusted Publishing** (OIDC — no API token in the repo). To cut a release:

```bash
# 1. bump the version in pyproject.toml (e.g. 0.2.1 → 0.2.2)
# 2. tag it and push — the tag must match pyproject's version (CI verifies):
git tag v0.2.2 && git push origin v0.2.2
# → publish.yml builds, INSTALLS + smoke-tests the wheel (version match,
#   calibration ships, a real `websec run`), then publishes. A bad build fails
#   CI instead of reaching PyPI — so you never have to yank after the fact.
```

One-time PyPI setup (before the first release): on pypi.org → **Account → Publishing → Add a pending
publisher** with project `websec-validator`, owner `raccioly`, repo `websec-validator`, workflow
`publish.yml`, environment `pypi`. The project is created on the first successful publish.

> Two independent channels, two update mechanisms: the **CLI** ships to **PyPI** (semver releases,
> `pip install --upgrade`); the **Claude Code plugin** ships from **git** (tracks latest commit,
> refreshed via `/plugin marketplace update`).

## Status / roadmap

**Done:** 11-extractor recon (incl. schema/entity → mass-assignment targeting), cross-tool de-dup,
tailored probe staging, agent briefing, traceable findings ledger with **calibrated confidence
(CJE — Wilson CIs)**, proof harness, test suite, **Docker bundle** (all scanners + Noir, arch-aware),
**dynamic phase v1** (authenticated read-only cross-tenant BOLA — validated live, reproduced a
hand-pentest's 14/14).
**Next:** dynamic write-verb BOLA + JWT/auth probes + ZAP/Nuclei two-role diff (gated, they mutate),
calibration on hand-labeled real repos (more representative base rate), ASVS index lookup, optional
model-SDK adapters for no-agent fallback.

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
  (`websec`). The skill's Step 0 installs it (`pipx install websec-validator`) if it's missing.
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

Methodology + probe library come from a real authenticated pentest pass
([`base-research/REPLICATION-PLAYBOOK.md`](base-research/REPLICATION-PLAYBOOK.md), not committed).
This tool productizes that hand-written pass into something an AI agent can run on any repo.

# How websec-validator works — the methodology, and the reasoning behind every test

This document explains **what** the tool checks, **why** each check matters, and **how** the
pieces fit together. It is the long-form companion to the README. If you only read one section,
read [The core idea](#the-core-idea) and [Why confidence is calibrated](#layer-3b--calibrated-confidence-cje).

---

## The core idea

Most security scanners try to *be* the expert: they run, they decide, they hand you a list of
alerts. The problem is well known — they cry wolf. Engineers drown in false positives, learn to
ignore the tool, and the one real bug hides in the noise.

websec-validator takes the opposite stance. **It does the deterministic half a machine is actually
good at — reading the whole repo, mapping the attack surface, citing the standards — and then hands
an AI coding agent a precise, fact-grounded briefing to do the reasoning half.** The tool itself
contains **no LLM, runs no server, and needs no running app** for its core pass. It is code-in,
artifacts-out.

Think of it as the auto-filled, repo-aware version of the handoff a senior penetration tester
writes for a junior: *"here's what this app is, here's where it's exposed, here's exactly what to
test and how, and here's how confident I am in each lead."* The agent (with a human in the loop)
then runs the probes, triages, fixes, and re-verifies.

Three actors, clear seams:

| Actor | Owns |
|---|---|
| 🔧 the tool (deterministic) | read the repo → map surface → de-dup scanner output → stage probes → emit the briefing + a calibrated findings ledger |
| 🤖 your AI agent | confirm the auth/tenant model, finalize + run the probes, triage real-vs-noise, propose fixes, re-verify |
| 🧑 the human | supply the running TEST instance + test accounts, review every diff, authorize any live probing |

The seam that matters most: **static recon + the briefing need only the code; the *probes* need a
live test instance + credentials.** The tool never touches a running app — that line is what keeps
it safe to run anywhere.

---

## The pipeline

```
                 ┌─────────────────────────── deterministic, no LLM, no running app ──────────────────────────┐
  your repo ──▶  1. RECON          2. STATIC SCANNERS      3. FINDINGS LEDGER        4. BRIEFING + REPORT
                 (11 extractors)   (Trivy/Gitleaks/…,      (evidence chain +         (marching orders for
                 walk once         de-duplicated)          standards + calibrated     your agent) + immutable
                                                           confidence)                run record
                                                                  │
                 ┌──── optional, needs a LIVE test target + creds + your OK ────┐
                 5. DYNAMIC PHASE  ──▶  confirms/escalates ledger findings  ──▶  feeds calibration (self-improving)
```

Every `run` is written to an **immutable, timestamped directory** (`websec-out/runs/<ts>/`) with a
`latest` symlink — nothing is ever overwritten, so you keep a full historical record of every pass.

---

## Layer 1 — Recon: the 11 extractors

Recon walks the repository **once** into a shared `RepoContext`, then runs eleven focused
extractors over it. Each answers one question a pentester asks first. The output is `FACTS.json`.

| # | Extractor | What it asks | Why it matters (the security reasoning) |
|---|---|---|---|
| 1 | **stack** | What languages, frameworks, datastores? Monorepo? | Everything downstream is stack-aware. The datastore class also tells the agent which static alerts are likely noise (e.g. on a NoSQL/JSON API, most SQLi alerts are false positives). |
| 2 | **routes** | What are all the HTTP endpoints? | The endpoint inventory *is* the attack surface. Powered by [OWASP Noir](https://github.com/owasp-noir/noir) (50+ frameworks) with a regex fallback. Every probe targets a real route. |
| 3 | **auth** | What authentication scheme, where's the token, where are the guards? | You cannot reason about "who can do what" without knowing how identity is established. Detects all schemes and picks a primary (JWT, session, passport/SSO, API key). |
| 4 | **authz** | Which endpoints have a visible auth guard, which don't? | **Broken access control is the #1 web risk (OWASP A01).** This builds the per-endpoint guard map and flags write endpoints with no visible guard — the highest-value missing-authz leads. |
| 5 | **tenant** | Is this multi-tenant, and what field isolates one customer from another? | The tenant boundary (`groupId`, `orgId`, `tenantId`…) is what every cross-tenant BOLA probe depends on, and it's the easiest thing to get subtly wrong. |
| 6 | **surface** | Where does user input reach a dangerous sink? | Maps 12 user-input-gated sink classes (SSRF, command injection, SQLi, path traversal, SSTI, open redirect, deserialization, XXE, prototype pollution…). "User-gated" is the key filter — a hardcoded `exec("ls")` is not a vuln; `exec(req.body.cmd)` is. |
| 7 | **schemas** | What are the data models, and which fields are *privileged*? | Finds ORM/schema models (Pydantic, SQLAlchemy, Django, Prisma, Mongoose, TypeORM, Zod, Sequelize) and the sensitive field names (`role`, `isAdmin`, `groupId`, `passwordHash`…). Turns mass-assignment from a generic guess into "try injecting *this* app's privileged fields." |
| 8 | **iac_ci** | Misconfigurations in Docker/CI/IaC? | Insecure defaults (containers as root, unpinned CI actions, disabled TLS) are real, common, and invisible at the app layer. |
| 9 | **client_exposure** | Do secrets leak into the browser bundle? | A secret in a `NEXT_PUBLIC_`/`VITE_` var or a client component ships to every visitor. High impact, easy to miss. |
| 10 | **graphql** | Is there a GraphQL surface, and is introspection open? | GraphQL has its own failure modes — introspection/playground in production, no depth/complexity limits (DoS), batching attacks. |
| 11 | **integrations** | Third-party integrations + webhooks; are webhooks signature-verified? | An unverified webhook endpoint is a forgeable, often-unauthenticated write path straight into your system. |

**Design note — the authz heuristic is a *hint*, not a verdict.** File-level guard detection
over-flags on apps that split routing from controllers (common in Express). That's intentional:
recon produces *leads* with honest confidence, and the dynamic phase (Layer 5) is what turns a
lead into a confirmed finding. This is also exactly what [calibration](#layer-3b--calibrated-confidence-cje)
measures — how often a recon lead is actually real.

---

## Layer 2 — Static scanners

When present on your machine, the tool shells out to best-of-breed open-source scanners and
**de-duplicates their findings across tools** into one severity-ranked set (`findings.json`, with
`--scan`):

| Scanner | Catches |
|---|---|
| **Gitleaks** | committed secrets / credentials |
| **Trivy** | vulnerable dependencies (CVEs), with fixed-version info |
| **Semgrep / OpenGrep** | code-level SAST patterns |
| **Checkov** | infrastructure-as-code misconfig |
| **Prowler** | cloud-account posture (when relevant) |

It **never hard-fails if a tool is absent** — it reports what's missing with install hints and
carries on. Scanners are detected by default and only *executed* with `--scan`, because execution
can be slow and the recon + briefing are valuable on their own.

---

## Layer 3 — The findings ledger

Recon signals, static-scanner hits, and (when run) dynamic results are correlated into **one ranked
record set** (`findings-ledger.json` + the human-readable `REPORT.md`). Every finding carries:

- **an evidence chain across layers** — e.g. a recon "no guard found" hypothesis (MEDIUM) and a
  dynamic "executed unauthenticated" verdict **merge into one** HIGH/CRITICAL finding with a
  `recon → dynamic` chain. One finding, full provenance.
- **a standards citation** — CWE + ASVS + the relevant OWASP API Top-10 entry (see
  [Standards coverage](#standards-coverage)). So a finding is traceable to an authoritative
  requirement, not just an assertion.
- **a rule-based confidence** — HIGH / MEDIUM / LOW (below).
- **a concrete remediation** — what to change.
- **suppression** — a committed `.websec-ignore` (glob paths or `category:<x>`) keeps the ledger
  focused without ever touching the immutable run records.

**The confidence rule (deterministic, no ML):**

- **HIGH** — dynamically confirmed (executed unauth / cross-tenant leak), a verified secret, or a
  fixed-version CVE at HIGH/CRITICAL.
- **MEDIUM** — concrete static evidence (a recon no-guard write, a SAST hit, a user-input-gated sink).
- **LOW** — a single-source hypothesis with no corroboration (a recon-only signal).

### Layer 3b — Calibrated confidence (CJE)

A label like "MEDIUM" is meaningless unless it maps to reality. **Calibration measures how often
each `(attack-class, confidence)` bucket is *actually* a real vulnerability**, so the number means
something you can act on.

- **How.** `websec calibrate` runs the recon ledger against a labeled corpus of deliberately-
  vulnerable apps (VAmPI, NodeGoat, DVGA), counts how often each bucket matches a documented vuln,
  and writes `calibration.json` (shipped, and applied at runtime). Each finding then gets a
  `P(real)` with a **95% confidence interval** and the sample size `n`.
- **Why a confidence interval, not just a number.** With a small corpus the *interval is the
  headline*. "MEDIUM = real ~57% of the time, CI 43–70%, n=51" honestly says "grounded, but here's
  how sure we are." The math is a Wilson score interval (binomial proportion) — deliberately *not*
  isotonic regression, which would overfit at this sample size. The structure upgrades to isotonic
  cleanly if a large labeled set ever exists.
- **The honest caveats, baked in.** A finding that matches no documented vuln is counted as a false
  positive (the corpus is well-documented, so unlisted = noise — conservative on purpose). And
  because the corpus is *deliberately vulnerable*, the rates **skew optimistic for clean production
  code** — every number is flagged as such, and to be conservative you threshold on the CI lower
  bound. A class we never researched falls back to the per-label aggregate rather than emitting a
  misleading `p=0`.
- **It self-improves.** `websec dynamic` is an *oracle*: a write that executes unauthenticated is a
  confirmed real vuln; a recon-flagged endpoint that turns out auth-enforced is a confirmed false
  positive. Every dynamic run folds those confirmed labels into a **local overlay**
  (`~/.cache/websec-validator/`, gitignored, never shipped) merged on top of the public table — so
  the numbers **personalize to your apps** the more you run it, and nothing leaves your machine.

This is the deterministic realization of the **CJE (Calibrated Judge Evaluation)** idea from the
AITPG/TRACE research: the tool emits the evidence + citation + a calibrated confidence; the agent
runs the judging.

---

## Layer 3c — The security constitution

From the same recon facts the tool derives a set of **Given/When/Then invariants** the app *should*
hold (`CONSTITUTION.md`) — e.g. *"Given a request to a write endpoint, When no session is present,
Then it must be rejected."* Each starts unchecked (⬜); the agent confirms it (✅ holds) or refutes
it (🔴 VIOLATED) with a probe. It reframes the findings as testable guarantees rather than a flat list.

---

## Layer 4 — The dynamic phase (optional, live, gated)

When you have a **running TEST instance + test credentials**, `websec dynamic` runs the probes the
static recon pointed at. This is where a lead becomes a confirmed finding. It is deliberately
conservative:

- **Authenticated cross-tenant BOLA** (`--config`) — logs in as two test accounts in different
  tenants and checks whether account A can read account B's data via the group-scoped GET endpoints
  recon found. **Read-only.** A leak is unambiguous proof of broken object-level authorization.
- **Unauthenticated reachability** (`--unauth`) — GETs each data-read endpoint with no auth to see
  what's reachable. **GET-only**, and trigger-style paths (cron/scrape/generate…) are excluded
  because *a GET can still be side-effecting*.
- **Write-verb auth enforcement** (`--probe-writes`) — **localhost-only**, non-destructive (empty
  bodies / dummy ids). Classifies each write as `auth-enforced` (good), `no-auth-gate`, or
  `EXECUTED-UNAUTH` (a real, critical missing-auth).

**The safety model is explicit and non-negotiable:** read-only by default; write probes are
localhost-only; nothing destructive; and **production is out of scope without written
authorization.** The tool refuses write probes against non-localhost targets, and the human owns
every credential and authorizes every live run.

---

## The verification method (how the agent should use this)

The briefing doesn't just hand over findings — it teaches the agent the verification method from the
AITPG/TRACE research, because **verification is the false-positive killer**:

- **Verify each finding with a 4-role debate** — *Advocate* (argue it's real, cite the chain +
  CWE), *Challenger* (try hard to refute it — intended-public? unreachable? guarded by a pattern
  the scan missed?), *Mediator* (decide; may override the tool), *Explainer* (write the survivor up
  with a `curl` repro + the fix). The Challenger is the point.
- **Generate probes the same way** — a *Positive* perspective (intended behavior), *Negative*
  (bypass/injection), *Edge* (boundary/concurrency), then a *Critic* dedupes them into one runnable
  suite.
- **Order of work** — static triage → confirm the auth/tenant model → run the targeted probes
  (low-priv, then cross-tenant; record PASS counts like "14/14 blocked") → fix what fails →
  re-run to confirm. The human reviews every diff.

---

## Standards coverage

Every finding is mapped to authoritative standards so it's traceable and actionable, not just an
opinion:

| Attack class | CWE | ASVS | OWASP API |
|---|---|---|---|
| Missing authorization | CWE-862 / CWE-306 | V4.1.1 | API1 (BOLA) / API5 (BFLA) |
| BOLA / IDOR | CWE-639 | V4.2.1 | API1 |
| SSRF | CWE-918 | V12.6 | API7 |
| Hardcoded secret | CWE-798 | V2.10 | API8 |
| SQL injection | CWE-89 | V5.3.4 | API8 |
| Command injection | CWE-78 | V5.3.8 | — |
| Path traversal | CWE-22 | V12.3 | — |
| SSTI | CWE-1336 | V5.2.5 | — |
| Mass assignment | CWE-915 | V5.1.2 | API3 (BOPLA) |
| Vulnerable dependency | CWE-1395 | V14.2.1 | API8 |
| Client-side secret exposure | CWE-200 | V14.3 | — |
| GraphQL exposure | CWE-200 | V13.1 | API8 |

(Full map, with remediation patterns, lives in `findings.py`. A future increment turns this curated
map into a full ASVS index lookup.)

---

## Proof & honesty

- **`websec proof`** clones the vuln-app corpus and scores whether recon **surfaces** each app's
  documented attack surface — a deterministic, regression-trackable proxy for engine quality. It is
  honest about what it *doesn't* measure: the full kill-criterion (does the briefing make an agent
  find planted bugs better than a generic prompt?) is the manual A/B in
  [`corpus/PROOF-PROTOCOL.md`](../corpus/PROOF-PROTOCOL.md).
- **What this tool is not:** an autonomous scanner, a SaaS, or a replacement for a human reviewer.
  It is the precise front-half that makes the agent + human dramatically more effective — and it
  tells you, with a calibrated and clearly-caveated number, how much to trust each lead.

For the market reasoning behind this design, see
[`MARKET-ANALYSIS-AND-VERDICT.md`](../MARKET-ANALYSIS-AND-VERDICT.md).

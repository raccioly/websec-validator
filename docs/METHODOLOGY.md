# How websec-validator works — the methodology, and the reasoning behind every test

<!-- docguard:version 0.9.0 -->
<!-- docguard:status approved -->
<!-- docguard:last-reviewed 2026-07-02 -->
<!-- docguard:owner @raccioly -->
<!-- docguard:quality negation-load off — this tool is defined by what it deliberately omits (no LLM, no server, no running app, no runtime deps); the negations describe real architectural properties, not phrasing defects. -->

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
                 (22 extractors)   (Trivy/Gitleaks/…,      (evidence chain +         (marching orders for
                 walk once         de-duplicated)          standards + calibrated     your agent) + immutable
                                                           confidence)                run record
                                                                  │
                 ┌──── optional, needs a LIVE test target + creds + your OK ────┐
                 5. DYNAMIC PHASE  ──▶  confirms/escalates ledger findings  ──▶  feeds calibration (self-improving)
```

Every `run` is written to an **immutable, timestamped directory** (`websec-out/runs/<ts>/`) with a
`latest` symlink — nothing is ever overwritten, so you keep a full historical record of every pass.

---

## Layer 1 — Recon: the 22 extractors

Recon walks the repository **once** into a shared `RepoContext`, then runs twenty-two focused
extractors over it. Each answers one question a pentester asks first. The output is `FACTS.json`.

| # | Extractor | What it asks | Why it matters (the security reasoning) |
|---|---|---|---|
| 1 | **stack** | What languages, frameworks, datastores? Monorepo? | Everything downstream is stack-aware. The datastore class also tells the agent which static alerts are likely noise (e.g. on a NoSQL/JSON API, most SQLi alerts are false positives). |
| 2 | **routes** | What are all the HTTP endpoints? | The endpoint inventory *is* the attack surface. Powered by [OWASP Noir](https://github.com/owasp-noir/noir) (50+ frameworks) with a regex fallback. Every probe targets a real route. |
| 3 | **auth** | What scheme, where's the token — and is the signing secret hard-coded? | You cannot reason about "who can do what" without knowing how identity is established. Detects all schemes and picks a primary; also flags an **insecure default signing secret** (`JWT_SECRET \|\| 'dev-secret'`) — if that fallback is reached at runtime, anyone who reads the source can forge tokens (a Critical the pen test found). |
| 4 | **authz** | Which endpoints have a visible auth guard, which don't? | **Broken access control is the #1 web risk (OWASP A01).** Builds the per-endpoint guard map and flags write endpoints with no visible guard. Models **router-mount auth** — `app.use('/x', authMiddleware, createXRouter())` — by resolving the mounted router factory to its file and walking the local-import graph, so an Express monorepo that splits routing from handlers isn't reported as one giant missing-auth cluster (the dominant false positive); also recognizes custom auth helpers (`getRequest*Auth`) and one-hop delegated guards in thin Next route handlers. |
| 5 | **tenant** | Is this multi-tenant, and what field isolates one customer from another? | The tenant boundary (`groupId`, `orgId`, `tenantId`…) is what every cross-tenant BOLA probe depends on, and the easiest thing to get subtly wrong. |
| 6 | **password_policy** | Is the password policy consistent across routes? | A strong policy on one route proves a weaker sibling is a *regression*, not a design choice. Fingerprints the `{min,upper,lower,digit,special}` requirement set per validator and flags any that is a strict subset of the strongest (the exact cross-route drift the pen test found). The subset comparison is logic a per-file linter can't express. |
| 7 | **surface** | Where does user input reach a dangerous sink — and where does the app leak internals back? | Maps 17 sink classes: 15 user-input-gated (SSRF, command injection, SQLi, traversal, SSTI, redirect, deserialization, XXE, prototype-pollution, ReDoS, eval, **log-injection** (CWE-117 — user input concatenated into a `console`/`logger`/`logging` message with no CR/LF neutralization; structured-logging-suppressed, server-only), **mass-assignment via object spread** `{...record, ...req.body}`, and **reflected/DOM/template XSS** — `innerHTML`/`dangerouslySetInnerHTML`/`v-html`/`document.write`/Jinja `|safe`/`mark_safe`, suppressed on a file that sanitizes with DOMPurify/bleach/escape) **plus var-arg SSRF** (`axios.get(someVar)` a file away from `req.query`) and a **response-side error-disclosure** sink (a 500 echoing `err.stack`). SSRF requires a *request-derived* URL (not any template literal) and is server-only — so browser fetches and hardcoded-host calls don't false-fire. Also flags a **reverse-proxy prefix-escape** (`..` in a catch-all path joined onto a fixed upstream prefix → confused-deputy with a forwarded token), a **host-header open-redirect** (redirect built from `X-Forwarded-Host`), and an **SSRF-redirect-hardening** gap (follows redirects with no allow-list, incl. worker scripts). "User-gated" is the key filter — `exec("ls")` is not a vuln; `exec(req.body.cmd)` is. |
| 8 | **schemas** | What are the data models, and which fields are *privileged*? | Finds ORM/schema models (Pydantic, SQLAlchemy, Django, Prisma, Mongoose, TypeORM, Zod, Sequelize) and the sensitive field names (`role`, `isAdmin`, `groupId`, `passwordHash`…). Turns mass-assignment into "try injecting *this* app's privileged fields." |
| 9 | **iac_ci** | Misconfigurations in Docker/CI/IaC — and in the managed-cloud auth config? | Insecure defaults (containers as root, unpinned CI actions) are real and invisible at the app layer. Also reads **AWS-CDK**: an AppSync `defaultAuthorization: API_KEY` is effectively **anonymous/over-permissive access** (the key ships to the browser) — the retest clarified this is *not* CSWSH (that needs cookie-WS auth, checked in `client_integrity`). And a **WAF byte-match on an app-layer token** (`__schema`, SQL keywords) is flagged as a bypassable band-aid, never a fix. WAFv2 WebACL = *"present — VERIFY association,"* never mitigation. Also parses **docker-compose** (host-takeover mounts: `docker.sock`, `pid: host`, host-root bind, `privileged`) and audits **secret-suppression** (`.gitleaksignore` silencing a leak in a real `.env`/secrets file — a hidden true positive, not a fix). |
| 10 | **client_exposure** | Do secrets leak into the browser bundle? | A secret in a `NEXT_PUBLIC_`/`VITE_` var ships to every visitor. Detected three ways: by **name**, by **value-shape** — **cloud-agnostic**: AWS (`da2-…` AppSync key, `AKIA`), Azure (storage `AccountKey=`, SAS, connection string), GCP (service-account JSON, PEM private key), plus generic (Stripe, JWT); survives a benign var rename — and by **build-injection** (a CloudFormation output wired into a public build var — invisible to every secret scanner). |
| 11 | **client_integrity** | Does a page display a **security-critical sink value** (one the user reads or copies) that a browser-resident attacker could silently swap? | The man-in-the-browser class, generalized from the agent-wallet lesson and detected by **data-flow role, not app type**: a crypto/bank address, IBAN/routing, 2FA/TOTP seed, recovery phrase, API key or webhook URL rendered/copied client-side can be rewritten by malware / a rogue extension / a poisoned dependency. Severity tracks **irreversibility** (money/credential = HIGH); confidence stays LOW — **no web app can make on-screen display tamper-proof**. Checks the two controls that move the needle (a strict CSP + an out-of-band anchor), plus a **client round-trip tamper-vector** check (#2 — a sink value fetched client-side instead of server-rendered), a **grindable safety-code** check (#7), and an **over-claimed "tamper-proof" framing** check (#8). Paired with `transport_security` (row 16). |
| 12 | **graphql** | Is there a GraphQL surface — is introspection / subscription authz sound? | GraphQL has its own failure modes. For **AppSync**: introspection **is** disablable engine-level (`introspectionConfig: IntrospectionConfig.DISABLED`), so it is flagged **only when not set** — the retest corrected an earlier over-flag, and the advice points to the engine control, not a WAF byte-match (which is bypassable via Unicode/JSON escapes). A `Subscription onEvent(groupId)` whose VTL resolver doesn't bind the tenant arg to the caller's identity is a **cross-group BOLA** (reads the `.graphql` SDL + co-located `.vtl`). |
| 13 | **upload_security** | Are file uploads (and the serve path) safe? | The polyglot/MIME-spoof class. Flags a handler that deny-lists instead of allow-listing by **sniffed bytes**, builds the stored key from the client filename (`Jpg.php` → stored executable), trusts the client `Content-Type`, or accepts SVG; and a serve path that returns a stored file with **no `X-Content-Type-Options: nosniff`** (stored XSS, re-interpreted as HTML same-origin). Checks both upload and serve, because the fix is defense-in-depth across both. |
| 14 | **pii_exposure** | Does customer PII leak at the API output boundary? | `res.json(rawEntity)` of a model with PII fields, with no DTO/masker — phone/email ship in cleartext, **including indirect carriers** (a phone embedded in a composed `providerMessageId`). The decisive tell: a masking helper / `view_full` permission **defined but with zero live call sites** (a dead control wired only into export paths). Verification is by **value shape, not field name** — a field allow-list misses the carriers. |
| 15 | **integrations** | Third-party integrations + webhooks; are webhooks signed, outbound-action endpoints guarded, secrets fetched once? | An unverified webhook is a forgeable write path. Also flags **abusable outbound-action endpoints** (#5 — an email/SMS/push handler with no auth-guard or only IP-only rate-limiting → spam / bill amplification / harassment) and **redundant secret-fetches** (#6 — the same secret-manager key pulled more than once per path, widening the exposure window). Both LOW/architectural — auth may live in middleware, so "verify these controls." |
| 16 | **transport_security** | Are the browser-hardening headers (CSP, HSTS, **CORS, SRI**) present and complete — across *all* responses, not just `/api`? | The enabling condition for the man-in-the-browser class: with no strict CSP an injected / supply-chain script can run and rewrite any on-screen value. Framework-agnostic baseline (React/Vue/Svelte/htmx/server-rendered): flags a missing/weak CSP (no nonce, `unsafe-inline`/`unsafe-eval`), inline event handlers that force `unsafe-inline`, and **partial HSTS** (set on `/api` but not the HTML document). Also flags **CORS misconfiguration** (an `Allow-Origin` that reflects the request `Origin` or `*` *together with* `Allow-Credentials: true` → any site reads authed responses), an **external script with no Subresource-Integrity** (CDN-compromise → arbitrary JS in your origin), and a **monorepo Next.js header gap** (no `headers()` security block in `packages/*/next.config.*`). Also runs a **framework-agnostic clickjacking baseline** (a web surface with neither `X-Frame-Options` nor a CSP `frame-ancestors` directive is framable — UI-redress) and a **CSRF baseline** (a cookie/session-authenticated app with HTTP routes but no anti-CSRF token library/middleware and no `SameSite` cookie — state-changing routes may be forgeable cross-site; a Bearer-token-only API is exempt, derived from the auth extractor to stay low-FP). LOW/architectural — a static scan can't see the edge/CDN layer, so verify against the live response headers. |
| 17 | **authz_dataflow** | Does the auth guard trust the *right thing*? | authz **correctness**, not just presence (row 4 answers "is there a guard?"; this answers "does it trust a forgeable input?"). Flags an access decision keyed on an **unsigned client cookie** (`twin-access-level` with no signature check — httpOnly stops JS reads, not the user's own curl), an authz check that compares a **user-influenceable JWT body claim** (office/role/group/tenant) instead of a server-resolved record, and a **transaction-local RLS context** (`set_config('app.*', …, true)` emitted outside a transaction, so the principal resets before the query and RLS runs with an empty context — defense-in-depth theater). |
| 18 | **llm_security** | Is the LLM / agent surface safe? (OWASP **LLM Top 10**) | The whole-class gap for AI apps. Detects **indirect prompt injection** (untrusted RAG/tool/web content concatenated into a prompt with no sanitizer/fence, esp. "render this URL verbatim"), **insecure output handling** (model text parsed into `JSON.parse`/a tool-call dispatch → injected text becomes tool execution), **excessive agency** (a state-changing agent tool with no human-confirmation gate), **unbounded generation** (an LLM call with no `maxTokens`/timeout → cost/latency DoS, worst unauthenticated), and **guardrail fail-open** (a moderation scan that returns allow on error/timeout). Gated on a real LLM SDK call in the file + server-only, so it points at the agentic runtime, not scripts. |
| 19 | **crypto_usage** | Are crypto primitives used correctly? | Beyond "is there a leaked secret" — *how* crypto is used. Flags a **weak password hash** (a fast/unsalted SHA-256/MD5 verifying a credential instead of argon2/scrypt/bcrypt), a **`jwtVerify` with no `algorithms` allowlist** (latent alg-confusion the day the key turns asymmetric), a **predictable principal** (a tenant/user id derived as a public hash of an identity field — anyone who knows the email recomputes the id), and a **non-constant-time secret compare** (`===`/`!==` on a request-supplied token instead of `timingSafeEqual`). |
| 20 | **webext** | Is the browser-extension client-trust boundary sound? | For MV2/MV3 extensions: **excessive host permissions** (`<all_urls>` / `*://*/*` → read/modify every site), **untrusted message channels** (a `runtime.onMessage` / window `message` handler with no `sender.id`/`event.origin` check, or `postMessage` to `'*'`), and **client-side entitlement** gates (a tier/plan read from `chrome.storage.local`/`localStorage` treated as an enforcement boundary). |
| 21 | **agent_config** | Is the repo's OWN agent/MCP wiring poisoned? (OWASP **Agentic Top 10**) | Reads the agent-steering config (`.claude/settings.json`, `.mcp.json`, cursor/copilot rules, `CLAUDE.md`/`AGENTS.md`) as **untrusted data, never executed**. Flags **invisible/bidi Unicode** in a rules file (Rules-File-Backdoor), a pre-consent hook with a **fetch-and-execute command shape** (CVE-2025-59536 class), **blanket MCP auto-approval**, a **non-vendor `*_BASE_URL` override** (key-exfil), and **unpinned/remote MCP servers**. Reads a fixed bounded allow-list off the root; tool-description *poisoning* (prose-grammar) is deferred to keep the FP bar. |
| 22 | **dependencies** | Offline supply-chain hygiene (the AI slopsquat / malicious-dep class) | What Trivy's known-CVE scan can't see. Ledger classes: a **malicious install/lifecycle script** (`postinstall` whose body fetches-and-executes/evals — the Shai-Hulud shape) and **lockfile drift** (a manifest dep absent from an existing JSON lockfile's installed set). **Unpinned versions** and **dependency-confusion-shaped names** are advisory-only (never routed to the ledger). Registry resolution / hallucinated-name / typosquat-distance are deferred behind an opt-in `--network` step — the default pass makes **zero network calls**. |

> **Why rows 17–19 exist (the self-improvement pass).** Dogfooding the tool on a large real-world
> **LLM-agent monorepo** (a 15-agent verification pass that adversarially confirmed every finding)
> surfaced two whole classes the route/auth/SSRF model couldn't see: the **agentic surface**
> (prompt construction → tool dispatch → output) and **crypto-usage / authz-correctness**. Rows 17–19
> close them. The same pass also drove the false-positive killers folded into rows 4/7/16 — validated
> end-to-end (the ledger's HIGH-finding noise dropped ~12× with no loss of the genuine findings).

> **The managed-cloud boundary (why rows 3, 9, 11, 12 grew).** A real authenticated pen test
> (`REF-PENTEST`) found that the two Criticals and two Highs lived in file types and constructs the
> recon never used to parse: the **AWS-CDK** auth config, the **AppSync GraphQL SDL**, and the **VTL**
> resolvers (`base.py` now walks `.graphql`/`.gql`/`.vtl`). Modern serverless apps put their
> authorization in exactly that managed-cloud boundary — so an AWS-heavy target's most important half
> was previously invisible. Two honest limits stated up front: regex over CDK TypeScript (not an AST)
> can be evaded by aliased / helper-extracted constructs (false negatives), and the man-in-the-browser
> class (row 11) can never be a confident static catch — it is the inherent web-platform ceiling that
> hardware wallets exist to solve, so it ships as a LOW-confidence "verify these compensating controls"
> lead, never a verdict.

> **The retest meta-lessons (what prevents the *next* finding).** A second pen-test pass on the same app
> taught five things now baked into the rules above: **(1)** a WAF/regex is never the *remediation* for an
> app-layer flaw, only a compensating control — so a `byteMatchStatement` on `__schema` is flagged as a
> smell, not a fix; **(2)** read the finding precisely — "set *old* password" is **reuse**, a different
> control from complexity, and "CSWSH" is only real with **ambient-cookie** auth; **(3)** assert by **value
> shape, not field name** — a phone embedded in a composed id slips past a field allow-list; **(4)**
> validate the whole **chain**, not the entry point — every redirect *hop*, the subscription not just the
> handshake, the byte content and the serve path not the declared type; **(5)** "tests pass" ≠ secure —
> run an adversarial pass after green. Two of these corrected the tool's *own* prior output (the AppSync
> introspection over-flag and the CSWSH mislabel) — the same discipline, applied inward.

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

## Why your agent might pause — and how to phrase the request

This tool is **defensive**: it reviews *your own* code, is read-only by default, and never touches a
live system unless you supply a TEST target and approve each probe. But a capable coding agent is
*trained* to slow down around security tooling — its own guidelines say dual-use security tools
"require clear authorization context." So if you open a repo and say **"pentest this,"** a careful
agent may stop and ask whether you're authorized. That's not a bug; it's the agent doing its job
without enough context. You remove the friction by *supplying* that context. Three levers, in order
of leverage:

1. **How you ask.** Frame it as a *defensive review of your own code*, not an *attack*. A line like —
   *"Do a defensive security self-review of my own codebase with websec-validator. It's local and
   read-only — read the repo and follow its briefing. I own this code and authorize the review."* —
   carries ownership + intent + scope + authorization in one breath, and is usually all it takes.
2. **What the tool tells the agent.** The skill description, the top of `SKILL.md`, and the
   `AGENT-BRIEFING.md` header all lead with the same scope-and-authorization statement, so an agent
   that reads them is *handed* its authorization instead of reconstructing it. Each staged probe
   carries a one-line `DEFENSIVE CHECK — run only against a system you own` header for the same reason.
3. **Where the tool comes from.** `pipx install websec-validator` from PyPI reads very differently
   from running code straight off a URL — provenance is its own trust signal.

What **doesn't** help: GitHub badges, stars, or extra README prose. An agent doesn't fetch those
before deciding — it reads your request, the skill text, and the briefing. Those are the surfaces
this tool front-loads, and the ones worth getting right.

One pause is worth **keeping**: before any probe fires at a *running* host, the agent should confirm
the target and scope with you. That checkpoint is a feature, not friction — the goal is to remove the
hesitation around *statically reading your own repo*, not the one before *live-firing at a server*.

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
| Reflected / DOM / template XSS | CWE-79 / CWE-116 | V5.3.3 | API8 |
| Mass assignment | CWE-915 | V5.1.2 | API3 (BOPLA) |
| Vulnerable dependency | CWE-1395 | V14.2.1 | API8 |
| Client-side secret exposure | CWE-200 | V14.3 | — |
| GraphQL exposure | CWE-200 | V13.1 | API8 |
| Forgeable JWT (insecure default secret) | CWE-798 / CWE-1188 | V2.10 | API2 |
| Auth backdoor (dev-token / accept-any-credential) | CWE-288 / CWE-798 / CWE-287 | V2.1.1 | API2 |
| Fail-open signature/secret verification | CWE-636 / CWE-325 | V1.1 | API2 |
| CSWSH (AppSync API_KEY default auth) | CWE-1385 / CWE-346 | V13.2 | API2 |
| Error / stack-trace disclosure | CWE-209 / CWE-200 | V7.4.1 | API8 |
| Weak / inconsistent password policy + **reuse** | CWE-521 / CWE-263 | V2.1 | API2 |
| Tamperable display (man-in-the-browser) | CWE-451 / CWE-829 | V14.4 | API8 |
| Unrestricted file upload | CWE-434 | V12.2 | API8 |
| MIME-sniffing → stored XSS (serve side) | CWE-430 / CWE-79 | V14.4.3 | API8 |
| Unmasked PII at the output boundary | CWE-359 / CWE-200 | V8.3 | API3 |
| Prompt injection (LLM, incl. indirect) | CWE-1427 / CWE-77 | V5.1 | LLM01 |
| Insecure LLM output handling | CWE-94 / CWE-79 | V5.2 | LLM02 |
| Excessive agency (agent tools) | CWE-862 / CWE-250 | V1.1 | LLM06 / LLM08 |
| Unbounded LLM consumption | CWE-770 | V11.1.4 | LLM10 / API4 |
| Guardrail fail-open | CWE-693 / CWE-755 | V1.1 | LLM01 / LLM02 |
| Weak password hashing | CWE-916 / CWE-759 | V2.4.1 | API2 |
| JWT verify without `algorithms` | CWE-347 | V3.5.2 | API2 |
| Predictable security principal | CWE-330 / CWE-340 | V6.3.1 | API1 |
| Non-constant-time secret compare | CWE-208 | V6.2.3 | API2 |
| CORS misconfiguration | CWE-942 | V14.5.3 | API8 |
| Clickjacking (no X-Frame-Options / frame-ancestors) | CWE-1021 / CWE-451 | V14.4.7 | API8 |
| CSRF (cookie-auth, no token / SameSite) | CWE-352 | V4.2.2 | API8 |
| Missing Subresource-Integrity | CWE-829 | V14.2.3 | API8 |
| Unsigned-cookie authorization | CWE-565 / CWE-602 | V3.4 | API1 / API5 |
| Claim-keyed authorization | CWE-639 / CWE-807 | V4.2.1 | API1 |
| Transaction-local RLS context | CWE-1188 | V4.1.3 | API1 |
| Reverse-proxy prefix-escape | CWE-441 / CWE-22 | V12.3 | API7 / API8 |
| Open redirect (incl. Host-header) | CWE-601 | V5.1.5 | — |

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

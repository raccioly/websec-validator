# How it works

websec does the deterministic half of a security review and hands the judgment half to your AI
agent and you. This page is the short conceptual tour: the flow, what the tool reads, how it ranks
what it finds, and what it refuses to claim. The long-form reasoning behind every check is in
[METHODOLOGY.md](../METHODOLOGY.md).

## The two halves

The tool reads supported source, maps the attack surface it can see, de-duplicates the scanners
you allow, stages probes tailored to what it found, and writes a briefing. It contains no LLM and
needs no server or running app for that core pass. Your agent and you do the reasoning: confirm the
model, triage, run probes against a test instance, fix and re-verify.

```text
websec (deterministic)                 your agent + you
─────────────────────────────────      ─────────────────────────────────
1. recon → full attack surface     →   confirm the tenant boundary + auth model
2. de-dup scanners (--scan, opt-in)→   triage real-vs-noise
3. stage tailored probes           →   fill placeholders, run vs a TEST instance
4. emit AGENT-BRIEFING.md          →   propose fixes, re-run to confirm, report back
```

Static recon and the briefing need only the code, and run without `--scan`. *Running* the probes
needs a live test instance and test credentials, which the human supplies. `websec run` itself never
touches a running app; only the separate, explicitly invoked `websec dynamic` does, and only against
a target you name. See [Dynamic testing](../guides/dynamic-testing.md).

| Actor | Owns |
|---|---|
| The tool (deterministic) | Read the repo, map the surface, de-dup scanner output, stage probes, emit the briefing and a calibrated findings ledger |
| Your AI agent | Confirm the auth and tenant model, finalize and run probes, triage real versus noise, propose fixes, re-verify |
| You | Supply the TEST instance and test accounts, review every diff, authorize any live probing |

[METHODOLOGY: the pipeline](../METHODOLOGY.md#the-pipeline) shows the same flow as five layers.

## What it extracts

Recon walks the repository once into a shared context and runs 22 deterministic extractors over
it. Each answers one question a pentester asks first; the answers land in `FACTS.json`. The table
groups them by the `category` each extractor declares in code.

| Category | Extractor | Dimension | Notable output |
|---|---|---|---|
| inventory | `stack` | Languages, frameworks, datastores | Manifest-aware service inventory, including Rust workspaces; declared hints do not prove deployment |
| data | `schemas` | Data models + **privileged fields** | Pydantic/SQLAlchemy/Django/Prisma/Mongoose/TypeORM/Zod/Sequelize → `role`/`isAdmin`/`groupId` for mass-assignment targeting; committed SQL `CREATE TABLE` and RLS posture |
| surface | `routes` | Endpoints via **OWASP Noir** plus websec's own registration lanes (Supabase Edge, AWS SAM / Function URL, raw `http.createServer`/`Bun.serve`/Python `http.server`, Django, Connexion, tRPC, literal Spring/ASP.NET) | Method, path, typed params, code path, **AuthType:NONE public endpoints**; **fixture/example routes split out of the attack surface** |
| surface | `graphql` | GraphQL surface | Introspection (**AppSync `introspectionConfig: DISABLED`-aware**), playground, depth limit, **AppSync subscription authz (cross-group BOLA)** |
| surface | `integrations` | Third-party services, webhooks, **outbound-action endpoints** | Unsigned webhooks; email/SMS/push handlers with no auth or IP-only rate limiting; redundant secret fetches |
| authn | `auth` | Scheme, login surface, **insecure-default signing secrets**, **broken-auth backdoors** | A hard-coded `JWT_SECRET \|\| 'dev-secret'` fallback (forgeable JWT), a **`dev-` token / accept-any-password backdoor** (total bypass, CRITICAL), and a **fail-open** `if(env.SECRET)` signature check |
| authn | `password_policy` | Cross-route consistency **+ reuse/history** | Complexity drift across routes; a set-password path that hashes without a reuse check |
| authz | `authz` | Access-control map | Guard coverage (including **router-mount auth**), **write endpoints with no visible guard**, roles |
| authz | `tenant` | Multi-tenancy key candidates | The BOLA boundary, ranked by frequency, for you to confirm |
| authz | `authz_dataflow` | Authz *correctness*: does the guard trust the right thing? | **Unsigned-cookie authorization**, **claim-keyed authz** (user-influenceable JWT claim), **transaction-local RLS context** (resets before the query) |
| sinks | `surface` | 17 sink classes **+ redirect-SSRF** | User-input-gated sinks, including mass assignment via object spread, reflected/DOM/template XSS (`innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `\|safe`; sanitizer-gated) and log injection (CWE-117; structured logging suppressed), plus variable-argument SSRF, error disclosure, redirects followed without a per-hop guard, reverse-proxy prefix escape and host-header open redirect |
| sinks | `upload_security` | Unrestricted upload + unsafe serve | Deny-list-only validation, stored name from client filename, trusted client MIME, accepted SVG, **serve without `nosniff`** |
| exposure | `client_exposure` | Browser leakage | Public-variable secrets by **name, value shape (`da2-…`) and CDK build injection**, server secrets in client code, source maps |
| exposure | `client_integrity` | Tamperable display (client trust boundary) + **WebSocket auth model** | Security-critical values the user reads or copies (address, IBAN, 2FA seed, API key, webhook) without a strict CSP or out-of-band anchor; client-tamper vector, grindable fingerprint, over-claimed control, the CSWSH determinant |
| exposure | `transport_security` | CSP, HSTS, **CORS**, **SRI**, **clickjacking**, **CSRF** baseline | Missing or weak CSP, inline event handlers, partial HSTS, CORS reflect-origin with credentials, external script without SRI, monorepo `next.config` header gap, no `X-Frame-Options`/`frame-ancestors`, cookie auth with no CSRF token library and no SameSite |
| exposure | `pii_exposure` | Unmasked PII at the output boundary | `res.json(rawEntity)` with PII, and a masking control defined but with zero live call sites (value shape, not field name) |
| crypto | `crypto_usage` | Crypto-API correctness | **Weak password hash** (fast/unsalted SHA-256/MD5), `jwtVerify` without an `algorithms` allowlist, **predictable principal** (id = hash of email), non-constant-time secret compare |
| llm | `llm_security` | LLM and agent surface (**OWASP LLM Top 10**) | Indirect **prompt injection**, **insecure output handling** (model text → tool dispatch), **excessive agency**, **unbounded generation**, **guardrail fail-open** |
| client-trust | `webext` | Browser-extension trust boundary | Excessive host permissions, unchecked message channels, client-side entitlement gates |
| infra | `iac_ci` | IaC + CI/CD | GitHub Actions injection (**`run:`-position aware**), unpinned actions, committed tfstate, CDK AppSync `API_KEY` default auth, **docker-compose host takeover** (`docker.sock`, `pid: host`, `privileged`), **`.gitleaksignore` secret-suppression audit** |
| agent-config | `agent_config` | The repo's own agent/MCP wiring (**OWASP Agentic Top 10**) | Reads `.claude/settings.json`, `.mcp.json`, cursor/copilot rules as untrusted data (never executed): **invisible/bidi Unicode** rules backdoor, **fetch-and-execute hook** (CVE-2025-59536), **blanket MCP auto-approve**, **`*_BASE_URL` override** (key exfiltration), **unpinned MCP server**, **committed secret in an MCP `env`/`headers` block** (value shape, `${VAR}`-safe) |
| supply-chain | `dependencies` | Offline supply-chain hygiene (the AI slopsquat class) | **Malicious install/lifecycle script** (fetch-and-exec `postinstall`), **lockfile drift** (manifest dependency absent from the lockfile), unpinned and dependency-confusion names (advisory only), registry and typosquat resolution behind opt-in `--network` |

Plus **derived targeting**: IDOR, SSRF, open-redirect, upload, write and auth-endpoint candidates,
so probes point at the exact endpoints rather than being fired blindly.

Two limits apply to the whole table:

- **It is bounded static analysis.** Regex and bounded AST passes, not a compiler or interpreter.
  Aliases, wrappers, cross-function flow and deployment behaviour stay unverified, and every
  finding is a lead with an honest confidence, not a verdict.
- **Depth depends on the language.** Python, JavaScript and TypeScript get the full set. Other
  languages get named checks or nothing. [Languages and frameworks](../reference/languages.md) is
  the authoritative matrix.

Each extractor's reasoning: [METHODOLOGY: Layer 1](../METHODOLOGY.md#layer-1--recon-the-22-extractors).

## Scanners and de-duplication

With `--scan`, websec executes the installed third-party scanners (Trivy, OSV-Scanner, Gitleaks,
Semgrep/OpenGrep, Checkov, plus Bandit, gosec or Brakeman when their language is detected) and
merges their native output into one severity-ranked set in `findings.json`. Without `--scan` it only
reports which scanners are available.

De-duplication is by fingerprint. When two results share one, the rows merge, keep the highest
severity and list every tool that reported it. Dependency CVEs use the same `cve|package|id` shape
for every SCA tool, so that is where cross-tool merging mostly happens: with both SCA engines
installed, Trivy and OSV-Scanner cross-check each other, the same CVE from both collapses to one row
tagged `tools: [osv-scanner, trivy]` (agreement means higher confidence), and OSV-Scanner's broader
lockfile coverage catches CVEs Trivy misses. Secret, SAST and IaC fingerprints include each tool's
own rule identifier and location, so they merge only on exact repeats.

Hygiene passes run before the merge: findings inside skipped directories and `--exclude` paths are
dropped, secrets in gitignored local files and in test/fixture files are downgraded rather than
dropped, because a real key pasted into a test is still a committed leak.

A missing scanner never fails the run unless you named it with `--scanners`; a named scanner that
is missing makes the run incomplete rather than clean. See
[METHODOLOGY: Layer 2](../METHODOLOGY.md#layer-2--static-scanners).

## Prioritization

A dependency CVE list is noise until you know which ones matter. With `--scan`, websec enriches every
dependency vulnerability along two deterministic, offline axes: reachable and exploitable.

- **Reachability.** Is the vulnerable package actually **imported** in your first-party source, or
  only declared in the lockfile? websec searches the real `import`/`require`/`from` sites and tags
  each CVE `imported` or **`declared-only` (likely unreachable; verify)**. Declared-only
  vulnerabilities are a major noise class. The check is name-based: a full call graph is out of
  model, import absence does not prove runtime unreachability (dynamic imports and transitive
  calls are not seen), and ecosystems whose imports websec does not parse (Go, Rust and others) are
  tagged `n/a` rather than guessed.
- **Exploitability.** Each CVE is joined against a **local cache** of
  [FIRST.org EPSS](https://www.first.org/epss/) (exploit probability) and the
  [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (known
  exploitation reports). These are prioritization inputs alongside application context.
  `websec intel refresh` explicitly downloads the public feeds without sending project data.
  Snapshots record source hashes, dates and freshness; consumers stay offline. Legacy flat caches
  are marked unverified. With no cache, this step is skipped.

Both are **strictly additive**: they annotate and re-rank, but never change a finding's severity,
drop one, or add one. They can sharpen triage; they cannot introduce a false positive.

An optional third input, blast radius, comes from a [graphify](https://github.com/Graphify-Labs/graphify)
knowledge graph if one is present (`graphify-out/graph.json` or `--graph`). It tags each mapped
finding with how much of the app transitively depends on the vulnerable code. It is read as plain
JSON and is also additive.

## Aim the pentest instead of competing with it

Dynamic scanners re-discover at runtime, expensively, much of what is already visible in the
source. websec knows it statically, so it aims them. Both sections below are in
`AGENT-BRIEFING.md`.

- **§4b: what a DAST *will* report, before you run one.** Each static finding is mapped to the
  concrete scanner signature it produces (`missing-csp` → ZAP 10038/10055, SQL injection → ZAP 40018
  or sqlmap, SSRF → Nuclei/ZAP out-of-band), with the source location that causes it. Fix those and
  the scan comes back clean on them; the run becomes confirmation, not discovery.
- **§4b also lists the blind spots.** BOLA, missing auth, mass assignment, RLS gaps, JWT algorithm
  confusion, committed secrets, supply chain, each with *why* no scanner finds it. A clean scan is
  not "safe", and saying so is the point.
- **§5b: a phased, pre-aimed runbook.** Phase 1 safe recon, Phase 2 authorization (two identities,
  the scanner-blind class), Phase 3 injection, fired only at sink-backed endpoints and gated behind
  an explicit authorization warning. Every item names a real target and a confirm/disconfirm oracle.
- **Close the loop.** Feed a real scan back to confirm or refute each prediction, so `P(real)`
  personalizes to your app over time:

  ```bash
  websec calibrate --ingest-dast zap.json --ledger findings-ledger.json
  ```

  Blind-spot classes are never scored: a scanner's silence there means nothing.

## Calibrated confidence

A label such as "MEDIUM" is only useful if it maps to how often such leads turn out real.
`websec calibrate` runs the ledger against a labeled corpus of deliberately vulnerable apps
(VAmPI, NodeGoat, DVGA), measures how often each *(attack class, confidence)* bucket is a **real**
documented vulnerability, and writes `calibration.json`, which ships with the package and is
applied at runtime. Each finding then carries `P(real)` with a **95% Wilson confidence interval**
and the sample size `n`, so "MEDIUM" becomes a measured rate with stated uncertainty.

How a finding gets its number:

1. Use the *(attack class, confidence)* cell if it has at least `min_n` samples (currently 5).
2. Otherwise fall back to the per-confidence aggregate.
3. Otherwise use a clearly flagged **uncalibrated prior**. The `basis` field on the finding says
   which tier was used.

**Honest caveats.** The corpus is *deliberately vulnerable*, so the rates skew **optimistic** for
clean production code. Small samples mean **wide intervals**: the interval is the headline, not the
point estimate, and both tighten as the corpus grows. Unmatched findings remain **unknown** unless
explicit negative evidence labels them false. Historical measurements that counted
unmatched-as-false are not a fresh measurement of the current detector revision. The shipped
table's `meta` block records its review date, how many findings carry reviewed labels and how many
stayed unknown, and states that it was not rebuilt for later detector changes; read it before
quoting a rate. No ML and no dependencies: a binomial proportion with a Wilson interval, a structure
that can upgrade to isotonic regression if a large labeled set ever exists.

**Evidence controls learning.** Dynamic status codes and scanner silence are observations, not
truth labels. Only evidence-backed labels are admitted to the local calibration overlay; legacy
unproven samples are quarantined. Unknown-only input reports no successful measurement and leaves
existing fitted calibration unchanged. A DAST hit may confirm a scoped lead; absence from a report
cannot refute it. Manual labels should include reviewer and evidence provenance, not only a boolean.
An operator's `websec feedback --verdict false-positive` queues a *candidate* that a human must
accept with `websec calibrate --accept`; it is never a label on its own. Authored paired fixtures
are scored separately (`websec calibrate --synthetic`) and never merged into `P(real)`.

**Shared format.** `websec calibrate --claimspec PATH` (or `-` for stdout) exports the table the
runtime actually uses, the shipped corpus table plus your local overlay merged, as a
[claimspec](https://github.com/raccioly/testguard/tree/main/spec) v1 `calibration` document, the
Guard-family interchange format. Nothing is lost in translation: the caveat, limitation, evidence
status, `minN` floor, the per-confidence backoff tier and the labelled uncalibrated prior all
travel with the numbers (`measures: finding-real`, `bucketBy: attackClass|confidence`). Each cell
carries raw `n` and `positives`, so a consumer can recompute `p` and the Wilson interval and merge
two tables by summing counts, the only merge the spec allows. `source.kind` says where the labels
came from: `human-label` for the shipped table, `tool-oracle` for an overlay-only table, `mixed` once
your samples are folded in. The writer refuses to export a cell whose stored numbers do not
reproduce from its counts, rather than emit a document the spec validator would reject. The internal
`calibration.json` shape and the local overlay are unchanged.

Full detail, including the strictly-proper-scoring-rule objective:
[METHODOLOGY: calibrated confidence](../METHODOLOGY.md#layer-3b--calibrated-confidence-cje).

## Proof harness

`websec proof` clones a vuln-app corpus (VAmPI, NodeGoat, DVGA) and scores whether recon surfaces
each app's documented attack surface. It is a deterministic, CI-trackable proxy for engine quality
(historically **10/10**, not rerun for the current detector revision). It does not measure the real
kill criterion: does the briefing lift an agent's bug-finding compared with a generic prompt? That
is the manual A/B in [corpus/PROOF-PROTOCOL.md](../../corpus/PROOF-PROTOCOL.md), and like the
competitor comparison it has not been run. Methodology, calibrated precision numbers and the
competitor-comparison protocol are in [BENCHMARKS.md](../../BENCHMARKS.md).

`proof` and `calibrate` are development commands; both fetch the public corpus apps from GitHub.

## The evidence model

Every finding in `findings-ledger.json` carries what you need to check it rather than trust it:

- **An evidence chain across layers.** A recon hypothesis and a later dynamic observation keep a
  `recon → dynamic` chain. A status code alone never promotes a missing-auth lead to a verified
  HIGH or CRITICAL.
- **A standards citation**: CWE, ASVS and the relevant OWASP API Top 10 entry.
- **Three separate axes**: severity (how bad if real), calibrated `P(real)` (how likely real) and a
  disposition (`agent-fixable` or `human-required`: can an agent act alone?). Disposition is
  derived from a published per-class policy (`websec capabilities`) and gates nothing.
- **A stable fingerprint**, so acknowledgements, baselines, SARIF and feedback all address the
  same finding across runs.

Around the findings, `coverage.json` records what ran, what was skipped and why, and hashes the
detector code and the bytes read. `manifest.json` hashes the emitted artifacts so later edits are
detectable. See [Outputs](../reference/outputs.md).

## What it refuses to claim

- **A clean run is not "secure".** Completed execution describes the requested checks;
  `protection_complete` is always `false`. A language with no analyzer is reported as a gap, never
  as clean. See [what a clean run means](../reference/languages.md#what-a-clean-run-means-for-your-stack).
- **A recon lead is not a confirmed vulnerability.** Guard detection is a hint; the dynamic phase
  or a human turns a lead into a finding.
- **Scanner silence is not safety**, and a DAST report's absence of a finding cannot refute one.
- **A disappeared finding is not a fix.** It is "no longer observed" until a repair is verified
  with positive and negative evidence.
- **A label or no-match check is not language support.** Named profiles are bounded checks, not
  whole-language coverage.
- **Evidence is not compliance.** `websec attest` renders no verdict, score or badge.
- **The local gate is not a control.** Client-side hooks are developer ergonomics; enforcement
  belongs in a required CI status check.

## See also

- [METHODOLOGY.md](../METHODOLOGY.md): the long-form why behind every check
- [Languages and frameworks](../reference/languages.md): what each language actually gets
- [Outputs](../reference/outputs.md): every artifact and its fields
- [Triage and suppression](../guides/triage-and-suppression.md): acting on the ledger
- [AI agents](../guides/ai-agents.md): handing the briefing to your agent
- [Glossary](../glossary.md)

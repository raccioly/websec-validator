# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Blast-radius enrichment from a graphify knowledge graph** (`graph_enrich.py`, opt-in, zero new
  deps). If the scanned repo has `graphify-out/graph.json` (or `--graph <file>` is passed), each
  finding is tagged with how much of the app transitively **depends on** the vulnerable code —
  reverse-reachability over dependency edges (calls/imports/references/inherits/…). A SQLi in a
  leaf handler and the same SQLi in a shared helper imported by 40 modules stop looking equally
  urgent. Findings gain a `graph` block (`nodes`, `blast_radius`, `dependents` sample, `community`)
  and the ledger a `graph_enrichment` summary. Pure stdlib JSON (never imports tree-sitter, so the
  zero-runtime-deps guarantee holds), reverse-BFS bounded at 20k visits with disclosed truncation,
  and wrapped so a malformed/oversized graph can never fail a run. 10 new tests.

- **`websec hooks` — git guardrail** (`hooks.py`). Wires the baseline-diff into git so websec runs
  automatically per commit/push: `hooks install` writes an advisory **post-commit** hook (recon-only,
  ~1s, prints a `baseline: N new` heads-up, never blocks); `hooks install --pre-push` writes a
  blocking **pre-push gate** that fails the push when NEW findings at/above `WEBSEC_HOOK_FAIL_ON`
  (default `high`) are introduced. Marker-delimited install/uninstall (appends to and preserves an
  existing hook), interpreter pinned + allowlist-sanitized so it survives pipx/uv isolation without
  shell-injection risk, hooks dir resolved via `git rev-parse` (worktrees + core.hooksPath aware),
  and old guardrail runs pruned to the last 5. `WEBSEC_SKIP_HOOK=1` overrides. Stdlib only, 10 new
  tests incl. an end-to-end real-commit run. Adapted from graphify's hook installer.

- **`websec install <host>` — multi-host agent installer** (`install.py`). Teaches any of the core
  agent hosts to reach for websec-validator on a security review: `claude`, `codex`, `cursor`,
  `gemini`, `aider`, plus a `generic` `AGENTS.md` writer. Skill-style hosts (Claude, Cursor) get a
  dedicated skill/rule file; shared-instruction hosts (Codex/Gemini/Aider/generic) get an idempotent
  marked block injected into their standing-instructions file without clobbering the user's own
  content. `--user` installs home-wide, `--uninstall` removes cleanly, `websec install status` lists
  what's present. Closes the gap between the README's "any agent can act on it" and shipping only a
  Claude plugin. Stdlib only, path-safety-guarded, 12 new tests.

- **No-Row-Level-Security detection** (`missing-rls` class, in `schemas.py` + the ledger) — committed
  Postgres/Supabase DDL declares owner/tenant-scoped tables but ships **zero** `CREATE POLICY` /
  `ENABLE ROW LEVEL SECURITY` anywhere in the `.sql` corpus (the CVE-2025-48757 "Lovable" class).
  Ledger-only correlation of existing facts (**not** a new extractor, count unchanged). Heavily FP-guarded:
  fires only on an owner-column-bearing table, aggregates RLS tokens across all migrations, gates on a
  Postgres/Supabase stack, honors the truncation guard, strips SQL comments, and ships **MEDIUM/LOW**
  with an explicit "RLS may be dashboard-defined — verify" caveat (escalates to HIGH only when a Supabase
  anon key makes the tables directly browser-reachable). Distinct from the existing `rls-context` class.
- **`agent_config` extractor** (21st extractor) — scans the repo's OWN agent/MCP wiring as untrusted data
  (`.claude/settings.json`, `.mcp.json`, cursor/copilot rules, `CLAUDE.md`/`AGENTS.md`), mapped to the
  OWASP Top 10 for Agentic Applications. Five classes: invisible/bidi Unicode in a rules file
  (Rules-File-Backdoor), a pre-consent hook with a fetch-and-execute command **shape** (CVE-2025-59536
  class), blanket MCP auto-approval, a non-vendor `*_BASE_URL` override (key-exfil), and unpinned/remote
  MCP servers. It reads a fixed bounded allow-list directly off the root and **never executes** anything it
  finds. Tool-description *poisoning* (prose-grammar match) is intentionally deferred to keep the FP bar.
- **Log-injection (CWE-117) sink class** — the 17th `surface` sink. User input concatenated/interpolated
  into a logging call (`console`/`logger`/`logging`/`winston`/`pino`) with no CR/LF neutralization (log
  forging). **LOW** severity (not RCE). Structured/parametrized logging (`logger.info('u=%s', x)`, pino's
  object arg, `extra={…}`), bare `print()`, and client/CLI/no-web-surface files are all suppressed.
- **`dependencies` extractor** (22nd extractor) — offline supply-chain hygiene for the AI slopsquat /
  malicious-dep class Trivy can't see. Two ledger classes: a **malicious install/lifecycle script**
  (fetch-and-execute/eval body — the Shai-Hulud shape, MEDIUM) and **lockfile drift** (a manifest dep
  absent from an existing JSON lockfile's installed set, LOW). Unpinned/floating versions and
  dependency-confusion-shaped names are surfaced as **advisory facts only** (never routed to the ledger,
  so they can't inflate findings). Registry resolution / known-hallucinated-name / typosquat-distance are
  **deferred behind an opt-in `--network` step** — the default pass makes zero network calls.
- Metrics: **20 → 22 extractors** (`agent_config`, `dependencies`), **16 → 17 sink classes**
  (log-injection), **285 → 324 tests**. New finding classes: `missing-rls`, `log-injection`,
  `agent-config-hidden-unicode` / `agent-hook-autoexec` / `agent-mcp-autoapprove` /
  `agent-config-baseurl-override` / `agent-mcp-unpinned-server`, `malicious-install-script`,
  `lockfile-drift`. `schema_version` unchanged (`1.0`, additive facts). All findings flow through the
  existing calibrated-`P(real)` + de-dup + `.websec-ignore` machinery.
- Open-source hygiene surface: root `SECURITY.md` (GitHub-recognized security policy with
  private-reporting flow), `CONTRIBUTING.md` (ground rules + dev setup + PR checklist),
  `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), issue templates (bug / **false positive** /
  feature) + PR template, and Dependabot config (GitHub Actions + Docker base image).
- README status badges (CI, PyPI, Python, zero-deps, SARIF, license).
- PyPI metadata: trove classifiers and `[project.urls]` (homepage, docs, changelog, issues) —
  populates the sidebar on the PyPI project page from the next release.

### Changed

### Fixed

### Removed

## [0.10.0] — 2026-07-03

Minor: the **browser-vuln trio** (XSS / clickjacking / CSRF) closes the classic-web-vuln gap, and a
new **enterprise / CI integration surface** turns websec from a CLI-a-human-runs into a truth source a
pipeline, dashboard, or any MCP agent can consume — SARIF, a `--fail-on` gate, git-diff baselining, a
GitHub Action, an MCP server, and versioned output schemas. All stdlib, zero new runtime deps.

### Added
- **SARIF 2.1.0 output** (`formats.py`) — every `run` writes `results.sarif` (one `rule` per attack
  class carrying its CWE/ASVS/OWASP citation; severity → error/warning/note; stable
  `partialFingerprints`). Drops into GitHub Code Scanning (inline PR annotations + Security tab),
  GitLab, Azure DevOps, VS Code, DefectDojo. `--format sarif` also emits it to stdout for piping.
- **CI gate** — `--fail-on {critical,high,medium,low}` exits 1 when a finding at/above that severity
  remains (report-only by default).
- **Baseline / diff** (`baseline.py`) — `--baseline <prior findings-ledger.json>` marks findings
  `new`/`unchanged`/`fixed` via a stable per-finding fingerprint (surfaced as SARIF `baselineState`);
  `--fail-on` then gates on **only the new** findings, so a legacy backlog doesn't block every PR.
- **Reusable GitHub Action** (`action.yml`) — composite action: install → run → upload SARIF, with
  `fail-on` / `baseline` / `scan` inputs.
- **MCP server** (`mcp_server.py`, `websec mcp` + a `websec-mcp` entry point) — Model Context Protocol
  over stdio (raw JSON-RPC 2.0, stdlib only) exposing `websec_recon` / `websec_findings` /
  `websec_sarif` / `websec_briefing` so Cursor/Cline/Windsurf/Zed can call recon as typed tools.
- **Versioned output contract** — `schema_version` on FACTS/ledger/envelope + published JSON Schemas
  (`schemas/facts.schema.json`, `schemas/ledger.schema.json`); a `findings.envelope.json` artifact.
- **JSON envelope output** (`--format json`) — a self-describing wrapper around the ledger for
  non-GitHub CI / dashboards.
- **Reflected / DOM / template XSS sink class** (`surface.py`, 16th sink class) — the classic
  browser-rendered vuln the recon layer previously deferred entirely to optional Semgrep. Detects
  DOM sinks (`innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write`/jQuery `.html()`), React
  `dangerouslySetInnerHTML`, Vue `v-html`, and server template-escape-off (Jinja `|safe`, `mark_safe`,
  `Markup(`, `{% autoescape false %}`, interpolated `res.send`/`res.write` HTML). A per-file sanitizer
  guard (DOMPurify / sanitize-html / bleach / `escapeHtml`) suppresses the lead so a sanitized render
  doesn't false-fire; kept LOW-confidence like every surface signal (`xss` → CWE-79/CWE-116, ASVS V5.3.3).
- **Framework-agnostic clickjacking baseline** (`transport_security.py`) — a web surface that sets
  neither `X-Frame-Options` nor a CSP `frame-ancestors` directive is framable (UI-redress). Previously
  clickjacking was only checked inside Next.js configs; now it parallels the CSP/HSTS baseline for
  Express/Flask/Django/any surface (`clickjacking` → CWE-1021/CWE-451, ASVS V14.4.7).
- **CSRF baseline** (`transport_security.py`) — a cookie/session-authenticated app with HTTP routes
  but no anti-CSRF token library/middleware (csurf/csrf-csrf/@fastify/csrf/Django/Rails) and no
  `SameSite` cookie attribute. Derived from the auth extractor so a Bearer-token-only API is exempt —
  low-FP by design (`csrf` → CWE-352, ASVS V4.2.2).

### Changed
- Metrics: 15 → **16 sink classes**, 238 → **285 tests**. New modules: `formats.py`, `baseline.py`,
  `mcp_server.py`, `schemas/`. New CLI: `--format`, `--fail-on`, `--baseline`, `websec mcp`.

### Added (coverage — false negatives the FP/FN audit surfaced)
- **AWS SAM / serverless route modeling** (`routes.py`) — a `template.yaml`'s `AWS::Serverless::Function`
  Api/HttpApi events and Function URLs are now mapped to routes (handler resolved to the source file,
  build-dir `dist/`→`src/` aware), so a serverless backend is no longer 0-routes/unprobed. A Function URL
  with `AuthType: NONE` emits an **unauthenticated-serverless-endpoint** finding (a public dashboard
  serving account/P&L/PII data is the risk). Stdlib-only line/regex parse — no YAML dependency. On the
  audit corpus this surfaced a public P&L dashboard and a 19-route backend that were previously invisible.
- **Broken-auth backdoor detector** (`auth.py`) — the total-auth-bypass bugs the route/guard model can't
  see because the endpoint *is* "guarded", just by something forgeable. Flags a **dev-token backdoor**
  (`token.startsWith('dev-')` deriving a principal), an **accept-any-credential** login (explicit
  accept-any/MVP intent, or a password-length-only check with no hash compare), and a **fail-open
  signature/secret verification** (`if(env.*_SECRET){ verify }` that silently skips when the secret is
  unset). New classes `auth-backdoor` (CRITICAL, CWE-288/798/287) and `fail-open-auth` (HIGH, CWE-636/325).
  On the audit corpus it caught a treasury API's `dev-*` bearer bypass, an accept-any-password login that
  self-elevates to admin, and a fail-open Stripe webhook verify — all previously missed.

### Fixed
Real-repo false-positive audit (ran recon against a diverse set of real GitHub repos — TS/Python
frontends, backends, CLIs, static sites):
- **Path-scoped standalone guard mounts** (`authz.py`) — `app.use('/api', requireAuth)` on its own
  line, with routers mounted on `/api` in later statements, is now recognized (resolving each router
  instance's import and respecting Express source order, so a router mounted *before* the guard — e.g.
  a public login route — stays unguarded). Cut a real backend's guarded-route false positives 63→5.
- **Frontend API-client files no longer parsed as server routes** (`routes.py`) — in a combined
  frontend+backend monorepo, a React axios client (`import {api} from './client'; api.get('/x')`) and
  static hosting config (`public/_redirects`) were emitted as endpoints and flagged missing-auth. Now
  dropped via a client-vs-handler discriminator that still keeps serverless handlers (Cloudflare Pages
  `onRequest*`, Lambda `handler`) even when they call axios/fetch. Cut a monorepo's missing-auth 185→3.
- **Python test files** (`test_*.py` / `*_test.py` / `conftest.py`) are now classified as tests
  (`base.py`), so a `test_curl.py` doing `requests.get()` no longer false-fires SSRF.
- **Browser-hardening findings gated on a served-web surface** (`transport_security.py`) — CSP / HSTS /
  clickjacking no longer fire on a non-web Python/CLI tool that merely builds an HTML string (a report
  generator); they require an HTTP-serving construct (`new Response` / `res.send` / a framework).

Second FP audit — a 15-agent adversarial workflow verified every finding across the corpus against the
real code and clustered the false positives; the dominant patterns are now fixed (corpus findings
308 → 191, −37%, with zero true-positive loss):
- **App-specific auth-wrapper recognition** (`authz.py`) — a handler wrapped in an application HOF that
  composes a known guard (`withDealAuth = withAuth(...)`, `withSuperAdmin`, `requireUserRecord`) is now
  credited (dynamic guard-alias resolver, generic-aware `withDealAuth<{…}>(`). Also recognizes Fastify
  `addHook('onRequest', auth)` / per-route `{preHandler: auth}` and a secret-bearer guard
  (`Bearer ${CRON_SECRET}`). Cut one real app's missing-auth 94→3 (total 111→18).
- **Request-driven sinks gated on a web surface** (`surface.py`) — SSRF / path-traversal /
  command-injection / open-redirect are suppressed on a repo with no HTTP listener (a CLI / library /
  data tool: `languages` analyzed, no routes, no framework) and in more script/CLI file classes
  (research/, tools/, notebooks/, a Python `__main__`/argparse module).
- **PKCE is not password hashing** (`crypto_usage.py`) — a `createHash('sha256')` over an OAuth PKCE
  `code_verifier` (RFC 7636) no longer false-fires weak-password-hash.
- **webhook-forgery requires receiver evidence** (`integrations.py`) — an OAuth authorization-code
  callback, a webhook-subscription-management CRUD route, or a GET stub at a webhook-ish path is no
  longer flagged unsigned; a weak path (`/callback`) now needs raw-body/event/signature evidence, and
  verification via an imported helper (`constructEvent`) counts. Cleared ~16 FPs; kept real leads.
- **CSRF credits framework defaults** (`transport_security.py`) — NextAuth/Auth.js (SameSite=Lax by
  default) and Next.js Server Actions (built-in Origin check) no longer trigger the no-SameSite CSRF lead.

## [0.9.1] — 2026-07-02

Patch: recognise a Supabase **anon/publishable** key (a JWT with `role: anon`, or an `sb_publishable_`
key) as **intended-public** — it's designed to ship to the browser and is protected by Row-Level
Security — so the generic secret scanners' "JWT token" hit on it is downgraded to INFO instead of
ranking as a HIGH secret above the real findings. A **service_role** key (bypasses RLS) is still
surfaced as a CRITICAL leak. 238 unit tests.

### Fixed
- **Supabase anon-key false positive** (`client_exposure.py`, `findings.py`) — decode the JWT `role`
  claim (or read the `sb_publishable_` / `sb_secret_` prefix) to classify the key by trust tier. Any
  scanner JWT finding (gitleaks/trivy/semgrep) on a file whose key is the anon/publishable key is
  reclassified to INFO; the anon key is listed at INFO (acknowledged-and-cleared) and a `service_role`
  key literal is raised to CRITICAL (`supabase_service_role_in_client`). Provider-agnostic by value —
  an arbitrary third-party JWT is left to the generic value-leak path.

## [0.9.0] — 2026-07-02

Licensed-app & browser-extension coverage. Recon now models manifest-less stacks (Deno/Supabase edge
functions + Chrome/WebExtension MV3 + `.sql` schemas) that a `package.json`-only scan saw as `stack: ?`,
and adds a 20th extractor plus three provider-agnostic finding classes for licensing/entitlement and
client-trust flaws. 232 unit tests.

### Added
- **WebExtension extractor** (`extractors/webext.py`, the 20th) — flags a **client-side entitlement gate**
  (a paid tier/level read from `chrome.storage.local`/`localStorage` and used as the only enforcement),
  **over-broad `host_permissions`** (`<all_urls>` / `*://*/*`), `world:"MAIN"` content scripts, and
  `onMessageExternal` handlers with no sender validation.
- **License/entitlement verification-trust findings** (`integrations.py`) — `entitlement-revocation-bypass`
  (HIGH: grants on a truthy `success`/`valid` alone, never inspecting refund/chargeback/dispute/cancel/
  status) and `missing-usage-cap` (no per-license seat/device/activation cap or rate limit). License/
  subscription providers (Gumroad/Stripe/Paddle/Lemon Squeezy/Keygen/…) are detected by API host even
  when called via a raw `fetch` (no npm SDK). Detection is provider-agnostic — matched on generic
  refund/cancel/seat/device/quota concepts as code, not any one provider's field names.
- **`entitlement-abuse` probe** — a seat/device-cap replay + revocation-bypass draft (`templates/probes/`).
- New attack classes with CWE/OWASP citations + remediations: `entitlement-revocation-bypass`,
  `missing-usage-cap`, `client-side-entitlement`, `excessive-permissions`, `extension-message-trust`.

### Changed
- **Stack detection** (`stack.py`) — file-extension fallback (a `.ts`/`.js`/`.py` repo with no manifest
  now reports a language) + detects **Deno**, **Supabase edge functions**, **WebExtension**
  (`manifest_version`), and a `.sql` schema → `postgres`, so `stack`/`datastores` are no longer `?`.
- **Route discovery** (`routes.py`) — synthesizes `POST /functions/v1/<name>` routes from `Deno.serve`
  handlers (Noir/the regex frameworks don't parse Deno), and counts `Deno.serve` as a handler signal.
- **Schema extractor** (`schemas.py`) — parses `CREATE TABLE` from `.sql` files (entities + ownership
  fields like `license_hash`), which were previously never read (`.sql` isn't in `CODE_EXT`).
- **Tenant candidates** (`tenant.py`) — adds per-license/per-device ownership keys (`license_hash`,
  `licenseKey`, `visitorId`, …) as BOLA-isolation candidates.

## [0.8.1] — 2026-06-23

Correctness/robustness patch. Merges the PR #8 review (3 reproduced regex/logic bugs on the always-on
run path — Flask route-fallback drop/mislabel, password-policy `re.I` lowercase false-negative, GHA
detail double-`github.`), then clears that PR's deferred backlog. 203 unit tests; no behavior change
beyond fixing the bugs.

### Fixed
- **Checkov findings were 100% discarded** (`scanners.py`) — Checkov writes `results_json.json` (not
  the `<key>.json` the tool recorded), had no `_count_findings` branch, and no parser. Added
  `_norm_checkov` (handles the single-object and per-framework-list shapes; null severity → MEDIUM),
  registered it, fixed the output path, and added a count branch. Verified live: 3 findings now flow
  through where 0 did.
- **Secret de-dup could hide a second real secret** (`scanners.py`) — the secret fingerprint omitted
  the line, so two distinct secrets matched by the same rule in one file collapsed to one row. Added
  `StartLine` to the trivy + gitleaks secret fingerprints (the safe direction: never hide a distinct
  secret; accept rare cross-tool duplicates).
- **gitignored-secret downgrade was a silent no-op** (`scanners.py`) — `git check-ignore` wants
  repo-relative paths and echoes the exact input, but `trivy fs` emits absolute paths, so nothing
  matched. `_gitignored` now normalizes to repo-relative and maps results back to the original strings.
- **`websec dynamic` robustness** (`dynamic.py`) — `mint()` crashed (`5[0]` `TypeError`) on a singular
  scalar tenant field and produced a single-char tenant for a scalar string (`_first_tenant` coerces to
  a list); and the cross-tenant LEAK verdict string-matched a 3-element empty-body allowlist that
  misclassified common empty wrappers (`{"items":[]}`, whitespace, paginated) as leaks (`_no_records`
  now tests JSON emptiness structurally, conservatively — never masks a real leak).

### Changed
- Docs test count synced to **203** (TEST-SPEC service-to-test map, ENVIRONMENT, README).

## [0.8.0] — 2026-06-22

Coverage release closing the deferred backlog from the 0.7.0 dogfooding pass — three new
broken-access-control / transport classes plus a `authz_dataflow` extractor, each gated tightly to
hold the line on precision (no ledger blow-up on the validation target). 15 new unit tests (196 total).

### Added
- **CORS misconfiguration** (`transport_security`) — flags an `Access-Control-Allow-Origin` that
  reflects the request `Origin` (or `*`) **together with** `Allow-Credentials: true` (HIGH — any site
  reads authenticated responses, CWE-942); reflect-without-allowlist alone is MEDIUM.
- **Next.js security-header gap, monorepo-aware** (`transport_security`) — globs every
  `**/next.config.{js,mjs,ts}` (not just the repo root) and flags a config with no `headers()` security
  block (missing CSP / X-Frame-Options / HSTS / nosniff).
- **External script without Subresource-Integrity** (`transport_security`) — an external
  `<script src="https://…">` in server-emitted HTML with no `integrity=` hash / version pin (CWE-829
  supply-chain).
- **Host-header → redirect** (`surface`) — a redirect `Location`/origin built from the
  attacker-controllable `Host`/`X-Forwarded-Host` header with no host allow-list (CWE-601).
- **SSRF-hardening: follows redirects with no allow-list** (`surface`) — an outbound client that
  deliberately follows redirects (`follow_redirects=True` / `maxRedirects>0`) with no host allow-list /
  private-range deny, **incl. Python worker/job scripts** the route scan never reached (CWE-918).
- **NEW `authz_dataflow` extractor** — authorization *correctness*, not just presence: **unsigned-cookie
  authorization** (an access decision keyed on a client-settable cookie with no signature check —
  CWE-565/602), **claim-keyed authorization** (an authz check comparing a user-influenceable JWT body
  claim — CWE-639/807), and **transaction-local RLS context** (`set_config('app.*', …, true)` emitted
  outside a transaction, so the RLS principal resets before the query — CWE-1188).

### Changed
- `findings` ledger cites the new CWE/OWASP classes (cors-misconfig, subresource-integrity,
  open-redirect via host header, cookie-authz, claim-authz, rls-context) with remediations.

## [0.7.0] — 2026-06-22

Self-improvement release driven by dogfooding on a large real-world LLM-agent monorepo: a 15-agent
verification pass adversarially confirmed every finding, then the verdicts were encoded back as
extractor fixes + two new detector families. The dominant false-positive clusters are gone (HIGH
178 → 15 on the validation target) and the previously-uncovered AI-agent + crypto surfaces are now
detected. **Two new extractors** (`llm_security`, `crypto_usage`); 40 new stdlib unit tests (181 total).

### Added
- **NEW LLM / AI-agent security extractor** (`extractors/llm_security.py`) — the OWASP LLM Top 10
  surface that was entirely uncovered: indirect **prompt injection** (untrusted RAG/tool/web content
  into a prompt with no sanitizer/fence, esp. "render this URL verbatim"), **insecure output
  handling** (model text → `JSON.parse`/tool-call dispatch), **excessive agency** (a state-changing
  agent tool with no human gate), **unbounded generation** (no `maxTokens`/timeout → cost DoS), and
  **guardrail fail-open**. Server-side, test/script-excluded, gated on a real LLM call site for
  precision. Surfaced in the briefing + ledger with LLM01/02/06/10 + CWE citations.
- **docker-compose host-exposure detector** (`extractors/iac_ci.py`): flags `docker.sock` mounts,
  `pid: host` / host-root bind mounts, `privileged: true`, host networking / dangerous `cap_add`, and
  plaintext secret env when a `secrets:` block exists — a whole compose class that had no parser.
- **Secret-suppression audit** (`extractors/iac_ci.py`): flags `.gitleaksignore`/`.trivyignore`/
  `.semgrepignore` entries that SILENCE a leak in a real `.env`/secrets/key file (a true positive
  being hidden, not rotated/purged) — the committed-`.env.prod` CRITICAL class.
- **Reverse-proxy prefix-escape detector** (`extractors/surface.py`): flags a confined-deputy proxy
  that joins user-controlled catch-all path segments after a fixed prefix and forwards a server-minted
  token with no `..`/encoded-slash rejection (`/api/x/%2e%2e/admin` normalizes past the prefix → any
  upstream route with valid creds). CWE-441/CWE-22.
- **NEW crypto-usage extractor** (`extractors/crypto_usage.py`): weak password hashing (fast/unsalted
  SHA-256/MD5 instead of argon2/scrypt/bcrypt — CWE-916/759, HIGH), `jwtVerify` without an
  `algorithms` allowlist (CWE-347, latent alg-confusion), and predictable principals (a tenant/user
  id derived as a public hash of an identity field — CWE-330).
- **Shared file-class helpers** (`extractors/base.py`): `is_test_file` / `is_script_file` /
  `is_client_file`, so sink/exposure extractors stop scanning test fixtures, build/CLI scripts, and
  browser code as if they were deployed server handlers (the dominant cross-cutting FP driver).
- `client_exposure`: an `intended_public_analytics` bucket (PostHog/Usertour/Segment/… write-only
  ingest tokens) reported at **INFO**, separated from real browser-secret leaks.

### Changed
- **Router-mount auth modeling** (`extractors/authz.py`): recognize Express
  `app.use('/prefix', authMiddleware(...), createXRouter())` mount-level auth and propagate it to the
  mounted router's files via a local-import-graph BFS (TS `.js`→`.ts` ESM resolution, inner
  `router.use` inheritance, test-harness mounts ignored). Also recognize custom auth helpers
  (`getRequestSessionAuth`-style) and one-hop delegated guards in thin Next.js route handlers.
- `surface` SSRF: require a **request-derived** URL (not any template literal), gate to server-side
  files, and skip same-origin relative / hardcoded-host+token fetches.
- `client_exposure`: gate name-based `NEXT_PUBLIC_*`/`VITE_*` leaks to packages that actually have a
  frontend bundler; `PUBLIC_*` is SvelteKit-gated.
- `iac_ci` GHA script-injection: position-aware — only flag untrusted context inside a `run:` step
  body (not `if:`/`env:`/`with:`); SHA/ref-typed contexts drop to LOW.
- `transport_security`: recognize the cookie `Secure` flag set conditionally (`secure: isProduction()`).
- `upload_security`: credit `Content-Disposition: attachment`; tighten the file-serve sink (no bare
  `getObject` / metrics `res.set` FP); broaden the allow-list to `ACCEPTED_*`.
- `pii_exposure`: count same-file call sites (a masker wired in its own module is not "dead");
  exclude secret-maskers from the PII category; dead-control downgraded HIGH→LOW.
- `routes`: exclude `postman_collection.json` from app routes (it's an API spec, not a handler).

### Fixed
- The dominant false-positive clusters, validated end-to-end against a real production LLM-agent
  monorepo: the FP-removal alone took the ledger **403 → 72** and **HIGH 178 → 8** (missing-auth
  292→30, ssrf 41→0, pii 8→0) with **no loss of the genuine findings**. With the new LLM /
  docker-compose / secret-suppression / proxy-escape / crypto detectors then adding real,
  previously-invisible findings, the end state is **128 findings / 15 HIGH** (CRITICAL 1) — noise
  gone, true coverage up. 181 stdlib unit tests pass.

### Removed

## [0.6.3] — 2026-06-19

Framing-only release: lead every agent-facing surface with a defensive scope-and-authorization
statement so a careful coding agent stops flagging a plain "security-review my repo" as suspicious.
No behavior change.

### Added
- **METHODOLOGY: "Why your agent might pause — and how to phrase the request"** — explains the
  dual-use false-positive (a careful agent stalling on a plain "security-review my repo") and the
  three levers that fix it (how you ask · what the tool tells the agent · provenance).

### Changed
- **Authorization-envelope framing across the agent-facing surfaces** — the skill `description`, the
  top of `SKILL.md`, the `AGENT-BRIEFING.md` header (`briefing.py`), the plugin/marketplace/PyPI/CLI
  descriptions, and all 22 staged probe templates now lead with a defensive scope-and-authorization
  statement (defensive · your OWN code · read-only by default · prod/third-party out of scope · human
  approves each probe). Reduces dual-use false-positive pauses. The README hero line now leads with a
  defensive, ownership-asserting phrasing and the PyPI install. **No behavior change** — wording/order
  only; the live-fire confirmation checkpoint is intentionally preserved.

## [0.6.2] — 2026-06-12

### Added
- **Report-the-passes for cookies (P3)** — `transport_security` now reports a cookie-hardening PASS
  (`HttpOnly + Secure + SameSite` present → ✓, surfaced in the briefing's §3c "report-the-pass / gap"
  line) and flags the gap as a new `insecure-cookie` finding (CWE-1004/614) when a flag is missing.
  Saying "checked ✓" builds trust and turns the control into a regression assertion.

## [0.6.1] — 2026-06-12

Precision fixes found by re-running 0.6.0 on the same Cloudflare Worker.

### Fixed
- **Skip `.wrangler` / `.vercel` dev-build caches** — these hold BUNDLED output, so the new router-call
  heuristic was emitting phantom duplicate routes from them (a real run dropped 62 → 47, all real now).
- **Mass-assignment now catches the shorthand `{...record, tier}`** (a privileged field pulled from a
  same-named var — the actual tier-downgrade / role-escalation form), gated on a privileged-field list
  so `{...state, theme}` and a literal `{...record, role:'x'}` stay silent.

## [0.6.0] — 2026-06-12

Field-feedback release from a real run on a Cloudflare Worker (hand-rolled router + HMAC cookies).
Fixes the route-discovery blind spot that silently no-op'd the whole dynamic half, plus auth-scheme,
CSP, secret-triage, and config gaps.

### Added
- **Generic router-call route discovery (P1)** — a `<obj>.<verb>('/path')` / `.on('METHOD','/path')`
  heuristic that ALWAYS supplements Noir (which collapses hand-rolled / itty-router / Hono / Workers
  routers to ~1 endpoint), with a leading-`/` FP guard, plus a surface-coverage warning when
  handler-ish functions outnumber mapped routes (an empty §3 then reads as "couldn't map").
- **HMAC-signed-cookie auth detection (P2)** — `crypto.subtle.sign/verify` + cookie usage → scheme
  `hmac-signed-cookie` (was misread as `api-key`).
- **CSP baseline for server-rendered / template-literal HTML (P3)** — `transport_security` now fires
  on Workers / SSR apps that build HTML in code, not just frontend frameworks.
- **Mass-assignment via object spread (P3)** — `{...record, ...req.body}` / `Object.assign(record,
  req.body)` (the tier-downgrade / privilege-escalation class) as a 15th surface sink.
- **Provider-prefix secret triage (P4)** — name a secret by prefix (`whsec_`/`sk_live_`/`gho_`/`SG.`/…),
  HIGH for real secrets vs LOW for sandbox (`sk_test_`) / publishable (`pk_live_`), with the
  rotate-FIRST remediation order (gitignoring a committed key doesn't scrub pushed history).
- **Managed-platform config parsing (P5)** — `wrangler`/`vercel`/`netlify`/`serverless` → framework +
  datastore (KV / D1→sqlite / R2 / Durable Objects) + cron triggers.

### Changed
- **Auth probes gated by detected scheme (P2)** — `forged-token` stages for any token/cookie auth
  (forges into bearer OR the signed cookie); `jwt-attacks` / `hs256-brute-force` only when JWT is
  actually present. `ALWAYS` trimmed to `unauth-baseline` + `rate-limit-burst`.
- **Cloudflare KV family + redis added to the NoSQL set (P6)** so classic SQLi alerts auto-down-rank
  on a KV-only app.

(135 tests; 16 extractors; 15 surface sink classes.)

## [0.5.0] — 2026-06-12

### Added
- **Client-trust-boundary detection group** — generalized the man-in-the-browser / display-integrity
  class beyond wallets to ANY security-critical sink value (crypto/bank address, IBAN/routing, 2FA/TOTP
  seed, recovery/mnemonic phrase, API/license key, webhook URL), detected by **data-flow role** and
  classified by **blast radius** (money/credential → HIGH severity, config → MEDIUM); confidence stays
  LOW (architectural, "verify the compensating controls"). Adds a **grindable safety-code / fingerprint**
  check (`weak-fingerprint`, CWE-331) and an **over-claimed "tamper-proof" control-framing** check
  (`overclaimed-control`, CWE-693).
- **`transport_security` extractor** (16th) — framework-agnostic CSP + HSTS baseline audit: missing/weak
  CSP (`missing-csp`), inline event handlers that force `unsafe-inline`, and missing/partial HSTS scope
  (`incomplete-hsts`, the "set on /api but not the HTML document" gap).
- **Cross-cloud secret-shape detection** in `client_exposure` — Azure (storage `AccountKey=`, SAS,
  connection string) and GCP (service-account JSON, PEM private key) value-shapes alongside AWS, so the
  ships-to-browser scan is cloud-agnostic (AWS/Azure/GCP).
- **Follow-up client-trust-boundary classes** — `client-tamper-vector` (#2: a security-critical value fed
  by an interceptable client fetch instead of server-rendered), `abusable-action-endpoint` (#5: outbound
  email/SMS/push handlers with no auth-gate or only IP-only rate-limiting), and `redundant-secret-fetch`
  (#6: the same secret-manager key pulled more than once per path). All LOW/architectural ("verify"), in
  `integrations` + `client_integrity`.
- 23 regression tests (103 → 126) covering the new groups + the false-positive fixes below.

### Changed
- AppSync introspection remediation now explains that **fronting AppSync with API Gateway is not a
  security fix** — it can't enforce GraphQL semantics and doesn't cover the separate realtime WebSocket
  endpoint; steer to engine-level controls and treat any gateway/WAF as defense-in-depth only.
- `client_integrity` severity now tracks the sink's **irreversibility** (money/credential = HIGH) instead
  of a fixed MEDIUM.

### Fixed
- **False-positive tuning from dogfooding on 5 real repos (68 → 11 new-group findings; 0 confirmed FPs left):**
  - `abusable-action-endpoint` now requires a real comms send-CALL inside a request-handler / serverless
    function (not a mere SDK import) and skips test/type/config/script files — was firing on dozens of
    non-handler files in a real-world app (config, repositories, tests, load tests).
  - `client_integrity` sinks (and the `weak-fingerprint` check) are gated to genuine frontend files, so a
    backend service / SDK model that merely references an `account`/`recipient` field is no longer flagged
    as a browser display; a backend HMAC truncation is no longer a "grindable safety code."
  - `SKIP_DIRS` now excludes `.aws-sam`, `cdk.out`, `.sst`, `.amplify` — stops scanning vendored build
    dependencies (was flagging third-party SDK code under an AWS SAM build dir).
  - client_integrity findings now carry their own `file` (correct location in the ledger, not always
    `sensitive_display[0]`).

### Removed

## [0.4.2] — 2026-06-10

Documentation-only release (no source change).

### Added
- DocGuard (Canonical-Driven Development) doc set: `docs-canonical/` (ARCHITECTURE, SECURITY, TEST-SPEC,
  ENVIRONMENT), `AGENTS.md`, `CHANGELOG.md`, `DRIFT-LOG.md`; `.docguard.json` + `.docguardignore`. Repo
  now passes `docguard guard` (86/86, 96/100 A+).

### Fixed
- README: corrected a stale test count (23 → 103); added Usage + License sections.

## [0.4.1] — 2026-06-10

### Fixed
- **CRITICAL recon false-negative**: a repo living under a skip-named *ancestor* directory had every
  route and finding silently dropped (the tool reported a vulnerable app as clean). Skip-dir matching
  is now relative to the scan root.
- HTTP 500 is no longer escalated to missing-auth (nor recorded as a confirmed oracle sample).
- Sink classes now cite their specific CWE (sqli / nosql / redos / eval) instead of a generic SAST label.

### Changed
- The full ranked static finding set flows into the ledger; walk-truncation is disclosed; webhook-forgery
  routed to the ledger. (+8 regression tests.)
- `.websec-ignore` skips the maintainer's gitignored `base-research/` on self-scan.

> 0.4.0 was tagged from a stale local `main` and shipped to PyPI without the `#1`/`#2` fixes already on
> `origin/main`; 0.4.1 rebases the retest work onto them and ships the complete set.

## [0.4.0] — 2026-06-10

### Added
- REF-PENTEST retest: four new detection classes and 15 extractor refinements.

### Fixed
- Two false positives the retest disproved: AppSync introspection **is** disablable engine-level, and
  AppSync `API_KEY`-default is anonymous-auth, **not** CSWSH.

## [0.3.0] — 2026-06-07

### Added
- Closed REF-PENTEST detection gaps; added the **man-in-the-browser / tamperable-display** class
  (`client_integrity`).
- AWS-CDK / managed-AppSync / VTL boundary parsing (`.graphql` / `.gql` / `.vtl`).

## [0.2.x] — 2026-05-30 → 2026-06-01

The initial public line. Highlights across 0.2.1–0.2.9:

### Added
- FACTS-driven probe bodies; auth-bypass probe; forged-token engine extended to cookie-only auth.
- PyPI publishing via Trusted Publishing (OIDC, tag-triggered semver releases).
- Static at-risk routes; non-web-app false-positive flagging.

### Changed
- `__version__` derived from package metadata (single source of truth: `pyproject.toml`).
- Secret-finding precision: generic/entropy rules tiered to MEDIUM; secrets in docs/example files tiered to LOW.

### Fixed
- Scanner-contamination and rate-limit fixes (agent-wallet dogfood).

[Unreleased]: https://github.com/raccioly/websec-validator/compare/v0.4.2...HEAD
[0.4.2]: https://github.com/raccioly/websec-validator/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/raccioly/websec-validator/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/raccioly/websec-validator/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/raccioly/websec-validator/compare/v0.2.9...v0.3.0
[0.2.x]: https://github.com/raccioly/websec-validator/releases

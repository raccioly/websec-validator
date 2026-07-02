# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

### Changed

### Fixed

### Removed

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

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

### Changed

### Fixed

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

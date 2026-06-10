# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

### Changed

### Fixed

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
- PTREQ0013000 retest: four new detection classes and 15 extractor refinements.

### Fixed
- Two false positives the retest disproved: AppSync introspection **is** disablable engine-level, and
  AppSync `API_KEY`-default is anonymous-auth, **not** CSWSH.

## [0.3.0] — 2026-06-07

### Added
- Closed PTREQ0013000 detection gaps; added the **man-in-the-browser / tamperable-display** class
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

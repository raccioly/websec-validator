# Test Specification

<!-- docguard:version 0.9.0 -->
<!-- docguard:status approved -->
<!-- docguard:last-reviewed 2026-07-02 -->
<!-- docguard:owner @raccioly -->
<!-- docguard:quality negation-load off — the suite deliberately uses no third-party runner, no network, and no running app; the negations describe real, intentional test constraints. -->

> **Canonical document** — Design intent. This file declares what tests MUST exist.  
> Last updated: 2026-06-22

The suite is **stdlib `unittest` only** — no third-party test runner, no network, no Noir, no running
app. **232 tests** across four files run in ~1s and gate every release (the `publish.yml` workflow
also installs the built wheel and smoke-runs `websec run`).

```bash
python3 -m unittest discover -s tests    # 232 tests, stdlib only
```

---

## Test Categories

| Category | Required | Applies To | Tool |
|----------|----------|-----------|------|
| Unit | ✅ Yes | extractors, findings ledger, calibration, scanners, probes | `unittest` |
| Regression | ✅ Yes | pen-test findings (REF-PENTEST) + every fixed bug — pinned so they can't silently come back | `unittest` |
| Hardening | ✅ Yes | CLI surface, dynamic-phase safety gates, partial-scan guard, edge/error paths | `unittest` |
| Coverage proxy | ✅ Yes | recon coverage vs the labeled vuln-app corpus (`websec proof`) | `proof.py` (network on first clone) |
| E2E / Canary / Load / Contract | ➖ N/A | no server, no HTTP API, no deployment target | — |

## Coverage Rules

| Source Pattern | Required Test Pattern | Category |
|----------------|----------------------|----------|
| `src/websec_validator/extractors/*.py` | a recon/extractor assertion in `tests/test_recon.py` | Unit |
| `src/websec_validator/{findings,calibration,scanners,probes}.py` | exercised in `tests/test_recon.py` | Unit |
| a fixed bug / disproven pen-test finding | a dedicated case in `tests/test_pentest_regressions.py` | Regression |
| entitlement / licensing + WebExtension client-trust classes (`integrations`, `webext`) | a case in `tests/test_entitlement_webext.py` (incl. cross-provider genericity) | Unit / Regression |
| `src/websec_validator/{cli,dynamic}.py` + safety invariants | a case in `tests/test_hardening.py` | Hardening |

## Service-to-Test Map

| Source area | Test File | Tests | Status |
|-------------|-----------|-------|--------|
| Recon extractors, ledger, calibration, scanners, probes, briefing (incl. the FP-killer + 0.7.0/0.8.0 detector tests: LLM-security, crypto-usage, authz-dataflow, CORS/SRI/header-gap, mount-auth) | `tests/test_recon.py` | 103 | ✅ |
| Pen-test + bug-fix regressions (detection precision, false-positive/negative guards) | `tests/test_pentest_regressions.py` | 66 | ✅ |
| CLI / dynamic-phase hardening + safety gates + edge cases (incl. the 0.8.1 scanner/dynamic deferred fixes) | `tests/test_hardening.py` | 34 | ✅ |
| **Total** | | **203** | ✅ |

## Test Fixtures

| Fixture | What it is | Used by |
|---------|-----------|---------|
| `tests/fixtures/node_app/` | a deliberately-vulnerable Express sample app | extractor + regression assertions |
| `tests/fixtures/py_app/` | a deliberately-vulnerable Flask sample app | extractor + regression assertions |

These are **test data the tool scans**, not part of the shipped package, and are excluded from doc
validation via `.docguardignore`.

## Coverage Proxy — the Proof Harness

`websec proof` clones the vuln-app corpus (VAmPI, NodeGoat, DVGA) and scores whether recon surfaces
each app's documented attack surface — a deterministic, CI-trackable proxy. The corpus contributes
coverage checks across three apps — VAmPI (4), NodeGoat (4), DVGA (2), **10 in total** — which the
engine currently passes **10/10**. The true
kill-criterion — does the briefing lift an agent's bug-finding vs a generic prompt? — is the manual
A/B in [`corpus/PROOF-PROTOCOL.md`](../corpus/PROOF-PROTOCOL.md).

## Recommended Test Patterns

| Pattern | Description | Priority |
|---------|-------------|----------|
| Regression guards | Pin every fixed bug / disproven finding with a dedicated case (the bulk of `test_pentest_regressions.py`) | ⚠️ High |
| Individual extractors | Test each extractor directly against a fixture, not only end-to-end | ⚠️ High |
| Safety-gate assertions | Prove dynamic write probes refuse non-localhost; prove the core pass stays offline | ⚠️ High |
| Edge cases | Empty repo, missing files, partial-scan (file-cap) truncation, absent scanners | ✅ Medium |
| Error paths | One failing extractor must never sink the whole run | ✅ Medium |

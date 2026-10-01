# Scoped dependency-alert review — 2026-10-01

Repository: `raccioly/websec-validator`. Reviewed source:
`eaac95e3f0f383d96d89a5b0ca96ba3a90d1c54b`; released engine: `v0.21.0`.

## Scope and disposition

This is a read-only classification of the four open GitHub Dependabot alerts reported during
the maintenance push. It is not a full dependency/IOC/install-directory/workstation audit; the
remaining supply-chain-audit phases were not run. No installation, upgrade, alert dismissal,
token rotation or global environment change was performed. Overall compromise posture is **not
assessed**. No zero-malware or clean-environment conclusion follows from this review.

All four alerts name `src/websec_validator/templates/demo/requirements.txt.txt`. That file pins
Flask 3.0.0 and Requests 2.31.0 as deliberately vulnerable **scan data**, shipped under `.txt` names.
`demo.materialize` copies them into an owned temporary directory; `demo.run` runs source recon,
never a package installer or target app. The source explicitly marks the sample deliberately
vulnerable; `tests/test_demo.py` verifies inert `.txt` packaging, planted finding classes and cleanup.
The package declares `dependencies = []`; the separately downloaded published 0.21.0 wheel has
zero `Requires-Dist`. GitHub's inferred runtime scope for a template is not installed-engine evidence.

| Alert | Package | Advisory | Classification |
|---|---|---|---|
| [1](https://github.com/raccioly/websec-validator/security/dependabot/1) | Requests 2.31.0 | [GHSA-9wx4-h78v-vm56](https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56) | Inert vulnerable demo manifest |
| [2](https://github.com/raccioly/websec-validator/security/dependabot/2) | Requests 2.31.0 | [GHSA-9hjg-9r4m-mvj7](https://github.com/psf/requests/security/advisories/GHSA-9hjg-9r4m-mvj7) | Inert vulnerable demo manifest |
| [3](https://github.com/raccioly/websec-validator/security/dependabot/3) | Flask 3.0.0 | [GHSA-68rp-wp8r-4726](https://github.com/pallets/flask/security/advisories/GHSA-68rp-wp8r-4726) | Inert vulnerable demo manifest |
| [4](https://github.com/raccioly/websec-validator/security/dependabot/4) | Requests 2.31.0 | [GHSA-gc5v-m9x4-r6x2](https://github.com/psf/requests/security/advisories/GHSA-gc5v-m9x4-r6x2) | Inert vulnerable demo manifest |

## Boundary and follow-up

Keep these alerts visible with their classification. Do not upgrade this intentionally vulnerable
sample merely to clear a dashboard, or present the sample as safe application code. If any future
workflow installs/runs it or adds either library to engine dependencies, this classification is
invalid and the actual advisory/version/runtime path must be reassessed. An operator manually
installing its requirements would install vulnerable versions; WebSec does not authorize that.

The full local application suite at this source passes 1,855 tests (one optional lifecycle skipped),
including demo regressions. That is behavioral regression evidence, not a vulnerability exploit
test or a complete supply-chain security assessment.

# Security Policy

`websec-validator` is itself a security tool, so we hold it to the standard it enforces.
The full security model — trust boundaries, the dynamic-phase safety guarantees, secrets
handling, and supply-chain posture — is documented in
[`docs-canonical/SECURITY.md`](docs-canonical/SECURITY.md).

## Supported versions

Only the latest release on [PyPI](https://pypi.org/project/websec-validator/) receives
security fixes. There is no LTS branch — upgrades are cheap (zero runtime dependencies,
no schema migrations on the user side).

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Use GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/raccioly/websec-validator/security/advisories/new)**
(Security tab → *Report a vulnerability*). You'll get an acknowledgement within **72 hours**
and a fix or a documented mitigation target of **30 days** for anything that breaks the
guarantees below.

For non-sensitive hardening suggestions, a regular issue is fine.

## What counts as a vulnerability here

The tool's core guarantees are:

- The core pass (`websec run` / `recon`) is **offline and read-only** on the target repo —
  no network, no writes into the target, no execution of target code.
- Live probing (`websec dynamic`) is **opt-in, read-only by default**, and write probes are
  **refused unless the target is localhost**.
- Secrets (dynamic-phase credentials, the local calibration overlay) **never enter shipped
  artifacts** and never leave the machine.
- **Zero runtime dependencies** — external scanners are shelled out to, never imported.

Anything that lets a scanned repository break out of those guarantees — e.g. a malicious
target repo achieving code execution in the tool, path traversal writing outside the output
directory, probe templates exfiltrating data, or secrets leaking into `websec-out/`
artifacts — is in scope and treated as high severity.

## What's out of scope

- Vulnerabilities in the third-party scanners the tool shells out to (Trivy, Gitleaks,
  Semgrep, Checkov, Noir) — report those upstream.
- Findings the tool produces about *your* application — that's the product working, not a
  vulnerability in the tool.
- Running the dynamic phase against systems you don't own or lack authorization to test —
  explicitly forbidden by the tool's safety model.

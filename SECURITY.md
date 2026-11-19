# Security Policy

`websec-validator` is itself a security tool, so we hold it to the standard it enforces.
The full security model covers trust boundaries, the dynamic-phase safety guarantees, secrets
handling, and supply-chain posture. It is documented in
[`docs-canonical/SECURITY.md`](docs-canonical/SECURITY.md).

## Supported versions

Only the latest release on [PyPI](https://pypi.org/project/websec-validator/) receives
security fixes. There is no LTS branch. Upgrades are cheap: zero runtime dependencies,
and no schema migrations on the user side.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Use GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/raccioly/websec-validator/security/advisories/new)**
(Security tab → *Report a vulnerability*). You get an acknowledgement within **72 hours**.
For anything that breaks the guarantees below, the target is a fix or a documented mitigation
within **30 days**.

For hardening suggestions that are not sensitive, a regular issue is fine.

## What counts as a vulnerability here

The tool gives these core guarantees:

- The core pass (`websec run` / `recon`) is **offline and read-only** on the target repo.
  It uses no network, writes nothing into the target, and executes no target code.
- Live probing (`websec dynamic`) is **opt-in, read-only by default**, and write probes are
  **refused unless the target is localhost**.
- Secrets (dynamic-phase credentials, the local calibration overlay) **never enter shipped
  artifacts** and never leave the machine.
- **Zero runtime dependencies.** The tool shells out to external scanners and never imports them.

Anything that lets a scanned repository break out of those guarantees is in scope and is
treated as high severity. Examples: a malicious target repo that achieves code execution in the
tool, path traversal that writes outside the output directory, probe templates that exfiltrate
data, or secrets that leak into `websec-out/` artifacts.

## What's out of scope

- Vulnerabilities in the third-party scanners the tool shells out to (Trivy, Gitleaks,
  Semgrep, Checkov, Noir). Report those upstream.
- Findings the tool produces about *your* application. That is the product working, not a
  vulnerability in the tool.
- Running the dynamic phase against systems you don't own or lack authorization to test.
  The tool's safety model explicitly forbids this.

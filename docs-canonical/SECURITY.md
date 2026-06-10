# Security

<!-- docguard:version 0.4.1 -->
<!-- docguard:status approved -->
<!-- docguard:last-reviewed 2026-06-10 -->
<!-- docguard:owner @raccioly -->
<!-- docguard:quality negation-load off — a security model is correctly stated as invariants (MUST NOT, never, read-only, out-of-scope); negation is the right register for safety guarantees. -->

> **Canonical document** — Design intent. This file defines the security model.  
> Last updated: 2026-06-10

`websec-validator` is itself a security tool, so its security model is about **the safety of running
the tool**, not about authenticating end users (it has none). The governing principle: the core pass
is **code-in, artifacts-out** — it reads the target repo, runs read-only subprocesses, and writes files
locally. It contains no LLM, runs no server, and never touches a running application unless you
explicitly invoke the gated dynamic phase against a TEST target you control.

---

## Trust Boundaries

| Boundary | What crosses it | Safety property |
|----------|-----------------|-----------------|
| Target repo → tool | source files (read-only) | The tool never writes into or executes the target's code. |
| Tool → scanner subprocesses | the target path | Scanners are detected and only **executed with `--scan`**; they are read-only and shelled out, never imported. |
| Tool → network | nothing, in the core pass | Recon + briefing are fully offline. The only outbound traffic is (a) optional scanner/Noir subprocesses and (b) the **explicit TEST URL** you pass to the dynamic phase. |
| Tool → disk | artifacts under `websec-out/` + a gitignored calibration overlay | Output is immutable per run; nothing in the repo is mutated. |

## Authentication & Authorization

Not applicable to the tool itself — there are no accounts, sessions, roles, or server. (The tool
*analyzes* the authentication and authorization of the **target** apps it scans; see
[`docs/METHODOLOGY.md`](../docs/METHODOLOGY.md) for the auth/authz/tenant extractors and the BOLA model.)

## The Dynamic-Phase Safety Model (explicit and non-negotiable)

The optional `websec dynamic` phase is the only part of the tool that contacts a live system. Its
guarantees are enforced in code (`dynamic.py`, `cli.py`):

- **Read-only by default.** `--config` (authenticated cross-tenant BOLA) and `--unauth` (reachability)
  issue **GET-only** requests.
- **Write probes are localhost-only.** `--probe-writes` is refused unless `--target` is localhost; it
  sends non-destructive write verbs (empty bodies / dummy ids), never destructive payloads.
- **Production is out of scope without written authorization.** The human owns every credential and
  authorizes every live run. Never point it at production.
- **Trigger-style paths are excluded** from unauth GET probing because a GET can still be side-effecting
  (cron / scrape / generate …).

## Secrets Management

| Secret | Storage | Access pattern |
|--------|---------|----------------|
| Dynamic-phase TEST credentials | `dynamic-config.json` (gitignored; copied from `dynamic-config.example.json`) | Read at runtime for `websec dynamic --config`; never written to artifacts. |
| PyPI publish | GitHub OIDC **Trusted Publishing** — no API token stored in the repo | Used only by `publish.yml` on a version tag. |
| Calibration overlay | `~/.cache/websec-validator/` (or `$WEBSEC_CALIBRATION_HOME`), gitignored | Local-only personalization; **never shipped**, never leaves the machine. |

The tool reads **one** optional environment variable — `WEBSEC_CALIBRATION_HOME` — to relocate the
calibration overlay. It requires no secrets to run its core pass.

## Supply Chain

- **Zero runtime dependencies** (stdlib only) — the smallest possible dependency-confusion / malicious-
  package surface. External scanners are invoked as subprocesses, not imported.
- Published to PyPI via **Trusted Publishing (OIDC)**; the release workflow builds, installs, and
  smoke-tests the wheel before it can reach PyPI, so a bad build fails CI instead of shipping.

## Security Rules

- The core pass (`recon` / `run`) MUST remain offline and read-only on the target.
- The tool MUST NOT execute or modify the target repository's code.
- Live probing MUST be opt-in, default read-only, and localhost-only for any write verb.
- Secrets (dynamic creds, calibration overlay) MUST stay gitignored and out of shipped artifacts.
- Runtime dependencies MUST stay at zero; new third-party tools are integrated by shelling out, not importing.

## Reporting a Vulnerability

Open a security advisory or issue at <https://github.com/raccioly/websec-validator>. Because the tool
runs locally with no server and no telemetry, the realistic risk surface is the dynamic phase and the
scanner subprocesses — report anything that breaks the read-only / localhost-only guarantees above.

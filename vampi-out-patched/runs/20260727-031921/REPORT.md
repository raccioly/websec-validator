# websec-validator report — /home/jules/.cache/websec-corpus/VAmPI

> Generated 20260727-031921 · websec-validator v0.11.0 · **immutable run record** (never overwritten).
> Deterministic recon — no LLM. Hand `AGENT-BRIEFING.md` (same dir) to your coding agent to act on this.

## Executive summary

| | |
|---|---|
| Stack | python · flask · sql-orm |
| Endpoints | **14** app routes (via noir) |
| Auth | jwt (bearer) · roles: none |
| Access control | 0 guarded · **14 no visible guard** · global-middleware: False |
| Static scanner (raw, pre-triage) | _run with --scan for static findings_ |
| **Findings ledger** (triaged + calibrated) | **16 findings** · {'HIGH': 4, 'MEDIUM': 10, 'LOW': 2} · confidence {'MEDIUM': 15, 'LOW': 1} |
| Attack surface | IDOR: 5 · SSRF: 0 · upload: 0 · writes: 6 |

## 1. Findings ledger (ranked · evidence chain · standards · confidence)

- **[HIGH/MEDIUM]** Missing authorization: POST /books/v1
  `/books/v1` · evidence: recon · CWE-862 Missing Authorization · API1:2023 BOLA, API5:2023 BFLA · P(real)≈**0.659** CI [0.505, 0.784] (n=41, class+label)
  _fix:_ Add an auth guard to the handler (e.g. requireAuth()/getServerSession()), or a middleware matcher over /api/(.*) with an explicit public allowlist so it can't be forgotten.
- **[HIGH/MEDIUM]** Missing authorization: DELETE /users/v1/{username}
  `/users/v1/{username}` · evidence: recon · CWE-862 Missing Authorization · API1:2023 BOLA, API5:2023 BFLA · P(real)≈**0.659** CI [0.505, 0.784] (n=41, class+label)
  _fix:_ Add an auth guard to the handler (e.g. requireAuth()/getServerSession()), or a middleware matcher over /api/(.*) with an explicit public allowlist so it can't be forgotten.
- **[HIGH/MEDIUM]** Missing authorization: PUT /users/v1/{username}/email
  `/users/v1/{username}/email` · evidence: recon · CWE-862 Missing Authorization · API1:2023 BOLA, API5:2023 BFLA · P(real)≈**0.659** CI [0.505, 0.784] (n=41, class+label)
  _fix:_ Add an auth guard to the handler (e.g. requireAuth()/getServerSession()), or a middleware matcher over /api/(.*) with an explicit public allowlist so it can't be forgotten.
- **[HIGH/MEDIUM]** Missing authorization: PUT /users/v1/{username}/password
  `/users/v1/{username}/password` · evidence: recon · CWE-862 Missing Authorization · API1:2023 BOLA, API5:2023 BFLA · P(real)≈**0.659** CI [0.505, 0.784] (n=41, class+label)
  _fix:_ Add an auth guard to the handler (e.g. requireAuth()/getServerSession()), or a middleware matcher over /api/(.*) with an explicit public allowlist so it can't be forgotten.
- **[MEDIUM/MEDIUM]** Missing authorization: GET /
  `/` · evidence: recon · CWE-862 Missing Authorization · API1:2023 BOLA, API5:2023 BFLA · P(real)≈**0.659** CI [0.505, 0.784] (n=41, class+label)
  _fix:_ Add an auth guard to the handler (e.g. requireAuth()/getServerSession()), or a middleware matcher over /api/(.*) with an explicit public allowlist so it can't be forgotten.
- **[MEDIUM/MEDIUM]** Missing authorization: GET /books/v1
  `/books/v1` · evidence: recon · CWE-862 Missing Authorization · API1:2023 BOLA, API5:2023 BFLA · P(real)≈**0.659** CI [0.505, 0.784] (n=41, class+label)
  _fix:_ Add an auth guard to the handler (e.g. requireAuth()/getServerSession()), or a middleware matcher over /api/(.*) with an explicit public allowlist so it can't be forgotten.
- **[MEDIUM/MEDIUM]** Missing authorization: GET /books/v1/{book_title}
  `/books/v1/{book_title}` · evidence: recon · CWE-862 Missing Authorization · API1:2023 BOLA, API5:2023 BFLA · P(real)≈**0.659** CI [0.505, 0.784] (n=41, class+label)
  _fix:_ Add an auth guard to the handler (e.g. requireAuth()/getServerSession()), or a middleware matcher over /api/(.*) with an explicit public allowlist so it can't be forgotten.
- **[MEDIUM/MEDIUM]** Missing authorization: GET /createdb
  `/createdb` · evidence: recon · CWE-862 Missing Authorization · API1:2023 BOLA, API5:2023 BFLA · P(real)≈**0.659** CI [0.505, 0.784] (n=41, class+label)
  _fix:_ Add an auth guard to the handler (e.g. requireAuth()/getServerSession()), or a middleware matcher over /api/(.*) with an explicit public allowlist so it can't be forgotten.
- **[MEDIUM/MEDIUM]** Missing authorization: GET /me
  `/me` · evidence: recon · CWE-862 Missing Authorization · API1:2023 BOLA, API5:2023 BFLA · P(real)≈**0.659** CI [0.505, 0.784] (n=41, class+label)
  _fix:_ Add an auth guard to the handler (e.g. requireAuth()/getServerSession()), or a middleware matcher over /api/(.*) with an explicit public allowlist so it can't be forgotten.
- **[MEDIUM/MEDIUM]** Missing authorization: GET /users/v1
  `/users/v1` · evidence: recon · CWE-862 Missing Authorization · API1:2023 BOLA, API5:2023 BFLA · P(real)≈**0.659** CI [0.505, 0.784] (n=41, class+label)
  _fix:_ Add an auth guard to the handler (e.g. requireAuth()/getServerSession()), or a middleware matcher over /api/(.*) with an explicit public allowlist so it can't be forgotten.
- **[MEDIUM/MEDIUM]** Missing authorization: GET /users/v1/{username}
  `/users/v1/{username}` · evidence: recon · CWE-862 Missing Authorization · API1:2023 BOLA, API5:2023 BFLA · P(real)≈**0.659** CI [0.505, 0.784] (n=41, class+label)
  _fix:_ Add an auth guard to the handler (e.g. requireAuth()/getServerSession()), or a middleware matcher over /api/(.*) with an explicit public allowlist so it can't be forgotten.
- **[MEDIUM/MEDIUM]** Missing authorization: GET /users/v1/_debug
  `/users/v1/_debug` · evidence: recon · CWE-862 Missing Authorization · API1:2023 BOLA, API5:2023 BFLA · P(real)≈**0.659** CI [0.505, 0.784] (n=41, class+label)
  _fix:_ Add an auth guard to the handler (e.g. requireAuth()/getServerSession()), or a middleware matcher over /api/(.*) with an explicit public allowlist so it can't be forgotten.
- **[MEDIUM/MEDIUM]** gha-unpinned-action: actions pinned to a mutable tag (pin to a commit SHA): docker/build-push-action@
  `.github/workflows/docker-image.yml` · evidence: recon · CWE-1188 Insecure Default · P(real)≈**0.569** CI [0.433, 0.695] (n=51, label)
  _fix:_ Apply the hardening (non-root user, pin actions to a SHA, enforce TLS, etc.).
- **[MEDIUM/MEDIUM]** docker-root: container runs as root (add a non-root USER)
  `Dockerfile` · evidence: recon · CWE-1188 Insecure Default · P(real)≈**0.569** CI [0.433, 0.695] (n=51, label)
  _fix:_ Apply the hardening (non-root user, pin actions to a SHA, enforce TLS, etc.).
- **[LOW/MEDIUM]** docker-no-healthcheck: no HEALTHCHECK defined
  `Dockerfile` · evidence: recon · CWE-1188 Insecure Default · P(real)≈**0.569** CI [0.433, 0.695] (n=51, label)
  _fix:_ Apply the hardening (non-root user, pin actions to a SHA, enforce TLS, etc.).
- **[LOW/LOW]** no-hsts: browser/transport hardening header
  `(response headers)` · evidence: recon · CWE-523 Unprotected Transport of Credentials · API8:2023 Misconfiguration · P(real)≈**0.125** CI [0.022, 0.471] (n=8, label)
  _fix:_ Apply HSTS uniformly at the EDGE to ALL responses (not just /api): `max-age>=31536000; includeSubDomains; preload` where the domain model allows.

_Full ledger with complete evidence chains + remediation in `findings-ledger.json`. Confidence: HIGH = dynamically confirmed or verified; MEDIUM = concrete static evidence; LOW = single-source hypothesis to verify._


_**P(real)** = measured real-vuln rate for that attack-class/confidence bucket, with a 95% confidence interval and sample size `n` (indicative — calibrated on a deliberately-vulnerable app corpus; skews optimistic on clean production code). A wide CI or `basis: prior (uncalibrated)` means thin data — lean on the verification debate, not the number; to be conservative, threshold on the CI lower bound._

## 2. Access control

**⚠ Write endpoints with no visible guard (verify — top missing-authz leads)** (4):
- DELETE /users/v1/{username}  (openapi_specs/openapi3.yml)
- POST /books/v1  (openapi_specs/openapi3.yml)
- PUT /users/v1/{username}/email  (openapi_specs/openapi3.yml)
- PUT /users/v1/{username}/password  (openapi_specs/openapi3.yml)

No global/mount auth middleware detected. Write endpoints with no visible guard are high-signal missing-authz leads — verify each.

## 3. Attack surface & targeting

**IDOR / BOLA candidates** (5):
- DELETE /users/v1/{username}
- GET /books/v1/{book_title}
- GET /users/v1/{username}
- PUT /users/v1/{username}/email
- PUT /users/v1/{username}/password

**SSRF candidates** (0):
_(none)_

**File-upload candidates** (0):
_(none)_

**Code-level sinks (user-input-gated):** none

**Mass-assignment targets (privileged model fields):** none detected  ·  ORMs: ?

## 4. Config / CI-CD / client-side

**IaC/CI:** 3 finding(s) · **GraphQL:** False · **client-side secret exposure:** 0

## 5. Staged probes

- `unauth-baseline` — Missing authentication (no-creds baseline)
- `rate-limit-burst` — Rate-limit + X-Forwarded-For bypass
- `forged-token` — Forged/unsigned-JWT acceptance (CWE-347 broken auth)
- `jwt-attacks` — JWT: alg:none, tamper, expiry, replay
- `hs256-brute-force` — Offline HS256 weak-secret brute
- `mass-assignment` — BOPLA / mass assignment (OWASP API #3)
- `webhook-forgery` — Inbound webhook signature/replay
- `race-conditions` — Race / claim-collision invariants
- `client-integrity-checklist` — Man-in-the-browser / tamperable-display posture

## Appendix — endpoint inventory

- `GET   ` /
- `GET   ` /books/v1
- `POST  ` /books/v1
- `GET   ` /books/v1/{book_title}
- `GET   ` /createdb
- `GET   ` /me
- `GET   ` /users/v1
- `DELETE` /users/v1/{username}
- `GET   ` /users/v1/{username}
- `PUT   ` /users/v1/{username}/email
- `PUT   ` /users/v1/{username}/password
- `GET   ` /users/v1/_debug
- `POST  ` /users/v1/login
- `POST  ` /users/v1/register

---
_Roadmap: this report grows into a traceable findings ledger — each finding gaining an evidence
chain (recon → static → dynamic), an OWASP/CWE citation, and a calibrated H/M/L confidence._

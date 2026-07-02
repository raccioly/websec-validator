"""Traceable findings ledger — correlate recon + static scanners + dynamic into ONE
ranked, standards-cited, confidence-scored record set.

Each finding carries an **evidence chain** across layers (recon → static → dynamic),
an **OWASP/CWE/ASVS citation**, a **rule-based confidence** (HIGH/MEDIUM/LOW — no ML;
dynamic-confirmed beats static hypothesis), and a **remediation**. This is the
deterministic half of the AITPG/TRACE design — the consuming agent then runs the
adversarial debate (Advocate→Challenger→Mediator→Explainer) to verify, per the briefing.

Confidence rule (deterministic):
  HIGH    — dynamically confirmed (executed unauth / cross-tenant leak), OR a verified
            secret, OR a fixed-version CVE at HIGH/CRITICAL.
  MEDIUM  — static evidence with a concrete pattern (recon no-guard write, SAST hit,
            user-input-gated sink, real-but-lower CVE).
  LOW     — single-source hypothesis with no corroboration (recon-only signal).
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

from . import calibration

# attack class → authoritative citations + a remediation pattern
STANDARDS = {
    "missing-auth": (["CWE-862 Missing Authorization", "CWE-306 Missing Authentication"],
                     "ASVS V4.1.1", ["API1:2023 BOLA", "API5:2023 BFLA"]),
    "unsafe-auth-decoder": (["CWE-347 Improper Verification of Cryptographic Signature",
                             "CWE-345 Insufficient Verification of Data Authenticity"],
                            "ASVS V3.5.2", ["API2:2023 Broken Authentication"]),
    "bola": (["CWE-639 Authorization Bypass (IDOR)"], "ASVS V4.2.1", ["API1:2023 BOLA"]),
    "ssrf": (["CWE-918 SSRF"], "ASVS V12.6", ["API7:2023 SSRF"]),
    "secret": (["CWE-798 Hard-coded Credentials"], "ASVS V2.10", ["API8:2023 Misconfiguration"]),
    "sqli": (["CWE-89 SQL Injection"], "ASVS V5.3.4", ["API8:2023"]),
    "nosql-injection": (["CWE-943 Improper Neutralization of Data within a Query"], "ASVS V5.3.4", ["API8:2023"]),
    "redos": (["CWE-1333 Inefficient Regular Expression Complexity (ReDoS)"], "ASVS V5.2.4", []),
    "eval-injection": (["CWE-95 Eval Injection", "CWE-94 Code Injection"], "ASVS V5.2.4", []),
    "command-injection": (["CWE-78 OS Command Injection"], "ASVS V5.3.8", []),
    "path-traversal": (["CWE-22 Path Traversal"], "ASVS V12.3", []),
    "proxy-escape": (["CWE-441 Unintended Proxy (Confused Deputy)", "CWE-22 Path Traversal"],
                     "ASVS V12.3", ["API7:2023 SSRF", "API8:2023 Misconfiguration"]),
    "ssti": (["CWE-1336 SSTI"], "ASVS V5.2.5", []),
    "open-redirect": (["CWE-601 Open Redirect"], "ASVS V5.1.5", []),
    "insecure-deserialization": (["CWE-502 Deserialization"], "ASVS V5.5", []),
    "xxe": (["CWE-611 XXE"], "ASVS V5.5.2", []),
    "prototype-pollution": (["CWE-1321 Prototype Pollution"], "ASVS V5.1", []),
    "mass-assignment": (["CWE-915 Mass Assignment"], "ASVS V5.1.2", ["API3:2023 BOPLA"]),
    "webhook-forgery": (["CWE-345 Insufficient Verification of Data Authenticity",
                         "CWE-347 Improper Verification of Cryptographic Signature"],
                        "ASVS V13.4", ["API8:2023 Misconfiguration"]),
    "cve": (["CWE-1395 Vulnerable Dependency"], "ASVS V14.2.1", ["API8:2023"]),
    "iac": (["CWE-1188 Insecure Default"], "ASVS V14.1", []),
    "client-exposure": (["CWE-200 Information Exposure"], "ASVS V14.3", []),
    "graphql": (["CWE-200 Information Exposure"], "ASVS V13.1", ["API8:2023"]),
    "sast": (["CWE-710 Coding Standards"], "ASVS V1.1", []),
    # --- REF-PENTEST classes ---
    "insecure-secret-default": (["CWE-798 Hard-coded Credentials", "CWE-1188 Insecure Default Initialization"],
                                "ASVS V2.10", ["API2:2023 Broken Authentication"]),
    "cswsh": (["CWE-1385 Missing Origin Validation in WebSockets", "CWE-346 Origin Validation Error"],
              "ASVS V13.2", ["API2:2023 Broken Authentication"]),
    "error-disclosure": (["CWE-209 Sensitive Information in Error Message", "CWE-200 Information Exposure"],
                         "ASVS V7.4.1", ["API8:2023 Misconfiguration"]),
    "password-policy": (["CWE-521 Weak Password Requirements"], "ASVS V2.1", ["API2:2023 Broken Authentication"]),
    "tamperable-display": (["CWE-451 UI Misrepresentation of Critical Information",
                            "CWE-829 Inclusion of Functionality from Untrusted Control Sphere"],
                           "ASVS V14.4", ["API8:2023 Misconfiguration"]),
    # --- REF-PENTEST retest classes ---
    "unrestricted-upload": (["CWE-434 Unrestricted Upload of File with Dangerous Type"],
                            "ASVS V12.2", ["API8:2023 Misconfiguration"]),
    "content-sniffing": (["CWE-430 Deployment of Wrong Handler (MIME sniffing)", "CWE-79 Stored XSS"],
                         "ASVS V14.4.3", ["API8:2023 Misconfiguration"]),
    "pii-exposure": (["CWE-359 Exposure of Private Personal Information", "CWE-200 Information Exposure"],
                     "ASVS V8.3", ["API3:2023 BOPLA / Excessive Data Exposure"]),
    # --- client-trust-boundary group (man-in-the-browser display integrity) ---
    "missing-csp": (["CWE-693 Protection Mechanism Failure", "CWE-1021 Improper Restriction of Rendered UI Layers"],
                    "ASVS V14.4.3", ["API8:2023 Misconfiguration"]),
    "incomplete-hsts": (["CWE-523 Unprotected Transport of Credentials",
                         "CWE-319 Cleartext Transmission of Sensitive Information"],
                        "ASVS V9.1.2", ["API8:2023 Misconfiguration"]),
    "weak-fingerprint": (["CWE-331 Insufficient Entropy", "CWE-326 Inadequate Encryption Strength"],
                         "ASVS V6.3.1", []),
    "overclaimed-control": (["CWE-693 Protection Mechanism Failure", "CWE-1059 Insufficient Technical Documentation"],
                            "ASVS V1.1", ["API8:2023 Misconfiguration"]),
    "client-tamper-vector": (["CWE-602 Client-Side Enforcement of Server-Side Security",
                              "CWE-345 Insufficient Verification of Data Authenticity"],
                             "ASVS V1.1", ["API8:2023 Misconfiguration"]),
    "abusable-action-endpoint": (["CWE-770 Allocation of Resources Without Limits or Throttling",
                                  "CWE-352 Cross-Site Request Forgery"],
                                 "ASVS V11.1.4", ["API4:2023 Unrestricted Resource Consumption",
                                                  "API6:2023 Unrestricted Access to Sensitive Business Flows"]),
    "redundant-secret-fetch": (["CWE-200 Information Exposure"], "ASVS V2.10", ["API8:2023 Misconfiguration"]),
    "insecure-cookie": (["CWE-1004 Sensitive Cookie Without HttpOnly", "CWE-614 Sensitive Cookie Without Secure"],
                        "ASVS V3.4.1", ["API8:2023 Misconfiguration"]),
    # --- LLM / AI-agent classes (OWASP LLM Top 10) ---
    "llm-prompt-injection": (["CWE-1427 Prompt Injection", "CWE-77 Command Injection"],
                             "ASVS V5.1", ["LLM01:2025 Prompt Injection"]),
    "llm-insecure-output": (["CWE-94 Code Injection", "CWE-79 XSS"],
                            "ASVS V5.2", ["LLM02:2025 Insecure Output Handling"]),
    "excessive-agency": (["CWE-862 Missing Authorization", "CWE-250 Execution with Unnecessary Privileges"],
                         "ASVS V1.1", ["LLM06:2025 Excessive Agency", "LLM08:2025"]),
    "llm-unbounded": (["CWE-770 Allocation of Resources Without Limits or Throttling"],
                      "ASVS V11.1.4", ["LLM10:2025 Unbounded Consumption", "API4:2023 Unrestricted Resource Consumption"]),
    "llm-guardrail": (["CWE-693 Protection Mechanism Failure", "CWE-755 Improper Handling of Exceptional Conditions"],
                      "ASVS V1.1", ["LLM02:2025", "LLM01:2025"]),
    # --- crypto-usage classes ---
    "weak-password-hash": (["CWE-916 Use of Password Hash With Insufficient Computational Effort", "CWE-759 Missing Salt"],
                           "ASVS V2.4.1", ["API2:2023 Broken Authentication"]),
    "jwt-verify-options": (["CWE-347 Improper Verification of Cryptographic Signature"],
                           "ASVS V3.5.2", ["API2:2023 Broken Authentication"]),
    "predictable-principal": (["CWE-330 Use of Insufficiently Random Values", "CWE-340 Predictable from Observable State"],
                              "ASVS V6.3.1", ["API1:2023 BOLA"]),
    "timing-unsafe-compare": (["CWE-208 Observable Timing Discrepancy"], "ASVS V6.2.3", ["API2:2023 Broken Authentication"]),
    # --- transport / access-control-dataflow classes (0.8.0) ---
    "cors-misconfig": (["CWE-942 Permissive Cross-domain Policy with Untrusted Domains"], "ASVS V14.5.3",
                       ["API8:2023 Misconfiguration"]),
    "subresource-integrity": (["CWE-829 Inclusion of Functionality from Untrusted Control Sphere"], "ASVS V14.2.3",
                              ["API8:2023 Misconfiguration"]),
    "cookie-authz": (["CWE-565 Reliance on Cookies Without Validation", "CWE-602 Client-Side Enforcement of Server-Side Security"],
                     "ASVS V3.4", ["API1:2023 BOLA", "API5:2023 BFLA"]),
    "claim-authz": (["CWE-639 Authorization Bypass Through User-Controlled Key", "CWE-807 Reliance on Untrusted Inputs in a Security Decision"],
                    "ASVS V4.2.1", ["API1:2023 BOLA"]),
    "rls-context": (["CWE-1188 Insecure Default Initialization of Resource"], "ASVS V4.1.3", ["API1:2023 BOLA"]),
    # --- entitlement / licensing + browser-extension client-trust classes ---
    "entitlement-revocation-bypass": (["CWE-863 Incorrect Authorization",
                                       "CWE-672 Operation on a Resource after Expiration or Release"],
                                      "ASVS V4.1.3", ["API6:2023 Unrestricted Access to Sensitive Business Flows",
                                                      "API2:2023 Broken Authentication"]),
    "missing-usage-cap": (["CWE-770 Allocation of Resources Without Limits or Throttling",
                           "CWE-799 Improper Control of Interaction Frequency"],
                          "ASVS V11.1.4", ["API4:2023 Unrestricted Resource Consumption",
                                           "API6:2023 Unrestricted Access to Sensitive Business Flows"]),
    "client-side-entitlement": (["CWE-602 Client-Side Enforcement of Server-Side Security",
                                 "CWE-603 Use of Client-Side Authentication"],
                                "ASVS V1.1", ["API6:2023 Unrestricted Access to Sensitive Business Flows"]),
    "excessive-permissions": (["CWE-272 Least Privilege Violation",
                               "CWE-250 Execution with Unnecessary Privileges"],
                              "ASVS V1.1", ["API8:2023 Misconfiguration"]),
    "extension-message-trust": (["CWE-346 Origin Validation Error",
                                 "CWE-940 Improper Verification of Source of a Communication Channel"],
                                "ASVS V13.2", ["API8:2023 Misconfiguration"]),
}
REMEDIATION = {
    "missing-auth": "Add an auth guard to the handler (e.g. requireAuth()/getServerSession()), or a "
                    "middleware matcher over /api/(.*) with an explicit public allowlist so it can't be forgotten.",
    "bola": "Enforce object ownership: verify the authenticated principal owns/can access the resource id (tenant scope).",
    "webhook-forgery": "Verify the provider's signature (HMAC over the RAW body, constant-time compare) before "
                       "processing, reject stale timestamps / replays, and fail closed when the signature header "
                       "is absent — don't trust an unsigned inbound webhook.",
    "unsafe-auth-decoder": "Verify the token/signature before trusting it for an auth/identity decision — use a "
                           "verifying decode (e.g. jwt.verify with the key / a checked session), never an *Unsafe* "
                           "or decode-only path whose output then feeds requireAuth/requireAdmin.",
    "ssrf": "Validate + allowlist outbound URLs; block RFC1918/IMDS/file://; never fetch a raw user-supplied URL.",
    "nosql-injection": "Never pass raw req.body into a query/operator position; reject $-prefixed keys, use a typed "
                       "query builder or schema validation, and cast expected types before querying.",
    "redos": "Bound the regex (no nested/ambiguous quantifiers), cap input length, or use a linear-time engine "
             "(RE2) — and never build a pattern from unsanitized user input.",
    "eval-injection": "Remove eval()/new Function()/exec on user input; use a safe parser, a typed dispatch table, "
                      "or an explicit allowlist of operations instead.",
    "proxy-escape": "Reject any catch-all segment that is `.`/`..` or contains an encoded slash/dot before building "
                    "the upstream URL; better, assemble it with `new URL` and assert the normalized pathname still "
                    "startsWith the intended prefix, else 400. The forwarded token makes an escaped path a "
                    "full-credential request to any upstream route.",
    "secret": "Rotate the credential, remove from code/history, load from a secrets manager.",
    "cve": "Upgrade the dependency to the fixed version.",
    "iac": "Apply the hardening (non-root user, pin actions to a SHA, enforce TLS, etc.).",
    "client-exposure": "Move the secret server-side; never reference it from a client component or a NEXT_PUBLIC_/VITE_ var.",
    "graphql": "Disable introspection + the playground in production; add query depth/complexity limits.",
    "insecure-secret-default": "Remove the hard-coded fallback; fail closed when the secret env var is unset, "
                               "and ROTATE the leaked value. Load signing keys from a secrets manager.",
    "cswsh": "Make the AppSync default authorization USER_POOL/OIDC/IAM/Lambda (not API_KEY); validate the "
             "WebSocket Origin; keep any API key to a scoped, non-default authorization mode only.",
    "error-disclosure": "Return a generic error to the client; log the stack/detail server-side only. Gate "
                        "verbose errors behind a non-production flag that defaults to OFF.",
    "password-policy": "Enforce ONE shared password policy across every route (a single validator/helper); "
                       "align the weaker siblings to the strongest character-class set.",
    "tamperable-display": "Kill the scalable vector with a strict CSP (script-src 'self' + per-request nonce, no "
                          "unsafe-inline/eval); anchor trust out-of-band (emailed canonical value, safety code, "
                          "server-rendered identicon, EIP-55 checksum) so single-surface tampering is user-detectable.",
    "unrestricted-upload": "Positive allow-list by SNIFFED magic bytes (reject octet-stream/unknown); derive the "
                           "stored name/extension from the detected type, never the client filename; don't trust the "
                           "client Content-Type; drop SVG (or sanitize + serve as attachment).",
    "content-sniffing": "On every file-serving path send `X-Content-Type-Options: nosniff` and force any browser-"
                        "executable type (html/svg/xml/js/text) to `application/octet-stream` + "
                        "`Content-Disposition: attachment` so a stored object can't render as HTML same-origin.",
    "pii-exposure": "Mask PII at ONE output boundary (a DTO/serializer), gated by an explicit permission; keep raw "
                    "data only in storage. Verify by VALUE SHAPE (no phone/email value in the response, incl. nested "
                    "objects, composed IDs and exports), not field name. Wire the masker into the LIVE handlers.",
    "missing-csp": "Add a nonce-based strict CSP (script-src 'self' + per-request nonce + strict-dynamic; no "
                   "unsafe-inline/eval; object-src 'none'). Ship REPORT-ONLY first with a violation-report collector, "
                   "soak, then enforce. Two gotchas: strict-dynamic IGNORES host allowlists (an allowlist gives false "
                   "comfort), and report-only UNDER-reports cascading failures (the first block masks the rest).",
    "incomplete-hsts": "Apply HSTS uniformly at the EDGE to ALL responses (not just /api): "
                       "`max-age>=31536000; includeSubDomains; preload` where the domain model allows.",
    "weak-fingerprint": "Use >=60 bits for any value an attacker can grind offline to forge a matching fingerprint; "
                        "keep it human-comparable (grouped base32, e.g. XXXX-XXXX-XXXX). Don't slice a hash to <60 bits.",
    "overclaimed-control": "Scope the claim honestly ('opportunistic tamper tripwire, not a guarantee') and make the "
                           "actual trust root out-of-band or server-side — never a client-side check the DOM can rewrite.",
    "client-tamper-vector": "Render the security-critical value server-side, or drop the redundant client round-trip; if "
                            "a round-trip is unavoidable, SIGN the payload and verify integrity rather than trusting raw "
                            "fields. A newly-added client fetch for a value that used to be server-rendered is itself a "
                            "regression — it manufactures a tamper vector.",
    "abusable-action-endpoint": "Gate outbound-action endpoints (email/SMS/push/expensive) with auth + CSRF, and rate-"
                                "limit on BOTH dimensions — per-IP AND per-authenticated-principal (IP-only is bypassed "
                                "via proxy pools / IPv6 rotation). Config-gate features that depend on a secret so they "
                                "FAIL CLOSED ('not configured') when it's absent, rather than half-initializing.",
    "redundant-secret-fetch": "Fetch each secret-manager key ONCE per request and reuse it; use the project's existing "
                              "secret-provider abstraction instead of a bespoke loader (smaller exposure window + "
                              "consistency).",
    "insecure-cookie": "Set auth/session cookies `HttpOnly` (blocks JS/XSS theft) + `Secure` (HTTPS-only) + "
                       "`SameSite=Lax`/`Strict` (CSRF). Verify against the live Set-Cookie header.",
    "llm-prompt-injection": "Fence externally-sourced content (RAG/tool/web/document) as untrusted data in the "
                            "prompt, run it through a prompt scrubber, and allow-list any URL host/scheme before "
                            "emitting it. Never instruct the model to render attacker-suppliable URLs verbatim.",
    "llm-insecure-output": "Treat model output as display-only, never a control channel. Don't parse model prose "
                           "into tool calls; if a text fallback exists, constrain it to a strict allow-list and "
                           "never let it invoke state-changing tools. Validate/encode output before any sink.",
    "excessive-agency": "Gate state-changing tools (send/delete/transfer/exec/spend) behind explicit human "
                        "confirmation when the model chooses the args; scope each tool's authority to least "
                        "privilege and run moderation over tool args/results, not just the final text.",
    "llm-unbounded": "Set an explicit maxOutputTokens and a request timeout/abortSignal on every model call, cap "
                     "in-flight concurrency, and rate-limit by token spend (not just request count) — especially "
                     "on unauthenticated endpoints.",
    "llm-guardrail": "Make guards FAIL CLOSED (return the refusal on guard error/timeout), require an explicit "
                     "opt-out to run without an output guard, scan retrieved/tool content (not just the user "
                     "message), and add circuit-breaker semantics instead of per-request silent fail-open.",
    "weak-password-hash": "Verify passwords with a memory-hard adaptive KDF (argon2id/scrypt/bcrypt) + a random "
                          "per-credential salt — never a fast unsalted digest (SHA-256/SHA-1/MD5). Move any "
                          "committed credential material to a secret store and rotate it.",
    "jwt-verify-options": "Pass an explicit `algorithms` allowlist (e.g. `['HS256']`) plus issuer/audience to every "
                          "verify call, so the symmetric-only guarantee is in the code, not an implicit property of "
                          "the key type — pre-empting alg-confusion if the key ever becomes asymmetric.",
    "predictable-principal": "Use an opaque server-assigned random id as the tenant/user principal, or HMAC the "
                             "identity→id mapping under a server secret; always verify the resolved row owns the "
                             "session before honoring a client-supplied id.",
    "timing-unsafe-compare": "Compare request-supplied secrets/tokens/signatures with `crypto.timingSafeEqual` "
                             "(equal-length buffers) or `compare_digest`, never `===`/`!==`, to remove the timing "
                             "side-channel.",
    "cors-misconfig": "Allow-list exact trusted origins; never reflect the request Origin or use `*` when "
                      "`Allow-Credentials: true`. If credentials aren't needed, drop them so a strict allow-list "
                      "isn't load-bearing.",
    "subresource-integrity": "Pin the external resource to an exact version and add a Subresource-Integrity "
                             "`integrity=` hash + `crossorigin`, or self-host it, and constrain it with a CSP so a "
                             "CDN/package compromise can't run arbitrary JS in your origin.",
    "cookie-authz": "Never make an authorization decision on an unsigned/unverified cookie — bind access to a "
                    "signed value (read it from the verified session JWT, or HMAC the cookie) and re-derive on the "
                    "server; treat client cookies as untrusted hints only.",
    "claim-authz": "Resolve the fields used for authorization (office/role/tenant) from the authenticated record "
                   "server-side, not from the JWT body claim; never write a client-asserted claim back as the record "
                   "of truth. Verify the resolved row owns the resource.",
    "rls-context": "Set the RLS context (`set_config('app.*', x, true)`) INSIDE the transaction that runs the "
                   "tenant-scoped query, on the SAME connection the handler uses — a transaction-local setting "
                   "emitted at autocommit resets before the query, so RLS evaluates with an empty context.",
    "entitlement-revocation-bypass": "Don't grant on a truthy verify result alone — inspect the purchase/"
                                     "subscription object and reject refunded/chargebacked/disputed/cancelled/"
                                     "ended/expired states before granting. Cache the verified status and flip it "
                                     "from the provider's refund/dispute webhook so revocation is near-instant.",
    "missing-usage-cap": "Enforce a per-principal usage cap: track distinct devices/seats/activations per license "
                        "and reject beyond the limit, and/or rate-limit per license — never per IP alone (IP limits "
                        "are bypassed via proxy pools / IPv6 rotation). Key every limit on the license/principal.",
    "client-side-entitlement": "Client storage (chrome.storage.local / localStorage) is user-editable, so a "
                              "tier/level/plan read from it is a UI hint, not an enforcement boundary. Enforce every "
                              "paid capability on the server (verify the license per request); if a feature can only "
                              "run in the browser, tie its value to a server-controlled benefit or accept it as "
                              "honor-system — don't sink time into client-side obfuscation.",
    "excessive-permissions": "Request the narrowest host_permissions/permissions the extension needs (specific "
                            "origins, never <all_urls> / *://*/*); prefer activeTab + optional_permissions with "
                            "runtime prompts over broad static grants.",
    "extension-message-trust": "Validate the sender/origin on every runtime.onMessage / window 'message' handler "
                              "(check sender.id / event.origin against an allowlist), set an explicit target origin "
                              "on postMessage (never '*'), and minimise `world:\"MAIN\"` content scripts that expose "
                              "privileged page-world APIs.",
}
_DEFAULT_REM = "Review and remediate per the cited standard."

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
CONF_RANK = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}
WRITE_VERBS = {"POST", "PUT", "PATCH", "DELETE"}

# surface.py sink keys → STANDARDS/attack-class keys where they differ, so a sink cites its SPECIFIC
# CWE instead of falling back to the generic "sast" (CWE-710). sql-injection is the high-value case
# (surface.py emits `sql-injection`; STANDARDS keys it `sqli`). nosql-injection/redos/eval-injection
# now have their own STANDARDS entries, so they resolve directly.
_SINK_ATTACK = {"sql-injection": "sqli"}


def _cite(cls):
    cwe, asvs, api = STANDARDS.get(cls, ([], "", []))
    return {"cwe": cwe, "asvs": asvs, "owasp_api": api}


def load_suppressions(repo_root: Path) -> list:
    """Read `.websec-ignore` (repo root or cwd): glob path patterns or `category:<x>` lines."""
    pats = []
    for cand in (repo_root / ".websec-ignore", Path.cwd() / ".websec-ignore"):
        try:
            if cand.is_file():
                for ln in cand.read_text().splitlines():
                    ln = ln.split("#", 1)[0].strip()
                    if ln:
                        pats.append(ln)
        except Exception:
            pass
    return pats


def _suppressed(f, pats):
    hay = f"{f.get('category','')} {f.get('location','')} {f.get('title','')}".lower()
    for p in pats:
        pl = p.lower()
        if pl.startswith("category:") and f.get("category", "").lower() == pl.split(":", 1)[1]:
            return True
        if fnmatch.fnmatch(f.get("location", "").lower(), pl) or pl in hay:
            return True
    return False


def _f(title, category, attack_class, severity, confidence, location, evidence):
    return {"title": title, "category": category, "attack_class": attack_class,
            "severity": severity, "confidence": confidence,
            "location": location, "evidence": evidence, "standards": _cite(attack_class),
            "remediation": REMEDIATION.get(attack_class, _DEFAULT_REM), "status": "open"}


def build_ledger(facts: dict, unified: dict | None, dynamic: dict | None = None,
                 suppressions: list | None = None) -> dict:
    suppressions = suppressions or []
    out = []

    # ---- 1. Access control: correlate recon (per-endpoint guard) with dynamic verdicts ----
    authz = facts.get("authz", {})
    dyn_write = {(r["method"], r["path"]): r for r in
                 ((dynamic or {}).get("write_auth_enforcement", {}) or {}).get("results", [])}
    dyn_get = {r["path"]: r for r in
               ((dynamic or {}).get("unauth_reachability", {}) or {}).get("results", [])}
    # If the dynamic run suspects a fail-OPEN test env, its unauth "successes" are untrustworthy —
    # do NOT escalate them to CRITICAL (the catastrophic-false-positive trap). Fall back to the
    # recon-level hypothesis with a caveat until the operator re-runs with auth resolving.
    dyn_fail_open = bool(((dynamic or {}).get("write_auth_enforcement", {}) or {}).get("fail_open_suspected")
                         or ((dynamic or {}).get("unauth_reachability", {}) or {}).get("fail_open_suspected"))
    for eg in authz.get("endpoint_guards", []):
        if eg.get("guarded") or eg.get("public_hint") or not eg.get("analyzed"):
            continue
        m, p = eg.get("method"), eg.get("path")
        is_write = m in WRITE_VERBS
        ev = [{"layer": "recon", "detail": f"no auth guard found in handler {eg.get('code_path','?')}"}]
        conf, sev = "MEDIUM", ("HIGH" if is_write else "MEDIUM")
        dv = dyn_write.get((m, p)) or dyn_get.get(p)
        if dv:
            verdict = dv.get("verdict", "")
            if dyn_fail_open and verdict not in ("auth-enforced", "protected"):
                ev.append({"layer": "dynamic", "detail": f"reached unauthenticated (HTTP {dv.get('status')}) — "
                           "BUT fail-open suspected (auth not resolving in the test env); UNTRUSTWORTHY, "
                           "re-run with a working auth provider before trusting this"})
                # keep recon-level conf/sev; do not escalate
            elif "EXECUTED-UNAUTH" in verdict:
                ev.append({"layer": "dynamic", "detail": f"{m} executed UNAUTHENTICATED (HTTP {dv.get('status')})"})
                conf, sev = "HIGH", "CRITICAL"
            elif "no-auth-gate" in verdict or verdict == "OPEN-no-auth":
                ev.append({"layer": "dynamic", "detail": f"reached unauthenticated (HTTP {dv.get('status')}, {verdict})"})
                conf = "HIGH"
                sev = "HIGH" if is_write else "MEDIUM"
            elif verdict in ("auth-enforced", "protected"):
                continue  # dynamic says it's actually protected → not a finding
        out.append(_f(f"Missing authorization: {m} {p}", "access-control", "missing-auth",
                      sev, conf, p, ev))

    # ---- 1b. Cross-tenant BOLA leaks (dynamically confirmed) ----
    for lk in ((dynamic or {}).get("cross_tenant_bola", {}) or {}).get("leaks", []):
        out.append(_f(f"Cross-tenant read: {lk.get('direction')} {lk.get('path')}", "access-control", "bola",
                      "CRITICAL", "HIGH", lk.get("path", ""),
                      [{"layer": "dynamic", "detail": f"cross-tenant GET returned another tenant's data "
                        f"(HTTP {lk.get('status')}, {lk.get('direction')})"}]))

    # ---- 1c. Unsafe/unverified decoder feeding an auth decision (F5) ----
    _authz = facts.get("authz", {}) or {}
    _uvr = _authz.get("unverified_signature_routes", []) or []
    for ud in (_authz.get("unsafe_auth_decoders", []) or []):
        ev = [{"layer": "recon", "detail": f"{ud.get('file')} makes an auth/identity decision AND calls "
               f"{ud.get('decoder')}() — if that decodes a token/signature WITHOUT verifying it, a forged "
               "value is trusted (the decodeJwtPayloadUnsafe → requireAdmin class of bug). Trace the call path."}]
        if _uvr:
            ev.append({"layer": "recon", "detail": f"static at-risk routes ({len(_uvr)}) — call a guard defined "
                       f"alongside this unverified decode: {', '.join(_uvr[:8])}{' …' if len(_uvr) > 8 else ''}. "
                       "Run `websec dynamic --unauth` / the forged-token probe to confirm which accept a forged token."})
        out.append(_f(f"Auth decision uses an unverified decoder: {ud.get('decoder')}", "access-control",
                      "unsafe-auth-decoder", "HIGH", "MEDIUM", ud.get("file", ""), ev))

    # ---- 1d. Forged-token acceptance — unverified signature, DYNAMICALLY CONFIRMED ----
    # The verdict for 1c: we presented an UNSIGNED/bogus-sig token and the route reached its
    # handler anyway (no-auth 401/403 → reached-handler with the forged token). That is the
    # decodeJwtPayloadUnsafe/jwt.decode(verify=False) hypothesis proven — CWE-347 broken auth.
    for b in ((dynamic or {}).get("forged_token_bypass", {}) or {}).get("bypassed", []):
        out.append(_f(
            f"Auth bypass: forged unsigned token accepted — {b.get('method')} {b.get('path')}",
            "access-control", "unsafe-auth-decoder", "CRITICAL", "HIGH",
            f"{b.get('method')} {b.get('path')}",
            [{"layer": "dynamic", "detail": f"no auth → HTTP {b.get('baseline')}; a token with NO valid "
              f"signature (via {b.get('via')}, far-future exp) → HTTP {b.get('forged')} — the auth gate "
              "accepted it, so the signature is NOT verified. Reachable by anyone who can craft a token "
              "string; route the guard through a verifying decode (jwt.verify w/ the key / a checked session)."}]))

    # ---- 1e. Insecure DEFAULT signing secret — forgeable JWT (REF-PENTEST #8) ----
    _auth = facts.get("auth", {}) or {}
    _jwt_used = bool((_auth.get("signal_counts") or {}).get("jwt")) or bool(_auth.get("jwt_sign_verify_present"))
    for sd in (_auth.get("insecure_secret_defaults", []) or []):
        if sd.get("dev_ish") and _jwt_used:
            sev, conf = "CRITICAL", "MEDIUM"        # dev placeholder + the repo signs JWTs → forgeable
        elif sd.get("dev_ish"):
            sev, conf = "HIGH", "MEDIUM"
        else:
            sev, conf = "MEDIUM", "LOW"             # a non-dev-ish fallback on a secret var — still verify
        out.append(_f(f"Hard-coded fallback signing secret in {sd.get('file')}", "authn",
                      "insecure-secret-default", sev, conf, sd.get("file", ""),
                      [{"layer": "recon", "detail": f"a *SECRET/*KEY var falls back to the literal "
                        f"{sd.get('literal')!r} — if that fallback is reached at runtime, anyone who reads the "
                        f"source can forge tokens."
                        + (" The repo signs/verifies JWTs." if _jwt_used else "")
                        + " Confirm reachability with the forged-token / hs256 probe (it seeds this literal)."}]))

    # ---- 2. Static scanner findings (de-duplicated `unified`) ----
    # Consume the FULL ranked set (`all`), not the briefing's short `top` slice — else a
    # HIGH/CRITICAL CVE/secret ranked #16+ never reaches the ledger/REPORT/calibration. Falls
    # back to `top` for older callers/tests that only pass that key.
    cat_to_class = {"sca": "cve", "secret": "secret", "iac": "iac", "sast": "sast"}
    # Supabase key tiers (from client_exposure): a "JWT"/secret scanner hit that is actually the
    # anon/publishable key is intended-public (RLS-protected) → downgrade to INFO so it stops ranking
    # above real findings; a service_role key stays a real leak (surfaced separately below).
    _cx0 = facts.get("client_exposure", {}) or {}
    _sb_anon = {a.replace("\\", "/") for a in _cx0.get("intended_public_supabase", [])}
    _sb_svc = {a.replace("\\", "/") for a in _cx0.get("supabase_service_role_in_client", [])}
    for t in ((unified or {}).get("all") or (unified or {}).get("top", [])):
        cat = t.get("category", "")
        cls = cat_to_class.get(cat, "sast")
        sev = t.get("severity", "MEDIUM")
        # Confidence follows severity for secrets/CVEs: a generic-api-key tiered down to MEDIUM
        # (low-precision rule, bug-072) should NOT be stamped HIGH-confidence — keep P(real) honest.
        conf = "HIGH" if (cat in ("secret", "sca") and sev in ("HIGH", "CRITICAL")) else "MEDIUM"
        _tfile = (t.get("file", "") or "").replace("\\", "/")
        _title = t.get("title", cat)
        # any scanner JWT hit (gitleaks/trivy → `secret`, semgrep → `sast`) on an anon-key file is the
        # intended-public Supabase key — downgrade regardless of the tool's category.
        if (cat in ("secret", "sast") and ("jwt" in _title.lower() or "web token" in _title.lower())
                and any(_tfile.endswith(a) for a in _sb_anon)
                and not any(_tfile.endswith(a) for a in _sb_svc)):
            out.append(_f(_title, f"static-{cat}", "client-exposure", "INFO", "LOW", t.get("file", ""),
                          [{"layer": "static", "detail": f"{'+'.join(t.get('tools', []))}: {_title}"},
                           {"layer": "recon", "detail": "decoded → a Supabase ANON/publishable key (role:anon) "
                            "— DESIGNED to ship to the browser and protected by Row-Level Security, not a secret "
                            "leak. (A service_role key would be CRITICAL; none detected in this file.)"}]))
            continue
        out.append(_f(_title, f"static-{cat}", cls, sev, conf, t.get("file", ""),
                      [{"layer": "static", "detail": f"{'+'.join(t.get('tools', []))}: {t.get('title','')}"}]))

    # ---- 3. Attack-surface sinks (recon hypotheses) ----
    # On a purely-NoSQL datastore, classic SQL-injection alerts are almost always FPs —
    # down-rank them (the inflation the field test flagged) rather than ranking them MEDIUM.
    _ds = {d.lower() for d in (facts.get("stack", {}).get("datastores") or [])}
    _nosql = {"dynamodb", "dynamo", "mongodb", "mongo", "firestore", "cosmos", "cosmosdb", "couchdb",
              "cassandra", "cloudflare-kv", "kv", "durable-objects", "r2-object-store", "redis"}
    # Include the ORM-ish labels stack.py actually emits (prisma(sql)/sql-orm) — and treat any label
    # CONTAINING "sql" (but not "nosql") as SQL — so a SQL-ORM app + Mongo isn't misread as nosql-only
    # and its SQLi findings wrongly down-ranked.
    _sql = {"postgres", "postgresql", "mysql", "mariadb", "sqlite", "mssql", "sqlserver", "aurora",
            "oracle", "cockroach", "prisma(sql)", "sql-orm"}
    has_sql = bool(_ds & _sql) or any("sql" in d and "nosql" not in d for d in _ds)
    is_nosql_only = bool(_ds & _nosql) and not has_sql
    for cls, info in (facts.get("surface", {}).get("sinks", {}) or {}).items():
        sev = "MEDIUM"
        if cls == "error-disclosure":
            # output-side sink — NOT user-input-gated (documented exception); don't mislabel it
            attack = "error-disclosure"
            ev = [{"layer": "recon", "detail": f"response-side disclosure in {info.get('count')} file(s): a handler "
                   "returns err.stack/err.message, or a NODE_ENV!=='production' branch spreads the stack (#7). "
                   "Confirm with the error-disclosure probe (force a 500, grep the body for stack frames)."}]
        elif cls.startswith("ssrf"):
            attack = "ssrf"
            ev = [{"layer": "recon", "detail": f"outbound HTTP with a non-literal (variable) URL in "
                   f"{info.get('count')} file(s) — SSRF if that URL is user-influenced (trace the source; the "
                   "same-line user marker isn't required here, so verify reachability from a req.query reader)"}]
            if cls == "ssrf-outbound-http":
                sev = "LOW"               # var-arg only — weaker than the user-gated `ssrf` class
        else:
            _acls = _SINK_ATTACK.get(cls, cls)
            attack = _acls if _acls in STANDARDS else "sast"
            ev = [{"layer": "recon", "detail": f"user-input-gated {cls} in {info.get('count')} file(s)"}]
        if cls in ("sqli", "sql-injection") and is_nosql_only:
            sev = "LOW"
            ev.append({"layer": "recon", "detail": f"datastore is {', '.join(sorted(_ds)) or 'NoSQL'} — "
                       "classic SQLi is unlikely here; check for NoSQL injection instead (usually a false positive)"})
        out.append(_f(f"{cls} sink ({info.get('count')} site(s))", "attack-surface",
                      attack, sev, "LOW", (info.get("files") or ["?"])[0], ev))

    # ---- 3b. SSRF-via-redirect — outbound client follows redirects with no per-hop guard (#1) ----
    for rel in (facts.get("surface", {}).get("ssrf_redirect_unguarded", []) or []):
        out.append(_f(f"SSRF-via-redirect (no per-hop guard): {rel}", "attack-surface", "ssrf",
                      "MEDIUM", "LOW", rel,
                      [{"layer": "recon", "detail": "an outbound HTTP client here follows redirects (axios/requests do "
                        "by default) with no beforeRedirect / maxRedirects:0 / per-hop host check — only hop 0 is "
                        "validated, so a 302 to 169.254.169.254 / RFC-1918 is followed (#1). Allow-list the host on "
                        "EVERY hop; run the ssrf-probes redirect matrix to confirm."}]))

    # ---- 3c. Reverse-proxy prefix-escape (confined-deputy via `..` in a catch-all path) ----
    for rel in (facts.get("surface", {}).get("proxy_prefix_escape", []) or []):
        out.append(_f(f"Reverse-proxy prefix-escape: {rel}", "attack-surface", "proxy-escape",
                      "HIGH", "MEDIUM", rel,
                      [{"layer": "recon", "detail": "user-controlled catch-all path segments are joined into a "
                        "fixed-prefix upstream URL with no `..`/encoded-slash rejection — WHATWG URL normalizes "
                        "`/prefix/../../admin` PAST the prefix, and the proxy forwards a server-minted token, so the "
                        "caller reaches any upstream route with valid creds (confused deputy). Reject `.`/`..`/`%2e` "
                        "segments or assert the normalized pathname still starts with the prefix."}]))

    # ---- 3d. Host-header → redirect (open redirect / cache poisoning) ----
    for rel in (facts.get("surface", {}).get("host_header_redirect", []) or []):
        out.append(_f(f"Host-header open-redirect: {rel}", "attack-surface", "open-redirect",
                      "MEDIUM", "LOW", rel,
                      [{"layer": "recon", "detail": "a redirect Location/origin is built from the attacker-controllable "
                        "Host / X-Forwarded-Host header with no host allow-list — an on-path or cache-poisoning attacker "
                        "can send the user to an arbitrary host (CWE-601). Pin the redirect base to a server-configured "
                        "origin allow-list, never request headers."}]))

    # ---- 3e. SSRF-hardening: outbound client follows redirects with no allow-list ----
    for rel in (facts.get("surface", {}).get("follows_redirect_no_allowlist", []) or []):
        out.append(_f(f"Follows redirects with no allow-list: {rel}", "attack-surface", "ssrf",
                      "MEDIUM", "LOW", rel,
                      [{"layer": "recon", "detail": "an outbound HTTP client deliberately follows redirects "
                        "(follow_redirects/allow_redirects=True, maxRedirects>0) with no host allow-list or private-range "
                        "deny — a 30x to 169.254.169.254 / an RFC1918 host is fetched server-side regardless of whether "
                        "the initial URL is user-tainted (CWE-918). Re-validate every hop against an allow-list; deny "
                        "loopback/link-local/private ranges."}]))

    # ---- 4. Client-side secret exposure (HIGH — ships to browser) ----
    # Name-based + value-shape (rename-proof) + CDK build-injection (#3) all land here.
    _cx = facts.get("client_exposure", {})
    for leak in (_cx.get("public_secret_leaks", []) + _cx.get("server_secret_in_client_component", [])
                 + _cx.get("public_secret_value_leaks", []) + _cx.get("public_var_from_cfn_output", [])):
        out.append(_f(f"Secret exposed to client: {leak}", "client-exposure", "client-exposure",
                      "HIGH", "HIGH", leak, [{"layer": "recon", "detail": "a secret (by name, value-shape, or CDK "
                       "build-injection) reaches the browser bundle"}]))
    # intended-public analytics ingest tokens (PostHog/Usertour/…) — INFO, designed to ship; surfaced
    # for completeness so they're acknowledged-and-cleared, not silently treated as a HIGH leak.
    for tok in _cx.get("intended_public_analytics", []):
        out.append(_f(f"Intended-public analytics token: {tok}", "client-exposure", "client-exposure",
                      "INFO", "LOW", tok, [{"layer": "recon", "detail": "a write-only analytics/telemetry "
                       "ingest token that is DESIGNED to ship to the browser (PostHog/Usertour/Segment/…) — "
                       "not a secret leak; confirm it's a publishable key, not a server API key reusing the name"}]))
    # Supabase key tiers: a service_role key literal BYPASSES RLS → CRITICAL leak; the anon/publishable
    # key is intended-public → INFO (surfaced so a scanner "JWT" hit on it is acknowledged-and-cleared).
    for f in _cx.get("supabase_service_role_in_client", []):
        out.append(_f(f"Supabase service_role key in client-reachable code: {f}", "client-exposure",
                      "client-exposure", "CRITICAL", "HIGH", f,
                      [{"layer": "recon", "detail": "a Supabase SERVICE_ROLE key (role:service_role) — it "
                        "BYPASSES Row-Level Security (full DB read/write) and must NEVER ship to a client or be "
                        "committed. Rotate it now in the Supabase dashboard and load it from a server-only secret."}]))
    for f in _cx.get("intended_public_supabase", []):
        out.append(_f(f"Supabase anon/publishable key (intended-public): {f}", "client-exposure",
                      "client-exposure", "INFO", "LOW", f,
                      [{"layer": "recon", "detail": "a Supabase ANON/publishable key (role:anon) — designed to "
                        "ship to the browser and protected by Row-Level Security. Not a leak; listed so a scanner "
                        "'JWT' hit on it is acknowledged-and-cleared. Confirm RLS is actually enabled on every table."}]))

    # ---- 5. IaC / CI-CD (AppSync API_KEY default → anonymous/missing-auth, retest-corrected from CSWSH) ----
    for fnd in (facts.get("iac_ci", {}).get("findings", []) or []):
        kind = fnd.get("kind", "")
        # a finding may name its own attack_class (e.g. suppressed-secret-leak → secret); else
        # appsync default-API_KEY is anonymous auth, everything else is generic IaC misconfig.
        cls = fnd.get("attack_class") or ("missing-auth" if kind.startswith("appsync-apikey") else "iac")
        out.append(_f(f"{kind}: {fnd.get('detail','')[:80]}", "iac-ci", cls,
                      fnd.get("severity", "MEDIUM"), "MEDIUM", fnd.get("file", ""),
                      [{"layer": "recon", "detail": fnd.get("detail", "")}]))

    # ---- 6. GraphQL (AppSync introspection #2 + subscription BOLA #5 carry their own attack_class) ----
    g = facts.get("graphql", {})
    if g.get("present"):
        for fnd in g.get("findings", []):
            out.append(_f(f"GraphQL: {fnd.get('issue')}", "graphql", fnd.get("attack_class", "graphql"),
                          fnd.get("severity", "MEDIUM"), "MEDIUM", (g.get("endpoints") or ["/graphql"])[0],
                          [{"layer": "recon", "detail": fnd.get("detail", "")}]))

    # ---- 7. Password-policy drift across sibling routes (REF-PENTEST #6) ----
    pp = facts.get("password_policy", {}) or {}
    for dr in pp.get("drift", []):
        out.append(_f(f"Inconsistent password policy: {dr.get('file')}", "authn", "password-policy",
                      "MEDIUM", "MEDIUM", dr.get("file", ""),
                      [{"layer": "recon", "detail": f"enforces {dr.get('enforces')} while the strongest sibling "
                        f"enforces {dr.get('strongest_enforces')} — the weaker validator is a regression (#6); "
                        "align all routes to one shared policy."}]))
    if pp.get("weak_policy"):
        out.append(_f("Weak password policy (uniform across routes)", "authn", "password-policy", "LOW", "LOW",
                      (pp.get("password_blocks") or [{}])[0].get("file", ""),
                      [{"layer": "recon", "detail": f"strongest policy found enforces only {pp.get('weak_policy')} "
                        "character class(es) — strengthen the requirements."}]))
    if (pp.get("password_reuse") or {}).get("gap"):
        out.append(_f("No password-reuse / history control", "authn", "password-policy", "MEDIUM", "MEDIUM",
                      "set-password paths",
                      [{"layer": "recon", "detail": "a set-password path hashes a new password with NO comparison to "
                        "the current/previous hashes, and no passwordHistory field — a user can re-set the same or a "
                        "prior password (REF-PENTEST #6, the REUSE control, separate from complexity). Add a history "
                        "check on EVERY set-password path (self-service, admin, profile, SSO-JIT) via one shared helper."}]))

    # ---- 8. Client-integrity / tamperable display — man-in-the-browser (the agent-wallet class) ----
    _ci = facts.get("client_integrity", {}) or {}
    for fnd in _ci.get("findings", []):
        out.append(_f(fnd.get("issue", "tamperable client display"), "client-integrity",
                      fnd.get("attack_class", "tamperable-display"),
                      fnd.get("severity", "LOW"), fnd.get("confidence", "LOW"),
                      fnd.get("file") or (_ci.get("sensitive_display") or ["client"])[0],
                      [{"layer": "recon", "detail": fnd.get("detail", "")}]))

    # ---- 8a2. WebExtension client-trust — client-side entitlement gate, over-broad host permissions,
    # world:MAIN content scripts, unvalidated external message handlers. ----
    for fnd in (facts.get("webext", {}) or {}).get("findings", []):
        out.append(_f(f"{fnd.get('kind')}: {fnd.get('file')}", "client-trust",
                      fnd.get("attack_class", "client-side-entitlement"),
                      fnd.get("severity", "LOW"), fnd.get("confidence", "LOW"),
                      fnd.get("file", ""),
                      [{"layer": "recon", "detail": fnd.get("detail", "")}]))

    # ---- 8b. Transport / browser-hardening header baseline (CSP #3, HSTS #4) ----
    for fnd in (facts.get("transport_security", {}) or {}).get("findings", []):
        # header-baseline findings have no file (they're about response headers); CORS/SRI/next-config
        # findings carry a real file — use it so the location is actionable.
        loc = fnd.get("file") or "(response headers)"
        title = f"{fnd.get('kind')}: {fnd.get('file')}" if fnd.get("file") else \
            f"{fnd.get('kind')}: browser/transport hardening header"
        out.append(_f(title, "transport", fnd.get("attack_class", "missing-csp"),
                      fnd.get("severity", "LOW"), "LOW", loc,
                      [{"layer": "recon", "detail": fnd.get("detail", "")}]))

    # ---- 9. Inbound webhooks with no signature verification (forgery / replay) ----
    # Recon found webhook handlers with no HMAC/signature check. This was surfaced in the briefing
    # but — alone among the recon signals — never entered the ranked, calibrated ledger. Wire it in
    # for parity (MEDIUM: heuristic — the check may live in middleware, so verify).
    for wh in (facts.get("integrations", {}) or {}).get("webhooks_without_sig_verification", []):
        out.append(_f(f"Webhook without signature verification: {wh}", "integrations",
                      "webhook-forgery", "MEDIUM", "MEDIUM", wh,
                      [{"layer": "recon", "detail": "no signature-verification code (HMAC / timingSafeEqual / "
                        "Stripe-Signature / svix / compare_digest) found in this webhook handler — a forged or "
                        "replayed request could be processed as authentic. Confirm it isn't handled in middleware, "
                        "then run the webhook-forgery probe."}]))

    # ---- 9b. Outbound-action endpoints (#5) + secret-handling hygiene (#6) ----
    for fnd in (facts.get("integrations", {}) or {}).get("findings", []):
        out.append(_f(f"{fnd.get('kind')}: {fnd.get('detail','')[:70]}", "integrations",
                      fnd.get("attack_class", "iac"), fnd.get("severity", "LOW"),
                      fnd.get("confidence", "LOW"), fnd.get("file", ""),
                      [{"layer": "recon", "detail": fnd.get("detail", "")}]))

    # ---- 10. Upload security — polyglot / MIME-spoof / serve-side stored XSS (REF-PENTEST #2b) ----
    for fnd in (facts.get("upload_security", {}) or {}).get("findings", []):
        kind = fnd.get("kind", "")
        cls = "content-sniffing" if kind == "serve-no-nosniff" else "unrestricted-upload"
        out.append(_f(f"{kind}: {fnd.get('file')}", "upload", cls,
                      fnd.get("severity", "MEDIUM"), "MEDIUM", fnd.get("file", ""),
                      [{"layer": "recon", "detail": fnd.get("detail", "")}]))

    # ---- 11. PII output-boundary — unmasked customer data + dead masking controls (#8) ----
    for fnd in (facts.get("pii_exposure", {}) or {}).get("findings", []):
        out.append(_f(f"{fnd.get('kind')}: {fnd.get('file')}", "pii", "pii-exposure",
                      fnd.get("severity", "MEDIUM"), "MEDIUM", fnd.get("file", ""),
                      [{"layer": "recon", "detail": fnd.get("detail", "")}]))

    # ---- 12. LLM / AI-agent surface — OWASP LLM Top 10 (prompt injection, insecure output,
    # excessive agency, unbounded generation, guardrail fail-open). New class for AI apps. ----
    for fnd in (facts.get("llm_security", {}) or {}).get("findings", []):
        out.append(_f(f"{fnd.get('kind')}: {fnd.get('file')}", "llm-security",
                      fnd.get("attack_class", "llm-prompt-injection"),
                      fnd.get("severity", "MEDIUM"), "LOW", fnd.get("file", ""),
                      [{"layer": "recon", "detail": fnd.get("detail", "")}]))

    # ---- 13. Crypto-usage — algorithm choice + verify-option correctness (weak password hash,
    # jwtVerify without an algorithms allowlist, predictable principal). ----
    for fnd in (facts.get("crypto_usage", {}) or {}).get("findings", []):
        out.append(_f(f"{fnd.get('kind')}: {fnd.get('file')}", "crypto",
                      fnd.get("attack_class", "weak-password-hash"),
                      fnd.get("severity", "MEDIUM"), "MEDIUM", fnd.get("file", ""),
                      [{"layer": "recon", "detail": fnd.get("detail", "")}]))

    # ---- 14. Authz data-flow — does the guard trust the right thing? (unsigned-cookie authz,
    # claim-keyed authz, transaction-local RLS context). ----
    for fnd in (facts.get("authz_dataflow", {}) or {}).get("findings", []):
        out.append(_f(f"{fnd.get('kind')}: {fnd.get('file')}", "access-control",
                      fnd.get("attack_class", "cookie-authz"),
                      fnd.get("severity", "MEDIUM"), "LOW", fnd.get("file", ""),
                      [{"layer": "recon", "detail": fnd.get("detail", "")}]))

    # ---- suppress + rank ----
    kept = [f for f in out if not _suppressed(f, suppressions)]
    suppressed_n = len(out) - len(kept)
    kept.sort(key=lambda f: (-SEV_RANK.get(f["severity"], 0), -CONF_RANK.get(f["confidence"], 0)))

    # ---- calibrate: attach a measured real-rate + CI to each finding (best-effort) ----
    cal_table = calibration.load()
    by_sev, by_conf, by_basis = {}, {}, {}
    for f in kept:
        f["calibrated"] = calibration.apply(f.get("attack_class", ""), f["confidence"], cal_table)
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_conf[f["confidence"]] = by_conf.get(f["confidence"], 0) + 1
        by_basis[f["calibrated"]["basis"]] = by_basis.get(f["calibrated"]["basis"], 0) + 1
    return {"findings": kept, "total": len(kept), "suppressed": suppressed_n,
            "by_severity": by_sev, "by_confidence": by_conf,
            "calibration": {"loaded": bool(cal_table), "by_basis": by_basis,
                            "personalized": bool((cal_table or {}).get("meta", {}).get("personalized")),
                            "local_samples": (cal_table or {}).get("meta", {}).get("local_samples", 0),
                            "caveat": (cal_table or {}).get("meta", {}).get("caveat")},
            "dynamic_included": bool(dynamic)}

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
    # --- PTREQ0013000 classes ---
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
    # --- PTREQ0013000 retest classes ---
    "unrestricted-upload": (["CWE-434 Unrestricted Upload of File with Dangerous Type"],
                            "ASVS V12.2", ["API8:2023 Misconfiguration"]),
    "content-sniffing": (["CWE-430 Deployment of Wrong Handler (MIME sniffing)", "CWE-79 Stored XSS"],
                         "ASVS V14.4.3", ["API8:2023 Misconfiguration"]),
    "pii-exposure": (["CWE-359 Exposure of Private Personal Information", "CWE-200 Information Exposure"],
                     "ASVS V8.3", ["API3:2023 BOPLA / Excessive Data Exposure"]),
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

    # ---- 1e. Insecure DEFAULT signing secret — forgeable JWT (PTREQ0013000 #8) ----
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
    for t in ((unified or {}).get("all") or (unified or {}).get("top", [])):
        cat = t.get("category", "")
        cls = cat_to_class.get(cat, "sast")
        sev = t.get("severity", "MEDIUM")
        # Confidence follows severity for secrets/CVEs: a generic-api-key tiered down to MEDIUM
        # (low-precision rule, bug-072) should NOT be stamped HIGH-confidence — keep P(real) honest.
        conf = "HIGH" if (cat in ("secret", "sca") and sev in ("HIGH", "CRITICAL")) else "MEDIUM"
        out.append(_f(t.get("title", cat), f"static-{cat}", cls, sev, conf, t.get("file", ""),
                      [{"layer": "static", "detail": f"{'+'.join(t.get('tools', []))}: {t.get('title','')}"}]))

    # ---- 3. Attack-surface sinks (recon hypotheses) ----
    # On a purely-NoSQL datastore, classic SQL-injection alerts are almost always FPs —
    # down-rank them (the inflation the field test flagged) rather than ranking them MEDIUM.
    _ds = {d.lower() for d in (facts.get("stack", {}).get("datastores") or [])}
    _nosql = {"dynamodb", "dynamo", "mongodb", "mongo", "firestore", "cosmos", "cosmosdb", "couchdb", "cassandra"}
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

    # ---- 4. Client-side secret exposure (HIGH — ships to browser) ----
    # Name-based + value-shape (rename-proof) + CDK build-injection (#3) all land here.
    _cx = facts.get("client_exposure", {})
    for leak in (_cx.get("public_secret_leaks", []) + _cx.get("server_secret_in_client_component", [])
                 + _cx.get("public_secret_value_leaks", []) + _cx.get("public_var_from_cfn_output", [])):
        out.append(_f(f"Secret exposed to client: {leak}", "client-exposure", "client-exposure",
                      "HIGH", "HIGH", leak, [{"layer": "recon", "detail": "a secret (by name, value-shape, or CDK "
                       "build-injection) reaches the browser bundle"}]))

    # ---- 5. IaC / CI-CD (AppSync API_KEY default → anonymous/missing-auth, retest-corrected from CSWSH) ----
    for fnd in (facts.get("iac_ci", {}).get("findings", []) or []):
        kind = fnd.get("kind", "")
        cls = "missing-auth" if kind.startswith("appsync-apikey") else "iac"
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

    # ---- 7. Password-policy drift across sibling routes (PTREQ0013000 #6) ----
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
                        "prior password (PTREQ0013000 #6, the REUSE control, separate from complexity). Add a history "
                        "check on EVERY set-password path (self-service, admin, profile, SSO-JIT) via one shared helper."}]))

    # ---- 8. Client-integrity / tamperable display — man-in-the-browser (the agent-wallet class) ----
    _ci = facts.get("client_integrity", {}) or {}
    for fnd in _ci.get("findings", []):
        out.append(_f(fnd.get("issue", "tamperable client display"), "client-integrity",
                      fnd.get("attack_class", "tamperable-display"),
                      fnd.get("severity", "LOW"), fnd.get("confidence", "LOW"),
                      (_ci.get("sensitive_display") or ["client"])[0],
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

    # ---- 10. Upload security — polyglot / MIME-spoof / serve-side stored XSS (PTREQ0013000 #2b) ----
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

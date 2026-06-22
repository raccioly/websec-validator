"""Authorization data-flow extractor — authz CORRECTNESS, not just presence.

`authz.py` answers "is there a guard on this route?". This answers the next question — "does the guard
trust the right thing?" — for three real broken-access-control patterns the route-level model can't see:

  - **Unsigned-cookie authorization (CWE-565/602)** — an access decision keyed on a client-settable,
    unsigned cookie (`twin-access-level`, `*role*`, `*allowed*`). httpOnly stops JS reads but the user
    still controls their own cookie jar (devtools/curl), so the gate is forgeable.
  - **Claim → authz decision (CWE-639/807)** — an authorization check that compares a profile-ish JWT
    BODY claim (office/role/group/tenant) the user may influence, instead of a server-resolved record.
  - **Transaction-local RLS context (CWE-1188)** — `set_config('app.*', x, true)` (is_local=true)
    emitted at autocommit (no surrounding transaction): the RLS principal resets before the handler's
    query runs, so row-level security evaluates with an EMPTY context — defense-in-depth theater.

All are file-level co-occurrence heuristics, server-side + test-excluded, framed as leads to verify —
a static scan can't prove the cookie is the one that gates, only point the agent at the file.
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext, is_client_file, is_test_file

# --- unsigned-cookie authorization ---
COOKIE_AUTHZ_READ = re.compile(
    r"(?:cookies?\.get|req\.cookies|getCookie|cookieStore\.get)\s*\(?\s*['\"]"
    r"([\w-]*(?:access|role|admin|allow|auth|tier|perm|priv|level|scope|tenant|clerk-user)[\w-]*)['\"]", re.I)
AUTHZ_GATE = re.compile(
    r"\b403\b|status\s*\(\s*40[13]|\.redirect\s*\([^)]*(?:login|signin|default|unauthorized|forbidden)"
    r"|[!=]==\s*['\"](?:full|admin|allowed|true|owner)|normalizeAccess|accessLevel|hasAccess|requireFull|denyAccess", re.I)
COOKIE_VERIFY = re.compile(
    r"jwtVerify|jwt\.verify|verifyToken|verifyCookie|\bhmac\b|timingSafeEqual|unseal|\bdecrypt\b"
    r"|signed\s*:\s*true|cookie-signature|verifySignature|getServerSession", re.I)

# --- claim → authz decision ---
AUTHZ_FN = re.compile(
    r"function\s+(?:can|authorize|check|assert)\w*|(?:const|let)\s+(?:can|authorize|check)\w*\s*=\s*"
    r"|\bcan[A-Z]\w*\s*\(|\bauthoriz\w*\s*\(|visibilit|buildVisibility|accessControl|ACL\b", re.I)
# a profile-ish claim taken from the JWT BODY / request identity (vs a server-resolved record)
CLAIM_SRC = re.compile(
    r"jwtPayload\s*\[\s*['\"](?:office|role|roles|group|org|department|tenant|plan|tier|scope)"
    r"|payload\.(?:office|role|group|org|department|tenant)\b"
    r"|claims?\s*[\[.]\s*['\"]?(?:office|role|group|org|department|tenant)"
    r"|\.tenant(?:Office|Role|Group|Plan)\b|req\.(?:user|auth)\.(?:office|role|group|org|department)\b", re.I)
CLAIM_COMPARE = re.compile(r"[!=]==|\.(?:includes|has|some)\s*\(|\bin\s+\[", re.I)

# --- transaction-local RLS context ---
SET_CONFIG_LOCAL = re.compile(r"set_config\s*\(\s*['\"]app\.[\w.]+['\"]\s*,[^,()]+,\s*true\s*\)", re.I)
IN_TRANSACTION = re.compile(
    r"\bBEGIN\b|\bSTART\s+TRANSACTION\b|\.transaction\s*\(|withTransaction|db\.transaction|\btx\b\.|\btrx\b\.|\bBEGIN;|"
    r"transaction\s*\(\s*async", re.I)


class AuthzDataflowExtractor(Extractor):
    name = "authz_dataflow"
    category = "authz"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        findings: list = []
        seen: set = set()

        def add(sev, kind, attack, rel, detail):
            if (kind, rel) in seen:
                return
            seen.add((kind, rel))
            findings.append({"severity": sev, "kind": kind, "attack_class": attack,
                             "file": rel, "detail": detail})

        for _p, rel, text in ctx.iter_code():
            if is_test_file(rel) or is_client_file(rel, text):
                continue

            # 1. authorization decision keyed on an unsigned cookie
            m = COOKIE_AUTHZ_READ.search(text)
            if m and AUTHZ_GATE.search(text) and not COOKIE_VERIFY.search(text):
                add("MEDIUM", "unsigned-cookie-authz", "cookie-authz", rel,
                    f"An access decision appears to be keyed on a client-settable cookie "
                    f"(`{m.group(1)}`) with no signature/JWT/HMAC verification in this file. httpOnly only "
                    "blocks JS reads — the user still controls their own cookie jar, so they can forge the "
                    "value and pass the gate (CWE-565/602). Bind access to a signed value (read it from the "
                    "verified session JWT, or HMAC the cookie) and re-derive server-side.")

            # 2. authz decision comparing a user-influenceable JWT claim
            if AUTHZ_FN.search(text) and CLAIM_SRC.search(text) and CLAIM_COMPARE.search(text):
                add("LOW", "claim-based-authz", "claim-authz", rel,
                    "An authorization check appears to compare a profile-ish JWT BODY claim "
                    "(office/role/group/tenant) that the user may be able to influence, rather than a "
                    "value resolved from the authenticated record (CWE-639/807). VERIFY the claim is "
                    "server-resolved and non-user-editable; otherwise resolve it from the tenant/user row "
                    "inside the request, and never write a client-asserted claim back as the record of truth.")

            # 3. transaction-local RLS context set outside a transaction (resets before the query)
            if SET_CONFIG_LOCAL.search(text) and not IN_TRANSACTION.search(text):
                add("MEDIUM", "rls-context-no-transaction", "rls-context", rel,
                    "`set_config('app.*', …, true)` sets the RLS principal TRANSACTION-LOCALLY "
                    "(is_local=true) but there's no surrounding transaction in this file — at autocommit "
                    "the setting resets the instant that one statement commits, before any handler query "
                    "runs, so RLS evaluates with an EMPTY context (CWE-1188, defense-in-depth theater). "
                    "Set it INSIDE the transaction that runs the tenant-scoped query, on the SAME "
                    "connection the handler uses (or use is_local=false on a dedicated per-request connection).")

        by_sev: dict = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        return {"findings": findings, "by_severity": by_sev,
                "note": (f"{len(findings)} authz-correctness lead(s) — these check whether a guard trusts the "
                         "RIGHT thing (signed cookie / server-resolved claim / live RLS context), not just whether "
                         "a guard exists. Verify each against the data flow.") if findings
                        else "No unsigned-cookie / claim-keyed-authz / transaction-local-RLS tells found."}

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

# attack class → authoritative citations + a remediation pattern
STANDARDS = {
    "missing-auth": (["CWE-862 Missing Authorization", "CWE-306 Missing Authentication"],
                     "ASVS V4.1.1", ["API1:2023 BOLA", "API5:2023 BFLA"]),
    "bola": (["CWE-639 Authorization Bypass (IDOR)"], "ASVS V4.2.1", ["API1:2023 BOLA"]),
    "ssrf": (["CWE-918 SSRF"], "ASVS V12.6", ["API7:2023 SSRF"]),
    "secret": (["CWE-798 Hard-coded Credentials"], "ASVS V2.10", ["API8:2023 Misconfiguration"]),
    "sqli": (["CWE-89 SQL Injection"], "ASVS V5.3.4", ["API8:2023"]),
    "command-injection": (["CWE-78 OS Command Injection"], "ASVS V5.3.8", []),
    "path-traversal": (["CWE-22 Path Traversal"], "ASVS V12.3", []),
    "ssti": (["CWE-1336 SSTI"], "ASVS V5.2.5", []),
    "open-redirect": (["CWE-601 Open Redirect"], "ASVS V5.1.5", []),
    "insecure-deserialization": (["CWE-502 Deserialization"], "ASVS V5.5", []),
    "xxe": (["CWE-611 XXE"], "ASVS V5.5.2", []),
    "prototype-pollution": (["CWE-1321 Prototype Pollution"], "ASVS V5.1", []),
    "mass-assignment": (["CWE-915 Mass Assignment"], "ASVS V5.1.2", ["API3:2023 BOPLA"]),
    "cve": (["CWE-1395 Vulnerable Dependency"], "ASVS V14.2.1", ["API8:2023"]),
    "iac": (["CWE-1188 Insecure Default"], "ASVS V14.1", []),
    "client-exposure": (["CWE-200 Information Exposure"], "ASVS V14.3", []),
    "graphql": (["CWE-200 Information Exposure"], "ASVS V13.1", ["API8:2023"]),
    "sast": (["CWE-710 Coding Standards"], "ASVS V1.1", []),
}
REMEDIATION = {
    "missing-auth": "Add an auth guard to the handler (e.g. requireAuth()/getServerSession()), or a "
                    "middleware matcher over /api/(.*) with an explicit public allowlist so it can't be forgotten.",
    "bola": "Enforce object ownership: verify the authenticated principal owns/can access the resource id (tenant scope).",
    "ssrf": "Validate + allowlist outbound URLs; block RFC1918/IMDS/file://; never fetch a raw user-supplied URL.",
    "secret": "Rotate the credential, remove from code/history, load from a secrets manager.",
    "cve": "Upgrade the dependency to the fixed version.",
    "iac": "Apply the hardening (non-root user, pin actions to a SHA, enforce TLS, etc.).",
    "client-exposure": "Move the secret server-side; never reference it from a client component or a NEXT_PUBLIC_/VITE_ var.",
    "graphql": "Disable introspection + the playground in production; add query depth/complexity limits.",
}
_DEFAULT_REM = "Review and remediate per the cited standard."

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
CONF_RANK = {"HIGH": 2, "MEDIUM": 1, "LOW": 0}
WRITE_VERBS = {"POST", "PUT", "PATCH", "DELETE"}


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
    return {"title": title, "category": category, "severity": severity, "confidence": confidence,
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
            if "EXECUTED-UNAUTH" in verdict:
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

    # ---- 2. Static scanner findings (de-duplicated `unified`) ----
    cat_to_class = {"sca": "cve", "secret": "secret", "iac": "iac", "sast": "sast"}
    for t in (unified or {}).get("top", []):
        cat = t.get("category", "")
        cls = cat_to_class.get(cat, "sast")
        sev = t.get("severity", "MEDIUM")
        conf = "HIGH" if cat in ("secret",) or (cat == "sca" and sev in ("HIGH", "CRITICAL")) else "MEDIUM"
        out.append(_f(t.get("title", cat), f"static-{cat}", cls, sev, conf, t.get("file", ""),
                      [{"layer": "static", "detail": f"{'+'.join(t.get('tools', []))}: {t.get('title','')}"}]))

    # ---- 3. Attack-surface sinks (recon hypotheses) ----
    for cls, info in (facts.get("surface", {}).get("sinks", {}) or {}).items():
        out.append(_f(f"{cls} sink ({info.get('count')} site(s))", "attack-surface",
                      cls if cls in STANDARDS else "sast", "MEDIUM", "LOW",
                      (info.get("files") or ["?"])[0],
                      [{"layer": "recon", "detail": f"user-input-gated {cls} in {info.get('count')} file(s)"}]))

    # ---- 4. Client-side secret exposure (HIGH — ships to browser) ----
    for leak in (facts.get("client_exposure", {}).get("public_secret_leaks", []) +
                 facts.get("client_exposure", {}).get("server_secret_in_client_component", [])):
        out.append(_f(f"Secret exposed to client: {leak}", "client-exposure", "client-exposure",
                      "HIGH", "HIGH", leak, [{"layer": "recon", "detail": "secret-named var reaches the browser bundle"}]))

    # ---- 5. IaC / CI-CD ----
    for fnd in (facts.get("iac_ci", {}).get("findings", []) or []):
        out.append(_f(f"{fnd.get('kind')}: {fnd.get('detail','')[:80]}", "iac-ci", "iac",
                      fnd.get("severity", "MEDIUM"), "MEDIUM", fnd.get("file", ""),
                      [{"layer": "recon", "detail": fnd.get("detail", "")}]))

    # ---- 6. GraphQL ----
    g = facts.get("graphql", {})
    if g.get("present"):
        for fnd in g.get("findings", []):
            out.append(_f(f"GraphQL: {fnd.get('issue')}", "graphql", "graphql",
                          fnd.get("severity", "MEDIUM"), "MEDIUM", (g.get("endpoints") or ["/graphql"])[0],
                          [{"layer": "recon", "detail": fnd.get("detail", "")}]))

    # ---- suppress + rank ----
    kept = [f for f in out if not _suppressed(f, suppressions)]
    suppressed_n = len(out) - len(kept)
    kept.sort(key=lambda f: (-SEV_RANK.get(f["severity"], 0), -CONF_RANK.get(f["confidence"], 0)))

    by_sev, by_conf = {}, {}
    for f in kept:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_conf[f["confidence"]] = by_conf.get(f["confidence"], 0) + 1
    return {"findings": kept, "total": len(kept), "suppressed": suppressed_n,
            "by_severity": by_sev, "by_confidence": by_conf,
            "dynamic_included": bool(dynamic)}

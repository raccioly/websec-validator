"""Pentest test plan — a phased, TARGETED runbook derived from the attack-surface inventory.

Commercial pentest platforms crawl blind, then fuzz everything. websec already knows the surface
statically, so it can hand a human (or an agent driving an opt-in dynamic run) the exact ordered list
of tests to run, each pre-aimed at a specific endpoint/param, with the tool command and a
confirm/disconfirm oracle. Static-targeted DAST beats a blind crawl — and this is the artifact that
aims it.

Three phases, gated by blast radius (the industry map→scan→exploit lifecycle):
  Phase 1 — SAFE / read-only recon: TLS, security headers, GraphQL introspection, exposed VCS. No auth,
            non-destructive — run these first, always.
  Phase 2 — AUTHZ (needs ≥2 identities): BOLA/IDOR id-swaps, BFLA role-swaps, mass-assignment. The
            highest-value class AND the one no scanner finds — this is where websec earns its keep.
  Phase 3 — INJECTION (targeted, potentially disruptive): sqlmap / ZAP-active / SSRF-OAST fired ONLY at
            the specific sink-backed endpoints. Gated: do NOT run without explicit human authorization
            against an instance you own.

Everything references `$BASE_URL` (the user's OWN test instance) — websec never runs these; it stages
them. Deterministic: pure functions over facts + inventory.
"""

from __future__ import annotations

import re

_HIGH_RISK_SINKS = {"sql-injection", "sqli", "command-injection", "eval-injection",
                    "nosql-injection", "path-traversal", "ssrf", "ssrf-outbound-http", "xxe"}


# Route paths are parsed out of SOURCE and then interpolated into shell commands the user is told to
# copy-paste. A path containing a quote, backtick or $( ) would break out of the string. websec is a
# security tool; it must not hand anyone a command that executes something unintended.
# Only the characters that actually BREAK OUT of the quoted string the path is embedded in:
# quotes, backtick, `$` (expansion), backslash, and any whitespace/newline. Chars like ; | & < > ( )
# are inert inside quotes, and `{ }` MUST stay allowed — `/api/orders/{id}` is the single most common
# shape of an IDOR target, and rejecting it would strip nearly every parameterised endpoint from the
# plan (a silent loss of exactly the endpoints Phase 2 exists to test).
_SHELL_UNSAFE = re.compile(r"""["'`$\\\s]""")


def _safe_path(path: str) -> str:
    """A route path that is safe to embed in a shell command, or "" if it is not."""
    p = str(path or "")
    return p if p and not _SHELL_UNSAFE.search(p) else ""


def _shell_safe_rows(rows: list) -> list:
    """Drop endpoints whose path can't be safely interpolated into a copy-paste command.

    Dropping is right here: these are OPTIONAL suggested commands, and a path with a quote/backtick/
    $( ) is far more likely to be a parser artifact than a real route. The inventory (§3a) still
    lists every endpoint, so nothing is hidden — only the generated command is withheld."""
    return [r for r in rows if _safe_path(r.get("path", ""))]


def _item(title, target, tool, command, oracle):
    return {"title": title, "target": target, "tool": tool, "command": command, "oracle": oracle}


def build(facts: dict, inventory: dict, prediction: dict | None = None) -> dict:
    """→ {phases: [ {name, gate, items:[…]} ], summary:{…}}. Pure, deterministic."""
    rows = (inventory or {}).get("endpoints", []) or []
    stack = facts.get("stack", {}) or {}
    gq = facts.get("graphql", {}) or {}
    schemas = facts.get("schemas", {}) or {}
    priv_fields = schemas.get("sensitive_fields", []) or []

    # ---- Phase 1: safe recon (host-level, no auth) ----
    p1 = [
        _item("TLS / cipher configuration", "$BASE_URL (host)", "testssl.sh",
              "testssl.sh --quiet --color 0 $BASE_URL",
              "any 'NOT ok' line for protocol/cipher/cert = a finding; clean = pass"),
        _item("Security response headers", "$BASE_URL (any page)", "nuclei",
              "nuclei -u $BASE_URL -tags headers,misconfig -severity low,medium,high",
              "confirms the §4b header predictions (CSP/HSTS/nosniff/frame-options)"),
    ]
    if gq.get("present"):
        ep = gq.get("endpoint", "/graphql")
        p1.append(_item("GraphQL introspection reachable in prod", f"POST {ep}", "curl",
                        f'curl -s $BASE_URL{ep} -H "Content-Type: application/json" '
                        '-d \'{"query":"{__schema{types{name}}}"}\'',
                        "a full type list back = introspection ON (should be disabled in prod)"))
    p1.append(_item("Exposed VCS / dotfiles under web root", "$BASE_URL/.git/config", "nuclei",
                    "nuclei -u $BASE_URL -tags exposure,config",
                    "a 200 with real content = exposed; 404/403 = pass"))

    # ---- Phase 2: authz — pull concrete targets from the ranked inventory ----
    p2 = []
    idor_targets = _shell_safe_rows(
        [r for r in rows if any("IDOR" in w for w in r.get("why", [])) or r.get("path_params")])
    for r in idor_targets[:12]:
        pp = ", ".join(r.get("path_params", [])) or "id"
        p2.append(_item(
            f"BOLA / IDOR — object id in path (`{pp}`)", f"{r['method']} {r['path']}",
            "two identities (curl/httpie) or the staged bola probe",
            f"# as user A, note an id you own; then as user B:\n"
            f"curl -s -H \"Authorization: Bearer $TOKEN_B\" \"$BASE_URL{r['path']}\"  "
            f"# with A's {pp}",
            "user B gets user A's object (200 + A's data) = BOLA; 403/404 = properly isolated"))
    write_rows = _shell_safe_rows([r for r in rows if r.get("is_write")])
    if priv_fields and write_rows:
        wr = write_rows[0]
        p2.append(_item(
            "Mass-assignment — inject privileged fields into a write", f"{wr['method']} {wr['path']}",
            "curl + the staged mass-assignment probe",
            f'curl -s -X {wr["method"]} "$BASE_URL{wr["path"]}" -H "Authorization: Bearer $TOKEN" '
            f'-H "Content-Type: application/json" -d \'{{"...":"valid", '
            + ", ".join(f'"{f}":"attacker"' for f in priv_fields[:3]) + "}'",
            f"the privileged field ({', '.join(priv_fields[:3])}) is persisted = mass-assignment"))
    unguarded_writes = _shell_safe_rows(
        [r for r in rows if r.get("is_write") and r.get("auth") == "UNGUARDED"])
    for r in unguarded_writes[:6]:
        p2.append(_item(
            "BFLA / missing function-level authz — write with no visible guard",
            f"{r['method']} {r['path']}", "curl (no token, then low-priv token)",
            f'curl -s -X {r["method"]} "$BASE_URL{r["path"]}" -H "Content-Type: application/json" -d \'{{}}\'',
            "a 2xx without auth (or from a low-priv user) = broken function-level authz"))

    # ---- Phase 3: injection — ONLY at sink-backed endpoints ----
    p3 = []
    sink_rows = _shell_safe_rows(
        [r for r in rows if any(s in _HIGH_RISK_SINKS for s in r.get("sinks", []))])
    for r in sink_rows[:12]:
        hot = [s for s in r.get("sinks", []) if s in _HIGH_RISK_SINKS]
        if any(s in ("sql-injection", "sqli", "nosql-injection") for s in hot):
            param = (r.get("params") or ["id"])[0]
            p3.append(_item(
                f"SQL/NoSQL injection — sink in `{r['handler']}`", f"{r['method']} {r['path']}",
                "sqlmap",
                f'sqlmap -u "$BASE_URL{r["path"]}" --data=\'{param}=1\' --batch --level 2 '
                "--risk 2 --technique=BEUST",
                "sqlmap confirms an injectable param = SQLi; 'not injectable' = pass"))
        if any(s in ("ssrf", "ssrf-outbound-http") for s in hot):
            param = next((p for p in (r.get("params") or []) if p), "url")
            p3.append(_item(
                "SSRF — url-ish param drives an outbound fetch", f"{r['method']} {r['path']}",
                "interactsh + curl (OAST)",
                f'curl -s "$BASE_URL{r["path"]}?{param}=http://$OAST_DOMAIN/"  '
                "# watch the interactsh listener",
                "an inbound hit on your OAST domain = SSRF confirmed"))
        if any(s in ("command-injection", "eval-injection") for s in hot):
            p3.append(_item(
                "Command / eval injection — exec sink in handler file", f"{r['method']} {r['path']}",
                "ZAP active / manual OAST payload",
                f'# fuzz each param of {r["method"]} {r["path"]} with `;curl http://$OAST/` style payloads',
                "an OAST callback or time delay = command execution"))
        if any(s == "path-traversal" for s in hot):
            p3.append(_item(
                "Path traversal — user path segment reaches the filesystem", f"{r['method']} {r['path']}",
                "curl", f'curl -s "$BASE_URL{r["path"]}" # try ../../etc/passwd in the path param',
                "file contents outside the intended dir = traversal"))

    phases = [
        {"name": "Phase 1 — SAFE recon (no auth, non-destructive) — run first, always",
         "gate": "none — read-only", "items": p1},
        {"name": "Phase 2 — AUTHZ (needs ≥2 identities you control) — the highest-value, scanner-blind class",
         "gate": "needs test accounts at ≥2 privilege levels", "items": p2},
        {"name": "Phase 3 — INJECTION (targeted at sink-backed endpoints)",
         "gate": "⚠ potentially disruptive — run ONLY against an instance you own, with explicit authorization",
         "items": p3},
    ]
    return {"phases": phases,
            "summary": {"phase1": len(p1), "phase2": len(p2), "phase3": len(p3),
                        "total": len(p1) + len(p2) + len(p3)}}


def render_md(plan: dict) -> str:
    phases = plan.get("phases", []) or []
    if not any(ph["items"] for ph in phases):
        return "_No targeted plan — no endpoints/sinks mapped to aim probes at._"
    out = ["_A phased runbook aimed at THIS app's surface — run top-to-bottom against an instance you "
           "own (`$BASE_URL`). websec stages these; it never runs them. Each item carries a "
           "confirm/disconfirm oracle so you know what a real hit looks like._\n"]
    for ph in phases:
        if not ph["items"]:
            continue
        out.append(f"### {ph['name']}")
        out.append(f"_Gate: {ph['gate']}._\n")
        for i, it in enumerate(ph["items"], 1):
            out.append(f"{i}. **{it['title']}** — `{it['target']}`  ")
            out.append(f"   tool: {it['tool']}  ")
            out.append(f"   ```\n   {it['command']}\n   ```")
            out.append(f"   _oracle:_ {it['oracle']}\n")
    return "\n".join(out)

"""`websec explain <attack-class>` — what a finding class means, offline.

A ledger entry names an attack class, cites a CWE and states a calibrated probability.
Acting on it still needs three things the entry does not carry: what the class actually
is, what would confirm or refute it in this codebase, and how much the number is worth.
Without that an agent either trusts every lead or none.

Everything here comes from data the package already ships — STANDARDS, REMEDIATION and
the calibration table — so there is no second source of truth to drift, and no network.
"""
from __future__ import annotations

import difflib
import re

from .findings import REMEDIATION, STANDARDS, _DEFAULT_REM

# What would settle it. Keyed by class where the generic line is not enough; the fallback
# is deliberately about *evidence*, since that is the step agents skip.
VERIFY = {
    "missing-auth": "Call the route with no credentials and with a valid non-owner identity. A 401 "
                    "for both is enforcement; a 200 for either is the finding. A changed status "
                    "alone proves nothing without a positive control that should succeed.",
    "bola": "Authenticate as user A, request user B's resource id. Success is the finding. Confirm "
            "the ids are genuinely distinct tenants, not two rows the same account owns.",
    "sqli": "Trace the parameter to the driver call. Concatenation or f-string into SQL is the "
            "finding; a parameterized placeholder is not, even when the value is attacker-controlled.",
    "command-injection": "Trace the argument to the exec call. shell=True with any request-derived "
                         "segment is the finding; an argument array is not.",
    "ssrf": "Confirm the URL is request-derived rather than a constant or template literal, and that "
            "the caller is server-side. A browser fetch is not SSRF.",
    "secret": "Confirm the value is live, not a placeholder or test fixture, then rotate it. A "
              "secret in git history stays exposed after deletion from the working tree.",
    "cve": "Confirm the vulnerable package is actually reachable from your entry points. An "
           "advisory on an unreachable transitive dependency is real but not urgent.",
}
_GENERIC_VERIFY = ("Read the cited file and confirm the dangerous operation is reachable from "
                   "attacker-controlled input. A framework name, a helper's name, a comment or a "
                   "safe sibling call does not prove the operation safe.")


def classes() -> list[str]:
    return sorted(STANDARDS)


def _calibration_for(attack_class: str) -> str:
    try:
        from . import calibration
        table = calibration.load()
        if not table:
            return "no calibration table available"
        cells = table.get("by_class_label", {})
        rows = {k.split("|", 1)[1]: v for k, v in cells.items()
                if k.split("|", 1)[0] == attack_class and isinstance(v, dict)}
        if not rows:
            return "no measured cell for this class — findings fall back to the label prior"
        parts = [f"{label} → p={v.get('p')} (n={v.get('n')})" for label, v in sorted(rows.items())]
        return "; ".join(parts)
    except Exception:
        return "calibration unavailable"


def describe(term: str) -> dict:
    """Resolve a class name or a CWE id. Never guesses between two matches."""
    key = (term or "").strip().lower()
    if not key:
        return {"ok": False, "error": "give an attack class or a CWE id, e.g. `websec explain bola`"}

    if key in STANDARDS:
        resolved = key
    elif re.fullmatch(r"cwe-\d+", key):
        hits = [c for c, (cwes, _a, _o) in STANDARDS.items()
                if any(w.lower().startswith(key) for w in cwes)]
        if not hits:
            return {"ok": False, "error": f"no shipped attack class cites {term.upper()}"}
        if len(hits) > 1:
            return {"ok": False, "error": f"{term.upper()} is cited by {len(hits)} classes: "
                                          f"{', '.join(sorted(hits))} — name one"}
        resolved = hits[0]
    else:
        near = difflib.get_close_matches(key, classes(), n=3, cutoff=0.6)
        hint = f" Did you mean: {', '.join(near)}?" if near else ""
        return {"ok": False, "error": f"unknown attack class {term!r}.{hint} "
                                      f"`websec capabilities` lists what this build detects."}

    cwe, asvs, api = STANDARDS[resolved]
    return {"ok": True, "attack_class": resolved,
            "cwe": list(cwe), "asvs": f"ASVS 4.0.3 {asvs[5:]}" if asvs.startswith("ASVS") else asvs,
            "owasp": list(api),
            "remediation": REMEDIATION.get(resolved, _DEFAULT_REM),
            "verify": VERIFY.get(resolved, _GENERIC_VERIFY),
            "calibration": _calibration_for(resolved)}


def render(info: dict) -> str:
    if not info.get("ok"):
        return f"error: {info.get('error', 'unknown')}"
    out = [f"{info['attack_class']}", ""]
    if info["cwe"]:
        out.append(f"  CWE:        {'; '.join(info['cwe'])}")
    if info["asvs"]:
        out.append(f"  ASVS:       {info['asvs']}")
    if info["owasp"]:
        out.append(f"  OWASP API:  {'; '.join(info['owasp'])}")
    out += ["", "  How to confirm or refute it:", f"    {info['verify']}",
            "", "  Remediation pattern:", f"    {info['remediation']}",
            "", f"  Calibration: {info['calibration']}",
            "  Severity, analyzer confidence and calibrated probability are separate signals;",
            "  an unknown truth label is not a false positive."]
    return "\n".join(out)

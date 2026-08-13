"""Calibrated confidence (CJE) — turn the rule-based HIGH/MEDIUM/LOW labels into
*measured* real-rates with honest confidence intervals.

WHAT THIS IS (honest scope): run the recon ledger against a labeled vuln-app corpus,
count how often each (attack_class, label) bucket actually corresponds to a real,
documented vulnerability, and express it as an observed rate + a **Wilson score
interval**. With a small corpus the INTERVAL is the headline — a wide CI means
"grounded, but not enough data to be sure yet." The numbers tighten as the corpus grows.

WHAT THIS IS NOT: calibrated on *deliberately-vulnerable* apps, so the rates skew
OPTIMISTIC for normal/clean code (real repos have a far lower base rate of true vulns).
Every per-finding estimate carries the sample size `n` and a `basis` so the consumer
can see how much to trust it; a finding that doesn't match a documented vuln is counted
as a false positive (the corpus is well-documented, so unlisted findings are noise).

No ML, no deps — binomial proportion + Wilson interval (stdlib `math`). The cell
structure upgrades cleanly to isotonic regression if a large labeled set ever exists.
"""

from __future__ import annotations

import json
import math
import os
from importlib import resources
from pathlib import Path

Z95 = 1.959963984540054   # z for a 95% two-sided interval
MIN_N = 5                 # a cell needs ≥ this many samples to be used (else fall back a tier)
# uncalibrated fallback prior — used ONLY when we have no data; always labeled as such
PRIOR = {"HIGH": 0.85, "MEDIUM": 0.5, "LOW": 0.25}
CAVEAT = ("indicative — calibrated on a deliberately-vulnerable app corpus; "
          "skews optimistic on clean production code")

# Self-improving LOCAL overlay: user-global, gitignored (lives outside any repo), never
# shipped. It accrues *confirmed* labels from your own dynamic runs (and optional hand-labels)
# and is merged on top of the shipped public table so the numbers personalize to YOUR apps.
LOCAL_PATH = Path(os.environ.get("WEBSEC_CALIBRATION_HOME",
                                 str(Path.home() / ".cache" / "websec-validator"))) / "calibration-local.json"


def wilson(k: int, n: int, z: float = Z95) -> tuple:
    """95% Wilson score interval for k successes in n trials → (lo, hi), clamped to [0,1].

    Wilson (not the normal approximation) because it stays sane at small n and extreme
    p — exactly our regime. n=0 → (0,1): maximal ignorance.
    """
    if n <= 0:
        return (0.0, 1.0)
    phat = k / n
    denom = 1 + z * z / n
    center = (phat + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(phat * (1 - phat) / n + z * z / (4 * n * n))
    return (max(0.0, center - half), min(1.0, center + half))


def _cell(k: int, n: int) -> dict:
    lo, hi = wilson(k, n)
    return {"n": n, "k": k, "p": round(k / n, 3) if n else None,
            "ci": [round(lo, 3), round(hi, 3)]}


def is_real(attack_class: str, location: str, truth: list) -> bool:
    """A finding is REAL iff it matches a documented truth entry, else a false positive.

    (Conservative rule, per design decision: on a well-documented vuln app, a finding
    that isn't on the known-vuln list is treated as noise.)
    """
    loc = (location or "").lower()
    for t in (truth or []):
        if t.get("class") != attack_class:
            continue
        sub = (t.get("location_contains") or "").lower()
        if not sub or sub == "*" or sub in loc:
            return True
    return False


def fit(labeled: list, corpus_names: list, researched_classes: set | None = None) -> dict:
    """labeled: list of {attack_class, confidence, is_real}. Returns the calibration table.

    `researched_classes`: classes for which the corpus has actual ground truth. Per-class
    cells are published ONLY for these — a class we never researched would otherwise emit a
    misleading p=0 (every finding auto-counted FP). Such findings still count as FP in the
    per-label aggregate (conservative), but at runtime fall back to that aggregate.
    """
    by_cl: dict = {}
    by_l: dict = {}
    for r in labeled:
        cl = f"{r['attack_class']}|{r['confidence']}"
        by_cl.setdefault(cl, [0, 0])
        by_l.setdefault(r["confidence"], [0, 0])
        by_cl[cl][1] += 1
        by_l[r["confidence"]][1] += 1
        if r["is_real"]:
            by_cl[cl][0] += 1
            by_l[r["confidence"]][0] += 1
    cells = {k: _cell(v[0], v[1]) for k, v in sorted(by_cl.items())}
    if researched_classes is not None:
        rc = set(researched_classes)
        cells = {k: c for k, c in cells.items() if k.split("|", 1)[0] in rc}
    return {
        "meta": {"corpus": corpus_names, "n_total": len(labeled),
                 "method": "binomial proportion + Wilson 95% CI", "min_n": MIN_N,
                 "unmatched_rule": "unmatched finding = false positive",
                 "researched_classes": sorted(researched_classes) if researched_classes is not None else None,
                 "caveat": CAVEAT},
        "by_class_label": cells,
        "by_label": {k: _cell(v[0], v[1]) for k, v in sorted(by_l.items())},
        "prior": PRIOR,
    }


def load_shipped() -> dict | None:
    """Load the shipped, public, corpus-based calibration.json (best-effort)."""
    try:
        p = resources.files("websec_validator").joinpath("calibration.json")
        return json.loads(p.read_text())
    except Exception:
        return None


def load_local() -> dict | None:
    """Load the user-global self-improving overlay (raw cell counts; best-effort)."""
    try:
        if LOCAL_PATH.is_file():
            return json.loads(LOCAL_PATH.read_text())
    except Exception:
        pass
    return None


def _merge(shipped: dict | None, local: dict | None) -> dict | None:
    """Combine the shipped table with the local overlay by SUMMING cell counts, then
    recomputing Wilson. Local samples are confirmed (oracle), so they're not filtered."""
    if not shipped and not local:
        return None
    base = json.loads(json.dumps(shipped)) if shipped else {"meta": {"caveat": CAVEAT},
                                                            "by_class_label": {}, "by_label": {}}
    base.setdefault("prior", PRIOR)
    base.setdefault("meta", {})
    if local:
        for grp in ("by_class_label", "by_label"):
            merged = dict(base.get(grp, {}))
            for key, lc in (local.get(grp, {}) or {}).items():
                sc = merged.get(key, {})
                merged[key] = _cell(sc.get("k", 0) + lc.get("k", 0), sc.get("n", 0) + lc.get("n", 0))
            base[grp] = merged
        ls = (local.get("meta", {}) or {}).get("samples", 0)
        base["meta"]["personalized"] = True
        base["meta"]["local_samples"] = ls
        base["meta"]["caveat"] = (base["meta"].get("caveat", CAVEAT)
                                  + f" · +{ls} confirmed local sample(s) folded in (personalized to your apps)")
    return base


def load() -> dict | None:
    """Merged calibration the runtime uses: shipped public table + your LOCAL self-improving overlay."""
    return _merge(load_shipped(), load_local())


def record_samples(labeled: list, runs: int = 1) -> dict | None:
    """Fold confirmed labeled samples into the LOCAL overlay (best-effort; user-global, gitignored).

    `labeled`: list of {attack_class, confidence, is_real}. Returns the updated overlay, or None
    if there was nothing to record / the write failed (never raises — calibration is non-critical).
    """
    if not labeled:
        return None
    try:
        local = load_local() or {"meta": {"source": "local self-improving overlay", "samples": 0, "runs": 0},
                                 "by_class_label": {}, "by_label": {}}
        for r in labeled:
            for grp, key in (("by_class_label", f"{r['attack_class']}|{r['confidence']}"),
                             ("by_label", r["confidence"])):
                cell = local.setdefault(grp, {}).setdefault(key, {"n": 0, "k": 0})
                cell["n"] += 1
                cell["k"] += 1 if r.get("is_real") else 0
        local["meta"]["samples"] = local["meta"].get("samples", 0) + len(labeled)
        local["meta"]["runs"] = local["meta"].get("runs", 0) + runs
        LOCAL_PATH.parent.mkdir(parents=True, exist_ok=True)
        LOCAL_PATH.write_text(json.dumps(local, indent=2) + "\n")
        return local
    except Exception:
        return None


def samples_from_dynamic(dynamic: dict) -> list:
    """Turn a dynamic run into confirmed calibration samples — dynamic is an ORACLE.

    Write-verb auth enforcement is unambiguous: a write that EXECUTED unauthenticated (or reached
    the handler past the auth gate) is a real missing-auth; one that's auth-enforced is a recon
    FALSE POSITIVE (recon flagged it, the live app actually blocks it). Cross-tenant LEAKs are
    confirmed BOLA. (Unauth GET reachability is excluded — a public endpoint reached without auth
    may be intended, so it's not a clean label.)
    """
    # NEVER learn from an untrustworthy run. dynamic.py computes fail_open_suspected (auth provider
    # not resolving → everything looks unauthenticated) and target_unreachable (nothing was contacted)
    # precisely to say "these results are meaningless" — the ledger already honors them, but this
    # oracle did not, and its samples are written to a PERSISTENT, CROSS-REPO overlay. One run against
    # a misconfigured test env would permanently inflate P(real) for missing-auth on every project.
    _wae = (dynamic or {}).get("write_auth_enforcement", {}) or {}
    _uar = (dynamic or {}).get("unauth_reachability", {}) or {}
    if (_wae.get("fail_open_suspected") or _uar.get("fail_open_suspected")
            or _wae.get("target_unreachable") or _uar.get("target_unreachable")):
        return []

    out = []
    for r in (((dynamic or {}).get("write_auth_enforcement", {}) or {}).get("results", []) or []):
        v = r.get("verdict", "")
        if v == "auth-enforced":
            out.append({"attack_class": "missing-auth", "confidence": "MEDIUM", "is_real": False})
        elif v == "EXECUTED-UNAUTH" or v.startswith("no-auth-gate"):
            out.append({"attack_class": "missing-auth", "confidence": "MEDIUM", "is_real": True})
    for _lk in (((dynamic or {}).get("cross_tenant_bola", {}) or {}).get("leaks", []) or []):
        out.append({"attack_class": "bola", "confidence": "MEDIUM", "is_real": True})
    return out


def apply(attack_class: str, confidence: str, table: dict | None) -> dict:
    """Attach a calibrated estimate for a finding's (attack_class, confidence) bucket.

    Three-tier graceful fallback: per-(class,label) if it has ≥ min_n samples, else
    per-label, else an explicitly-flagged uncalibrated prior. Always reports `n` + `basis`.
    """
    if table:
        min_n = table.get("meta", {}).get("min_n", MIN_N)
        caveat = table.get("meta", {}).get("caveat", CAVEAT)
        cl = table.get("by_class_label", {}).get(f"{attack_class}|{confidence}")
        if cl and cl["n"] >= min_n:
            return {"p": cl["p"], "ci": cl["ci"], "n": cl["n"], "basis": "class+label", "note": caveat}
        lab = table.get("by_label", {}).get(confidence)
        if lab and lab["n"] >= min_n:
            return {"p": lab["p"], "ci": lab["ci"], "n": lab["n"], "basis": "label", "note": caveat}
    prior = (table or {}).get("prior", PRIOR)
    return {"p": prior.get(confidence, 0.5), "ci": [0.0, 1.0], "n": 0,
            "basis": "prior (uncalibrated)", "note": "no calibration data for this bucket — uncalibrated prior"}

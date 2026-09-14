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
can see how much to trust it. Unmatched findings are unknown, never synthetic negatives.
The existing shipped table retains its original corpus caveat until explicitly rebuilt.

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


def is_real(attack_class: str, location: str, truth: list) -> bool | None:
    """Match explicit corpus ground truth; absence of a label means unknown.

    Entries default to positive documented vulnerabilities. Explicit ``is_real: false`` entries
    provide reviewed negative controls. Conflicting matching truth entries remain unknown.
    """
    outcomes = set()
    loc = (location or "").lower()
    for entry in truth or []:
        if entry.get("class") != attack_class:
            continue
        sub = (entry.get("location_contains") or "").lower()
        if not sub or sub == "*" or sub in loc:
            label = entry.get("is_real", True)
            if isinstance(label, bool):
                outcomes.add(label)
    return next(iter(outcomes)) if len(outcomes) == 1 else None


def fit(labeled: list, corpus_names: list, researched_classes: set | None = None) -> dict:
    """labeled: list of {attack_class, confidence, is_real}. Returns the calibration table.

    Unknown labels are excluded from every count, including per-label aggregates.
    ``researched_classes`` limits published class-specific cells to reviewed classes.
    """
    by_cl: dict = {}
    by_l: dict = {}
    unknown = sum(not isinstance(row.get("is_real"), bool) for row in labeled)
    for r in labeled:
        if not isinstance(r.get("is_real"), bool):
            continue
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
        "meta": {"corpus": corpus_names, "n_total": len(labeled) - unknown, "n_unknown": unknown,
                 "method": "binomial proportion + Wilson 95% CI", "min_n": MIN_N,
                 "unmatched_rule": "unmatched finding = unknown (excluded from calibration)",
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
        historical = json.loads(p.read_text())
        if historical.get("meta", {}).get("evidence_status") == "historical-unverified" or "= false positive" in historical.get("meta", {}).get("unmatched_rule", ""):
            return {"meta": {"n_total": 0, "historical_uncertain_samples": historical.get("meta", {}).get("n_total", 0),
                             "evidence_status": "historical-quarantined", "caveat": "Historical public corpus labels used unmatched=false and unpinned revisions; retained for audit, excluded from measured probabilities."},
                    "by_class_label": {}, "by_label": {}, "prior": PRIOR, "legacy_uncertain": historical}
        return historical
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
        local = _upgrade_local(local)
        for grp in ("by_class_label", "by_label"):
            merged = dict(base.get(grp, {}))
            for key, lc in (local.get(grp, {}) or {}).items():
                sc = merged.get(key, {})
                merged[key] = _cell(sc.get("k", 0) + lc.get("k", 0), sc.get("n", 0) + lc.get("n", 0))
            base[grp] = merged
        ls = (local.get("meta", {}) or {}).get("samples", 0)
        base["meta"]["personalized"] = bool(ls)
        base["meta"]["local_samples"] = ls
        legacy = local.get("legacy_uncertain", {}).get("meta", {}).get("samples", 0)
        base["meta"]["legacy_uncertain_samples"] = legacy
        base["meta"]["caveat"] = (base["meta"].get("caveat", CAVEAT)
                                  + f" · +{ls} evidence-backed local sample(s) folded in (personalized to your apps)"
                                  + (f" · {legacy} legacy sample(s) quarantined pending review" if legacy else ""))
    return base


def load() -> dict | None:
    """Merged calibration the runtime uses: shipped public table + your LOCAL self-improving overlay."""
    return _merge(load_shipped(), load_local())


def _upgrade_local(local: dict) -> dict:
    """Retain pre-evidence history for review, excluding it from measured probabilities."""
    local = json.loads(json.dumps(local))
    if local.get("schema_version") == 2:
        return local
    return {"schema_version": 2,
            "meta": {"source": "local evidence overlay", "samples": 0, "runs": 0},
            "by_class_label": {}, "by_label": {}, "observations": {},
            "legacy_uncertain": local}


def record_samples(labeled: list, runs: int = 1) -> dict | None:
    """Persist and deduplicate verified evidence; preserve weak historical labels for review.

    Reimporting the same build/fixture observation does not inflate confidence. Samples without
    explicit evidence and provenance remain in legacy_uncertain and never enter the active table.
    """
    if not labeled:
        return None
    try:
        local = _upgrade_local(load_local() or {})
        added = 0
        for row in labeled:
            verified = (row.get("evidence_verified") is True and row.get("sample_id")
                        and isinstance(row.get("provenance"), dict)
                        and isinstance(row.get("is_real"), bool))
            if not verified:
                archive = local.setdefault("legacy_uncertain", {})
                archive.setdefault("pending_review", []).append(row)
                meta = archive.setdefault("meta", {})
                meta["samples"] = meta.get("samples", 0) + 1
                continue
            observations = local.setdefault("observations", {})
            if row["sample_id"] in observations:
                continue
            observations[row["sample_id"]] = row
            for grp, key in (("by_class_label", f"{row['attack_class']}|{row['confidence']}"),
                             ("by_label", row["confidence"])):
                cell = local.setdefault(grp, {}).setdefault(key, {"n": 0, "k": 0})
                cell["n"] += 1
                cell["k"] += int(row["is_real"])
            added += 1
        local["meta"]["samples"] = local["meta"].get("samples", 0) + added
        local["meta"]["runs"] = local["meta"].get("runs", 0) + (runs if added else 0)
        LOCAL_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Atomic replacement avoids a truncated JSON overlay if the process is interrupted.
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", dir=LOCAL_PATH.parent, delete=False) as handle:
            temp = Path(handle.name)
            json.dump(local, handle, indent=2)
            handle.write("\n")
        try:
            temp.replace(LOCAL_PATH)
        finally:
            temp.unlink(missing_ok=True)
        return local
    except Exception:
        return None


def samples_from_dynamic(dynamic: dict) -> list:
    """Learn only from verified, build-bound controls; HTTP status observations are not labels."""
    sections = [((dynamic or {}).get(key) or {}) for key in
                ("write_auth_enforcement", "unauth_reachability", "cross_tenant_bola")]
    if any(s.get("fail_open_suspected") or s.get("target_unreachable") for s in sections):
        return []
    out = []
    # Current write probes only observe statuses, so they intentionally cannot label missing-auth.
    for row in sections[2].get("leaks", []) or []:
        if (row.get("state") == "confirmed-vulnerable" and row.get("evidence_verified") is True
                and row.get("sample_id") and row.get("provenance")
                and all(row.get("controls", {}).get(key) is True for key in ("identity", "owner", "private"))):
            out.append({"attack_class": "bola", "confidence": "MEDIUM", "is_real": True,
                        "sample_id": row["sample_id"], "provenance": row["provenance"],
                        "evidence_verified": True})
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

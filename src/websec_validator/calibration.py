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

import hashlib
import json
import math
import os
from importlib import resources
from pathlib import Path

Z95 = 1.959963984540054   # z for a 95% two-sided interval
MIN_N = 5                 # a cell needs ≥ this many samples to be used (else fall back a tier)
# uncalibrated fallback prior — used ONLY when we have no data; always labeled as such
PRIOR = {"HIGH": 0.85, "MEDIUM": 0.5, "LOW": 0.25}

# DESIGN CONSTRAINT — read this before fitting anything from labels.
# Any quantity derived from labeled outcomes (a bucket probability, a cut-off, a threshold default)
# must be chosen by a STRICTLY PROPER SCORING RULE — Brier or log score — never by accuracy,
# precision, recall or F1. A strictly proper rule is maximized only by honest probabilities;
# accuracy-shaped objectives are maximized by a confidently-wrong estimator, which is precisely the
# failure this module exists to prevent. Report those other metrics if useful; never optimize them.
# `brier()` below exists so the honest metric is available at the moment the temptation arises.
SCORING_RULE = "strictly proper (Brier / log score) — never accuracy, precision, recall or F1"
CAVEAT = ("indicative — calibrated on a deliberately-vulnerable app corpus; "
          "skews optimistic on clean production code")
# Used when NO shipped corpus table is present and the numbers come only from the operator's own
# confirmed runs. CAVEAT must not be reused here: it asserts corpus provenance this data does not
# have, and its specific bias direction ("optimistic on clean production code") describes the
# vulnerable-app corpus, not local samples. Claiming the wrong provenance is worse than claiming
# none, so the local-only path gets its own honest label.
LOCAL_ONLY_CAVEAT = ("indicative — no shipped corpus table was available; these numbers come only "
                     "from your own confirmed local samples and carry no corpus baseline")

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


def brier(labeled: list, table: dict) -> dict | None:
    """Mean Brier score of `table`'s predictions against the labels that produced them.

    Brier = mean((p - outcome)^2), lower is better; 0.25 is what a constant 0.5 scores. It is a
    STRICTLY PROPER rule (see SCORING_RULE): it is minimized only by honest probabilities, so
    unlike accuracy it cannot be improved by becoming more confident than the evidence warrants.

    Reported, never optimized against — nothing in the runtime reads this. It exists so the honest
    number is already on screen if anyone later reaches for a threshold to tune. Rows whose bucket
    has no measured cell fall back through `apply()` exactly as a real finding would, so the score
    describes the estimates the tool would actually have emitted, priors included.
    """
    rows = [r for r in (labeled or []) if isinstance(r.get("is_real"), bool)]
    if not rows:
        return None
    total = 0.0
    for row in rows:
        est = apply(row.get("attack_class", ""), row.get("confidence", ""), table)
        p = est["p"] if isinstance(est.get("p"), (int, float)) else 0.5
        total += (p - float(row["is_real"])) ** 2
    return {"brier": round(total / len(rows), 4), "n": len(rows),
            "reference": {"always_0.5": 0.25},
            "rule": SCORING_RULE,
            "note": "reported for honesty; no runtime behavior depends on it"}


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


REVIEWED_STATUS = "reviewed"


def reviewed_classes(corpus: list) -> set:
    """Attack classes with at least one REVIEWED truth entry — the only ones eligible for a
    class-specific published cell.

    A truth entry qualifies when `review_status` is "reviewed" AND `is_real` is an explicit
    boolean. The historical entries are neither: they are class-level wildcards
    (`location_contains: "*"`, `is_real: null`) that cannot separate a real vulnerability from a
    false positive inside the same class, so a cell fitted from them would assert a precision the
    labels never established. Those classes fall back to the per-label tier, which is wider and
    honest. Relabelling requires cloning the pinned revision and reviewing each finding by hand;
    there is deliberately no code path that promotes an unreviewed entry.
    """
    out = set()
    for entry in corpus or []:
        for truth in entry.get("truth") or []:
            if truth.get("review_status") == REVIEWED_STATUS and isinstance(truth.get("is_real"), bool):
                if truth.get("class"):
                    out.add(truth["class"])
    return out


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
    base = (json.loads(json.dumps(shipped)) if shipped
            else {"meta": {"caveat": LOCAL_ONLY_CAVEAT, "corpus": [], "shipped_table": False},
                  "by_class_label": {}, "by_label": {}})
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
        # Only CLAIM personalization when something was actually folded in. Merely having a local
        # overlay file — which queuing a pending feedback candidate creates — is not personalization,
        # and "+0 samples folded in (personalized to your apps)" is a false statement about the number.
        base["meta"]["caveat"] = (base["meta"].get("caveat", CAVEAT)
                                  + (f" · +{ls} evidence-backed local sample(s) folded in "
                                     "(personalized to your apps)" if ls else "")
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
        _write_local(local)
        return local
    except Exception:
        return None


# ---- operator feedback → CANDIDATE labels (never a measured probability without human review) ----
# An operator reporting a false positive is evidence, not proof. `record_samples` already refuses
# anything without evidence_verified/sample_id/provenance, and that bar must not be lowered: a wrong
# label lowers P(real) for that bucket on every future run of every project, permanently
# (bug-212 poisoned the overlay exactly this way). So a report becomes a CANDIDATE — visible,
# counted, reviewable — and only an explicit human acceptance promotes it into a cell.
CANDIDATE_KEY = "feedback_candidates"


def _candidate_id(record: dict) -> str:
    """Stable identity for a report: the finding + the detector that produced it.

    Includes detector_revision deliberately. The same finding reported against a different detector
    build is a different claim, because the rule that produced it may no longer exist.
    """
    finding = record.get("finding") or {}
    basis = "|".join([str(finding.get("fingerprint", "")), str(record.get("verdict", "")),
                      str(record.get("detector_revision", ""))])
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


def record_candidate(record: dict, *, detector_revision: str = "",
                     analyzed_input_digest: str = "") -> dict | None:
    """Store an operator feedback record as a pending candidate. Changes no probability.

    Returns the stored candidate (with its `candidate_id`), or None when the record is not a
    labelling claim about an existing finding. Re-reporting the same finding does not duplicate.
    """
    if not isinstance(record, dict):
        return None
    verdict = record.get("verdict")
    # Only false-positive is a LABEL (is_real=False). `severity-wrong` disputes the severity, not
    # the existence, and `false-negative` describes a finding that was never produced, so neither
    # can be scored against a bucket — storing them as labels would fabricate an outcome.
    if verdict != "false-positive":
        return None
    finding = record.get("finding") or {}
    attack_class, confidence = finding.get("attack_class"), finding.get("confidence")
    if not attack_class or confidence not in PRIOR:
        return None
    try:
        local = _upgrade_local(load_local() or {})
        enriched = dict(record)
        if detector_revision:
            enriched["detector_revision"] = detector_revision
        if analyzed_input_digest:
            enriched["analyzed_input_digest"] = analyzed_input_digest
        candidate_id = _candidate_id(enriched)
        pending = local.setdefault(CANDIDATE_KEY, {})
        if candidate_id in pending:
            return pending[candidate_id]
        pending[candidate_id] = {
            "candidate_id": candidate_id, "state": "pending",
            "attack_class": attack_class, "confidence": confidence,
            "is_real": False,                      # the claim under review, not yet counted
            "reason": record.get("reason", ""), "recorded": record.get("recorded", ""),
            "fingerprint": finding.get("fingerprint", ""),
            "detector_revision": enriched.get("detector_revision", ""),
            "analyzed_input_digest": enriched.get("analyzed_input_digest", ""),
            "tool_version": record.get("tool_version", ""),
        }
        _write_local(local)
        return pending[candidate_id]
    except Exception:
        return None


def candidates(current_revision: str = "") -> list:
    """Pending candidates, newest first, each marked `stale` when its detector no longer exists."""
    local = _upgrade_local(load_local() or {})
    rows = []
    for row in (local.get(CANDIDATE_KEY, {}) or {}).values():
        row = dict(row)
        row["stale"] = bool(current_revision and row.get("detector_revision")
                            and row["detector_revision"] != current_revision)
        rows.append(row)
    return sorted(rows, key=lambda r: r.get("recorded", ""), reverse=True)


def review_candidate(candidate_id: str, *, accept: bool, reason: str = "",
                     current_revision: str = "") -> dict:
    """Promote or discard one candidate. Acceptance requires a human reason and a live detector.

    Returns {"ok": bool, "error": str, "candidate": dict}. Acceptance is the ONLY path from an
    operator's opinion into a measured cell, and it goes through `record_samples`, so the evidence
    bar (`evidence_verified` + `sample_id` + `provenance`) is enforced by the same code that
    enforces it for dynamic-confirmed samples — there is no second, weaker door.
    """
    local = _upgrade_local(load_local() or {})
    pending = local.get(CANDIDATE_KEY, {}) or {}
    row = pending.get(candidate_id)
    if not row:
        return {"ok": False, "error": f"no pending candidate {candidate_id!r}", "candidate": None}
    if not accept:
        del pending[candidate_id]
        _write_local(local)
        return {"ok": True, "error": "", "candidate": dict(row, state="rejected")}
    if not (reason or "").strip():
        return {"ok": False, "error": "accepting a candidate requires --reason: a label with no "
                                      "reviewer rationale is an assertion, not evidence",
                "candidate": row}
    if current_revision and row.get("detector_revision") and row["detector_revision"] != current_revision:
        return {"ok": False, "error": "candidate is STALE: it was reported against detector "
                                      f"{row['detector_revision'][:19]}… but this build is "
                                      f"{current_revision[:19]}…. The rule that produced it may no "
                                      "longer exist; re-run the scan and re-report.",
                "candidate": row}
    del pending[candidate_id]
    _write_local(local)
    sample = {"attack_class": row["attack_class"], "confidence": row["confidence"],
              "is_real": False, "sample_id": f"feedback:{candidate_id}",
              "evidence_verified": True,
              "provenance": {"kind": "operator-review", "reviewer_reason": reason.strip(),
                             "reported_reason": row.get("reason", ""),
                             "detector_revision": row.get("detector_revision", ""),
                             "analyzed_input_digest": row.get("analyzed_input_digest", ""),
                             "fingerprint": row.get("fingerprint", "")}}
    record_samples([sample])
    return {"ok": True, "error": "", "candidate": dict(row, state="accepted")}


def _write_local(local: dict) -> None:
    """Atomic overwrite of the overlay; a truncated JSON file would lose every measured cell."""
    import tempfile
    LOCAL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", dir=LOCAL_PATH.parent, delete=False) as handle:
        temp = Path(handle.name)
        json.dump(local, handle, indent=2)
        handle.write("\n")
    try:
        temp.replace(LOCAL_PATH)
    finally:
        temp.unlink(missing_ok=True)


# ---- authored-pair precision: measured, published, and NEVER merged into the real table ----
# The repository's paired fixtures (a vulnerable variant that must fire, a sanitized twin that must
# not) are reviewed, reproducible labels — the strongest ones on disk. But they measure precision on
# cases the rule author ALREADY ANTICIPATED, which is not the field base rate: it skews optimistic
# in the same direction, and for a related reason, as the deliberately-vulnerable corpus. So they get
# their own file, their own basis and their own caveat. `apply()` never reads this table; summing it
# into `by_class_label` would launder authored coverage into a claim about real code.
SYNTHETIC_PATH = LOCAL_PATH.parent / "calibration-synthetic.json"
SYNTHETIC_CAVEAT = ("authored paired fixtures — measures REGRESSION precision on cases the detector "
                    "was written to handle, not the rate in real code. Never merged into P(real).")


def fit_synthetic(pairs: list) -> dict:
    """Fit a separate table from authored pairs.

    `pairs`: [{attack_class, confidence, is_real, sample_id}] where is_real is True for a variant
    that SHOULD fire and False for its sanitized control. Same cell shape as the real table, so the
    numbers are comparable by eye — but carried in a different file under a different basis.
    """
    by_cl: dict = {}
    by_l: dict = {}
    for row in pairs or []:
        if not isinstance(row.get("is_real"), bool):
            continue
        for group, key in ((by_cl, f"{row['attack_class']}|{row['confidence']}"),
                           (by_l, row["confidence"])):
            cell = group.setdefault(key, [0, 0])
            cell[1] += 1
            cell[0] += int(row["is_real"])
    return {"meta": {"basis": "synthetic-paired", "n_total": len(pairs or []),
                     "method": "binomial proportion + Wilson 95% CI", "min_n": MIN_N,
                     "caveat": SYNTHETIC_CAVEAT,
                     "never_merged": "apply() does not read this table; it is reported beside the "
                                     "measured one, never summed into it"},
            "by_class_label": {k: _cell(v[0], v[1]) for k, v in sorted(by_cl.items())},
            "by_label": {k: _cell(v[0], v[1]) for k, v in sorted(by_l.items())}}


def write_synthetic(table: dict) -> Path:
    SYNTHETIC_PATH.parent.mkdir(parents=True, exist_ok=True)
    SYNTHETIC_PATH.write_text(json.dumps(table, indent=2) + "\n")
    return SYNTHETIC_PATH


def load_synthetic() -> dict | None:
    try:
        if SYNTHETIC_PATH.is_file():
            return json.loads(SYNTHETIC_PATH.read_text())
    except Exception:
        pass
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


# ---- claimspec `calibration` writer (additive: the internal table shape above is unchanged) ----
# claimspec is the Guard-family shared spec (testguard `spec/`). Its `calibration` kind carries the
# same honesty fields this table does — corpus, caveat, limitation, evidence status, min-n floor,
# backoff tier and a labelled fallback — under different names. This writer is the translation.
CLAIMSPEC_SCHEMA_VERSION = 1
CLAIMSPEC_MEASURES = "finding-real"            # P(a reported finding of this class is a real vulnerability)
CLAIMSPEC_BUCKET_BY = "attackClass|confidence"  # `by_class_label` keys are `class|LABEL`
CLAIMSPEC_BACKOFF_BY = "confidence"             # `by_label` keys are `LABEL`
CLAIMSPEC_CONFIDENCE = 0.95                     # Z95 above is the exact quantile for this level
_EVIDENCE_STATUS = {"historical-unverified": "unverified", "historical-quarantined": "quarantined"}
# meta keys that are websec provenance with no claimspec field; they travel in `source.detail`.
_DETAIL_KEYS = ("n_total", "n_unknown", "unmatched_rule", "researched_classes", "personalized",
                "local_samples", "legacy_uncertain_samples", "historical_uncertain_samples",
                "shipped_table", "method")


def _claimspec_cell(key: str, cell: dict) -> dict:
    """Translate one `{n, k, p, ci}` cell to `{n, positives, p, ci}`, refusing one that does not
    reproduce from its own counts.

    The stored `p`/`ci` are passed through, not recomputed: they are the numbers `apply()` actually
    attaches to findings, and an exported document must not quote a different one. The validator
    recomputes both from `positives`/`n` at the document's own precision, so a stale hand-edited
    cell would make the whole document non-conforming — better to refuse here and name the cell.
    Precision note: `_cell` uses Python `round()` (round-half-even on the binary value) where the
    JS validator uses `toFixed` (round-half-away); an exact tie at 3 dp is effectively impossible
    for a Wilson bound, so the two agree in practice.
    """
    n, k = int(cell.get("n", 0)), int(cell.get("k", 0))
    if k > n or n < 0:
        raise ValueError(f"calibration cell {key!r} has {k} positives in {n} trials")
    expected = _cell(k, n)
    got = {"p": cell.get("p"), "ci": list(cell.get("ci", []))}
    if got["p"] != expected["p"] or got["ci"] != expected["ci"]:
        raise ValueError(f"calibration cell {key!r} does not reproduce from its counts "
                         f"({k}/{n}): stored p={got['p']} ci={got['ci']}, "
                         f"expected p={expected['p']} ci={expected['ci']}")
    return {"n": n, "positives": k, "p": got["p"], "ci": got["ci"]}


def to_claimspec(table: dict, computed_at: str | None = None) -> dict:
    """Render an internal calibration table (shipped, local-only or merged, i.e. anything `load()`
    returns) as a claimspec v1 `calibration` document.

    Field mapping is fixed by the spec's own reference translation of the shipped table
    (`spec/conformance/examples/calibration-websec.json` in testguard). `source.kind` says where
    the labels came from: `human-label` for the shipped corpus table, `tool-oracle` when only the
    operator's confirmed local samples exist, `mixed` once local samples are folded over shipped.
    `source.caveat` is always written — a number quoted without it is a misquote.
    """
    from datetime import datetime, timezone
    from . import __version__

    meta = table.get("meta", {}) or {}
    if meta.get("shipped_table") is False:
        kind, ref = "tool-oracle", "calibration-local.json (operator overlay; no shipped table)"
    elif meta.get("personalized"):
        kind, ref = "mixed", "shipped calibration.json + operator overlay calibration-local.json"
    else:
        kind, ref = "human-label", "src/websec_validator/calibration.json, shipped in the package"
    source: dict = {"kind": kind, "ref": ref}
    if meta.get("corpus"):
        source["corpus"] = list(meta["corpus"])
    source["caveat"] = meta.get("caveat") or CAVEAT
    if meta.get("limitation"):
        source["limitation"] = meta["limitation"]
    source["evidenceStatus"] = _EVIDENCE_STATUS.get(meta.get("evidence_status"), "verified")
    detail = {key: meta[key] for key in _DETAIL_KEYS if meta.get(key) is not None}
    if detail:
        source["detail"] = detail

    if computed_at is None:
        computed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return {
        "schemaVersion": CLAIMSPEC_SCHEMA_VERSION,
        "tool": {"name": "websec-validator", "version": __version__},
        "computedAt": computed_at,
        "method": "wilson",
        "confidence": CLAIMSPEC_CONFIDENCE,
        "measures": CLAIMSPEC_MEASURES,
        "bucketBy": CLAIMSPEC_BUCKET_BY,
        "minN": int(meta.get("min_n", MIN_N)),
        "source": source,
        "buckets": {key: _claimspec_cell(key, cell)
                    for key, cell in sorted((table.get("by_class_label") or {}).items())},
        "backoff": [{"bucketBy": CLAIMSPEC_BACKOFF_BY,
                     "buckets": {key: _claimspec_cell(key, cell)
                                 for key, cell in sorted((table.get("by_label") or {}).items())}}],
        "fallback": {"basis": "uncalibrated-prior", "values": dict(table.get("prior") or PRIOR)},
    }


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

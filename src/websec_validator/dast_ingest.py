"""Close the loop with a REAL dynamic scan — feed a ZAP/DAST report back to calibrate the static side.

websec's own dynamic phase already closes the calibration loop (calibration.samples_from_dynamic). But
most teams run an external scanner (OWASP ZAP, Nuclei) in CI, not websec's probes. This module lets that
existing scan close the loop instead:

    1. websec §4b PREDICTED which scanner alert classes its static findings would produce.
    2. You run ZAP/Nuclei against the deployed app and export a JSON report.
    3. `websec calibrate --ingest-dast report.json --ledger findings-ledger.json` matches the report
       back to the ledger and derives CONFIRMED labels:
         • a predicted class the scanner DID raise → the static finding was REAL (is_real=True)
         • a predicted class the scanner is CAPABLE of raising but did NOT → likely a FALSE POSITIVE /
           already-mitigated (is_real=False)
       Only DAST-findable classes (in dast_predict._DAST_MAP) are labelled — a scanner's silence on a
       blind-spot class (BOLA, mass-assignment…) means NOTHING and must never be scored as an FP.

The label feeds calibration.record_samples, so every real scan you already run makes websec's static
P(real) sharper and personalized to your app — the compounding advantage no static-only tool has.

Deterministic parsing (ZAP JSON + a generic {alerts:[…]} shape). Stdlib only; no network.
"""

from __future__ import annotations

from . import dast_predict

# ZAP pluginid → the websec class(es) it can confirm. Inverted from dast_predict._DAST_MAP's alert_id
# field, which may bundle several ids ("10038 / 10055" → both mean missing-csp).
#
# The value is a SET, not a single class, because one plugin id legitimately confirms MORE than one
# static class: ZAP 90020 ("Remote OS Command Injection") is the dynamic signature of BOTH
# `command-injection` and `eval-injection` — user input reaching an exec sink. A plain dict inversion
# silently dropped whichever class was declared first, making it permanently un-ingestible (caught by
# test_every_predictable_class_is_ingestible).
def _alertid_to_class() -> dict:
    m: dict = {}
    for cls, (_scanner, _alert, aid, _why) in dast_predict._DAST_MAP.items():
        for part in str(aid).replace(",", "/").split("/"):
            part = part.strip()
            if part and part.isdigit():
                m.setdefault(part, set()).add(cls)
    return m


def _is_active(attack_class: str) -> bool:
    """True if this class needs an ACTIVE scan (payload injection) rather than passive observation.

    Derived from the scanner label in dast_predict._DAST_MAP ("ZAP (passive)" vs "ZAP (active)"), so
    the two modules can't drift. Passive classes (missing headers, cookie flags) are raised by simply
    loading a page; active classes (SQLi, XSS, SSRF, cmd-injection) require the scanner to fuzz."""
    entry = dast_predict._DAST_MAP.get(attack_class)
    if not entry:
        return False
    return "passive" not in str(entry[0]).lower()


def parse_report(data) -> dict:
    """→ {plugin_ids: set[str], names: set[str]} of alerts the scanner ACTUALLY raised.

    Accepts the ZAP JSON shape (`{site:[{alerts:[{pluginid, alert}]}]}`) and a generic
    (`{alerts:[{pluginid|id, name|alert}]}`) / SARIF-lite (`{runs:[{results:[{ruleId}]}]}`)."""
    plugin_ids: set = set()
    names: set = set()

    def _add(pid, nm):
        if pid is not None and str(pid).strip():
            plugin_ids.add(str(pid).strip())
        if nm:
            names.add(str(nm).strip().lower())

    if isinstance(data, dict) and data.get("site"):                    # ZAP
        for site in data.get("site") or []:
            for a in (site or {}).get("alerts", []) or []:
                _add(a.get("pluginid"), a.get("alert") or a.get("name"))
    if isinstance(data, dict) and data.get("alerts"):                  # generic
        for a in data.get("alerts") or []:
            _add(a.get("pluginid") or a.get("id"), a.get("name") or a.get("alert"))
    if isinstance(data, dict) and data.get("runs"):                    # SARIF (nuclei -sarif etc.)
        # SARIF ruleIds aren't ZAP plugin ids, so they can't match by id — capture them as names only
        # (id-based class matching just won't fire for a SARIF report; that's honest, not a bug).
        for run in data.get("runs") or []:
            for r in (run or {}).get("results", []) or []:
                _add(None, r.get("ruleId"))
    return {"plugin_ids": plugin_ids, "names": names}


def derive_labels(ledger: dict, report: dict) -> dict:
    """Match the ledger's predictable findings against the scan → confirmed calibration labels.

    Returns {labels:[{attack_class,confidence,is_real}], confirmed:[…], refuted:[…], skipped_blind:int}.
    """
    seen = parse_report(report)
    raised_ids = seen["plugin_ids"]
    id2class = _alertid_to_class()
    # classes the scan actually confirmed (any of that class's ZAP ids appeared). One id can map to
    # several classes (e.g. 90020 → command-injection AND eval-injection), so union the sets.
    confirmed_classes: set = set()
    for i in raised_ids:
        confirmed_classes |= id2class.get(i, set())

    # CAN this report refute anything? Silence only means "not vulnerable" if the scan actually ran
    # the relevant rules. A ZAP *baseline* (passive-only) scan — the most common CI configuration —
    # structurally cannot raise SQLi/XSS/SSRF, and an empty or failed report raises nothing at all.
    # Treating that silence as proof marked every active-class finding a FALSE POSITIVE and wrote it
    # to the PERMANENT cross-repo overlay. Require positive evidence instead: at least one ACTIVE
    # alert in the report proves active rules ran.
    active_ran = any(_is_active(c) for c in confirmed_classes)
    can_refute_passive = bool(raised_ids)          # any alert at all proves the scan reached the app

    labels, confirmed, refuted, unjudged = [], [], [], []
    skipped_blind = 0
    for f in (ledger or {}).get("findings", []) or []:
        ac = str(f.get("attack_class", "")).lower()
        conf = f.get("confidence", "MEDIUM")
        if ac not in dast_predict._DAST_MAP:
            # not DAST-findable (blind spot or non-web) → a scan can neither confirm nor refute it
            if ac in dast_predict._BLIND_SPOTS:
                skipped_blind += 1
            continue
        row = {"attack_class": ac, "location": f.get("location", ""), "confidence": conf}
        if ac in confirmed_classes:
            labels.append({"attack_class": ac, "confidence": conf, "is_real": True})
            confirmed.append(row)
            continue
        # not raised — only score it a false positive if this scan COULD have raised it
        provable = active_ran if _is_active(ac) else can_refute_passive
        if provable:
            labels.append({"attack_class": ac, "confidence": conf, "is_real": False})
            refuted.append(row)
        else:
            row["why"] = ("this scan shows no evidence it ran "
                          + ("active" if _is_active(ac) else "any")
                          + " rules for this class — silence is not proof")
            unjudged.append(row)
    return {"labels": labels, "confirmed": confirmed, "refuted": refuted,
            "unjudged": unjudged, "skipped_blind": skipped_blind,
            "active_rules_evidenced": active_ran,
            "scan_alert_classes": sorted(confirmed_classes)}

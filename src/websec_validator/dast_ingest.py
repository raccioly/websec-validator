"""Offline, evidence-bound DAST correlation. Scanner silence is never ground truth."""

from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit

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


def _rows(value):
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def _context(parent: dict, row: dict) -> dict:
    context = dict(parent)
    envelope = row.get("dast_context")
    allowed = ("application_id", "build_id", "identity", "endpoint", "method", "parameter", "origin", "auth_verified")
    if isinstance(envelope, dict):
        context.update({key: envelope[key] for key in allowed if key in envelope})
    for key in ("application_id", "build_id", "identity", "endpoint", "method", "parameter", "auth_verified"):
        if key in row:
            context[key] = row[key]
    url = row.get("uri") or row.get("url")
    if url:
        try:
            parsed = urlsplit(str(url))
        except ValueError:
            context.pop("endpoint", None)
            return context
        context["endpoint"] = parsed.path or "/"
        # An explicit application id binds deployment identity; URL origin is checked separately.
        if parsed.netloc:
            context["origin"] = f"{parsed.scheme}://{parsed.netloc.rsplit('@', 1)[-1]}"
    if "param" in row:
        context["parameter"] = row["param"]
    if isinstance(context.get("endpoint"), str):
        context["endpoint"] = context["endpoint"].split("?", 1)[0].split("#", 1)[0]
    if context.get("method"):
        context["method"] = str(context["method"]).upper()
    return context


def parse_report(data) -> dict:
    """Preserve scanner occurrences; class-level summaries alone are supporting evidence.

    ZAP instances and generic alerts accept an explicit ``dast_context`` envelope with
    application_id, build_id and identity. SARIF names remain informational. Negative evidence
    is supplied separately as ``checks`` with exact context and successful coverage assertions.
    """
    data = data if isinstance(data, dict) else {}
    context = _context({}, data)
    plugin_ids, names, occurrences = set(), set(), []

    def add(alert, parent):
        pid = alert.get("pluginid", alert.get("id"))
        pid = str(pid).strip() if pid is not None else ""
        name = alert.get("alert") or alert.get("name")
        if pid:
            plugin_ids.add(pid)
        if name:
            names.add(str(name).strip().lower())
        base = _context(parent, alert)
        for instance in _rows(alert.get("instances")) or [alert]:
            occurrences.append({"plugin_id": pid, "context": _context(base, instance),
                                "attack_class": alert.get("attack_class")})

    for site in _rows(data.get("site")):
        for alert in _rows(site.get("alerts")):
            add(alert, _context(context, site))
    for alert in _rows(data.get("alerts")):
        add(alert, context)
    for run in _rows(data.get("runs")):
        for result in _rows(run.get("results")):
            if result.get("ruleId"):
                names.add(str(result["ruleId"]).strip().lower())
    return {"plugin_ids": plugin_ids, "names": names, "occurrences": occurrences,
            "checks": [{**check, "context": _context(context, check)}
                       for check in _rows(data.get("checks"))]}


def _matches(expected: dict, actual: dict) -> bool:
    # Empty parameter explicitly means no parameter (e.g. passive header checks).
    required = ("application_id", "build_id", "identity", "endpoint", "method", "parameter")
    if any(not isinstance(expected.get(key), str) or not isinstance(actual.get(key), str) for key in required):
        return False
    if any(not expected[key] for key in required if key != "parameter"):
        return False
    if actual.get("auth_verified") is False or (expected["identity"] != "anonymous" and actual.get("auth_verified") is not True):
        return False
    return (all(expected[key] == actual[key] for key in required)
            and ("origin" not in expected or expected["origin"] == actual.get("origin")))


def derive_labels(ledger: dict, report: dict) -> dict:
    """Judge only exact, build-bound observations; unrelated alerts never refute findings.

    Findings provide ``dast_context`` (inheriting the ledger envelope). Completed negative
    checks must additionally assert coverage_complete and auth_verified, name the attack_class
    and pluginid, and state outcome=not-vulnerable. Ordinary scanner silence stays unjudged.
    """
    seen = parse_report(report)
    id2class = _alertid_to_class()
    classes = set().union(*(id2class.get(pid, set()) for pid in seen["plugin_ids"]))
    labels, confirmed, refuted, unjudged = [], [], [], []
    skipped_blind = 0
    for finding in _rows((ledger or {}).get("findings")):
        ac = str(finding.get("attack_class", "")).lower()
        if ac not in dast_predict._DAST_MAP:
            skipped_blind += int(ac in dast_predict._BLIND_SPOTS)
            continue
        context = _context(_context({}, ledger or {}), finding)
        row = {"attack_class": ac, "location": finding.get("location", ""),
               "confidence": finding.get("confidence", "MEDIUM")}
        positive = [o for o in seen["occurrences"] if ac in id2class.get(o["plugin_id"], set())
                    and _matches(context, o["context"])
                    and (not o["attack_class"] or o["attack_class"] == ac)
                    and (len(id2class[o["plugin_id"]]) == 1 or o["attack_class"] == ac)]
        negative = [c for c in seen["checks"] if c.get("attack_class") == ac
                    and ac in id2class.get(str(c.get("pluginid", "")), set())
                    and _matches(context, c["context"])
                    and c.get("completed") is True and c.get("coverage_complete") is True
                    and c.get("auth_verified") is True and c.get("outcome") == "not-vulnerable"]
        if positive and negative:
            row["why"] = "conflicting positive and negative evidence for the same check"
            unjudged.append(row)
        elif positive or negative:
            real = bool(positive)
            proof = positive[0] if real else negative[0]
            provenance = {**context, "source": "dast", "attack_class": ac,
                          "plugin_id": proof.get("plugin_id", str(proof.get("pluginid", ""))),
                          "is_real": real}
            sample_id = hashlib.sha256(json.dumps(provenance, sort_keys=True).encode()).hexdigest()
            labels.append({"attack_class": ac, "confidence": row["confidence"], "is_real": real,
                           "evidence_verified": True, "sample_id": sample_id, "provenance": provenance})
            (confirmed if real else refuted).append(row)
        else:
            row["why"] = "no exact application/build/identity/endpoint/method/parameter evidence; silence is not proof"
            unjudged.append(row)
    return {"labels": labels, "confirmed": confirmed, "refuted": refuted,
            "unjudged": unjudged, "skipped_blind": skipped_blind,
            "active_rules_evidenced": any(_is_active(c) for c in classes),
            "scan_alert_classes": sorted(classes)}

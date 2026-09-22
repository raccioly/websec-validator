"""Finding clustering — one ISSUE with N sites, instead of N findings that look like N issues.

A well-managed repo reads as alarming when the report lists 39 HIGHs that are really about six
things: 13 sites of one `jwtSecret` pattern, 22 blobs from one deleted-file incident, and four
others (field report #4). The count is arithmetically right and communicatively wrong — the reader
has no way to see that thirteen rows share a single fix.

**This module is PRESENTATION ONLY, by deliberate design.** It does not touch `findings[]`,
`total`, `by_severity`, the per-site fingerprints, the `--fail-on` count, SARIF results, or the
baseline. Every one of those is a contract something else already depends on: a stored baseline
holds per-site fingerprints, `websec feedback` addresses one site, and GitHub Code Scanning wants
one SARIF result per location so it can annotate the right line. Collapsing findings[] would have
broken all four to improve a Markdown table. So clusters are a SIBLING view — `clusters[]` next to
`findings[]` — and the numbers they summarise stay exactly where they were.

Two grouping dimensions, because the two complaints have different shapes:

  * **rule**     — the same detector firing at N sites. One pattern, one fix, N places to apply it.
  * **incident** — secrets that left the working tree in the SAME commit. Not "22 problems": one
                   person deleted one set of files once, and every blob is still fetchable. The
                   remediation is a single act (rotate + purge), not twenty-two.
"""

from __future__ import annotations

import hashlib

SEV_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
CONF_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
# Below this a "cluster" is just a finding with extra ceremony.
MIN_SITES = 2


def _rule_of(f: dict) -> str:
    """The stable detector identity — what a reader means by "this is the same issue"."""
    for key in ("rule_id", "key", "semantic_id"):
        value = f.get(key)
        if isinstance(value, str) and value:
            return value
    return str(f.get("attack_class") or f.get("category") or "finding")


def _location_of(f: dict) -> str:
    return str(f.get("location") or f.get("file") or "")


def _group_key(f: dict) -> tuple:
    """(kind, discriminator) — which cluster this finding belongs to, or ("", "") for none.

    Incident wins over rule: 22 blobs from one deletion are one INCIDENT even though they were
    matched by several different secret rules, and telling the reader "someone deleted a directory
    of config in commit abc123" is far more actionable than three rule-shaped buckets."""
    commit = f.get("commit") or f.get("commit_short")
    if f.get("history_only") and isinstance(commit, str) and commit:
        return ("incident", f"deleted-in:{commit[:12]}")
    return ("rule", f"{f.get('category') or ''}:{_rule_of(f)}")


def _cluster_id(kind: str, disc: str) -> str:
    return f"wc1_{kind[:3]}_" + hashlib.sha256(f"{kind}|{disc}".encode()).hexdigest()[:12]


def _title(kind: str, disc: str, members: list) -> str:
    """A cluster headline that says what the reader needs: how many sites, and one fix or many."""
    n = len(members)
    if kind == "incident":
        commit = disc.split(":", 1)[1]
        return (f"{n} secret(s) removed from the working tree in commit {commit} — the files are "
                f"gone but every blob is still fetchable from the repo. ONE incident: rotating the "
                f"{n} credential(s) is the fix; deleting the files was not.")
    # Reuse the longest shared prefix of the member titles so the cluster reads like the findings.
    base = min((str(m.get("title") or "") for m in members), key=len, default="")
    base = base.split(" — ")[0][:110] or _rule_of(members[0])
    return f"{base} — {n} site(s), one pattern"


def build(ledger: dict) -> list:
    """`clusters[]` for a findings ledger. Never mutates the ledger; returns [] when nothing groups.

    Single-site groups are omitted on purpose — a cluster of one adds a layer of indirection and
    tells the reader nothing they could not see in the finding itself."""
    groups: dict = {}
    for f in (ledger.get("findings") or []):
        kind, disc = _group_key(f)
        if not kind:
            continue
        groups.setdefault((kind, disc), []).append(f)

    out = []
    for (kind, disc), members in groups.items():
        if len(members) < MIN_SITES:
            continue
        members = sorted(members, key=lambda m: (_location_of(m), m.get("line") or 0))
        top = max(members, key=lambda m: SEV_ORDER.get(m.get("severity"), 0))
        sites = [{"location": _location_of(m), "line": m.get("line") or 0,
                  "severity": m.get("severity"), "confidence": m.get("confidence"),
                  # BOTH ids: `fingerprint` is what a baseline and `websec feedback` already
                  # address, `instance_id` is the portable one. A cluster must never become the
                  # only way to reach a site.
                  **({"fingerprint": m["fingerprint"]} if m.get("fingerprint") else {}),
                  **({"instance_id": m["instance_id"]} if m.get("instance_id") else {}),
                  **({"in_tree": m["in_tree"]} if isinstance(m.get("in_tree"), bool) else {})}
                 for m in members]
        out.append({
            "cluster_id": _cluster_id(kind, disc),
            "kind": kind,
            "rule": _rule_of(top),
            "category": top.get("category"),
            "attack_class": top.get("attack_class"),
            "title": _title(kind, disc, members),
            # The cluster inherits the WORST severity/confidence among its sites — a cluster is at
            # least as urgent as its most urgent member, never averaged down.
            "severity": top.get("severity"),
            "confidence": max((m.get("confidence") for m in members),
                              key=lambda c: CONF_ORDER.get(c, 0), default=None),
            "site_count": len(members),
            "sites": sites,
            "representative": top.get("fingerprint") or (sites[0].get("fingerprint") if sites else None),
            "remediation": top.get("remediation"),
            **({"commit": disc.split(":", 1)[1]} if kind == "incident" else {}),
            "gating_note": ("presentation only — every site remains its own gating finding, with its "
                            "own fingerprint, in findings[], SARIF and the baseline"),
        })
    # Worst first, then widest — the cluster a reader should look at first is the one that is both.
    out.sort(key=lambda c: (-SEV_ORDER.get(c["severity"], 0), -c["site_count"], c["cluster_id"]))
    return out


def summary(clusters: list, total_findings: int) -> dict:
    """Headline numbers for the report: how much of the noise is actually repetition."""
    clustered = sum(c["site_count"] for c in clusters)
    # "distinct issues" = every cluster counts once, plus the findings that clustered with nothing.
    distinct = len(clusters) + max(total_findings - clustered, 0)
    return {"clusters": len(clusters), "clustered_findings": clustered,
            "distinct_issues": distinct, "total_findings": total_findings,
            "largest": max((c["site_count"] for c in clusters), default=0)}

"""`websec attest` — project EXISTING run artifacts into an evidence table an assessor can read.

This command computes nothing new. It answers one question about a run that already happened:
*which audit-relevant facts does websec actually hold, and which does it not?*

THE GAP LIST COMES FIRST, in the data and in the rendering. That ordering is the feature. A tool
that leads with coverage invites the reader to treat absence as satisfaction; leading with what is
missing makes the artifact useful to someone whose job is to find the hole.

WHAT THIS IS NOT, and the reasoning, because the temptation to overclaim here is enormous:

  * It never renders a verdict, score, percentage, badge or tick, and the word "compliant" must not
    appear in its output — there is a test asserting that. Compliance is an attribute of an assessed
    ENTITY, determined solely by a QSA/ISA or an auditor and evidenced by a ROC/SAQ/AOC. PCI SSC
    FAQ 1258: "no single product can provide PCI DSS compliance". A tool that badges itself makes
    exactly the claim the standard forbids.
  * It does not claim the gate could not be bypassed. It demonstrably can: a client-side hook is a
    developer convenience, not a control. websec records honoured WEBSEC_SKIP_HOOK bypasses, and
    that record is not exhaustive — `git push --no-verify`, an uninstalled hook and a deleted hook
    are invisible.
  * It does not evidence approver independence. That is a property of a two-party approval
    workflow and lives in the forge's approval record, not in a scan artifact.

CITATIONS. Getting these exactly right is part of the point, since a misattributed clause is the
fastest way for an assessor to discount the whole artifact:

  * EU DORA change management is **Commission Delegated Regulation (EU) 2024/1774 Art. 17**, the
    RTS made under DORA Art. 9(4)(e). Regulation (EU) 2022/2554 (DORA) Art. 17 itself is
    "ICT-related incident management process" and is the wrong citation for change control.
  * SOX has **no article** to cite for ITGC. The domains come from SEC Release 33-8810 §II.A.2.d
    (program development, program changes, computer operations, access to programs and data);
    PCAOB AS 2201 ¶B29 names three. The Act itself mentions none of them.
  * PCI DSS v4.0.1 **6.2.3 permits automated review** ("either manual or automated processes, or a
    combination of both"). **6.2.3.1 is conditional** — "If manual code reviews are performed…" —
    so its four-eyes rule binds only when manual review is the chosen method. Nothing in
    Requirement 6 says automated tooling alone is insufficient.
"""
from __future__ import annotations

import json
from pathlib import Path

SCHEMA_VERSION = "1.0"

DISCLAIMER = (
    "This is an evidence inventory, not a compliance determination. websec does not and cannot "
    "assess an entity against any framework: that is done by a qualified assessor or auditor and "
    "evidenced by their report. Read the gaps first — an absent row means websec holds nothing, "
    "not that the control is satisfied."
)

# (framework, clause, citation, holds[], gaps[])
# `holds` entries name the artifact field that carries the evidence, so a reader can check the
# claim against the file rather than trusting this table.
_CONTROLS = [
    ("EU DORA (ICT change management)", "Art. 17(1)(a) — verification that ICT security requirements have been met",
     "Commission Delegated Regulation (EU) 2024/1774, Art. 17(1)(a) (RTS under Regulation (EU) 2022/2554 Art. 9(4)(e))",
     ["coverage.detector_revision — the exact detector set that ran, including uncommitted local edits",
      "coverage.analyzed_input_digest + coverage.inputs — the exact bytes analyzed, per file",
      "coverage.execution_complete + coverage.gaps[] — whether the requested checks finished",
      "findings[].standards — CWE / ASVS 4.0.3 / OWASP-API citations per finding",
      "attribution.vcs.commit + tree_clean — which change the findings describe"],
     ["websec's detector set is NOT the entity's security requirements; only the entity defines those",
      "coverage.protection_complete is always false — execution completeness is not protection"]),

    ("EU DORA (ICT change management)", "Art. 17(1)(b) — independence of the functions that approve changes",
     "Commission Delegated Regulation (EU) 2024/1774, Art. 17(1)(b)",
     [],
     ["a declared non-goal. Independence is a property of a two-party approval "
      "workflow; the evidence is a forge approval record (approver != author, approval after the "
      "last push, approver lacks bypass rights). websec records the RUN side only",
      "attribution.declared.* is self-asserted and is not identity evidence"]),

    ("EU DORA (ICT change management)", "Art. 17(1)(c) — changes are tested and finalised in a controlled manner",
     "Commission Delegated Regulation (EU) 2024/1774, Art. 17(1)(c)",
     ["repair plans bind original -> fixed by application_id / build_id / source_digest and are content-addressed",
      "repair verification requires paired positive AND negative controls, plus a FAILED before-control on the vulnerable build",
      "tests_executed_by_websec is always false — operator-supplied test records are validated, never executed here"],
     ["role assignment and accountability for testing/QA are organisational and not recorded",
      "websec validates the SHAPE of supplied test evidence; it does not run the tests"]),

    ("EU DORA (ICT change management)", "Art. 17(1)(e) — fall-back procedures and responsibilities",
     "Commission Delegated Regulation (EU) 2024/1774, Art. 17(1)(e)",
     [],
     ["a declared non-goal. Rollback is a deployment capability; websec holds no "
      "deployment state and cannot observe whether a fall-back path exists or was exercised"]),

    ("EU DORA (ICT change management)", "Art. 17(1)(f)-(g) — emergency changes documented and subsequently approved",
     "Commission Delegated Regulation (EU) 2024/1774, Art. 17(1)(f)-(g)",
     ["honoured WEBSEC_SKIP_HOOK bypasses are recorded to $GIT_DIR/websec-guardrail/bypass.jsonl with hook, HEAD and timestamp"],
     ["the bypass record is NOT exhaustive: `git push --no-verify`, an uninstalled hook and a "
      "deleted hook are invisible to websec. An empty bypass log is not evidence that no bypass occurred",
      "subsequent approval of an emergency change is not recorded"]),

    ("EU DORA (ICT change management)", "Art. 17(1)(h) — impact of a change on existing ICT security measures",
     "Commission Delegated Regulation (EU) 2024/1774, Art. 17(1)(h)",
     ["baseline lifecycle per finding: new / unchanged / changed / reopened / no-longer-observed",
      "--diff hunk scoping identifies findings inside the changed lines",
      "graph blast-radius enrichment when a graph is supplied",
      "no-longer-observed carries an explicit 'absence is not a verified fix' disclaimer"],
     ["whether ADDITIONAL measures are required is a human assessment; websec supplies inputs to it"]),

    ("PCI DSS v4.0.1", "6.2.3 — bespoke and custom software reviewed prior to release",
     "PCI DSS v4.0.1 Req. 6.2.3. Applicability Notes permit review by "
     "'either manual or automated processes, or a combination of both'.",
     ["an automated review demonstrably ran: detector revision, analyzed input digest, completion state and gap list",
      "findings carry CWE / ASVS 4.0.3 / OWASP-API citations",
      "per-run immutable artifacts with sha256 digests of everything emitted",
      "the gate record states threshold, baseline, count at or above threshold and verdict"],
     ["binding to a RELEASE is the entity's to establish; websec records the commit, not the deployment",
      "whether corrections were implemented prior to release is not observable from a scan"]),

    ("PCI DSS v4.0.1", "6.2.3.1 — four-eyes review (ONLY IF manual review is performed)",
     "PCI DSS v4.0.1 Req. 6.2.3.1, which opens 'If manual code reviews are performed…'. "
     "Its Customized Approach Objective is that the manual review process 'cannot be bypassed'.",
     [],
     ["websec should not be offered against this clause. It is conditional on "
      "choosing manual review, and its objective is a process that cannot be bypassed — websec's "
      "local gate demonstrably can be"]),

    ("PCI DSS v4.0.1", "6.3.1 — vulnerabilities identified from industry-recognised sources and risk-ranked",
     "PCI DSS v4.0.1 Req. 6.3.1. Its applicability note states this is 'not achieved by, and is in "
     "addition to, performing vulnerability scans'.",
     ["EPSS and CISA KEV enrichment with recorded feed provenance and freshness",
      "severity and calibrated confidence recorded separately per finding"],
     ["actively monitoring industry sources is an organisational process; websec is one input to it"]),

    ("PCI DSS v4.0.1", "6.4.2 — automated technical solution for public-facing web applications",
     "PCI DSS v4.0.1 Req. 6.4.2 (governs from 31 March 2025; the 6.4.1 periodic-review option is withdrawn).",
     [],
     ["a declared non-goal. This requires a deployed runtime control that "
      "continually detects and prevents web attacks (WAF-class). websec is a static analyser and "
      "must not be mapped here"]),

    ("SOX ITGC", "Program changes",
     "No SOX article prescribes this. The ITGC domains come from SEC Release 33-8810 §II.A.2.d; "
     "PCAOB AS 2201 ¶B29 names three in its benchmarking appendix. SOX §404 (15 U.S.C. 7262) "
     "mentions none of them.",
     ["a scan executed against an exact input set with an exact detector revision, and what it found",
      "the change identifier: attribution.vcs.commit, with tree_clean and commit-signature status",
      "the gate record: which threshold ran and what it returned"],
     ["completeness of population — that the control operated on EVERY change — is not evidenced "
      "and cannot be, client-side",
      "the local gate is bypassable; enforcement is server-side branch protection with a required "
      "status check, which websec can BE but cannot attest to"]),

    ("SOX ITGC", "Logical access / computer operations / program development",
     "SEC Release 33-8810 §II.A.2.d.",
     [],
     ["declared non-goals. websec contributes nothing to access provisioning, "
      "job scheduling, backup, or the development lifecycle outside the code it reads. This is "
      "where a security tool is most tempting to overclaim"]),
]


def _load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def collect(run_dir: Path) -> dict:
    """Read what the run actually produced. Absent artifacts are reported, never imputed."""
    ledger = _load(run_dir / "findings-ledger.json") or {}
    manifest = _load(run_dir / "manifest.json") or {}
    coverage = _load(run_dir / "coverage.json") or ledger.get("coverage") or {}
    return {
        "run_directory": str(run_dir),
        "verification_context": ledger.get("verification_context") or {},
        "attribution": ledger.get("attribution") or {},
        "gate": ledger.get("gate") or {},
        "execution_complete": coverage.get("execution_complete"),
        "protection_complete": coverage.get("protection_complete", False),
        "gaps": coverage.get("gaps") or [],
        "detector_revision": coverage.get("detector_revision"),
        "analyzed_input_digest": coverage.get("analyzed_input_digest"),
        "artifact_digests": manifest.get("artifact_digests") or {},
        "findings_total": ledger.get("total"),
    }


def build(run_dir: Path, bypasses: dict | None = None) -> dict:
    """The evidence table. Gaps first, everywhere."""
    observed = collect(run_dir)
    have_attr = bool(observed["attribution"].get("vcs") or observed["attribution"].get("ci"))
    controls = []
    for framework, clause, citation, holds, gaps in _CONTROLS:
        # A row's evidence is only claimed when the run actually produced it.
        present = list(holds)
        if not have_attr:
            present = [h for h in present if "attribution." not in h]
            gaps = gaps + ["this run recorded no VCS or CI attribution, so it is not bound to a change"]
        if not observed["artifact_digests"]:
            present = [h for h in present if "sha256 digests" not in h]
        controls.append({
            "framework": framework, "clause": clause, "citation": citation,
            "not_evidenced": gaps,                 # FIRST, deliberately
            "websec_evidence": present,
            "evidence_count": len(present),
        })
    out = {
        "tool": "websec-validator", "command": "attest", "schema_version": SCHEMA_VERSION,
        "disclaimer": DISCLAIMER,
        "read_this_first": {
            "verdict": None,
            "note": ("websec renders no verdict and no score. Every row lists what is NOT evidenced "
                     "before what is."),
            "enforcement": ("the local gate is bypassable and its bypass record is not exhaustive; "
                            "enforcement is a server-side required status check, not this tool"),
            "approver_independence": "not evidenced by design — it lives in the forge approval record",
        },
        "observed": observed,
        "controls": controls,
        "totals": {"controls": len(controls),
                   "with_no_websec_evidence": sum(1 for c in controls if not c["websec_evidence"])},
    }
    if bypasses is not None:
        out["observed"]["hook_bypasses"] = bypasses
    return out


def to_in_toto(attestation: dict) -> dict:
    """The ledger as an UNSIGNED in-toto Statement.

    Deliberately unsigned. websec is not a builder in a trusted build service, so a websec-signed
    provenance would be a self-signed statement from the same process that could lie — tier-3
    assurance with extra JSON. Emitting the unsigned shape lets an organisation sign it with THEIR
    key and THEIR identity (cosign, actions/attest-build-provenance), which is what makes it
    verifiable: it becomes evidence precisely because websec did not vouch for itself.

    websec also does not CONSUME in-toto: DSSE verification means Sigstore bundles, Fulcio chains
    and Rekor inclusion proofs — crypto plus network I/O, infeasible in a stdlib-only runtime — and
    "parse but don't verify" is worse than nothing, because it launders an unverified claim into an
    audit artifact.
    """
    observed = attestation.get("observed") or {}
    digest = str(observed.get("analyzed_input_digest") or "")
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": str((observed.get("verification_context") or {}).get("application_id") or "source"),
                     "digest": {"sha256": digest.replace("sha256:", "")} if digest else {}}],
        "predicateType": "https://websec-validator.dev/attestations/evidence/v1",
        "predicate": {
            "disclaimer": attestation.get("disclaimer"),
            "signing": ("UNSIGNED BY DESIGN. Sign this with your own key and identity; a "
                        "websec-signed statement would attest only that websec ran."),
            "observed": observed,
            "controls": attestation.get("controls"),
        },
    }


def render_text(attestation: dict) -> str:
    lines = ["websec evidence inventory — NOT a compliance determination", "",
             attestation["disclaimer"], ""]
    observed = attestation["observed"]
    attr = observed.get("attribution") or {}
    lines.append(f"run: {observed['run_directory']}")
    lines.append(f"  change:    {(attr.get('vcs') or {}).get('commit', '(not recorded)')}"
                 f"  assurance={attr.get('assurance', 'none')}")
    lines.append(f"  execution: complete={observed['execution_complete']}  "
                 f"protection_complete={observed['protection_complete']}")
    gate = observed.get("gate") or {}
    lines.append(f"  gate:      {gate.get('verdict', '(not recorded)')} "
                 f"threshold={gate.get('threshold')}")
    lines.append("")
    for control in attestation["controls"]:
        lines.append(f"── {control['framework']} — {control['clause']}")
        lines.append(f"   cite: {control['citation']}")
        for gap in control["not_evidenced"]:
            lines.append(f"   NOT EVIDENCED: {gap}")
        for item in control["websec_evidence"]:
            lines.append(f"   evidence:      {item}")
        lines.append("")
    totals = attestation["totals"]
    lines.append(f"{totals['with_no_websec_evidence']} of {totals['controls']} rows have NO websec "
                 "evidence at all. That is expected: most of these controls are organisational.")
    return "\n".join(lines)

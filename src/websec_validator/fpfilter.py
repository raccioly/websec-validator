"""Deterministic FP-exclusion pre-pass — pre-compute what a downstream LLM reviewer would filter out.

anthropics/claude-code-security-review reduces false positives in two stages: a set of hard, regex-shaped
exclusion rules, and then a per-finding LLM re-judgement pass (an extra model call for EVERY surviving
finding). The first stage is pure logic — no model needed. websec encodes the same categories, so it can
TAG findings a reviewer would drop before that reviewer ever spends a token on them.

Crucially this only **tags**; it never drops. A finding marked `likely_filtered` stays in the ledger, in
SARIF, and in the report, with the reason attached. The downstream consumer decides. Silently deleting
findings on a heuristic is exactly the failure mode websec exists to avoid — and a rule that's wrong
about YOUR codebase must remain visible and arguable.

Categories mirror the published hard-exclusion list: denial-of-service / resource exhaustion, missing
rate limiting, resource leaks, open redirect (low-signal on its own), regex-injection, memory-safety in
memory-safe languages, SSRF reachable only from HTML, and anything that lives purely in docs/tests.
"""

from __future__ import annotations

from .extractors.base import is_test_file

# attack_class → why a reviewer would routinely filter it. Deliberately NARROW: each entry is a class
# whose findings are, on their own and without more context, usually not actionable security bugs.
_LOW_SIGNAL_CLASSES: dict = {
    "redos": "regex-complexity / DoS class — reviewers routinely drop these without a proven "
             "attacker-controlled input reaching the regex at scale",
    "open-redirect": "open redirect on its own is low-signal (no data loss); only material when it "
                     "feeds an OAuth/SSO token flow",
    "missing-usage-cap": "missing rate limit / usage cap is a hardening gap, not an exploitable bug "
                         "by itself",
    "llm-unbounded": "unbounded generation is a cost/DoS concern rather than a security boundary break",
}

# docs-only locations: a "finding" in prose is not a vulnerability in the product.
_DOC_SUFFIXES = (".md", ".mdx", ".rst", ".txt", ".adoc")

# languages whose runtime forecloses classic memory-safety bugs — a memory-safety finding there is
# almost always a scanner artefact.
_MEMORY_SAFE = {"python", "node", "typescript", "ruby", "go", "java", "csharp"}
_MEMORY_CLASSES = {"buffer-overflow", "use-after-free", "memory-safety"}


def evaluate(finding: dict, facts: dict | None = None) -> tuple:
    """→ (likely_filtered: bool, reason: str). Pure; no side effects."""
    ac = str(finding.get("attack_class", "")).lower()
    loc = str(finding.get("location", "")).replace("\\", "/")
    low = loc.lower()

    if ac in _LOW_SIGNAL_CLASSES:
        return True, _LOW_SIGNAL_CLASSES[ac]
    if low.endswith(_DOC_SUFFIXES):
        return True, "documentation/prose file — not product code"
    if loc and is_test_file(loc):
        return True, "test/fixture file — not the deployed product"
    if ac in _MEMORY_CLASSES:
        langs = {str(x).lower() for x in ((facts or {}).get("stack", {}) or {}).get("languages", [])}
        if langs and langs <= _MEMORY_SAFE:
            return True, (f"memory-safety class in a memory-safe stack "
                          f"({', '.join(sorted(langs))}) — almost certainly a scanner artefact")
    return False, ""


def annotate(ledger: dict, facts: dict | None = None) -> dict:
    """Tag ledger findings with `likely_filtered` + `filter_reason`. ADDITIVE — nothing is dropped."""
    n = 0
    for f in (ledger or {}).get("findings", []) or []:
        flagged, reason = evaluate(f, facts)
        if flagged:
            f["likely_filtered"] = True
            f["filter_reason"] = reason
            n += 1
    return {"likely_filtered": n,
            "kept": len((ledger or {}).get("findings", []) or []) - n}


def render_md(ledger: dict, counts: dict) -> str:
    n = counts.get("likely_filtered", 0)
    if not n:
        return ("_No findings match the standard reviewer-exclusion categories — the ledger is already "
                "high-signal._")
    rows = [f for f in (ledger or {}).get("findings", []) or [] if f.get("likely_filtered")]
    out = [f"**{n} finding(s)** match categories a security reviewer (or the popular LLM review "
           "actions) routinely filters out. They are **kept and listed here, not deleted** — the "
           "reason is stated so you can disagree:\n",
           "| Finding | Where | Why a reviewer would filter it |", "|---|---|---|"]
    for f in rows[:20]:
        out.append(f"| {f.get('attack_class', '?')} — {str(f.get('title', ''))[:60]} | "
                   f"`{f.get('location', '?')}` | {f.get('filter_reason', '')} |")
    out.append("\n_Feeding these pre-tagged to an LLM reviewer lets it skip its own filtering pass._")
    return "\n".join(out)

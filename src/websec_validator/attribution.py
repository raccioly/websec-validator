"""Run attribution — WHO and WHICH CHANGE a finding set describes, graded by how much it is worth.

The ledger already binds findings to an exact input set (`analyzed_input_digest`, per-file hashes,
`detector_revision` including uncommitted edits). What it never recorded is the thing every change
management framework asks for first: **which change**. `application_id` defaults to a local
filesystem path, and while `diffscope` resolves `base...HEAD` only the base ref is persisted, so the
HEAD the findings describe was never written down.

This module adds that, and grades it honestly. The grading is the point:

  tier 1  ci-minted      CI runner env / OIDC claims. Not settable from inside the job and
                         corroborable against the forge's own audit log.          REAL evidence.
  tier 2  vcs-observed   `git rev-parse HEAD`, signature status. The SHA is fixed by content;
                         the signature is the forgery-resistant part.             MEDIUM.
  tier 3  self-asserted  --actor, $WEBSEC_ACTOR, git config user.email, $USER, git trailers.
                         `git config user.email "cfo@corp.com"` takes one second. ZERO.

Tier 3 is recorded but quarantined under `declared`, carrying a warning string INLINE in the
artifact so it survives being pasted into an audit binder. Presenting a self-asserted string as
identity evidence would manufacture exactly the false assurance this tool exists to avoid — the same
discipline as the shipped `protection_complete: False` and `tests_executed_by_websec: False` markers.

`assurance` is COMPUTED from what was actually observed and is never accepted as input.

DELIBERATE NON-GOAL: approver identity and reviewer independence. Independence is a property of a
two-party workflow, not of a scan; the evidence is a forge approval record (approver != author,
approval after the last push, approver lacks bypass rights), which needs authenticated network I/O
against a forge API. websec contributes the RUN side only, and `attest` states the gap explicitly.

Read-only, stdlib + git only. Every probe is bounded and non-raising: attribution is evidence
*about* a run and must never be able to fail one.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

SCHEMA_VERSION = "1.0"
_TIMEOUT = 10
_MAX = 4096

DECLARED_WARNING = ("Operator-declared and NOT verified by websec. A value the runner can set to any "
                    "string is a label, not audit evidence.")

# Only fields a CI runner injects into the job environment. A value the job can trivially rewrite is
# no better than tier 3, so this list stays deliberately short and provider-specific.
_GITHUB_ENV = {
    "repository": "GITHUB_REPOSITORY",
    "sha": "GITHUB_SHA",
    "run_id": "GITHUB_RUN_ID",
    "run_attempt": "GITHUB_RUN_ATTEMPT",
    "workflow_ref": "GITHUB_WORKFLOW_REF",
    "triggering_actor": "GITHUB_TRIGGERING_ACTOR",
    "actor": "GITHUB_ACTOR",
    "event": "GITHUB_EVENT_NAME",
    "ref": "GITHUB_REF",
}
_GITLAB_ENV = {
    "repository": "CI_PROJECT_PATH",
    "sha": "CI_COMMIT_SHA",
    "run_id": "CI_PIPELINE_ID",
    "job_id": "CI_JOB_ID",
    "workflow_ref": "CI_CONFIG_PATH",
    "triggering_actor": "GITLAB_USER_LOGIN",
    "event": "CI_PIPELINE_SOURCE",
    "ref": "CI_COMMIT_REF_NAME",
}

_SHA = re.compile(r"^[0-9a-f]{7,64}$")


def _clean(value, limit: int = 256) -> str:
    """CI env and git output are untrusted strings that end up in a published artifact."""
    if not isinstance(value, str):
        return ""
    return value.replace("\x00", "").strip()[:limit]


def _git(target, *args: str):
    """Bounded, argument-array git. Returns stdout or None; never raises."""
    try:
        proc = subprocess.run(["git", "-C", str(target), *args],
                              capture_output=True, text=True, timeout=_TIMEOUT)
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout[:_MAX]


def _vcs(target) -> dict:
    """Tier 2: what the repository itself says, independent of who is asserting it."""
    if _git(target, "rev-parse", "--is-inside-work-tree") is None:
        return {}
    head = _clean(_git(target, "rev-parse", "HEAD") or "")
    if not _SHA.match(head):
        return {}
    out: dict = {"commit": head}

    status = _git(target, "status", "--porcelain")
    if status is not None:
        # A dirty tree means the findings do NOT describe the commit alone. Saying so is the whole
        # value of the field: binding evidence to a SHA that the scanned bytes did not match would be
        # worse than recording no SHA at all.
        out["tree_clean"] = status.strip() == ""

    branch = _clean(_git(target, "rev-parse", "--abbrev-ref", "HEAD") or "")
    if branch and branch != "HEAD":
        out["branch"] = branch

    for key, fmt in (("author_email", "%ae"), ("committer_email", "%ce"), ("committed_at", "%cI")):
        value = _clean(_git(target, "log", "-1", f"--format={fmt}") or "")
        if value:
            out[key] = value

    # Signature status is the one locally checkable forgery-resistant signal. It proves a KEY signed
    # the commit — not that a human rather than an agent produced it.
    raw = _git(target, "verify-commit", "--raw", "HEAD")
    if raw is None:
        out["signature"] = "none"
    else:
        blob = raw + (_git(target, "log", "-1", "--format=%G?") or "")
        out["signature"] = "good" if "GOODSIG" in blob else ("bad" if "BADSIG" in blob else "unchecked")
        fpr = re.search(r"VALIDSIG\s+([0-9A-Fa-f]{16,64})", raw)
        if fpr:
            # The key fingerprint, deliberately NOT a claimed human name.
            out["signer"] = fpr.group(1)
    return out


def _ci(env: dict) -> dict:
    """Tier 1: only present when a recognised runner injected it."""
    if env.get("GITHUB_ACTIONS") == "true":
        provider, mapping = "github-actions", _GITHUB_ENV
    elif env.get("GITLAB_CI") == "true":
        provider, mapping = "gitlab-ci", _GITLAB_ENV
    else:
        return {}
    out = {"provider": provider}
    for key, var in mapping.items():
        value = _clean(env.get(var, ""))
        if value:
            out[key] = value
    # The most valuable field in the object: it tells an assessor where to check this claim against a
    # system websec does not control.
    if provider == "github-actions" and out.get("repository") and out.get("run_id"):
        server = _clean(env.get("GITHUB_SERVER_URL") or "https://github.com")
        out["corroborate_at"] = f"{server}/{out['repository']}/actions/runs/{out['run_id']}"
    elif provider == "gitlab-ci" and env.get("CI_PIPELINE_URL"):
        out["corroborate_at"] = _clean(env.get("CI_PIPELINE_URL"))
    return out


def _declared(env: dict, actor: str | None) -> dict:
    """Tier 3: recorded, labelled, and never promoted."""
    out: dict = {}
    operator = _clean(actor or env.get("WEBSEC_ACTOR", ""))
    if operator:
        out["operator"] = operator
    agent = {}
    for key, var in (("model", "WEBSEC_AGENT_MODEL"), ("harness", "WEBSEC_AGENT_HARNESS"),
                     ("session", "WEBSEC_AGENT_SESSION")):
        value = _clean(env.get(var, ""))
        if value:
            agent[key] = value
    if agent:
        out["agent"] = agent
    if out:
        out["warning"] = DECLARED_WARNING
    return out


def build(target, *, actor: str | None = None, env: dict | None = None) -> dict:
    """Assemble the attribution record for one run.

    Returned as a SIBLING of `verification_context`, never merged into it: `repairs` compares that
    object by STRICT DICT EQUALITY in four places, so an added key would invalidate every repair
    plan emitted before this change.
    """
    env = os.environ if env is None else env
    vcs = _vcs(target)
    ci = _ci(env)
    declared = _declared(env, actor)

    # COMPUTED, never supplied. Ordered by what the evidence is actually worth.
    if ci:
        assurance = "ci-minted"
    elif vcs:
        assurance = "vcs-observed"
    elif declared:
        assurance = "self-asserted"
    else:
        assurance = "none"

    out: dict = {"schema_version": SCHEMA_VERSION, "assurance": assurance}
    if vcs:
        out["vcs"] = vcs
    if ci:
        out["ci"] = ci
    if declared:
        out["declared"] = declared

    # An honesty marker that travels inline, like `protection_complete` and
    # `tests_executed_by_websec`. Attribution says who ran the scan; it never says a change was
    # independently approved, and an audit binder must not be able to read it that way.
    out["approver_independence"] = {
        "evidenced": False,
        "note": ("websec records the RUN side only. Reviewer independence is a property of a "
                 "two-party approval workflow and lives in the forge's approval record, not in a "
                 "scan artifact. Absence here is not evidence that review occurred or did not."),
    }
    return out

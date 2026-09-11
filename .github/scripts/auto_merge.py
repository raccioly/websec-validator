"""Merge a green bot PR, or label it and leave it for a human.

Runs from `workflow_run` (write scope, no PR code checked out — PR metadata is read via the API
only). It deliberately re-derives the check state from the API instead of trusting the run that
triggered it: `gh pr merge --auto` with no required checks configured merges immediately, and a
single successful workflow_run says nothing about the other matrix legs.

The merge conditions, all of which must hold:
  1. the head SHA belongs to an open, mergeable PR by an allowlisted bot
  2. every check in .github/required-checks.json reported success on that exact SHA
  3. no check on that SHA is failed, cancelled, or still running
  4. triage.verdict() says 'merge'
"""

from __future__ import annotations

import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import gh        # noqa: E402
import triage    # noqa: E402

REPO = os.environ["REPO"]
HEAD_SHA = os.environ["HEAD_SHA"]
ALLOWED_BOTS = {"dependabot[bot]", "google-labs-jules[bot]"}
HOLD_LABEL = "needs-human"
ROOT = pathlib.Path(__file__).resolve().parents[1]
REQUIRED = set(json.loads((ROOT / "required-checks.json").read_text())["required"])

OK_CONCLUSIONS = {"success", "neutral", "skipped"}


def check_state(sha):
    """(ok, reason). Collapses check-runs for the SHA to a single go/no-go."""
    runs = gh.paged(f"/repos/{REPO}/commits/{sha}/check-runs")
    by_name = {}
    for r in runs:
        # Keep the newest attempt per name; re-runs append rather than replace.
        prev = by_name.get(r["name"])
        if prev is None or (r.get("started_at") or "") >= (prev.get("started_at") or ""):
            by_name[r["name"]] = r

    missing = REQUIRED - set(by_name)
    if missing:
        return False, f"required check(s) never reported: {sorted(missing)}"

    for name in sorted(REQUIRED):
        r = by_name[name]
        if r.get("status") != "completed":
            return False, f"{name} is {r.get('status')}"
        if r.get("conclusion") not in OK_CONCLUSIONS:
            return False, f"{name} concluded {r.get('conclusion')}"

    # Anything else red on this SHA blocks too — a bot must not merge past a failing extra check.
    for name, r in by_name.items():
        if r.get("status") == "completed" and r.get("conclusion") in ("failure", "timed_out", "cancelled"):
            return False, f"{name} concluded {r.get('conclusion')}"
    return True, f"{len(REQUIRED)} required check(s) green"


def ensure_label(pr_number, label, color, desc):
    gh.request("POST", f"/repos/{REPO}/labels",
               {"name": label, "color": color, "description": desc}, accept_status=(422,))
    gh.request("POST", f"/repos/{REPO}/issues/{pr_number}/labels",
               {"labels": [label]}, accept_status=(404, 422))


def already_commented(pr_number, marker):
    for c in gh.paged(f"/repos/{REPO}/issues/{pr_number}/comments"):
        if marker in (c.get("body") or ""):
            return True
    return False


def main():
    pulls = gh.get(f"/repos/{REPO}/commits/{HEAD_SHA}/pulls") or []
    if not pulls:
        print(f"no PR associated with {HEAD_SHA}")
        return

    for pr in pulls:
        n = pr["number"]
        author = pr["user"]["login"]
        print(f"\n=== PR #{n} by {author} — {pr['title'][:70]}")

        if pr["state"] != "open":
            print("  skip: not open")
            continue
        if pr["head"]["sha"] != HEAD_SHA:
            print(f"  skip: head moved ({pr['head']['sha'][:8]} != {HEAD_SHA[:8]}) — stale run")
            continue
        if author not in ALLOWED_BOTS:
            print(f"  skip: {author} is not an allowlisted bot")
            continue
        if pr.get("draft"):
            print("  skip: draft")
            continue

        ok, why = check_state(HEAD_SHA)
        if not ok:
            print(f"  hold: {why}")
            continue
        print(f"  checks: {why}")

        files = gh.paged(f"/repos/{REPO}/pulls/{n}/files")
        verdict, reason = triage.verdict(author, pr["title"], files)
        print(f"  verdict: {verdict} — {reason}")

        if verdict != "merge":
            marker = "<!-- websec-automation:hold -->"
            ensure_label(n, HOLD_LABEL, "B60205", "Bot PR held for human review by the merge gate")
            if not already_commented(n, marker):
                gh.request("POST", f"/repos/{REPO}/issues/{n}/comments", {
                    "body": f"{marker}\n**Held for human review.**\n\n{reason}\n\n"
                            f"CI is green; the merge gate stops here on scope, not on test results. "
                            f"Merge it yourself if the change is what you want.",
                }, accept_status=(403, 404))
            continue

        # mergeable is computed asynchronously; re-read the PR for a settled value.
        fresh = gh.get(f"/repos/{REPO}/pulls/{n}")
        if fresh.get("mergeable") is False:
            print("  hold: PR has conflicts")
            continue

        status, body = gh.request(
            "PUT", f"/repos/{REPO}/pulls/{n}/merge",
            {"merge_method": "squash",
             "commit_title": f"{pr['title']} (#{n})",
             "commit_message": f"Auto-merged by the bot-PR gate: {reason}\n\nCo-Authored-By: Claude Opus 5 <noreply@anthropic.com>"},
            accept_status=(405, 409, 403),
        )
        if status == 200:
            print(f"  MERGED #{n}")
        else:
            print(f"  merge refused ({status}): {body}")


if __name__ == "__main__":
    main()

"""Triage a freshly opened bot PR: close it or label it.

Runs from `pull_request_target`, which carries write scope. It therefore reads PR metadata through
the API and never checks out or executes PR code; the scripts come from the default branch.

* Jules PRs follow `jules_policy.triage`: noise, duplicates (same routine target or same identifying
  file set), work declined in the last 60 days, and a review-queue cap of five are closed; the rest
  are labelled with what the merge gate would say.
* Dependabot PRs keep the older rule: a duplicate of an open dependabot PR by changed-file set is
  closed; the rest are labelled with the merge gate's verdict.

Comments never mention the agent by handle. With Jules' Reactive Mode on, a mention is an
instruction, and a closed PR is not one to act on.
"""

from __future__ import annotations

import datetime as dt
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import gh            # noqa: E402
import jules_policy  # noqa: E402
import triage        # noqa: E402

REPO = os.environ["REPO"]
PR_NUMBER = int(os.environ["PR_NUMBER"])
DEPENDABOT = "dependabot[bot]"
MARKER = "<!-- websec-automation:triage -->"

COLORS = {
    jules_policy.LABELS["noise"]: "CCCCCC", jules_policy.LABELS["duplicate"]: "CCCCCC",
    jules_policy.LABELS["declined"]: "CCCCCC", jules_policy.LABELS["queue_full"]: "FBCA04",
    jules_policy.LABELS["review"]: "B60205", jules_policy.LABELS["eligible"]: "0E8A16",
}

POLICY_NOTE = (
    "Jules PRs on this repository follow `.github/scripts/jules_policy.py` and the *Automated "
    "agents* section of `AGENTS.md`: one PR per routine target, a target is not re-proposed while "
    f"it is open or for {jules_policy.DECLINE_WINDOW_DAYS} days after it was declined, and at most "
    f"{jules_policy.QUEUE_CAP} wait for review at once. A maintainer can reopen this if the policy "
    "got it wrong."
)


def comment(number, body):
    gh.request("POST", f"/repos/{REPO}/issues/{number}/comments",
               {"body": f"{MARKER}\n{body}"}, accept_status=(403, 404))


def label(number, name, color, desc=""):
    gh.request("POST", f"/repos/{REPO}/labels",
               {"name": name, "color": color, "description": desc}, accept_status=(422,))
    gh.request("POST", f"/repos/{REPO}/issues/{number}/labels",
               {"labels": [name]}, accept_status=(403, 404, 422))


def close(number):
    gh.request("PATCH", f"/repos/{REPO}/pulls/{number}", {"state": "closed"}, accept_status=(403, 404))


def files_of(number):
    return [f["filename"] for f in gh.paged(f"/repos/{REPO}/pulls/{number}/files")]


def shape(p):
    return {"number": p["number"], "title": p.get("title") or "", "labels": p.get("labels") or [],
            "merged_at": p.get("merged_at"), "closed_at": p.get("closed_at"),
            "files": files_of(p["number"])}


def triage_jules(pr, files):
    now = dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(days=jules_policy.DECLINE_WINDOW_DAYS)
    open_prs = [shape(p) for p in gh.paged(f"/repos/{REPO}/pulls?state=open")
                if jules_policy.is_jules(p["user"]["login"]) and p["number"] != PR_NUMBER]
    closed_prs = []
    for p in gh.paged(f"/repos/{REPO}/pulls?state=closed&sort=updated&direction=desc"):
        if not jules_policy.is_jules(p["user"]["login"]) or not p.get("closed_at"):
            continue
        if dt.datetime.fromisoformat(p["closed_at"].replace("Z", "+00:00")) < cutoff:
            continue
        closed_prs.append(shape(p))

    decision = jules_policy.triage(
        {"number": PR_NUMBER, "title": pr["title"], "files": files},
        open_prs, closed_prs, now.isoformat(),
        lambda fs: triage.verdict(pr["user"]["login"], pr["title"], fs))
    print(f"#{PR_NUMBER}: {decision['action']} ({decision['label']}) — {decision['reason']}")

    label(PR_NUMBER, decision["label"], COLORS.get(decision["label"], "CCCCCC"),
          "Set by Jules PR triage (.github/scripts/jules_policy.py)")
    if decision["action"] == "close":
        comment(PR_NUMBER, f"**Closed automatically:** {decision['reason']}.\n\n{POLICY_NOTE}")
        close(PR_NUMBER)
    elif decision["label"] == jules_policy.LABELS["eligible"]:
        comment(PR_NUMBER, f"**Eligible to merge on green CI** — {decision['reason']}. The auto-merge "
                           "gate re-checks the exact head against its base before it merges.")
    else:
        comment(PR_NUMBER, f"**Needs a maintainer** — {decision['reason']}. CI still runs; nothing "
                           "merges without a human.")


def triage_dependabot(pr, files):
    names = [f["filename"] for f in files]
    key = triage.dup_key(names)
    for other in gh.paged(f"/repos/{REPO}/pulls?state=open&sort=created&direction=asc"):
        if other["number"] >= PR_NUMBER or other["user"]["login"] != DEPENDABOT:
            continue
        if triage.dup_key(files_of(other["number"])) == key:
            label(PR_NUMBER, "auto-closed", "CCCCCC", "Closed automatically by bot-PR triage")
            comment(PR_NUMBER, f"**Closed automatically — duplicate of #{other['number']}.** Both "
                               f"change exactly `{', '.join(sorted(key))}`.")
            close(PR_NUMBER)
            print(f"closed: duplicate of #{other['number']}")
            return
    verdict, reason = triage.verdict(pr["user"]["login"], pr["title"], files)
    if verdict == "hold":
        label(PR_NUMBER, "needs-human", "B60205", "Bot PR held for human review by the merge gate")
        print(f"labelled needs-human: {reason}")
    else:
        print(f"eligible for auto-merge once CI is green: {reason}")


def main():
    pr = gh.get(f"/repos/{REPO}/pulls/{PR_NUMBER}")
    author = pr["user"]["login"]
    if pr["state"] != "open":
        print("not open")
        return
    files = gh.paged(f"/repos/{REPO}/pulls/{PR_NUMBER}/files")
    print(f"#{PR_NUMBER} by {author}: {[f['filename'] for f in files]}")
    if jules_policy.is_jules(author):
        triage_jules(pr, files)
    elif author == DEPENDABOT:
        triage_dependabot(pr, files)
    else:
        print(f"{author} is not a triaged bot — leaving #{PR_NUMBER} alone")


if __name__ == "__main__":
    main()

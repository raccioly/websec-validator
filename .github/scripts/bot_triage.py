"""Triage a freshly opened bot PR: close it if it is known noise or a duplicate, else label it.

Runs from `pull_request_target`, which carries write scope. It therefore reads PR metadata through
the API and never checks out or executes PR code.

Duplicate detection is by changed-file overlap, not by title. These bots word the same change
differently every attempt — "Fix flaky git hooks test", "fix(tests): pin core.hooksPath",
"Fix `test_hooks.py` bypassed by global `core.hooksPath`" were all the same one-line edit — so title
normalisation does not group them, while the file set does.
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
PR_NUMBER = int(os.environ["PR_NUMBER"])
BOTS = {"dependabot[bot]", "google-labs-jules[bot]"}
MARKER = "<!-- websec-automation:triage -->"


AGENT_GUIDANCE = (
    "\n\n---\n@jules — before opening a PR, search **open and closed** PRs for the same change. "
    "This one has been proposed many times over. The repo rule is in `AGENTS.md` under *Automated "
    "agents*: no duplicates, and a new PR only for a genuinely new finding backed by evidence "
    "(a failing test for a defect, a reproduction for a false positive)."
)


def close_with(number, body, label="auto-closed"):
    gh.request("POST", f"/repos/{REPO}/issues/{number}/comments",
               {"body": f"{MARKER}\n{body}"}, accept_status=(403, 404))
    gh.request("POST", f"/repos/{REPO}/labels",
               {"name": label, "color": "CCCCCC", "description": "Closed automatically by bot-PR triage"},
               accept_status=(422,))
    gh.request("POST", f"/repos/{REPO}/issues/{number}/labels", {"labels": [label]},
               accept_status=(403, 404, 422))
    gh.request("PATCH", f"/repos/{REPO}/pulls/{number}", {"state": "closed"}, accept_status=(403, 404))


def label(number, name, color, desc):
    gh.request("POST", f"/repos/{REPO}/labels",
               {"name": name, "color": color, "description": desc}, accept_status=(422,))
    gh.request("POST", f"/repos/{REPO}/issues/{number}/labels",
               {"labels": [name]}, accept_status=(403, 404, 422))


def main():
    pr = gh.get(f"/repos/{REPO}/pulls/{PR_NUMBER}")
    author = pr["user"]["login"]
    if author not in BOTS:
        print(f"{author} is not a triaged bot — leaving #{PR_NUMBER} alone")
        return
    if pr["state"] != "open":
        print("not open")
        return

    files = gh.paged(f"/repos/{REPO}/pulls/{PR_NUMBER}/files")
    names = [f["filename"] for f in files]
    print(f"#{PR_NUMBER} by {author}: {names}")

    noise = triage.is_known_noise(names)
    if noise:
        close_with(PR_NUMBER,
                   f"**Closed automatically — known-noise class.**\n\n{noise}\n\n"
                   f"This exact change has been proposed many times. The underlying defect is fixed "
                   f"on `main`, and CI now reproduces the environment it needed (a global "
                   f"`core.hooksPath`), so a regression would fail the `hermeticity` check rather "
                   f"than go unnoticed.\n\n"
                   f"If you believe this PR does something different, say so and it will be reopened."
                   + AGENT_GUIDANCE)
        print("closed: known noise")
        return

    key = triage.dup_key(names)
    for other in gh.paged(f"/repos/{REPO}/pulls?state=open&sort=created&direction=asc"):
        if other["number"] >= PR_NUMBER or other["user"]["login"] != author:
            continue
        other_files = [f["filename"] for f in gh.paged(f"/repos/{REPO}/pulls/{other['number']}/files")]
        if triage.dup_key(other_files) == key:
            close_with(PR_NUMBER,
                       f"**Closed automatically — duplicate of #{other['number']}.**\n\n"
                       f"Both change exactly `{', '.join(sorted(key))}`. Matched on changed files "
                       f"rather than title, since the same change gets worded differently each "
                       f"attempt.\n\nContinue the work in #{other['number']}." + AGENT_GUIDANCE)
            print(f"closed: duplicate of #{other['number']}")
            return

    verdict, reason = triage.verdict(author, pr["title"], files)
    if verdict == "hold":
        label(PR_NUMBER, "needs-human", "B60205", "Bot PR held for human review by the merge gate")
        print(f"labelled needs-human: {reason}")
    else:
        print(f"eligible for auto-merge once CI is green: {reason}")


if __name__ == "__main__":
    main()

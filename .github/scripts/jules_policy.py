"""Policy for Google Jules pull requests — pure functions, stdlib only, no network, no clock.

Which routines exist and what each may work on, what is noise, what is a duplicate, what was
already declined, when the review queue is full, and what may merge without a human.

Three consumers pass it data:
  * .jules/preflight.py           — before Jules works (cooperative: no work → STOP)
  * .github/scripts/bot_triage.py — when a Jules PR opens (authoritative: close or label)
  * .github/scripts/auto_merge.py — after CI is green (through triage.verdict, the merge gate)

Ported from TestGuard's .github/scripts/jules-policy.mjs (raccioly/testguard#207). Two websec
lessons are encoded on top of it:
  * 69 Jules PRs in 60 days merged 0, and declined ideas kept coming back (crypto_usage ~9 times).
    The declined check and the queue cap exist for that.
  * #187, a real fix touching only AGENTS.md, was closed as a "duplicate" of #185, a count sync
    touching only AGENTS.md. A shared, high-traffic file does not identify a change, so it is not
    part of the duplicate key.

The default is HOLD. Every merge rule is an allowlist; a wrongly held PR costs a click, a wrongly
merged one ships to PyPI through the release train.
"""

from __future__ import annotations

import datetime as _dt
import re

JULES_LOGIN = "google-labs-jules[bot]"

# Open Jules PRs that may wait for review before new ones are closed unread.
QUEUE_CAP = 5

# A Jules PR closed unmerged this recently blocks the same work being re-proposed.
DECLINE_WINDOW_DAYS = 60

LABELS = {
    "noise": "jules-noise",
    "duplicate": "jules-duplicate",
    "declined": "jules-previously-declined",
    "queue_full": "jules-queue-full",
    "review": "jules-review",
    "eligible": "jules-automerge-eligible",
}

# Weekly routines. Each one's target list comes from the repository (see preflight), never memory.
ROUTINES = ("fn-hunt", "fp-hunt", "docs-drift")

# Files whose churn does not make two changes different.
BOOKKEEPING = frozenset({"CHANGELOG.md", ".websec-ignore", ".docguardignore"})

# Files so many unrelated changes touch that sharing them says nothing about sameness (#187/#185).
SHARED = frozenset({
    "AGENTS.md", "CLAUDE.md", "README.md", "BENCHMARKS.md", "CONTRIBUTING.md",
    "docs/security-review/backlog-reconciliation.md",
    "tests/test_pentest_regressions.py",   # the shared regression module most fixes append to
})


def is_jules(login) -> bool:
    login = str(login or "").lower()
    return login.removeprefix("app/") in (JULES_LOGIN, "google-labs-jules")


_TAG = re.compile(r"^\[jules:([a-z0-9-]+)\]\s+(\S+)")


def parse_tag(title):
    """`[jules:fp-hunt] crypto_usage — two FPs` → ('fp-hunt', 'crypto_usage'), else None."""
    m = _TAG.match(str(title or "").strip())
    return (m.group(1), m.group(2)) if m and m.group(1) in ROUTINES else None


def tag_title(routine: str, target: str) -> str:
    return f"[jules:{routine}] {target}"


def _names(files) -> list:
    return [f["filename"] if isinstance(f, dict) else f for f in files]


def dup_key(filenames) -> frozenset:
    """The file set that identifies a change: bots word one change many ways, the files do not move.
    Bookkeeping and shared high-traffic files are excluded; an empty key identifies nothing."""
    return frozenset(f for f in filenames if f not in BOOKKEEPING and f not in SHARED)


def is_doc_path(f: str) -> bool:
    """Prose a bot may change without a human: the user docs, not the rules or the records.
    docs-canonical/ is design intent, specs/ is the contract, docs/security-review/ binds evidence."""
    return f == "README.md" or (f.startswith("docs/") and f.endswith(".md")
                                and not f.startswith("docs/security-review/"))


_PERSONA = re.compile(r"(?:^|\s|\])(?:🛡️|⚡|🎨)|\b(?:sentinel|bolt|palette)\s*:", re.I)
_NO_OP = re.compile(r"\b(?:no (?:changes?|action|issues?|updates?) (?:needed|required|found)"
                    r"|(?:already|is|are) up[- ]to[- ]date|nothing to (?:do|change|fix|update)"
                    r"|verif(?:y|ied|ying) (?:test )?stability)\b", re.I)
_COUNT_SYNC = re.compile(r"\b(?:sync|update|bump|refresh|fix|correct)\b.{0,50}?"
                         r"\b(?:test )?(?:counts?|metrics?|numbers?|totals?)\b", re.I)


def noise_reason(title, files):
    """Classes that are reliably regenerated noise. Returns a reason, or None."""
    names = _names(files)
    if not names:
        return "it changes no files: a status report is a task summary, not a pull request"
    if _PERSONA.search(title or ""):
        return ("it comes from a built-in Jules persona (Sentinel, Bolt, Palette), which is not "
                "enabled for this repository")
    if _NO_OP.search(title or ""):
        return "its title reports that nothing needed changing"
    if all(n.startswith(".jules/") for n in names):
        return ("it changes only `.jules/`, the routines that steer Jules; those change through a "
                "maintainer")
    if _COUNT_SYNC.search(title or "") and all(n.endswith(".md") for n in names):
        return ("it syncs a count or metric in prose; counts change with every merge, the docs "
                "checks own the ones that matter, and AGENTS.md says not to record them")
    if frozenset(names) - BOOKKEEPING == frozenset({"tests/test_hooks.py"}):
        return ("a test_hooks.py-only change: the defect behind it (bug-217, a suite not hermetic "
                "against an ambient core.hooksPath) is fixed on main, and CI's `hermeticity` job "
                "reproduces that environment")
    return None


def _when(value) -> _dt.datetime:
    return _dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _days_between(a, b) -> float:
    return abs((_when(a) - _when(b)).total_seconds()) / 86400


def _labelled(pr, name) -> bool:
    return any((label.get("name") if isinstance(label, dict) else label) == name
               for label in (pr.get("labels") or []))


def same_work(a, b) -> bool:
    """The same routine target, or the same identifying file set."""
    ta, tb = parse_tag(a.get("title")), parse_tag(b.get("title"))
    if ta and tb and ta == tb:
        return True
    ka, kb = dup_key(_names(a.get("files") or [])), dup_key(_names(b.get("files") or []))
    return bool(ka) and ka == kb


def _declined(pr, now) -> bool:
    """Closed without merging, recently, by a judgement about the work. A PR closed only because the
    queue was full, or because it was noise, says nothing about whether the work is wanted."""
    return (not pr.get("merged_at") and bool(pr.get("closed_at"))
            and _days_between(pr["closed_at"], now) <= DECLINE_WINDOW_DAYS
            and not _labelled(pr, LABELS["queue_full"]) and not _labelled(pr, LABELS["noise"]))


def _waiting(open_prs) -> int:
    return sum(1 for o in open_prs if not _labelled(o, LABELS["queue_full"]))


def triage(pr, open_prs, closed_prs, now, merge_verdict):
    """Decide what happens to a Jules PR the moment it opens.

    pr             {number, title, files}
    open_prs       other OPEN Jules PRs: {number, title, files, labels}
    closed_prs     recently closed Jules PRs: {number, title, files, labels, merged_at, closed_at}
    now            ISO timestamp — passed in; the policy reads no clock
    merge_verdict  callable(files) -> (verdict, reason): the merge gate, for a preview label only

    → {action: 'close'|'keep', label, reason, ref?}
    """
    noise = noise_reason(pr.get("title"), pr.get("files") or [])
    if noise:
        return {"action": "close", "label": LABELS["noise"], "reason": noise}

    others = [o for o in open_prs if o["number"] != pr["number"]]
    older = sorted((o for o in others if o["number"] < pr["number"] and same_work(o, pr)),
                   key=lambda o: o["number"])
    if older:
        ref = older[0]["number"]
        return {"action": "close", "label": LABELS["duplicate"], "ref": ref,
                "reason": f"it is the same work as #{ref}, which is still open"}

    declined = sorted((c for c in closed_prs if _declined(c, now) and same_work(c, pr)),
                      key=lambda c: -c["number"])
    if declined:
        ref = declined[0]["number"]
        return {"action": "close", "label": LABELS["declined"], "ref": ref,
                "reason": (f"the same work was closed without merging in #{ref} within the last "
                           f"{DECLINE_WINDOW_DAYS} days")}

    waiting = _waiting(others)
    if waiting >= QUEUE_CAP:
        return {"action": "close", "label": LABELS["queue_full"],
                "reason": (f"{waiting} Jules PRs are already waiting for review (cap {QUEUE_CAP}); "
                           f"the work is not lost, the routine proposes it again once the queue "
                           f"drains")}

    # A preview only: auto_merge.py re-decides on the immutable base...head once CI is green.
    verdict, reason = merge_verdict(pr.get("files") or [])
    label = LABELS["eligible"] if verdict == "merge" else LABELS["review"]
    return {"action": "keep", "label": label, "reason": reason}


def iso_week(iso) -> int:
    return _when(iso).isocalendar()[1]


def pick_target(routine, candidates, open_prs, closed_prs, now):
    """The work a routine has been given this week, or why it has none.

    Deterministic for a week: the rotation starts at the ISO week number and skips every target
    that is open, or was declined in the window, for the same routine.
    → {go: True, target} | {go: False, reason}
    """
    if routine not in ROUTINES:
        return {"go": False, "reason": f'unknown routine "{routine}"; known: {", ".join(ROUTINES)}'}
    waiting = _waiting(open_prs)
    if waiting >= QUEUE_CAP:
        return {"go": False, "reason": f"the review queue is full: {waiting} Jules PRs are waiting (cap {QUEUE_CAP})"}
    if not candidates:
        return {"go": False, "reason": "the routine has no candidate targets"}
    taken = set()
    for p in list(open_prs) + [c for c in closed_prs if _declined(c, now)]:
        tag = parse_tag(p.get("title"))
        if tag and tag[0] == routine:
            taken.add(tag[1])
    start = iso_week(now) % len(candidates)
    for i in range(len(candidates)):
        target = candidates[(start + i) % len(candidates)]
        if target not in taken:
            return {"go": True, "target": target}
    return {"go": False, "reason": (f"every {routine} target is already open or was declined in the "
                                    f"last {DECLINE_WINDOW_DAYS} days")}

"""Password-policy consistency extractor — cross-route drift (PTREQ0013000 #6).

The finding the pen test caught: one route (`change-password`) enforced 5 character classes
(min length + upper + lower + digit + special) while sibling routes (`createUser`, `updateProfile`)
enforced only a weak subset. No single-rule scanner finds this — the bug is *relative*: a strong
policy in one place proves the weaker siblings are a regression, not an intentional design.

So we fingerprint the {min, upper, lower, digit, special} requirement set of every password-
validating block and flag any block whose set is a STRICT SUBSET of the strongest block found.
That subset comparison is the load-bearing logic a per-file linter structurally cannot express.

Honest scope (matches the case study caveat): this targets the WU drift shape — co-locatable
Zod/Joi/yup/express-validator/class-validator blocks on a `password`-named field with lookahead-
required classes (`(?=.*[A-Z])`) or explicit min*/isStrongPassword options. A policy centralized
behind a helper, or expressed as an allowed-char set rather than a requirement, degrades it. It
catches the WU regression well; it is NOT a general "is this policy strong" oracle.
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext

PW_FIELD = re.compile(r"\b(?:password|passwd|pwd|newPassword|new_password|currentPassword)\b", re.I)
# a window only counts as a *policy* block if it actually validates (not just references the field)
VALIDATION_SIGNAL = re.compile(
    r"\.min\(|minLength|\.matches\(|\.regex\(|\.pattern\(|RegExp|isStrongPassword|@MinLength|@Matches"
    r"|\.length\s*[<>=]|\bjoi\b|\bzod\b|\byup\b|z\.string|Joi\.|express-validator|body\(|check\(", re.I)

# character-class REQUIREMENT signals. Lookahead `(?=.*[A-Z])` is the canonical "require this class"
# idiom and is unambiguous; we also read express-validator option counts and explicit min length.
_LA = r"\(\?=[^)]{0,40}"
_RE_MIN = re.compile(r"\.min\(\s*(\d{1,3})|minLength\s*[:=]\s*(\d{1,3})|@MinLength\(\s*(\d{1,3})"
                     r"|\.length\s*>=?\s*(\d{1,3})|\{\s*(\d{1,3})\s*,")
_RE_UPPER = re.compile(_LA + r"\[[^\]]*A-Z|minUppercase\s*:\s*[1-9]|requireUppercase\s*[:=]\s*true", re.I)
_RE_LOWER = re.compile(_LA + r"\[[^\]]*a-z|minLowercase\s*:\s*[1-9]|requireLowercase\s*[:=]\s*true", re.I)
_RE_DIGIT = re.compile(_LA + r"(?:\\d|\[[^\]]*0-9)|minNumbers\s*:\s*[1-9]|requireDigit\s*[:=]\s*true", re.I)
_RE_SPECIAL = re.compile(_LA + r"(?:\\W|\[\^[A-Za-z0-9\\w]|\[[^\]]*[!@#$%^&*])|minSymbols\s*:\s*[1-9]"
                         r"|require[_]?Symbol", re.I)
_RE_STRONG = re.compile(r"isStrongPassword", re.I)

_ALL = ("min", "upper", "lower", "digit", "special")


def _classes(window: str) -> set:
    """The character-class requirement set enforced in one validation window."""
    if _RE_STRONG.search(window):
        return set(_ALL)                       # express-validator default: all 5 classes
    s = set()
    if _RE_MIN.search(window):
        s.add("min")
    if _RE_UPPER.search(window):
        s.add("upper")
    if _RE_LOWER.search(window):
        s.add("lower")
    if _RE_DIGIT.search(window):
        s.add("digit")
    if _RE_SPECIAL.search(window):
        s.add("special")
    return s


class PolicyConsistencyExtractor(Extractor):
    name = "password_policy"
    category = "authn"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        blocks = []        # (file, frozenset(classes))
        seen = set()
        for _p, rel, text in ctx.iter_code():
            if not PW_FIELD.search(text):
                continue
            # FORWARD-only window, capped at the next password field — validation follows the field
            # name in Zod/Joi/express-validator (`password: z.string().min()…`), so reading backward (or
            # past a sibling) would bleed an adjacent validator's classes and mask the drift. (Trade-off:
            # class-validator decorators written BEFORE the field aren't captured — a noted gap.)
            positions = [mm.start() for mm in PW_FIELD.finditer(text)]
            for i, pos in enumerate(positions):
                nxt = positions[i + 1] if i + 1 < len(positions) else len(text)
                window = text[pos: min(pos + 320, nxt)]
                if not VALIDATION_SIGNAL.search(window):
                    continue
                cls = _classes(window)
                if not cls:
                    continue
                key = (rel, frozenset(cls))
                if key in seen:
                    continue
                seen.add(key)
                blocks.append({"file": rel, "classes": sorted(cls, key=_ALL.index)})
                if len(blocks) >= 40:
                    break

        drift, strongest = [], []
        weak_policy = None
        distinct = {frozenset(b["classes"]) for b in blocks}
        if len(blocks) >= 2 and len(distinct) >= 2:
            smax = max((frozenset(b["classes"]) for b in blocks), key=len)
            strongest = sorted(smax, key=_ALL.index)
            if len(smax) >= 3:                 # there IS a real policy to be inconsistent with
                for b in blocks:
                    cs = frozenset(b["classes"])
                    if cs < smax:              # STRICT subset → weaker sibling = regression
                        drift.append({"file": b["file"], "enforces": b["classes"],
                                      "strongest_enforces": strongest})
        elif blocks:
            smax = max((frozenset(b["classes"]) for b in blocks), key=len)
            strongest = sorted(smax, key=_ALL.index)
            if len(smax) < 3:
                weak_policy = strongest

        return {
            "password_blocks": blocks[:20],
            "strongest_policy": strongest,
            "drift": drift,                    # MEDIUM in findings.py — inconsistent siblings (#6)
            "weak_policy": weak_policy,        # LOW — uniformly weak, no strong sibling to compare
            "consistent": not drift,
            "note": ("Password-policy DRIFT: a sibling route enforces fewer character classes than the "
                     "strongest one found — align them (the WU #6 regression). " if drift else
                     "" if not blocks else
                     "Single/uniform password policy detected; no cross-route drift. ")
                    + "Heuristic over Zod/Joi/express-validator lookahead-required classes — verify against "
                      "the actual validators; a helper-centralized policy can hide here.",
        }

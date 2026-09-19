"""PII output-boundary extractor — unmasked customer data in API responses (REF-PENTEST #8).

Two high-signal static tells the retest taught us:

1. **Dead security control.** A masking helper / `view_full`-style permission EXISTS in the codebase
   but has ZERO call sites in the live request handlers — it was wired only into offline export paths.
   A control defined-but-never-called is worse than none (it reads as "handled"). This is very
   distinctive and cheap to find: collect `mask*/redact*/canViewFull*` definitions, count live (non-
   test) call sites, flag the ones with none.

2. **Raw entity to the client.** A controller does `res.json(entity)` on a raw ORM/repo object that
   carries PII fields, with no DTO/serializer/masker — so phone/email ship in cleartext, *including*
   indirect carriers (a phone embedded in a composed `providerMessageId`, a denormalized `lastMessage`).
   The decisive verification is **value-shape, not field-name** — a field allow-list misses the
   indirect carriers — so the probe asserts no phone/email *value* reaches a non-privileged caller.
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext, is_test_file
from .syntax import call_expression, in_literal, js_functions, split_arguments, without_comments

# helper/permission DEFINITIONS (function/arrow/def) — not variable assignments to a call result
MASK_DEF = re.compile(
    r"(?:function\s+|export\s+(?:async\s+)?function\s+|def\s+)"
    r"(mask\w+|redact\w+|canViewFull\w+|scrub\w+|anonymi[sz]e\w+|toPublic\w+|sanitize\w*Pii)\b"
    r"|(?:const|let|export\s+const)\s+(mask\w+|redact\w+|canViewFull\w+|toPublic\w+)\s*=\s*(?:async\s*)?\(", re.I)
# PII field mentions that are NOT a customer-PII value in the response — a schema validator, a type
# declaration, or the CALLER's own audit identity. Blanked before the raw-entity check (value-shape,
# not field-name — the tool's own stated discipline, applied to its detection).
PII_NONCARRIER = re.compile(
    r"z\.string\(\)(?:\.\w+\([^)]*\))*\.email|\.email\(\)|email:\s*z\.|(?:joi|yup|zod)\b[^;\n]*email"
    r"|actor[_-]?email|performed[_-]?by[_-]?email|(?:req|request|ctx|session|token|payload)\.(?:user|auth|claims)\s*\??\.\s*email"
    r"|currentUser\s*\.\s*email|createdBy[_-]?email|updatedBy[_-]?email"
    r"|\bemail\s*:\s*(?:z|Joi|yup|t)\.|@IsEmail|IsEmail\(|email\(\)\.(?:optional|required|min|max)", re.I)
PII_FIELD = re.compile(r"\b(?:phone|phoneNumber|msisdn|mobile|email|emailAddress|ssn|socialSecurity"
                       r"|dob|dateOfBirth|birthDate|creditCard|cardNumber|taxId|nationalId)\b", re.I)
# returning a raw variable / a fresh ORM read straight to the client
RES_RAW = re.compile(r"res\.(?:json|send)\s*\(\s*(?:await\s+)?[A-Za-z_$][\w$]*\s*\)"
                     r"|res\.(?:json|send)\s*\(\s*await\s+[\w.]+\.(?:find|findOne|findById|findAll|get|query)\s*\(")
MASK_CALL_NEAR = re.compile(r"mask\w+\(|redact\w+\(|toPublic\w+\(|canViewFull\w+\(|\.serialize\(|toDto\(|\bDTO\b|pick\(", re.I)
TESTFILE = re.compile(r"(?:^|/)(?:tests?|__tests__|spec)/|\.(?:test|spec)\.", re.I)
# A helper that masks a SECRET (connection string / password / token), not customer PII — wrong
# category, and "defined but unused" on it is at most a lint nit. Excluded from the PII dead-control.
SECRET_MASKER = re.compile(r"(?:mask|redact|scrub)\w*(?:Url|Uri|Dsn|Database|Conn|Connection|Secret|Password|Passwd|Token|Key|Cred)\w*", re.I)
# inline object-projection (`.map(x => ({...}))` / a returned object literal) IS a serializer — a
# raw-entity finding on a file that projects fields before responding is a false positive.
def _projected_binding(code: str, position: int, argument: str, scopes: list[dict]) -> bool:
    """Recognize a local explicit object projection used only by this response.

    Aliases, spreads, mutation, nested bindings and unknown calls remain review
    leads. This proves a small projection idiom, not authorization or PII policy.
    """
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", argument):
        return False
    containing = [scope for scope in scopes if scope["body_start"] <= position < scope["end"]]
    if not containing:
        return False
    scope = min(containing, key=lambda row: row["end"] - row["body_start"])
    if not scope.get("complete", True):
        return False
    body = code[scope["body_start"]:scope["end"]]
    name = re.escape(argument)
    if len(re.findall(r"\b" + name + r"\b", body)) != 2:
        return False
    prefix = code[scope["body_start"]:position]

    # Destructuring rest parameter: const { email, ...safeProfile } = user;
    destruct_match = re.search(r"\b(?:const|let)\s*\{\s*([^}]*?)\.\.\.\s*" + name + r"\s*\}\s*=\s*[^;]+;", prefix)
    if destruct_match:
        destructured_fields = [f.strip() for f in destruct_match.group(1).split(",") if f.strip()]
        if any(PII_FIELD.search(f) for f in destructured_fields):
            return True

    # Lodash omit equivalent: const safeAdmin = omit(admin, ['ssn', 'email']);
    omit_match = re.search(r"\b(?:const|let)\s+" + name + r"\s*=\s*(?:_\.)?omit\s*\([^,]+,\s*\[(.*?)\]\s*\)", prefix)
    if omit_match and bool(PII_FIELD.search(omit_match.group(1))):
        return True

    # Lodash pick equivalent: const safeAdmin = pick(admin, ['id', 'name']);
    pick_match = re.search(r"\b(?:const|let)\s+" + name + r"\s*=\s*(?:_\.)?pick\s*\([^,]+,\s*\[(.*?)\]\s*\)", prefix)
    if pick_match and not bool(PII_FIELD.search(pick_match.group(1))):
        return True

    # Array map destructuring: const safe = arr.map(({ pii, ...rest }) => rest)
    map_destruct_match = re.search(r"\b(?:const|let)\s+" + name + r"\s*=\s*[\w$.]+\.map\s*\(\s*\(\s*\{\s*([^}]*?)\.\.\.\s*([A-Za-z_$][\w$]*)\s*\}\s*\)\s*=>\s*\2\s*\)\s*;", prefix)
    if map_destruct_match:
        destructured_fields = [f.strip() for f in map_destruct_match.group(1).split(",") if f.strip()]
        if any(PII_FIELD.search(f) for f in destructured_fields):
            return True

    # Map projection to object literal: const safe = arr.map(u => ({ id: u.id }))
    map_binding = re.search(r"\b(?:const|let)\s+" + name + r"\s*=\s*[\w$.]+\.map\s*\(\s*(?:[^)]+)\s*=>\s*\(?\s*(\{[^{}]*\})\s*\)?\s*\)\s*;", prefix)
    binding = re.search(r"\bconst\s+" + name + r"\s*=\s*(\{[^{};]*\})\s*;\s*$", prefix)

    match_literal = map_binding or binding
    if not match_literal or in_literal(prefix, match_literal.start()):
        return False
    fields = split_arguments(match_literal.group(1)[1:-1])
    return bool(fields) and all(re.fullmatch(r"[\w$]+\s*:\s*[\w$.]+", field)
                               and not PII_FIELD.search(field) for field in fields)


class PiiExposureExtractor(Extractor):
    name = "pii_exposure"
    category = "exposure"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        texts = []
        helpers: dict = {}      # name -> def file
        for _p, rel, text in ctx.iter_code():
            texts.append((rel, text))
            for m in MASK_DEF.finditer(text):
                nm = m.group(1) or m.group(2)
                if nm and len(nm) > 4 and nm not in helpers:
                    helpers[nm] = rel

        findings = []

        # 1. dead masking/permission control — defined but no reference ANYWHERE (incl. its own file).
        # The old check excluded the definition file, so a masker wired into a singleton/formatter/CLI
        # or pipeline stage WITHIN its own module always read as dead (≈100% FP on real code). Now: a
        # reference beyond the definition (a call OR a value-pass like `log: redactX`) means wired.
        dead = []
        for nm, deffile in helpers.items():
            if SECRET_MASKER.search(nm):      # masks a secret, not PII — wrong category
                continue
            ref_rx = re.compile(r"\b" + re.escape(nm) + r"\b")
            refs = sum(len(ref_rx.findall(text)) for rel, text in texts if not is_test_file(rel))
            if refs <= 1:                     # only the definition itself → genuinely unused
                dead.append(nm)
                findings.append({"severity": "LOW", "kind": "dead-pii-control", "file": deffile,
                                 "detail": f"`{nm}` (a masking/PII-permission control) appears to have NO reference "
                                           "beyond its definition — possibly a security control that exists but isn't "
                                           "wired into the request handlers (REF-PENTEST #8). LOW: a same-module or "
                                           "value-passed wiring can read as unused — confirm it's actually dead before "
                                           "acting; if dead, apply it at the live output boundary or delete it."})

        # 2. raw entity with PII to the client, no masker/DTO in the handler
        raw_leaks = []
        for rel, text in texts:
            if is_test_file(rel):
                continue
            # A `phone`/`email` mention that is NOT customer-PII-in-a-response: a Zod/Joi/Yup validator,
            # a type/interface field decl, or the CALLER's own identity in audit metadata (actorEmail /
            # req.user.email / createdBy). Blank those out first, then require a REMAINING PII field — so a
            # Tag/Role/config entity that merely logs the actor's email no longer false-fires (the 76%
            # a real monorepo outlier: 5 non-PII entities flagged raw-entity-pii).
            scrubbed = PII_NONCARRIER.sub("  ", text)
            if not PII_FIELD.search(scrubbed):
                continue
            code = without_comments(text)
            scopes = js_functions(code)
            for response in RES_RAW.finditer(code):
                if len(raw_leaks) >= 30:
                    break
                if in_literal(code, response.start()):
                    continue
                expression = call_expression(code, response.start())
                argument = expression[expression.find("(") + 1:-1].strip()
                if not _projected_binding(code, response.start(), argument, scopes):
                    raw_leaks.append(rel)
                    findings.append({"severity": "MEDIUM", "kind": "raw-entity-pii-response", "file": rel,
                                     "line": code.count("\n", 0, response.start()) + 1,
                                     "control_scope": "response expression; unrelated controls unverified",
                                     "detail": "A handler returns a raw entity (`res.json(entity)`) in a file that "
                                               "handles PII fields; no supported projection is bound to this response. "
                                               "Review whether phone/email reach the caller. Mask at ONE output boundary (a DTO), gated by a "
                                               "permission. VERIFY BY VALUE SHAPE (no phone/email value in the JSON), "
                                               "not field name — indirect carriers (composed IDs, denormalized fields) "
                                               "leak too (the `providerMessageId`-embeds-the-phone class, #8)."})

        by_sev: dict = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        return {
            "findings": findings,
            "dead_controls": dead,
            "raw_pii_responses": raw_leaks,
            "masking_helpers": sorted(helpers.keys())[:20],
            "by_severity": by_sev,
            "note": ("PII output-boundary review: " + (f"{len(dead)} masking control(s) defined but unused; " if dead else "")
                     + (f"{len(raw_leaks)} handler(s) return a raw PII entity. " if raw_leaks else "no obvious raw-PII responses. ")
                     + "Probe with a per-role response diff asserting NO phone/email VALUE (/\\+?\\d{7,}/ or an email "
                       "regex) reaches a non-privileged caller — across nested objects, IDs, and exports (#8)."),
        }

"""PII output-boundary extractor — unmasked customer data in API responses (PTREQ0013000 #8).

Two high-signal static tells the retest taught us:

1. **Dead security control.** A masking helper / `view_full`-style permission EXISTS in the codebase
   but has ZERO call sites in the live request handlers — it was wired only into offline export paths.
   A control defined-but-never-called is worse than none (it reads as "handled"). This is very
   distinctive and cheap to find: collect `mask*/redact*/canViewFull*` definitions, count live (non-
   test) call sites, flag the ones with none.

2. **Raw entity to the client.** A controller does `res.json(entity)` on a raw ORM/repo object that
   carries PII fields, with no DTO/serializer/masker — so phone/email ship in cleartext, *including*
   indirect carriers (a phone embedded in a composed `messageBirdId`, a denormalized `lastMessage`).
   The decisive verification is **value-shape, not field-name** — a field allow-list misses the
   indirect carriers — so the probe asserts no phone/email *value* reaches a non-privileged caller.
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext

# helper/permission DEFINITIONS (function/arrow/def) — not variable assignments to a call result
MASK_DEF = re.compile(
    r"(?:function\s+|export\s+(?:async\s+)?function\s+|def\s+)"
    r"(mask\w+|redact\w+|canViewFull\w+|scrub\w+|anonymi[sz]e\w+|toPublic\w+|sanitize\w*Pii)\b"
    r"|(?:const|let|export\s+const)\s+(mask\w+|redact\w+|canViewFull\w+|toPublic\w+)\s*=\s*(?:async\s*)?\(", re.I)
PII_FIELD = re.compile(r"\b(?:phone|phoneNumber|msisdn|mobile|email|emailAddress|ssn|socialSecurity"
                       r"|dob|dateOfBirth|birthDate|creditCard|cardNumber|taxId|nationalId)\b", re.I)
# returning a raw variable / a fresh ORM read straight to the client
RES_RAW = re.compile(r"res\.(?:json|send)\s*\(\s*(?:await\s+)?[A-Za-z_$][\w$]*\s*\)"
                     r"|res\.(?:json|send)\s*\(\s*await\s+[\w.]+\.(?:find|findOne|findById|findAll|get|query)\s*\(")
MASK_CALL_NEAR = re.compile(r"mask\w+\(|redact\w+\(|toPublic\w+\(|canViewFull\w+\(|\.serialize\(|toDto\(|\bDTO\b|pick\(", re.I)
TESTFILE = re.compile(r"(?:^|/)(?:tests?|__tests__|spec)/|\.(?:test|spec)\.", re.I)


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

        # 1. dead masking/permission control — defined but no LIVE (non-test) call site
        dead = []
        for nm, deffile in helpers.items():
            callrx = re.compile(r"\b" + re.escape(nm) + r"\s*\(")
            live = sum(1 for rel, text in texts
                       if rel != deffile and not TESTFILE.search(rel) and callrx.search(text))
            if live == 0:
                dead.append(nm)
                findings.append({"severity": "HIGH", "kind": "dead-pii-control", "file": deffile,
                                 "detail": f"`{nm}` (a masking/PII-permission control) is defined but has NO live "
                                           "call site outside its own file/tests — a security control that exists but "
                                           "isn't wired into the request handlers (it was likely only on export/report "
                                           "paths). Apply it at the live API output boundary, or remove the false "
                                           "sense of safety (PTREQ0013000 #8)."})

        # 2. raw entity with PII to the client, no masker/DTO in the handler
        raw_leaks = []
        for rel, text in texts:
            if TESTFILE.search(rel):
                continue
            if PII_FIELD.search(text) and RES_RAW.search(text) and not MASK_CALL_NEAR.search(text):
                if len(raw_leaks) < 30:
                    raw_leaks.append(rel)
                    findings.append({"severity": "MEDIUM", "kind": "raw-entity-pii-response", "file": rel,
                                     "detail": "A handler returns a raw entity (`res.json(entity)`) in a file that "
                                               "handles PII fields, with no DTO/serializer/masker — phone/email likely "
                                               "ship in cleartext. Mask at ONE output boundary (a DTO), gated by a "
                                               "permission. VERIFY BY VALUE SHAPE (no phone/email value in the JSON), "
                                               "not field name — indirect carriers (composed IDs, denormalized fields) "
                                               "leak too (the `messageBirdId`-embeds-the-phone class, #8)."})

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

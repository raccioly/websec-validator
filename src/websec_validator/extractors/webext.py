"""WebExtension (Chrome/Firefox/Edge, MV2/MV3) extractor — the browser-extension client-trust surface.

An extension's popup / service-worker / content scripts run in the *user's own* browser, so anything
the extension ENFORCES there is user-editable, not a security boundary. The headline class:

  - client-side-entitlement : a paid tier/level/plan read from chrome.storage.local / localStorage and
                              used as a feature gate. The user can rewrite that value from the devtools
                              console, so the gate is a UI hint — every paid capability must ALSO be
                              enforced server-side.

Plus the two other recurring extension footguns:

  - excessive-permissions  : `<all_urls>` / `*://*/*` host access → the extension can read/modify every
                             site the user visits, so a compromise has all-web blast radius.
  - extension-message-trust: a `world:"MAIN"` content script (shares the page's JS world) or an
                             `onMessageExternal` listener with no sender validation (any page/extension
                             can invoke privileged handlers).

Deterministic, regex + JSON-parse only. Detect-by-behaviour, never by app name.
"""

from __future__ import annotations

import json
import re

from .base import Extractor, RepoContext
from .syntax import expression_end, guarded_body, in_literal, js_functions, split_arguments, without_comments

# extension storage a tier/plan can be (user-)read from
EXT_STORAGE = re.compile(r"chrome\.storage\.(?:local|sync|managed)|browser\.storage\.(?:local|sync)|\blocalStorage\b")
# a paid-tier / entitlement gate: a level/tier/plan value used in a comparison, or compared against a
# TIERS/PRO/PREMIUM constant. Matched as code (a comparison operator) so a prose mention doesn't fire.
ENTITLEMENT_GATE = re.compile(
    r"(?:userLevel|\.level|\btier\b|\bplan\b|\bentitlement)\s*[<>]=?"
    r"|[<>]=?\s*TIERS?\.|[<>]=?\s*(?:PRO|PREMIUM|PAID|PLUS)\b", re.I)
# the file is extension code (uses the extension API surface)
EXT_API = re.compile(r"\bchrome\.\w+|\bbrowser\.(?:runtime|storage|tabs)\b")
# an externally-reachable message listener (web pages / other extensions) — the real trust boundary
ON_MESSAGE_EXTERNAL = re.compile(r"\.onMessageExternal\.addListener")
# a host match pattern granting all-web access
BROAD_HOST = re.compile(r"<all_urls>|\*://\*/\*|https?://\*/\*")


def _sender_control(scope: dict) -> bool:
    if len(scope["params"]) < 2:
        return False
    sender = scope["params"][1]
    body = scope["body"]
    # A check on an earlier value does not authorize a replaced sender object.
    mutations = re.finditer(r"\b" + re.escape(sender) + r"(?:\.[\w$]+)?\s*(?:=(?!=)|\+\+|--)", body)
    if any(not in_literal(body, match.start()) for match in mutations):
        return False

    def predicate(condition):
        condition = condition.strip()

        inverted = False
        if condition.startswith("!"):
            inverted = True
            condition = condition[1:].strip()
            if condition.startswith("(") and condition.endswith(")"):
                condition = condition[1:-1].strip()

        # `sender?.origin` as well as `sender.origin`: optional chaining is the same read.
        # Deliberately NOT extended to local aliases (`const { origin } = sender`) — an alias can be
        # reassigned between the binding and the check, and crediting one would turn a missing
        # sender check into silence. Any extension needs a control proving a REASSIGNED alias is
        # still reported.
        sender_prop = re.escape(sender) + r"(?:\?)?\.(?:id|origin|url)"
        op = r"(===|!==|==|!=)"

        match1 = re.fullmatch(sender_prop + r"\s*" + op + r"\s*(['\"])([^'\"*\\$`]+)\2", condition)
        match2 = re.fullmatch(r"(['\"])([^'\"*\\$`]+)\1\s*" + op + r"\s*" + sender_prop, condition)

        if match1:
            operator = match1[1]
        elif match2:
            operator = match2[3]
        else:
            operator = None

        if operator:
            is_equality = (operator in {"===", "=="})
            if inverted:
                is_equality = not is_equality
            return 1 if is_equality else -1

        match3 = re.fullmatch(r"(!)?\s*(\[[^\[\]]+\])\.includes\(\s*" + sender_prop + r"\s*\)", condition)
        if match3:
            includes_inverted = bool(match3[1])
            if inverted:
                includes_inverted = not includes_inverted

            items = split_arguments(match3[2][1:-1])
            if items and all(re.fullmatch(r"(['\"])[^'\"*\\$`]+\1", item) for item in items):
                return -1 if includes_inverted else 1

        return 0

    return guarded_body(body, predicate)


def _external_listeners(text: str) -> list[tuple[int, bool]]:
    source = without_comments(text)
    scopes = js_functions(source)
    listeners = []
    for match in ON_MESSAGE_EXTERNAL.finditer(source):
        if in_literal(source, match.start()):
            continue
        opening = match.end()
        while opening < len(source) and source[opening].isspace():
            opening += 1
        if source[opening:opening+1] != "(":
            continue
        end = expression_end(source, opening, closing=")")
        argument = source[opening+1:end-1].strip()
        candidates = [scope for scope in scopes if opening < scope["start"] < end and scope["end"] <= end]
        if re.fullmatch(r"[\w$]+", argument):
            candidates = [scope for scope in scopes if scope["name"] == argument]
            # Named declarations are supported only without any later replacement.
            assignments = list(re.finditer(r"\b" + re.escape(argument) + r"\s*=(?!=)", source))
            replaced = any(not in_literal(source, item.start()) and not (
                len(candidates) == 1 and item.end() <= candidates[0]["start"]
                and source[item.end():candidates[0]["start"]].strip() in {"", "async"}
                and re.search(r"\b(?:const|let|var)\s*$", source[max(0, item.start()-20):item.start()]))
                for item in assignments)
            shadowed = any(scope["start"] < match.start() < scope["end"]
                           and (not scope["simple_params"] or argument in scope["params"])
                           for scope in scopes)
            destructured = re.finditer(r"\b(?:const|let|var)\s*[\[{][^;=]{0,500}\b"
                                       + re.escape(argument) + r"\b[^;=]{0,500}[\]}]\s*=", source)
            shadowed = shadowed or any(not in_literal(source, item.start()) for item in destructured)
            if replaced or shadowed:
                candidates = []
        else:
            # The callback must be the whole first argument, with no wrapper call.
            candidates = [scope for scope in candidates if not source[opening+1:scope["start"]].strip()
                          or source[opening+1:scope["start"]].strip() == "async"]
            candidates = [scope for scope in candidates if not source[scope["end"]:end-1].strip()]
        listeners.append((match.start(), len(candidates) == 1 and _sender_control(candidates[0])))
    return listeners


class WebExtExtractor(Extractor):
    name = "webext"
    category = "client-trust"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        manifests = [mf for mf in ctx.glob("**/manifest.json", 40) if '"manifest_version"' in ctx.text(mf)]
        findings: list = []
        permissions: list = []
        host_permissions: list = []
        mv = None
        main_world = False

        for mf in manifests:
            try:
                data = json.loads(ctx.text(mf))
            except Exception:
                continue
            mv = data.get("manifest_version", mv)
            permissions = list(data.get("permissions", []) or [])
            host_permissions = list(data.get("host_permissions", []) or [])
            # MV2 folds host match patterns into `permissions`; check both.
            all_hosts = host_permissions + [p for p in permissions if "://" in p or p == "<all_urls>"]
            broad = sorted({h for h in all_hosts if BROAD_HOST.search(h)})
            if broad:
                findings.append({
                    "severity": "MEDIUM", "confidence": "MEDIUM", "kind": "excessive-host-permissions",
                    "attack_class": "excessive-permissions", "file": ctx.rel(mf),
                    "detail": f"manifest requests broad host access ({', '.join(broad)}) — the extension can "
                              "read/modify EVERY site the user visits, so any compromise (supply-chain, an XSS in "
                              "the extension, a rogue update) has all-web blast radius. Narrow to the specific "
                              "origins it needs; prefer activeTab + optional_permissions with runtime prompts."})
            for cs in (data.get("content_scripts") or []):
                if cs.get("world") == "MAIN":
                    main_world = True
                    findings.append({
                        "severity": "LOW", "confidence": "MEDIUM", "kind": "content-script-main-world",
                        "attack_class": "extension-message-trust", "file": ctx.rel(mf),
                        "detail": f"a content script runs in world:\"MAIN\" (matches {cs.get('matches')}) — it shares "
                                  "the untrusted page's JS context, so extension-injected globals are reachable and "
                                  "tamperable by the page. Prefer the default ISOLATED world; use MAIN only for a "
                                  "narrow, audited page bridge, and never expose privileged capabilities through it."})

        gate_files: list = []
        message_leads: list = []
        for _p, rel, text in ctx.iter_code():
            if not EXT_API.search(text):
                continue
            if EXT_STORAGE.search(text) and ENTITLEMENT_GATE.search(text):
                gate_files.append(rel)
            for position, controlled in _external_listeners(text):
                if not controlled:
                    message_leads.append((rel, text.count("\n", 0, position) + 1))

        if gate_files:
            findings.append({
                "severity": "LOW", "confidence": "LOW", "kind": "client-side-entitlement-gate",
                "attack_class": "client-side-entitlement", "file": sorted(gate_files)[0],
                "detail": f"a paid-tier/entitlement value is read from client storage and used as a feature gate in "
                          f"{', '.join(sorted(set(gate_files))[:4])} — chrome.storage/localStorage is user-editable "
                          "(one line in the devtools console), so this gate is a UI hint, not enforcement. Confirm "
                          "every paid capability is ALSO enforced server-side (re-verify the license per request). A "
                          "feature that only runs in the browser can't be truly enforced — tie that tier's value to a "
                          "server-controlled benefit, or accept it as honor-system; don't sink time into client-side "
                          "obfuscation."})
        for rel, line in message_leads:
            findings.append({
                "severity": "MEDIUM", "confidence": "LOW", "kind": "unvalidated-external-message",
                "attack_class": "extension-message-trust", "file": rel, "line": line,
                "control_scope": "listener callback; unresolved controls require review",
                "detail": f"an onMessageExternal listener in {rel} has no supported enforcing sender allowlist "
                          "in its own callback — any web page or other extension allowed to message it can "
                          "invoke privileged handlers. Validate the sender against an allowlist and scope "
                          "externally_connectable narrowly. Named helpers, aliases and complex branches remain "
                          "unverified; this lead does not establish that validation is absent."})

        return {
            "is_extension": bool(manifests),
            "manifest_version": mv,
            "permissions": permissions,
            "host_permissions": host_permissions,
            "main_world_content_script": main_world,
            "client_entitlement_gates": sorted(set(gate_files)),
            "findings": findings,
            "note": ("WebExtension client-trust surface: a storage-read entitlement gate is a UI hint (enforce paid "
                     "features server-side); minimise host permissions, world:MAIN content scripts, and unvalidated "
                     "external message handlers." if manifests else
                     "No WebExtension manifest detected — extension client-trust class N/A."),
        }

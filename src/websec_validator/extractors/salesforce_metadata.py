"""Salesforce declarative metadata — the `salesforce-metadata` profile (#251).

Direct syntax only, on Flow (`*.flow-meta.xml`), Visualforce (`*.page`, `*.component`), Aura
markup (`aura/**/*.cmp`) and LWC JavaScript. Bounded regular expressions, no XML parser.

Checks:
  * flow-system-mode — a screen or auto-launched Flow that runs `SystemModeWithoutSharing` /
    `SystemModeWithSharing`; HIGH when it also deletes or updates records.
  * flow-screen-input-dml — a record delete/update/create whose filter or assignment references a
    screen input field, with no decision element in the Flow.
  * flow-hardcoded-id — a literal 15/18-character record ID with a known key prefix (LOW).
  * flow-literal-credential — a literal string in a variable or input named like a key/token/
    secret/password.
  * vf-unescaped-output — `escape="false"` on `apex:outputText`, or `{!...}` inside `<script>`
    without JSENCODE.
  * aura-unescaped-html — `<aura:unescapedHtml value="{!...}">`, and LWC `lwc:dom="manual"` with an
    `innerHTML =` assignment in the component's JavaScript.
  * lwc-apex-entry — every `import x from '@salesforce/apex/Class.method'`: one server entry point.
"""
from __future__ import annotations

import re

_RUN_MODE = re.compile(r"<runInMode>\s*(SystemModeWithoutSharing|SystemModeWithSharing)\s*</runInMode>")
_PROCESS = re.compile(r"<processType>\s*(\w+)\s*</processType>")
_DML = re.compile(r"<(recordDeletes|recordUpdates|recordCreates)>(.*?)</\1>", re.S)
_SCREEN_INPUT = re.compile(r"<fields>\s*(?:(?!</fields>).)*?<name>\s*(\w+)\s*</name>(?:(?!</fields>).)*?"
                           r"<fieldType>\s*InputField\s*</fieldType>", re.S)
_ELEMENT_REF = re.compile(r"<elementReference>\s*([\w.$]+)\s*</elementReference>")
_STRING_VALUE = re.compile(r"<stringValue>\s*([^<]*?)\s*</stringValue>")
_ID_PREFIXES = ("001", "003", "005", "006", "00G", "00Q", "00D", "00e", "012", "500", "701", "800", "801", "a0", "a1")
_SECRET_NAME = re.compile(r"key|token|secret|password|passwd|apikey|credential", re.I)
_NAMED_VALUE = re.compile(r"<(variables|inputParameters|inputAssignments|constants)>(.*?)</\1>", re.S)
_VF_UNESCAPED = re.compile(r"<apex:outputText\b[^>]*\bescape\s*=\s*[\"']false[\"'][^>]*>", re.I | re.S)
_VF_SCRIPT = re.compile(r"<script\b[^>]*>(.*?)</script>", re.I | re.S)
_AURA_UNESCAPED = re.compile(r"<aura:unescapedHtml\b[^>]*\bvalue\s*=\s*[\"']\{![^\"']*\}[\"']", re.I)
_APEX_IMPORT = re.compile(r"""import\s+(\w+)\s+from\s+['"]@salesforce/apex/([\w]+)\.([\w]+)['"]""")


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _row(rule, line, attack, severity, confidence, cwe, title, evidence, remediation, limitation):
    return {"rule_id": rule, "line": line, "attack_class": attack, "severity": severity, "confidence": confidence,
            "cwe": cwe, "title": title, "evidence": evidence, "remediation": remediation, "limitations": [limitation]}


def _record_id(value: str) -> bool:
    return bool(re.fullmatch(r"[a-zA-Z0-9]{15}(?:[a-zA-Z0-9]{3})?", value)) and value.startswith(_ID_PREFIXES) \
        and bool(re.search(r"\d", value[3:])) and bool(re.search(r"[A-Za-z]", value[3:]))


def analyze_flow(text: str, rel: str) -> list:
    rows = []
    mode = _RUN_MODE.search(text)
    process = (_PROCESS.search(text) or [None, ""])[1]
    writes = [m for m in _DML.finditer(text) if m[1] in ("recordDeletes", "recordUpdates")]
    if mode and process in ("Flow", "AutoLaunchedFlow", "FieldServiceMobile", "Survey", "CheckoutFlow"):
        severity = "HIGH" if writes and mode[1] == "SystemModeWithoutSharing" else "MEDIUM"
        rows.append(_row("flow-system-mode", _line(text, mode.start()), "missing-auth", severity, "MEDIUM", "CWE-862",
                         f"Flow runs in {mode[1]}" + (" and deletes or updates records" if writes else ""),
                         f"<runInMode>{mode[1]}</runInMode>, processType {process}",
                         "Run the Flow in user context, or check the running user's access to each record "
                         "before the delete/update.",
                         "Who can launch the Flow (profiles, Experience sites, invocable callers) is not resolved."))
    inputs = set(_SCREEN_INPUT.findall(text))
    if inputs and "<decisions>" not in text:
        for dml in _DML.finditer(text):
            refs = {ref.split(".")[0] for ref in _ELEMENT_REF.findall(dml[2])}
            used = sorted(refs & inputs)
            if used:
                name = (re.search(r"<name>\s*(\w+)\s*</name>", dml[2]) or [None, dml[1]])[1]
                rows.append(_row("flow-screen-input-dml", _line(text, dml.start()), "bola",
                                 "HIGH" if mode and mode[1] == "SystemModeWithoutSharing" else "MEDIUM", "MEDIUM",
                                 "CWE-639", f"Flow element {name} uses screen input {', '.join(used)} in a record operation",
                                 f"{dml[1]} {name} references screen InputField {', '.join(used)} with no decision element",
                                 "Check that the running user may act on the record the input names before the "
                                 "operation.", "Validation in subflows or invocable actions is not followed."))
    for match in _STRING_VALUE.finditer(text):
        if _record_id(match[1]):
            rows.append(_row("flow-hardcoded-id", _line(text, match.start()), "hardcoded-reference", "LOW", "MEDIUM",
                             "CWE-547", "Flow uses a hard-coded record ID", f"stringValue {match[1][:5]}… (record ID)",
                             "Look the record up by a stable key (DeveloperName, custom metadata) instead.",
                             "Key prefixes are matched by pattern; the ID is not resolved."))
    for block in _NAMED_VALUE.finditer(text):
        name = (re.search(r"<(?:name|field)>\s*([\w.]+)\s*</(?:name|field)>", block[2]) or [None, ""])[1]
        value = _STRING_VALUE.search(block[2])
        if name and value and _SECRET_NAME.search(name) and len(value[1]) >= 8 and not value[1].startswith(("{!", "$")):
            rows.append(_row("flow-literal-credential", _line(text, block.start()), "secret", "HIGH", "MEDIUM", "CWE-798",
                             f"Flow stores a literal value in {name}", f"{block[1]} {name} has a literal stringValue (not shown)",
                             "Use Named Credentials or protected custom metadata, and rotate the value.",
                             "Whether the value is live is not verified."))
    return rows


def analyze_visualforce(text: str, rel: str) -> list:
    rows = []
    for match in _VF_UNESCAPED.finditer(text):
        tag = match[0]
        request = "$CurrentPage.parameters" in tag
        rows.append(_row("vf-unescaped-output", _line(text, match.start()), "xss", "HIGH" if request else "MEDIUM",
                         "HIGH" if request else "MEDIUM", "CWE-79", "Visualforce output with escape=\"false\"",
                         re.sub(r"\s+", " ", tag)[:160], "Remove escape=\"false\", or encode with HTMLENCODE.",
                         "Controller property provenance is not traced."))
    for script in _VF_SCRIPT.finditer(text):
        for merge in re.finditer(r"\{!\s*([^}]*)\}", script[1]):
            if re.match(r"\s*(?:JSENCODE|JSINHTMLENCODE)\s*\(", merge[1], re.I):
                continue
            rows.append(_row("vf-unescaped-output", _line(text, script.start(1) + merge.start()), "xss", "MEDIUM",
                             "MEDIUM", "CWE-79", "Visualforce merge field inside <script> without JSENCODE",
                             "{!" + merge[1][:80] + "}", "Wrap the merge field in JSENCODE().",
                             "Values that are numeric or system-generated are not distinguished."))
    return rows


def analyze_aura(text: str, rel: str) -> list:
    return [_row("aura-unescaped-html", _line(text, match.start()), "xss", "MEDIUM", "MEDIUM", "CWE-79",
                 "Aura markup renders unescaped HTML", re.sub(r"\s+", " ", match[0])[:160],
                 "Render text with {!v.x} (escaped), or sanitize the HTML before it is set.",
                 "Where the attribute value comes from is not traced.")
            for match in _AURA_UNESCAPED.finditer(text)]


def lwc_apex_links(text: str, rel: str) -> list:
    return [{"file": rel, "line": _line(text, m.start()), "local": m[1], "apex_class": m[2], "method": m[3]}
            for m in _APEX_IMPORT.finditer(text)]


def lwc_manual_dom(template: str, script: str, rel: str) -> list:
    if 'lwc:dom="manual"' not in template.replace("'", '"'):
        return []
    match = re.search(r"\.innerHTML\s*=(?!=)", script)
    if not match:
        return []
    return [_row("aura-unescaped-html", _line(script, match.start()), "xss", "MEDIUM", "MEDIUM", "CWE-79",
                 "LWC manual DOM assigns innerHTML", "lwc:dom=\"manual\" with an innerHTML assignment",
                 "Build nodes with textContent, or sanitize the HTML first.",
                 "Where the assigned value comes from is not traced.")]

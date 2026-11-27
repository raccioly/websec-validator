"""Salesforce Apex — direct-syntax checks for the `salesforce-apex` profile (#246).

Apex was walked past in silence: `.cls`/`.trigger` were neither read nor listed as unanalysed, so a
Salesforce project reported COMPLETED. Files are recognised as Apex only in a Salesforce DX context
(`sfdx-project.json` above them, a `force-app/` path, or a `-meta.xml` sibling), because `.cls` is
also a LaTeX class file.

Checks, each bounded to direct syntax in one file:
  * apex-soql-injection — `Database.query/countQuery/getQueryLocator`, `Search.query` with a
    concatenated non-constant operand (a `String.escapeSingleQuotes(...)` operand is treated as
    escaped). HIGH when the operand is a parameter of an exposed method.
  * apex-without-sharing-entrypoint — a `without sharing` class exposing `@AuraEnabled`,
    `@RemoteAction`, `@InvocableMethod`, `webservice` or `@RestResource` methods.
  * apex-crud-fls — an exposed method running SOQL or DML with no user-mode / security-enforced /
    stripInaccessible / describe-check anywhere in the class.
Exposed methods are reported as entry points, not routes: the platform authenticates them, and
their authorization is the sharing/CRUD/FLS question the checks above ask.
"""
from __future__ import annotations

import re
from pathlib import Path

from .jvm import balanced_end

APEX_SUFFIXES = {".cls", ".trigger", ".apex"}
_EXPOSED = re.compile(r"@(?:AuraEnabled|RemoteAction|InvocableMethod|Http(?:Get|Post|Put|Patch|Delete))\b|\bwebservice\s+", re.I)
_REST = re.compile(r"@RestResource\s*\(\s*urlMapping\s*=\s*'([^']*)'", re.I)
_DYNAMIC_QUERY = re.compile(r"\b(?:Database\s*\.\s*(?:query|countQuery|getQueryLocator|queryWithBinds)|Search\s*\.\s*query)\s*\(", re.I)
_ENFORCED = re.compile(r"\bWITH\s+(?:USER_MODE|SECURITY_ENFORCED)\b|AccessLevel\s*\.\s*USER_MODE|Security\s*\.\s*stripInaccessible"
                       r"|\.\s*is(?:Accessible|Createable|Updateable|Deletable|Upsertable)\s*\(\s*\)", re.I)
_DATA_ACCESS = re.compile(r"\[\s*(?:SELECT|FIND)\b|\b(?:insert|update|upsert|delete|undelete|merge)\s+[\w\[\(]"
                          r"|Database\s*\.\s*(?:insert|update|upsert|delete|query|countQuery)\s*\(", re.I)
_SQL_WORD = re.compile(r"\b(?:select|from|where|find|returning|order\s+by|limit)\b", re.I)


def mask(text: str) -> str:
    """Blank `//` and `/* */` comments and the inside of '...' literals (offsets and newlines kept)."""
    out, i, n = list(text), 0, len(text)
    while i < n:
        if text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            for j in range(i, end):
                out[j] = " "
            i = end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            for j in range(i, end):
                if out[j] != "\n":
                    out[j] = " "
            i = end
        elif text[i] == "'":
            j = i + 1
            while j < n and text[j] != "'" and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


def _operands(original: str, masked: str) -> list[str]:
    depth, cuts = 0, [-1]
    for i, ch in enumerate(masked):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "+" and depth == 0 and masked[i + 1:i + 2] not in ("+", "="):
            cuts.append(i)
    cuts.append(len(original))
    return [original[a + 1:b].strip() for a, b in zip(cuts, cuts[1:])]


def _dynamic(expression: str, constants: set) -> list[str]:
    out = []
    for operand in _operands(expression, mask(expression)):
        while operand.startswith("(") and operand.endswith(")"):
            operand = operand[1:-1].strip()
        if not operand or re.fullmatch(r"'(?:\\.|[^'\\])*'", operand) or re.fullmatch(r"\d+(?:\.\d+)?[lL]?", operand):
            continue
        if re.fullmatch(r"String\s*\.\s*escapeSingleQuotes\s*\([\s\S]*\)", operand, re.I):
            continue
        if re.fullmatch(r"(?:\w+\s*\.\s*)*[A-Z][A-Z0-9_]*", operand) or operand in constants:
            continue
        out.append(operand)
    return out


def _constants(masked: str, text: str) -> set:
    names = set()
    for match in re.finditer(r"\b(?:static\s+final|final\s+static)\s+\w+\s+(\w+)\s*=", masked, re.I):
        end = masked.find(";", match.end())
        if end > 0 and not _dynamic(text[match.end():end], set()):
            names.add(match[1])
    return names


def _methods(masked: str) -> list[dict]:
    """Method bodies with their annotation/modifier block and parameter names."""
    rows = []
    for match in re.finditer(r"\b(\w+)\s*\(([^()]*)\)\s*(?:throws\s+[\w.,\s]+)?\{", masked):
        if match[1].lower() in {"if", "for", "while", "switch", "catch", "when", "try"}:
            continue
        start = max(masked.rfind(";", 0, match.start()), masked.rfind("{", 0, match.start()),
                    masked.rfind("}", 0, match.start())) + 1
        header = masked[start:match.start()]
        if not re.search(r"\b(?:public|global|private|protected|static|webservice|override)\b", header, re.I):
            continue
        body_open = match.end() - 1
        params = re.findall(r"(\w+)\s*(?:,|$)", match[2].strip())
        rows.append({"name": match[1], "header": header, "params": params,
                     "start": body_open, "end": balanced_end(masked, body_open),
                     "line": masked.count("\n", 0, match.start()) + 1})
    return rows


def _assignments(masked: str, text: str, name: str, before: int) -> list[str]:
    rows = []
    for match in re.finditer(r"(?<![\w.])" + re.escape(name) + r"\s*(\+?=)(?!=)", masked[:before]):
        end = masked.find(";", match.end())
        if 0 <= end <= before:
            rows.append(text[match.end():end])
    return rows


def analyze(text: str, rel: str) -> dict:
    masked = mask(text)
    constants = _constants(masked, text)
    methods = _methods(masked)
    exposed = [m for m in methods if _EXPOSED.search(m["header"])]
    rest = _REST.search(text)
    entrypoints = [{"file": rel, "line": m["line"], "method": m["name"],
                    "kind": re.search(r"@(\w+)|\b(webservice)\b", m["header"], re.I).group(0).lstrip("@")}
                   for m in exposed]
    if rest:
        for m in exposed:
            verb = re.search(r"@Http(Get|Post|Put|Patch|Delete)\b", m["header"], re.I)
            if verb:
                entry = next(e for e in entrypoints if e["method"] == m["name"] and e["line"] == m["line"])
                entry.update(http_method=verb[1].upper(), path="/services/apexrest/" + rest[1].lstrip("/"))
    queries, findings = [], []
    for call in _DYNAMIC_QUERY.finditer(masked):
        opening = call.end() - 1
        close = balanced_end(masked, opening)
        from .syntax import split_arguments
        arguments = split_arguments(text[opening + 1:close - 1])
        first = arguments[0].strip() if arguments else ""
        if re.fullmatch(r"\w+", first):
            assigned = _assignments(masked, text, first, call.start())
            expressions = assigned if any(_SQL_WORD.search(a) for a in assigned) else []
        else:
            expressions = [first] if _SQL_WORD.search(first) else []
        dynamic = [op for expression in expressions for op in _dynamic(expression, constants)]
        if not dynamic:
            continue
        owner = next((m for m in methods if m["start"] < call.start() < m["end"]), None)
        bound = sorted({op for op in dynamic if owner and owner in exposed
                        and re.split(r"[.\s(\[]", op, 1)[0] in owner["params"]})
        queries.append({"offset": call.start(), "end": close, "line": masked.count("\n", 0, call.start()) + 1,
                        "dynamic": dynamic[:6], "request_bound": bound[:6]})
    without_sharing = re.search(r"\bwithout\s+sharing\s+class\s+(\w+)", masked, re.I)
    if without_sharing and (exposed or rest):
        findings.append({"rule_id": "apex-without-sharing-entrypoint", "line": masked.count("\n", 0, without_sharing.start()) + 1,
                         "attack_class": "missing-auth", "severity": "MEDIUM", "confidence": "MEDIUM", "cwe": "CWE-862",
                         "title": f"Apex class {without_sharing[1]} runs exposed methods without sharing",
                         "evidence": f"`without sharing` with {len(exposed)} exposed method(s) "
                                     f"({', '.join(sorted({e['kind'] for e in entrypoints})) or 'RestResource'})",
                         "remediation": "Declare the class `with sharing` (or `inherited sharing`) and enforce "
                                        "record access for the calling user; isolate any system-mode work.",
                         "limitations": ["Sharing inherited from callers, permission sets and guest-user site "
                                         "exposure are not resolved."]})
    if exposed and not _ENFORCED.search(masked):
        touching = [m for m in exposed if _DATA_ACCESS.search(masked[m["start"]:m["end"]])]
        if touching:
            findings.append({"rule_id": "apex-crud-fls", "line": touching[0]["line"],
                             "attack_class": "missing-auth", "severity": "LOW", "confidence": "MEDIUM", "cwe": "CWE-285",
                             "title": "Exposed Apex method reads or writes records without CRUD/FLS enforcement",
                             "evidence": ", ".join(m["name"] for m in touching[:5]) + " run SOQL/DML; no WITH USER_MODE, "
                                         "WITH SECURITY_ENFORCED, AccessLevel.USER_MODE, Security.stripInaccessible "
                                         "or describe check appears in this class",
                             "remediation": "Run queries and DML in user mode (WITH USER_MODE / AccessLevel.USER_MODE) "
                                            "or strip inaccessible fields before returning or writing them.",
                             "limitations": ["Checks in called helper classes are not followed."]})
    return {"entrypoints": entrypoints, "queries": queries, "findings": findings}


def is_apex_source(root: Path, rel: str, cache: dict | None = None) -> bool:
    """`.cls`/`.trigger`/`.apex` in a Salesforce DX context (not a LaTeX `.cls`)."""
    rel = rel.replace("\\", "/")
    suffix = Path(rel).suffix.lower()
    if suffix not in APEX_SUFFIXES:
        return False
    if (root / (rel + "-meta.xml")).is_file() or re.search(r"(?:^|/)force-app/", rel):
        return True
    directory = str(Path(rel).parent)
    cache = cache if cache is not None else {}
    probe = directory
    seen = []
    while True:
        if probe in cache:
            result = cache[probe]
            break
        seen.append(probe)
        if (root / probe / "sfdx-project.json").is_file():
            result = True
            break
        if probe in ("", "."):
            result = False
            break
        probe = str(Path(probe).parent)
    for item in seen:
        cache[item] = result
    return result

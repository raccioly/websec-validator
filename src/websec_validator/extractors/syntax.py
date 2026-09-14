"""Small, bounded syntax helpers for evidence-local heuristics; not a dataflow engine.

Offsets remain in the original source. Unsupported or ambiguous expressions retain
security leads instead of being interpreted as proof that a control is effective.
"""
from __future__ import annotations

import ast
import hashlib
import io
import re
import tokenize
from pathlib import Path

MAX_EXPRESSION = 8192


def without_comments(text: str, suffix: str = "") -> str:
    chars = list(text)
    if suffix == ".py":
        offsets = [0]
        for line in text.splitlines(keepends=True):
            offsets.append(offsets[-1] + len(line))
        try:
            for token in tokenize.generate_tokens(io.StringIO(text).readline):
                if token.type == tokenize.COMMENT:
                    start = offsets[token.start[0] - 1] + token.start[1]
                    end = offsets[token.end[0] - 1] + token.end[1]
                    chars[start:end] = " " * (end - start)
        except (tokenize.TokenError, IndentationError):
            pass  # incomplete source remains a lead, never a control proof
        return "".join(chars)
    i = 0
    while i < len(text):
        if text[i] in "\"'`":
            quote = text[i]
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                elif text[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
        elif text.startswith(("//", "/*", "<!--"), i):
            start = i
            if text.startswith("//", i):
                end = text.find("\n", i)
                i = len(text) if end < 0 else end
            else:
                closing = "-->" if text.startswith("<!--", i) else "*/"
                end = text.find(closing, i + 2)
                i = len(text) if end < 0 else end + len(closing)
            for j in range(start, i):
                if chars[j] != "\n":
                    chars[j] = " "
        else:
            i += 1
    return "".join(chars)


def expression_end(text: str, start: int, *, closing: str | None = None) -> int:
    """End of a balanced expression, or the cap if parsing is uncertain."""
    stack = []
    quote = None
    i = start
    while i < min(len(text), start + MAX_EXPRESSION):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
        elif ch in "([{":
            stack.append({"(": ")", "[": "]", "{": "}"}[ch])
        elif ch in ")]}":
            if not stack:
                return i
            if stack.pop() != ch:
                return i
            if closing and not stack:
                return i + 1
        elif not stack and ch in ";\n":
            if ch == "\n" and text[i + 1:].lstrip().startswith(("+", "?", ".", "[", "(")):
                i += 1
                continue
            return i
        i += 1
    return i


def call_expression(text: str, start: int) -> str:
    opening = text.find("(", start, min(len(text), start + 180))
    if opening < 0:
        return text[start:expression_end(text, start)]
    return text[start:expression_end(text, opening, closing=")")]


def in_literal(text: str, position: int) -> bool:
    """Conservative ordinary-string/template boundary check for control declarations."""
    for match in re.finditer(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`''', text):
        if match.start() > position:
            return False
        if match.start() <= position < match.end():
            return True
    return False


def direct_call(expression: str, names: str, prefix: str = "", *, program: str = "") -> bool:
    """Recognize a whole-expression control call, excluding shadowing/reassignment."""
    expression = expression.strip()
    if len(expression) >= MAX_EXPRESSION or not expression.endswith(")"):
        return False
    match = re.match(r"(?:" + names + r")\s*\(", expression)
    if not match:
        return False
    opening = expression.find("(")
    if expression_end(expression, opening, closing=")") != len(expression):
        return False
    root = re.match(r"[\w$]+", expression)[0]
    # JS function declarations are hoisted. A same-named local implementation later
    # in the source cannot be treated as a known sanitizer/verification library.
    declarations = re.finditer(r"\b(?:function|def|class)\s+" + re.escape(root) + r"\b", program)
    if any(not in_literal(program, match.start()) for match in declarations):
        return False
    # An imported library is useful evidence; a reassigned or locally implemented
    # identically named helper is not. Aliases are deliberately unresolved.
    shadow = re.compile(r"(?:\b(?:function|def|class)\s+" + re.escape(root)
                        + r"\b|\b" + re.escape(root) + r"(?:\.[\w$]+)?\s*=(?!=)|"
                        r"\([^)]*\b" + re.escape(root) + r"\b[^)]*\)\s*(?:=>|\{))")
    source = program or prefix
    return not any(not in_literal(source, match.start()) for match in shadow.finditer(source))


def occurrence(text: str, start: int, expression: str, rel: str, kind: str,
               ordinal: int = 0, *, control: str = "none observed") -> dict:
    normalized = re.sub(r"\s+", "", expression)
    digest = hashlib.sha256(normalized.encode()).hexdigest()[:16]
    sink = re.match(r"[\w.$-]+", expression)
    return {"file": rel, "line": text.count("\n", 0, start) + 1,
            "attack_class": "sqli" if kind == "sql-injection" else kind,
            "sink_class": kind, "sink": sink[0] if sink else kind,
            "semantic_id": f"{kind}:{digest}:{ordinal}",
            "source": "dynamic expression; provenance requires review", "control_scope": control}


def python_shell_safe(expression: str) -> bool:
    try:
        node = ast.parse(expression, mode="eval").body
    except (SyntaxError, ValueError, RecursionError):
        return False
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess"
            and node.func.attr in {"run", "call", "check_output", "Popen"}
            and bool(node.args) and (isinstance(node.args[0], (ast.List, ast.Tuple))
                                    or (isinstance(node.args[0], ast.BinOp)
                                        and isinstance(node.args[0].op, ast.Add)
                                        and isinstance(node.args[0].right, (ast.List, ast.Tuple))))
            and any(k.arg == "shell" and isinstance(k.value, ast.Constant)
                    and k.value.value is False for k in node.keywords))


def server_file(rel: str, text: str, legacy_client: bool) -> bool:
    """TSX is not inherently browser code: explicit use-client wins; server evidence wins next."""
    if re.search(r"(?:^|\n)\s*['\"]use client['\"]", text[:400]):
        return False
    if Path(rel).suffix.lower() in {".tsx", ".jsx"}:
        if re.search(r"(?:^|/)app/.*(?:page|layout|route)\.[jt]sx$", rel):
            return True
        if re.search(r"['\"]use server['\"]|next/headers|server-only|"
                     r"export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)\b", text):
            return True
    return not legacy_client


def split_arguments(text: str) -> list[str]:
    """Split only outer commas; nested objects, calls and string contents stay together."""
    parts, stack = [], []
    quote = None
    start = i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'`":
            quote = ch
        elif ch in "([{":
            stack.append(ch)
        elif ch in ")]}":
            if stack:
                stack.pop()
        elif ch == "," and not stack:
            parts.append(text[start:i].strip())
            start = i + 1
        i += 1
    parts.append(text[start:].strip())
    return parts


def direct_options(expression: str) -> dict[str, str]:
    arguments = expression[expression.find("(") + 1:-1].strip()
    if arguments.startswith("{") and arguments.endswith("}"):
        arguments = arguments[1:-1]
    options = {}
    for field in split_arguments(arguments):
        if field.startswith(("...", "**")):
            return {}  # uncertain spread overrides are not control evidence
        match = re.match(r"(\w+)\s*[:=]\s*(.+)", field, re.S)
        if match:
            options[match[1]] = match[2]
    return options


def js_functions(text: str) -> list[dict]:
    """Locate ordinary JS scopes with one lexical pass and bounded header work.

    Literal contents are opaque, including templates. Unsupported/oversized scope
    bodies are returned with complete=False and no safety-creditable parameters;
    no function-count cap silently discards the tail. This is not a JS parser.
    """
    chars = list(text)
    pairs, stack = {}, []
    i = 0
    while i < len(text):
        char = text[i]
        if char in "\"'`":
            quote, start = char, i
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                elif text[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
            chars[start:i] = " " * (min(i, len(text)) - start)
            continue
        if char in "([{":
            stack.append((char, i))
        elif char in ")]}":
            if stack and stack[-1][0] == {")": "(", "]": "[", "}": "{"}[char]:
                _, opening = stack.pop()
                pairs[opening] = i
            else:
                stack.clear()  # malformed nesting cannot establish a complete scope
        i += 1
    masked = "".join(chars)
    scopes = []
    # Bound aggregate body copies under pathological deep nesting as well as the
    # size of any one control proof. Incomplete records retain their full offsets.
    copy_budget = 8 * len(text) + MAX_EXPRESSION
    for opening in (index for index, char in enumerate(masked) if char == "("):
        closing = pairs.get(opening)
        if closing is None or closing - opening > 502 or "(" in masked[opening+1:closing]:
            continue
        after = closing + 1
        while after < len(text) and masked[after].isspace():
            after += 1
        arrow = masked.startswith("=>", after)
        if arrow:
            after += 2
            while after < len(text) and masked[after].isspace():
                after += 1
        if masked[after:after+1] != "{" or after not in pairs:
            continue
        prefix_start = max(0, opening - 128)
        prefix = masked[prefix_start:opening]
        declaration = re.search(r"\b(?:async\s+)?function(?:\s+([\w$]+))?\s*$", prefix)
        method = re.search(r"([\w$]+)\s*$", prefix)
        name, start = "", opening
        if declaration:
            name = declaration[1] or ""
            start = prefix_start + declaration.start()
        elif not arrow:
            if not method or method[1] in {"if", "for", "while", "switch", "catch", "with"}:
                continue
            name, start = method[1], prefix_start + method.start()
        else:
            if method and method[1] == "async":
                start = prefix_start + method.start()
            binding = re.search(r"\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s*)?$", prefix)
            name = binding[1] if binding else ""
        # A truncated identifier/header is unresolved, never a different binding.
        if start == prefix_start and prefix_start and masked[prefix_start-1:prefix_start].isalnum():
            continue
        end = pairs[after] + 1
        params = [part.strip() for part in text[opening+1:closing].split(",") if part.strip()]
        size = end - after - 2
        complete = size <= MAX_EXPRESSION and size <= copy_budget
        body = text[after+1:end-1] if complete else ""
        copy_budget -= len(body)
        simple = complete and all(re.fullmatch(r"[A-Za-z_$][\w$]*", param) for param in params)
        scopes.append({"start": start, "body_start": after + 1, "end": end, "name": name,
                       "params": params if simple else [], "simple_params": simple,
                       "complete": complete, "body": body})
    return scopes


def rejecting_statement(statement: str) -> bool:
    """Only a literal unsuccessful return or unconditional throw is a known stop."""
    statement = statement.strip()
    if statement.startswith("{") and statement.endswith("}"):
        statement = statement[1:-1].strip()
    return bool(re.fullmatch(r"return(?:\s+(?:null|false|undefined))?\s*;?", statement)
                or re.fullmatch(r"throw\s+new\s+Error\(\s*['\"][^'\"]*['\"]\s*\)\s*;?", statement))


def guarded_body(body: str, predicate) -> bool:
    """A first-statement rejecting guard, or a single positive guarded action.

    predicate(condition) returns +1 for a positive authorization test, -1 for
    rejection, 0 for unknown. No credit for logging, later checks, helper names,
    nested/sibling functions, else branches, or uncertain control flow.
    """
    body = body.strip()
    match = re.match(r"if\s*\(", body)
    if not match or js_functions(body):
        return False
    opening = body.find("(")
    cond_end = expression_end(body, opening, closing=")")
    if body[cond_end-1:cond_end] != ")":
        return False
    polarity = predicate(body[opening+1:cond_end-1].strip())
    if not polarity:
        return False
    start = cond_end
    while start < len(body) and body[start].isspace():
        start += 1
    if body[start:start+1] == "{":
        end = expression_end(body, start, closing="}")
        if body[end-1:end] != "}":
            return False
    else:
        end = expression_end(body, start)
        if body[end:end+1] == ";":
            end += 1
    statement, tail = body[start:end], body[end:].strip()
    if tail.startswith("else"):
        return False
    if polarity < 0:
        return rejecting_statement(statement) and bool(tail)
    return bool(statement.strip()) and (not tail or rejecting_statement(tail))

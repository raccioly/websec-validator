"""Strict bounded YAML data subset for literal source registrations, not a YAML engine.

No object constructors, tags, anchors, aliases, merge keys or document composition.
Unsupported syntax fails the whole document; the general OpenAPI informational parser
keeps its separately labelled partial mode. No target module is imported or executed.
"""
from __future__ import annotations

import json
import re

MAX_BYTES = 512 * 1024
MAX_LINES = 10_000
MAX_NODES = 20_000
MAX_DEPTH = 32


class LimitReached(ValueError):
    pass


class BlockText(str):
    """Opaque description text, never a routing/handler scalar."""


def load(text):
    if len(text.encode('utf-8')) > MAX_BYTES:
        raise LimitReached('Registered contract byte budget exceeded')
    count = 0

    def tick(depth=0):
        nonlocal count
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise LimitReached('Registered contract node/depth budget exceeded')

    def pairs(items):
        result = {}
        for key, value in items:
            tick()
            if key in result:
                raise ValueError('Duplicate contract keys are unresolved')
            result[key] = value
        return result

    def no_constant(_value):
        raise ValueError('Nonfinite contract constants are unresolved')

    def json_data(value):
        try:
            doc = json.loads(value, object_pairs_hook=pairs, parse_constant=no_constant)
        except RecursionError as error:
            raise LimitReached('Registered JSON depth budget exceeded') from error
        pending = [(doc, 0)]
        while pending:
            value, depth = pending.pop()
            tick(depth)
            children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
            pending.extend((child, depth+1) for child in children)
        return doc

    if text.lstrip().startswith('{'):
        doc = json_data(text)
        return doc, 'json'
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise LimitReached('Registered YAML line budget exceeded')
    rows = []
    document_start = False
    for line in lines:
        if '\t' in line:
            raise ValueError('YAML tabs are unsupported')
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if line.strip() == '---' and not rows:
            if document_start:
                raise ValueError('YAML multi-document composition unsupported')
            document_start = True
            continue
        quote = None
        end = len(line)
        for index, char in enumerate(line):
            if quote:
                if char == quote and (index == 0 or line[index-1] != '\\'):
                    quote = None
            elif char in '\"\'':
                quote = char
            elif char == '#' and (index == 0 or line[index-1].isspace()):
                end = index
                break
        content = line[:end].rstrip()
        if content.strip():
            rows.append((len(content)-len(content.lstrip()), content.lstrip()))
    if not rows or rows[0][0] != 0:
        raise ValueError('YAML document root unresolved')

    def scalar(value):
        tick()
        if value.startswith(('!', '&', '*', '|', '>', '%')) or '{{' in value or '}}' in value:
            raise ValueError('YAML constructors/composition/templates are unsupported')
        if value.startswith('[') and value.endswith(']'):
            try:
                return json_data(value)
            except json.JSONDecodeError:
                # Common OpenAPI enum lists use YAML single-quoted strings.
                # Only a flat literal scalar list is supported outside exact JSON.
                fields, start, quote = [], 1, None
                for index, char in enumerate(value[1:-1], 1):
                    if quote:
                        if char == quote and value[index-1] != '\\':
                            quote = None
                    elif char in '\"\'':
                        quote = char
                    elif char == ',':
                        fields.append(value[start:index].strip())
                        start = index+1
                    elif char in '[]{}':
                        raise ValueError('Nested non-JSON YAML flow syntax unsupported')
                if quote:
                    raise ValueError('YAML flow quoting unresolved')
                fields.append(value[start:-1].strip())
                if fields == ['']:
                    return []
                if any(not field for field in fields):
                    raise ValueError('YAML flow missing scalar unsupported')
                return [scalar(field) for field in fields]
        if value.startswith(('"', '[', '{')):
            return json_data(value)  # only exact JSON-compatible flow syntax
        if value.startswith("'"):
            if not re.fullmatch(r"'(?:[^']|'')*'", value):
                raise ValueError('YAML quoted scalar unresolved')
            return value[1:-1].replace("''", "'")
        if '\"' in value or "'" in value:
            raise ValueError('YAML plain scalar quoting outside supported subset')
        if value == 'null' or value == '~':
            return None
        if value in {'true', 'false'}:
            return value == 'true'
        if re.search(r':\s', value) or value in {'---', '...'}:
            raise ValueError('YAML scalar composition unsupported')
        return value  # numeric-looking metadata stays a string; no routing coercion

    def pair(value):
        match = re.fullmatch(r'''("(?:\\.|[^"\\])*"|'(?:[^']|'')*'|[^:]+):(?:\s+(.*))?''', value)
        if not match:
            raise ValueError('YAML mapping syntax unsupported')
        key = scalar(match[1].strip())
        if not isinstance(key, str) or not key or key == '<<':
            raise ValueError('YAML mapping key unresolved')
        return key, (match[2] or '').strip()

    def block(index, indent, depth):
        tick(depth)
        sequence = rows[index][1] == '-' or rows[index][1].startswith('- ')
        output = [] if sequence else {}
        while index < len(rows) and rows[index][0] == indent:
            value = rows[index][1]
            if sequence:
                if not (value == '-' or value.startswith('- ')):
                    raise ValueError('Mixed YAML collection unsupported')
                rest = value[1:].strip()
                if re.match(r'''(?:[^:]+|"[^"]*"|'[^']*'):($|\s)''', rest):
                    rows[index] = (indent+2, rest)
                    item, index = block(index, indent+2, depth+1)
                elif rest:
                    item, index = scalar(rest), index+1
                elif index+1 < len(rows) and rows[index+1][0] > indent:
                    item, index = block(index+1, rows[index+1][0], depth+1)
                else:
                    item, index = None, index+1
                output.append(item)
            else:
                key, rest = pair(value)
                if key in output:
                    raise ValueError('Duplicate YAML keys unresolved')
                index += 1
                if rest in {'|', '>', '|-', '>-', '|+', '>+'}:
                    parts = []
                    while index < len(rows) and rows[index][0] > indent:
                        tick(depth+1)
                        parts.append(rows[index][1])
                        index += 1
                    item = BlockText(('\n' if rest.startswith('|') else ' ').join(parts))
                elif rest:
                    item = scalar(rest)
                elif index < len(rows) and rows[index][0] > indent:
                    item, index = block(index, rows[index][0], depth+1)
                else:
                    item = None
                output[key] = item
            if index < len(rows) and rows[index][0] > indent:
                raise ValueError('Unsupported YAML continuation')
        return output, index

    doc, end = block(0, 0, 0)
    if end != len(rows) or not isinstance(doc, dict):
        raise ValueError('YAML document composition unresolved')
    return doc, 'yaml-literal-subset'

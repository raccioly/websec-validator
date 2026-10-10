"""Bounded local request provenance for retained commands/JS queries; no target execution.

Python reuses the query AST work limits and branch joins. JavaScript models local,
simple assignments only. Complex control flow remains may-flow, not a safety proof.
"""
from __future__ import annotations
import ast
from dataclasses import replace
import re

from . import sql_flow
from .syntax import MAX_EXPRESSION, call_expression, js_functions, split_arguments, without_comments

MAX_SOURCE_BYTES = 512 * 1024
MAX_EVENTS = 2048
MAX_SCOPES = 128            # per-file floor; the limit scales with file size up to MAX_SCOPES_CAP
SCOPE_BYTES = 64            # one scope per 64 source bytes is denser than ordinary callback-heavy code
MAX_SCOPES_CAP = 8192
MAX_BINDINGS = 512
MAX_TOTAL_SOURCE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_EVENTS = 20_000
# The walk used to stop at the first right-hand side longer than MAX_EXPRESSION (an
# `async (event) => {...}` handler or a large object literal). Everything up to that point is
# unchanged; the overflowing expression and all work after it are charged to this allowance:
# EXTENDED_FACTOR characters per source character, hard-capped per file and per run. A file that
# exhausts it stops at the same visible LimitReached as before, never earlier.
EXTENDED_FACTOR = 8
MAX_EXTENDED_PER_FILE = 1024 * 1024
MAX_TOTAL_EXTENDED = 8 * 1024 * 1024
INERT_ARGV_EXECUTABLES = {'echo', '/bin/echo', '/usr/bin/echo'}
REQUEST = re.compile(r'\b(?:req|request|ctx)\.(?:query|params|body|args|form|headers|json|get_json|GET|POST)\b')
LITERAL = re.compile(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`''')
ASSIGNMENT = re.compile(r'(?<![\w$.=!<>])(?:(?:const|let|var)\s+)?([\w$]+)\s*(\+?=)(?!=|>)')
JS_CALL = re.compile(r'\b(?:[\w$]+\.(?:query|execute|raw)|child_process\.exec|execSync|exec)\s*\(')
COMMAND = re.compile(r'\b(?:[\w]+\.)?(?:system|popen|run|call|check_output|Popen|getoutput|getstatusoutput)\s*\(')
LIMITATIONS = [
    'Python import-bound stdlib command calls reuse bounded query-analysis assignments and branch joins.',
    'JS simple local assignments and first query/shell argument only; receiver names are review hints, not execution proof.',
    'JS branch writes preserve may-taint; loops, closure capture, destructuring, aliases, object mutation and cross-function flows require review.',
    'Unknown wrappers retain provenance; no sanitizer is inferred from a helper name. Separate query bind values do not taint query text.',
    'Bound HTTP method additions require a stable supported package import; other clients and dynamic dispatch remain unverified.',
]


class CommandAnalysis(sql_flow.Analysis):
    def __init__(self, source, budget):
        super().__init__(source, budget)
        self.mutated = set()
        self.wildcard = False

    def observe_node(self, node):
        if isinstance(node, ast.ImportFrom) and any(alias.name == '*' for alias in node.names):
            self.wildcard = True
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            root = node.value
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            if isinstance(root, ast.Name):
                self.mutated.add(root.id)
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in {'setattr', 'delattr'} and node.args and isinstance(node.args[0], ast.Name)):
            self.mutated.add(node.args[0].id)

    def import_kind(self, node, alias):
        if id(alias) not in self.trusted_imports or getattr(node, 'level', 0):
            return ''
        if isinstance(node, ast.Import) and alias.name in {'os', 'subprocess'}:
            return 'command-module:' + alias.name
        if isinstance(node, ast.ImportFrom) and node.module in {'os', 'subprocess'}:
            if alias.name in {'system', 'popen', 'run', 'call', 'check_output', 'Popen', 'getoutput', 'getstatusoutput'}:
                return 'command:' + node.module + '.' + alias.name
        return super().import_kind(node, alias)

    def value(self, node, env, depth=0):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            self.tick()
            return sql_flow.Value(callable_kind='fixed-executable:' + node.value)
        if isinstance(node, ast.Attribute):
            receiver = super().value(node.value, env, depth + 1)
            if receiver.callable_kind.startswith('command-module:'):
                module = receiver.callable_kind.split(':', 1)[1]
                if node.attr in {'system', 'popen', 'run', 'call', 'check_output', 'Popen', 'getoutput', 'getstatusoutput'}:
                    return sql_flow.Value(callable_kind='command:' + module + '.' + node.attr)
        if isinstance(node, (ast.List, ast.Tuple)):
            executable = node.elts[0].value if node.elts and isinstance(node.elts[0], ast.Constant) and isinstance(node.elts[0].value, str) else ''
            return replace(super().value(node, env, depth), vector=True, vector_executable=executable)
        if isinstance(node, ast.Call):
            function = self.value(node.func, env, depth + 1)
            if function.callable_kind.startswith('command:'):
                self.tick()
                argument = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg in {'args', 'command', 'cmd'}), None)
                value = self.value(argument, env, depth + 1)
                shell = next((kw.value for kw in node.keywords if kw.arg == 'shell'), ast.Constant(value=False))
                safe_vector = (function.callable_kind in {'command:subprocess.' + name for name in ('run', 'call', 'check_output', 'Popen')}
                               and len(node.args) == 1 and all(keyword.arg is not None for keyword in node.keywords)
                               and not self.wildcard and not (isinstance(node.func, ast.Attribute)
                                   and isinstance(node.func.value, ast.Name) and node.func.value.id in self.mutated)
                               and value.vector and value.vector_executable in INERT_ARGV_EXECUTABLES
                               and isinstance(shell, ast.Constant) and shell.value is False)
                if value.sources and not safe_vector:
                    if len(self.findings) >= sql_flow.MAX_FINDINGS:
                        raise sql_flow.LimitReached('command occurrence budget exceeded')
                    start = self.offset(node)
                    self.findings[start] = {'offset': start, 'end': self.offset(node, True), 'line': node.lineno,
                                            'legacy_offset': start, 'value': value, 'sink_class': 'command-injection'}
                return sql_flow.Value()
        return super().value(node, env, depth)

    def bind_assignment(self, target, value, env, line):
        super().bind_assignment(target, value, env, line)
        if isinstance(target, ast.Name) and isinstance(value, tuple):
            first = value[0].callable_kind if value and isinstance(value[0], sql_flow.Value) else ''
            executable = first.removeprefix('fixed-executable:') if first.startswith('fixed-executable:') else ''
            env[target.id] = replace(env[target.id], vector_executable=executable)


def python_commands(source, budget):
    result = sql_flow.analyze(source, budget, analysis_type=CommandAnalysis, candidate_pattern=COMMAND)
    result['occurrences'] = [row for row in result['occurrences'] if row.get('sink_class') == 'command-injection']
    return result


def _masked(source):
    def mask(match):
        return ''.join('\n' if char == '\n' else ' ' for char in match[0])
    return LITERAL.sub(mask, source)


def scope_limit(size):
    """Per-file scope budget: a floor for small files, proportional to size, hard-capped."""
    return min(max(MAX_SCOPES, size // SCOPE_BYTES), MAX_SCOPES_CAP)


# Same string/comment boundaries as syntax.without_comments (backslash escapes any character,
# including a newline); a regex literal is recognised only where JS grammar requires an operand.
_LEXEME = re.compile(r'''["'`]|<!--|//|/\*|/''')
_STRING = {quote: re.compile(quote + r'(?:\\.|[^' + quote + r'\\])*' + quote, re.S) for quote in '"\'`'}
_REGEX_LITERAL = re.compile(r'/(?![*/])((?:\\[^\n]|\[(?:\\[^\n]|[^\]\\\n]){0,256}\]|[^/\\\[\n]){1,1024})/')
_REGEX_PRECEDERS = frozenset('(,=:[!&|?{};+-~^')
_REGEX_KEYWORDS = frozenset({'return', 'typeof', 'case', 'do', 'else', 'in', 'of', 'new', 'delete',
                             'void', 'throw', 'yield', 'await', 'instanceof'})
_TRAILING_WORD = re.compile(r'[\w$]+$')


def _regex_operand(source, slash):
    """True only where a `/` cannot be division: after an operator/opener or an operand keyword.

    `)`, `]`, `}`, identifiers, numbers, `<`/`>` (JSX tags) and postfix `++`/`--` stay division, so
    an ambiguous slash keeps the previous lexical treatment.
    """
    before = source[max(0, slash - 256):slash].rstrip()
    if not before:
        return slash < 256
    last = before[-1]
    if last in '+-' and before.endswith(('++', '--')):
        return False
    if last in _REGEX_PRECEDERS:
        return True
    word = _TRAILING_WORD.search(before)
    # `obj.in / 2` is a property access followed by division, not a keyword.
    return bool(word) and word[0] in _REGEX_KEYWORDS and before[word.start() - 1:word.start()] != '.'


def _without_regex_bodies(source):
    """Blank JS regex literal bodies, preserving offsets.

    A quote or bracket inside `/'/g` or `/["']/` otherwise opens a phantom string that swallows
    the rest of the file: every later assignment and sink is mis-scanned and the lane stops at the
    expression bound. A literal regex body carries no data flow, so blanking it removes nothing.
    """
    if '/' not in source:
        return source
    chars, i = None, 0
    while True:
        match = _LEXEME.search(source, i)
        if match is None:
            break
        i, token = match.start(), match[0]
        if token in _STRING:
            literal = _STRING[token].match(source, i)
            if literal is None:
                break  # unterminated: without_comments treats the remainder as the literal too
            i = literal.end()
        elif token in ('//', '/*', '<!--'):
            closing = {'//': '\n', '/*': '*/', '<!--': '-->'}[token]
            end = source.find(closing, i + len(token))
            if end < 0:
                break
            i = end if token == '//' else end + len(closing)
        else:
            literal = _REGEX_LITERAL.match(source, i) if _regex_operand(source, i) else None
            if literal is None:
                i += 1
                continue
            chars = chars or list(source)
            chars[literal.start(1):literal.end(1)] = ' ' * (literal.end(1) - literal.start(1))
            i = literal.end()
    return source if chars is None else ''.join(chars)


def _scope_owner(scopes):
    """owner(position) -> body_start of the innermost scope body containing it, else 0.

    Positions must be queried in ascending order. js_functions derives every body from one
    balanced bracket matching, so bodies nest or are disjoint and the innermost containing body
    (the shortest, as before) is the top of a stack swept in position order: amortised O(1) per
    query instead of O(scopes), which lets the scope budget scale with file size.
    """
    ordered = sorted(scopes, key=lambda row: row['body_start'])
    active, cursor = [], 0
    def owner(position):
        nonlocal cursor
        while cursor < len(ordered) and ordered[cursor]['body_start'] <= position:
            while active and active[-1]['end'] <= ordered[cursor]['body_start']:
                active.pop()
            active.append(ordered[cursor])
            cursor += 1
        while active and active[-1]['end'] <= position:
            active.pop()
        return active[-1]['body_start'] if active else 0
    return owner


_NONSPACE = re.compile(r'\S')
_CLOSERS = {'(': ')', '[': ']', '{': '}'}


def _expression_end(text, start, bound):
    """syntax.expression_end with an explicit bound; returns (end, closed).

    Identical result for every end below MAX_EXPRESSION. The continuation lookahead jumps to the
    next non-space character instead of copying the remaining text at every newline (which made
    method chains cost O(lines x file size)). `closed` is False when the scan ran out of bound, or
    reached end of input inside a literal or an open bracket.
    """
    stack, quote, i = [], None, start
    stop = min(len(text), bound)
    while i < stop:
        char = text[i]
        if quote:
            if char == '\\':
                i += 2
                continue
            if char == quote:
                quote = None
        elif char in '"\'`':
            quote = char
        elif char in '([{':
            stack.append(_CLOSERS[char])
        elif char in ')]}':
            if not stack or stack.pop() != char:
                return i, True
        elif not stack and char in ';\n':
            if char == '\n':
                following = _NONSPACE.search(text, i + 1)
                if following is not None and text[following.start()] in '+?.[(':
                    i = min(following.start(), stop)
                    continue
            return i, True
        i += 1
    return i, i >= len(text) and quote is None and not stack


def _value(expression, environment, line, source_pattern=REQUEST):
    # Ordinary literal examples are opaque; supported template interpolation is code.
    interpolations = []
    for literal in LITERAL.finditer(expression):
        if literal[0].startswith('`'):
            for interpolation in re.finditer(r'\$\{([^{}]*)\}', literal[0]):
                back = interpolation.start() - 1
                while back >= 0 and literal[0][back] == '\\':
                    back -= 1
                if (interpolation.start() - back - 1) % 2 == 0:
                    interpolations.append(interpolation[1])
    executable = _masked(expression) + ' '.join(interpolations)
    sources, assignments = set(), set()
    if source_pattern.search(executable):
        sources.add(line)
    for name in re.findall(r'\b[\w$]+\b', executable):
        previous = environment.get(name)
        if previous:
            sources.update(previous[0])
            assignments.update(previous[1])
    return set(sorted(sources)[:8]), set(sorted(assignments)[:8])


def javascript(source, budget, *, source_pattern=REQUEST, sink_pattern=JS_CALL,
               sink_kind=None, argument_selector=None):
    """Shared bounded assignment walk; internal consumers select actual sink arguments."""
    result = {'occurrences': [], 'errors': [], 'candidate': bool(sink_pattern.search(source))}
    if not result['candidate']:
        return result
    size = len(source.encode())
    if size > MAX_SOURCE_BYTES or budget['bytes'] + size > MAX_TOTAL_SOURCE_BYTES:
        result['errors'].append({'kind': 'LimitReached', 'detail': 'JS assignment source budget exceeded'})
        return result
    budget['bytes'] += size
    code = without_comments(_without_regex_bodies(source))
    masked = _masked(code)
    scopes = js_functions(code)
    if len(scopes) > scope_limit(size):
        result['errors'].append({'kind': 'LimitReached', 'detail': 'JS assignment scope budget exceeded'})
        return result
    depth, depths = 0, []
    for char in masked:
        depths.append(depth)
        depth += int(char == '{') - int(char == '}')
    owner = _scope_owner(scopes)
    events =[(match.start(), 'assign', match) for match in ASSIGNMENT.finditer(masked)]
    events += [(match.start(), 'sink', match) for match in sink_pattern.finditer(masked)]
    if len(events) > MAX_EVENTS or budget['events'] + len(events) > MAX_TOTAL_EVENTS:
        result['errors'].append({'kind': 'LimitReached', 'detail': 'JS assignment event budget exceeded'})
        return result
    budget['events'] += len(events)
    budget.setdefault('extended', 0)
    allowance = max(0, min(EXTENDED_FACTOR * len(code), MAX_EXTENDED_PER_FILE,
                           MAX_TOTAL_EXTENDED - budget['extended']))
    extended = None  # None until the first long right-hand side; then the remaining allowance
    environments = {}
    line, counted = 1, 0
    for position, kind, match in sorted(events, key=lambda row: row[0]):
        env = environments.setdefault(owner(position), {})
        line += source.count('\n', counted, position)  # incremental: events ascend
        counted = position
        if kind == 'assign':
            start = match.end()
            bound = start + (MAX_EXPRESSION + allowance if extended is None else extended)
            end, closed = _expression_end(code, start, bound)
            if extended is None and end - start >= MAX_EXPRESSION:
                extended = allowance
            if extended is not None:
                # Analysed in full only if it ends structurally within the remaining allowance;
                # otherwise the file's walk stops here, visibly, as it always did.
                if not closed or end - start > extended:
                    result['errors'].append({'kind': 'LimitReached', 'detail': 'JS assignment expression budget exceeded'})
                    break
                extended -= end - start
                budget['extended'] += end - start
            value = _value(code[start:end], env, line, source_pattern)
            prior = env.get(match[1])
            prefix = masked[max(0, position - 128):position].rstrip()
            conditional = not prefix or prefix[-1] not in ';{}'
            if prior and (depths[position] != prior[2] or conditional or match[2] == '+='):
                value = (value[0] | prior[0], value[1] | prior[1])
            if value[0]:
                value[1].add(line)
            if match[1] not in env and len(env) >= MAX_BINDINGS:
                result['errors'].append({'kind': 'LimitReached', 'detail': 'JS assignment binding budget exceeded'})
                break
            env[match[1]] = (*value, depths[position])
            continue
        expression = call_expression(code, position)
        if extended is not None:
            if len(expression) > extended:
                result['errors'].append({'kind': 'LimitReached', 'detail': 'JS assignment expression budget exceeded'})
                break
            extended -= len(expression)
            budget['extended'] += len(expression)
        if not expression.endswith(')'):
            result['errors'].append({'kind': 'LimitReached', 'detail': 'JS call expression incomplete or budget exceeded'})
            continue
        arguments = split_arguments(expression[expression.find('(') + 1:-1])
        if not arguments:
            continue
        argument = argument_selector(expression, arguments) if argument_selector else arguments[0]
        value = _value(argument, env, line, source_pattern)
        if value[0]:
            sink_class = sink_kind or ('sql-injection' if re.search(r'\.(?:query|execute|raw)\s*\(', match[0]) else 'command-injection')
            result['occurrences'].append({'offset': position, 'end': position + len(expression), 'line': line,
                'legacy_offset': position + expression.find('.') if sink_class == 'sql-injection' else position,
                'sink_class': sink_class, 'source_lines': sorted(value[0])[:8], 'assignment_lines': sorted(value[1])[:8]})
    return result


def http_methods(source, budget):
    """Stable default/require needle imports only; names or reassigned receivers aren't clients."""
    if 'needle' not in source:
        return []
    size = len(source.encode())
    if size > MAX_SOURCE_BYTES or budget['bytes'] + size > MAX_TOTAL_SOURCE_BYTES:
        raise sql_flow.LimitReached('bound HTTP-method source budget exceeded')
    budget['bytes'] += size
    code, rows = without_comments(source), []
    masked = _masked(code)
    scopes = js_functions(code)
    if len(scopes) > scope_limit(size):
        raise sql_flow.LimitReached('bound HTTP-method scope budget exceeded')
    imports = re.compile(r'''\bimport\s+([\w$]+)\s+from\s+(['"])needle\2\s*;?|\bconst\s+([\w$]+)\s*=\s*require\(\s*(['"])needle\4\s*\)\s*;?''')
    bindings = list(imports.finditer(code))
    if len(bindings) > MAX_SCOPES:
        raise sql_flow.LimitReached('bound HTTP-method import budget exceeded')
    for binding in bindings:
        if masked[binding.start():binding.start()+6].strip() not in {'import', 'const'}:
            continue
        name = binding[1] or binding[3]
        remainder = code[:binding.start()] + ' ' * len(binding[0]) + code[binding.end():]
        writes = re.compile(r'\b' + re.escape(name) + r'(?:\.[\w$]+|\[[^\]\n]{0,128}\])*\s*(?:=(?!=)|\+=|-=|\+\+|--)|\b(?:function|class)\s+' + re.escape(name) + r'\b')
        if (writes.search(_masked(remainder))
                or re.search(r'\bimport\s+' + re.escape(name) + r'\b', _masked(remainder))
                or any(name in scope['params'] for scope in scopes)):
            continue
        for call in re.finditer(r'\b' + re.escape(name) + r'\.(get|post|put|patch|delete|head|request)\s*\(', masked):
            budget['events'] += 1
            if budget['events'] > MAX_TOTAL_EVENTS or len(rows) >= MAX_EVENTS:
                raise sql_flow.LimitReached('bound HTTP-method call budget exceeded')
            expression = call_expression(code, call.start())
            arguments = split_arguments(expression[expression.find('(') + 1:-1])
            index = 1 if call[1] == 'request' else 0
            if len(arguments) > index:
                url = arguments[index]
                if _value(url, {}, 1)[0]:
                    rows.append((call.start(), expression, 'ssrf'))
                elif re.fullmatch(r'[\w$.]+', url):
                    rows.append((call.start(), expression, 'ssrf-outbound-http'))
    return rows

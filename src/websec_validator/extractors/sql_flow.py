"""Bounded Python request-to-query assignment analysis; target code is never run.

Only candidate files containing a query call are parsed. This is intraprocedural
may-flow evidence, not a Python interpreter or proof of SQL execution/reachability.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, replace
import re

MAX_NODES = 20_000
MAX_SCOPES = 128
MAX_STEPS = 100_000
MAX_BINDINGS = 512
MAX_FINDINGS = 256
MAX_DEPTH = 64
MAX_SOURCE_BYTES = 512 * 1024
MAX_TOTAL_NODES = 200_000
MAX_TOTAL_STEPS = 1_000_000
MAX_TOTAL_SOURCE_BYTES = 8 * 1024 * 1024
QUERY_CALL = re.compile(r"\.(?:execute|executemany|query|raw)\s*\(")
REQUEST_FIELDS = {'args', 'form', 'GET', 'POST', 'query', 'query_params', 'json',
                  'get_json', 'body', 'data', 'params', 'headers', 'cookies'}
LIMITATIONS = [
    'Python candidate query files only; positional first query argument and keyword statement/query/sql.',
    'Intraprocedural may-flow through local assignments and branch joins; no application execution or cross-function call graph.',
    'Request/req fields and imported Flask request aliases are source hints; arbitrary parameter provenance is unknown.',
    'Unknown wrappers retain request provenance; they are not verified sanitizers. Bound-value arguments do not taint query text.',
    'Object mutation, dynamic imports, comprehensions and runtime dispatch are not fully modeled.',
    'SQLAlchemy select/text imports distinguish bound scalar builder values from explicit raw text; assigned factory aliases are unverified.',
    'Standalone overloaded predicates are outside direct-string flow analysis; source and assignment line traces retain at most eight entries each.',
    'Loops use one may-flow pass; query bindings written in the loop carry an explicit later-iteration review gap, not fixed-point coverage.',
]


@dataclass(frozen=True)
class Value:
    sources: frozenset[int] = frozenset()
    assignments: frozenset[int] = frozenset()
    request: bool = False
    uncertain: bool = False
    callable_kind: str = ''
    builder: bool = False
    query_text: bool = False
    predicate: bool = False


def merge(*values):
    return Value(frozenset(sorted(set().union(*(v.sources for v in values)))[:8]),
                 frozenset(sorted(set().union(*(v.assignments for v in values)))[:8]),
                 any(v.request for v in values), any(v.uncertain for v in values),
                 values[0].callable_kind if values and all(v.callable_kind == values[0].callable_kind for v in values) else '',
                 bool(values) and all(v.builder for v in values), any(v.query_text for v in values),
                 bool(values) and all(v.predicate or not v.sources for v in values))


class LimitReached(ValueError):
    pass


@dataclass
class Budget:
    nodes: int = 0
    steps: int = 0
    source_bytes: int = 0


class Analysis:
    def __init__(self, source, budget):
        self.budget = budget
        self.source = source
        self.lines = source.splitlines(keepends=True)
        self.offsets = [0]
        for line in self.lines:
            self.offsets.append(self.offsets[-1] + len(line))
        self.steps = self.scopes = 0
        self.findings = {}
        self.unverified = {}
        self.trusted_imports = set()

    def imports(self, scope):
        """Credit a factory import only if its lexical binding has no other writer."""
        bindings, imported = {}, []
        pending = list(scope.body)
        for arg in getattr(getattr(scope, 'args', None), 'args', []):
            bindings[arg.arg] = 1
        while pending:
            node = pending.pop()
            self.tick()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bindings[node.name] = bindings.get(node.name, 0) + 1
                self.imports(node)
                continue
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    name = alias.asname or alias.name.split('.')[0]
                    bindings[name] = bindings.get(name, 0) + 1
                    imported.append((name, id(alias)))
            elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                bindings[node.id] = bindings.get(node.id, 0) + 1
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
                root = node.value
                while isinstance(root, ast.Attribute):
                    root = root.value
                if isinstance(root, ast.Name):
                    bindings[root.id] = bindings.get(root.id, 0) + 1
            pending.extend(ast.iter_child_nodes(node))
        self.trusted_imports.update(identity for name, identity in imported if bindings[name] == 1)

    def tick(self, amount=1):
        self.steps += amount
        self.budget.steps += amount
        if self.budget.steps > MAX_TOTAL_STEPS:
            raise LimitReached('aggregate expression/statement work budget exceeded')
        if self.steps > MAX_STEPS:
            raise LimitReached('statement/expression work budget exceeded')

    def offset(self, node, end=False):
        line = node.end_lineno if end else node.lineno
        column = node.end_col_offset if end else node.col_offset
        # CPython AST columns count UTF-8 bytes, while occurrence offsets count characters.
        return self.offsets[line - 1] + len(self.lines[line - 1].encode('utf-8')[:column].decode('utf-8'))

    def value(self, node, env, depth=0):
        self.tick()
        if depth > MAX_DEPTH:
            raise LimitReached('expression depth exceeded')
        if node is None or isinstance(node, ast.Constant):
            return Value()
        if isinstance(node, ast.Name):
            return env.get(node.id, Value())
        if isinstance(node, ast.Attribute):
            value = self.value(node.value, env, depth + 1)
            if value.callable_kind == 'sqlalchemy' and node.attr in {'text', 'select'}:
                return Value(callable_kind=node.attr)
            if value.request and node.attr in REQUEST_FIELDS:
                return Value(frozenset({node.lineno}))
            return Value(value.sources, value.assignments, False, value.uncertain)
        if isinstance(node, ast.Call):
            receiver = self.value(node.func.value, env, depth + 1) if isinstance(node.func, ast.Attribute) else Value()
            args = [self.value(arg, env, depth + 1) for arg in node.args]
            keywords = {kw.arg: self.value(kw.value, env, depth + 1) for kw in node.keywords}
            function_value = self.value(node.func, env, depth + 1)
            if isinstance(node.func, ast.Attribute) and node.func.attr in {'execute', 'executemany', 'query', 'raw'}:
                query = args[0] if args else merge(*(keywords.get(key, Value()) for key in ('statement', 'query', 'sql')))
                if query.sources and query.predicate:
                    if len(self.unverified) >= MAX_FINDINGS:
                        raise LimitReached('unverified query occurrence budget exceeded')
                    self.unverified[self.offset(node)] = {'line': node.lineno,
                        'reason': 'Overloaded predicate or unknown query DSL; no direct string flow established'}
                if query.sources and not query.predicate:
                    start, end = self.offset(node), self.offset(node, True)
                    prior = self.findings.get(start)
                    if prior:
                        query = merge(query, prior['value'])
                    elif len(self.findings) >= MAX_FINDINGS:
                        raise LimitReached('query occurrence budget exceeded')
                    self.findings[start] = {'offset': start, 'end': end, 'line': node.lineno, 'value': query,
                                           'legacy_offset': self.offset(node.func, True) - len(node.func.attr) - 1}
                return Value()  # database results are not themselves query text
            if function_value.callable_kind == 'text':
                value = args[0] if args else keywords.get('text', Value())
                return replace(value, query_text=True, request=False, callable_kind='')
            if function_value.callable_kind == 'select':
                value = merge(*(value for value in args if value.query_text or value.builder))
                return replace(value, builder=True, callable_kind='', request=False)
            if receiver.builder and isinstance(node.func, ast.Attribute) and node.func.attr in {
                    'where', 'filter', 'filter_by', 'values', 'order_by', 'select_from', 'join'}:
                # Only an import-bound SQLAlchemy builder grants this distinction:
                # scalar predicates/values bind parameters; explicit raw SQL stays tainted.
                value = merge(receiver, *(value for value in [*args, *keywords.values()]
                                          if value.query_text or value.builder))
                return replace(value, builder=True, callable_kind='', request=False)
            # SQLAlchemy bindparams supplies values, not SQL text. Preserve any
            # taint already in its receiver; never let values taint a literal query.
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'bindparams' and (receiver.query_text or receiver.builder):
                return receiver
            value = merge(receiver, *args, *keywords.values())
            # request.get_json() and related source-method calls already carry
            # provenance through their attribute; unknown wrappers preserve it too.
            value = merge(value, function_value)
            return Value(value.sources, value.assignments, False, bool(value.sources),
                         query_text=bool(value.sources), predicate=value.predicate)
        if isinstance(node, (ast.Lambda, ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp)):
            return Value(uncertain=True)
        values = [self.value(child, env, depth + 1) for child in ast.iter_child_nodes(node)]
        value = merge(*values)
        if isinstance(node, (ast.JoinedStr, ast.BinOp)):
            value = replace(value, query_text=bool(value.sources), predicate=False)
        elif isinstance(node, ast.Compare):
            value = replace(value, query_text=False, predicate=True)
        return value

    def bind(self, target, value, env, line, *, imported=False):
        if isinstance(target, ast.Name):
            if target.id not in env and len(env) >= MAX_BINDINGS:
                raise LimitReached('local binding budget exceeded')
            assignments = value.assignments | {line} if value.sources else frozenset()
            env[target.id] = replace(value, assignments=frozenset(sorted(assignments)[:8]),
                                     callable_kind=value.callable_kind if imported else '')
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self.bind(item, value, env, line)
        elif isinstance(target, ast.Starred):
            self.bind(target.value, value, env, line)

    def assignment(self, node, env):
        """Evaluate all RHS elements before changing targets (including swaps)."""
        if isinstance(node, (ast.Tuple, ast.List)) and not any(isinstance(item, ast.Starred) for item in node.elts):
            return tuple(self.assignment(item, env) for item in node.elts)
        return self.value(node, env)

    def bind_assignment(self, target, value, env, line):
        if (isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, tuple)
                and len(target.elts) == len(value) and not any(isinstance(item, ast.Starred) for item in target.elts)):
            for item, element in zip(target.elts, value):
                self.bind_assignment(item, element, env, line)
            return
        def combined(item):
            return merge(*(combined(child) for child in item)) if isinstance(item, tuple) else item
        self.bind(target, combined(value), env, line)

    def loop_gaps(self, statements):
        pending, calls, written = list(statements), [], set()
        while pending:
            node = pending.pop()
            self.tick()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                written.add(node.id)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {'execute', 'executemany', 'query', 'raw'}:
                calls.append(node)
            pending.extend(ast.iter_child_nodes(node))
        for call in calls:
            query = call.args[:1] or [kw.value for kw in call.keywords if kw.arg in {'statement', 'query', 'sql'}]
            names = set()
            for value in query:
                for item in ast.walk(value):
                    self.tick()
                    if isinstance(item, ast.Name):
                        names.add(item.id)
            start = self.offset(call)
            if names & written and start not in self.findings:
                if len(self.unverified) >= MAX_FINDINGS:
                    raise LimitReached('unverified query occurrence budget exceeded')
                self.unverified[start] = {'line': call.lineno,
                    'reason': 'Query binding written within loop; later iterations require review (no fixed-point analysis)'}

    def joined(self, env, *branches):
        keys = set(env).union(*(set(branch) for branch in branches))
        self.tick(len(keys))
        if len(keys) > MAX_BINDINGS:
            raise LimitReached('joined binding budget exceeded')
        return {key: merge(*(branch.get(key, Value()) for branch in branches)) for key in keys}

    def block(self, statements, env, depth=0):
        if depth > MAX_DEPTH:
            raise LimitReached('statement depth exceeded')
        for node in statements:
            self.tick()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.scopes += 1
                if self.scopes > MAX_SCOPES:
                    raise LimitReached('function scope budget exceeded')
                local = dict(env)
                # Local names cannot borrow a same-named global assignment.
                pending = list(node.body)
                while pending:
                    item = pending.pop()
                    self.tick()
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        local.pop(item.name, None)
                        continue
                    if isinstance(item, ast.Lambda):
                        continue
                    if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store):
                        local.pop(item.id, None)
                    pending.extend(ast.iter_child_nodes(item))
                for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
                    local[arg.arg] = Value(request=arg.arg in {'request', 'req'})
                for arg in (node.args.vararg, node.args.kwarg):
                    if arg:
                        local[arg.arg] = Value()
                if len(local) > MAX_BINDINGS:
                    raise LimitReached('function binding budget exceeded')
                self.block(node.body, local, depth + 1)
                self.bind(ast.Name(id=node.name), Value(), env, node.lineno)
            elif isinstance(node, ast.ClassDef):
                self.block(node.body, dict(env), depth + 1)
                self.bind(ast.Name(id=node.name), Value(), env, node.lineno)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                value = self.value(node.value, env) if isinstance(node, ast.AugAssign) else self.assignment(node.value, env)
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if isinstance(node, ast.AugAssign):
                    value = merge(self.value(node.target, env), value)
                for target in targets:
                    self.bind_assignment(target, value, env, node.lineno)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    self.bind(ast.Name(id=alias.asname or alias.name),
                              Value(request=node.module == 'flask' and alias.name == 'request',
                                    callable_kind=alias.name if node.module == 'sqlalchemy' and alias.name in {'text', 'select'}
                                    and id(alias) in self.trusted_imports else ''), env, node.lineno, imported=True)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.bind(ast.Name(id=alias.asname or alias.name.split('.')[0]),
                              Value(callable_kind='sqlalchemy' if alias.name == 'sqlalchemy' and id(alias) in self.trusted_imports else ''),
                              env, node.lineno, imported=True)
            elif isinstance(node, ast.If):
                self.value(node.test, env)
                left = self.block(node.body, dict(env), depth + 1)
                right = self.block(node.orelse, dict(env), depth + 1)
                env = self.joined(env, left, right)
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                self.value(node.iter if isinstance(node, (ast.For, ast.AsyncFor)) else node.test, env)
                loop = dict(env)
                if hasattr(node, 'target'):
                    self.bind(node.target, Value(uncertain=True), loop, node.lineno)
                loop = self.block(node.body, loop, depth + 1)
                self.loop_gaps(node.body)
                env = self.joined(env, env, loop)
                env = self.block(node.orelse, env, depth + 1)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    self.value(item.context_expr, env)
                    if item.optional_vars:
                        self.bind(item.optional_vars, Value(), env, node.lineno)
                env = self.block(node.body, env, depth + 1)
            elif isinstance(node, (ast.Try, ast.TryStar)):
                body = self.block(node.body, dict(env), depth + 1)
                branches = [self.block(node.orelse, body, depth + 1)]
                branches.extend(self.block(handler.body, self.joined(env, env, body), depth + 1) for handler in node.handlers)
                env = self.joined(env, *branches)
                env = self.block(node.finalbody, env, depth + 1)
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    self.bind(target, Value(uncertain=True), env, node.lineno)
            elif isinstance(node, (ast.Return, ast.Raise)):
                self.value(node.value if isinstance(node, ast.Return) else node.exc, env)
                break
            else:
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, ast.expr):
                        self.value(child, env)
        return env


def analyze(source, budget=None):
    result = {'occurrences': [], 'unverified_queries': [], 'errors': [], 'nodes': 0, 'candidate': bool(QUERY_CALL.search(source))}
    if not result['candidate']:
        return result
    budget = budget if budget is not None else Budget()
    analysis = Analysis('', budget)
    try:
        size = len(source.encode('utf-8'))
        if size > MAX_SOURCE_BYTES:
            raise LimitReached('candidate source byte budget exceeded')
        if (budget.source_bytes + size > MAX_TOTAL_SOURCE_BYTES or budget.nodes >= MAX_TOTAL_NODES
                or budget.steps >= MAX_TOTAL_STEPS):
            raise LimitReached('aggregate Python query-flow budget exceeded')
        budget.source_bytes += size
        analysis = Analysis(source, budget)
        tree = ast.parse(source)
        for _node in ast.walk(tree):
            result['nodes'] += 1
            budget.nodes += 1
            if budget.nodes > MAX_TOTAL_NODES:
                raise LimitReached('aggregate AST node budget exceeded')
            if result['nodes'] > MAX_NODES:
                raise LimitReached('AST node budget exceeded')
        analysis.imports(tree)
        analysis.block(tree.body, {'request': Value(request=True), 'req': Value(request=True)})
    except (SyntaxError, ValueError, RecursionError) as error:
        result['errors'].append({'kind': type(error).__name__, 'detail': str(error)[:240]})
    for row in analysis.findings.values():
        value = row.pop('value')
        row.update(source_lines=sorted(value.sources), assignment_lines=sorted(value.assignments),
                   uncertain_wrapper=value.uncertain)
        result['occurrences'].append(row)
    result['unverified_queries'] = list(analysis.unverified.values())
    return result

"""Bounded Django literal-template/same-returned-response observations; target stays data."""
from __future__ import annotations

import ast
from collections import Counter
from itertools import islice
import re
import warnings

MAX_SOURCE_BYTES = 512 * 1024
MAX_NODES = 20_000
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_OBSERVATIONS = 256


def analyze(source, budget):
    result = {'observations': [], 'errors': []}
    if not re.search(r'\b(?:from|import)\s+django\b', source):
        return result
    size = len(source.encode('utf-8'))
    budget['bytes'] += size
    if size > MAX_SOURCE_BYTES or budget['bytes'] > MAX_TOTAL_BYTES:
        result['errors'].append({'detail': 'Django response source budget exceeded'})
        return result
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            tree = ast.parse(source)
        nodes = list(islice(ast.walk(tree), MAX_NODES + 1))
    except (SyntaxError, ValueError, RecursionError):
        result['errors'].append({'detail': 'Django response syntax unresolved'})
        return result
    if len(nodes) > MAX_NODES:
        result['errors'].append({'detail': 'Django response node budget exceeded'})
        return result
    writes = Counter(node.id for node in nodes if isinstance(node, ast.Name)
                     and isinstance(node.ctx, (ast.Store, ast.Del)))
    writes.update(node.arg for node in nodes if isinstance(node, ast.arg))
    writes.update(node.name for node in nodes if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    for node in nodes:
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            root = node.value
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            if isinstance(root, ast.Name):
                writes[root.id] += 1
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {'setattr', 'delattr'}:
            if node.args and isinstance(node.args[0], ast.Name):
                writes[node.args[0].id] += 1
    imports = {}
    for node in nodes:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == '*':
                    return result
                name = alias.asname or alias.name.split('.')[0]
                writes[name] += 1
                if node in tree.body and not getattr(node, 'level', 0):
                    imports[name] = ((node.module+'.'+alias.name) if isinstance(node, ast.ImportFrom)
                                     else alias.name if alias.asname else alias.name.split('.')[0], node.lineno)
    imports = {key: value for key, value in imports.items() if writes[key] == 1}

    def rendered(value, function):
        if not isinstance(value, ast.Call):
            return None
        callee, members = value.func, []
        while isinstance(callee, ast.Attribute):
            members.insert(0, callee.attr)
            callee = callee.value
        if not isinstance(callee, ast.Name):
            return None
        root, suffix = callee.id, ''.join('.'+member for member in members)
        imported = imports.get(root)
        if not imported or imported[0]+suffix != 'django.shortcuts.render' or imported[1] >= function.lineno:
            return None
        options = {keyword.arg: keyword.value for keyword in value.keywords}
        if (len(value.args) not in {2, 3} or any(isinstance(arg, ast.Starred) for arg in value.args)
                or None in options or len(options) != len(value.keywords)
                or set(options) - {'context', 'status', 'content_type'}
                or len(value.args) == 3 and 'context' in options):
            return None
        if 'content_type' in options and literal(options['content_type']) != 'text/html':
            return None
        template = literal(value.args[1])
        if not template:
            return None
        return {'view': function.name, 'line': value.lineno, 'template': template,
                'headers': {}, 'flow_resolved': not bool(function.decorator_list),
                'loader_verified': False, 'deployment_verified': False,
                'basis': 'literal render source and same returned response; loader/middleware/runtime unverified'}

    def literal(node):
        return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

    for function in tree.body:
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) or writes[function.name] != 1:
            continue
        bindings = {}
        for statement in function.body:
            if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
                target = statement.targets[0]
                if isinstance(target, ast.Name):
                    observation = rendered(statement.value, function)
                    if observation:
                        if any(not isinstance(value, (ast.Name, ast.Constant)) for value in
                               [*statement.value.args, *(kw.value for kw in statement.value.keywords)]):
                            for previous in bindings.values():
                                previous['flow_resolved'] = False
                        bindings[target.id] = observation
                        continue
                    bindings.pop(target.id, None)
                elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
                    observation = bindings.get(target.value.id)
                    key = literal(target.slice)
                    if observation and key:
                        if literal(statement.value) is None:
                            for previous in bindings.values():
                                previous['flow_resolved'] = False
                        observation['headers'][key.lower()] = literal(statement.value)
                        continue
            if isinstance(statement, ast.Return):
                observation = bindings.get(statement.value.id) if isinstance(statement.value, ast.Name) else rendered(statement.value, function)
                if observation:
                    budget['observations'] += 1
                    if budget['observations'] > MAX_OBSERVATIONS:
                        result['errors'].append({'detail': 'Django response observation budget exceeded'})
                        return result
                    policy = observation['headers'].get('content-security-policy') if observation['flow_resolved'] else None
                    scripts = re.findall(r'(?:^|;)\s*script-src\s+([^;]*)', policy or '')
                    observation['strict_csp_shape'] = bool(len(scripts) == 1 and "'self'" in scripts[0]
                        and ("'nonce-" in scripts[0] or "'strict-dynamic'" in scripts[0])
                        and not re.search(r"'unsafe-(?:inline|eval)'", scripts[0]))
                    observation['return_line'] = statement.lineno
                    result['observations'].append(observation)
                break  # statements after an unconditional return cannot supply evidence
            # Unknown control flow, aliases and calls can mutate any response; no header credit.
            for observation in bindings.values():
                observation['flow_resolved'] = False
    return result

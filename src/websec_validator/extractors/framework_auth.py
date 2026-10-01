"""Bounded, source-only FastAPI dependency evidence; unresolved controls stay unverified."""
from __future__ import annotations

import ast
from collections import Counter
from itertools import islice
import re
import warnings

MAX_SOURCE_BYTES = 512 * 1024
MAX_NODES = 20_000


def fastapi_guards(source: str) -> dict | None:
    """Return endpoint-local evidence, never credit a Depends name or imported helper.

    Supports local literal decorator paths and direct JWT-decoding dependencies with
    a rejecting branch. Imported dependencies, prefixes, aliases and complex control
    flow require review. This is static evidence, not deployed authorization proof.
    """
    if not re.search(r'\b(?:from|import)\s+fastapi\b', source):
        return None
    unknown = {'guarded': False, 'scope': '', 'reason':
               'FastAPI dependency/endpoint composition unresolved; names and siblings are not protection'}
    if len(source.encode('utf-8')) > MAX_SOURCE_BYTES:
        return {'routes': {}, 'unknown': dict(unknown, reason='FastAPI source-analysis byte budget exceeded')}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            tree = ast.parse(source)
        nodes = list(islice(ast.walk(tree), MAX_NODES + 1))
    except (SyntaxError, ValueError, RecursionError):
        return {'routes': {}, 'unknown': dict(unknown, reason='FastAPI source syntax could not be resolved')}
    if len(nodes) > MAX_NODES:
        return {'routes': {}, 'unknown': dict(unknown, reason='FastAPI source-analysis node budget exceeded')}
    writes = Counter(node.id for node in nodes if isinstance(node, ast.Name)
                     and isinstance(node.ctx, (ast.Store, ast.Del)))
    writes.update(node.arg for node in nodes if isinstance(node, ast.arg))
    writes.update(node.name for node in nodes if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    for node in nodes:
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            root = node.value
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                writes[root.id] += 1
    imports = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split('.')[0]
                writes[name] += 1
                imports[name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == '*':
                    return {'routes': {}, 'unknown': dict(unknown, reason='Wildcard import makes dependency bindings unresolved')}
                name = alias.asname or alias.name
                writes[name] += 1
                if node.level == 0:
                    imports[name] = (node.module or '') + '.' + alias.name
    imports = {name: value for name, value in imports.items() if writes[name] == 1}

    def imported(expr, qualified):
        if isinstance(expr, ast.Name):
            return imports.get(expr.id) == qualified
        if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
            return imports.get(expr.value.id, '') + '.' + expr.attr == qualified
        return False

    receivers = set()
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and writes[node.targets[0].id] == 1
                and isinstance(node.value, ast.Call)
                and any(imported(node.value.func, 'fastapi.' + name) for name in ('FastAPI', 'APIRouter'))):
            receivers.add(node.targets[0].id)
    functions = {node.name: node for node in tree.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and writes[node.name] == 1}
    registrations = {}
    for function in functions.values():
        for decorator in function.decorator_list:
            if (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                    and isinstance(decorator.func.value, ast.Name) and decorator.func.value.id in receivers
                    and decorator.func.attr.upper() in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'} and decorator.args
                    and isinstance(decorator.args[0], ast.Constant)
                    and isinstance(decorator.args[0].value, str)):
                registrations.setdefault((decorator.func.attr.upper(), decorator.args[0].value), []).append((function, decorator))

    def dependency_enforces(call):
        if not (isinstance(call, ast.Call) and any(imported(call.func, 'fastapi.' + name)
                for name in ('Depends', 'Security')) and len(call.args) == 1
                and isinstance(call.args[0], ast.Name)):
            return False
        function = functions.get(call.args[0].id)
        if function is None or function.decorator_list:
            return False
        # Deliberately narrow straight-line shape: verified value, rejection,
        # return of that value. Exceptions/branches/wrappers cannot assert safety.
        body = function.body
        if len(body) != 3 or not isinstance(body[0], ast.Assign) or len(body[0].targets) != 1:
            return False
        assignment, check, returned = body
        target, decode = assignment.targets[0], assignment.value
        if not (isinstance(target, ast.Name) and isinstance(decode, ast.Call)
                and imported(decode.func, 'jwt.decode') and len(decode.args) == 2
                and not any(isinstance(arg, ast.Starred) for arg in decode.args)):
            return False
        parameters = [*function.args.posonlyargs, *function.args.args]
        defaults = dict(zip([arg.arg for arg in parameters[-len(function.args.defaults):]],
                            function.args.defaults)) if function.args.defaults else {}
        parameters += function.args.kwonlyargs
        defaults.update({arg.arg: value for arg, value in zip(function.args.kwonlyargs,
                         function.args.kw_defaults) if value is not None})
        credential = decode.args[0]
        if (not isinstance(credential, ast.Name) or credential.id not in {arg.arg for arg in parameters}
                or credential.id in defaults):
            return False  # fixed/default/unknown supplier cannot establish caller authentication
        options = {kw.arg: kw.value for kw in decode.keywords}
        algorithms = options.get('algorithms')
        if (None in options or len(options) != len(decode.keywords)
                or not isinstance(algorithms, (ast.List, ast.Tuple)) or not algorithms.elts
                or not all(isinstance(value, ast.Constant) and isinstance(value.value, str)
                           and value.value and value.value.lower() != 'none' for value in algorithms.elts)
                or set(options) - {'algorithms', 'audience', 'issuer', 'leeway'}):
            return False
        if not (isinstance(check, ast.If) and not check.orelse
                and isinstance(check.test, ast.UnaryOp) and isinstance(check.test.op, ast.Not)
                and isinstance(check.test.operand, ast.Name) and check.test.operand.id == target.id
                and len(check.body) == 1 and isinstance(check.body[0], ast.Raise)):
            return False
        exception = check.body[0].exc
        rejected = (isinstance(exception, ast.Call) and imported(exception.func, 'fastapi.HTTPException')
                    and any(kw.arg == 'status_code' and isinstance(kw.value, ast.Constant)
                            and kw.value.value in (401, 403) for kw in exception.keywords))
        return (rejected and isinstance(returned, ast.Return) and isinstance(returned.value, ast.Name)
                and returned.value.id == target.id)

    results = {}
    dependency_results = {}
    for key, matched in registrations.items():
        guarded = []
        for function, decorator in matched:
            candidates = list(function.args.defaults) + [value for value in function.args.kw_defaults if value]
            for keyword in decorator.keywords:
                if keyword.arg == 'dependencies' and isinstance(keyword.value, (ast.List, ast.Tuple)):
                    candidates.extend(keyword.value.elts)
            controls = []
            for value in candidates:
                identity = ast.dump(value)
                if identity not in dependency_results:
                    dependency_results[identity] = dependency_enforces(value)
                controls.append(dependency_results[identity])
            guarded.append(any(controls))
        results[key] = {'guarded': all(guarded), 'scope': '',
                        'reason': '' if all(guarded) else unknown['reason']}
    return {'routes': results, 'unknown': unknown}

"""Bounded FastAPI upload provenance; no target imports or runtime safety certificate."""
from __future__ import annotations

import ast
from collections import Counter
from itertools import islice
import warnings

MAX_SOURCE_BYTES = 512 * 1024
MAX_NODES = 20_000
MAX_BINDINGS = 512
_METHODS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options'}
_TYPES = {'image/png', 'image/jpeg', 'image/webp', 'application/pdf'}


def analyze(source: str) -> dict:
    """Top-level bound UploadFile route parameters and supported local may-flow.

    Unknown wrappers/closures/dynamic registrations remain unverified. Filename
    leads require a write/storage operation; declared MIME requires an actual
    decision/use, never bare metadata logs or response fields. Validation credit
    is a narrow same-file detected-type rejection, not whole-file sniff presence.
    """
    if len(source.encode('utf-8')) > MAX_SOURCE_BYTES:
        raise ValueError('Python upload source byte budget exceeded')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            tree = ast.parse(source)
        nodes = list(islice(ast.walk(tree), MAX_NODES + 1))
    except (SyntaxError, ValueError, RecursionError) as error:
        raise ValueError('Python upload syntax unresolved') from error
    if len(nodes) > MAX_NODES:
        raise ValueError('Python upload AST node budget exceeded')
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
    imports, lines = {}, {}
    for node in nodes:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == '*':
                    return {'handlers': [], 'findings': [], 'unverified': ['wildcard import bindings']}
                name = alias.asname or alias.name.split('.')[0]
                writes[name] += 1
                if node not in tree.body or isinstance(node, ast.ImportFrom) and node.level:
                    continue
                imports[name] = ((node.module or '') + '.' + alias.name if isinstance(node, ast.ImportFrom)
                                 else alias.name if alias.asname else alias.name.split('.')[0])
                lines[name] = node.lineno
    imports = {name: value for name, value in imports.items() if writes[name] == 1}

    def qualified(expr):
        if isinstance(expr, ast.Name):
            return imports.get(expr.id, '') if lines.get(expr.id, expr.lineno) < expr.lineno else ''
        if isinstance(expr, ast.Attribute):
            base = qualified(expr.value)
            return base + '.' + expr.attr if base else ''
        return ''

    receivers = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and writes[node.targets[0].id] == 1 and isinstance(node.value, ast.Call)
                and qualified(node.value.func) in {'fastapi.FastAPI', 'fastapi.APIRouter'}):
            receivers[node.targets[0].id] = node.lineno

    def upload_annotation(expr):
        if isinstance(expr, ast.Subscript) and qualified(expr.value) == 'typing.Annotated':
            expr = expr.slice.elts[0] if isinstance(expr.slice, ast.Tuple) and expr.slice.elts else None
        return expr is not None and qualified(expr) == 'fastapi.UploadFile'

    handlers, findings, seen = [], [], set()
    for function in tree.body:
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) or writes[function.name] != 1:
            continue
        registered = any(isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
            and isinstance(dec.func.value, ast.Name) and dec.func.value.id in receivers
            and receivers[dec.func.value.id] < function.lineno and dec.func.attr in _METHODS
            and dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str)
            for dec in function.decorator_list)
        parameters = {arg.arg for arg in [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
                      if arg.annotation is not None and upload_annotation(arg.annotation)}
        if not registered or not parameters:
            continue
        handlers.append({'function': function.name, 'line': function.lineno, 'parameters': sorted(parameters)})
        env = {name: {(name, 'object')} for name in parameters}
        no_credit = (len(function.decorator_list) != 1
                     or any(isinstance(node, (ast.Try, ast.TryStar)) for node in ast.walk(function)))

        def values(expr, state):
            if expr is None or isinstance(expr, (ast.Constant, ast.Lambda)):
                return set()
            if isinstance(expr, ast.Name):
                return state.get(expr.id, set())
            if isinstance(expr, ast.Await):
                return values(expr.value, state)
            if isinstance(expr, ast.Attribute):
                result = values(expr.value, state)
                kinds = {'filename': 'filename', 'content_type': 'mime', 'file': 'stream'}
                if expr.attr in kinds:
                    return {(name, kinds[expr.attr]) for name, kind in result if kind == 'object'}
                return result
            if (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == 'read'
                    and not expr.args and not expr.keywords):
                return {(name, 'bytes') for name, kind in values(expr.func.value, state) if kind in {'object', 'stream'}}
            # Unknown calls/operations preserve possible metadata use but cannot
            # manufacture exact original bytes or a detector-result identity.
            return {(name, kind) for child in ast.iter_child_nodes(expr) for name, kind in values(child, state)
                    if kind in {'filename', 'mime'}}

        def emit(kind, node, detail):
            identity = kind, node.lineno, function.name
            if identity not in seen:
                seen.add(identity)
                findings.append({'kind': kind, 'severity': 'HIGH' if kind == 'upload-key-from-filename' else 'MEDIUM',
                                 'line': node.lineno, 'handler': function.name,
                                 'control_scope': 'supported local Python upload flow; complex controls unverified',
                                 'detail': detail})

        def mime(expr, state, checked):
            if any(kind == 'mime' and name not in checked for name, kind in values(expr, state)):
                emit('upload-trusts-client-mime', expr, 'A storage/validation operation uses caller-declared '
                     'UploadFile.content_type without supported same-file detected-type rejection. '
                     'Metadata is not proof of bytes; verify complex controls and serve policy.')

        def calls(expr, state, checked):
            if expr is None or isinstance(expr, ast.Lambda):
                return
            if isinstance(expr, (ast.Compare, ast.BoolOp)):
                mime(expr, state, checked)
            if isinstance(expr, ast.Call):
                name = expr.func.id if isinstance(expr.func, ast.Name) else expr.func.attr if isinstance(expr.func, ast.Attribute) else ''
                root = expr.func.value if isinstance(expr.func, ast.Attribute) else None
                logger = isinstance(root, ast.Name) and root.id in {'logger', 'logging'} and name in {'info', 'debug', 'warning', 'error', 'exception'}
                call_checked = checked
                if name in {'store', 'save', 'put_object', 'upload_file', 'upload_fileobj', 'write_bytes', 'write_text'}:
                    data_args = list(expr.args[1:] if name in {'store', 'save'} and len(expr.args) > 1 else expr.args)
                    data_args += [kw.value for kw in expr.keywords if kw.arg in {'Body', 'body', 'data'}]
                    byte_sets = [{name for name, kind in values(arg, state) if kind == 'bytes'} for arg in data_args]
                    same_bytes = set.intersection(*byte_sets) if byte_sets and all(byte_sets) else set()
                    call_checked = checked & same_bytes
                if not logger and (name != 'print' or writes['print']):
                    for arg in [*expr.args, *(kw.value for kw in expr.keywords)]:
                        mime(arg, state, call_checked)
                paths = []
                if name == 'open' and isinstance(expr.func, ast.Name) and not writes['open'] and expr.args:
                    mode = expr.args[1] if len(expr.args) > 1 else next((kw.value for kw in expr.keywords if kw.arg == 'mode'), None)
                    if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(c in mode.value for c in 'wax+'):
                        paths = [expr.args[0]]
                elif name in {'write_bytes', 'write_text'} and root is not None:
                    paths = [root]
                elif name in {'store', 'save', 'put_object', 'upload_file', 'upload_fileobj'}:
                    paths = list(expr.args[:1]) + [kw.value for kw in expr.keywords if kw.arg in {'Key', 'key', 'path', 'filename', 'destination'}]
                if any(kind == 'filename' for path in paths for _, kind in values(path, state)):
                    emit('upload-key-from-filename', expr, 'A supported write/storage operation derives its path/key '
                         'from caller-supplied UploadFile.filename. This is a source lead, not proof of '
                         'executable storage; generate a server-selected name and verify serving policy.')
            for child in ast.iter_child_nodes(expr):
                calls(child, state, checked)

        def assign(target, value, state):
            if isinstance(target, ast.Name):
                state[target.id] = value
                if len(state) > MAX_BINDINGS:
                    raise ValueError('Python upload binding budget exceeded')
            elif isinstance(target, (ast.Tuple, ast.List)):
                for item in target.elts:
                    assign(item, value, state)

        def rejecting(check, state):
            test = check.test
            if (no_credit or check.orelse or not isinstance(test, ast.Compare) or len(test.ops) != 1
                    or not isinstance(test.ops[0], ast.NotIn) or len(test.comparators) != 1
                    or not isinstance(test.comparators[0], (ast.Set, ast.List, ast.Tuple))):
                return set()
            allowed = test.comparators[0].elts
            if not allowed or not all(isinstance(item, ast.Constant) and item.value in _TYPES for item in allowed):
                return set()
            if len(check.body) != 1:
                return set()
            stop = check.body[0]
            if not isinstance(stop, ast.Raise) or not isinstance(stop.exc, ast.Call) or qualified(stop.exc.func) != 'fastapi.HTTPException':
                return set()
            if (stop.exc.args or len(stop.exc.keywords) != 1 or stop.exc.keywords[0].arg != 'status_code'
                    or not isinstance(stop.exc.keywords[0].value, ast.Constant) or stop.exc.keywords[0].value.value != 415):
                return set()
            return {name for name, kind in values(test.left, state) if kind == 'detected'} if isinstance(test.left, ast.Name) else set()

        def walk(statements, state, checked):
            for statement in statements:
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue  # an unused closure is not an executed storage operation
                if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                    calls(statement.value, state, checked)
                    value = values(statement.value, state)
                    call = statement.value.value if isinstance(statement.value, ast.Await) else statement.value
                    if (isinstance(call, ast.Call) and qualified(call.func) == 'magic.from_buffer' and len(call.args) == 1
                            and len(call.keywords) == 1 and call.keywords[0].arg == 'mime'
                            and isinstance(call.keywords[0].value, ast.Constant) and call.keywords[0].value.value is True):
                        value = {(name, 'detected') for name, kind in values(call.args[0], state) if kind == 'bytes'}
                    for target in statement.targets if isinstance(statement, ast.Assign) else [statement.target]:
                        affected = values(target, state)
                        checked -= {name for name, _ in affected}
                        assign(target, value, state)
                elif isinstance(statement, ast.If):
                    calls(statement.test, state, checked)
                    mime(statement.test, state, checked)
                    credit = rejecting(statement, state)
                    if not credit:
                        checked.clear()  # an unsupported branch cannot preserve a validation proof
                    left, right = dict(state), dict(state)
                    walk(statement.body, left, set(checked))
                    walk(statement.orelse, right, set(checked))
                    for name in left.keys() | right.keys():
                        state[name] = left.get(name, set()) | right.get(name, set())
                    checked.update(credit)
                elif isinstance(statement, (ast.With, ast.AsyncWith)):
                    for item in statement.items:
                        calls(item.context_expr, state, checked)
                        if item.optional_vars:
                            assign(item.optional_vars, set(), state)
                    walk(statement.body, state, checked)
                elif isinstance(statement, (ast.Return, ast.Expr, ast.Raise)):
                    calls(getattr(statement, 'value', getattr(statement, 'exc', None)), state, checked)
                    if isinstance(statement, (ast.Return, ast.Raise)):
                        break
                else:
                    # Unsupported loops/try/match preserve possible local flow but
                    # can never establish enforcing byte validation.
                    checked.clear()
                    for child in ast.iter_child_nodes(statement):
                        if isinstance(child, ast.expr):
                            calls(child, state, checked)
                            if isinstance(statement, (ast.Assert, ast.While)):
                                mime(child, state, checked)
                    for field in ('body', 'orelse', 'finalbody'):
                        branch = getattr(statement, field, [])
                        alternative = dict(state)
                        walk(branch, alternative, set())
                        for name, value in alternative.items():
                            state[name] = state.get(name, set()) | value
                    for handler in getattr(statement, 'handlers', []):
                        walk(handler.body, state, set())
        walk(function.body, env, set())
    return {'handlers': handlers, 'findings': findings,
            'unverified': ['cross-function flow, dynamic registrations, upload collections and complex validation']}

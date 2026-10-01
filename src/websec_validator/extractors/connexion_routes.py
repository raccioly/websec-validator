"""Bounded local Connexion registration evidence, never execute/import the target."""
from __future__ import annotations

import ast
from collections import Counter
from itertools import islice
from pathlib import Path
import re
from urllib.parse import urlsplit
import warnings

from .framework_auth import MAX_NODES, MAX_SOURCE_BYTES
from .. import literal_yaml

MAX_TOTAL_NODES = 100_000
MAX_ROUTES = 1024
MAX_DIAGNOSTICS = 80


def operation_bodies(source):
    """Exact immutable top-level Python functions; absence is not lack of auth."""
    if len(source.encode('utf-8')) > MAX_SOURCE_BYTES:
        return {}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            tree = ast.parse(source)
        nodes = list(islice(ast.walk(tree), MAX_NODES + 1))
    except (SyntaxError, ValueError, RecursionError):
        return {}
    if len(nodes) > MAX_NODES:
        return {}
    writes = Counter(node.id for node in nodes if isinstance(node, ast.Name)
                     and isinstance(node.ctx, (ast.Store, ast.Del)))
    writes.update(node.name for node in nodes if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    writes.update(node.arg for node in nodes if isinstance(node, ast.arg))
    for node in nodes:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == '*':
                    return {}
                writes[alias.asname or alias.name.split('.')[0]] += 1
    return {node.name: '\n'.join([*(ast.get_source_segment(source, dec) or '' for dec in node.decorator_list),
                                ast.get_source_segment(source, node) or ''])
            for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and writes[node.name] == 1}


def analyze(ctx):
    result = {'routes': [], 'gaps': [], 'errors': [], 'diagnostics_truncated': 0,
              'limits': {'source_bytes': MAX_SOURCE_BYTES, 'nodes_per_file': MAX_NODES,
                         'nodes_total': MAX_TOTAL_NODES, 'routes': MAX_ROUTES},
              'note': 'Literal top-level local registrations are source evidence, not deployed '
                      'handler or security enforcement proof. Registered YAML uses a strict literal subset; dynamic '
                      'registration, templates, resolvers and cross-module composition remain unverified.'}
    total = 0

    def gap(rel, reason, *, error=False):
        bucket = result['errors' if error else 'gaps']
        if len(result['gaps']) + len(result['errors']) < MAX_DIAGNOSTICS:
            bucket.append({'file': rel, 'detail': reason})
        else:
            result['diagnostics_truncated'] += 1

    def literal(node):
        return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None

    for path, rel, source in ctx.iter_code():
        if path.suffix != '.py' or not re.search(r'\bconnexion\b', source):
            continue
        if len(source.encode('utf-8')) > MAX_SOURCE_BYTES:
            gap(rel, 'Connexion source byte budget exceeded', error=True)
            continue
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                tree = ast.parse(source)
            nodes = list(islice(ast.walk(tree), MAX_NODES + 1))
        except (SyntaxError, ValueError, RecursionError):
            gap(rel, 'Connexion source syntax unresolved', error=True)
            continue
        total += len(nodes)
        if len(nodes) > MAX_NODES or total > MAX_TOTAL_NODES:
            gap(rel, 'Connexion AST node budget exceeded', error=True)
            if total > MAX_TOTAL_NODES:
                break
            continue
        writes = Counter(node.id for node in nodes if isinstance(node, ast.Name)
                         and isinstance(node.ctx, (ast.Store, ast.Del)))
        writes.update(node.arg for node in nodes if isinstance(node, ast.arg))
        writes.update(node.name for node in nodes if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
        imports = {}
        import_lines = {}
        wildcard = False
        for node in nodes:
            if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
                # A literal Flask configuration item does not replace the Connexion
                # receiver or add_api primitive. It supplies no auth/route-runtime credit.
                if (isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant)
                        and isinstance(node.slice.value, str) and isinstance(node.value, ast.Attribute)
                        and node.value.attr == 'config' and isinstance(node.value.value, ast.Attribute)
                        and node.value.value.attr == 'app' and isinstance(node.value.value.value, ast.Name)):
                    continue
                root = node.value
                while isinstance(root, (ast.Attribute, ast.Subscript)):
                    root = root.value
                if isinstance(root, ast.Name):
                    writes[root.id] += 1
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {'setattr', 'delattr'}:
                if node.args and isinstance(node.args[0], ast.Name):
                    writes[node.args[0].id] += 1
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split('.')[0]
                    writes[name] += 1
                    if node in tree.body:
                        imports[name] = alias.name
                        import_lines[name] = node.lineno
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    wildcard |= alias.name == '*'
                    name = alias.asname or alias.name
                    writes[name] += 1
                    if not node.level and node in tree.body:
                        imports[name] = (node.module or '') + '.' + alias.name
                        import_lines[name] = node.lineno
        if wildcard:
            gap(rel, 'Wildcard import makes Connexion bindings unresolved')
            continue
        imports = {name: value for name, value in imports.items() if writes[name] == 1}

        def qualified(expr):
            if isinstance(expr, ast.Name):
                return imports.get(expr.id, '')
            if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
                return imports.get(expr.value.id, '') + '.' + expr.attr
            return ''

        receivers = {}
        for node in tree.body:
            if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) and writes[node.targets[0].id] == 1
                    and isinstance(node.value, ast.Call)
                    and qualified(node.value.func) in {'connexion.App', 'connexion.FlaskApp', 'connexion.AsyncApp'}):
                continue
            call = node.value
            imported_name = call.func.id if isinstance(call.func, ast.Name) else call.func.value.id
            options = {kw.arg: kw.value for kw in call.keywords}
            directory = literal(options['specification_dir']) if 'specification_dir' in options else ''
            if (len(call.args) != 1 or not isinstance(call.args[0], ast.Name) or call.args[0].id != '__name__'
                    or writes['__name__'] or import_lines.get(imported_name, node.lineno) >= node.lineno
                    or directory is None or None in options
                    or len(options) != len(call.keywords) or set(options) - {'specification_dir'}):
                gap(rel, 'App root or constructor options unresolved')
                continue
            receivers[node.targets[0].id] = (directory, node.lineno)
        direct_calls = {id(node.value) for node in tree.body if isinstance(node, ast.Expr)}
        for call in nodes:
            if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                    and call.func.attr == 'add_api' and isinstance(call.func.value, ast.Name)):
                continue
            receiver = call.func.value.id
            if receiver not in receivers or id(call) not in direct_calls or call.lineno <= receivers[receiver][1]:
                gap(rel, 'add_api receiver or top-level execution unresolved')
                continue
            options = {kw.arg: kw.value for kw in call.keywords}
            spec = literal(call.args[0]) if len(call.args) == 1 else literal(options.get('specification'))
            if (len(call.args) > 1 or (call.args and 'specification' in options) or None in options
                    or len(options) != len(call.keywords) or spec is None
                    or set(options) - {'specification', 'base_path', 'name'}):
                gap(rel, 'Specification, templates or registration options unresolved')
                continue
            directory = Path(receivers[receiver][0])
            destination = path.parent / directory / spec
            if (directory.is_absolute() or Path(spec).is_absolute() or '..' in directory.parts
                    or '..' in Path(spec).parts or re.match(r'^[A-Za-z][\w+.-]*:', spec)
                    or destination.suffix.lower() not in {'.json', '.yaml', '.yml'}):
                gap(rel, 'Specification destination is not a contained local literal path')
                continue
            # The shared reader enforces private-tree/exclude/alias containment too.
            text = ctx.text(destination)
            if not text:
                gap(rel, 'Registered specification missing, excluded or unreadable')
                continue
            from .. import openapi
            try:
                doc, mode = literal_yaml.load(text)
            except literal_yaml.LimitReached as error:
                gap(rel, str(error), error=True)
                continue
            except (AttributeError, TypeError, ValueError, RecursionError):
                gap(rel, 'Registered specification malformed or outside supported literal syntax')
                continue
            if not isinstance(doc, dict) or not (doc.get('openapi') or doc.get('swagger')) or not doc.get('paths'):
                gap(rel, 'Registered specification has no usable contract paths')
                continue
            if not isinstance(doc.get('paths'), dict) or not all(
                    isinstance(item, dict) and all(isinstance(value, dict) for key, value in item.items()
                                                   if key in openapi._HTTP_METHODS)
                    for item in doc['paths'].values()):
                gap(rel, 'Registered operation shape malformed')
                continue
            if any('$ref' in item or any('$ref' in value for key, value in item.items()
                                        if key in openapi._HTTP_METHODS) for item in doc['paths'].values()):
                gap(rel, 'Registered path/operation references unresolved')
                continue
            if any(isinstance(value.get('operationId'), literal_yaml.BlockText) for item in doc['paths'].values()
                   for key, value in item.items() if key in openapi._HTTP_METHODS):
                gap(rel, 'Block-scalar routing identifiers are outside the literal subset')
                continue
            base = literal(options.get('base_path')) if 'base_path' in options else doc.get('basePath', '')
            if 'base_path' not in options and 'servers' in doc:
                servers = doc['servers']
                if (not isinstance(servers, list) or len(servers) != 1 or not isinstance(servers[0], dict)
                        or type(servers[0].get('url')) is not str or servers[0].get('variables')):
                    gap(rel, 'OpenAPI server path unresolved')
                    continue
                try:
                    base = urlsplit(servers[0]['url']).path
                except ValueError:
                    gap(rel, 'OpenAPI server URL malformed')
                    continue
            if (type(base) is not str or (base and not base.startswith('/'))
                    or any(c in base for c in ('{', '}', '?', '#', '\\'))):
                gap(rel, 'Registered base path unresolved')
                continue
            for endpoint, item in doc['paths'].items():
                if not isinstance(endpoint, str) or not endpoint.startswith('/') or any(c in endpoint for c in ('?', '#', '\\')):
                    gap(rel, 'Registered endpoint path malformed')
                    continue
                for method in (key for key in openapi._HTTP_METHODS if key in item):
                    if len(result['routes']) >= MAX_ROUTES:
                        gap(rel, 'Connexion route budget exceeded', error=True)
                        return result
                    result['routes'].append({'method': method.upper(), 'path': base.rstrip('/') + endpoint,
                                             'params': [], 'technology': 'connexion', 'code_path': rel,
                                             'spec_path': ctx.rel(destination), 'source': 'connexion-registration',
                                             'contract_path': endpoint,
                                             'contract_mode': mode,
                                             'operation_id': item[method].get('operationId') if isinstance(item[method].get('operationId'), str) else None,
                                             'registration_line': call.lineno})
    return result

"""Bounded local tRPC composition; only visible Express mounts supply HTTP paths."""
from __future__ import annotations

import re

from .syntax import expression_end, in_literal, js_functions, object_properties, split_arguments, without_comments

MAX_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_BINDINGS = 512
MAX_ROUTES = 1024
MAX_DEPTH = 16


def _file(source: str, rel: str) -> dict:
    source = without_comments(source, '.ts')
    if len(source.encode('utf-8')) > MAX_BYTES:
        raise ValueError('tRPC source byte budget exceeded')
    # Mask literals before inspecting top-level lexical braces. Unsupported
    # TypeScript/generic/runtime composition remains a gap, never executed.
    masked = re.sub(r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`''',
                    lambda match: ' ' * len(match[0]), source)
    levels, depth = [], 0
    for char in masked:
        levels.append(depth)
        depth += (char == '{') - (char == '}')
    functions = js_functions(source)
    imports, import_lines = {}, {}
    for match in re.finditer(r'''\bimport\s+(\{[^{}]*\}|[\w$]+)\s+from\s+(['"])([^'"]+)\2''', source):
        if levels[match.start()] or in_literal(source, match.start()):
            continue
        if match[1].startswith('{'):
            for part in split_arguments(match[1][1:-1]):
                binding = re.fullmatch(r'([\w$]+)(?:\s+as\s+([\w$]+))?', part)
                if binding:
                    name = binding[2] or binding[1]
                    imports[name] = (match[3], binding[1])
                    import_lines[name] = match.start()
        else:
            imports[match[1]] = (match[3], 'default')
            import_lines[match[1]] = match.start()
    bindings, positions = {}, {}
    declarations = list(re.finditer(r'\b(?:const|let|var)\s+([\w$]+)\s*=\s*', source))
    if len(declarations) > MAX_BINDINGS:
        raise ValueError('tRPC binding budget exceeded')
    for match in declarations:
        if levels[match.start()] or in_literal(source, match.start()):
            continue
        bindings[match[1]] = source[match.end():expression_end(source, match.end())].strip()
        positions[match[1]] = match.start()

    def stable(name):
        if not re.fullmatch(r'[\w$]+', name):
            return False
        writes = re.finditer(r'(?<![\w$.])' + re.escape(name) + r'\s*=(?!=)', source)
        if sum(not in_literal(source, match.start()) for match in writes) > (1 if name in bindings else 0):
            return False
        mutations = re.compile(r'\b' + re.escape(name) + r'(?:\.[\w$]+(?:\.[\w$]+)*\s*=(?!=)|(?:\.[\w$]+)*\s*\[)|'
            r'\b(?:setattr|Object\.(?:assign|defineProperty|defineProperties)|Reflect\.(?:set|defineProperty))\s*\(\s*' + re.escape(name) + r'\b')
        if any(not in_literal(source, match.start()) for match in mutations.finditer(source)):
            return False
        if any(scope['name'] == name or re.search(r'\b'+re.escape(name)+r'\b',
                source[scope['start']:scope['body_start']]) for scope in functions):
            return False
        # A second declaration or destructured alias makes lexical provenance unknown.
        declarations_here = re.finditer(r'\b(?:const|let|var|function|class)\s+'+re.escape(name)+r'\b', source)
        if sum(not in_literal(source, match.start()) for match in declarations_here) > (1 if name in bindings else 0):
            return False
        return not any(not in_literal(source, match.start()) for match in re.finditer(
            r'\b(?:const|let|var)\s*\{[^{};]*\b'+re.escape(name)+r'\b', source))

    def imported(name, package, export, position):
        return imports.get(name) == (package, export) and import_lines[name] < position and stable(name)

    instances, apps = set(), set()
    for name, value in bindings.items():
        init = re.fullmatch(r'([\w$]+)\.create\(\s*\)', value)
        if init and imported(init[1], '@trpc/server', 'initTRPC', positions[name]) and stable(name):
            instances.add(name)
        app = re.fullmatch(r'([\w$]+)\(\s*\)', value)
        if app and imported(app[1], 'express', 'default', positions[name]) and stable(name):
            apps.add(name)

    def enforcing(value, instance, position, depth=0):
        if depth > MAX_DEPTH:
            return False
        if value in bindings:
            return stable(value) and positions[value] < position and enforcing(bindings[value], instance, positions[value], depth + 1)
        middleware = re.fullmatch(re.escape(instance) + r'\.middleware\((.*)\)', value, re.S)
        if not middleware:
            return False
        callback = re.fullmatch(r'(?:async\s*)?\(\s*\{\s*ctx\s*,\s*next\s*\}\s*\)\s*=>\s*\{(.*)\}', middleware[1].strip(), re.S)
        if not callback:
            return False
        # A deliberately complete body shape. Presence of ctx.user is only a
        # rejection hint; the context supplier and runtime identity remain unverified.
        body = re.fullmatch(r'\s*if\s*\(\s*!ctx\.user\s*\)\s*\{\s*throw\s+new\s+([\w$]+)\s*\('
            r'\s*\{\s*code\s*:\s*([\'"])UNAUTHORIZED\2\s*\}\s*\)\s*;?\s*\}\s*return\s+next\(\s*\)\s*;?\s*', callback[1], re.S)
        return bool(body and imported(body[1], '@trpc/server', 'TRPCError', len(source)))

    def procedure(value, position, depth=0):
        if depth > MAX_DEPTH:
            return None
        if value in bindings:
            return procedure(bindings[value], positions[value], depth + 1) if stable(value) and positions[value] < position else None
        base = re.fullmatch(r'([\w$]+)\.procedure', value)
        if base and base[1] in instances and positions[base[1]] < position:
            return base[1], False, True
        used = re.fullmatch(r'(.*)\.use\((.*)\)', value, re.S)
        if used:
            previous = procedure(used[1], position, depth + 1)
            if previous and len(split_arguments(used[2])) == 1:
                middleware = used[2].strip()
                resolved = bindings.get(middleware, middleware) if stable(middleware) else middleware
                continuation = bool(re.fullmatch(re.escape(previous[0]) +
                    r'\.middleware\(\s*\(\s*\{\s*ctx\s*,\s*next\s*\}\s*\)\s*=>\s*\{\s*return\s+next\(\s*\)\s*;?\s*\}\s*\)', resolved))
                rejects = enforcing(middleware, previous[0], position)
                return previous[0], previous[1] or (previous[2] and rejects), previous[2] and (continuation or rejects)
        return None

    routers = {}
    gaps = []

    def router(value, position, prefix='', depth=0):
        if depth > MAX_DEPTH:
            raise ValueError('tRPC router composition depth exceeded')
        if value in bindings:
            return router(bindings[value], positions[value], prefix, depth + 1) if stable(value) and positions[value] < position else []
        call = re.fullmatch(r'([\w$]+)\.router\((.*)\)', value, re.S)
        properties = object_properties(call[2]) if call and call[1] in instances and positions[call[1]] < position else None
        if properties is None:
            return []
        rows = []
        for name, member in properties.items():
            if not re.fullmatch(r'[A-Za-z_]\w*', name):
                gaps.append({'file': rel, 'detail': 'tRPC procedure segment is unsupported'})
                continue
            path = prefix + name
            operation = re.fullmatch(r'(.*)\.(query|mutation)\((.*)\)', member, re.S)
            previous = procedure(operation[1], position) if operation else None
            if previous and previous[0] == call[1] and len(split_arguments(operation[3])) == 1:
                rows.append({'procedure': path, 'method': 'POST' if operation[2] == 'mutation' else 'GET',
                             'trpc_guarded': previous[1], 'code_path': rel, 'technology': 'trpc',
                             'source': 'trpc-registration', 'params': []})
            else:
                nested = router(member, position, path + '.', depth + 1)
                if nested:
                    rows.extend(nested)
                else:
                    gaps.append({'file': rel, 'detail': 'tRPC member composition is unresolved: ' + path})
            if len(rows) > MAX_ROUTES:
                raise ValueError('tRPC procedure budget exceeded')
        return rows

    for name, value in bindings.items():
        if stable(name) and re.match(r'[\w$]+\.router\(', value):
            routers[name] = router(value, positions[name])
            if not routers[name]:
                gaps.append({'file': rel, 'detail': 'tRPC router/instance composition is unresolved: ' + name})
            if sum(map(len, routers.values())) > MAX_ROUTES:
                raise ValueError('tRPC per-file aggregate procedure budget exceeded')
    routes, mounted = [], set()
    for match in re.finditer(r'\b([\w$]+)\.use\s*\(', source):
        if (levels[match.start()] or in_literal(source, match.start()) or match[1] not in apps
                or positions[match[1]] > match.start()):
            continue
        prefix = source[source.rfind(';', 0, match.start()) + 1:match.start()].strip()
        if prefix:
            gaps.append({'file': rel, 'detail': 'tRPC adapter mount is not a direct top-level statement'})
            continue
        opening = source.find('(', match.start())
        end = expression_end(source, opening, closing=')')
        args = split_arguments(source[opening + 1:end - 1])
        if len(args) != 2 or not re.fullmatch(r'''(['"])/[A-Za-z0-9/_-]*\1''', args[0]):
            continue
        adapter = re.fullmatch(r'([\w$]+)\((.*)\)', args[1], re.S)
        if not adapter or not imported(adapter[1], '@trpc/server/adapters/express', 'createExpressMiddleware', match.start()):
            continue
        options = object_properties(adapter[2])
        name = options.get('router') if options else None
        if (name not in routers or positions[name] > match.start() or set(options) - {'router', 'createContext'}):
            gaps.append({'file': rel, 'detail': 'tRPC Express adapter router/options unresolved'})
            continue
        mounted.add(name)
        routes.extend(dict(row, path=args[0][1:-1].rstrip('/') + '/' + row['procedure']) for row in routers[name])
        if len(routes) > MAX_ROUTES:
            raise ValueError('tRPC per-file mounted route budget exceeded')
    candidates = [dict(row, router=name) for name, rows in routers.items() if name not in mounted for row in rows]
    if candidates:
        gaps.append({'file': rel, 'detail': 'tRPC procedures have no supported visible transport mount; no HTTP target inferred'})
    return {'routes': routes, 'candidates': candidates, 'gaps': gaps}


def analyze(ctx):
    result = {'routes': [], 'candidates': [], 'gaps': [], 'errors': [], 'diagnostics_truncated': 0,
              'limits': {'source_bytes_per_file': MAX_BYTES, 'source_bytes_total': MAX_TOTAL_BYTES,
                         'bindings_per_file': MAX_BINDINGS, 'routes': MAX_ROUTES, 'depth': MAX_DEPTH},
              'note': 'Supported same-file initTRPC/Express mount only. Middleware rejection is source evidence, '
                      'not verified context identity or deployed authorization. Cross-module, generics, '
                      'input chains and other adapters remain unverified.'}
    total = 0
    for path, rel, source in ctx.iter_code():
        if path.suffix not in {'.js', '.ts', '.mjs', '.mts'} or '@trpc/server' not in source:
            continue
        total += len(source.encode('utf-8'))
        try:
            if total > MAX_TOTAL_BYTES:
                raise ValueError('tRPC aggregate source budget exceeded')
            current = _file(source, rel)
            for key in ('routes', 'candidates', 'gaps'):
                result[key].extend(current[key])
                if len(result[key]) > MAX_ROUTES:
                    raise ValueError('tRPC aggregate result budget exceeded')
        except (ValueError, RecursionError) as error:
            if len(result['errors']) < 80:
                result['errors'].append({'file': rel, 'detail': str(error) or 'tRPC recursion budget exceeded'})
            else:
                result['diagnostics_truncated'] += 1
    return result

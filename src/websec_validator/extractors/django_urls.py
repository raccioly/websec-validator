"""Bounded, data-only Django URLconf discovery. Never imports target modules."""
from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath

from .base import is_test_file
from .profiles import service_for

MAX_MODULES = 128
MAX_NODES = 20_000
MAX_TOTAL_NODES = 100_000
MAX_DEPTH = 12
MAX_ROUTES = 2_000
MAX_DIAGNOSTICS = 100
MAX_STEPS = 10_000
MAX_PATH = 4096


def _name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name(node.value)
        return prefix + "." + node.attr if prefix else ""
    return ""


def _string(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _items(node):
    if isinstance(node, (ast.List, ast.Tuple)):
        return list(node.elts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _items(node.left), _items(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _pattern(value):
    if (not isinstance(value, str) or len(value) > 2048 or value.startswith("/")
            or any(c in value for c in "?#{}")
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)):
        return None
    params = []
    def replace(match):
        params.append({"name": match[2], "where": "path", "type": match[1] or "str"})
        return "{" + match[2] + "}"
    path = re.sub(r"<(?:(\w+):)?(\w+)>", replace, value)
    if "<" in path or ">" in path:
        return None
    return path, params


def analyze(ctx, facts: dict) -> dict:
    result = {"routes": [], "candidates": [], "gaps": [], "errors": [],
              "diagnostics_truncated": 0, "modules_parsed": 0,
              "limits": {"modules": MAX_MODULES, "ast_nodes_per_module": MAX_NODES,
                         "ast_nodes_total": MAX_TOTAL_NODES,
                         "traversal_steps": MAX_STEPS,
                         "assembled_path_characters": MAX_PATH,
                         "include_depth": MAX_DEPTH, "routes_and_candidates": MAX_ROUTES},
              "limitations": ["AST declarations only; target code is never imported or executed.",
                              "HTTP methods, deployment settings and dynamic URLconf mutations remain unverified."]}
    inventory = (facts.get("stack") or getattr(ctx, "stack", {})).get("service_inventory", [])
    paths = {ctx.rel(path): path for path in ctx.code_files if path.suffix == ".py"
             and (ctx.include_fixtures or not is_test_file(ctx.rel(path)))}
    modules = {}
    roots = {}
    dynamic_roots = set()
    total_nodes = 0

    def diagnostic(kind, rel, reason, *, error=False, line=None):
        bucket = result["errors" if error else "gaps"]
        row = {"file": rel, "kind": kind, "detail": reason}
        if line is not None:
            row["line"] = line
        if row in bucket:
            return
        if len(bucket) < MAX_DIAGNOSTICS:
            bucket.append(row)
        else:
            result["diagnostics_truncated"] += 1

    def service(rel):
        return service_for(inventory, rel).get("root", ".")

    def resolve(module, owner):
        if not isinstance(module, str) or not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", module):
            return None
        base = service(owner)
        bases = ["" if base == "." else base + "/"]
        bases.append(bases[0] + "src/")
        candidates = {prefix + module.replace(".", "/") + suffix
                      for prefix in bases for suffix in (".py", "/__init__.py")}
        candidates = {rel for rel in candidates if rel in paths and service(rel) == base}
        return next(iter(candidates)) if len(candidates) == 1 else None

    for rel, path in sorted(paths.items()):
        text = ctx.text(path)
        if not any(mark in text for mark in ("urlpatterns", "ROOT_URLCONF")):
            continue
        if result["modules_parsed"] >= MAX_MODULES:
            diagnostic("module_budget", rel, "Django candidate-module budget exhausted", error=True)
            break
        result["modules_parsed"] += 1
        nodes = []
        try:
            tree = ast.parse(text, filename=rel)
            for node in ast.walk(tree):
                nodes.append(node)
                total_nodes += 1
                if len(nodes) > MAX_NODES or total_nodes > MAX_TOTAL_NODES:
                    raise ValueError("AST node budget exceeded")
        except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
            exhausted = len(nodes) > MAX_NODES or total_nodes > MAX_TOTAL_NODES
            diagnostic("ast_budget" if exhausted else "parse_error", rel, type(exc).__name__, error=True)
            if total_nodes > MAX_TOTAL_NODES:
                break
            continue
        bindings = {}
        binding_lines = {}
        repeated_imports = set()
        imported = set()
        for statement in tree.body:
            if isinstance(statement, ast.ImportFrom):
                module_name = statement.module or ""
                if statement.level:
                    owner = service(rel)
                    relative = rel.removeprefix(owner + "/") if owner != "." else rel
                    relative = relative.removeprefix("src/")
                    package = list(PurePosixPath(relative).parent.parts)
                    if statement.level > len(package):
                        continue
                    base = package[:len(package) - statement.level + 1]
                    module_name = ".".join(base + ([module_name] if module_name else []))
                for alias in statement.names:
                    if alias.name != "*":
                        key = alias.asname or alias.name
                        if key in imported:
                            repeated_imports.add(key)
                        bindings[key] = module_name + "." + alias.name
                        binding_lines[key] = statement.lineno
                        imported.add(key)
            elif isinstance(statement, ast.Import):
                for alias in statement.names:
                    key = alias.asname or alias.name.split(".")[0]
                    if key in imported:
                        repeated_imports.add(key)
                    bindings[key] = alias.name if alias.asname else key
                    binding_lines[key] = statement.lineno
                    imported.add(key)
        # Any reassignment or shadowing makes this small import-binding proof
        # ambiguous; do not infer that a same-named custom path() is Django.
        overwritten = {node.id for node in nodes if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)}
        overwritten |= {node.arg for node in nodes if isinstance(node, ast.arg)}
        overwritten |= {node.name for node in nodes if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
        overwritten |= {_name(node).split(".")[0] for node in nodes
                        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del))}
        overwritten |= repeated_imports
        bindings = {key: value for key, value in bindings.items() if key not in overwritten}

        def bound(node):
            name = _name(node)
            first, dot, rest = name.partition(".")
            return (bindings[first] + (dot + rest if dot else "")
                    if first in bindings and binding_lines[first] <= node.lineno else "")

        assignments = [node for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))
                       and any(isinstance(target, ast.Name) and target.id == "urlpatterns"
                               for target in (node.targets if isinstance(node, ast.Assign) else [node.target]))]
        writes = [node for node in nodes if isinstance(node, ast.Name) and node.id == "urlpatterns"
                  and isinstance(node.ctx, ast.Store)]
        mutations = [node for node in nodes if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                     and _name(node.func.value) == "urlpatterns"]
        mutations += [node for node in nodes if isinstance(node, (ast.Subscript, ast.Attribute))
                      and _name(node.value) == "urlpatterns" and isinstance(node.ctx, (ast.Store, ast.Del))]
        mutations += [node for node in nodes if isinstance(node, ast.Name) and node.id == "urlpatterns"
                      and isinstance(node.ctx, (ast.Load, ast.Del))]
        dynamic = len(assignments) != 1 or len(writes) != 1 or bool(mutations)
        pattern_nodes = _items(assignments[0].value) if len(assignments) == 1 else None
        if pattern_nodes is None:
            dynamic = True
        route_calls = [node for node in nodes if isinstance(node, ast.Call)
                       and bound(node.func) in {"django.urls.path", "django.urls.re_path"}]
        # Function-local URL factories are candidates, never definitive urlpatterns.
        if assignments or route_calls or writes:
            modules[rel] = {"bindings": bindings, "binding_lines": binding_lines,
                            "shadowed_imports": imported & overwritten, "calls": route_calls,
                            "patterns": pattern_nodes or [], "dynamic": dynamic}
            if dynamic:
                diagnostic("dynamic_urlpatterns", rel, "Conditional, mutated or computed urlpatterns; mount is unverified")
        root_writes = [node for node in nodes if isinstance(node, ast.Name) and node.id == "ROOT_URLCONF"
                       and isinstance(node.ctx, ast.Store)]
        root_values = [node.value for node in tree.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == "ROOT_URLCONF" for target in node.targets)]
        if root_writes:
            if len(root_writes) == len(root_values) == 1 and _string(root_values[0]) is not None:
                roots.setdefault(service(rel), set()).add((_string(root_values[0]), rel))
            else:
                dynamic_roots.add(service(rel))
                diagnostic("dynamic_root", rel, "ROOT_URLCONF is not a single literal assignment")

    def bound(node, module):
        first, dot, rest = _name(node).partition(".")
        binding = module["bindings"].get(first)
        return binding + dot + rest if binding and module["binding_lines"][first] <= node.lineno else ""

    seen = set()
    visited = set()
    steps = 0

    def consume(rel):
        nonlocal steps
        steps += 1
        if steps >= MAX_STEPS:
            diagnostic("traversal_budget", rel, "Django include/pattern traversal budget exhausted", error=True)
            return False
        return True

    def candidate(rel, call, prefix, reason):
        if not consume(rel):
            return
        raw = _string(call.args[0]) if call.args else None
        key = (rel, call.lineno, prefix, reason)
        if key in seen:
            return
        seen.add(key)
        if len(result["routes"]) + len(result["candidates"]) >= MAX_ROUTES:
            diagnostic("route_budget", rel, "Django route/candidate budget exhausted", error=True)
            return
        result["candidates"].append({"code_path": rel, "line": call.lineno,
                                     "declared_pattern": raw[:2048] if raw is not None else None,
                                     "declared_pattern_truncated": bool(raw and len(raw) > 2048),
                                     "known_prefix": prefix[:MAX_PATH],
                                     "method": "ANY", "mount_resolved": False, "reason": reason})

    def visit(rel, prefix, chain, definite=True):
        if not consume(rel):
            return
        if rel in chain or len(chain) >= MAX_DEPTH:
            diagnostic("include_cycle_or_depth", rel, "Include cycle or depth budget reached", error=True)
            return
        module = modules.get(rel)
        if module is None:
            diagnostic("unresolved_include", rel, "Contained source has no supported URLconf")
            return
        visited.add(rel)
        if module["dynamic"] or not definite:
            for call in module["calls"]:
                candidate(rel, call, prefix, "dynamic or unresolved URLconf mount")
                if steps >= MAX_STEPS:
                    break
            return
        for item in module["patterns"]:
            handle(item, rel, prefix, (*chain, rel))
            if steps >= MAX_STEPS:
                break

    def handle(call, rel, prefix, chain):
        if not consume(rel):
            return
        if len(chain) > MAX_DEPTH:
            diagnostic("include_depth", rel, "Inline include depth budget reached", error=True)
            return
        module = modules[rel]
        if not isinstance(call, ast.Call) or bound(call.func, module) not in {"django.urls.path", "django.urls.re_path"}:
            diagnostic("unsupported_pattern", rel, "URL pattern is not an import-bound path/re_path call")
            return
        raw = _string(call.args[0]) if call.args else None
        if bound(call.func, module).endswith("re_path"):
            candidate(rel, call, prefix, "Regular expression preserved; not an exact network path")
            diagnostic("regex_pattern", rel, "re_path expression requires manual mount/path review", line=call.lineno)
            return
        parsed = _pattern(raw)
        if parsed is None or len(call.args) < 2:
            candidate(rel, call, prefix, "Computed/unsupported route prefix or missing view")
            diagnostic("dynamic_pattern", rel, "Route prefix/view could not be resolved", line=call.lineno)
            return
        fragment, params = parsed
        full = prefix + fragment
        if len(full) > MAX_PATH:
            candidate(rel, call, prefix, "Assembled path exceeds the analysis budget")
            diagnostic("path_budget", rel, "Assembled route path exceeded the configured bound", error=True)
            return
        view = call.args[1]
        if isinstance(view, ast.Call) and _name(view.func).split(".")[0] in module["shadowed_imports"]:
            candidate(rel, call, prefix, "View/include binding was reassigned or shadowed")
            diagnostic("shadowed_include", rel, "View/include import is ambiguous", line=call.lineno)
            return
        if isinstance(view, ast.Call) and bound(view.func, module) == "django.urls.include":
            target = view.args[0] if view.args else None
            inline = _items(target)
            if inline is not None:
                # include((patterns, app_name)) is not itself two URL patterns.
                if isinstance(target, ast.Tuple) and len(target.elts) == 2:
                    inline = _items(target.elts[0])
                if inline is not None:
                    for item in inline:
                        handle(item, rel, full, (*chain, rel))
                        if steps >= MAX_STEPS:
                            break
                    return
            module_name = _string(target) or bound(target, module)
            child = resolve(module_name, rel)
            if child:
                visit(child, full, chain)
            else:
                candidate(rel, call, prefix, "Include module is dynamic, external, ambiguous or unavailable")
                diagnostic("unresolved_include", rel, "Include module not uniquely contained in the selected source", line=call.lineno)
            return
        if len(result["routes"]) + len(result["candidates"]) >= MAX_ROUTES:
            diagnostic("route_budget", rel, "Django route/candidate budget exhausted", error=True)
            return
        key = (rel, call.lineno, full)
        if key in seen:
            return
        seen.add(key)
        own_params = {row["name"]: row for row in params}
        params = [own_params.get(name, {"name": name, "where": "path", "type": "unknown"})
                  for name in dict.fromkeys(re.findall(r"\{(\w+)\}", full))]
        result["routes"].append({"method": "ANY", "path": "/" + full.lstrip("/"),
                                 "params": params, "technology": "django", "source": "django-ast",
                                 "code_path": rel, "line": call.lineno, "methods_detected": [],
                                 "note": "Literal Django URLconf path; HTTP methods and view authorization unverified"})

    for owner, declarations in roots.items():
        names = {name for name, _rel in declarations}
        if len(names) != 1 or owner in dynamic_roots:
            diagnostic("ambiguous_root", owner, "Multiple or dynamic root URL configurations; deployment choice unverified")
            continue
        name, declaration_file = sorted(declarations)[0]
        root = resolve(name, declaration_file)
        if root:
            visit(root, "", ())
        else:
            diagnostic("unresolved_root", declaration_file, "ROOT_URLCONF does not resolve to unique contained source")
    for rel in modules.keys() - visited:
        diagnostic("unmounted_urlconf", rel, "URLconf has no resolved literal root/include mount")
        visit(rel, "", (), definite=False)
    return result

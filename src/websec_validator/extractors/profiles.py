"""Bounded language profiles and manifest-based service boundaries.

These named checks identify direct syntax and explicit configuration. They do not
resolve imports, framework binding, aliases, build variants, or interprocedural flow.
A completed check with no match is not a statement that the service is secure.
"""
from __future__ import annotations

import copy
import json
import plistlib
import re
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath

from .base import is_test_file, is_script_file
from .syntax import without_comments, expression_end, split_arguments, in_literal, occurrence

_LANG = {".java": "java", ".cs": "csharp", ".go": "go", ".rb": "ruby", ".php": "php",
         ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift", ".rs": "rust",
         ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp", ".m": "objective-c",
         ".mm": "objective-c", ".py": "python", ".js": "node", ".ts": "typescript",
         ".tsx": "typescript", ".jsx": "node", ".vue": "node", ".svelte": "node",
         ".mjs": "node", ".cjs": "node", ".mts": "typescript", ".cts": "typescript"}
_MANIFESTS = {"package.json", "pyproject.toml", "requirements.txt", "setup.py", "Pipfile",
              "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "Gemfile",
              "composer.json", "Cargo.toml", "Package.swift", "CMakeLists.txt"}
_SPECS = [
    ("java-spring", ["java"], ["java-direct-command", "java-direct-query", "spring-literal-routes"]),
    ("dotnet", ["csharp"], ["dotnet-direct-command", "dotnet-direct-query", "dotnet-literal-routes"]),
    ("go", ["go"], ["go-direct-command", "go-direct-query"]),
    ("ruby", ["ruby"], ["ruby-direct-command", "ruby-direct-query"]),
    ("php", ["php"], ["php-direct-command", "php-direct-query"]),
    ("android", ["java", "kotlin"], ["android-explicit-cleartext"]),
    ("ios", ["swift", "objective-c"], ["ios-explicit-ats-exception"]),
    ("rust", ["rust"], ["rust-reqwest-invalid-certificates"]),
    ("native", ["c", "cpp"], ["native-memory-review"]),
]
_LIMIT = "Direct syntax only; aliases, binding resolution, authorization, build variants and cross-function flows require review."
MAX_MANIFEST_ERRORS = 200


def capabilities() -> dict:
    """Machine-readable catalog for `websec capabilities`; no target is read."""
    return {"schema_version": "1.0", "scope": "named checks, not whole-language vulnerability coverage",
            "profiles": [{"id": name, "languages": languages,
                          "checks": [{"id": check, "kind": "manual" if check.startswith("native-") else
                                      "routes" if check.endswith("routes") else
                                      "configuration" if "explicit-" in check or "certificates" in check else "sink",
                                      "scope": "direct syntax or explicit configuration"} for check in checks],
                          "limitations": [_LIMIT] + (["C/C++ source inventory only; memory safety is not analyzed."]
                                                    if name == "native" else [])}
                         for name, languages, checks in _SPECS]}


def service_for(inventory: list, path: str) -> dict:
    """Return the nearest manifest boundary, using component-safe path matching."""
    path = str(path).replace("\\", "/").removeprefix("./")
    candidates = [s for s in inventory if s["root"] == "." or path == s["root"]
                  or path.startswith(s["root"] + "/")]
    return max(candidates, key=lambda s: len(s["root"]) if s["root"] != "." else 0) if candidates else {}


def manifest_paths(ctx) -> list:
    """Use the same bounded inventory and product-first policy for every language."""
    paths = [path for path in ctx._files if path.name in _MANIFESTS
             or (path.name.startswith("requirements") and path.suffix == ".txt")
             or path.suffix.lower() == ".csproj"]
    if ctx.include_fixtures:
        return paths
    product = [path for path in paths
               if not (is_test_file(ctx.rel(path)) or is_script_file(ctx.rel(path)))]
    return product or paths


def node_metadata(text: str) -> dict:
    """Declared dependency hints, never proof of installation or deployment.

    Npm dependency sections are name-to-spec objects. Text in scripts,
    descriptions, exports and malformed sections cannot create dependencies.
    """
    from .stack import NODE_FRAMEWORKS, DATASTORES
    deps = set()
    errors = []
    try:
        package = json.loads(text)
        if isinstance(package, dict):
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                if section not in package:
                    continue
                entries = package.get(section)
                if not isinstance(entries, dict):
                    errors.append(section + " must be a dependency-name-to-spec object")
                    continue
                valid = {key for key, spec in entries.items()
                         if isinstance(key, str) and key and isinstance(spec, str) and spec.strip()}
                deps.update(valid)
                if len(valid) != len(entries):
                    errors.append(section + " contains " + str(len(entries) - len(valid)) + " invalid dependency declaration(s)")
        else:
            errors.append("package.json must contain an object")
    except (ValueError, TypeError, RecursionError) as error:
        errors.append("package.json could not be parsed: " + type(error).__name__)
    frameworks = {label for dep, label in NODE_FRAMEWORKS.items()
                  if dep in deps or (dep == "@remix-run" and any(name.startswith(dep + "/") for name in deps))}
    return {"dependencies": deps, "frameworks": frameworks, "errors": errors,
            "datastores": {label for dep, label in DATASTORES.items() if dep in deps},
            "languages": {"typescript"} if "typescript" in deps else set()}


def _manifest_metadata(service: dict, text: str, name: str) -> list:
    low = text.lower()
    language = {"package.json": "node", "pom.xml": "java", "build.gradle": "java",
                "build.gradle.kts": "kotlin", "go.mod": "go", "Gemfile": "ruby",
                "composer.json": "php", "Cargo.toml": "rust", "Package.swift": "swift",
                "pyproject.toml": "python", "requirements.txt": "python", "setup.py": "python",
                "Pipfile": "python", "CMakeLists.txt": "cpp"}.get(name)
    if name.endswith(".csproj"):
        language = "csharp"
    if name.startswith("requirements") and name.endswith(".txt"):
        language = "python"
    if language:
        service["languages"].add(language)
    # Local import avoids coupling the catalog API to the stack driver's initialization.
    from .stack import PY_FRAMEWORKS
    if name == "package.json":
        metadata = node_metadata(text)
        for key in ("frameworks", "datastores", "languages"):
            service[key].update(metadata[key])
        return metadata["errors"]  # Other-language heuristics cannot interpret npm descriptions/scripts.
    else:
        for dep, label in PY_FRAMEWORKS.items():
            if language == "python" and re.search(r"\b" + dep + r"\b", low):
                service["frameworks"].add(label)
        for pattern, label in ((r"postgres|psycopg|npgsql", "postgres"), (r"mysql", "mysql"),
                               (r"sqlite", "sqlite"), (r"mongodb|mongoose", "mongo"),
                               (r"dynamodb", "dynamodb"), (r"sqlalchemy|jdbc|entityframework", "sql-orm")):
            if re.search(pattern, low):
                service["datastores"].add(label)
    for pattern, label in (("spring", "spring"), ("microsoft.net.sdk.web", "aspnet-core"),
                           ("microsoft.aspnetcore", "aspnet-core"), ("gin-gonic", "gin"),
                           ("rails", "rails"), ("sinatra", "sinatra"), ("laravel", "laravel"),
                           ("com.android.application", "android")):
        if pattern in low:
            service["frameworks"].add(label)
    return []


def _new_service(root: str) -> dict:
    return {"id": root, "root": root, "manifests": [], "languages": set(), "frameworks": set(),
            "datastores": set(), "input_boundaries": set()}


def _inventory(ctx) -> tuple[list, list, list]:
    services = {".": _new_service(".")}
    configs = []
    errors = []
    omitted = 0
    selected_manifests = set(manifest_paths(ctx))
    for path in ctx._files:
        rel = ctx.rel(path)
        fixture = not ctx.include_fixtures and (is_test_file(rel) or is_script_file(rel))
        if fixture and path not in selected_manifests:
            continue
        if not fixture and path.name in ("AndroidManifest.xml", "Info.plist"):
            configs.append(path)
        if path in selected_manifests:
            root = str(PurePosixPath(rel).parent)
            service = services.setdefault(root, _new_service(root))
            service["manifests"].append(rel)
            for error in _manifest_metadata(service, ctx.text(path), path.name):
                if len(errors) < MAX_MANIFEST_ERRORS:
                    errors.append({"file": rel, "check": "node-manifest-metadata", "error": error})
                else:
                    omitted += 1
    if omitted:
        errors.append({"file": "", "check": "node-manifest-metadata",
                       "error": str(omitted) + " additional manifest diagnostics omitted at the limit"})
    return list(services.values()), configs, errors


_SINK_RULES = {
    ".java": ("java-spring", r"(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(",
              r"\.(?:executeQuery|executeUpdate|execute|createQuery|createNativeQuery)\s*\(",
              r"\b(?:request|req)\.get(?:Parameter|Header|QueryString)\s*\("),
    ".cs": ("dotnet", r"(?:Process\.Start|new\s+ProcessStartInfo)\s*\(",
            r"(?:new\s+SqlCommand|\.(?:FromSqlRaw|ExecuteSqlRaw|ExecuteSqlCommand))\s*\(",
            r"\b(?:Request|request|HttpContext\.Request)\.(?:Query|Form|Headers)\s*\["),
    ".go": ("go", r"\bexec\.Command(?:Context)?\s*\(", r"\.(?:Query|QueryRow|Exec)(?:Context)?\s*\(",
            r"\b(?:r|req|request)\.(?:FormValue\s*\(|URL\.Query\(\)\.Get\s*\()"),
    ".rb": ("ruby", r"\b(?:system|exec|IO\.popen)\s*\(", r"\.(?:execute|find_by_sql|where)\s*\(",
            r"\bparams\s*\["),
    ".php": ("php", r"\b(?:system|exec|shell_exec|passthru|popen)\s*\(",
             r"(?:->(?:query|exec)|mysqli_query)\s*\(", r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\["),
}


def _source(expression: str, pattern: str) -> bool:
    for match in re.finditer(pattern, expression):
        if not in_literal(expression, match.start()):
            return True
        # Ruby interpolation, C# interpolated strings and PHP double-quoted interpolation.
        if re.search(r"#\{[^}]*$|\$\"[^\"]*\{[^}]*$", expression[:match.start()]):
            return True
        if pattern.startswith(r"\$_") and re.search(r'"(?:\\.|[^"\\])*$', expression[:match.start()]):
            return True
    return False


def java_fixed_argv(expression: str) -> bool:
    """Only the explicit String[] overload with a fixed non-shell executable."""
    match = re.search(r"\bexec\s*\(\s*new\s+String\s*\[\s*]\s*\{", expression)
    if not match:
        return False
    end = expression_end(expression, match.end() - 1, closing="}")
    args = split_arguments(expression[match.end():end - 1])
    if not args or not re.fullmatch(r'"[^"\\]+"', args[0].strip()):
        return False
    executable = args[0].strip().strip('"').replace("\\", "/").split("/")[-1].lower()
    return executable not in {"sh", "bash", "cmd", "cmd.exe", "powershell", "powershell.exe"}


def _sink_candidates(text: str, suffix: str):
    profile, command, query, source = _SINK_RULES[suffix]
    for kind, pattern in (("command", command), ("query", query)):
        for match in re.finditer(pattern, text):
            if in_literal(text, match.start()):
                continue
            end = expression_end(text, match.end() - 1, closing=")")
            expression = text[match.start():end]
            args = split_arguments(text[match.end():end - 1])
            if not args:
                continue
            target = args[0]
            if kind == "query":
                # Context and mysqli connection arguments precede the query text.
                if (suffix == ".go" and "Context(" in match[0]) or "mysqli_query" in match[0]:
                    target = args[1] if len(args) > 1 else ""
                if suffix == ".rb" and target.strip().startswith("[") and target.strip().endswith("]"):
                    parts = split_arguments(target.strip()[1:-1])
                    target = parts[0] if parts else ""
                unsafe = _source(target, source)
                if suffix == ".rb" and ".where" in match[0]:
                    condition = target.strip().removeprefix("{").strip()
                    if re.match(r'''(?:\w+\s*:|:\w+\s*=>|["']\w+["']\s*=>)''', condition):
                        unsafe = False  # Rails binds literal-key hash values as parameters.
            else:
                if suffix == ".go" and "CommandContext" in match[0]:
                    args = args[1:]
                java_array = re.fullmatch(r"new\s+String\s*\[\s*]\s*\{(.*)}", args[0].strip(), re.S) if suffix == ".java" and args else None
                if java_array:
                    args = split_arguments(java_array[1])
                # A fixed executable with separate arguments does not invoke a shell.
                executable = args[0] if args else ""
                shell = bool(re.fullmatch(r'''["'](?:/bin/)?(?:sh|bash|cmd(?:\.exe)?|powershell(?:\.exe)?)["']''', executable.strip(), re.I))
                unsafe = _source(executable, source) or (shell and any(_source(arg, source) for arg in args[1:]))
                if suffix == ".php" or (suffix == ".java" and "Runtime.getRuntime" in match[0] and not java_array):
                    unsafe = any(_source(arg, source) for arg in args)
            yield profile, kind, match.start(), expression, unsafe


def _literal_routes(text: str, suffix: str, rel: str) -> list:
    rows = []
    patterns = []
    prefix = ""
    classes = [match for match in re.finditer(r"\bclass\s+(\w+)", text) if not in_literal(text, match.start())]
    if len(classes) == 1:
        before = text[:classes[0].start()]
        prefix_pattern = (r'@RequestMapping\s*\(\s*(?:(?:value|path)\s*=\s*)?["\']([^"\']*)["\']'
                          if suffix == ".java" else r'\[Route\s*\(\s*"([^"]*)"')
        prefixes = [match for match in re.finditer(prefix_pattern, before) if not in_literal(before, match.start())]
        if len(prefixes) == 1:
            prefix = prefixes[0][1].replace("[controller]", re.sub(r"Controller$", "", classes[0][1]))
    if suffix == ".java":
        patterns = [(r'@(Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:(?:value|path)\s*=\s*)?["\']([^"\']*)["\']', "spring")]
    elif suffix == ".cs":
        patterns = [(r'\bMap(Get|Post|Put|Patch|Delete)\s*\(\s*["\']([^"\']*)["\']', "aspnet-core"),
                    (r'\[Http(Get|Post|Put|Patch|Delete)\s*\(\s*["\']([^"\']*)["\']', "aspnet-core")]
    for pattern, technology in patterns:
        for match in re.finditer(pattern, text):
            if in_literal(text, match.start()):
                continue
            if match[1] == "Request":
                continue
            path = match[2]
            if prefix and not (suffix == ".cs" and path.startswith(("/", "~/"))):
                path = "/" + prefix.strip("/") + "/" + path.lstrip("/")
            path = "/" + path.removeprefix("~/").lstrip("/")
            rows.append({"method": match[1].upper(), "path": path, "params": [],
                         "technology": technology, "code_path": rel, "source": "profile-literal",
                         "limitations": ["Only a single class with one literal prefix is combined; route groups, multiple classes, binding and conventions remain unresolved."]})
    return rows


def _configuration(ctx, path, service: dict) -> tuple[str, str, int, list, str | None]:
    raw = ctx.text(path)
    rel = ctx.rel(path)
    risks = []
    if path.name == "AndroidManifest.xml":
        profile, check = "android", "android-explicit-cleartext"
        try:
            root = ET.fromstring(raw)
            application = root.find("application")
        except ET.ParseError as error:
            return profile, check, 0, [], type(error).__name__
        service["frameworks"].add("android")
        service["input_boundaries"].add("native")
        if application is not None:
            attr = "{http://schemas.android.com/apk/res/android}"
            if application.get(attr + "usesCleartextTraffic") == "true":
                risks.append(("usesCleartextTraffic", "Android explicitly permits cleartext traffic",
                              "CWE-319", "Disable cleartext traffic and review the effective network security configuration.",
                              "Network security configuration, Android API level and manifest merging may change effective behavior."))
    else:
        profile, check = "ios", "ios-explicit-ats-exception"
        try:
            config = plistlib.loads(raw.encode())
        except (ValueError, TypeError, plistlib.InvalidFileException) as error:
            return profile, check, 0, [], type(error).__name__
        service["frameworks"].add("ios")
        service["input_boundaries"].add("native")
        ats = config.get("NSAppTransportSecurity", {}) if isinstance(config, dict) else {}
        if isinstance(ats, dict):
            for key in ("NSAllowsArbitraryLoads", "NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsForMedia"):
                if ats.get(key) is True:
                    risks.append((key, "App Transport Security exception requires review", "CWE-319",
                                  "Remove unnecessary ATS exceptions; restrict required exceptions to documented domains and usage.",
                                  "Scoped ATS keys and OS version change precedence; this is advisory configuration evidence, not proof of an insecure connection."))
    rows = []
    for marker, title, cwe, remediation, limit in risks:
        start = max(0, raw.find(marker))
        rows.append({"rule_id": check, "profile_id": profile, "service_id": service["id"], "file": rel,
                     "line": raw[:start].count("\n") + 1, "semantic_id": check + ":" + marker,
                     "attack_class": "transport-security", "title": title, "severity": "MEDIUM",
                     "confidence": "MEDIUM", "cwe": cwe, "evidence": marker + " explicitly true",
                     "remediation": remediation, "limitations": [limit]})
    return profile, check, 1, rows, None


def analyze(ctx) -> dict:
    """Reuse RepoContext's bounded inventory/cache; never traverse or read externally."""
    inventory, configs, errors = _inventory(ctx)
    measurements: dict[tuple, dict] = {}
    sinks, routes, findings = [], [], []

    def measured(service, profile, check, examined=0, hits=0):
        row = measurements.setdefault((service["id"], profile, check), {"id": check, "examined": 0, "findings": 0})
        row["examined"] += examined
        row["findings"] += hits

    for path, rel, raw in ctx.iter_code():
        if not ctx.include_fixtures and is_test_file(rel):
            continue
        service = service_for(inventory, rel)
        suffix = path.suffix.lower()
        if suffix in _LANG:
            service["languages"].add(_LANG[suffix])
        text = without_comments(raw, suffix)
        for pattern, label in ((r"\b(?:req|request|Request)\.|@(Get|Post|Request)Mapping|MapGet\s*\(|\bhttp\.Handle|\bparams\[|\$_GET", "http"),
                               (r"\b(?:sys\.argv|process\.argv|os\.Args|ARGV|CommandLine\.arguments)\b", "cli"),
                               (r"\b(?:document\.|window\.|'use client'|\"use client\")", "browser"),
                               (r"@Scheduled|cron\b|queue\.process|@app\.task", "jobs"),
                               (r"\b(?:UITextField|Intent|onNewIntent|UIApplication|GetCommandLine)\b", "native"),
                               (r"\b(?:generateText|streamText|Agent|tool)\s*\(", "agent")):
            if re.search(pattern, text):
                service["input_boundaries"].add(label)
        if suffix in _SINK_RULES:
            profile = _SINK_RULES[suffix][0]
            prefix = "java" if profile == "java-spring" else profile
            for kind in ("command", "query"):
                measured(service, profile, prefix + "-direct-" + kind, 1)
            seen = {}
            for profile, kind, start, expression, unsafe in _sink_candidates(text, suffix):
                if not unsafe:
                    continue
                cls = "command-injection" if kind == "command" else "sql-injection"
                ordinal = seen.get(expression, 0)
                seen[expression] = ordinal + 1
                row = occurrence(text, start, expression, rel, cls, ordinal)
                row.update({"service_id": service["id"], "profile_id": profile,
                            "offset": start + (expression.index("exec(") if expression.startswith("Runtime.getRuntime().exec(") else 0),
                            "rule_id": prefix + "-direct-" + kind,
                            "source": "request read appears directly in the sink argument; aliases unresolved"})
                sinks.append(row)
                measured(service, profile, prefix + "-direct-" + kind, hits=1)
            if suffix in (".java", ".cs"):
                own_routes = _literal_routes(text, suffix, rel)
                for row in own_routes:
                    row["service_id"] = service["id"]
                routes.extend(own_routes)
                measured(service, profile, "spring-literal-routes" if suffix == ".java" else "dotnet-literal-routes", 1, len(own_routes))
        if suffix == ".rs":
            check = "rust-reqwest-invalid-certificates"
            measured(service, "rust", check, 1)
            manifests = " ".join(ctx.text(ctx.root / item) for item in service["manifests"])
            if "reqwest" in text or re.search(r"\breqwest\b", manifests):
                seen_certificates = {}
                for match in re.finditer(r"\.(?:tls_)?danger_accept_invalid_certs\s*\(\s*true\s*\)", text):
                    if in_literal(text, match.start()):
                        continue
                    ordinal = seen_certificates.get(match[0], 0)
                    seen_certificates[match[0]] = ordinal + 1
                    findings.append({"rule_id": check, "profile_id": "rust", "service_id": service["id"],
                                     "file": rel, "line": text[:match.start()].count("\n") + 1,
                                     "semantic_id": occurrence(text, match.start(), match[0], rel, check, ordinal)["semantic_id"],
                                     "attack_class": "transport-security", "title": "Rust client opts out of certificate validation",
                                     "severity": "MEDIUM", "confidence": "MEDIUM", "cwe": "CWE-295",
                                     "evidence": match[0], "remediation": "Keep certificate validation enabled and configure specific trusted certificates.",
                                     "limitations": ["Method receiver type and compiled feature selection are unresolved."]})
                    measured(service, "rust", check, hits=1)
    for path in configs:
        service = service_for(inventory, ctx.rel(path))
        profile, check, examined, rows, error = _configuration(ctx, path, service)
        if error:
            errors.append({"file": ctx.rel(path), "check": check, "error": error})
        findings.extend(rows)
        measured(service, profile, check, examined, len(rows))
    profiles = []
    catalog = capabilities()["profiles"]
    for service in inventory:
        for spec in catalog:
            selected = bool(set(spec["languages"]) & service["languages"])
            if spec["id"] in ("android", "ios"):
                selected = spec["id"] in service["frameworks"] or any(key[:2] == (service["id"], spec["id"]) for key in measurements)
            if not selected:
                continue
            checks = []
            for check in spec["checks"]:
                row = copy.copy(measurements.get((service["id"], spec["id"], check["id"]),
                                                 {"id": check["id"], "examined": 0, "findings": 0}))
                row["status"] = "manual" if check["kind"] == "manual" else "completed" if row["examined"] else "unknown"
                checks.append(row)
            profiles.append({"id": spec["id"], "service_id": service["id"], "checks": checks,
                             "limitations": spec["limitations"]})
        for key in ("languages", "frameworks", "datastores", "input_boundaries"):
            service[key] = sorted(service[key])
        if not service["input_boundaries"]:
            service["input_boundaries"] = ["unknown"]
    return {"service_inventory": inventory, "profiles": profiles, "findings": findings,
            "sink_occurrences": sinks, "routes": routes, "errors": errors,
            "limitations": [_LIMIT, "No-match results are not security proof; manifest boundaries approximate deployment boundaries.",
                            "Dependency labels include development, peer and optional declarations; they do not prove installation, deployment or a native application."]}

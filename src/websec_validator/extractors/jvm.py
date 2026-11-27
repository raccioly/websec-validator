"""Small, dependency-free JVM source helpers shared by the Java/Kotlin checks.

Nothing here parses Java fully. Each helper does one bounded job and says what it leaves out:
  * `mask_literals` blanks string/char literals and text blocks (offsets are kept), so a regex
    never matches inside SQL text, Javadoc examples or annotation values by accident;
  * `string_literals` reads the literal values back out of a span of the ORIGINAL text;
  * `handlers` locates Spring MVC handler methods with their own and their class annotations;
  * `build_module` / `module_dependencies` resolve the Maven/Gradle module a file belongs to.
"""
from __future__ import annotations

import posixpath
import re

JVM_SUFFIXES = {".java", ".kt", ".kts", ".groovy", ".scala"}

# A path below a language source root: segments after it are PACKAGE names, not directory roles
# (#244). `src/main/java/com/example/build/Tool.java` is application code in package
# `com.example.build`, not an example, a build output or a script.
JVM_SOURCE_ROOT = re.compile(r"(?:^|/)src/(?:main|test|testFixtures|integrationTest|it)/(?:java|kotlin|scala|groovy)/")


def jvm_package_split(rel: str) -> tuple[str, str] | None:
    """`(above_root_including_root, package_part)` for a path under a JVM source root, else None."""
    match = JVM_SOURCE_ROOT.search(rel.replace("\\", "/"))
    if not match:
        return None
    rel = rel.replace("\\", "/")
    return rel[:match.end()], rel[match.end():]


def mask_literals(text: str) -> str:
    """Replace the inside of every string, char literal and text block with spaces.

    Quotes stay, so `"..."` is still visibly a literal; newlines stay, so line numbers hold.
    Comments must already be removed (see `syntax.without_comments`).
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        if text.startswith('"""', i):
            end = text.find('"""', i + 3)
            end = n if end < 0 else end
            for j in range(i + 3, end):
                if out[j] != "\n":
                    out[j] = " "
            i = end + 3
            continue
        ch = text[i]
        if ch in "\"'":
            j = i + 1
            while j < n and text[j] != ch and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                out[k] = " "
            i = j + 1
            continue
        i += 1
    return "".join(out)


_LITERAL = re.compile(r'"""(.*?)"""|"((?:\\.|[^"\\\n])*)"', re.S)


def string_literals(original_span: str) -> list[str]:
    return [m[1] if m[1] is not None else m[2] for m in _LITERAL.finditer(original_span)]


def balanced_end(masked: str, opening: int) -> int:
    """Index just past the bracket that closes `masked[opening]` (literals already masked)."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = []
    for i in range(opening, len(masked)):
        ch = masked[i]
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch in ")]}":
            if not stack or stack.pop() != ch:
                return i + 1
            if not stack:
                return i + 1
    return len(masked)


_MAPPING = re.compile(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\b")
_CLASS = re.compile(r"\b(?:class|interface|object)\s+(\w+)")


def _annotation_args(original: str, masked: str, end: int) -> tuple[str, int]:
    """The `( ... )` text right after an annotation name, and the index after it."""
    j = end
    while j < len(masked) and masked[j] in " \t":
        j += 1
    if j < len(masked) and masked[j] == "(":
        close = balanced_end(masked, j)
        return original[j + 1:close - 1], close
    return "", end


def _mapping_paths(args: str) -> list[str]:
    if not args.strip():
        return [""]
    named = re.search(r"\b(?:value|path)\s*=\s*(\{[^}]*\}|\"(?:\\.|[^\"\\])*\")", args)
    if named:
        return string_literals(named[1]) or [""]
    first = args.strip()
    if first.startswith(("\"", "{")):
        head = first if first.startswith("\"") else first[:first.find("}") + 1]
        return string_literals(head.split(",")[0] if head.startswith("\"") else head) or [""]
    return [""]


def _mapping_methods(kind: str, args: str) -> list[str]:
    if kind != "Request":
        return [kind.upper()]
    found = re.findall(r"RequestMethod\.(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)", args)
    return found or ["ANY"]


def _join(prefix: str, path: str) -> str:
    return "/" + "/".join(part.strip("/") for part in (prefix, path) if part.strip("/"))


def _block_before(masked: str, position: int) -> int:
    """Start of the annotation/modifier block that ends at `position` (after the last ; { or })."""
    start = max(masked.rfind(";", 0, position), masked.rfind("{", 0, position), masked.rfind("}", 0, position))
    return start + 1


def handlers(text: str) -> list[dict]:
    """Spring MVC handler methods in one comment-free source text.

    Each row: methods, full paths (class prefix joined), the handler's own annotation block, its
    class annotation block and the class name. Nested/inner classes use the nearest preceding class;
    meta-annotations and inherited mappings from interfaces are not followed.
    """
    masked = mask_literals(text)
    classes = [(m.start(), m[1]) for m in _CLASS.finditer(masked)]
    class_info = {}
    for start, name in classes:
        block_start = _block_before(masked, start)
        block = text[block_start:start]
        prefixes = [""]
        for mapping in _MAPPING.finditer(masked, block_start, start):
            if mapping[1] == "Request":
                args, _ = _annotation_args(text, masked, mapping.end())
                prefixes = _mapping_paths(args)
        class_info[start] = {"name": name, "annotations": block, "prefixes": prefixes}
    rows = []
    for mapping in _MAPPING.finditer(masked):
        owner = max((start for start, _ in classes if start < mapping.start()), default=None)
        if owner is None:
            continue
        info = class_info[owner]
        # the class's own @RequestMapping sits BEFORE `class`; handler mappings sit after its `{`.
        if mapping.start() < owner:
            continue
        args, after = _annotation_args(text, masked, mapping.end())
        body_open = masked.find("{", after)
        semi = masked.find(";", after)
        if body_open < 0 and semi < 0:
            continue
        decl_end = min(x for x in (body_open, semi) if x >= 0)
        block = text[_block_before(masked, mapping.start()):decl_end]
        decl = re.findall(r"(\w+)\s*\(", masked[after:decl_end])
        paths = [_join(prefix, path) for prefix in info["prefixes"] for path in _mapping_paths(args)]
        body = (decl_end, balanced_end(masked, decl_end)) if masked[decl_end:decl_end + 1] == "{" else (decl_end, decl_end)
        rows.append({"methods": _mapping_methods(mapping[1], args), "paths": paths,
                     "annotations": block, "class_annotations": info["annotations"],
                     "class": info["name"], "name": decl[-1] if decl else "",
                     "signature": text[after:decl_end], "body": text[body[0]:body[1]],
                     "line": text.count("\n", 0, mapping.start()) + 1})
    return rows


def normalize_route(path: str) -> str:
    path = "/" + (path or "").strip().strip("/")
    return re.sub(r"\{[^}/]*\}", "{}", path)


def handler_for(rows: list[dict], method: str, path: str) -> list[dict]:
    """Handlers whose mapping produces this route (method ANY matches any verb)."""
    want = normalize_route(path)
    method = (method or "").upper()
    return [row for row in rows
            if any(normalize_route(p) == want for p in row["paths"])
            and ("ANY" in row["methods"] or method in row["methods"] or method in ("ANY", "ALL", ""))]


BUILD_FILES = ("pom.xml", "build.gradle", "build.gradle.kts")


def build_module(ctx, rel: str) -> str:
    """Directory (repo-relative, "" for the root) of the nearest Maven/Gradle build file."""
    directory = posixpath.dirname(rel.replace("\\", "/"))
    while True:
        if any((ctx.root / directory / name).is_file() for name in BUILD_FILES):
            return directory
        if not directory:
            return ""
        directory = posixpath.dirname(directory)


def _build_text(ctx, module: str) -> str:
    for name in BUILD_FILES:
        path = ctx.root / module / name
        if path.is_file():
            try:
                return path.read_text(errors="replace")[:512 * 1024]
            except OSError:
                return ""
    return ""


def module_name(ctx, module: str) -> str:
    text = _build_text(ctx, module)
    if "<project" in text:
        own = re.sub(r"<parent>.*?</parent>|<dependencies>.*?</dependencies>|<dependencyManagement>.*?"
                     r"</dependencyManagement>|<build>.*?</build>|<profiles>.*?</profiles>", "", text, flags=re.S)
        match = re.search(r"<artifactId>\s*([\w.-]+)\s*</artifactId>", own)
        if match:
            return match[1]
    return posixpath.basename(module) or ""


def module_depends_on(ctx, module: str, other: str) -> bool:
    """Does `module`'s build file declare a dependency on the module at `other` (one hop)?"""
    if module == other:
        return True
    name = module_name(ctx, other)
    if not name:
        return False
    text = _build_text(ctx, module)
    if "<project" in text:
        deps = " ".join(re.findall(r"<dependency>(.*?)</dependency>", text, flags=re.S))
        return bool(re.search(r"<artifactId>\s*" + re.escape(name) + r"\s*</artifactId>", deps))
    return bool(re.search(r"project\s*\(\s*(?:path\s*[:=]\s*)?['\"](?:[:\w.-]*:)?" + re.escape(name) + r"['\"]", text)
                or re.search(r"projects\.\w*" + re.escape(re.sub(r"[-_.](\w)", lambda m: m[1].upper(), name)) + r"\b", text))


def module_text(ctx, module: str) -> str:
    return _build_text(ctx, module)


# ---- SQL text built by concatenation (#243) -------------------------------------------------------
_SQL_CALL = re.compile(
    r"\.\s*(query|queryForList|queryForObject|queryForMap|queryForRowSet|queryForStream|queryForLong"
    r"|queryForInt|update|batchUpdate|execute|executeQuery|executeUpdate|executeLargeUpdate|addBatch"
    r"|prepareStatement|prepareCall|createQuery|createNativeQuery|createSQLQuery|nativeQuery)\s*\(")
_SQL_WORD = re.compile(r"\b(?:select|insert|update|delete|merge|upsert|with|call|exec|from|where|order\s+by"
                       r"|group\s+by|values|set|limit|join|truncate|drop|alter|create)\b", re.I)
_REQUEST_PARAM = re.compile(
    r"@(RequestParam|PathVariable|RequestHeader|RequestBody|CookieValue|ModelAttribute|MatrixVariable|"
    r"RequestPart|QueryParam|PathParam|FormParam|HeaderParam)\b")
_INLINE_REQUEST = re.compile(r"\b(?:request|req|httpRequest|servletRequest)\s*\.\s*get(?:Parameter|Header|QueryString|"
                             r"ParameterValues|Cookies)\s*\(")
_CONSTANT = re.compile(r"(?:[A-Za-z_$][\w$]*\s*\.\s*)*[A-Z][A-Z0-9_]*")
_NUMBER = re.compile(r"[-+]?(?:0[xX][\da-fA-F_]+|\d[\d_]*(?:\.\d+)?)[lLfFdD]?")


def _top_level_plus(masked: str) -> list[int]:
    depth, cuts = 0, []
    for i, ch in enumerate(masked):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "+" and depth == 0 and masked[i - 1:i] != "+" and masked[i + 1:i + 2] not in ("+", "="):
            cuts.append(i)
    return cuts


def _operands(expression: str) -> list[str]:
    masked = mask_literals(expression)
    cuts = [-1] + _top_level_plus(masked) + [len(expression)]
    return [expression[a + 1:b].strip() for a, b in zip(cuts, cuts[1:])]


def _unwrap(value: str) -> str:
    value = value.strip()
    while value.startswith("(") and balanced_end(mask_literals(value), 0) == len(value):
        value = value[1:-1].strip()
    return value


def dynamic_operands(expression: str, constants: set, _depth: int = 0) -> list[str]:
    """Operands of a string expression that are neither literals nor named constants."""
    out = []
    for operand in _operands(expression):
        operand = _unwrap(operand)
        if not operand:
            continue
        if re.fullmatch(r'"""[\s\S]*"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])\'', operand):
            continue
        if _NUMBER.fullmatch(operand) or operand in ("true", "false", "null"):
            continue
        if _CONSTANT.fullmatch(operand) or operand.split(".")[-1].strip() in constants:
            continue
        fmt = re.fullmatch(r"(?:String\s*\.\s*format|\"(?:\\.|[^\"\\])*\"\s*\.\s*formatted)\s*\(([\s\S]*)\)", operand)
        if fmt and _depth < 3:
            from .syntax import split_arguments
            args = split_arguments(fmt[1])
            args = args[1:] if operand.startswith("String") else args
            for arg in args:
                out.extend(dynamic_operands(arg, constants, _depth + 1))
            continue
        if len(_operands(operand)) > 1 and _depth < 3:
            out.extend(dynamic_operands(operand, constants, _depth + 1))
            continue
        out.append(operand)
    return out


def _file_constants(masked: str, text: str) -> set:
    """Names declared `static final` (or Kotlin `const val`) with a literal/constant-only value."""
    names = set()
    for match in re.finditer(r"\b(?:static\s+final|final\s+static)\s+[\w<>\[\]]+\s+(\w+)\s*=|\bconst\s+val\s+(\w+)\s*(?::\s*\w+)?\s*=", masked):
        end = masked.find(";", match.end())
        end = masked.find("\n", match.end()) if end < 0 else end
        value = text[match.end():end if end > 0 else len(text)]
        if not dynamic_operands(value, set()):
            names.add(match[1] or match[2])
    return names


def _assignments(masked: str, text: str, name: str, before: int) -> list[str]:
    rows = []
    for match in re.finditer(r"(?<![\w.$])" + re.escape(name) + r"\s*(\+?=)(?!=)", masked[:before]):
        end = masked.find(";", match.end())
        if 0 <= end <= before:
            rows.append(text[match.end():end])
    return rows


def _request_params(masked: str, text: str, position: int) -> list[str]:
    """Names of Spring/JAX-RS-annotated parameters of the method whose body holds `position`."""
    names = []
    for match in _REQUEST_PARAM.finditer(masked):
        if match.start() > position:
            break
        after = match.end()
        if masked[after:after + 1] == "(" or masked[after:].lstrip().startswith("("):
            opening = masked.find("(", after)
            after = balanced_end(masked, opening)
        decl = re.match(r"\s*(?:final\s+)?(?:@\w+(?:\([^)]*\))?\s+)*([\w.$<>\[\], ?]+?)\s+(\w+)\s*[,)]", masked[after:])
        if not decl:
            continue
        body = masked.find("{", after)
        if body < 0 or body > position:
            continue
        if balanced_end(masked, body) > position:
            names.append((decl[2], decl[1].strip()))
    return names


# A value of these types cannot carry SQL syntax once concatenated (`" WHERE id = " + id` with `long id`).
_INERT_TYPES = re.compile(r"(?:java\.lang\.|java\.util\.|java\.math\.|java\.time\.)?(?:byte|short|int|long|float|double|boolean"
                          r"|Byte|Short|Integer|Long|Float|Double|Boolean|BigInteger|BigDecimal|UUID|LocalDate|LocalDateTime"
                          r"|Instant|OffsetDateTime|ZonedDateTime)")


def sql_sinks(text: str) -> list[dict]:
    """JDBC/JPA/SOQL-style calls whose SQL text has a non-constant concatenated operand.

    Rows: offset (the call's dot), expression, dynamic operands, request-bound operands. The SQL
    argument is the first argument whose string literals contain SQL words, or a variable whose
    assignments in this file do (one hop). StringBuilder chains and cross-method flows are not
    followed; prepared statements with `?`/`:name` placeholders and only constants are safe.
    """
    masked = mask_literals(text)
    constants = _file_constants(masked, text)
    rows = []
    from .syntax import split_arguments
    for call in _SQL_CALL.finditer(masked):
        opening = call.end() - 1
        close = balanced_end(masked, opening)
        args = split_arguments(text[opening + 1:close - 1])
        sql_expressions = []
        for arg in args[:3]:
            literals = " ".join(string_literals(arg))
            if literals and _SQL_WORD.search(literals):
                sql_expressions = [arg]
                break
            name = arg.strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
                assigned = _assignments(masked, text, name, call.start())
                if any(_SQL_WORD.search(" ".join(string_literals(value))) for value in assigned):
                    sql_expressions = assigned
                    break
        if not sql_expressions:
            continue
        params = dict(_request_params(masked, text, call.start()))
        inert = {name for name, kind in params.items() if _INERT_TYPES.fullmatch(kind)}
        dynamic = []
        for expression in sql_expressions:
            dynamic.extend(op for op in dynamic_operands(expression, constants) if op not in inert)
        if not dynamic:
            continue
        bound = sorted({op for op in dynamic if re.split(r"[.\s(\[]", op, 1)[0] in params}
                       | {op for op in dynamic if _INLINE_REQUEST.search(op)})
        rows.append({"offset": call.start(), "end": close, "method": call[1],
                     "dynamic": dynamic[:6], "request_bound": bound[:6]})
    return rows

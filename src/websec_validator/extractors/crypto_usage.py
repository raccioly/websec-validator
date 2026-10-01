"""Crypto-usage extractor — algorithm-choice + verify-option correctness.

Static scanners catch hard-coded/leaked secrets but not how crypto primitives are USED. Three tells
the field review surfaced as real (or latent) bugs the rest of the engine had no model for:

  - **Weak password hashing (CWE-916/759)** — a password verified with a fast, unsalted digest
    (`createHash('sha256'|'md5'|'sha1').update(password)` / `hashlib.sha256(password…)`). GPU-crackable
    + rainbow-tableable; must be a memory-hard KDF (argon2id/scrypt/bcrypt) with a per-credential salt.
  - **jwtVerify without an `algorithms` allowlist (CWE-347)** — a verify call that doesn't pin the
    accepted algorithm set. Not exploitable while the key is symmetric (jose constrains it), but a
    latent alg-confusion / alg:none re-opener the day it migrates to an asymmetric/JWKS key. LOW.
  - **Predictable security principal (CWE-330/340)** — a tenant/user id derived as a public, keyless
    hash of user-controlled input (`tenant_id = sha256(email)`), so anyone who knows the email can
    recompute the victim's principal. The id's secrecy then adds zero defense in depth.

Server-side + test-excluded; regex over code (points the agent at the file, doesn't prove the break).
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext, is_test_file
from .syntax import (call_expression, expression_end, in_literal, js_functions,
                     object_properties, split_arguments, without_comments)

# Exact metadata suffixes are not password bytes. Hashes/tokens in general remain
# credential-shaped; a broad suffix exemption would hide double-hashed passwords.
_PW_METADATA = r"_?(?:reset_?(?:token|url)|attempt_?count|file_?path|salt|updated_?(?:at|timestamp))"
_PW = r"(?:password|passwd|passphrase|\bpwd\b|userPassword|plainPassword)(?!" + _PW_METADATA + r"\b)"
# a fast digest fed a password-shaped value (either arg order, within a small window)
WEAK_PW_HASH = re.compile(
    r"createHash\s*\(\s*['\"](?:md5|sha1|sha256|sha224)['\"]\s*\)[\s\S]{0,160}?\.update\s*\([^)]*" + _PW
    + r"|hashlib\.(?:md5|sha1|sha256|sha224)\s*\([^)]*" + _PW
    + r"|(?:md5|sha1|sha256)\s*\([^)]*" + _PW + r"[^)]*\)\.(?:hexdigest|digest)", re.I)
# a password-auth context + a fast hash + no strong KDF in the file — catches the case where the
# password is renamed (`sha256Hex(password)` → `createHash('sha256').update(input)`) so the token
# isn't adjacent to the hash, but the file is clearly hashing a credential the weak way.
PW_CONTEXT = re.compile(r"verify\w*[Pp]assword|hash\w*[Pp]assword|compare\w*[Pp]assword|"
                        r"[Pp]asswordHash|checkPassword|passwordDigest|set\w*[Pp]assword", re.I)
FAST_HASH = re.compile(r"createHash\s*\(\s*['\"](?:md5|sha1|sha256|sha224)['\"]|hashlib\.(?:md5|sha1|sha256|sha224)\b", re.I)
STRONG_KDF = re.compile(r"\bbcrypt\b|\bargon2|\bscrypt\b|\bpbkdf2\b", re.I)
# PKCE (RFC 7636) MANDATES a SHA-256 digest over the code_verifier to build the code_challenge. That's a
# createHash('sha256') sitting in an auth file, but its input is a VERIFIER, not a password — flagging it
# weak-password-hash is a false positive (real repos: a real Next.js app, a real app OAuth adapters).
PKCE_CONTEXT = re.compile(r"code_challenge|code_verifier|codeVerifier|codeChallenge|\bS256\b|\bPKCE\b", re.I)
JWT_VERIFY = re.compile(r"\bjwtVerify\s*\(|\bjwt\.verify\s*\(|\bjwtv2\.verify\s*\(|verifyJwt\s*\(", re.I)
JWT_ALGS = re.compile(r"algorithms?\s*[:=]|['\"]alg['\"]\s*:", re.I)
# a public hash of an identity field, used as a security principal / tenant key
PRINCIPAL_HASH = re.compile(
    r"createHash\s*\(\s*['\"]sha256['\"]\s*\)[\s\S]{0,100}?\.update\s*\([^)]*\b(?:email|userId|user_id|username|userEmail|sub)\b"
    r"|hashlib\.sha256\s*\([^)]*\b(?:email|user_id|username)\b", re.I)
PRINCIPAL_USE = re.compile(r"\b(?:tenant_?Id|user_?Id|set_config\s*\(\s*['\"]app\.|app\.user_id|principal|formatUuid|asUuid|toUuid)\b", re.I)
_PRINCIPAL_NAME = re.compile(r'(?:tenant_?id|user_?id|principal)', re.I)
_HASH_ASSIGN = re.compile(r'(?<![\w$.])(?:\b(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=(?!=)')
_PRINCIPAL_CONVERT = re.compile(r'\b(?:formatUuid|asUuid|toUuid)\s*\(')
MAX_HASH_SOURCE = 512 * 1024
MAX_HASH_SCOPES = 128
MAX_HASH_EVENTS = 2048
MAX_HASH_TOTAL_BYTES = 8 * 1024 * 1024


def _principal_hash_use(source: str, suffix: str) -> bool:
    """Supported local result bindings, not identity/tenant keywords elsewhere.

    Unknown wrappers, cross-function flow and closure mutation are not resolved.
    This detects principal provenance, not that principal secrecy is relied upon.
    """
    if not PRINCIPAL_HASH.search(source):
        return False
    if len(source.encode('utf-8')) > MAX_HASH_SOURCE:
        raise ValueError('Principal source byte budget exceeded')
    if suffix == '.py':
        import ast
        import warnings
        from itertools import islice
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                tree = ast.parse(source)
            if len(list(islice(ast.walk(tree), 20_001))) > 20_000:
                raise ValueError('Principal AST node budget exceeded')
        except (SyntaxError, RecursionError) as error:
            raise ValueError('Principal AST syntax unresolved') from error
        # Each Python suite owns its assignments. Branches conservatively retain
        # possible provenance; nested functions/classes never lend their bindings.
        def suite(body, initial=None, branch=False):
            bindings = set(initial or ())
            for node in body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if suite(node.body)[0]:
                        return True, bindings
                    continue
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    value = node.value
                    digest = (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                              and value.func.attr in {'hexdigest', 'digest'} and not value.args
                              and isinstance(value.func.value, ast.Call))
                    hash_call = value.func.value if digest else None
                    identity = (hash_call and isinstance(hash_call.func, ast.Attribute)
                                and isinstance(hash_call.func.value, ast.Name) and hash_call.func.value.id == 'hashlib'
                                and hash_call.func.attr == 'sha256' and len(hash_call.args) == 1
                                and any(isinstance(item, ast.Name) and item.id in {'email', 'user_id', 'username'}
                                        for item in ast.walk(hash_call.args[0])))
                    tainted = bool(identity) or (isinstance(value, ast.Name) and value.id in bindings)
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target, ast.Name):
                            if tainted:
                                bindings.add(target.id)
                                if _PRINCIPAL_NAME.fullmatch(target.id):
                                    return True, bindings
                            elif not branch:
                                bindings.discard(target.id)
                if isinstance(node, ast.If):
                    for child in (node.body, node.orelse):
                        found, possible = suite(child, bindings, branch=True)
                        if found:
                            return True, bindings
                        bindings.update(possible)
            return False, bindings
        return suite(tree.body)[0]
    scopes = js_functions(source)
    if len(scopes) > MAX_HASH_SCOPES or any(not scope.get('complete') for scope in scopes):
        raise ValueError('Principal scope analysis incomplete or budget exceeded')

    def owner(position):
        own = [scope for scope in scopes if scope['body_start'] <= position < scope['end']]
        return min(own, key=lambda scope: scope['end'] - scope['body_start']) if own else None

    bindings = {}
    events = sorted([(m.start(), 'assign', m) for m in _HASH_ASSIGN.finditer(source)]
                    + [(m.start(), 'convert', m) for m in _PRINCIPAL_CONVERT.finditer(source)])
    if len(events) > MAX_HASH_EVENTS:
        raise ValueError('Principal assignment event budget exceeded')
    for position, kind, match in events:
        if in_literal(source, position):
            continue
        scope = owner(position)
        key = scope['start'] if scope else -1
        values = bindings.setdefault(key, set())
        if kind == 'convert':
            call = call_expression(source, position)
            args = split_arguments(call[call.find('(')+1:-1])
            if len(args) == 1 and args[0] in values:
                return True
            continue
        expression = source[match.end():expression_end(source, match.end())].strip()
        direct_hash = re.match(r'(?:crypto\.)?createHash\s*\(\s*([\'"])sha256\1\s*\)\s*\.update\s*\(', expression)
        identity = False
        if direct_hash:
            end = expression_end(expression, direct_hash.end()-1, closing=')')
            argument = expression[direct_hash.end():end-1]
            identity = any(not in_literal(argument, item.start()) for item in
                           re.finditer(r'\b(?:email|userId|user_id|username|userEmail|sub)\b', argument))
            tail = expression[end:]
            identity = identity and bool(re.fullmatch(r'''\s*\.digest\s*\(\s*(?:(['"])hex\1)?\s*\)\s*''', tail))
        tainted = expression in values or identity
        if tainted:
            values.add(match[1])
            if _PRINCIPAL_NAME.fullmatch(match[1]):
                return True
        else:
            start = scope['body_start'] if scope else 0
            prefix = source[start:position]
            # Only a visibly straight-line overwrite clears provenance. Braced
            # branches conservatively retain may-flow, not a control-flow proof.
            if prefix.count('{') <= prefix.count('}') and not re.search(r'\b(?:if|for|while)\s*\([^)]*\)\s*$', prefix):
                values.discard(match[1])
    return False


def _hibp_digest_positions(source: str) -> set[int]:
    """Narrow whole-function prefix lookup, never a helper-name/file-wide exemption.

    Exactly SHA-1 hex -> five-character prefix -> fixed range endpoint, with the
    remainder used only for a boolean local response comparison. Anything else
    (storage, unknown options, different prefix/URL or unsafe sibling) keeps leads.
    """
    if not FAST_HASH.search(source) or 'api.pwnedpasswords.com' not in source:
        return set()
    if len(source.encode('utf-8')) > MAX_HASH_SOURCE:
        raise ValueError('HIBP purpose source byte budget exceeded')
    proof = re.compile(
        r'\s*const\s+(?P<h>[A-Za-z_$][\w$]*)\s*=\s*(?:crypto\.)?createHash\s*\(\s*([\'"])sha1\2\s*\)'
        r'\s*\.update\s*\(\s*(?:password|passwd|passphrase)\s*\)\s*\.digest\s*\(\s*([\'"])hex\3\s*\)'
        r'(?:\s*\.toUpperCase\s*\(\s*\))?\s*;\s*const\s+(?P<p>[A-Za-z_$][\w$]*)\s*=\s*(?P=h)'
        r'\s*\.slice\s*\(\s*0\s*,\s*5\s*\)\s*;\s*const\s+(?P<s>[A-Za-z_$][\w$]*)\s*=\s*(?P=h)'
        r'\s*\.slice\s*\(\s*5\s*\)\s*;\s*const\s+(?P<r>[A-Za-z_$][\w$]*)\s*=\s*await\s+fetch\s*\('
        r'\s*`https://api\.pwnedpasswords\.com/range/\$\{(?P=p)\}`\s*\)\s*;\s*return\s*\(\s*await\s+'
        r'(?P=r)\.text\s*\(\s*\)\s*\)\s*\.includes\s*\(\s*(?P=s)\s*\)\s*;?\s*')
    positions = set()
    scopes = js_functions(source)
    if len(scopes) > MAX_HASH_SCOPES:
        raise ValueError('HIBP purpose scope budget exceeded')
    masked = re.sub(_TIMING_LITERAL, lambda match: ' ' * len(match[0]), source)
    # Native fetch plus a visible Node crypto import. Unknown imports/replaced
    # globals and parameter bindings are not an observable primitive contract.
    named_crypto = re.search(r'''\bimport\s*\{\s*createHash\s*\}\s*from\s*(['"])(?:node:)?crypto\1''', source)
    module_crypto = re.search(r'''\bimport\s+(?:\*\s+as\s+)?crypto\s+from\s*(['"])(?:node:)?crypto\1''', source)
    mutation = re.search(r'\b(?:fetch|createHash|crypto)\s*(?:=(?!=)|\+=|\+\+|\[)|\bcrypto\s*\.\s*createHash\s*=(?!=)', masked)
    imported_fetch = re.search(r'\bimport\b[^;\n]*\bfetch\b|\bfunction\s+(?:fetch|createHash)\b', masked)
    destructured = any(re.search(r'\b(?:fetch|createHash|crypto)\b', match[0]) for match in
                       re.finditer(r'\b(?:const|let|var)\s*(?:\{[^;]{0,512}\}|\[[^;]{0,512}\])', masked))
    reflection = re.search(r'\b(?:Object\.(?:defineProperty|assign)|Reflect\.set)\s*\(\s*(?:globalThis|global|window|crypto)\b'
                           r'|\b(?:globalThis|global|window)\s*\[[^;]{0,512}\]\s*=(?!=)', masked)
    if mutation or imported_fetch or destructured or reflection:
        return set()
    for scope in scopes:
        if (scope.get('complete') and scope.get('simple_params') and len(scope['params']) == 1
                and scope['params'][0] in {'password', 'passwd', 'passphrase'} and proof.fullmatch(scope['body'])):
            ancestors = [other for other in scopes if other['body_start'] <= scope['start'] < other['end']]
            if any(not parent.get('simple_params') or set(parent['params']) & {'fetch', 'createHash', 'crypto'}
                   for parent in ancestors):
                continue
            match = FAST_HASH.search(scope['body'])
            module_call = bool(re.search(r'\bcrypto\s*\.\s*createHash', scope['body']))
            primitive = module_crypto if module_call else named_crypto
            if match and primitive and primitive.start() < scope['start'] and not in_literal(source, primitive.start()):
                positions.add(scope['body_start'] + match.start())
    return positions
_TIMING_LITERAL = (r'"""(?:\\.|(?!""")[^\\])*"""'
                   r"|'''(?:\\.|(?!''')[^\\])*'''"
                   r'''|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`''')
_TIMING_ITEMS = re.compile(_TIMING_LITERAL + r"|(?P<comparison>!==|===|!=|==)")
_CREDENTIAL_NAME = re.compile(
    r"\b[\w$]*(?:authorization|signature|hmac|token|password|passwd|passphrase|secret|api[_-]?key)[\w$]*\b"
    r"|\bexpectedAuth\b", re.I)
MAX_COMPARISON_OPERAND = 1024


def _jwt_without_algorithms(source: str) -> bool:
    """Only this invocation's direct nonempty literal allowlist is supported evidence."""
    for match in JWT_VERIFY.finditer(source):
        if in_literal(source, match.start()):
            continue
        call = call_expression(source, match.start())
        arguments = split_arguments(call[call.find('(') + 1:-1])
        # jose jwtVerify(token,key,options), jsonwebtoken verify(token,key,options).
        options = object_properties(arguments[2]) if len(arguments) >= 3 and call.endswith(')') else None
        value = (options or {}).get('algorithms', '')
        if not value.startswith('[') or not value.endswith(']'):
            return True
        algorithms = split_arguments(value[1:-1])
        if not algorithms or not all(re.fullmatch(r'''(['"])[A-Za-z][A-Za-z0-9_-]*\1''', item)
                                     and item[1:-1].lower() != 'none' for item in algorithms):
            return True
    return False


def _comparison_operand(source: str, position: int, direction: int) -> tuple[str, bool]:
    """Read one bounded operand; syntax uncertainty never proves a safe control."""
    start, index, stack, quote = position, position, [], None
    limit = max(-1, position - MAX_COMPARISON_OPERAND) if direction < 0 else min(len(source), position + MAX_COMPARISON_OPERAND)
    opening, closing = ("([{", ")]}") if direction > 0 else (")]}", "([{")
    while (index > limit if direction < 0 else index < limit):
        char = source[index]
        if quote:
            if char == quote:
                back = index - 1
                while back >= 0 and source[back] == "\\":
                    back -= 1
                if (index - back - 1) % 2 == 0:
                    quote = None
        elif char in "\"'`":
            quote = char
        elif char in opening:
            stack.append(closing[opening.index(char)])
        elif char in closing:
            if not stack:
                break
            if stack.pop() != char:
                break
        elif not stack and char in ";\n,?:=&|!<>":
            break
        index += direction
    value = source[index + 1:start + 1] if direction < 0 else source[start:index]
    complete = not stack and quote is None and (index != limit or limit in {-1, len(source)})
    value = value.strip()
    if direction < 0:
        value = re.sub(r"^(?:return|yield|if|elif|while|assert)\s+", "", value)
    return value, complete


def _unparenthesized(value: str) -> str:
    for _ in range(16):
        if not value.startswith("(") or expression_end(value, 0, closing=")") != len(value):
            break
        value = value[1:-1].strip()
    return value


# Identifier-shaped arguments: not credentials, so hashing them weakly is not a password-hash bug.
_NON_CREDENTIAL_ARGUMENT = re.compile(
    r"(?:^|\.)(?:id|email|userId|user_id|tenantId|tenant_id|password" + _PW_METADATA + r")$", re.I)


_METADATA_SUFFIXES = {"name", "type", "id", "method", "algorithm", "class", "url", "uri",
                      "path", "count", "salt", "format", "state", "required", "status", "date", "time"}


def _metadata_operand(value: str) -> bool:
    """Name heuristic for a simple metadata value, never a compound secret expression."""
    value = _unparenthesized(value)
    if not re.fullmatch(r"[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*", value):
        return False
    leaf = value.rsplit(".", 1)[-1].strip()
    if "." in value and leaf in {"length", "size", "byteLength", "type"}:
        return True
    # Require actual snake/camel token boundaries: `secretValid` is not `secret_id`.
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", leaf)
    parts = normalized.lower().split("_")
    return (len(parts) > 1 and parts[-1] in _METADATA_SUFFIXES
            and bool(_CREDENTIAL_NAME.search("_".join(parts[:-1]))))


def _credential_operand(value: str) -> bool:
    # Literal words in arbitrary message strings aren't credential variables.
    if _metadata_operand(value):
        return False
    bare = re.sub(_TIMING_LITERAL, "''", value)
    if _CREDENTIAL_NAME.search(bare):
        return True
    for match in re.finditer(r'''(?:\[\s*|\.(?:get|header)\s*\(\s*)(['"])([^'"\\]+)\1''', value):
        if _CREDENTIAL_NAME.search(match[2]):
            return True
    return False


def _presence_literal(value: str, suffix: str) -> bool:
    value = _unparenthesized(value)
    if value in {"''", '""', '0', '"0"', "'0'"}:
        return True
    if suffix == ".py":
        return value in {"None", "True", "False"}
    if suffix not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"}:
        return False
    return value in {"null", "true", "false"}


def _typeof_operand(value: str, suffix: str) -> bool:
    if suffix not in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts"}:
        return False
    value = _unparenthesized(value)
    # `undefined` is a shadowable JavaScript identifier, unlike these literals.
    # Only a simple typeof operand is a type check; concatenation stays unknown.
    kind = re.match(r"typeof\b\s*", value)
    if kind:
        target = _unparenthesized(value[kind.end():].strip())
        return bool(re.fullmatch(r'''[\w$]+(?:\s*\.\s*[\w$]+|\s*\[\s*(?:[\w$]+|'[^'\\]*'|"[^"\\]*")\s*\])*''', target))
    return False


def _type_comparison(left: str, right: str, suffix: str) -> bool:
    def label(value):
        value = _unparenthesized(value)
        return (len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]
                and value[1:-1] in {"undefined", "object", "boolean", "number", "bigint", "string", "symbol", "function"})
    left_type, right_type = _typeof_operand(left, suffix), _typeof_operand(right, suffix)
    return ((left_type and (label(right) or right_type))
            or (right_type and label(left)))


def _interpolated_comparison(literal: str, suffix: str, depth: int, *, python: bool = False) -> dict | None:
    """Inspect bounded interpolation expressions, never ordinary string contents."""
    position = 1
    while position < len(literal) - 1:
        start = literal.find("{" if python else "${", position)
        if start < 0:
            break
        back = start - 1
        while back >= 0 and literal[back] == "\\":
            back -= 1
        escaped = (start - back - 1) % 2 == 1
        if (python and literal.startswith("{{", start)) or (not python and escaped):
            position = start + 2
            continue
        opening = start if python else start + 1
        end = expression_end(literal, opening, closing="}")
        payload = literal[opening + 1:end - 1]
        bounded = end <= opening or literal[end - 1:end] != "}" or depth >= 4
        if bounded:
            payload = literal[opening + 1:end]
            if _CREDENTIAL_NAME.search(payload) and re.search(r"!==|===|!=|==", payload):
                return {"line": literal.count("\n", 0, opening) + 1,
                        "operator": "unresolved", "control_scope": "interpolation analysis limit; credential comparison unverified"}
        else:
            row = _timing_comparison(payload, suffix, depth + 1)
            if row:
                row["line"] += literal.count("\n", 0, opening)
                return row
        position = max(end, start + 1)
    return None


def _timing_comparison(source: str, suffix: str, _depth: int = 0) -> dict | None:
    """Equality-site hints only; a helper elsewhere cannot certify this comparison."""
    if not _CREDENTIAL_NAME.search(source):
        return None
    for match in _TIMING_ITEMS.finditer(source):
        if match.group("comparison") is None:
            python = suffix == ".py" and bool(re.search(r"(?:^|\W)(?:[rR]?[fF]|[fF][rR])$", source[max(0, match.start()-3):match.start()]))
            if match[0].startswith("`") or python:
                row = _interpolated_comparison(match[0], suffix, _depth, python=python)
                if row:
                    row["line"] += source.count("\n", 0, match.start())
                    return row
            continue
        left, left_complete = _comparison_operand(source, match.start() - 1, -1)
        right, right_complete = _comparison_operand(source, match.end(), 1)
        if not (_credential_operand(left) or _credential_operand(right)):
            continue
        if left_complete and right_complete and (_presence_literal(left, suffix) or _presence_literal(right, suffix)
                                                 or _type_comparison(left, right, suffix)):
            continue
        return {"line": source.count("\n", 0, match.start()) + 1,
                "operator": match.group("comparison"),
                "control_scope": "bounded equality operands; credential purpose and runtime timing unverified; JavaScript regex literals are unresolved"}
    return None


class CryptoUsageExtractor(Extractor):
    name = "crypto_usage"
    category = "crypto"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        findings: list = []
        seen: set = set()
        hash_errors = []
        hash_bytes = 0

        def add(sev, kind, attack, rel, detail, evidence=None):
            if (kind, rel) in seen:
                return
            seen.add((kind, rel))
            findings.append({"severity": sev, "kind": kind, "attack_class": attack,
                             "file": rel, "detail": detail, **(evidence or {})})

        for _p, rel, text in ctx.iter_code():
            if is_test_file(rel):
                continue
            source = without_comments(text, _p.suffix)
            hibp, principal = set(), False
            if PRINCIPAL_HASH.search(source) or (FAST_HASH.search(source) and 'api.pwnedpasswords.com' in source):
                hash_bytes += len(source.encode('utf-8'))
                try:
                    if hash_bytes > MAX_HASH_TOTAL_BYTES:
                        raise ValueError('Hash-purpose aggregate source budget exceeded')
                    principal = _principal_hash_use(source, _p.suffix.lower())
                    if _p.suffix.lower() in {'.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx'}:
                        hibp = _hibp_digest_positions(source)
                except ValueError as error:
                    if len(hash_errors) < 50:
                        hash_errors.append({'file': rel, 'detail': str(error)})
            # PKCE elsewhere cannot excuse an explicit password-fed digest. For a
            # renamed input, require the password helper's own bounded scope;
            # unrelated strong KDF imports/calls likewise cannot protect it.
            weak = any(not in_literal(source, match.start()) and match.start() not in hibp
                       for match in WEAK_PW_HASH.finditer(source))
            for scope in js_functions(source):
                if not scope.get("complete", True) and PW_CONTEXT.search(scope["name"]):
                    if FAST_HASH.search(source[scope["body_start"]:scope["end"]-1]):
                        weak = True
                    continue
                if PW_CONTEXT.search(scope["name"]) and FAST_HASH.search(scope["body"]):
                    body = scope["body"]
                    for match in FAST_HASH.finditer(body):
                        if in_literal(body, match.start()):
                            continue
                        if scope['body_start'] + match.start() in hibp:
                            continue
                        # Only the actual verifier-fed digest is a PKCE exception.
                        opening = body.find("(", match.start())
                        end = expression_end(body, opening, closing=")") if opening >= 0 else match.end()
                        update = re.match(r"\s*\.\s*update\s*\(", body[end:])
                        argument = ""
                        if update:
                            arg_start = end + update.end()
                            arg_end = expression_end(body, arg_start-1, closing=")")
                            argument = body[arg_start:arg_end-1].strip()
                        # A PKCE verifier is hashed by design, and an identifier is not a
                        # credential: `md5(user.id)` inside a password-ish function is a cache key,
                        # not a password hash. Hashing an identifier to MINT a token is a different
                        # bug (predictable token), not this one, so it is skipped here rather than
                        # reported under a class that would misdescribe it.
                        # These arguments CONTRIBUTE NOTHING; they must not clear a weak hash found
                        # earlier in the same function. Assigning False here instead let a later
                        # PKCE/identifier hash clobber a real `md5(password)` above it —
                        # test_pkce_exception_belongs_only_to_its_own_hash_argument catches exactly
                        # that, and the exception belongs to its own argument, not to the function.
                        if argument not in {"codeVerifier", "code_verifier"} \
                                and not _NON_CREDENTIAL_ARGUMENT.search(argument):
                            weak = True
            if weak:
                add("HIGH", "weak-password-hash", "weak-password-hash", rel,
                    "A password appears to be hashed/verified with a FAST, unsalted digest "
                    "(SHA-256/SHA-1/MD5). These are GPU-crackable at billions/sec and rainbow-tableable "
                    "with no per-credential salt (CWE-916/759). Use a memory-hard KDF — argon2id / scrypt "
                    "/ bcrypt — with a random per-password salt. Never commit credential material to source.")
            if _jwt_without_algorithms(source):
                add("LOW", "jwt-verify-no-algorithms", "jwt-verify-options", rel,
                    "A JWT verify call doesn't pin an `algorithms` allowlist. Safe TODAY only if the key is "
                    "symmetric (the library constrains it to HMAC) — but it silently re-opens alg-confusion / "
                    "alg:none the moment the verifier is migrated to an asymmetric/JWKS key (CWE-347). Pass an "
                    "explicit `algorithms: ['HS256']` (and issuer/audience) so the guarantee is in the code.")
            timing = _timing_comparison(source, _p.suffix.lower())
            if timing:
                add("LOW", "timing-unsafe-compare", "timing-unsafe-compare", rel,
                    "A credential-shaped value is compared with raw equality/inequality. Review whether "
                    "this compares an attacker-supplied credential against a secret and whether observable "
                    "timing matters (CWE-208); source syntax alone does not prove an exploitable side channel. "
                    "Use an appropriate constant-time comparison for secret bytes, with compatible types and "
                    "lengths, and review the surrounding code. A timing-safe helper elsewhere does not protect "
                    "this operation. Nonempty literals and unresolved JavaScript undefined remain review leads.", timing)
            if principal:
                add("LOW", "predictable-principal", "predictable-principal", rel,
                    "A security principal (tenant/user id) appears to be derived as a public, keyless hash of "
                    "an identity field (e.g. `sha256(email)`), so anyone who knows the email can recompute the "
                    "victim's exact id (CWE-330/340). The id's secrecy adds zero defense in depth. Use an opaque "
                    "server-assigned random id, or HMAC the mapping under a server secret; verify the resolved "
                    "row owns the session before honoring a client-supplied id.")

        by_sev: dict = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        return {"findings": findings, "by_severity": by_sev,
                **({'error': 'Hash-purpose source analysis incomplete; see hash_flow.errors'} if hash_errors else {}),
                'hash_flow': {'errors': hash_errors, 'source_bytes': hash_bytes,
                              'limits': {'source_bytes_per_file': MAX_HASH_SOURCE, 'source_bytes_total': MAX_HASH_TOTAL_BYTES,
                                         'scopes_per_file': MAX_HASH_SCOPES, 'events_per_file': MAX_HASH_EVENTS},
                              'limitations': ['Local supported assignments only; aliases, loops and cross-function flow remain unverified.',
                                              'Hash purpose is not principal secrecy reliance or correct breach-screening proof.']},
                "note": (f"{len(findings)} crypto-usage lead(s) — algorithm choice + verify-option correctness "
                         "(beyond the secret-leak scanners). Verify each: is the hashed value really a password, "
                         "is the JWT key symmetric, is the hashed id used as an authz principal?")
                        if findings else "No weak-hash / unpinned-verify / predictable-principal crypto tells found."}

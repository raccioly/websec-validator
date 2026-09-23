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
from .syntax import expression_end, in_literal, js_functions, without_comments

_PW = r"(?:password|passwd|passphrase|\bpwd\b|userPassword|plainPassword)(?![a-zA-Z0-9_]*?(?:[Tt]oken|[Hh]ash|[Ss]alt|[Aa]ttempt|[Rr]eset|[Cc]ount|[Uu]ri|[Uu]rl|[Ii]d\b|[Ff]ile))"
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
_TIMING_LITERAL = (r'"""(?:\\.|(?!""")[^\\])*"""'
                   r"|'''(?:\\.|(?!''')[^\\])*'''"
                   r'''|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`''')
_TIMING_ITEMS = re.compile(_TIMING_LITERAL + r"|(?P<comparison>!==|===|!=|==)")
_CREDENTIAL_NAME = re.compile(
    r"\b[\w$]*(?:authorization|signature|hmac|token|password|passwd|passphrase|secret|api[_-]?key)[\w$]*\b"
    r"|\bexpectedAuth\b", re.I)
MAX_COMPARISON_OPERAND = 1024


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
_NON_CREDENTIAL_ARGUMENT = re.compile(r"(?:^|\.)(?:id|email|userId|user_id|tenantId|tenant_id)$", re.I)


def _credential_operand(value: str) -> bool:
    # Literal words in arbitrary message strings aren't credential variables.
    if re.search(r'\.(?:length|size|byteLength|type)$', value):
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
            # PKCE elsewhere cannot excuse an explicit password-fed digest. For a
            # renamed input, require the password helper's own bounded scope;
            # unrelated strong KDF imports/calls likewise cannot protect it.
            weak = any(not in_literal(source, match.start()) for match in WEAK_PW_HASH.finditer(source))
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
            if JWT_VERIFY.search(text) and not JWT_ALGS.search(text):
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
            if PRINCIPAL_HASH.search(text) and PRINCIPAL_USE.search(text):
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
                "note": (f"{len(findings)} crypto-usage lead(s) — algorithm choice + verify-option correctness "
                         "(beyond the secret-leak scanners). Verify each: is the hashed value really a password, "
                         "is the JWT key symmetric, is the hashed id used as an authz principal?")
                        if findings else "No weak-hash / unpinned-verify / predictable-principal crypto tells found."}

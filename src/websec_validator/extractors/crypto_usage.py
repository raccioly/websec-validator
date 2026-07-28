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

_PW = r"(?:password|passwd|passphrase|\bpwd\b|userPassword|plainPassword)"
# a fast digest fed a password-shaped value (either arg order, within a small window)
WEAK_PW_HASH = re.compile(
    r"createHash\s*\(\s*['\"](?:md5|sha1|sha256|sha224)['\"]\s*\)[\s\S]{0,160}?\.update\s*\([^)]*" + _PW
    + r"|" + _PW + r"[\s\S]{0,80}?createHash\s*\(\s*['\"](?:md5|sha1|sha256|sha224)['\"]"
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
# a request-supplied secret/token/signature compared with ===/!== (non-constant-time) instead of a
# timing-safe equal — a credential/HMAC timing side-channel (CWE-208).
TIMING_UNSAFE = re.compile(
    r"(?:req|request|ctx)\.(?:headers?|header|get)\b[^;\n]{0,70}\b(?:authorization|token|signature|hmac|secret|api[_-]?key)\b[^;\n]{0,70}[!=]==?\s*(?!(?:undefined|null|true|false)\b|['\"](?:Bearer\s*)?['\"](?:;|\s|\)|$)|['\"]['\"](?:;|\s|\)|$))[a-zA-Z0-9_\"'\.`\$\(]+"
    r"|\b(?:authorization|signature|hmac|x-[\w-]*signature|providedToken|givenToken)\b[^;\n]{0,50}[!=]==?\s*(?:expected|valid|secret|process\.env|config\.)"
    r"|[!=]==?\s*(?:expectedSignature|expectedToken|expectedAuth|expectedHmac|validSignature)\b", re.I)
TIMING_SAFE = re.compile(r"timingSafeEqual|compare_digest|secure_compare|constantTimeEqual|crypto\.timingSafeEqual", re.I)


class CryptoUsageExtractor(Extractor):
    name = "crypto_usage"
    category = "crypto"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        findings: list = []
        seen: set = set()

        def add(sev, kind, attack, rel, detail):
            if (kind, rel) in seen:
                return
            seen.add((kind, rel))
            findings.append({"severity": sev, "kind": kind, "attack_class": attack,
                             "file": rel, "detail": detail})

        for _p, rel, text in ctx.iter_code():
            if is_test_file(rel):
                continue
            if ((WEAK_PW_HASH.search(text) or (PW_CONTEXT.search(text) and FAST_HASH.search(text)
                                               and not STRONG_KDF.search(text)))
                    and not PKCE_CONTEXT.search(text)):     # PKCE S256 over the verifier ≠ password hash
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
            if TIMING_UNSAFE.search(text) and not TIMING_SAFE.search(text):
                add("LOW", "timing-unsafe-compare", "timing-unsafe-compare", rel,
                    "A request-supplied secret/token/signature appears to be compared with `===`/`!==` "
                    "(not constant-time). This leaks a byte-by-byte timing side-channel on the credential "
                    "(CWE-208). Compare with `crypto.timingSafeEqual` on equal-length buffers (or hash both "
                    "sides first). Low impact when fronted by another auth layer, but cheap to fix.")
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

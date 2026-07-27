#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────────────────────
# websec-validator — DRAFT probe. Any example endpoints / auth / login below are
# PLACEHOLDERS from the template. THIS target's real surface — routes, auth scheme
# + token location, sensitive fields, tenant key — is in  ./probe-context.json
# (generated from FACTS.json for this app). Use those values before running; the
# agent should finalize this draft against probe-context.json, then fill secrets.
# ─────────────────────────────────────────────────────────────────────────────
# ⚠ DEFENSIVE CHECK — run only against a system you own/operate, with consent. Not for production or third-party targets.
"""
HS256 JWT secret brute-force probe.

Tries a wordlist of common weak secrets against a captured JWT. If any
candidate verifies the signature, we have the secret -> can forge any
token -> critical finding.

This is OFFLINE — no server requests. Run safely against any token.

Usage: python3 hs256-brute-force.py <jwt_token>
"""
import sys, hmac, hashlib, base64

if len(sys.argv) != 2:
    print("Usage: hs256-brute-force.py <jwt_token>", file=sys.stderr)
    sys.exit(2)

token = sys.argv[1].strip()
try:
    h_b64, p_b64, s_b64 = token.split('.')
except ValueError:
    print("Token isn't a 3-part JWT", file=sys.stderr)
    sys.exit(2)

def b64url_pad(s):
    return s + '=' * (-len(s) % 4)

signed = (h_b64 + '.' + p_b64).encode()
expected_sig = base64.urlsafe_b64decode(b64url_pad(s_b64))

# Wordlist: common weak JWT secrets seen in the wild.
# Real bug bounties: "secret", "your-256-bit-secret" (the JWT.io default!),
# "jwt-secret", common framework defaults, project-name guesses.
# TODO: Add project-name candidates: variations of <PROJECT_NAME>, the company
# name, internal team names, any nickname you've seen in docs. Attackers will.
CANDIDATES = [
    # JWT.io default (used by tutorials, sometimes makes it to production)
    "your-256-bit-secret",
    # NextAuth + Auth.js defaults
    "your-secret-key", "your-secret",
    # Express + jsonwebtoken tutorials
    "secret", "jwt-secret", "jwtsecret", "JWT_SECRET",
    "supersecret", "supersecretkey",
    # Common dev placeholders
    "changeme", "changeit", "changethis", "CHANGEME",
    "password", "Password1!", "admin", "admin123",
    "test", "test123", "testing",
    "dev", "development", "local",
    "default", "default-secret",
    # PROJECT-SPECIFIC START
    # TODO: project-name and company-name guesses go here.
    # "<project-name>", "<project-slug>", "<company-name>",
    # PROJECT-SPECIFIC END
    # Common framework env defaults
    "your-secret-jwt-key", "secretkey",
    # Length-32 placeholders
    "0123456789abcdef0123456789abcdef",
    "abcdefghijklmnopqrstuvwxyz123456",
    # Empty/null secrets (sometimes accepted)
    "",
    "null", "undefined",
    # Common from leaked-secret datasets
    "123456", "12345678", "qwerty",
]

print(f"=== HS256 brute force test ===")
print(f"  Token header.payload length: {len(h_b64) + 1 + len(p_b64)} bytes")
print(f"  Trying {len(CANDIDATES)} candidate secrets (offline, no requests)...")
print()

found = None
for cand in CANDIDATES:
    computed = hmac.new(cand.encode(), signed, hashlib.sha256).digest()
    if hmac.compare_digest(computed, expected_sig):
        found = cand
        break

if found is not None:
    print(f"  !! CRITICAL: signing secret cracked!")
    print(f"  Secret value: {'<EMPTY STRING>' if not found else repr(found)}")
    print(f"  Implication: any attacker can forge JWTs for any user/role.")
    print(f"  Action: ROTATE the JWT signing secret IMMEDIATELY.")
    sys.exit(1)
else:
    print(f"  OK -- none of {len(CANDIDATES)} weak-secret candidates work.")
    print(f"  This does NOT prove the secret is strong -- only that it's not in")
    print(f"  this short wordlist. For a real engagement, use hashcat mode 16500")
    print(f"  against rockyou.txt or larger lists.")
    sys.exit(0)

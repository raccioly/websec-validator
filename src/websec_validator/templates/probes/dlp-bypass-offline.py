#!/usr/bin/env python3
# ⚠ DEFENSIVE CHECK — run only against a system you own/operate, with consent. Not for production or third-party targets.
"""
DLP bypass corpus — OFFLINE regex analysis.

Pulls the live DLP rules from the API, then tests each rule's regex
against an encoding corpus (the same payload encoded different ways).
If the regex DOES NOT match an encoded variant, that variant is a bypass.

No messages are sent. No network calls beyond fetching the rule list.

Output: per-rule per-encoding match/bypass table.

PRECONDITION: your project has a DLP / content-filtering feature with rules
the admin can list via API. If not, this script is N/A.
"""
import base64, json, os, re, sys, urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lib  # noqa: E402

TARGET = _lib.base_url()
HDR = _lib.auth_headers("A")    # a privileged/admin token that can list DLP rules
if not HDR:
    sys.exit("Supply an admin token: TOKEN_A=<jwt> (or COOKIE_A). See _lib.py.")

# DLP-rules endpoint + rule schema vary by app. Set RULES_ENDPOINT, or edit this.
RULES_ENDPOINT = os.environ.get("RULES_ENDPOINT", "/api/dlp/rules")

code, rules_raw = _lib.curl("GET", f"{TARGET}{RULES_ENDPOINT}", headers=HDR)
if code != 200:
    sys.exit(f"Couldn't fetch DLP rules from {RULES_ENDPOINT} (HTTP {code}). If this app has no "
             "DLP/content-filter feature this probe is N/A; otherwise set RULES_ENDPOINT to the real path.")
try:
    all_rules = json.loads(rules_raw)
except Exception:
    sys.exit(f"DLP rules endpoint returned non-JSON (HTTP {code}).")

# Filter to content (regex) rules, skipping any media/file-type-prefix rules
content_rules = [r for r in all_rules if not r.get('pattern','').startswith('MEDIA_TYPE:')]
print(f"=== {len(content_rules)} content-pattern DLP rules loaded ===")
for r in content_rules:
    print(f"  - {r.get('id','?'):50s} action={r.get('action','?')} scope={r.get('scope','?')}")

# Sensitive payloads — fake but format-correct
PAYLOADS = {
    'amex_card':    '3782 822463 10005',      # American Express test number
    'visa_card':    '4111-1111-1111-1111',    # Visa test number
    'ssn':          '123-45-6789',
    'email':        'victim@example.com',
    'phone':        '+1 (212) 555-1234',
}

def encodings(text):
    """Generate same payload in different encodings/obfuscations"""
    return {
        'plain':                    text,
        'base64':                   base64.b64encode(text.encode()).decode(),
        'base64_padded':            'data:text/plain;base64,' + base64.b64encode(text.encode()).decode(),
        'hex':                      text.encode().hex(),
        'url_encoded':              urllib.parse.quote(text),
        'url_double_encoded':       urllib.parse.quote(urllib.parse.quote(text)),
        'zero_width_split':         text[:2] + '​' + text[2:],  # zero-width space
        'rtl_override':             '‮' + text,
        'spacing_split':            ' '.join(text),
        'rot13':                    text.translate(str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm')),
        'html_entity_digit':        re.sub(r'(\d)', lambda m: f"&#{ord(m.group(1))};", text),
        'leet':                     text.replace('1','l').replace('0','O').replace('4','A'),
        'json_unicode_escape':      ''.join(f'\\u{ord(c):04x}' if c.isdigit() else c for c in text),
        'mixed_case_keyword':       text.upper(),
        'comment_inline':           text.replace(' ', '/*x*/'),
    }

print()
print("=== Bypass matrix: rule x payload x encoding -> matches? ===")
print()

findings = []

for rule in content_rules:
    pat = rule.get('pattern', '')
    name = rule.get('name', '?')
    rid = rule.get('id', '?')
    print(f"\n--- {name} ({rid}) ---")
    print(f"    pattern: {pat[:80]}{'...' if len(pat) > 80 else ''}")
    try:
        regex = re.compile(pat, re.IGNORECASE)
    except re.error as e:
        print(f"    !! rule pattern invalid: {e}")
        continue

    relevant_payloads = []
    if 'amex' in rid: relevant_payloads.append('amex_card')
    if 'visa' in rid or 'mc' in rid: relevant_payloads.append('visa_card')
    if 'ssn' in rid.lower() or 'social' in name.lower(): relevant_payloads.append('ssn')
    if 'email' in rid.lower(): relevant_payloads.append('email')
    if 'phone' in rid.lower(): relevant_payloads.append('phone')

    if not relevant_payloads:
        print(f"    (no matching test payload -- skip)")
        continue

    for pname in relevant_payloads:
        payload = PAYLOADS[pname]
        print(f"    test payload: {pname} ({payload!r})")
        for ename, encoded in encodings(payload).items():
            matched = bool(regex.search(encoded))
            mark = 'OK BLOCK' if matched else '!! BYPASS'
            if ename == 'plain' and not matched:
                mark = 'XX MISCONFIGURED (regex does not match plain text)'
            line = f"      [{mark:35s}] {ename:25s} -> {encoded[:60]}"
            print(line)
            findings.append({
                'rule_id': rid,
                'rule_name': name,
                'payload': pname,
                'encoding': ename,
                'matched': matched,
                'sample': encoded[:80],
            })

out = _lib.save("dlp-bypass", findings)

bypasses = [f for f in findings if not f['matched'] and f['encoding'] != 'plain']
plain_misses = [f for f in findings if not f['matched'] and f['encoding'] == 'plain']
print()
print(f"=== Summary ===")
print(f"  Total tests:        {len(findings)}")
print(f"  Bypasses found:     {len(bypasses)}")
print(f"  Misconfigured rules:{len(plain_misses)} (regex doesnt match its own intended payload)")
print(f"  Saved: {out}")

if bypasses:
    print()
    print(f"=== Bypass details ===")
    for b in bypasses[:20]:
        print(f"  [{b['rule_id']:50s}] {b['encoding']:25s} {b['payload']} -> bypass")

sys.exit(0)

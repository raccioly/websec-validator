#!/usr/bin/env python3
"""Authorized TEST-only race observation; bounded stdlib threads, never exploit proof.

Eight simultaneous requests by default (maximum sixteen), at most eight endpoints.
Review each endpoint's actual invariant before interpreting status counts. Multiple
2xx responses alone do not prove a race or that state changed. No response bodies,
redirect locations or exception text are saved. No extra package installation.
"""
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lib

PARALLEL = 8
MAX_PARALLEL = 16
MAX_PAYLOAD = 16_384
TIMEOUT = 5


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fire(target, *, headers=None, opener=None):
    """One guarded request; status/error-kind only, including HTTP redirect errors."""
    _lib.guard_request(target['method'], target['url'])
    payload = json.dumps(target.get('payload', {})).encode('utf-8')
    if len(payload) > MAX_PAYLOAD:
        raise ValueError('race payload exceeds bounded request size')
    request = urllib.request.Request(target['url'], data=payload,
        method=target['method'], headers=dict(headers or {}, **{'Content-Type': 'application/json'}))
    transport = opener if opener is not None else urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with transport.open(request, timeout=TIMEOUT) as response:
            return response.status, None  # deliberately never read arbitrary response bytes
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        return status, None
    except Exception as error:
        return None, type(error).__name__  # exception text can reflect credentials


def run_target(target, *, headers=None, parallel=PARALLEL):
    if isinstance(parallel, bool) or not isinstance(parallel, int) or not 1 <= parallel <= MAX_PARALLEL:
        raise ValueError('race concurrency must be an integer from 1 to 16')
    _lib.guard_request(target['method'], target['url'])
    with ThreadPoolExecutor(max_workers=parallel) as pool:
        results = list(pool.map(lambda _: fire(target, headers=headers), range(parallel)))
    codes = Counter(row[0] for row in results)
    successes = sum(1 for status, _ in results if status and 200 <= status < 300)
    expected = target.get('expected_unique', 1)
    suspected = successes > expected
    print(f"  status counts: {dict(codes)}; successes: {successes}, expected: {expected}")
    return {'name': target.get('name', 'race observation'), 'parallel': parallel,
            'status_counts': dict(codes), 'success_count': successes, 'expected_unique': expected,
            'race_suspected': suspected, 'error_kinds': dict(Counter(error for _, error in results if error)),
            'note': 'Status-only observation; validate endpoint invariant and state before claiming a race.'}


def main():
    base = _lib.base_url()
    _lib.require('OBJ_A')
    token, cookie = os.environ.get('TOKEN_A'), os.environ.get('COOKIE_A')
    headers = {'Authorization': f'Bearer {token}'} if token else ({'Cookie': cookie} if cookie else {})
    if not headers:
        sys.exit('Supply TOKEN_A or COOKIE_A for an authorized test account; see _lib.py.')
    targets = [{'name': f'{method} {path}', 'method': method,
                'url': base + re.sub(r'\{[^}]+\}', os.environ['OBJ_A'], path),
                'payload': {}, 'expected_unique': 1}
               for method, path in _lib.write_endpoints()][:8]
    if not targets:
        sys.exit('No write endpoints in probe-context.json; nothing to probe.')
    # Validate every destination before starting even the first request.
    for target in targets:
        _lib.guard_request(target['method'], target['url'])
    results = [run_target(target, headers=headers) for target in targets]
    _lib.save('race-conditions', results)
    return 1 if any(row['race_suspected'] for row in results) else 0


if __name__ == '__main__':
    sys.exit(main())

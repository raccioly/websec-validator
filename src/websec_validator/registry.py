"""OPT-IN package-existence verification — the AI slopsquat / hallucinated-dependency class.

Commercial models hallucinate dependencies at >=5.2% across 576,000 samples, generating 200,000+
unique non-existent package names. That is the attack surface behind dependency squatting, and it
is not detectable offline: only the registry knows whether a name resolves.

WHAT A RESULT MEANS, precisely, because this is easy to overclaim:

  exists   the registry serves this name TODAY. **This is NOT evidence of safety.** A squatter who
           has already registered a hallucinated name also returns 200 — that is the successful
           attack, not the clean case.
  missing  an explicit 404. A lead, not proof. It is split downstream into
           `dependency-nonexistent` and `dependency-unpublished-or-removed` using offline lockfile
           evidence, because a package pulled for malware and a name that never existed both 404
           and need different remediation.
  unknown  rate-limited, timed out, offline, or any non-404 error. UNKNOWN is NOT clean and NOT
           missing; it makes execution incomplete.

WHY THIS IS NOT A HARD GATE. The UNKNOWN rate is non-deterministic and outside the operator's
control — measured at 0%, 0%, 0% and 4.5% across four identical 200-name runs. A gate has two
options on UNKNOWN and both are wrong: fail-closed makes registry availability a dependency of
shipping (an outage amplifier, and the team pins `--no-network` within a week), fail-open
manufactures false verification. The third option, which only a non-gate can take, is the right
one: UNKNOWN makes the run incomplete, exactly as a selected-but-missing scanner does.

PRIVACY. A membership query leaks. Asking npmjs about `@acme/billing-core` tells npm, Inc. — and
anyone watching TLS SNI — that a machine running websec depends on that name, and a 404 tells an
attacker precisely which name to squat. **The check can create the dependency-confusion opportunity
it exists to find.** So names this repository publishes itself, names bound to a private registry
by repo-local config, and non-registry specs are all subtracted OFFLINE, before any request.
`--network-dry-run` prints the exact list and sends nothing.

Network conventions mirror `intel.py`: host allowlist enforced on the request AND on every redirect
hop, HTTPS only, no userinfo, no non-443 port, explicit timeouts, bounded reads. Only bare package
NAMES are sent — never a version, path, repository identity or operator identity — and nothing is
ever POSTed.
"""
from __future__ import annotations

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

_HOSTS = {"registry.npmjs.org", "pypi.org"}
CONNECT_TIMEOUT = 8
ABSOLUTE_DEADLINE = 20
DEFAULT_WORKERS = 8
DEFAULT_RATE = 20.0            # requests/second, global across workers
MAX_NAMES = 500
_RETRY_AFTER = 1.5

# Conservative: anything outside this is not a registry name we are willing to send anywhere.
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$", re.I)
_PYPI_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _check_url(url: str) -> None:
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in _HOSTS
            or parsed.username or parsed.password or parsed.port not in (None, 443)):
        raise ValueError("registry redirect is outside the allowed HTTPS registries")


class _Redirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _Throttle:
    """Global token bucket shared by every worker. Rate-limited, not concurrency-limited: being
    polite to a public registry is about requests per second, not threads."""

    def __init__(self, rate: float):
        self._interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if not self._interval:
            return
        with self._lock:
            now = time.monotonic()
            when = max(now, self._next)
            self._next = when + self._interval
        delay = when - now
        if delay > 0:
            time.sleep(delay)


def url_for(ecosystem: str, name: str) -> str:
    """The cheapest endpoint that answers existence.

    npm's packument is >=256KB per package; a HEAD against the same path transfers ZERO body bytes.
    `/{name}/latest` is rejected deliberately: it 404s for a package that exists but has no `latest`
    dist-tag (all versions unpublished, or prerelease-only), which would manufacture a false
    'missing'. PyPI's `/simple/` applies PEP 503 normalisation, so Flask_Cors and flask-cors resolve
    identically.
    """
    if ecosystem == "npm":
        return "https://registry.npmjs.org/" + quote(name, safe="@/")
    if ecosystem == "pip":
        return "https://pypi.org/simple/" + quote(name.lower().replace("_", "-").replace(".", "-"), safe="") + "/"
    raise ValueError(f"unsupported ecosystem: {ecosystem}")


def valid_name(ecosystem: str, name: str) -> bool:
    pattern = _NPM_NAME if ecosystem == "npm" else _PYPI_NAME
    return bool(name) and len(name) <= 214 and bool(pattern.match(name))


def probe(ecosystem: str, name: str, *, opener=None) -> dict:
    """One HEAD request. Every failure mode collapses to UNKNOWN; only an explicit 404 is MISSING."""
    if not valid_name(ecosystem, name):
        return {"state": "unknown", "reason": "name is not a valid registry identifier"}
    try:
        url = url_for(ecosystem, name)
        _check_url(url)
    except ValueError as error:
        return {"state": "unknown", "reason": str(error)}
    request = Request(url, method="HEAD",
                      headers={"User-Agent": "websec-validator/registry",
                               "Accept-Encoding": "identity"})
    client = opener or build_opener(_Redirect())
    for attempt in (0, 1):
        try:
            with client.open(request, timeout=CONNECT_TIMEOUT) as response:
                _check_url(response.geturl())
                return {"state": "exists", "status": response.status}
        except HTTPError as error:
            if error.code == 404:
                return {"state": "missing", "status": 404}
            if error.code in (429, 500, 502, 503, 504) and attempt == 0:
                time.sleep(_RETRY_AFTER)
                continue
            return {"state": "unknown", "status": error.code,
                    "reason": f"registry returned {error.code}"}
        except (URLError, TimeoutError, OSError) as error:
            if attempt == 0:
                time.sleep(_RETRY_AFTER)
                continue
            return {"state": "unknown", "reason": f"{type(error).__name__}"}
        except ValueError as error:
            return {"state": "unknown", "reason": str(error)}
    return {"state": "unknown", "reason": "exhausted retries"}


def plan(dependencies: dict) -> dict:
    """Decide OFFLINE what would be sent. This is what --network-dry-run prints.

    Suppression happens here, before any socket is opened: a private package name that reaches the
    public registry cannot be un-sent."""
    local = {n.lower() for n in dependencies.get("local_names") or []}
    scopes = {s.lower() for s in dependencies.get("private_scopes") or []}
    private_index = dependencies.get("private_index") or ""
    queued, suppressed = [], []
    seen = set()
    for dec in dependencies.get("declarations") or []:
        eco, name = dec.get("ecosystem"), str(dec.get("name") or "")
        key = (eco, name.lower())
        if not name or key in seen:
            continue
        seen.add(key)
        scope = name[1:].split("/")[0].lower() if name.startswith("@") else ""
        if name.lower() in local:
            suppressed.append({**dec, "why": "published by a manifest in this repository (workspace/monorepo)"})
        elif scope and scope in scopes:
            suppressed.append({**dec, "why": "scope is bound to a private registry by repo-local config"})
        elif eco == "pip" and private_index:
            suppressed.append({**dec, "why": f"pip index-url points away from pypi.org ({private_index})"})
        elif not valid_name(eco, name):
            suppressed.append({**dec, "why": "not a valid public registry identifier"})
        else:
            queued.append({"ecosystem": eco, "name": name, "file": dec.get("file")})
    return {"queued": queued[:MAX_NAMES], "suppressed": suppressed,
            "truncated": len(queued) > MAX_NAMES,
            "note": ("only these bare NAMES would be sent to the public registry; suppression is "
                     "applied offline, before any request")}


def check(dependencies: dict, *, workers: int = DEFAULT_WORKERS, rate: float = DEFAULT_RATE,
          prober=None) -> dict:
    """Run the opt-in existence check. Returns results plus an honest completeness signal."""
    scheduled = plan(dependencies)
    queued = scheduled["queued"]
    throttle = _Throttle(rate)
    run_probe = prober or (lambda eco, name: probe(eco, name))
    started = time.monotonic()

    def _one(item):
        throttle.wait()
        return {**item, **run_probe(item["ecosystem"], item["name"])}

    results: list = []
    if queued:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            results = list(pool.map(_one, queued))

    resolved_once = {n.lower() for n in dependencies.get("resolved_once") or []}
    missing, unknown = [], []
    for row in results:
        if row["state"] == "missing":
            # Offline discriminator: a lockfile entry with `resolved` + `integrity` proves the name
            # WAS published, so a 404 now means removed/unpublished — possibly pulled for malware —
            # not hallucinated. Different cause, different fix.
            row["class"] = ("dependency-unpublished-or-removed" if row["name"].lower() in resolved_once
                            else "dependency-nonexistent")
            missing.append(row)
        elif row["state"] == "unknown":
            unknown.append(row)

    return {
        "ran": True,
        "queried": len(results),
        "suppressed": len(scheduled["suppressed"]),
        "suppressed_detail": scheduled["suppressed"][:100],
        "exists": sum(1 for r in results if r["state"] == "exists"),
        "missing": missing,
        "unknown": unknown,
        "truncated": scheduled["truncated"],
        "elapsed_seconds": round(time.monotonic() - started, 2),
        # An UNKNOWN is the tool failing to answer, not the dependency being fine. Surfacing this as
        # incompleteness is what lets the check stay useful without becoming a build-breaking gate.
        "complete": not unknown and not scheduled["truncated"],
        "note": ("a 200 from the registry is NOT evidence the dependency is safe — a squatter who "
                 "has already registered a hallucinated name also returns 200. UNKNOWN results are "
                 "neither clean nor missing and make this check incomplete."),
    }


def findings_from(result: dict) -> list:
    """Ledger-bound findings. MEDIUM severity, LOW confidence, and NOT --fail-on eligible by
    default: a 404 is an observation, not a proof, and the UNKNOWN rate is outside operator
    control."""
    out = []
    for row in result.get("missing") or []:
        removed = row["class"] == "dependency-unpublished-or-removed"
        detail = (f"`{row['name']}` is declared in {row.get('file')} but the {row['ecosystem']} "
                  "registry returns 404. ")
        detail += ("A committed lockfile shows it once resolved with an integrity hash, so it was "
                   "PUBLISHED and has since been removed or unpublished — packages pulled for "
                   "malware look exactly like this. Check why it was removed before restoring it."
                   if removed else
                   "No lockfile shows it ever resolving, which is the AI-hallucinated-dependency "
                   "shape: an install would fail today, and an attacker who registers the name "
                   "owns your build tomorrow. Verify the name against the real package.")
        out.append({"kind": row["class"], "attack_class": row["class"],
                    "severity": "MEDIUM", "confidence": "LOW", "file": row.get("file"),
                    "detail": detail})
    return out

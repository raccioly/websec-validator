"""Proof harness — score the recon engine against a known-vuln-app corpus.

WHAT THIS MEASURES (honest scope): for each deliberately-vulnerable app, does the
recon engine SURFACE the attack surface the app is known to have (right framework,
auth scheme, endpoint count, IDOR/GraphQL presence)? That's a deterministic,
regression-trackable PROXY for the engine's quality — it tells us the briefing
points the agent at the right places.

WHAT IT DOES NOT MEASURE: the full kill-criterion — whether handing the briefing
to a coding agent makes it find the *planted bugs* better than a generic prompt.
That A/B requires driving real agents against running apps; the protocol for it is
in corpus/PROOF-PROTOCOL.md and is a manual step.
"""

from __future__ import annotations

import hashlib
import json
import stat
import os
import re
import tempfile
import subprocess
from pathlib import Path

from . import __version__, recon
from .extractors.base import read_artifact
from .coverage import execution_errors


def _git(args, cwd=None):
    env = dict(os.environ)
    # Inherited repository/config selectors must not redirect operations to the user's checkout.
    for key in list(env):
        if key.startswith("GIT_"):
            env.pop(key)
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")
    return subprocess.run(["git", "-c", "core.hooksPath=" + os.devnull,
                           "-c", "protocol.file.allow=never", "-c", "core.fsmonitor=false", "-c", "init.templateDir=", *args], cwd=cwd, env=env,
                          capture_output=True, text=True, check=True, timeout=240).stdout.strip()


def _clean_tree(dest: Path) -> bool:
    """Compare raw Git blobs, bypassing status/filters/fsmonitor and index assume-unchanged flags."""
    listing = _git(["ls-tree", "-rz", "HEAD"], dest)
    tracked, total = set(), 0
    for item in listing.split("\0"):
        if not item:
            continue
        metadata, name = item.split("\t", 1)
        mode, kind, expected = metadata.split()
        relative = Path(name)
        if (relative.is_absolute() or ".." in relative.parts
                or any(part.casefold() == ".local" for part in relative.parts) or kind != "blob"):
            return False
        tracked.add(name)
        if len(tracked) > 50000:
            return False
        path = dest / relative
        # No parent directory may redirect a tracked blob outside the checkout.
        if any(parent.is_symlink() for parent in path.parents if parent != dest and dest in parent.parents):
            return False
        info = path.lstat()
        if mode == "120000":
            if not stat.S_ISLNK(info.st_mode):
                return False
            content = os.readlink(path).encode()
        else:
            if not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024 * 1024:
                return False
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    return False
                content = stream.read(16 * 1024 * 1024 + 1)
            if len(content) > 16 * 1024 * 1024:
                return False
        total += len(content)
        if total > 512 * 1024 * 1024:
            return False
        actual = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        if actual != expected:
            return False
    observed = set()
    for directory, dirs, files in os.walk(dest, followlinks=False):
        dirs[:] = [d for d in dirs if d != ".git" and d.casefold() != ".local"]
        for name in list(dirs):
            if (Path(directory) / name).is_symlink():
                files.append(name); dirs.remove(name)
        for name in files:
            relative = (Path(directory) / name).relative_to(dest).as_posix()
            if relative == ".git":
                continue
            observed.add(relative)
            if len(observed) > 50000 or relative not in tracked:
                return False
    return observed == tracked


def prepare_repo(entry: dict, workdir: Path) -> dict:
    """Validate immutable remote checkouts; never reset or clean a pre-existing directory."""
    if not isinstance(entry, dict):
        return {"path": None, "revision_status": "invalid-entry", "reason": "Corpus entry must be an object."}
    if entry.get("local_path"):
        if not isinstance(entry["local_path"], (str, Path)):
            return {"path": None, "revision_status": "invalid-local-path", "reason": "local_path must be a path string."}
        path = Path(entry["local_path"])
        return {"path": str(path) if path.is_dir() else None,
                "revision_status": "local-path-unpinned", "actual_revision": None,
                "reason": "Explicit local input; no immutable revision asserted."}
    revision, name, url = entry.get("revision", ""), entry.get("name", ""), entry.get("repo", "")
    if not isinstance(revision, str) or not re.fullmatch(r"[a-fA-F0-9]{40}", revision):
        return {"path": None, "revision_status": "missing-or-invalid-pin", "reason": "Remote corpus requires a full 40-hex revision."}
    if not isinstance(name, str) or not isinstance(url, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", name) or not re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+(?:\.git)?", str(url)):
        return {"path": None, "revision_status": "invalid-source", "reason": "Expected a safe corpus name and public GitHub HTTPS repository."}
    workdir = Path(workdir); workdir.mkdir(parents=True, exist_ok=True)
    dest = workdir / name
    try:
        if dest.exists() or dest.is_symlink():
            if dest.is_symlink() or not dest.is_dir():
                raise ValueError("cache is not a real directory")
            actual = _git(["rev-parse", "HEAD"], dest)
            root = Path(_git(["rev-parse", "--show-toplevel"], dest)).resolve()
            clean = _clean_tree(dest)
            if actual.lower() != revision.lower() or root != dest.resolve() or not clean:
                return {"path": None, "revision_status": "cache-mismatch", "actual_revision": actual,
                        "reason": "Cached revision, root or working tree differs; retained unchanged."}
        else:
            with tempfile.TemporaryDirectory(prefix=".proof-", dir=workdir) as temporary:
                checkout = Path(temporary) / "checkout"
                _git(["init", str(checkout)])
                _git(["fetch", "--depth=1", "--no-tags", url, revision], checkout)
                _git(["checkout", "--detach", "FETCH_HEAD"], checkout)
                actual = _git(["rev-parse", "HEAD"], checkout)
                if actual.lower() != revision.lower():
                    raise ValueError("fetched revision mismatch")
                os.rename(checkout, dest)
        return {"path": str(dest), "revision_status": "pinned-verified", "actual_revision": actual}
    except Exception as error:
        return {"path": None, "revision_status": "unavailable", "reason": type(error).__name__}


def _ensure_repo(entry: dict, workdir: Path) -> Path | None:
    result = prepare_repo(entry, workdir)
    return Path(result["path"]) if result.get("path") else None


def _valid_expectations(entry):
    expected = entry.get("expect", {})
    if not isinstance(expected, dict):
        return False
    for key, value in expected.items():
        if key == "frameworks" and (not isinstance(value, list) or any(not isinstance(x, str) for x in value)):
            return False
        if key == "min_endpoints" and (type(value) is not int or value < 0):
            return False
        if key in {"auth_scheme_contains", "tenant_key"} and not isinstance(value, str):
            return False
        if key in {"idor_present", "graphql_present"} and type(value) is not bool:
            return False
    truth = entry.get("truth", [])
    return isinstance(truth, list) and all(isinstance(row, dict) for row in truth)


def _score(entry: dict, facts: dict) -> dict:
    exp = entry.get("expect", {})
    stack = facts.get("stack", {})
    routes = facts.get("routes", {})
    tgt = routes.get("targeting", {})
    auth = facts.get("auth", {})
    gql = facts.get("graphql", {})
    checks = []

    def chk(name, ok, got):
        checks.append({"check": name, "pass": bool(ok), "got": got})

    if "frameworks" in exp:
        got = stack.get("frameworks", [])
        chk("frameworks ⊇ expected", set(exp["frameworks"]).issubset(set(got)), got)
    if "min_endpoints" in exp:
        chk(f"endpoints ≥ {exp['min_endpoints']}", routes.get("count", 0) >= exp["min_endpoints"], routes.get("count", 0))
    if "auth_scheme_contains" in exp:
        hay = (auth.get("scheme", "") + " " + " ".join(auth.get("schemes_detected", []))).lower()
        chk(f"auth ~ '{exp['auth_scheme_contains']}'", exp["auth_scheme_contains"] in hay, auth.get("scheme"))
    if exp.get("idor_present"):
        n = len(tgt.get("idor_candidates", []))
        chk("IDOR candidates found", n > 0, n)
    if exp.get("graphql_present"):
        chk("GraphQL detected", gql.get("present", False), gql.get("present", False))
    if exp.get("tenant_key"):
        keys = [c["key"] for c in facts.get("tenant", {}).get("candidates", [])]
        chk(f"tenant key '{exp['tenant_key']}'", exp["tenant_key"] in keys, keys[:3])

    if execution_errors(facts.get("coverage", {})):
        for check in checks:
            check.update({"pass": None, "state": "unknown", "reason": "recon execution incomplete"})
        return {"checks": checks, "passed": 0, "total": 0, "unknown_checks": len(checks), "score": None}
    passed = sum(1 for c in checks if c["pass"])
    return {"checks": checks, "passed": passed, "total": len(checks),
            "score": round(passed / len(checks), 2) if checks else None}


def run_proof(corpus_path: Path, workdir: Path) -> dict:
    corpus = json.loads(read_artifact(Path(corpus_path)))
    if not isinstance(corpus, list) or len(corpus) > 100:
        raise ValueError("corpus must contain at most 100 entries")
    workdir.mkdir(parents=True, exist_ok=True)
    results = []
    for entry in corpus:
        if not isinstance(entry, dict) or not _valid_expectations(entry):
            results.append({"name": "invalid-entry", "status": "unavailable", "revision_status": "invalid-entry"})
            continue
        prepared = prepare_repo(entry, workdir)
        repo = Path(prepared["path"]) if prepared.get("path") else None
        if not repo:
            results.append({"name": entry.get("name", "unnamed"), "status": "unavailable", **prepared})
            continue
        try:
            facts = recon.build_facts(repo, __version__)
        except Exception as e:
            results.append({"name": entry.get("name", "unnamed"), "status": "recon-error", "error": type(e).__name__, **prepared})
            continue
        results.append({"name": entry.get("name", "unnamed"), "status": "analyzed", **prepared,
                        "execution_complete": not execution_errors(facts.get("coverage", {})),
                        "execution_errors": execution_errors(facts.get("coverage", {})),
                        "unknown_labels": sum(1 for row in entry.get("truth", []) if not isinstance(row.get("is_real"), bool)),
                        "endpoints": facts.get("routes", {}).get("count"),
                        "vulns": entry.get("vulns", ""), **_score(entry, facts)})

    total_checks = sum(r.get("total", 0) for r in results)
    total_pass = sum(r.get("passed", 0) for r in results)
    return {"results": results,
            "limitation": "Recon coverage checks are not vulnerability precision or exploit confirmation. Unavailable applications are excluded from the numeric check denominator and reported separately.",
            "aggregate": {"apps": len(results),
                          "analyzed_apps": sum(r.get("status") == "analyzed" for r in results),
                          "completed_apps": sum(r.get("status") == "analyzed" and r.get("execution_complete") is True for r in results),
                          "incomplete_apps": sum(r.get("status") == "analyzed" and r.get("execution_complete") is not True for r in results),
                          "unavailable_apps": sum(r.get("status") != "analyzed" for r in results),
                          "unknown_labels": sum(r.get("unknown_labels", 0) for r in results),
                          "failed_checks": total_checks - total_pass,
                          "unknown_checks": sum(r.get("unknown_checks", 0) for r in results),
                          "overall_coverage": round(total_pass / total_checks, 2) if total_checks else None,
                          "checks_passed": total_pass, "checks_total": total_checks}}

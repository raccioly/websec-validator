"""Static scanner registry + detection + execution.

v1 philosophy: the tool does NOT install scanners and does NOT import them. It
detects which are on PATH (or reachable via Docker) and shells out to the ones
that are present, writing each tool's native JSON to the output dir. Missing
tools are reported in the briefing so the agent can offer to install them — we
never hard-fail because a scanner is absent.

Each scanner runs read-only against the filesystem (no network target, no
running app). Anything that needs a live instance (ZAP, Nuclei DAST) is NOT
here — that is the dynamic phase, which v1 leaves to the agent + human.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import posixpath
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import enrichment
from .extractors.base import (SKIP_DIRS, is_doc_or_example, is_example_file, is_placeholder_value,
                             is_test_file, path_in_skip_dir, read_artifact)


@dataclass(frozen=True)
class Scanner:
    key: str
    name: str
    category: str          # sast | sca | secrets | iac | cloud
    binary: str            # what we look for on PATH
    languages: tuple = ()  # () == language-agnostic
    install: str = ""      # one-line install hint for the briefing
    # argv builder: (target, out_file) -> list[str]; None means "detect only" for now
    argv: object = None
    # Lowest version whose CLI matches the argv WE build. Presence on PATH is not compatibility:
    # osv-scanner 2.4.0 was installed, detected, selected, and produced nothing usable because the
    # adapter's invocation was wrong for it — `doctor` reported a green ✓ the whole time (field
    # report #2). A version below this is reported LOUDLY but never blocks: the operator's binary is
    # the operator's business, and we would rather run and report a gap than refuse to run.
    min_version: tuple = ()
    version_note: str = ""


# ONE source of truth for "don't scan here": the walker's SKIP_DIRS (extractors/base.py).
# A subprocess scanner has its OWN traversal and will otherwise re-enter dirs the walker
# skips — e.g. trivy walked `.claude/worktrees/<full-repo-copy>/websec-out/.../gitleaks.json`
# and reported the tool's OWN prior output back as an AWS-key CRITICAL (bug-066). The
# --skip-dirs / --exclude flags below are best-effort perf; `_in_skip_dir` post-filtering in
# normalize_findings is the correctness guarantee (it also covers gitleaks, which has no skip
# flag). Was previously a hand-maintained subset that omitted .claude / .worktrees / .wolf.
EXCLUDE_DIRS = tuple(sorted(SKIP_DIRS))

# Scanners that must NEVER run implicitly, even when installed — each departs from websec's
# offline/read-only posture in a way the user has to consent to per run.
_OPT_IN_SCANNERS = {"trufflehog"}


def _in_skip_dir(path: str, root=None) -> bool:
    """True if `path` is under a SKIP_DIR, measured RELATIVE to the scan `root` when given.

    Delegates to the shared helper. Trivy/Semgrep can emit ABSOLUTE paths, so pass `target`
    (the scanned repo) or a repo living under a skip-named ancestor has its real findings
    dropped as 'contamination' (bug-005/066 recurrence). `root=None` keeps the legacy
    raw-segment behavior for relative inputs (and the existing single-arg unit test)."""
    return path_in_skip_dir(path, root)


def _rel_to(path: str, root=None) -> str:
    """Scanner paths normalized ROOT-RELATIVE (trivy/semgrep emit absolute). Empty string when
    an absolute path can't be made relative — callers treat that as 'no match' (fail open)."""
    p = (path or "").replace("\\", "/")
    if not p:
        return ""
    if root is not None and Path(p).is_absolute():
        try:
            return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
        except (ValueError, OSError):
            return ""
    return p


def _matches_excludes(path: str, excludes, root=None) -> bool:
    """True if `path` matches a user --exclude path/glob, measured RELATIVE to the scan root.

    Same match semantics as RepoContext._excluded (substring OR fnmatch) so recon and the
    scanner post-filter agree on what an exclude means. Gitleaks and checkov have no usable
    path-exclude argv flag, so this post-filter — not the best-effort per-scanner flags —
    is what makes the `--exclude` help-text contract ("recon + scanners") hold for every
    scanner. Fail OPEN (keep the finding) when an absolute path can't be made root-relative."""
    if not excludes:
        return False
    p = _rel_to(path, root)
    if not p:
        return False
    return any(ex in p or fnmatch.fnmatch(p, ex) for ex in excludes if ex)


def _trivy(target: Path, out: Path, excludes=()) -> list:
    # SCA + secrets + IaC misconfig in one pass; pinned by the user's install.
    cmd = ["trivy", "fs", "--scanners", "vuln,secret,misconfig", "--format", "json", "--output", str(out)]
    for d in list(EXCLUDE_DIRS) + list(excludes):
        cmd += ["--skip-dirs", d]
    return cmd + [str(target)]


def _annotate_history_only_secrets(raw: list, target: Path | None) -> int:
    """Flag secrets that exist ONLY in git history — the file is gone from the working tree.

    `gitleaks detect` scans the commit graph across ALL refs (verified: a secret committed on a side
    branch is found from another branch, with the file absent from HEAD and the tree). So a hit whose
    file no longer exists is a HISTORY leak: someone already "fixed" it by deleting the file, which
    does NOT un-leak anything — the blob is still fetchable by anyone with the repo. The only real
    remediation is rotating the credential at the provider. Say so explicitly, because "I deleted it"
    is the single most common false sense of safety with committed secrets."""
    if not target:
        return 0
    n = 0
    for f in raw:
        if f.get("tool") != "gitleaks" or f.get("category") != "secret":
            continue
        # EVERY gitleaks finding is labelled with where it lives, not only the history-only ones.
        # Previously a history-mode hit on a file that still exists carried no marker at all, and a
        # hit on a DELETED file was flagged only by appending prose to the title — so a reader
        # scanning a table of 22 HIGHs had no column that said "these are commit-graph blobs, not
        # your working tree" and had to run `git log` to find out (field report #3). `in_tree` is a
        # first-class field; `scan_mode` already says which surface produced it.
        if f.get("scan_mode") == "dir":
            # A working-tree hit is present in the tree by definition — no filesystem probe needed.
            f.setdefault("in_tree", True)
            continue
        rel = _rel_to(f.get("file", ""), target)
        if not rel:
            continue
        try:
            exists = (Path(target) / rel).exists()
        except OSError:
            continue
        f["in_tree"] = exists
        # guard on the FIELD, not a title substring: several provider notes already mention the word
        # "history" ("…does NOT scrub pushed history"), which silently suppressed this annotation.
        if not exists and not f.get("history_only"):
            f["history_only"] = True
            seen = f.get("commit_short") or f.get("commit") or ""
            where = f" last seen in commit {seen}" if seen else ""
            when = f" ({f['commit_date']})" if f.get("commit_date") else ""
            f["title"] += (f" [HISTORY-ONLY — not in the working tree;{where or ' reachable in git history'}"
                           f"{when}. Someone likely 'fixed' this by deleting the file. The blob is still "
                           "fetchable by anyone with the repo, so it is NOT fixed until the credential "
                           "is rotated.]")
            n += 1
    return n


_GITLEAKS_DIR_SUPPORT: dict = {}


def _gitleaks_has_subcommands(binary: str = "gitleaks") -> bool:
    """Does the installed gitleaks have the 8.19+ `git`/`dir` subcommands?

    `detect` survives only as a DEPRECATED alias and may be removed in a future major, so prefer the
    explicit subcommands where available and fall back to the legacy spelling otherwise. Probed once
    per process; a probe failure means "assume legacy", never "skip the scan"."""
    if binary not in _GITLEAKS_DIR_SUPPORT:
        try:
            probe = subprocess.run([binary, "dir", "--help"], capture_output=True, timeout=20)
            _GITLEAKS_DIR_SUPPORT[binary] = probe.returncode == 0
        except Exception:
            _GITLEAKS_DIR_SUPPORT[binary] = False
    return _GITLEAKS_DIR_SUPPORT[binary]


def _gitleaks(target: Path, out: Path, excludes=()) -> list:
    """HISTORY mode — scans the commit graph across ALL refs. See _annotate_history_only_secrets."""
    common = ["--no-banner", "--report-format", "json", "--report-path", str(out)]
    if _gitleaks_has_subcommands():
        return ["gitleaks", "git", str(target), *common]
    return ["gitleaks", "detect", "--source", str(target), *common]


def _gitleaks_dir(target: Path, out: Path, excludes=()) -> list:
    """WORKING-TREE mode — the uncommitted surface history mode cannot see.

    bug-218: the adapter only ever ran history mode, so a secret written but not yet committed was
    invisible to gitleaks. Verified: an uncommitted .env yields 0 hits in history mode and 2 in
    working-tree mode. That is exactly the state an AI coding agent leaves a tree in mid-task, and
    trivy `fs` was the only working-tree secret path, so a gitleaks-only run reported a false clean."""
    common = ["--no-banner", "--report-format", "json", "--report-path", str(out)]
    if _gitleaks_has_subcommands():
        return ["gitleaks", "dir", str(target), *common]
    return ["gitleaks", "detect", "--source", str(target), "--no-git", *common]


def _trufflehog(target: Path, out: Path, excludes=()) -> list:
    """TruffleHog with LIVE VERIFICATION — the only scanner here that answers "is this key actually
    live?" by calling the provider's API (AWS GetCallerIdentity, GitHub /user, …).

    GATED behind `--verify-secrets` because that is a genuine departure from websec's posture: it
    sends the discovered credential to a THIRD PARTY. Everything else in this tool is offline and
    read-only. Off by default, never implicit — the user opts in per run."""
    return ["trufflehog", "filesystem", str(target), "--json", "--no-update",
            "--results=verified,unknown"]


def _bundled_rules_dir():
    """Path to the shipped Semgrep rules (websec_validator/rules/), or None if unavailable. These
    cover patterns the community registry misses — insecure-default signing secret + error-stack
    disclosure (REF-PENTEST #8/#7). Validated at build; gated on existence so a packaging miss
    never breaks the `--config auto` run."""
    try:
        from importlib import resources
        p = resources.files("websec_validator").joinpath("rules")
        return str(p) if p.is_dir() and any(p.iterdir()) else None
    except Exception:
        return None


def _semgrep(target: Path, out: Path, excludes=()) -> list:
    cmd = ["semgrep", "scan", "--config", "auto", "--json", "--output", str(out)]
    rules = _bundled_rules_dir()
    if rules:
        cmd += ["--config", rules]      # bundled rules run ALONGSIDE auto — the repo-wide multiplier
    for d in list(EXCLUDE_DIRS) + list(excludes):
        cmd += ["--exclude", d]
    return cmd + [str(target)]


def _checkov(target: Path, out: Path, excludes=()) -> list:
    return ["checkov", "-d", str(target), "--compact", "-o", "json",
            "--output-file-path", str(out.parent)]


def _osv(target: Path, out: Path, excludes=()) -> list:
    # OSV-Scanner (Google) — SCA against the OSV.dev advisory DB, with the strongest lockfile
    # ecosystem coverage of any OSS SCA tool. Runs ALONGSIDE Trivy: same-CVE findings collapse via
    # the shared `cve|pkg|CVE` fingerprint (→ tools:[trivy,osv-scanner]), while OSV catches lockfile
    # formats Trivy misses. Like Trivy's DB, it consults an advisory source about YOUR deps — not the
    # target app. Exit 1 = "vulns found" (not an error); the run loop writes output regardless.
    #
    # `--recursive` IS LOAD-BEARING, not a tuning flag. osv-scanner only extracts from the directory
    # it is handed unless told to descend, so on any repo whose lockfiles are not at the root —
    # `backend/package-lock.json`, a monorepo, basically every real project — the walk finished with
    # "0 Extract calls" and exited with `No package sources found`, writing NO output file at all.
    # websec then recorded `osv-scanner: error` and reported zero dependency findings. Reproduced
    # against osv-scanner 2.4.0 with two nested package-lock.json: without -r, 0 packages; with -r,
    # both lockfiles scanned. Dependency CVEs are the highest-frequency true-positive class in any
    # repo, so this silently removed the single most productive scanner in the set (field report #2).
    return ["osv-scanner", "scan", "--recursive", "--format", "json", "--output", str(out), str(target)]


def _gosec(target: Path, out: Path, excludes=()) -> list:
    # Go SAST (securego/gosec) — hardcoded creds, SQLi, weak crypto, path traversal, unsafe TLS:
    # framework-aware Go patterns Semgrep's community rules cover only shallowly. `-no-fail` so a
    # finding isn't a non-zero exit; `<target>/...` recurses the module. Only runs for Go repos.
    cmd = ["gosec", "-fmt", "json", "-out", str(out), "-quiet", "-no-fail"]
    for d in list(EXCLUDE_DIRS) + list(excludes):
        cmd += ["-exclude-dir", d]
    return cmd + [f"{target}/..."]


def _brakeman(target: Path, out: Path, excludes=()) -> list:
    # Rails SAST (presidentbeef/brakeman) — deeply Rails-aware (knows ActiveRecord queries are
    # parameterized, so far fewer FPs than generic SAST on Rails). Native JSON; `--no-exit-on-*` so
    # findings don't fail the process. Only runs for Ruby repos with a Rails layout.
    return ["brakeman", "-f", "json", "-o", str(out), "-q",
            "--no-exit-on-warn", "--no-exit-on-error", str(target)]


def _bandit(target: Path, out: Path, excludes=()) -> list:
    # An explicit empty INI bypasses Bandit's recursive target .bandit discovery.
    # Without -c Bandit uses its built-in defaults, not target YAML/pyproject settings.
    # Installed Bandit/plugins remain operator-trusted external executables.
    cmd = ["bandit", "-r", str(target), "-f", "json", "-o", str(out),
           "--ini", os.devnull, "--ignore-nosec"]
    skipped = list(EXCLUDE_DIRS) + list(excludes)
    if skipped:
        cmd += ["--exclude", ",".join(skipped)]
    return cmd


REGISTRY: tuple = (
    Scanner("trivy", "Trivy", "sca", "trivy",
            install="brew install trivy  # pin by digest in CI", argv=_trivy,
            min_version=(0, 38, 0),
            version_note="`--scanners vuln,secret,misconfig` replaced `--security-checks` in 0.38"),
    Scanner("gitleaks", "Gitleaks", "secrets", "gitleaks",
            install="brew install gitleaks", argv=_gitleaks,
            min_version=(8, 0, 0),
            version_note="8.19+ adds the `git`/`dir` subcommands; older builds fall back to the "
                         "deprecated `detect` spelling automatically"),
    # Same binary, second pass: history mode and working-tree mode are DISJOINT surfaces in gitleaks
    # and neither subsumes the other. Kept as its own registry entry so the existing one-argv-per-
    # scanner runner is untouched; `--scanners gitleaks` selects both (see _expand_only).
    Scanner("gitleaks-dir", "Gitleaks (working tree)", "secrets", "gitleaks",
            install="brew install gitleaks", argv=_gitleaks_dir),
    Scanner("semgrep", "Semgrep/OpenGrep", "sast", "semgrep",
            install="pipx install semgrep  # or opengrep for fully-OSS", argv=_semgrep,
            min_version=(1, 0, 0), version_note="`semgrep scan` + repeatable `--config` need 1.x"),
    Scanner("checkov", "Checkov", "iac", "checkov",
            install="pipx install checkov", argv=_checkov,
            min_version=(2, 0, 0), version_note="the parsed JSON summary shape is 2.x+"),
    Scanner("bandit", "Bandit", "sast", "bandit", languages=("python",),
            install="pipx install bandit", argv=_bandit,
            min_version=(1, 7, 0), version_note="`--ignore-nosec` + `metrics._totals` need 1.7+"),
    Scanner("gosec", "gosec", "sast", "gosec", languages=("go",),
            install="brew install gosec  # Go SAST", argv=_gosec,
            min_version=(2, 0, 0), version_note="`-no-fail` and JSON `Issues[]` are 2.x"),
    Scanner("brakeman", "Brakeman", "sast", "brakeman", languages=("ruby",),
            install="gem install brakeman  # Rails SAST", argv=_brakeman,
            min_version=(4, 0, 0), version_note="`--no-exit-on-warn/--no-exit-on-error` need 4.x"),
    Scanner("osv-scanner", "OSV-Scanner", "sca", "osv-scanner",
            install="brew install osv-scanner", argv=_osv,
            min_version=(2, 0, 0),
            version_note="the `scan` subcommand is 2.x; 1.x takes the directory as a bare "
                         "argument and will reject this invocation"),
    # OPT-IN ONLY (--verify-secrets): verification calls third-party APIs with the found credential.
    # run_available() skips this unless explicitly enabled, even when the binary is installed.
    Scanner("trufflehog", "TruffleHog (live verification)", "secrets", "trufflehog",
            install="brew install trufflehog  # opt-in: websec run … --verify-secrets", argv=_trufflehog),
    Scanner("prowler", "Prowler", "cloud", "prowler",
            install="pipx install prowler  # needs AWS creds"),
)


_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
_VERSION_CACHE: dict = {}


def probe_version(binary: str, timeout: int = 15) -> str | None:
    """`<binary> --version` → the first dotted version in its output, or None.

    Every scanner in the registry prints a version in a slightly different shape ("osv-scanner
    version: 2.4.0", "gitleaks version 8.30.1", "Version: 0.72.0", bare "1.177.0"), so we take the
    first dotted number rather than teaching this nine formats. Cached per process. NEVER raises:
    a version probe that fails must degrade to "unknown", never break `doctor` or a scan."""
    if binary in _VERSION_CACHE:
        return _VERSION_CACHE[binary]
    version = None
    try:
        proc = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=timeout)
        m = _VERSION_RE.search((proc.stdout or "") + "\n" + (proc.stderr or ""))
        if m:
            version = ".".join(part for part in m.groups() if part is not None)
    except Exception:
        version = None
    _VERSION_CACHE[binary] = version
    return version


def _parse_version(text: str | None) -> tuple:
    m = _VERSION_RE.search(text or "")
    return tuple(int(part) for part in m.groups() if part is not None) if m else ()


def check_version(scanner: Scanner) -> dict:
    """Is the INSTALLED build one this adapter's argv actually works with?

    `doctor` used to answer only "is the binary on PATH", which is a different and much weaker
    question. An incompatible-but-present scanner is the worst state to be in: it is selected, it
    runs, it fails in its own idiom, and its silence is indistinguishable from a clean result.
    Returns {version, ok, status, note}; status is one of ok | too_old | unknown | not_installed."""
    if not shutil.which(scanner.binary):
        return {"version": None, "ok": False, "status": "not_installed", "note": ""}
    version = probe_version(scanner.binary)
    if not scanner.min_version:
        return {"version": version, "ok": True,
                "status": "ok" if version else "unknown", "note": ""}
    parsed = _parse_version(version)
    if not parsed:
        return {"version": version, "ok": True, "status": "unknown",
                "note": (f"could not read a version; websec's invocation expects "
                         f">= {'.'.join(map(str, scanner.min_version))}"
                         + (f" — {scanner.version_note}" if scanner.version_note else ""))}
    # Compare on the components the minimum actually specifies, so a "2.4" reading satisfies
    # a (2, 0, 0) minimum instead of being judged against a missing patch component.
    want = scanner.min_version[:len(parsed)] or scanner.min_version
    got = parsed[:len(want)]
    if got < want:
        return {"version": version, "ok": False, "status": "too_old",
                "note": (f"websec builds an invocation that needs "
                         f">= {'.'.join(map(str, scanner.min_version))}, but {version} is installed"
                         + (f" — {scanner.version_note}" if scanner.version_note else ""))}
    return {"version": version, "ok": True, "status": "ok", "note": ""}


def detect(stack_languages: list | None = None, check_versions: bool = True) -> dict:
    """Return {'available': [...], 'missing': [...]} for the relevant scanners.

    A language-specific scanner (e.g. Bandit/python) is only considered relevant
    when that language is present in the stack.
    """
    langs = set(stack_languages or [])
    available, missing = [], []
    for s in REGISTRY:
        if s.languages and not (set(s.languages) & langs):
            continue  # not relevant to this repo's stack
        # Same binary as `gitleaks`, run as a second pass. Listing it again would imply a separate
        # tool the operator has to install. Presence/absence is already covered by the entry above.
        if s.key == "gitleaks-dir":
            continue
        entry = {"key": s.key, "name": s.name, "category": s.category,
                 "runnable": s.argv is not None}
        if shutil.which(s.binary):
            if check_versions:
                entry.update(check_version(s))
            available.append(entry)
        else:
            missing.append({**entry, "install": s.install})
    # A present-but-incompatible scanner is NOT the same as a missing one and must not hide in the
    # green ✓ list — it is the failure mode that reads as "scanned clean" (field report #2).
    incompatible = [e for e in available if e.get("status") == "too_old"]
    return {"available": available, "missing": missing, "incompatible": incompatible}


def run_available(target: Path, outdir: Path, stack_languages: list | None = None,
                  timeout: int = 600, excludes: list | None = None, only: list | None = None,
                  verify_secrets: bool = False) -> list:
    """Execute every available, runnable static scanner. Returns per-scanner status.

    `excludes`: extra paths/dirs to skip (--exclude). `only`: run just these scanner keys.
    Raw JSON lands in outdir/scanners/<key>.json. We capture status only here;
    cross-tool normalization + de-duplication is a separate (next) step.
    """
    langs = set(stack_languages or [])
    excludes = excludes or []
    # bug-218: gitleaks is ONE tool to the operator but two registry entries. Selecting it by name
    # must run both passes, or `--scanners gitleaks` silently keeps the old history-only blind spot.
    if only:
        only = list(only) + (["gitleaks-dir"] if "gitleaks" in only else [])
    only = set(only) if only else None
    scan_dir = outdir / "scanners"
    scan_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for s in REGISTRY:
        if s.argv is None:
            continue  # detect-only for now
        if only is not None and s.key not in only:
            continue
        if s.languages and not (set(s.languages) & langs):
            continue
        # OPT-IN scanners stay off unless explicitly enabled — trufflehog's verification egresses the
        # discovered credential to a third party, which must never happen implicitly.
        if s.key in _OPT_IN_SCANNERS and not (verify_secrets and s.key == "trufflehog"):
            continue
        if not shutil.which(s.binary):
            continue
        out_file = scan_dir / f"{s.key}.json"
        try:
            proc = subprocess.run(s.argv(target, out_file, excludes), capture_output=True,
                                  text=True, timeout=timeout)
            # Checkov ignores the filename and writes `results_json.json` into the dir passed to
            # `--output-file-path` — so the recorded <key>.json never existed and 100% of its findings
            # were silently dropped. Normalize the produced file to the expected path.
            # trufflehog streams JSON-lines to STDOUT and writes no report file — persist it so the
            # normal parse path works (same shape of special-case as checkov's renamed output).
            if s.key == "trufflehog" and not out_file.exists():
                out_file.write_text(proc.stdout or "")
            if s.key == "checkov" and not out_file.exists():
                produced = scan_dir / "results_json.json"
                if produced.exists():
                    produced.replace(out_file)
            results.append({"key": s.key, "name": s.name, "category": s.category,
                            "exit_code": proc.returncode, "output": str(out_file),
                            **({"configuration_policy": "built-in defaults; target .bandit/YAML/pyproject ignored",
                                "suppression_policy": "inline nosec ignored"} if s.key == "bandit" else {}),
                            "findings": _count_findings(s.key, out_file)})
        except subprocess.TimeoutExpired:
            results.append({"key": s.key, "name": s.name, "status": "timeout"})
        except Exception as e:  # never let one scanner sink the run
            results.append({"key": s.key, "name": s.name, "status": f"error: {e}"})
    return results


_SBOM_FORMATS = {"cyclonedx": ("cyclonedx", "sbom.cdx.json"), "spdx": ("spdx-json", "sbom.spdx.json")}


def write_sbom(target: Path, outdir: Path, fmt: str = "cyclonedx",
               excludes: list | None = None, timeout: int = 300) -> dict:
    """Emit a Software Bill of Materials via Trivy (offline, deterministic, read-only).

    CycloneDX/SPDX SBOM is table-stakes for CI/compliance (SLSA, EO 14028) and the substrate a
    downstream scanner can rescan without re-walking the tree. Trivy is already the SCA scanner, so
    this is one more invocation of a tool we already require — no new dependency. Returns a status
    dict; never raises (a missing trivy just yields {'available': False})."""
    tfmt, fname = _SBOM_FORMATS.get(fmt, _SBOM_FORMATS["cyclonedx"])
    if not shutil.which("trivy"):
        return {"available": False, "reason": "trivy not on PATH (brew install trivy)"}
    out_file = outdir / fname
    cmd = ["trivy", "fs", "--format", tfmt, "--output", str(out_file)]
    for d in list(EXCLUDE_DIRS) + list(excludes or []):
        cmd += ["--skip-dirs", d]
    cmd.append(str(target))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if out_file.exists() and out_file.stat().st_size > 0:
            comps = 0
            try:
                data = json.loads(read_artifact(out_file))
                field = "components" if fmt == "cyclonedx" else "packages"
                if not isinstance(data, dict) or not isinstance(data.get(field), list):
                    raise ValueError("SBOM does not contain the requested component inventory")
                comps = len(data.get("components") or data.get("packages") or [])
            except (OSError, ValueError) as error:
                return {"available": False, "reason": f"invalid SBOM: {error}"}
            return {"available": True, "format": fmt, "path": fname, "components": comps}
        return {"available": False, "reason": f"trivy exit {proc.returncode}: {(proc.stderr or '')[:120]}"}
    except subprocess.TimeoutExpired:
        return {"available": False, "reason": "trivy SBOM timed out"}
    except Exception as e:
        return {"available": False, "reason": f"{type(e).__name__}: {e}"}


def _count_findings(key: str, out_file: Path) -> int:
    """Best-effort finding count from a scanner's native JSON (for the summary)."""
    if not out_file.exists():
        return 0
    # trufflehog emits JSON-LINES, not a JSON document — count before the whole-file parse below,
    # which would raise and silently report 0.
    if key == "trufflehog":
        return sum(1 for ln in read_artifact(out_file).splitlines() if ln.strip().startswith("{"))
    try:
        data = json.loads(read_artifact(out_file))
    except Exception:
        return 0
    if key == "trivy":
        return sum(len(r.get("Vulnerabilities", []) or []) +
                   len(r.get("Secrets", []) or []) +
                   len(r.get("Misconfigurations", []) or [])
                   for r in (data.get("Results") or []))
    if key == "gitleaks":
        return len(data) if isinstance(data, list) else 0
    if key in {"semgrep", "bandit"}:
        return len(data.get("results", []) or [])
    if key == "checkov":
        return sum(len((b.get("results") or {}).get("failed_checks", []) or [])
                   for b in (data if isinstance(data, list) else [data]) if isinstance(b, dict))
    if key == "osv-scanner":
        return sum(len(p.get("groups", []) or [])
                   for r in (data.get("results") or []) for p in (r.get("packages") or []))
    if key == "gosec":
        return len(data.get("Issues", []) or [])
    if key == "brakeman":
        return len(data.get("warnings", []) or [])
    return 0


# ---- cross-tool normalization + de-duplication -------------------------------------------
# The thing no OSS orchestrator does: one ranked finding even when two scanners
# report the same CVE / secret / misconfig. Fingerprints are scheme-shared across
# tools so e.g. a secret found by both Gitleaks and Trivy collapses to one row.

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": 1}


def _sev(s: str) -> str:
    s = (s or "").upper()
    return s if s in SEV_ORDER else "MEDIUM"


def _aws_secret_tier(secret: str, match: str):
    """Tier an AWS-credential hit by key type / context → (severity, note) or (None, None).

    Not every 'AWS key' is a live, long-lived breach risk: presigned-URL creds and ASIA
    short-lived STS tokens are usually scoped + expired. Only AKIA long-lived keys are HIGH.
    """
    blob = f"{secret or ''} {match or ''}"
    if re.search(r"X-Amz-(Signature|Credential|Expires|Security-Token)=", blob, re.I):
        return "LOW", "presigned-URL credential (temporary + scoped, usually already expired)"
    if re.search(r"\bASIA[0-9A-Z]{16}\b", blob):
        return "MEDIUM", "temporary STS token (ASIA — short-lived, likely expired)"
    if re.search(r"\b(?:AROA|AIDA|AGPA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b", blob):
        return "LOW", "AWS resource/role identifier (not a usable secret)"
    if re.search(r"\bAKIA[0-9A-Z]{16}\b", blob):
        return "HIGH", "long-lived access key (AKIA)"
    return None, None


# P4: name a secret by its provider PREFIX (so triage isn't "generic, verify") and tier by whether
# the prefix denotes a real SECRET. A NAMED live-provider secret is HIGH, not MEDIUM-generic — and the
# remediation ORDER matters: rotate FIRST (gitignoring or deleting a committed key does NOT scrub it
# from pushed history — anyone who cloned still has it). Prefix-keyed → cloud-agnostic.
_ROTATE = " — ROTATE at the provider FIRST; deleting/gitignoring a committed key does NOT scrub pushed history (use BFG/git-filter-repo after rotating)."
_PROVIDER_PREFIXES = [
    (re.compile(r"\bwhsec_[A-Za-z0-9]{16,}"), "HIGH", "Stripe/svix webhook signing secret (whsec_)"),
    (re.compile(r"\bsk_live_[A-Za-z0-9]{16,}"), "HIGH", "Stripe LIVE secret key (sk_live_)"),
    (re.compile(r"\brk_live_[A-Za-z0-9]{16,}"), "HIGH", "Stripe restricted LIVE key (rk_live_)"),
    (re.compile(r"\bsk_test_[A-Za-z0-9]{16,}"), "LOW", "Stripe TEST secret key (sk_test_ — sandbox)"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}"), "HIGH", "GitHub token (gh*_/github_pat_)"),
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}"), "HIGH", "GitLab personal access token (glpat-)"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "HIGH", "Slack token (xox*-)"),
    (re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"), "HIGH", "SendGrid API key (SG.)"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "HIGH", "npm access token (npm_)"),
    (re.compile(r"\bdop_v1_[a-f0-9]{64}\b"), "HIGH", "DigitalOcean token (dop_v1_)"),
    (re.compile(r"\bshpat_[a-fA-F0-9]{32}\b"), "HIGH", "Shopify access token (shpat_)"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "MEDIUM", "Google API key (AIza — often domain/API-restricted; verify scope)"),
    (re.compile(r"\bpk_live_[A-Za-z0-9]{16,}"), "LOW", "publishable key (pk_live_ — usually PUBLIC by design; verify with the provider)"),
]


def _provider_secret_tier(blob: str):
    for rx, sev, note in _PROVIDER_PREFIXES:
        if rx.search(blob or ""):
            return sev, note + (_ROTATE if sev in ("HIGH", "MEDIUM") else "")
    return None, None


# gitleaks/trivy "generic" + entropy/keyword rules are high-recall, low-precision: they fire on
# public keys, wallet addresses, hashes, env-var refs and test fixtures about as often as real
# credentials. Tier those to MEDIUM + a verify note (NEVER hide them) so the HIGH secret tier
# stays trustworthy in a shareable report; specific-format rules (AKIA, private-key, GitHub/
# Stripe/Slack/JWT, etc.) keep HIGH. (bug-072 — dogfooding a wallet app surfaced ~20 HIGH
# generic-api-key FPs in committed source.)
_GENERIC_SECRET_RULES = {"generic-api-key", "generic-api-key-1", "generic", "api-key",
                         "secret-keyword", "high-entropy", "high-entropy-string", "entropy"}
_GENERIC_NOTE = ("generic/entropy match — verify it's a live credential "
                 "(often a public key, address, hash or env-ref, not a secret)")


def _generic_secret(rule: str) -> bool:
    r = (rule or "").lower()
    return r in _GENERIC_SECRET_RULES or "generic" in r or "entropy" in r


# Secrets matched in DOCUMENTATION / EXAMPLE files are overwhelmingly placeholders, not live
# credentials — e.g. `curl -H "Authorization: Bearer <token>"` in a README/API doc, or a
# value in `.env.example`. Tier those down + a verify note (still visible — a real key CAN be
# pasted into docs by mistake). Dogfooding flagged 4 HIGH curl-auth-header FPs across an API's
# README + docs/*.md (bug below).
#
# The marker tables now live in extractors/base.py so the recon EXTRACTORS share one definition
# with this pipeline. They had drifted: `client_exposure`'s AppSync `da2-` detector had no
# doc/example tier at all, so a placeholder in `.env.example` stayed HIGH while the very same
# file's gitleaks hits were LOW (field report #5).
_DOC_NOTE = "in a documentation/example file — almost always a placeholder, verify before treating as real"
# `.env.example` / `config.sample.yml` are a STRONGER signal than a README: the naming convention
# exists precisely to say "these values are fake, copy me and fill them in". Its own tier + note.
_EXAMPLE_NOTE = ("in a *.example/*.sample template file — this file exists to hold placeholder values, "
                 "so a match here is a placeholder unless the value itself looks real")
_PLACEHOLDER_NOTE = ("the matched VALUE is self-evidently a placeholder (fill-me-in shape), not a "
                     "credential")


def _is_doc_or_example(path: str) -> bool:
    """Thin alias kept for the existing call sites + unit tests; the definition is shared."""
    return is_doc_or_example(path)


def _placeholder_tier(path: str, value: str = "", provider_identified: bool = False) -> tuple:
    """(severity, note) for a secret match that is a placeholder by FILE or by VALUE — else (None, "").

    Three tiers, weakest to strongest evidence that this is not a credential:
      * documentation file            → LOW  (a README can still hold a real pasted key)
      * *.example/*.sample template   → LOW  (the file's whole purpose is fake values)
      * placeholder-shaped VALUE      → INFO (`da2-xxxxxxxx…`, `your-api-key`, `<TOKEN>`)
    A placeholder VALUE is decisive wherever it appears, so it wins over the file tiers. Nothing is
    ever DROPPED — a real key pasted into `.env.example` is precisely the mistake worth catching.

    `provider_identified` DISABLES the value check, and that guard is load-bearing. A provider tier
    fires on a structural PREFIX — `sk_live_`, `whsec_`, `AKIA` — which is issued by the provider and
    is itself the evidence. The body after that prefix is opaque, so a low-entropy body proves
    nothing: `sk_live_aaaaaaaaaaaaaaaaaaaa` matches "a run of identical characters" and is still a
    Stripe LIVE key. Demoting it to INFO would have been a false NEGATIVE on the single highest-value
    secret class this tool detects — caught by test_named_provider_key_is_high_not_generic_via_gitleaks.
    The FILE tiers still apply: a `sk_live_` in `.env.example` is very likely fake, just not INFO-fake."""
    if not provider_identified and is_placeholder_value(value):
        return "INFO", _PLACEHOLDER_NOTE
    if is_example_file(path):
        return "LOW", _EXAMPLE_NOTE
    if is_doc_or_example(path):
        return "LOW", _DOC_NOTE
    return None, ""


def _norm_trivy(data: dict) -> list:
    out = []
    for res in (data.get("Results") or []):
        tgt = res.get("Target", "")
        eco = (res.get("Type") or "").lower()   # npm | pip | gomod | cargo | ... — drives reachability
        for v in (res.get("Vulnerabilities") or []):
            out.append({"tool": "trivy", "category": "sca", "severity": _sev(v.get("Severity")),
                        "key": v.get("VulnerabilityID", ""), "file": tgt, "line": 0,
                        # clean structured fields so the reachability + EPSS/KEV enrichers don't have to
                        # re-parse the title (which stays human-readable for the ledger/briefing).
                        "pkg": v.get("PkgName", ""), "cve": v.get("VulnerabilityID", ""),
                        "installed": v.get("InstalledVersion", ""), "fixed": v.get("FixedVersion", ""),
                        "ecosystem": eco,
                        "title": f"{v.get('PkgName')} {v.get('InstalledVersion')} → {v.get('FixedVersion', '(no fix)')}",
                        "fingerprint": f"cve|{v.get('PkgName')}|{v.get('VulnerabilityID')}"})
        for s in (res.get("Secrets") or []):
            rid = s.get("RuleID", "")
            sev, note = _aws_secret_tier(s.get("Match", ""), s.get("Code", "") or "")
            if not sev:
                sev, note = _provider_secret_tier(f"{s.get('Match','')} {s.get('Code','') or ''}")
            if not sev and _generic_secret(rid):
                sev, note = "MEDIUM", _GENERIC_NOTE
            ph_sev, ph_note = _placeholder_tier(tgt, s.get("Match", "") or s.get("Secret", ""),
                                                provider_identified=bool(sev))
            if ph_sev and not (sev and ph_sev == "INFO"):
                sev, note = ph_sev, (note + "; " if note else "") + ph_note
            title = f"secret: {s.get('Title') or rid}" + (f" — {note}" if note else "")
            out.append({"tool": "trivy", "category": "secret", "severity": sev or _sev(s.get("Severity") or "HIGH"),
                        "key": rid, "file": tgt, "line": s.get("StartLine", 0),
                        # include the line: two DISTINCT secrets matched by the same rule in one file
                        # must not collapse to one row (hiding the second is the worst FN for a secret
                        # scanner). Safe direction — at worst a rare cross-tool duplicate, never a hidden secret.
                        "title": title, "fingerprint": f"secret|{tgt}|{rid}|{s.get('StartLine', 0)}"})
        for m in (res.get("Misconfigurations") or []):
            out.append({"tool": "trivy", "category": "iac", "severity": _sev(m.get("Severity")),
                        "key": m.get("ID", ""), "file": tgt, "line": 0, "title": (m.get("Title") or "")[:90],
                        "fingerprint": f"iac|{tgt}|{m.get('ID')}"})
    return out


# OSV ecosystem label → the `ecosystem` token the reachability enricher understands.
_OSV_ECO = {"pypi": "pip", "npm": "npm", "go": "gomod", "crates.io": "cargo",
            "rubygems": "gem", "packagist": "composer", "maven": "maven", "nuget": "nuget"}


def _cvss_band(score) -> str:
    """CVSS base score → severity band (osv-scanner reports groups[].max_severity as a number)."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "MEDIUM"           # no score → don't over- or under-claim; MEDIUM like _sev's default
    return ("CRITICAL" if s >= 9.0 else "HIGH" if s >= 7.0
            else "MEDIUM" if s >= 4.0 else "LOW" if s > 0 else "UNKNOWN")


def _norm_osv(data: dict) -> list:
    """OSV-Scanner JSON → SCA findings. One finding per vuln GROUP (a group aliases the OSV/GHSA/CVE
    ids of the same underlying vuln). Fingerprint mirrors Trivy's `cve|pkg|CVE` so the same CVE from
    both engines collapses to one row with tools:[trivy,osv-scanner]; OSV-only lockfile hits survive."""
    out = []
    for r in (data.get("results") or []):
        for p in (r.get("packages") or []):
            pkgobj = p.get("package", {}) or {}
            name = pkgobj.get("name", "")
            version = pkgobj.get("version", "")
            eco = _OSV_ECO.get(str(pkgobj.get("ecosystem", "")).lower(), "")
            # map each vuln id → its human summary for a readable title (best-effort)
            for g in (p.get("groups") or []):
                ids = g.get("ids", []) or []
                aliases = g.get("aliases", ids) or ids
                cve = next((a for a in aliases if str(a).upper().startswith("CVE-")), None) or (ids[0] if ids else "")
                sev = _cvss_band(g.get("max_severity"))
                out.append({"tool": "osv-scanner", "category": "sca", "severity": sev,
                            "key": cve, "file": r.get("source", {}).get("path", ""), "line": 0,
                            "pkg": name, "cve": cve, "installed": version, "fixed": "", "ecosystem": eco,
                            "advisory_aliases": sorted({a for a in aliases if isinstance(a, str) and a}),
                            "title": f"{name} {version} — {cve} ({', '.join(i for i in ids if i != cve)[:60]})".rstrip(" ()"),
                            "fingerprint": f"cve|{name}|{cve}"})
    return out


def _norm_trufflehog(data) -> list:
    """TruffleHog JSON-LINES → secret findings, carrying the VERIFICATION verdict.

    `Verified: true` means the tool authenticated with the credential against the provider — that is
    the single most actionable finding a security report can contain, so it outranks every heuristic
    secret hit. Unverified/unknown stays MEDIUM (the detector matched but liveness is unproven)."""
    out = []
    rows = data if isinstance(data, list) else []
    for x in rows:
        if not isinstance(x, dict):
            continue
        det = x.get("DetectorName") or x.get("DetectorType") or "secret"
        meta = ((x.get("SourceMetadata") or {}).get("Data") or {})
        fs = meta.get("Filesystem") or meta.get("Git") or {}
        f = fs.get("file") or fs.get("path") or ""
        line = fs.get("line") or 0
        verified = bool(x.get("Verified"))
        sev = "CRITICAL" if verified else "MEDIUM"
        note = ("★ VERIFIED LIVE — TruffleHog authenticated with this credential against the provider. "
                "Rotate it NOW; it is not a maybe."
                if verified else
                "detector matched but liveness UNVERIFIED (provider unreachable or key inactive)")
        out.append({"tool": "trufflehog", "category": "secret", "severity": sev,
                    "key": str(det), "file": f, "line": line, "verified": verified,
                    "title": f"secret: {det} — {note}",
                    "fingerprint": f"secret|{f}|{det}|{line}"})
    return out


def _norm_gitleaks(data) -> list:
    rows = data if isinstance(data, list) else (data.get("findings") or [])
    out = []
    for x in rows:
        f, rule = x.get("File", ""), x.get("RuleID", "")
        sev, note = _aws_secret_tier(x.get("Secret", ""), x.get("Match", ""))
        if not sev:
            sev, note = _provider_secret_tier(f"{x.get('Secret','')} {x.get('Match','')}")
        if not sev and _generic_secret(rule):
            sev, note = "MEDIUM", _GENERIC_NOTE
        # `sev` is set above ONLY by _aws_secret_tier / _provider_secret_tier — i.e. a rule that
        # identified a specific provider. Generic/entropy matches leave it None.
        ph_sev, ph_note = _placeholder_tier(f, x.get("Secret", ""), provider_identified=bool(sev))
        if ph_sev and not (sev and ph_sev == "INFO"):
            sev, note = ph_sev, (note + "; " if note else "") + ph_note
        title = f"secret: {(x.get('Description') or rule)[:80]}" + (f" — {note}" if note else "")
        # Commit provenance, straight from gitleaks' own record — no `git log` needed. In history
        # ("git") mode EVERY hit came out of the commit graph, so the reader must be told that up
        # front; without it 22 HIGHs pointing at files that no longer exist read as live findings
        # and the only way to work out otherwise was to run `git log` by hand (field report #3).
        commit = x.get("Commit") or ""
        out.append({"tool": "gitleaks", "category": "secret", "severity": sev or "HIGH",
                    "key": rule, "file": f, "line": x.get("StartLine", 0),
                    **({"commit": commit, "commit_short": commit[:12]} if commit else {}),
                    **({"commit_date": x["Date"]} if x.get("Date") else {}),
                    **({"commit_author": x["Author"]} if x.get("Author") else {}),
                    "title": title, "fingerprint": f"secret|{f}|{rule}|{x.get('StartLine', 0)}"})
    return out


def _norm_semgrep(data: dict) -> list:
    sevmap = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "INFO"}
    out = []
    for r in (data.get("results") or []):
        rule = r.get("check_id", "")
        path = r.get("path", "")
        line = (r.get("start") or {}).get("line", 0)
        sev = sevmap.get((r.get("extra") or {}).get("severity", "INFO"), "MEDIUM")
        out.append({"tool": "semgrep", "category": "sast", "severity": sev,
                    "rule_id": r.get("check_id", ""),
                    **({"semantic_id": r["match_based_id"]} if isinstance(r.get("match_based_id"), str) and r["match_based_id"] else {}),
                    "key": rule.split(".")[-1], "file": path, "line": line,
                    "title": ((r.get("extra") or {}).get("message") or rule)[:90],
                    "fingerprint": f"sast|{path}|{line}|{rule}|{r.get('match_based_id', '')}"})
    return out


def _norm_gosec(data: dict) -> list:
    """gosec JSON (`{"Issues":[{severity,confidence,cwe:{id},rule_id,details,file,line}]}`) → sast."""
    out = []
    for i in (data.get("Issues") or []):
        f = i.get("file", "")
        try:
            line = int(i.get("line", "0").split("-")[0])   # gosec line is a string, sometimes "12-14"
        except (ValueError, AttributeError):
            line = 0
        rule = i.get("rule_id", "")
        cwe = (i.get("cwe") or {}).get("id", "")
        title = (i.get("details") or rule)[:90] + (f" (CWE-{cwe})" if cwe else "")
        out.append({"tool": "gosec", "category": "sast", "severity": _sev(i.get("severity")),
                    "key": rule, "file": f, "line": line, "title": title,
                    "fingerprint": f"sast|{f}|{line}|{rule}"})
    return out


def _norm_bandit(data: dict) -> list:
    """Bandit AST findings; confidence is independent of issue severity."""
    out, occurrences = [], {}
    for issue in data["results"]:
        path, rule = issue.get("filename", ""), issue.get("test_id", "")
        line = issue.get("line_number", 0)
        confidence = issue.get("issue_confidence")
        confidence = confidence if isinstance(confidence, str) and confidence in {"LOW", "MEDIUM", "HIGH"} else "UNKNOWN"
        cwe = (issue.get("issue_cwe") or {}).get("id")
        cwe = f"CWE-{int(cwe)}" if not isinstance(cwe, bool) and re.fullmatch(r"[1-9][0-9]{0,5}", str(cwe)) else None
        # Native code excerpts have numbered lines. Keep source text as an anchor,
        # excluding shifting line labels; ordinals distinguish identical repeated sites.
        code = str(issue.get("code") or "")
        source = re.sub(r"(?m)^\s*\d+\s+", "", code).strip()
        anchor = hashlib.sha256(source.encode()).hexdigest()[:20] if source else "unavailable"
        key = (path, rule, anchor)
        occurrences[key] = occurrences.get(key, 0) + 1
        out.append({"tool": "bandit", "category": "sast", "severity": _sev(issue.get("issue_severity")),
                    "confidence": confidence,
                    "key": rule, "rule_id": rule, "file": path, "line": line,
                    "cwe": cwe,
                    "semantic_id": f"bandit:{anchor}:{occurrences[key]}",
                    "title": (issue.get("issue_text") or issue.get("test_name") or rule)[:180],
                    "fingerprint": f"sast|{path}|{rule}|{anchor}|{occurrences[key]}"})
    return out


# brakeman uses a 3-level confidence, not a severity — map it (High→HIGH … Weak→LOW).
_BRAKEMAN_SEV = {"High": "HIGH", "Medium": "MEDIUM", "Weak": "LOW"}


def _norm_brakeman(data: dict) -> list:
    """brakeman JSON (`{"warnings":[{warning_type,message,file,line,confidence,check_name,fingerprint}]}`)."""
    out = []
    for w in (data.get("warnings") or []):
        f = w.get("file", "")
        line = w.get("line") or 0
        check = w.get("check_name", "")
        title = f"{w.get('warning_type', 'warning')}: {w.get('message', '')}"[:90]
        out.append({"tool": "brakeman", "category": "sast",
                    **({"semantic_id": w["fingerprint"]} if isinstance(w.get("fingerprint"), str) and w["fingerprint"] else {}),
                    "severity": _BRAKEMAN_SEV.get(w.get("confidence", "Medium"), "MEDIUM"),
                    "key": check, "file": f, "line": line, "title": title,
                    # brakeman ships a stable per-warning fingerprint — reuse it so re-runs dedup.
                    "fingerprint": w.get("fingerprint") or f"sast|{f}|{line}|{check}"})
    return out


def _norm_checkov(data) -> list:
    """Checkov `failed_checks` → normalized IaC findings. Checkov emits either ONE object or a LIST
    of objects (one per framework: terraform / dockerfile / github_actions …), so handle both.
    Severity is frequently null off the paid platform → default MEDIUM. Fingerprint keys on the
    Checkov check id (CKV_*), which is distinct from Trivy's AVD ids, so the two IaC scanners COEXIST
    (more coverage) rather than silently merging — accept some overlap; never drop a real misconfig."""
    out = []
    for block in (data if isinstance(data, list) else [data]):
        if not isinstance(block, dict):
            continue
        for c in ((block.get("results") or {}).get("failed_checks") or []):
            cid = c.get("check_id", "")
            f = c.get("file_path", "") or c.get("repo_file_path", "")
            rng = c.get("file_line_range") or [0]
            out.append({"tool": "checkov", "category": "iac",
                        **({"resource": c["resource"]} if isinstance(c.get("resource"), str) else {}),
                        "severity": _sev(c.get("severity") or "MEDIUM"),
                        "key": cid, "file": f, "line": (rng[0] if rng else 0),
                        "title": (c.get("check_name") or cid)[:90],
                        # include the LINE: a Terraform file with 12 unencrypted buckets is 12
                        # findings, not one. Without it they collapsed and the undercount was
                        # presented as healthy dedup (same reasoning as the secret fingerprint).
                        "fingerprint": f"iac|{f}|{cid}|{c.get('resource', '')}|{rng[0] if rng else 0}"})
    return out


_PARSERS = {"trivy": _norm_trivy, "gitleaks": _norm_gitleaks, "gitleaks-dir": _norm_gitleaks, "semgrep": _norm_semgrep,
            "checkov": _norm_checkov, "osv-scanner": _norm_osv,
            "gosec": _norm_gosec, "brakeman": _norm_brakeman,
            "trufflehog": _norm_trufflehog, "bandit": _norm_bandit}


def _checkov_summary(data) -> bool:
    """The native zero-resource report is a summary, without a results object."""
    return (isinstance(data, dict)
            and all(type(data.get(k)) is int and data[k] >= 0
                    for k in ("passed", "failed", "skipped", "parsing_errors", "resource_count"))
            and isinstance(data.get("checkov_version"), str))


def _valid_report(key: str, data) -> bool:
    """A valid JSON scalar/object is not evidence that a scanner finished."""
    if key in ("gitleaks", "gitleaks-dir"):
        return isinstance(data, list) or (isinstance(data, dict) and isinstance(data.get("findings"), list))
    if key == "checkov":
        rows = data if isinstance(data, list) else [data]
        return bool(rows) and all(
            isinstance(row, dict) and (
                isinstance(row.get("results"), dict)
                and isinstance(row["results"].get("failed_checks"), list)
                or _checkov_summary(row) and all(row[k] == 0 for k in ("passed", "failed", "skipped", "resource_count"))
            ) for row in rows)
    if key == "bandit":
        return (isinstance(data, dict) and isinstance(data.get("results"), list)
                and isinstance(data.get("errors"), list) and isinstance(data.get("metrics"), dict))
    field = {"trivy": "Results", "semgrep": "results", "osv-scanner": "results",
             "gosec": "Issues", "brakeman": "warnings"}.get(key)
    if not isinstance(data, dict) or field is None:
        return False
    # Trivy and gosec use null for empty result collections in some releases.
    return field in data and (isinstance(data[field], list) or (data[field] is None and key in {"trivy", "gosec"}))


def _sca_occurrence(finding: dict, target: Path | None) -> None:
    """Namespace vulnerability identity by affected input, not only advisory name."""
    path = _rel_to(finding.get("file", ""), target) or finding.get("file", "")
    path = posixpath.normpath(path.replace("\\", "/")) if path else ""
    eco = str(finding.get("ecosystem") or "").lower()
    eco = {"python-pkg": "pip", "node-pkg": "npm", "gobinary": "gomod"}.get(eco, eco)
    identity = [path, eco, finding.get("pkg", ""), finding.get("installed", ""), finding.get("cve", "")]
    finding["file"], finding["ecosystem"] = path, eco
    finding["semantic_id"] = "dependency:" + hashlib.sha256(json.dumps(identity).encode()).hexdigest()[:24]
    finding["fingerprint"] = finding["semantic_id"]


def _report_details(key: str, doc) -> dict:
    """Native diagnostics are execution evidence even with a successful exit."""
    details = {"errors": [], "skipped_checks": 0}
    rows = doc if key == "checkov" and isinstance(doc, list) else [doc]
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("errors") or row.get("Errors"):
            details["errors"].append("scanner reported errors")
        if key == "checkov":
            results = row.get("results") or {}
            summary = row.get("summary") or (row if _checkov_summary(row) else {})
            if not isinstance(summary, dict):
                raise ValueError("invalid Checkov summary")
            parse_errors = results.get("parsing_errors", [])
            if not isinstance(parse_errors, list):
                raise ValueError("invalid Checkov parsing_errors")
            count = summary.get("parsing_errors", 0)
            skipped = summary.get("skipped", len(results.get("skipped_checks") or []))
            if any(type(n) is not int or n < 0 for n in (count, skipped)):
                raise ValueError("invalid Checkov diagnostic counts")
            if parse_errors or count:
                details["errors"].append(f"{row.get('check_type', 'checkov')}: {max(len(parse_errors), count)} input parsing errors")
            for count_key, rows_key in (("failed", "failed_checks"), ("passed", "passed_checks"), ("skipped", "skipped_checks")):
                if count_key not in summary or rows_key not in results:
                    continue
                reported = summary[count_key]
                actual = results[rows_key]
                if (type(reported) is not int or reported < 0 or not isinstance(actual, list)
                        or reported != len(actual)):
                    details["errors"].append(f"{row.get('check_type', 'checkov')}: {count_key} summary contradicts result inventory")
            details["skipped_checks"] += skipped
            version = summary.get("checkov_version")
            if isinstance(version, str) and version:
                details["reported_version"] = version
        elif key == "bandit":
            totals = doc["metrics"].get("_totals", {})
            if not isinstance(totals, dict):
                raise ValueError("invalid Bandit metric totals")
            for key_name in ("nosec", "skipped_tests"):
                count = totals.get(key_name, 0)
                if type(count) is not int or count < 0:
                    raise ValueError("invalid Bandit suppression counts")
                details[key_name] = count
            details["skipped_checks"] += details["skipped_tests"]
    return details


def _gitignored(target: Path | None, paths) -> set:
    """Subset of `paths` (relative to `target`) that git IGNORES — local-only files that were
    never committed. A WORKING-TREE secret in such a file (e.g. a gitignored `.env.local`) is
    not a repo leak, so we downgrade it instead of crying CRITICAL (bug-066). Empty set if not
    a git repo / git absent (fail-open). Git-HISTORY findings (gitleaks) are left untouched —
    those ARE committed."""
    paths = sorted({p for p in paths if p})
    if not target or not paths or not shutil.which("git"):
        return set()
    # `git check-ignore` wants paths RELATIVE to the repo and echoes the EXACT input back. Trivy fs
    # typically emits absolute / root-prefixed paths, so a raw query matched nothing and the downgrade
    # was a silent no-op. Normalize to repo-relative for the query, then map the ignored results back
    # to the ORIGINAL strings the caller still holds (so its `file in ignored` test works).
    rel_to_orig: dict = {}
    for p in paths:
        try:
            rel = os.path.relpath(p, str(target)) if os.path.isabs(p) else p
        except Exception:
            rel = p
        rel_to_orig.setdefault(rel, p)
    try:
        proc = subprocess.run(["git", "-C", str(target), "check-ignore", "--stdin"],
                              input="\n".join(rel_to_orig), capture_output=True, text=True, timeout=30)
        ignored_rel = {ln.strip() for ln in proc.stdout.splitlines() if ln.strip()}
        return {rel_to_orig[r] for r in ignored_rel if r in rel_to_orig}
    except Exception:
        return set()
# --- confidence + stable per-instance identity (field report #6) -----------------------------
# The LEDGER carried a confidence for every finding, but the normalized SCANNER findings that feed
# findings.json / the envelope carried one only when the scanner itself supplied it — bandit and
# gosec, i.e. 2 of 11 adapters. Everything else rendered as `?`, which made a ledger described as
# "calibrated" look uncalibrated. Derive it, and — because an unexplained confidence label is just
# as unarguable as a missing one — say WHY in `confidence_basis`.
_CONF_OK = {"HIGH", "MEDIUM", "LOW"}
_GENERIC_CONF_NOTE = "generic/entropy rule — matches any high-entropy string, often a hash or public id"


def _derive_confidence(f: dict, target=None) -> tuple:
    """(confidence, basis) for a normalized scanner finding. Deterministic and explainable.

    Confidence answers "how sure are we this MATCH is what it claims to be", which is independent
    of severity ("how bad if it is"). A CVE matched against a pinned lockfile version is a HIGH-
    confidence observation even at LOW severity; a generic-entropy secret hit is LOW confidence even
    at HIGH severity."""
    native = str(f.get("confidence") or "").upper()
    if native in _CONF_OK:
        return native, f"reported by {f.get('tool', 'the scanner')}"
    if "confidence" in f:
        # The scanner DID report a confidence and we could not parse it. That is a known state with
        # an existing contract: the ledger records native_confidence="UNKNOWN" and routes the finding
        # to LOW rather than inventing a value. Deriving a category default here would have silently
        # overwritten that honesty with a confident-looking MEDIUM.
        return "LOW", "scanner reported an unrecognized confidence value — treated as unknown"
    cat, rel = f.get("category"), _rel_to(f.get("file", ""), target) or f.get("file", "")
    key = str(f.get("key") or f.get("rule_id") or "")
    if cat == "secret":
        if f.get("verified"):
            return "HIGH", "liveness VERIFIED against the provider"
        if f.get("severity") == "INFO" or is_placeholder_value(str(f.get("secret", ""))):
            return "LOW", "value is placeholder-shaped"
        if is_example_file(rel):
            return "LOW", "*.example/*.sample template file — values are fake by convention"
        if is_doc_or_example(rel):
            return "LOW", "documentation/example file"
        if is_test_file(rel):
            return "LOW", "test/fixture file — planted fakes are common"
        if _generic_secret(key):
            return "LOW", _GENERIC_CONF_NOTE
        return "HIGH", "provider-specific rule matched a credential-shaped value"
    if cat == "sca":
        # A lockfile pins an exact version, so the advisory match itself is not in doubt; what is
        # uncertain is whether the vulnerable code is REACHED — which is severity/triage, not
        # identity. Only an unpinned/unresolved occurrence lowers identity confidence.
        if f.get("reachability") == "not-imported":
            return "MEDIUM", "advisory matches the pinned version, but the package is never imported"
        return "HIGH", "advisory matched an exact pinned version from a lockfile"
    if cat == "iac":
        return "MEDIUM", "config-file policy check — deterministic match, deployment context unknown"
    if cat == "sast":
        if is_test_file(rel) or is_doc_or_example(rel):
            return "LOW", "pattern matched in test/doc code, not the running product"
        if f.get("semantic_id"):
            return "MEDIUM", "semantic (dataflow-aware) rule match"
        return "MEDIUM", "syntactic pattern match — confirm the sink is attacker-reachable"
    return "MEDIUM", "no adapter-specific rule; defaulted"


def _instance_id(f: dict, target=None) -> str:
    """Stable, portable, per-INSTANCE identifier.

    `key` is a RULE id (`generic-api-key`) — it names the detector, not the occurrence, so it cannot
    address one finding for `websec feedback` or a baseline entry (field report #6). `fingerprint`
    does identify the instance, but trivy and semgrep emit ABSOLUTE paths, so a fingerprint minted on
    one machine does not match the same finding on another. This hashes the ROOT-RELATIVE identity,
    so it is the same id for the same finding in CI, on a laptop, and after the repo is moved.
    Emitted ALONGSIDE `fingerprint`, never replacing it — existing baselines keep matching."""
    rel = _rel_to(f.get("file", ""), target) or f.get("file", "")
    parts = [str(f.get("category") or ""), rel, str(f.get("key") or f.get("rule_id") or ""),
             str(f.get("line") or 0), str(f.get("cve") or f.get("pkg") or "")]
    return "wv1_" + hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


# Rules that are SECRET DETECTION regardless of which adapter reported them. Semgrep ships a pile
# of these ("AWS AppSync GraphQL Key detected", "hardcoded-api-key", …) and they arrive as category
# `sast`, so the per-parser secret tiering in _norm_gitleaks/_norm_trivy never saw them: a `da2-`
# placeholder in `.env.example` was demoted to INFO by one detector and reported HIGH by another,
# in the same run, on the same line (field report #5). Tiering belongs to the FINDING, not to the
# adapter that happened to produce it.
_SECRETISH_RULE = re.compile(
    r"secret|credential|api[_-]?key|token|password|passwd|private[_-]?key|appsync|"
    r"access[_-]?key|auth[_-]?header|hardcoded", re.I)


def _is_secret_like(f: dict) -> bool:
    if f.get("category") == "secret":
        return True
    return bool(_SECRETISH_RULE.search(
        f"{f.get('rule_id') or ''} {f.get('key') or ''} {f.get('title') or ''}"))


def _tier_placeholder_matches(raw: list, target) -> int:
    """Apply the doc/example/placeholder tier to EVERY secret-like finding, whatever produced it.

    Idempotent: a parser that already tiered its own finding is left alone. Never drops anything —
    the finding stays in the ledger, in SARIF and in the report, with the reason attached."""
    n = 0
    for f in raw:
        if not _is_secret_like(f) or f.get("placeholder_tier"):
            continue
        rel = _rel_to(f.get("file", ""), target) or f.get("file", "")
        # A provider-identified credential is never demoted on value shape — see _placeholder_tier.
        value = str(f.get("secret") or f.get("match") or "")
        sev, note = _placeholder_tier(rel, value)
        if not sev:
            continue
        if SEV_ORDER.get(f.get("severity"), 0) <= SEV_ORDER.get(sev, 0):
            continue                      # already at or below the tier — nothing to do
        f["severity"] = sev
        f["placeholder_tier"] = "example-file" if is_example_file(rel) else "doc-file"
        if note not in f.get("title", ""):
            f["title"] += f" — {note}"
        n += 1
    return n


def normalize_findings(scan_results: list, outdir: Path, target: Path | None = None,
                       excludes: list | None = None, include_fixtures: bool = False) -> dict:
    """Merge every scanner's native JSON into one de-duplicated, severity-ranked
    findings.json. Returns a summary (raw vs deduped, by severity/category).

    `target` (the scanned repo) enables two bug-066 hygiene passes: drop findings under a
    SKIP_DIR (a scanner re-entered a dir the walker skips), and downgrade working-tree secrets
    that live in gitignored (never-committed) files.

    `excludes` (user --exclude paths/globs) is enforced HERE, not only in the per-scanner
    argv flags: gitleaks/checkov ignore those flags entirely, so without this post-filter a
    `--exclude 'tests/**'` still surfaced fixture secrets as HIGH (DocGuard field report)."""
    raw = []
    parse_failed: list = []
    _parse_attempted: list = []
    report_versions: dict = {}
    report_details: dict = {}
    # A scanner that crashed, timed out, or wrote truncated JSON yields zero findings — which the CLI
    # and briefing render identically to "scanned clean". Track it so silence can be attributed.
    crashed = [r.get("key") for r in scan_results
               if r.get("status") or (r.get("exit_code") not in (None, 0, 1))]
    for r in scan_results:
        out, key = r.get("output"), r.get("key")
        parser = _PARSERS.get(key)
        if not (out and parser and Path(out).exists()):
            if not r.get("status"):
                parse_failed.append(key)
            continue
        try:
            output_path = Path(out).absolute()
            text = read_artifact(output_path)
            _parse_attempted.append(key)
            if key == "trufflehog":          # JSON-LINES, one finding per line
                doc = []
                for ln in text.splitlines():
                    ln = ln.strip()
                    if ln.startswith("{"):
                        try:
                            doc.append(json.loads(ln))
                        except ValueError:
                            parse_failed.append(key)
                    elif ln:
                        parse_failed.append(key)
            else:
                doc = json.loads(text)
            if key != "trufflehog" and not _valid_report(key, doc):
                raise ValueError("scanner report has an unexpected shape")
            details = _report_details(key, doc)
            report_details[key] = details
            if details["errors"]:
                crashed.append(key)
            if details.get("reported_version"):
                report_versions[key] = details["reported_version"]
            if isinstance(doc, dict):
                version = doc.get("version") or doc.get("scanner_version")
                if isinstance(version, (str, int)):
                    report_versions[key] = str(version)
            normalized = parser(doc)
            for finding in normalized:
                if finding.get("category") == "sca":
                    _sca_occurrence(finding, target)
                # bug-218: gitleaks runs twice over disjoint surfaces. Record WHICH surface produced
                # the hit so history-only annotation and the briefing can tell them apart.
                if key in ("gitleaks", "gitleaks-dir"):
                    finding["scan_mode"] = "dir" if key == "gitleaks-dir" else "git"
            raw += normalized
        except Exception:
            parse_failed.append(key)          # a truncated/OOM-killed scanner must not read as clean
            continue

    # bug-218: the same committed-and-still-present secret is found by BOTH gitleaks passes and
    # shares a fingerprint (secret|file|rule|line). Collapse to one finding carrying both modes, so
    # the dual pass adds RECALL without inflating the count.
    _seen_gl: dict = {}
    deduped = []
    for f in raw:
        if f.get("tool") != "gitleaks":
            deduped.append(f)
            continue
        fp = f.get("fingerprint")
        prior = _seen_gl.get(fp)
        if prior is None:
            _seen_gl[fp] = f
            deduped.append(f)
        elif prior.get("scan_mode") != f.get("scan_mode"):
            # SAME secret seen by BOTH passes — one finding, both modes recorded.
            prior["scan_mode"] = "git+dir"
        else:
            # Same mode: a within-tool duplicate. Leave it to the existing within-tool dedup so
            # total_raw and the dedup counters keep their established meaning.
            deduped.append(f)
    gitleaks_modes_merged = len(raw) - len(deduped)
    raw = deduped

    # bug-066 (a): a subprocess scanner can re-enter dirs the walker skips (nested worktrees,
    # build output, the tool's own websec-out) → drop anything under a SKIP_DIR. The
    # correctness guarantee behind the best-effort flags; also catches gitleaks (no skip flag).
    before = len(raw)
    raw = [f for f in raw if not _in_skip_dir(f.get("file", ""), target)]
    contamination_dropped = before - len(raw)

    # user --exclude contract: recon honors it via RepoContext, scanners must too. The argv
    # flags above are best-effort (gitleaks/checkov have none) — this is the guarantee.
    before = len(raw)
    raw = [f for f in raw if not _matches_excludes(f.get("file", ""), excludes, target)]
    user_excluded_dropped = before - len(raw)

    # bug-066 (b): working-tree secrets (trivy fs) in GITIGNORED files are local-only / never
    # committed — not a repo leak. Downgrade + annotate rather than report CRITICAL. Gitleaks
    # findings come from git HISTORY (already committed) and are deliberately left alone.
    ignored = _gitignored(target, (f.get("file", "") for f in raw
                                   if f.get("tool") == "trivy" and f.get("category") == "secret"))
    local_only_downgraded = 0
    for f in raw:
        if (f.get("tool") == "trivy" and f.get("category") == "secret"
                and f.get("file", "") in ignored
                and SEV_ORDER.get(f.get("severity"), 0) >= SEV_ORDER["MEDIUM"]):
            f["severity"] = "LOW"
            if "local-only" not in f["title"]:
                f["title"] += " — local-only (gitignored, never committed; rotate if real, not a repo leak)"
            local_only_downgraded += 1

    # field report #5: the doc/example/placeholder tier applies to every secret-like finding, not
    # just the ones the secret parsers produced. Runs BEFORE dedup so a cross-tool duplicate cannot
    # resurrect the higher severity through the max() in the fingerprint merge.
    placeholder_tiered = _tier_placeholder_matches(raw, target)

    # A gitleaks hit whose file is gone from the tree is a HISTORY-only leak — deleting the file did
    # not un-leak it. Annotate so the remediation is ROTATE, not "already removed".
    history_only = _annotate_history_only_secrets(raw, target)

    # DocGuard field report F1: secrets in test/fixture files are overwhelmingly PLANTED fakes
    # (scanner corpora, negative tests). Demote to LOW + annotate — never drop: a real key pasted
    # into a test is still a committed leak. Mirrors the local-only downgrade above; the doc/
    # example-file tier already happens at parse time (_is_doc_or_example).
    test_fixture_downgraded = 0
    if not include_fixtures:
        for f in raw:
            if (f.get("category") == "secret"
                    and is_test_file(_rel_to(f.get("file", ""), target))
                    and SEV_ORDER.get(f.get("severity"), 0) >= SEV_ORDER["MEDIUM"]):
                f["severity"] = "LOW"
                if "test/fixture" not in f["title"]:
                    f["title"] += (" — in a test/fixture file (planted fakes are common; "
                                   "verify + rotate if real, or --include-fixtures)")
                test_fixture_downgraded += 1

    by_fp: dict = {}
    for f in raw:
        fp = f["fingerprint"]
        if fp in by_fp:
            if f["tool"] not in by_fp[fp]["tools"]:
                by_fp[fp]["tools"].append(f["tool"])
            if SEV_ORDER[f["severity"]] > SEV_ORDER[by_fp[fp]["severity"]]:
                by_fp[fp]["severity"] = f["severity"]
            # A second tool may supply remediation/aliases missing from the first.
            if f.get("fixed"):
                fixes = {value for value in (f["fixed"], by_fp[fp].get("fixed", "")) if value}
                by_fp[fp]["fixed"] = ", ".join(sorted(fixes))
            aliases = set(by_fp[fp].get("advisory_aliases", [])) | set(f.get("advisory_aliases", []))
            if aliases:
                by_fp[fp]["advisory_aliases"] = sorted(aliases)
        else:
            f = dict(f)
            f["tools"] = [f.pop("tool")]
            by_fp[fp] = f
    deduped = sorted(by_fp.values(), key=lambda f: (-SEV_ORDER[f["severity"]], f["fingerprint"]))
    for finding in deduped:
        finding["tools"].sort()

    # ADDITIVE enrichment (never changes severity / count): is the vulnerable dependency actually
    # imported (reachability), and is the CVE known-exploited / high-EPSS (exploitability)? Both
    # sharpen triage in the briefing; neither can reintroduce a false positive.
    reachability = enrichment.enrich_reachability(deduped, target)
    exploitability = enrichment.enrich_exploitability(deduped)
    # Every finding gets a confidence + a stable per-instance id. Runs AFTER enrichment so the
    # reachability signal can inform confidence, and after all the demotion passes so a finding
    # already tiered to INFO/LOW is read as the placeholder it is (field report #6).
    for f in deduped:
        # Keep the scanner's ORIGINAL value verbatim: findings.py inspects it to decide whether the
        # producer's own confidence was usable, and a derived value must never impersonate one.
        if "confidence" in f:
            f["native_confidence"] = f["confidence"]
        conf, basis = _derive_confidence(f, target)
        f["confidence"], f["confidence_basis"] = conf, basis
        f["instance_id"] = _instance_id(f, target)
    by_conf: dict = {}
    for f in deduped:
        by_conf[f["confidence"]] = by_conf.get(f["confidence"], 0) + 1

    (outdir / "findings.json").write_text(json.dumps(deduped, indent=2))

    by_sev, by_cat = {}, {}
    for f in deduped:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    summaries = [{"severity": f["severity"], "category": f["category"], "title": f["title"],
                  "file": f["file"], "tools": f["tools"],
                  **{k: f[k] for k in ("key", "rule_id", "id", "cve", "package", "pkg", "resource",
                                      "service", "symbol", "sink", "semantic_id", "line", "fingerprint",
                                      "installed", "fixed", "ecosystem", "advisory_aliases", "confidence", "cwe",
                                      # field report #6: a per-INSTANCE id (`key` is a rule id) + why
                                      # this confidence, so `feedback`/baselining can address one finding.
                                      "instance_id", "confidence_basis", "native_confidence",
                                      # field report #3: where the secret LIVES. in_tree=False means the
                                      # file is gone from the working tree but the blob is still fetchable.
                                      "in_tree", "history_only", "commit", "commit_short", "commit_date") if k in f},
                  # bug-218: which gitleaks surface produced the hit (git | dir | git+dir). Committed
                  # vs working-tree-only changes the remediation, so the ledger must see it.
                  **({"scan_mode": f["scan_mode"]} if isinstance(f.get("scan_mode"), str) else {}),
                  # carry enrichment fields so the briefing/ledger/SARIF can render structured badges
                  **({"reachability": f["reachability"]} if f.get("reachability") else {}),
                  **({"epss": f["epss"]} if f.get("epss") is not None else {}),
                  **({"epss_pct": f["epss_pct"]} if f.get("epss_pct") is not None else {}),
                  **({"kev": f["kev"]} if type(f.get("kev")) is bool else {}),
                  **({"intel": f["intel"]} if isinstance(f.get("intel"), dict) else {}),
                  **({"intel_status": f["intel_status"]} if isinstance(f.get("intel_status"), str) else {})}
                 for f in deduped]
    return {"total_raw": len(raw), "total": len(deduped),
            "by_confidence": by_conf,
            "cross_tool_or_dup_merged": len(raw) - len(deduped),
            "contamination_dropped": contamination_dropped,
            "user_excluded_dropped": user_excluded_dropped,
            "local_only_downgraded": local_only_downgraded,
            "test_fixture_downgraded": test_fixture_downgraded,
            "history_only_secrets": history_only,
            "placeholder_tiered": placeholder_tiered,
            "reachability": reachability,
            "exploitability": exploitability,
            "parse_failed": sorted(set(parse_failed)),
            "parse_attempted": sorted(set(_parse_attempted)),
            "report_versions": report_versions,
            "report_details": report_details,
            "scanner_errors": sorted({c for c in crashed if c}),
            "by_severity": by_sev, "by_category": by_cat,
            # `top` = a short slice for the human briefing; `all` = the FULL ranked set the
            # findings ledger consumes. The ledger must NOT silently drop a HIGH/CRITICAL static
            # finding ranked #16+ — that undercounted the ledger + calibration on scan-heavy repos
            # while the CLI printed ledger.total as if complete. (cli excludes `all` from manifest
            # to avoid duplicating findings.json.)
            "top": summaries[:15],
            "all": summaries}

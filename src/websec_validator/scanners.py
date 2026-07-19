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
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import enrichment
from .extractors.base import SKIP_DIRS, is_test_file, path_in_skip_dir


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
        rel = _rel_to(f.get("file", ""), target)
        if not rel:
            continue
        try:
            exists = (Path(target) / rel).exists()
        except OSError:
            continue
        # guard on the FIELD, not a title substring: several provider notes already mention the word
        # "history" ("…does NOT scrub pushed history"), which silently suppressed this annotation.
        if not exists and not f.get("history_only"):
            f["history_only"] = True
            f["title"] += (" [HISTORY-ONLY: the file is already gone from the working tree — someone "
                           "likely 'fixed' this by deleting it. The blob is still reachable in the "
                           "repo, so it is NOT fixed until the credential is rotated.]")
            n += 1
    return n


def _gitleaks(target: Path, out: Path, excludes=()) -> list:
    return ["gitleaks", "detect", "--source", str(target), "--no-banner",
            "--report-format", "json", "--report-path", str(out)]


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
    return ["osv-scanner", "scan", "--format", "json", "--output", str(out), str(target)]


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


REGISTRY: tuple = (
    Scanner("trivy", "Trivy", "sca", "trivy",
            install="brew install trivy  # pin by digest in CI", argv=_trivy),
    Scanner("gitleaks", "Gitleaks", "secrets", "gitleaks",
            install="brew install gitleaks", argv=_gitleaks),
    Scanner("semgrep", "Semgrep/OpenGrep", "sast", "semgrep",
            install="pipx install semgrep  # or opengrep for fully-OSS", argv=_semgrep),
    Scanner("checkov", "Checkov", "iac", "checkov",
            install="pipx install checkov", argv=_checkov),
    Scanner("bandit", "Bandit", "sast", "bandit", languages=("python",),
            install="pipx install bandit"),
    Scanner("gosec", "gosec", "sast", "gosec", languages=("go",),
            install="brew install gosec  # Go SAST", argv=_gosec),
    Scanner("brakeman", "Brakeman", "sast", "brakeman", languages=("ruby",),
            install="gem install brakeman  # Rails SAST", argv=_brakeman),
    Scanner("osv-scanner", "OSV-Scanner", "sca", "osv-scanner",
            install="brew install osv-scanner", argv=_osv),
    # OPT-IN ONLY (--verify-secrets): verification calls third-party APIs with the found credential.
    # run_available() skips this unless explicitly enabled, even when the binary is installed.
    Scanner("trufflehog", "TruffleHog (live verification)", "secrets", "trufflehog",
            install="brew install trufflehog  # opt-in: websec run … --verify-secrets", argv=_trufflehog),
    Scanner("prowler", "Prowler", "cloud", "prowler",
            install="pipx install prowler  # needs AWS creds"),
)


def detect(stack_languages: list | None = None) -> dict:
    """Return {'available': [...], 'missing': [...]} for the relevant scanners.

    A language-specific scanner (e.g. Bandit/python) is only considered relevant
    when that language is present in the stack.
    """
    langs = set(stack_languages or [])
    available, missing = [], []
    for s in REGISTRY:
        if s.languages and not (set(s.languages) & langs):
            continue  # not relevant to this repo's stack
        entry = {"key": s.key, "name": s.name, "category": s.category}
        if shutil.which(s.binary):
            available.append(entry)
        else:
            missing.append({**entry, "install": s.install})
    return {"available": available, "missing": missing}


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
                data = json.loads(out_file.read_text())
                comps = len(data.get("components") or data.get("packages") or [])
            except Exception:
                pass
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
        return sum(1 for ln in out_file.read_text().splitlines() if ln.strip().startswith("{"))
    try:
        data = json.loads(out_file.read_text())
    except Exception:
        return 0
    if key == "trivy":
        return sum(len(r.get("Vulnerabilities", []) or []) +
                   len(r.get("Secrets", []) or []) +
                   len(r.get("Misconfigurations", []) or [])
                   for r in (data.get("Results") or []))
    if key == "gitleaks":
        return len(data) if isinstance(data, list) else 0
    if key == "semgrep":
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
# value in `.env.example`. Tier those to LOW + a verify note (still visible — a real key CAN be
# pasted into docs by mistake). Dogfooding flagged 4 HIGH curl-auth-header FPs across an API's
# README + docs/*.md (bug below).
_DOC_EXT = (".md", ".mdx", ".markdown", ".rst", ".txt", ".adoc")
_DOC_DIR_MARKERS = ("/docs/", "/doc/", "/examples/", "/example/", "/samples/", "/sample/", "/.github/")
_DOC_NAME_PREFIX = ("readme", "changelog", "contributing", "license", "authors", "history", "notice")
_EXAMPLE_SUFFIX = (".example", ".sample", ".dist", ".template", ".tmpl")
_DOC_NOTE = "in a documentation/example file — almost always a placeholder, verify before treating as real"


def _is_doc_or_example(path: str) -> bool:
    # "/" prefix so ROOT-LEVEL dirs match the /marker/ patterns too — `examples/app.js`
    # previously slipped past `/examples/` and kept HIGH (DocGuard field report F1).
    p = "/" + (path or "").replace("\\", "/").lower().lstrip("/")
    base = p.rsplit("/", 1)[-1]
    return (p.endswith(_DOC_EXT)
            or any(m in p for m in _DOC_DIR_MARKERS)
            or any(base.startswith(m) for m in _DOC_NAME_PREFIX)
            or any(s in base for s in _EXAMPLE_SUFFIX))


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
            if _is_doc_or_example(tgt):
                sev, note = "LOW", (note + "; " if note else "") + _DOC_NOTE
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
        if _is_doc_or_example(f):
            sev, note = "LOW", (note + "; " if note else "") + _DOC_NOTE
        title = f"secret: {(x.get('Description') or rule)[:80]}" + (f" — {note}" if note else "")
        out.append({"tool": "gitleaks", "category": "secret", "severity": sev or "HIGH",
                    "key": rule, "file": f, "line": x.get("StartLine", 0),
                    "title": title, "fingerprint": f"secret|{f}|{rule}|{x.get('StartLine', 0)}"})
    return out


def _norm_semgrep(data: dict) -> list:
    sevmap = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "INFO"}
    out = []
    for r in (data.get("results") or []):
        rule = (r.get("check_id", "")).split(".")[-1]
        path = r.get("path", "")
        line = (r.get("start") or {}).get("line", 0)
        sev = sevmap.get((r.get("extra") or {}).get("severity", "INFO"), "MEDIUM")
        out.append({"tool": "semgrep", "category": "sast", "severity": sev,
                    "key": rule, "file": path, "line": line,
                    "title": ((r.get("extra") or {}).get("message") or rule)[:90],
                    "fingerprint": f"sast|{path}|{line}|{rule}"})
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
                        "severity": _sev(c.get("severity") or "MEDIUM"),
                        "key": cid, "file": f, "line": (rng[0] if rng else 0),
                        "title": (c.get("check_name") or cid)[:90],
                        "fingerprint": f"iac|{f}|{cid}"})
    return out


_PARSERS = {"trivy": _norm_trivy, "gitleaks": _norm_gitleaks, "semgrep": _norm_semgrep,
            "checkov": _norm_checkov, "osv-scanner": _norm_osv,
            "gosec": _norm_gosec, "brakeman": _norm_brakeman,
            "trufflehog": _norm_trufflehog}


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
    for r in scan_results:
        out, key = r.get("output"), r.get("key")
        parser = _PARSERS.get(key)
        if not (out and parser and Path(out).exists()):
            continue
        try:
            text = Path(out).read_text()
            if key == "trufflehog":          # JSON-LINES, one finding per line
                doc = []
                for ln in text.splitlines():
                    ln = ln.strip()
                    if ln.startswith("{"):
                        try:
                            doc.append(json.loads(ln))
                        except ValueError:
                            continue         # a partial/among-progress line is not fatal
            else:
                doc = json.loads(text or "{}")
            raw += parser(doc)
        except Exception:
            continue

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
        else:
            f = dict(f)
            f["tools"] = [f.pop("tool")]
            by_fp[fp] = f
    deduped = sorted(by_fp.values(), key=lambda f: -SEV_ORDER[f["severity"]])

    # ADDITIVE enrichment (never changes severity / count): is the vulnerable dependency actually
    # imported (reachability), and is the CVE known-exploited / high-EPSS (exploitability)? Both
    # sharpen triage in the briefing; neither can reintroduce a false positive.
    reachability = enrichment.enrich_reachability(deduped, target)
    exploitability = enrichment.enrich_exploitability(deduped)
    (outdir / "findings.json").write_text(json.dumps(deduped, indent=2))

    by_sev, by_cat = {}, {}
    for f in deduped:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    summaries = [{"severity": f["severity"], "category": f["category"], "title": f["title"],
                  "file": f["file"], "tools": f["tools"],
                  # carry enrichment fields so the briefing/ledger/SARIF can render structured badges
                  **({"reachability": f["reachability"]} if f.get("reachability") else {}),
                  **({"epss": f["epss"]} if f.get("epss") is not None else {}),
                  **({"kev": True} if f.get("kev") else {})}
                 for f in deduped]
    return {"total_raw": len(raw), "total": len(deduped),
            "cross_tool_or_dup_merged": len(raw) - len(deduped),
            "contamination_dropped": contamination_dropped,
            "user_excluded_dropped": user_excluded_dropped,
            "local_only_downgraded": local_only_downgraded,
            "test_fixture_downgraded": test_fixture_downgraded,
            "history_only_secrets": history_only,
            "reachability": reachability,
            "exploitability": exploitability,
            "by_severity": by_sev, "by_category": by_cat,
            # `top` = a short slice for the human briefing; `all` = the FULL ranked set the
            # findings ledger consumes. The ledger must NOT silently drop a HIGH/CRITICAL static
            # finding ranked #16+ — that undercounted the ledger + calibration on scan-heavy repos
            # while the CLI printed ledger.total as if complete. (cli excludes `all` from manifest
            # to avoid duplicating findings.json.)
            "top": summaries[:15],
            "all": summaries}


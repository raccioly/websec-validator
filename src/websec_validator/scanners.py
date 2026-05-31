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

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


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


# Never scan the tool's own output, deps, or build artifacts. Scanning `websec-out/`
# made Semgrep re-flag the AWS keys Gitleaks had just written into the report (and the
# count compounded across runs). Filesystem scanners get these excluded explicitly.
EXCLUDE_DIRS = ("websec-out", "node_modules", ".next", "dist", "build", ".git",
                "security", ".venv", "venv", "__pycache__", ".mypy_cache", "coverage")


def _trivy(target: Path, out: Path) -> list:
    # SCA + secrets + IaC misconfig in one pass; pinned by the user's install.
    cmd = ["trivy", "fs", "--scanners", "vuln,secret,misconfig", "--format", "json", "--output", str(out)]
    for d in EXCLUDE_DIRS:
        cmd += ["--skip-dirs", d]
    return cmd + [str(target)]


def _gitleaks(target: Path, out: Path) -> list:
    return ["gitleaks", "detect", "--source", str(target), "--no-banner",
            "--report-format", "json", "--report-path", str(out)]


def _semgrep(target: Path, out: Path) -> list:
    cmd = ["semgrep", "scan", "--config", "auto", "--json", "--output", str(out)]
    for d in EXCLUDE_DIRS:
        cmd += ["--exclude", d]
    return cmd + [str(target)]


def _checkov(target: Path, out: Path) -> list:
    return ["checkov", "-d", str(target), "--compact", "-o", "json",
            "--output-file-path", str(out.parent)]


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
    Scanner("osv-scanner", "OSV-Scanner", "sca", "osv-scanner",
            install="brew install osv-scanner"),
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
                  timeout: int = 600) -> list:
    """Execute every available, runnable static scanner. Returns per-scanner status.

    Raw JSON lands in outdir/scanners/<key>.json. We capture status only here;
    cross-tool normalization + de-duplication is a separate (next) step.
    """
    langs = set(stack_languages or [])
    scan_dir = outdir / "scanners"
    scan_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for s in REGISTRY:
        if s.argv is None:
            continue  # detect-only for now
        if s.languages and not (set(s.languages) & langs):
            continue
        if not shutil.which(s.binary):
            continue
        out_file = scan_dir / f"{s.key}.json"
        try:
            proc = subprocess.run(s.argv(target, out_file), capture_output=True,
                                  text=True, timeout=timeout)
            results.append({"key": s.key, "name": s.name, "category": s.category,
                            "exit_code": proc.returncode, "output": str(out_file),
                            "findings": _count_findings(s.key, out_file)})
        except subprocess.TimeoutExpired:
            results.append({"key": s.key, "name": s.name, "status": "timeout"})
        except Exception as e:  # never let one scanner sink the run
            results.append({"key": s.key, "name": s.name, "status": f"error: {e}"})
    return results


def _count_findings(key: str, out_file: Path) -> int:
    """Best-effort finding count from a scanner's native JSON (for the summary)."""
    if not out_file.exists():
        return 0
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


def _norm_trivy(data: dict) -> list:
    out = []
    for res in (data.get("Results") or []):
        tgt = res.get("Target", "")
        for v in (res.get("Vulnerabilities") or []):
            out.append({"tool": "trivy", "category": "sca", "severity": _sev(v.get("Severity")),
                        "key": v.get("VulnerabilityID", ""), "file": tgt, "line": 0,
                        "title": f"{v.get('PkgName')} {v.get('InstalledVersion')} → {v.get('FixedVersion', '(no fix)')}",
                        "fingerprint": f"cve|{v.get('PkgName')}|{v.get('VulnerabilityID')}"})
        for s in (res.get("Secrets") or []):
            sev, note = _aws_secret_tier(s.get("Match", ""), s.get("Code", "") or "")
            title = f"secret: {s.get('Title') or s.get('RuleID')}" + (f" — {note}" if note else "")
            out.append({"tool": "trivy", "category": "secret", "severity": sev or _sev(s.get("Severity") or "HIGH"),
                        "key": s.get("RuleID", ""), "file": tgt, "line": s.get("StartLine", 0),
                        "title": title, "fingerprint": f"secret|{tgt}|{s.get('RuleID')}"})
        for m in (res.get("Misconfigurations") or []):
            out.append({"tool": "trivy", "category": "iac", "severity": _sev(m.get("Severity")),
                        "key": m.get("ID", ""), "file": tgt, "line": 0, "title": (m.get("Title") or "")[:90],
                        "fingerprint": f"iac|{tgt}|{m.get('ID')}"})
    return out


def _norm_gitleaks(data) -> list:
    rows = data if isinstance(data, list) else (data.get("findings") or [])
    out = []
    for x in rows:
        f, rule = x.get("File", ""), x.get("RuleID", "")
        sev, note = _aws_secret_tier(x.get("Secret", ""), x.get("Match", ""))
        title = f"secret: {(x.get('Description') or rule)[:80]}" + (f" — {note}" if note else "")
        out.append({"tool": "gitleaks", "category": "secret", "severity": sev or "HIGH",
                    "key": rule, "file": f, "line": x.get("StartLine", 0),
                    "title": title, "fingerprint": f"secret|{f}|{rule}"})
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


_PARSERS = {"trivy": _norm_trivy, "gitleaks": _norm_gitleaks, "semgrep": _norm_semgrep}


def normalize_findings(scan_results: list, outdir: Path) -> dict:
    """Merge every scanner's native JSON into one de-duplicated, severity-ranked
    findings.json. Returns a summary (raw vs deduped, by severity/category)."""
    raw = []
    for r in scan_results:
        out, key = r.get("output"), r.get("key")
        parser = _PARSERS.get(key)
        if not (out and parser and Path(out).exists()):
            continue
        try:
            raw += parser(json.loads(Path(out).read_text() or "{}"))
        except Exception:
            continue

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
    (outdir / "findings.json").write_text(json.dumps(deduped, indent=2))

    by_sev, by_cat = {}, {}
    for f in deduped:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    return {"total_raw": len(raw), "total": len(deduped),
            "cross_tool_or_dup_merged": len(raw) - len(deduped),
            "by_severity": by_sev, "by_category": by_cat,
            "top": [{"severity": f["severity"], "category": f["category"], "title": f["title"],
                     "file": f["file"], "tools": f["tools"]} for f in deduped[:15]]}


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


def _trivy(target: Path, out: Path) -> list:
    # SCA + secrets + IaC misconfig in one pass; pinned by the user's install.
    return ["trivy", "fs", "--scanners", "vuln,secret,misconfig",
            "--skip-dirs", "node_modules", "--skip-dirs", "security",
            "--format", "json", "--output", str(out), str(target)]


def _gitleaks(target: Path, out: Path) -> list:
    return ["gitleaks", "detect", "--source", str(target), "--no-banner",
            "--report-format", "json", "--report-path", str(out)]


def _semgrep(target: Path, out: Path) -> list:
    return ["semgrep", "scan", "--config", "auto", "--json",
            "--output", str(out), str(target)]


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

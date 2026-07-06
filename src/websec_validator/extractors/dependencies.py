"""Dependencies extractor — OFFLINE supply-chain hygiene (the AI slopsquat / malicious-dep class).

Deterministic, offline, read-only. Trivy already finds KNOWN-VULN packages; this finds the AI-specific
failure modes Trivy can't: an install-time-RCE lifecycle script, and drift between a manifest and its
lockfile. It ships two LEDGER-bound classes:

  - **malicious-install-script** (MEDIUM) : an npm lifecycle script (install/postinstall/…) whose BODY
    fetches-and-executes or evals — the Shai-Hulud / install-time-RCE shape.
  - **lockfile-drift** (LOW)              : a manifest dependency absent from an EXISTING lockfile.

Everything FP-prone is ADVISORY-ONLY — surfaced in facts but NEVER routed to the ledger, so it can't
inflate the finding count or reintroduce false positives: floating/unpinned versions, and
dependency-confusion-shaped names (the public-org allowlist is inherently incomplete). The network
signals that would actually confirm a hallucinated/typosquatted package (registry resolution, a shipped
known-hallucinated-name list, Levenshtein-to-top-N) are DEFERRED behind an opt-in `--network` step: this
extractor makes ZERO network calls in the default pass (`facts['dependencies']['network']['ran']` is
always False here). No new pip dependency; stdlib json/re only.
"""

from __future__ import annotations

import json
import re

from .base import Extractor, RepoContext

# npm lifecycle scripts that run automatically on install. A BODY matching a fetch-and-execute / eval
# shape is the install-time-RCE class (keyed on the SHAPE, never on the mere presence of a script — a
# `postinstall: "husky install"` / `tsc` / `node-gyp rebuild` / `patch-package` must stay silent).
_LIFECYCLE_KEYS = ("install", "preinstall", "postinstall", "prepare", "prepublish", "prepublishOnly")
SUSPICIOUS_LIFECYCLE = re.compile(
    r"\bcurl\b|\bwget\b|\|\s*(?:ba)?sh\b|node\s+-e\b|python[0-9.]*\s+-c\b"
    r"|base64\s+(?:-d|--decode)|atob\s*\(|Buffer\.from\([^)]*base64|\beval\s*\("
    r"|\bhttps?://[^\s\"']+\.(?:sh|py|js)\b|/dev/tcp/|\bnc\s+-|powershell", re.I)

# npm spec prefixes that are INTENTIONAL (monorepo / alias) — never "unpinned".
_NPM_INTENTIONAL = ("workspace:", "file:", "link:", "portal:", "catalog:", "npm:")
# scoped @org/* whose org is a well-known public publisher → not a dependency-confusion candidate. The
# list is deliberately partial (it only gates an ADVISORY, never a ledger finding), so gaps cost nothing.
_PUBLIC_SCOPES = {
    "aws-sdk", "angular", "angular-devkit", "babel", "nestjs", "types", "vue", "remix-run", "remix",
    "apollo", "sentry", "google-cloud", "googleapis", "hapi", "slack", "wordpress", "storybook",
    "testing-library", "tanstack", "radix-ui", "floating-ui", "emotion", "mui", "next", "vitejs",
    "swc", "typescript-eslint", "octokit", "prisma", "supabase", "modelcontextprotocol", "img",
    "smithy", "reduxjs", "tailwindcss", "vercel", "playwright", "sinonjs", "eslint", "trpc",
}
# Any lockfile → the deps are effectively pinned at install (softens the unpinned advisory). But DRIFT is
# computed ONLY from a reliably-parseable JSON lock (package-lock.json / npm-shrinkwrap.json) — text-format
# yarn/pnpm locks are skipped to avoid a FALSE drift (a false negative is the safe direction here).
_NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
_NPM_JSON_LOCKS = ("package-lock.json", "npm-shrinkwrap.json")

_PIP_LINE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(.*)$")


def _npm_unpinned(spec: str) -> bool:
    s = (spec or "").strip()
    if not s or s.startswith(_NPM_INTENTIONAL):
        return False
    if s in ("*", "latest", "x", "") or s.startswith(("^", "~", ">=", "<=", ">", "<", "git+", "git:",
                                                      "http://", "https://")):
        return True
    if re.match(r"^\d", s):                 # 1.2.3 pinned; 1.2.x / 1.x floating
        return "x" in s.lower() or "*" in s
    return True                              # github user/repo shorthand, url, etc. → unpinned


def _npm_installed(texts: list) -> set:
    """Set of INSTALLED package names from package-lock.json/npm-shrinkwrap.json — the `node_modules/*`
    keys (lockfileVersion 2/3) and the top-level `dependencies` tree (v1). Deliberately EXCLUDES the
    root `packages[""]` manifest-mirror, so a manifest dep that isn't actually resolved reads as drift."""
    names: set = set()
    for t in texts:
        try:
            d = json.loads(t)
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        pkgs = d.get("packages")
        if isinstance(pkgs, dict):
            for k in pkgs:
                if k.startswith("node_modules/"):
                    names.add(k.rsplit("node_modules/", 1)[-1])
        dep = d.get("dependencies")
        if isinstance(dep, dict):
            names.update(dep.keys())        # lockfileVersion 1 shape
    return names


class DependenciesExtractor(Extractor):
    name = "dependencies"
    category = "supply-chain"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        findings: list = []       # LEDGER-bound: install-script + drift ONLY
        unpinned: list = []       # ADVISORY — never routed to the ledger
        confusion: list = []      # ADVISORY — never routed to the ledger
        lockfiles_present: list = []
        ecosystems: set = set()
        manifests = 0

        # ---- npm ----
        for mf in ctx.glob("**/package.json", 120):
            rel = ctx.rel(mf)
            try:
                data = json.loads(ctx.text(mf))
            except Exception:
                data = None
            manifests += 1
            ecosystems.add("npm")
            has_lock = False
            json_lock_texts: list = []
            for lname in _NPM_LOCKFILES:
                lp = mf.parent / lname
                if lp.is_file():
                    has_lock = True
                    lockfiles_present.append(ctx.rel(lp))
                    if lname in _NPM_JSON_LOCKS:
                        json_lock_texts.append(ctx.text(lp))
            installed = _npm_installed(json_lock_texts)
            can_drift = bool(json_lock_texts)
            if not isinstance(data, dict):
                continue

            scripts = data.get("scripts") or {}
            if isinstance(scripts, dict):
                for k in _LIFECYCLE_KEYS:
                    body = str(scripts.get(k, ""))
                    if body and SUSPICIOUS_LIFECYCLE.search(body):
                        findings.append({
                            "kind": "malicious-install-script", "attack_class": "malicious-install-script",
                            "severity": "MEDIUM", "confidence": "MEDIUM", "file": rel,
                            "detail": f"npm `{k}` lifecycle script runs a fetch-and-execute / eval command "
                                      f"(`{body[:120]}`) — it executes automatically on `npm install`, before any "
                                      "code review (the Shai-Hulud install-time-RCE shape). Vet the script; pin it "
                                      "to a committed local file, or remove the lifecycle hook."})

            deps = {}
            for block in ("dependencies", "optionalDependencies"):
                d = data.get(block)
                if isinstance(d, dict):
                    deps.update(d)
            for name, spec in deps.items():
                spec = str(spec)
                if _npm_unpinned(spec):
                    reason = "floating/unpinned version"
                    if has_lock:
                        reason += " (lockfile present — pins resolved at install)"
                    unpinned.append({"file": rel, "name": name, "spec": spec, "reason": reason})
                # dependency-confusion (ADVISORY): a scoped name on a non-public org, plain registry spec.
                m = re.match(r"^@([\w.-]+)/", name)
                if m and m.group(1).lower() not in _PUBLIC_SCOPES and not spec.startswith(_NPM_INTENTIONAL) \
                        and not spec.startswith(("git", "http", "file", "link")):
                    confusion.append({"file": rel, "name": name, "scope": m.group(1),
                                      "note": "scoped name on a non-public org — verify the scope is claimed on "
                                              "the public registry (dependency-confusion surface)."})
                # lockfile drift (LEDGER, LOW): only when a JSON lockfile exists and the dep is NOT in its
                # installed set. Skipped entirely for yarn/pnpm (text locks) — no false drift.
                if can_drift and name not in installed:
                    findings.append({
                        "kind": "lockfile-drift", "attack_class": "lockfile-drift",
                        "severity": "LOW", "confidence": "LOW", "file": rel,
                        "detail": f"`{name}` is declared in {block} but does not appear in the lockfile — the "
                                  "manifest and lockfile have drifted, so `npm install` may resolve a version "
                                  "nobody reviewed. Regenerate the lockfile and commit it as a reviewable diff."})

        # ---- pip ----
        pip_manifests = (ctx.glob("**/requirements*.txt", 80) + ctx.glob("**/pyproject.toml", 40)
                         + ctx.glob("**/Pipfile", 20))
        for mf in pip_manifests:
            rel = ctx.rel(mf)
            manifests += 1
            ecosystems.add("pip")
            for lname in ("poetry.lock", "Pipfile.lock"):
                lp = mf.parent / lname
                if lp.is_file():
                    lockfiles_present.append(ctx.rel(lp))
            if mf.name.startswith("requirements") and mf.suffix == ".txt":
                for raw in ctx.text(mf).splitlines():
                    line = raw.split("#", 1)[0].strip()
                    if not line or line.startswith(("-", "git+", "http")):
                        continue
                    if "==" in line or "@" in line:
                        continue                       # pinned (== or @ url/hash)
                    m = _PIP_LINE.match(line)
                    if m and re.search(r"[<>~*!]|^[A-Za-z0-9._-]+$", (m.group(2) or "").strip() or m.group(1)):
                        unpinned.append({"file": rel, "name": m.group(1), "spec": (m.group(2) or "").strip() or "*",
                                         "reason": "unpinned pip requirement (no == pin)"})

        counts = {"unpinned": len(unpinned), "confusion_candidates": len(confusion),
                  "install_scripts": sum(1 for f in findings if f["kind"] == "malicious-install-script"),
                  "drift": sum(1 for f in findings if f["kind"] == "lockfile-drift")}
        return {
            "manifests_scanned": manifests,
            "ecosystems": sorted(ecosystems),
            "lockfiles_present": sorted(set(lockfiles_present)),
            "findings": findings,                      # LEDGER-bound (install-script + drift only)
            "unpinned": unpinned[:200],                # ADVISORY — not routed to the ledger
            "confusion_candidates": confusion[:100],   # ADVISORY — not routed to the ledger
            "counts": counts,
            "network": {"ran": False,
                        "note": "registry resolution / known-hallucinated-name list / typosquat distance are "
                                "deferred behind an opt-in --network step; the default pass is fully offline."},
        }

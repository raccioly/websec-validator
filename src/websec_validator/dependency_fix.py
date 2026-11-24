"""Dependency fix guidance — turn "upgrade to the fixed version" into the change a reader makes.

A vulnerable-dependency finding used to carry one generic remediation for every CVE: "Upgrade the
dependency to the fixed version." That sentence does not answer the three questions that decide the
actual fix:

  * **Which version?** Scanners list every fixed release ("5.3.0, 4.2.5"). The right target is the
    lowest fix on the release line already installed; only when that line has no fix is a major
    upgrade the answer — and a major upgrade must be called out, because it breaks APIs.
  * **Where do I change it?** A transitive package (pulled in by another dependency) is fixed by
    upgrading its PARENT. Adding an override for the child is the fallback, not the first move.
  * **Is it even a dependency of the app?** A module embedded in a compiled binary (a CLI committed
    or downloaded into the checkout) is fixed by upgrading or rebuilding that tool, or by keeping it
    out of the tree — not by editing a manifest.

Deterministic, offline, stdlib only. It reads a lockfile already in scope; it never resolves
anything over the network and never changes severity, count or identity of a finding.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_MAX_LOCK_BYTES = 32 * 1024 * 1024
_NUM = re.compile(r"\d+")


def version_key(text: str) -> tuple:
    """A comparable key for a dotted version. Pre-release/build suffixes are ignored.

    `v1.2.3`, `1.2.3+incompatible` and `1.2.3-0.2025…` compare on (1, 2, 3). Good enough to order
    the FIX candidates of one advisory, which is all this module needs; empty when unparseable."""
    core = re.split(r"[-+]", str(text or "").strip().lstrip("vV"), maxsplit=1)[0]
    parts = core.split(".")
    out = []
    for part in parts:
        m = _NUM.match(part)
        if not m:
            break
        out.append(int(m.group()))
    return tuple(out)


# Ecosystems whose resolvers treat a 0.x MINOR bump as breaking (npm caret, Cargo). Go modules and
# PyPI do not: example.org/x/codec 0.12 → 0.19 is a routine upgrade, not a major one.
_ZERO_MINOR_BREAKS = {"npm", "node-pkg", "yarn", "pnpm", "cargo"}


def _line(key: tuple, ecosystem: str = "") -> tuple:
    """The compatibility line: the major, or major.minor for 0.x where the ecosystem says so."""
    if not key:
        return ()
    if key[0] == 0 and str(ecosystem or "").lower() in _ZERO_MINOR_BREAKS:
        return key[:2]
    return key[:1]


def pick_fix(installed: str, fixed: str, ecosystem: str = "") -> tuple:
    """(target, major_bump) — the smallest fix on the installed line, else the smallest fix above.

    `fixed` is a comma-separated list as the scanners report it. Returns ("", False) when nothing
    is published. A fix that cannot be parsed is returned verbatim rather than guessed at."""
    fixes = [f.strip() for f in str(fixed or "").split(",") if f.strip()]
    if not fixes:
        return "", False
    have = version_key(installed)
    parsed = [(version_key(f), f) for f in fixes]
    usable = [(k, f) for k, f in parsed if k and (not have or k > have)]
    if not usable:
        return fixes[0], False
    same = [(k, f) for k, f in usable if have and _line(k, ecosystem) == _line(have, ecosystem)]
    key, target = min(same or usable)
    return target, bool(have) and _line(key, ecosystem) != _line(have, ecosystem) and key > have


def _fixed_by(version: tuple, fixes: list, ecosystem: str) -> bool:
    """Is one advisory fixed at `version`, given its fixed releases (one per release line)?

    A fix on the same line at or below `version` fixes it. With no fix on that line, it is fixed only
    when every fix is older than `version` (the line was cut after the fix landed). A line whose
    only fix is newer is still affected — 5.1.0 is NOT fixed by "4.2.5, 5.3.0"."""
    keys = [k for k in (version_key(f) for f in fixes) if k]
    if not keys:
        return False
    same = [k for k in keys if _line(k, ecosystem) == _line(version, ecosystem)]
    if same:
        return min(same) <= version
    return max(keys) < version


def _clears_all(installed: str, fixed_lists: list, ecosystem: str = "") -> str:
    """The lowest published fix that fixes EVERY advisory in the list, else "" (never a guess)."""
    have = version_key(installed)
    per_advisory = [[f.strip() for f in str(v or "").split(",") if f.strip()] for v in fixed_lists]
    if not all(per_advisory):
        return ""
    candidates = sorted({f for fixes in per_advisory for f in fixes if version_key(f) and
                         (not have or version_key(f) > have)}, key=lambda v: (version_key(v), v))
    for candidate in candidates:
        key = version_key(candidate)
        if all(_fixed_by(key, fixes, ecosystem) for fixes in per_advisory):
            return candidate
    return ""


# ---- npm lockfile: direct or transitive, and who pulls it in ------------------------------------

def _load_lock(path: Path) -> dict | None:
    try:
        if path.stat().st_size > _MAX_LOCK_BYTES:
            return None
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


_DEP_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def _resolve(packages: dict, dependent: str, pkg: str) -> str:
    """The lock key npm loads `pkg` from when `dependent` requires it: the nearest node_modules up."""
    chain = dependent.split("/node_modules/") if dependent else []
    while chain:
        candidate = "/node_modules/".join(chain) + "/node_modules/" + pkg
        if candidate in packages:
            return candidate
        chain.pop()
    return "node_modules/" + pkg


def npm_paths(doc: dict, pkg: str, version: str = "") -> tuple:
    """("direct" | "bundled" | "transitive" | "", parents) for `pkg`@`version` in a package-lock.json.

    Version-aware: a lockfile can hold several copies of one package, and only the copy at the
    vulnerable version matters. Its dependents are the packages whose node_modules resolution lands
    on that copy — not every package that names `pkg` (postcss 8.4.31 nested under one framework is
    not "pulled in by" the twenty other packages that use the top-level postcss).
    lockfileVersion 2/3 use the flat `packages` map (key "" is the root project); version 1 uses
    the nested `dependencies` tree with `requires`. Unknown shapes answer "" — never a guess."""
    packages = doc.get("packages")
    if isinstance(packages, dict) and packages:
        tail = "node_modules/" + pkg
        copies = [k for k, e in packages.items()
                  if k and (k == tail or k.endswith("/" + tail)) and isinstance(e, dict)
                  and (not version or e.get("version") in (None, version))]
        if not copies:
            return "", []
        kind, parents = "", []
        for key in copies:
            prefix = key[: -len(tail)].rstrip("/")
            if packages[key].get("inBundle") and prefix:
                return "bundled", [prefix.rsplit("node_modules/", 1)[-1]]
            for dep_key, entry in packages.items():
                if not isinstance(entry, dict) or dep_key == key:
                    continue
                if not any(pkg in (entry.get(f) or {}) for f in _DEP_FIELDS):
                    continue
                if _resolve(packages, dep_key, pkg) != key:
                    continue
                if dep_key == "":
                    kind = "direct"
                    continue
                name = entry.get("name") or dep_key.rsplit("node_modules/", 1)[-1]
                if name not in parents:
                    parents.append(name)
        if kind == "direct":
            return "direct", []
        return ("transitive", sorted(parents)) if parents else ("", [])
    deps = doc.get("dependencies")
    if isinstance(deps, dict) and deps:
        parents = []

        def walk(tree: dict) -> None:
            for name, entry in tree.items():
                if not isinstance(entry, dict):
                    continue
                if pkg in (entry.get("requires") or {}) and name != pkg and name not in parents:
                    parents.append(name)
                if isinstance(entry.get("dependencies"), dict):
                    walk(entry["dependencies"])
        walk(deps)
        if pkg in deps and not parents:
            return "direct", []
        return ("transitive", sorted(parents)) if parents else ("", [])
    return "", []


_NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json")


def _relpath(finding: dict) -> str:
    return str(finding.get("file") or "").replace("\\", "/")


def _deprecated_remediation(finding: dict, pkg: str, installed: str) -> str:
    """A deprecated version has no CVE to fix — the fix is getting off it, usually via the parent."""
    path, parents = finding.get("dependency_path"), finding.get("introduced_by") or []
    if path == "direct":
        how = (f"Upgrade {pkg} to a maintained release, or replace it with the successor its "
               f"deprecation notice names (`npm view {pkg}@{installed} deprecated`).")
    elif path in ("transitive", "bundled") and parents:
        via = ", ".join(parents[:4]) + (" and others" if len(parents) > 4 else "")
        how = (f"It is pulled in by {via}. Upgrade that package to a release that no longer depends "
               f"on {pkg} {installed}, then regenerate the lockfile.")
    else:
        how = (f"Find what pulls it in (`npm ls {pkg}`), upgrade that package to a release that no "
               f"longer uses it, then regenerate the lockfile.")
    return (f"{pkg} {installed} is deprecated by its maintainer, so it gets no more fixes: the next "
            f"advisory against it will have no upgrade path. " + how)


def remediation(finding: dict) -> str:
    """The one-paragraph fix for an annotated SCA finding (see annotate)."""
    pkg, installed = finding.get("pkg") or "the package", finding.get("installed") or "?"
    if finding.get("deprecated"):
        return _deprecated_remediation(finding, pkg, installed)
    target, cve = finding.get("fix_target") or "", finding.get("cve") or "this advisory"
    where = _relpath(finding)
    if not target:
        text = (f"No fixed version of {pkg} is published for {cve}. Check whether your code uses the "
                f"affected feature, apply the advisory's workaround if one exists, and watch the advisory "
                f"for a release.")
        if finding.get("artifact") == "binary":
            text += (f" {pkg} is embedded in the compiled binary `{where}`; if that file is a tool and not "
                     f"part of your product, keep it out of the repository and the scanned checkout.")
        return text
    major = ""
    if finding.get("fix_major_bump"):
        major = (f" The {installed} release line has no fix: {target} is a MAJOR upgrade, so expect "
                 f"breaking changes and run the full test suite.")
    all_fix = finding.get("fix_all_target") or ""
    if all_fix and all_fix != target:
        major += (f" {finding.get('package_advisories', 'Several')} advisories affect {pkg} {installed};"
                  f" {all_fix} is the lowest version that clears all of them.")
    if finding.get("artifact") == "binary":
        # The reader does not edit this module; a major-line note would be noise here.
        built = f"Go {target}" if pkg == "stdlib" else f"{pkg} {target}"
        embeds = f"the Go {installed} standard library" if pkg == "stdlib" else f"{pkg} {installed}"
        return (f"`{where}` is a compiled binary that embeds {embeds}. Upgrade that tool to a "
                f"release built with {built} or later, or rebuild it. If a pipeline downloads the "
                f"tool, download it outside the scanned checkout so it is not committed, shipped or "
                f"scanned as part of the app.")
    if finding.get("dependency_path") == "bundled":
        parent = (finding.get("introduced_by") or ["its parent package"])[0]
        return (f"{pkg} {installed} is bundled inside {parent}, so an override or resolution cannot "
                f"replace it. Upgrade {parent} to a release that bundles {pkg} {target} or later, then "
                f"regenerate the lockfile." + major)
    if finding.get("dependency_path") == "transitive":
        parents = finding.get("introduced_by") or []
        via = f" (pulled in by {', '.join(parents[:4])}{' and others' if len(parents) > 4 else ''})" if parents else ""
        return (f"{pkg} {installed} is a transitive dependency{via}. Upgrade the parent to a release "
                f"that requires {pkg} {target} or later, then regenerate the lockfile. Use an "
                f"override or resolution for {pkg} only if no parent release has the fix, and test it."
                + major)
    return (f"Upgrade {pkg} from {installed} to {target} and regenerate the lockfile." + major)


def annotate(findings: list, target=None) -> dict:
    """Add fix_target / fix_major_bump / dependency_path / introduced_by / remediation to SCA rows.

    Mutates in place and returns counts for the run summary. Additive only: severity, identity and
    the number of findings never change here."""
    root = Path(target) if target else None
    locks: dict = {}
    counts = {"annotated": 0, "major_bump": 0, "transitive": 0, "binary": 0, "no_fix": 0}
    rows = [f for f in findings if f.get("category") == "sca"]
    for f in rows:
        f["fix_target"], f["fix_major_bump"] = pick_fix(f.get("installed", ""), f.get("fixed", ""),
                                                        f.get("ecosystem", ""))
    # One package version with several advisories: the version that clears ALL of them is what a
    # reader upgrades to, so say it on each row (4.2.5 fixes two, 5.6.0 fixes four).
    by_pkg: dict = {}
    for f in rows:
        if f.get("artifact") != "binary" and not f.get("deprecated"):
            by_pkg.setdefault((_relpath(f), f.get("pkg"), f.get("installed")), []).append(f)
    for group in by_pkg.values():
        if len(group) < 2:
            continue
        clear_all = _clears_all(group[0].get("installed", ""), [g.get("fixed", "") for g in group],
                                group[0].get("ecosystem", ""))
        if clear_all:
            for g in group:
                g["fix_all_target"], g["package_advisories"] = clear_all, len(group)
    for f in rows:
        target_version, major = f["fix_target"], f["fix_major_bump"]
        rel = _relpath(f)
        if root is not None and f.get("artifact") != "binary" and rel.rsplit("/", 1)[-1] in _NPM_LOCKS:
            if rel not in locks:
                locks[rel] = _load_lock(root / rel)
            doc = locks[rel]
            if doc is not None:
                path, parents = npm_paths(doc, f.get("pkg", ""), f.get("installed", ""))
                if path:
                    f["dependency_path"] = path
                if parents:
                    f["introduced_by"] = parents
        f["remediation"] = remediation(f)
        # Two advisories on one package used to render as two identical "pkg 1.0 → 2.0" rows.
        # Name the advisory and the version to move to; say when it is a major upgrade.
        if f.get("deprecated"):
            f["fix_target"], f["fix_major_bump"] = "", False
            counts["deprecated"] = counts.get("deprecated", 0) + 1
            continue
        cve = f.get("cve") or f.get("key") or ""
        inside = f" in binary {rel}" if f.get("artifact") == "binary" else ""
        fix = target_version or "no fix published"
        # Keep the old title shape so a v1 (title-hashed) baseline alias still matches this row.
        f.setdefault("title_previous", f.get("title", ""))
        f["title"] = (f"{f.get('pkg', '')} {f.get('installed', '')}{inside} — {cve} → {fix}"
                      + (" (major upgrade)" if major and not inside else ""))
        counts["annotated"] += 1
        counts["major_bump"] += int(major)
        counts["transitive"] += int(f.get("dependency_path") in ("transitive", "bundled"))
        counts["binary"] += int(f.get("artifact") == "binary")
        counts["no_fix"] += int(not target_version)
    return counts

"""Integration and low-code source that `Path.suffix` cannot classify (#249).

A MuleSoft API keeps its logic in flow XML and DataWeave; a Salesforce org keeps access-control
logic in Flow, Visualforce and Aura metadata; a Marketing Cloud page runs AMPscript/SSJS inside an
`.html` file. Classified by compound suffix, path or a bounded content probe, never by `.xml`
alone (that would catch every `pom.xml`).

Each dialect is either read by a named profile (`PROFILE_DIALECTS`) or disclosed as a language
without an analyzer. Nothing here is silently dropped.
"""
from __future__ import annotations

import re
from pathlib import Path

PROBE_BYTES = 64 * 1024
_MULE_ROOT = re.compile(r"<mule\b[^>]*xmlns=[\"']http://www\.mulesoft\.org/schema/mule/core", re.I)
_AMPSCRIPT = re.compile(r"%%\[|%%=|<script\b[^>]*runat\s*=\s*[\"']?server", re.I)
_VISUALFORCE = re.compile(r"<apex:(?:page|component)\b", re.I)

# dialect -> the profile that reads it (dialects absent here have no analyzer)
PROFILE_DIALECTS = {"mule-flow-xml": "mule", "dataweave": "mule", "salesforce-flow": "salesforce-metadata",
                    "visualforce": "salesforce-metadata", "aura-markup": "salesforce-metadata"}
UNANALYZED_DIALECTS = {"ampscript"}


def _head(path: Path, limit: int = PROBE_BYTES) -> str:
    try:
        with open(path, "rb") as stream:
            return stream.read(limit).decode("utf-8", errors="ignore")
    except OSError:
        return ""


def classify(path: Path, rel: str, read_path: Path | None = None) -> str | None:
    """The dialect of one walked file, or None for ordinary files.

    `read_path` is the walker's resolved, containment-checked path; content probes read only it.
    """
    name = path.name.lower()
    probe = read_path or path
    rel = rel.replace("\\", "/")
    suffix = path.suffix.lower()
    if suffix == ".dwl":
        return "dataweave"
    if name.endswith(".flow-meta.xml"):
        return "salesforce-flow"
    if suffix == ".xml":
        if re.search(r"(?:^|/)src/main/mule/", rel) and not name.endswith("-meta.xml"):
            return "mule-flow-xml"
        if not name.endswith(("pom.xml", "-meta.xml")) and _MULE_ROOT.search(_head(probe, 4096)):
            return "mule-flow-xml"
        return None
    if suffix in (".page", ".component"):
        return "visualforce" if _VISUALFORCE.search(_head(probe)) else None
    if suffix in (".cmp", ".app", ".evt", ".intf", ".design", ".tokens") and re.search(r"(?:^|/)aura/", rel):
        return "aura-markup"
    if suffix in (".html", ".htm", ".amp", ".ampscript"):
        return "ampscript" if (suffix in (".amp", ".ampscript") or _AMPSCRIPT.search(_head(probe))) else None
    return None

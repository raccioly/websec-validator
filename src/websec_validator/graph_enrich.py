"""Optional blast-radius enrichment from a graphify knowledge graph.

If the scanned repo already has a `graphify-out/graph.json` (from the `graphify` tool), websec reads it
— plain JSON, stdlib only, no tree-sitter, no new dependency — and answers "how much of the app
depends on this vulnerable code?" for each finding. A SQLi in a leaf handler and the same SQLi in a
shared query helper imported by 40 modules are not equally urgent; the graph makes that difference
visible.

Mapping: a finding's `location` (a repo-relative file, optionally `:line`) is matched to graph nodes
by `source_file`. Blast radius = the count of distinct nodes that transitively DEPEND ON the finding's
node(s) — i.e. reverse reachability over dependency edges (calls / imports / references / inherits /
uses / …). A hub file legitimately yields a large radius; that is the signal, not a bug.

Design constraints (AGENTS.md): stdlib only; must never crash a run (the CLI calls this under a
try/except and it also guards internally); coverage bounds are DISCLOSED, never silently applied.
"""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path

# The graph is directed as `dependent -> dependency` for these relations (A calls/imports B ⇒ edge
# A→B), so the nodes AFFECTED by a vulnerable B are B's predecessors — found by walking edges in
# reverse. This mirrors graphify's own affected-set relation list.
_DEPENDENCY_RELATIONS = frozenset({
    "calls", "indirect_call", "references", "imports", "imports_from", "re_exports",
    "inherits", "extends", "implements", "uses", "mixes_in", "embeds",
})

# Bound the reverse-BFS so a hub node in a huge graph can't blow up a run. If we hit the cap we say so
# (truncated=True) rather than silently under-report — a capped radius still reads as "very large".
_MAX_VISIT = 20000

# Cap the human-facing dependents sample; the count is always exact (up to _MAX_VISIT).
_SAMPLE = 8


def _norm(path: str) -> str:
    p = (path or "").replace("\\", "/").strip()
    while p.startswith("./"):
        p = p[2:]
    return p


def _location_file(location: str) -> str:
    """A finding's `location` is a file, sometimes `file:42` or `file:L42` — take the file part."""
    loc = _norm(location)
    # Strip a trailing :NN or :LNN line reference (but keep Windows drive colons, which have a letter
    # before them, not a digit/L — so only strip when the tail after ':' is a line ref).
    if ":" in loc:
        head, _, tail = loc.rpartition(":")
        t = tail[1:] if tail[:1] in ("L", "l") else tail
        if head and t.isdigit():
            loc = head
    return loc


def load_graph(graph_path: Path) -> dict | None:
    try:
        data = json.loads(graph_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or "nodes" not in data:
        return None
    return data


def _build_index(graph: dict):
    """Return (file -> [node_id], reverse_adjacency, node_by_id) over dependency edges only."""
    nodes = graph.get("nodes") or []
    node_by_id: dict[str, dict] = {}
    file_to_nodes: dict[str, list[str]] = {}
    for n in nodes:
        nid = n.get("id")
        if nid is None:
            continue
        node_by_id[nid] = n
        sf = _norm(n.get("source_file", ""))
        if sf:
            file_to_nodes.setdefault(sf, []).append(nid)
    reverse: dict[str, list[str]] = {}
    for e in (graph.get("links") or graph.get("edges") or []):
        if e.get("relation") not in _DEPENDENCY_RELATIONS:
            continue
        src, tgt = e.get("source"), e.get("target")
        if src is None or tgt is None:
            continue
        reverse.setdefault(tgt, []).append(src)  # who depends on tgt
    return file_to_nodes, reverse, node_by_id


def _match_nodes(loc_file: str, file_to_nodes: dict[str, list[str]]) -> list[str]:
    if not loc_file:
        return []
    if loc_file in file_to_nodes:
        return file_to_nodes[loc_file]
    # Fall back to a suffix match — finding paths and graph paths may be anchored differently
    # (e.g. one repo-relative, one package-relative). Prefer the longest unambiguous suffix.
    hits = [f for f in file_to_nodes if f.endswith("/" + loc_file) or loc_file.endswith("/" + f)]
    if len(hits) == 1:
        return file_to_nodes[hits[0]]
    # Last resort: basename match, only if it identifies exactly one file.
    base = loc_file.rsplit("/", 1)[-1]
    bhits = [f for f in file_to_nodes if f.rsplit("/", 1)[-1] == base]
    return file_to_nodes[bhits[0]] if len(bhits) == 1 else []


def _blast_radius(seed_ids: list[str], reverse: dict[str, list[str]], node_by_id: dict[str, dict]):
    """Reverse-BFS from the seed nodes; return (count, sample_labels, truncated)."""
    seen: set[str] = set(seed_ids)
    q: deque[str] = deque(seed_ids)
    dependents: list[str] = []
    truncated = False
    while q:
        cur = q.popleft()
        for pred in reverse.get(cur, ()):
            if pred in seen:
                continue
            seen.add(pred)
            dependents.append(pred)
            q.append(pred)
            if len(seen) >= _MAX_VISIT:
                truncated = True
                q.clear()
                break
    def _label(nid: str) -> str:
        n = node_by_id.get(nid, {})
        return str(n.get("label") or n.get("source_file") or nid)
    sample = [_label(nid) for nid in dependents[:_SAMPLE]]
    return len(dependents), sample, truncated


def enrich_ledger(ledger: dict, target: Path, graph_path: Path | None = None) -> dict:
    """Attach a `graph` block to each finding whose location maps to a graph node, plus a ledger-level
    `graph_enrichment` summary. No-op (ledger returned unchanged) when no graph is present.

    Callers should still wrap this in try/except — enrichment must never fail a run.
    """
    gp = graph_path or (target / "graphify-out" / "graph.json")
    if not gp.exists():
        return ledger
    graph = load_graph(gp)
    if graph is None:
        return ledger

    file_to_nodes, reverse, node_by_id = _build_index(graph)
    findings = ledger.get("findings") or []
    mapped = 0
    max_radius = 0
    any_truncated = False
    for f in findings:
        nodes = _match_nodes(_location_file(f.get("location", "")), file_to_nodes)
        if not nodes:
            continue
        radius, sample, truncated = _blast_radius(nodes, reverse, node_by_id)
        community = node_by_id.get(nodes[0], {}).get("community")
        f["graph"] = {
            "nodes": nodes,
            "blast_radius": radius,
            "dependents": sample,
            "community": community,
            "truncated": truncated,
        }
        mapped += 1
        max_radius = max(max_radius, radius)
        any_truncated = any_truncated or truncated

    ledger["graph_enrichment"] = {
        "graph": str(gp),
        "built_at_commit": graph.get("built_at_commit"),
        "nodes": len(node_by_id),
        "mapped": mapped,
        "unmapped": len(findings) - mapped,
        "max_blast_radius": max_radius,
        "visit_cap": _MAX_VISIT,
        "truncated": any_truncated,
    }
    return ledger

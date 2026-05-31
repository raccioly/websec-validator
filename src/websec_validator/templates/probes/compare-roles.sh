#!/usr/bin/env bash
# compare-roles.sh — diff two ZAP role-scoped SARIF reports.
#
# Usage:
#   ./run.sh agent          # produces zap-report-sarif-agent.json
#   ./run.sh admin          # produces zap-report-sarif-admin.json
#   ./compare-roles.sh      # prints the access-control delta
#
# What it shows:
#   - Routes ADMIN can reach that AGENT cannot      → expected; verifies authz
#   - Routes AGENT can reach that ADMIN cannot      → almost always wrong; investigate
#   - Routes both can reach                         → no role distinction (may be intentional public)
#
# This is the "two-role diff" step. Without it, the active scan only proves what one
# role can see; the diff is what proves cross-role access control actually works.
set -euo pipefail
cd "$(dirname "$0")"

AGENT="zap-report-sarif-agent.json"
ADMIN="zap-report-sarif-admin.json"

[[ -f "$AGENT" ]] || { echo "missing $AGENT — run ./run.sh agent first" >&2; exit 1; }
[[ -f "$ADMIN" ]] || { echo "missing $ADMIN — run ./run.sh admin first" >&2; exit 1; }

python3 - <<PY
import json, re
from collections import defaultdict

def load_urls(path):
    """Return {normalized_path: set(method)} of every URL ZAP touched."""
    with open(path) as f:
        sarif = json.load(f)
    out = defaultdict(set)
    for r in sarif["runs"][0]["results"]:
        for loc in r.get("locations", []):
            uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            if not uri.startswith("http"): continue
            # strip host + querystring, normalize ids/uuids/slugs
            path = re.sub(r"https?://[^/]+", "", uri).split("?")[0]
            path = re.sub(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f-]{20,}", "/{uuid}", path)
            path = re.sub(r"/[0-9a-f]{20,}", "/{id}", path)
            path = re.sub(r"/\d+(?=/|\$)", "/{n}", path)
            out[path].add(r.get("properties", {}).get("method", "?"))
    return out

agent = load_urls("$AGENT")
admin = load_urls("$ADMIN")

agent_only = set(agent) - set(admin)
admin_only = set(admin) - set(agent)
both       = set(agent) & set(admin)

print(f"=== AGENT touched {len(agent)} distinct path patterns ===")
print(f"=== ADMIN touched {len(admin)} distinct path patterns ===")
print()
print(f"--- Paths AGENT reached that ADMIN did not ({len(agent_only)}) ---")
print("    These are SUSPICIOUS — admin should see everything agent sees.")
for p in sorted(agent_only): print(f"  AGENT-ONLY  {p}")
print()
print(f"--- Paths ADMIN reached that AGENT did not ({len(admin_only)}) ---")
print("    These should match the access-control matrix (admin-only routes).")
for p in sorted(admin_only): print(f"  ADMIN-ONLY  {p}")
print()
print(f"--- Paths both reached ({len(both)}) ---")
print("    These are routes neither blocked at the auth/authz layer for either role.")
print("    Verify against access-control-matrix.md — anything here that should be")
print("    admin-only is a real access-control gap.")
for p in sorted(both): print(f"  BOTH        {p}")
PY

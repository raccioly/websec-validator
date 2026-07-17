#!/usr/bin/env bash
# Refresh the local EPSS + CISA-KEV cache that websec's exploitability enricher reads.
#
# This is the ONLY network step in the exploitability feature — websec itself stays offline and
# read-only; it just JOINs whatever cache this script leaves on disk. Run it periodically (e.g. a
# daily cron / CI cache step). Both sources are free, public, and require no auth.
#
#   EPSS  — FIRST.org daily "epss_scores-current.csv.gz"  (exploit probability per CVE)
#   KEV   — CISA "known_exploited_vulnerabilities.json"   (vulns known-exploited in the wild)
#
# Cache location (first match): $WEBSEC_ENRICH_DIR, else ${XDG_CACHE_HOME:-~/.cache}/websec
set -euo pipefail

CACHE_DIR="${WEBSEC_ENRICH_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/websec}"
mkdir -p "$CACHE_DIR"

EPSS_URL="https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

echo "websec: refreshing EPSS + KEV cache → $CACHE_DIR"

# --- EPSS (gzipped CSV; header lines begin with '#model_version', then a 'cve,epss,percentile' row) ---
if curl -fsSL "$EPSS_URL" -o "$CACHE_DIR/epss.csv.gz"; then
  gunzip -f "$CACHE_DIR/epss.csv.gz"     # → epss.csv
  epss_rows=$(grep -c '^CVE-' "$CACHE_DIR/epss.csv" || true)
  echo "  EPSS:  $epss_rows CVEs  ($CACHE_DIR/epss.csv)"
else
  echo "  EPSS:  download FAILED (leaving any existing cache in place)" >&2
fi

# --- CISA KEV (JSON) ---
if curl -fsSL "$KEV_URL" -o "$CACHE_DIR/kev.json.tmp"; then
  mv "$CACHE_DIR/kev.json.tmp" "$CACHE_DIR/kev.json"
  kev_n=$(grep -c '"cveID"' "$CACHE_DIR/kev.json" || true)
  echo "  KEV:   $kev_n known-exploited CVEs  ($CACHE_DIR/kev.json)"
else
  rm -f "$CACHE_DIR/kev.json.tmp"
  echo "  KEV:   download FAILED (leaving any existing cache in place)" >&2
fi

echo "websec: done. CVE findings will now carry EPSS probability + KEV flags."

# Source-only transport library for manually executed shell drafts, not a probe template.
WEBSEC_PROBE_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
curl() {
  python3 "$WEBSEC_PROBE_DIR/_lib.py" --curl "$@" || exit 2
}

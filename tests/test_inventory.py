"""Attack-Surface Inventory — the ranked per-endpoint planning table (routes × guards × sinks)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator import inventory  # noqa: E402


def _facts(endpoints, guards=(), sinks=None, targeting=None, target=None):
    return {
        "target": target,
        "routes": {"endpoints": list(endpoints), "targeting": dict(targeting or {})},
        "authz": {"endpoint_guards": list(guards)},
        "surface": {"sinks": dict(sinks or {})},
    }


class InventoryTests(unittest.TestCase):
    def test_unguarded_write_outranks_guarded_read(self):
        f = _facts(
            endpoints=[{"method": "GET", "path": "/a", "code_path": "a.js"},
                       {"method": "POST", "path": "/b", "code_path": "b.js"}],
            guards=[{"method": "GET", "path": "/a", "guarded": True, "analyzed": True},
                    {"method": "POST", "path": "/b", "guarded": False, "analyzed": True,
                     "public_hint": False}])
        inv = inventory.build(f)
        self.assertEqual(inv["endpoints"][0]["path"], "/b")        # unguarded write ranks first
        self.assertEqual(inv["endpoints"][0]["auth"], "UNGUARDED")
        self.assertEqual(inv["summary"]["unguarded_writes"], 1)
        self.assertIn("write endpoint with no visible guard", inv["endpoints"][0]["why"])

    def test_unanalyzed_endpoint_is_unknown_not_unguarded(self):
        # never claim UNGUARDED when the analyzer didn't actually look (accuracy bar).
        f = _facts(endpoints=[{"method": "GET", "path": "/x", "code_path": "x.js"}],
                   guards=[{"method": "GET", "path": "/x", "guarded": False, "analyzed": False}])
        inv = inventory.build(f)
        self.assertEqual(inv["endpoints"][0]["auth"], "unknown")
        self.assertEqual(inv["summary"]["unguarded"], 0)

    def test_public_hint_not_counted_as_unguarded(self):
        f = _facts(endpoints=[{"method": "GET", "path": "/health", "code_path": "h.js"}],
                   guards=[{"method": "GET", "path": "/health", "guarded": False,
                            "analyzed": True, "public_hint": True}])
        inv = inventory.build(f)
        self.assertEqual(inv["endpoints"][0]["auth"], "public (intentional)")
        self.assertEqual(inv["summary"]["unguarded"], 0)

    def test_sink_attribution_is_file_scoped_and_says_so(self):
        f = _facts(endpoints=[{"method": "GET", "path": "/q", "code_path": "db.js"}],
                   sinks={"sql-injection": {"files": ["db.js"], "count": 1}})
        inv = inventory.build(f)
        row = inv["endpoints"][0]
        self.assertIn("sql-injection", row["sinks"])
        # wording must scope to the FILE, never assert the endpoint itself is vulnerable
        self.assertTrue(any("same file" in w for w in row["why"]))
        self.assertFalse(any("in handler:" in w for w in row["why"]))

    def test_absolute_route_path_normalized_to_relative(self):
        # Noir emits ABSOLUTE code_paths; guards/sinks are repo-relative — they must still join.
        import tempfile
        root = Path(tempfile.mkdtemp()).resolve()
        (root / "src").mkdir()
        f = _facts(endpoints=[{"method": "GET", "path": "/z", "code_path": str(root / "src" / "s.js")}],
                   sinks={"ssrf": {"files": ["src/s.js"], "count": 1}}, target=str(root))
        inv = inventory.build(f)
        self.assertEqual(inv["endpoints"][0]["handler"], "src/s.js")
        self.assertIn("ssrf", inv["endpoints"][0]["sinks"])       # joined despite abs vs rel

    def test_targeting_tags_raise_risk(self):
        f = _facts(endpoints=[{"method": "GET", "path": "/o/{id}", "code_path": "o.js",
                               "params": [{"name": "id", "where": "path"}]}],
                   targeting={"idor_candidates": ["GET /o/{id}"]})
        inv = inventory.build(f)
        row = inv["endpoints"][0]
        self.assertGreaterEqual(row["risk"], 3)
        self.assertTrue(any("IDOR" in w for w in row["why"]))
        self.assertEqual(row["path_params"], ["id"])

    def test_empty_surface_renders_gracefully(self):
        inv = inventory.build(_facts(endpoints=[]))
        self.assertEqual(inv["endpoints"], [])
        self.assertIn("No endpoints mapped", inventory.render_md(inv))

    def test_render_includes_ranked_table(self):
        f = _facts(endpoints=[{"method": "POST", "path": "/w", "code_path": "w.js"}],
                   guards=[{"method": "POST", "path": "/w", "guarded": False, "analyzed": True}])
        md = inventory.render_md(inventory.build(f))
        self.assertIn("| `POST /w` |", md)
        self.assertIn("Why test it", md)


if __name__ == "__main__":
    unittest.main()

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

    def test_same_path_services_keep_independent_guards(self):
        endpoints = [{"service_id": service, "method": "POST", "path": "/sensitive", "code_path": service + "/api.js"}
                     for service in ("billing", "admin")]
        guards = [{**endpoint, "guarded": endpoint["service_id"] == "admin", "analyzed": True} for endpoint in endpoints]
        for ordered in (guards, list(reversed(guards))):
            result = inventory.build(_facts(endpoints, ordered))
            self.assertEqual({"billing": "UNGUARDED", "admin": "guarded"},
                             {row["service_id"]: row["auth"] for row in result["endpoints"]})
            self.assertEqual(1, result["summary"]["unguarded_writes"])
            self.assertIn("`billing`", inventory.render_md(result))

    def test_same_service_different_source_does_not_share_guard(self):
        endpoints = [{"service_id": "api", "method": "POST", "path": "/same", "code_path": path}
                     for path in ("first.js", "second.js")]
        guards = [{**endpoints[0], "guarded": True, "analyzed": True},
                  {**endpoints[1], "guarded": False, "analyzed": True}]
        rows = inventory.build(_facts(endpoints, guards))["endpoints"]
        self.assertEqual({"first.js": "guarded", "second.js": "UNGUARDED"}, {r["handler"]: r["auth"] for r in rows})

    def test_ambiguous_legacy_guard_is_unknown_for_every_service(self):
        endpoints = [{"service_id": service, "method": "GET", "path": "/same", "code_path": service + "/api.js"}
                     for service in ("one", "two")]
        rows = inventory.build(_facts(endpoints, [{"method": "GET", "path": "/same", "guarded": True, "analyzed": True}]))["endpoints"]
        self.assertEqual(["unknown", "unknown"], [r["auth"] for r in rows])

    def test_conflicting_known_service_cannot_fallback_by_path(self):
        endpoints = [{"service_id": "one", "method": "GET", "path": "/same", "code_path": "api.js"}]
        guards = [{"service_id": "two", "method": "GET", "path": "/same", "code_path": "api.js", "guarded": True, "analyzed": True}]
        self.assertEqual("unknown", inventory.build(_facts(endpoints, guards))["endpoints"][0]["auth"])

    def test_absolute_guard_source_joins_relative_endpoint(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            endpoints = [{"method": "GET", "path": "/same", "code_path": "api.js"}]
            guards = [{"method": "GET", "path": "/same", "code_path": str(Path(directory) / "api.js"), "guarded": True, "analyzed": True}]
            self.assertEqual("guarded", inventory.build(_facts(endpoints, guards, target=directory))["endpoints"][0]["auth"])

    def test_noir_absolute_source_and_fallback_share_service_identity(self):
        import json
        import tempfile
        from unittest.mock import patch
        from websec_validator.extractors.base import RepoContext
        from websec_validator.extractors.stack import StackExtractor
        from websec_validator.extractors.routes import RoutesExtractor
        from websec_validator.extractors.authz import AuthzExtractor
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for service, framework, source in (
                    ("a", "fastify", 'fastify.addHook("onRequest", authenticate); fastify.post("/sensitive", handler);'),
                    ("b", "express", 'app.post("/sensitive", handler);')):
                (root / service).mkdir()
                (root / service / "package.json").write_text(json.dumps({"dependencies": {framework: "1"}}))
                (root / service / "server.js").write_text(source)
            context = RepoContext(root)
            facts = {"target": str(root), "stack": StackExtractor().extract(context, {})}
            # Include equivalent absolute/relative Noir rows and rely on the existing
            # heuristic for the other service, exactly as the real integration does.
            noir = [{"method": "POST", "path": "/sensitive", "details": {"code_paths": [{"path": path}]}}
                    for path in (str((root / "b/server.js").resolve()), "b/server.js")]
            with patch("websec_validator.extractors.routes._noir_scan", return_value=noir):
                facts["routes"] = RoutesExtractor().extract(context, facts)
            facts["authz"] = AuthzExtractor().extract(context, facts)
            self.assertEqual(2, len(facts["routes"]["endpoints"]))
            self.assertEqual({"a", "b"}, {row["service_id"] for row in facts["routes"]["endpoints"]})
            for endpoints in (facts["routes"]["endpoints"], list(reversed(facts["routes"]["endpoints"]))):
                facts["routes"]["endpoints"] = endpoints
                rows = inventory.build(facts)["endpoints"]
                self.assertEqual({"a": "guarded", "b": "UNGUARDED"}, {row["service_id"]: row["auth"] for row in rows})
                self.assertEqual({"a/server.js", "b/server.js"}, {row["handler"] for row in rows})




class TaggingPrecisionTests(unittest.TestCase):
    def test_prefix_does_not_over_fire_on_a_shorter_sibling_path(self):
        # `GET /api/user` must NOT inherit the IDOR tag belonging to `GET /api/users/{id}` — it would
        # flow into the test plan as a BOLA target aimed at the wrong endpoint.
        f = _facts(endpoints=[{"method": "GET", "path": "/api/user", "code_path": "u.js"}],
                   targeting={"idor_candidates": ["GET /api/users/{id}  (param: id)"]})
        row = inventory.build(f)["endpoints"][0]
        self.assertEqual(row["risk"], 0)
        self.assertEqual(row["why"], [])

    def test_exact_match_with_trailing_annotation_still_fires(self):
        f = _facts(endpoints=[{"method": "GET", "path": "/api/users/{id}", "code_path": "u.js"}],
                   targeting={"idor_candidates": ["GET /api/users/{id}  (param: id)"]})
        self.assertTrue(any("IDOR" in w for w in inventory.build(f)["endpoints"][0]["why"]))

if __name__ == "__main__":
    unittest.main()

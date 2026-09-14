"""Synthetic named-check controls; no production vulnerability-recall claim."""
import json
import plistlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.profiles import analyze, capabilities, service_for
from websec_validator.extractors.stack import StackExtractor
from websec_validator.extractors.surface import SurfaceExtractor
from websec_validator.extractors.routes import RoutesExtractor
from websec_validator.extractors.authz import AuthzExtractor


class ProfileTests(unittest.TestCase):
    def run_profile(self, files, excludes=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, content in files.items():
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            ctx = RepoContext(root, excludes=excludes)
            stack = StackExtractor().extract(ctx, {})
            facts = {"stack": stack}
            with patch("websec_validator.extractors.routes._noir_scan", return_value=None):
                facts["routes"] = RoutesExtractor().extract(ctx, facts)
            facts["surface"] = SurfaceExtractor().extract(ctx, facts)
            facts["authz"] = AuthzExtractor().extract(ctx, facts)
            return facts

    def test_direct_command_pairs(self):
        cases = [
            ("java", 'Runtime.getRuntime().exec(request.getParameter("cmd"));', 'new ProcessBuilder("printf", "%s", request.getParameter("name"));'),
            ("cs", 'Process.Start("sh", "-c " + Request.Query["cmd"]);', 'Process.Start("uptime");'),
            ("go", 'exec.Command("sh", "-c", r.FormValue("cmd"))', 'exec.Command("printf", "%s", r.FormValue("name"))'),
            ("rb", 'system(params[:command])', 'system("printf", "%s", params[:name])'),
            ("php", 'shell_exec($_GET["command"]);', 'shell_exec("uptime");'),
        ]
        for suffix, unsafe, safe in cases:
            with self.subTest(suffix=suffix):
                found = self.run_profile({"handler." + suffix: unsafe})["stack"]["profiles"]
                self.assertEqual(1, len(found["sink_occurrences"]))
                clean = self.run_profile({"handler." + suffix: safe})["stack"]["profiles"]
                self.assertEqual([], clean["sink_occurrences"])

    def test_direct_query_pairs(self):
        cases = [
            ("java", 'stmt.executeQuery("SELECT * FROM t WHERE id=" + request.getParameter("id"));', 'stmt.executeQuery("SELECT * FROM t");'),
            ("cs", 'db.FromSqlRaw("SELECT * FROM t WHERE id=" + Request.Query["id"]);', 'db.FromSqlRaw("SELECT * FROM t WHERE id={0}", Request.Query["id"]);'),
            ("go", 'db.Query("SELECT * FROM t WHERE id=" + r.FormValue("id"))', 'db.Query("SELECT * FROM t WHERE id=$1", r.FormValue("id"))'),
            ("rb", 'db.execute("SELECT * FROM t WHERE id=" + params[:id])', 'db.execute("SELECT * FROM t WHERE id=?", params[:id])'),
            ("php", '$pdo->query("SELECT * FROM t WHERE id=" . $_GET["id"]);', '$pdo->query("SELECT * FROM t");'),
        ]
        for suffix, unsafe, safe in cases:
            with self.subTest(suffix=suffix):
                self.assertEqual(1, len(self.run_profile({"handler." + suffix: unsafe})["stack"]["profiles"]["sink_occurrences"]))
                self.assertEqual([], self.run_profile({"handler." + suffix: safe})["stack"]["profiles"]["sink_occurrences"])

    def test_context_argument_and_string_pseudocode(self):
        facts = self.run_profile({"handler.go": 'db.QueryContext(ctx, "SELECT " + r.FormValue("q")); exec.CommandContext(ctx, "sh", "-c", r.FormValue("x"))'})
        self.assertEqual(2, len(facts["stack"]["profiles"]["sink_occurrences"]))
        facts = self.run_profile({"handler.java": '// Runtime.getRuntime().exec(request.getParameter("x"));\nString s = "request.getParameter(thing)"; stmt.executeQuery("request.getParameter(thing)");'})
        self.assertEqual([], facts["stack"]["profiles"]["sink_occurrences"])

    def test_multiple_same_line_sinks_reach_surface(self):
        facts = self.run_profile({"handler.java": 'Runtime.getRuntime().exec(request.getParameter("a")); Runtime.getRuntime().exec(request.getParameter("b"));'})
        self.assertEqual(2, len(facts["surface"]["sink_occurrences"]))
        self.assertEqual(2, len({r["semantic_id"] for r in facts["surface"]["sink_occurrences"]}))

    def test_android_explicit_config_pairs(self):
        manifest = '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><application android:usesCleartextTraffic="%s" /></manifest>'
        for value, count in (("true", 1), ("false", 0)):
            facts = self.run_profile({"app/build.gradle": 'plugins { id "com.android.application" }',
                                      "app/src/main/AndroidManifest.xml": manifest % value})
            self.assertEqual(count, len(facts["stack"]["profiles"]["findings"]))
            self.assertIn("android", [p["id"] for p in facts["stack"]["profiles"]["profiles"]])

    def test_ats_exceptions_are_advisory_and_scope_visible(self):
        for enabled, count in ((True, 1), (False, 0)):
            info = plistlib.dumps({"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": enabled,
                                                            "NSAllowsLocalNetworking": True}}).decode()
            findings = self.run_profile({"Info.plist": info})["stack"]["profiles"]["findings"]
            self.assertEqual(count, len(findings))
            if findings:
                self.assertIn("advisory", findings[0]["limitations"][0])

    def test_rust_certificate_pairs_and_receiver_uncertainty(self):
        for method in ("danger_accept_invalid_certs", "tls_danger_accept_invalid_certs"):
            for value, count in (("true", 1), ("false", 0)):
                facts = self.run_profile({"Cargo.toml": '[dependencies]\nreqwest = "0.12"', "src/main.rs": f'let client = Client::builder().{method}({value}).build();'})
                findings = facts["stack"]["profiles"]["findings"]
                self.assertEqual(count, len(findings))
                if findings:
                    self.assertIn("receiver", findings[0]["limitations"][0])

    def test_native_and_unreadable_configs_are_explicitly_unknown(self):
        facts = self.run_profile({"src/native.c": 'strcpy(dst, src);', "Info.plist": '<broken',
                                  "AndroidManifest.xml": '<broken'})
        profiles = facts["stack"]["profiles"]["profiles"]
        native = next(p for p in profiles if p["id"] == "native")
        self.assertEqual("manual", native["checks"][0]["status"])
        self.assertTrue(all(p["checks"][0]["status"] == "unknown" for p in profiles if p["id"] in ("ios", "android")))

    def test_repeated_rust_configuration_occurrences_remain_distinct(self):
        facts = self.run_profile({"relay.rs": 'reqwest::Client::builder().danger_accept_invalid_certs(true); reqwest::Client::builder().danger_accept_invalid_certs(true);'})
        self.assertEqual(2, len({row["semantic_id"] for row in facts["stack"]["profiles"]["findings"]}))

    def test_php_interpolation_and_literal_control(self):
        for text, count in [('shell_exec("cat {$_GET[\'file\']}");', 1),
                            ('shell_exec("cat $_GET[file]");', 1),
                            ('''shell_exec('cat $_GET[file]');''', 0)]:
            self.assertEqual(count, len(self.run_profile({"app.php": text})["stack"]["profiles"]["sink_occurrences"]))

    def test_ruby_literal_hash_condition_is_parameterized(self):
        for text, count in [('User.where(id: params[:id])', 0),
                            ('User.where({id: params[:id]})', 0),
                            ('User.where("id=" + params[:id])', 1)]:
            self.assertEqual(count, len(self.run_profile({"app.rb": text})["stack"]["profiles"]["sink_occurrences"]))

    def test_java_argv_array_does_not_make_argument_a_shell_command(self):
        for args, count in [('"printf", "%s", request.getParameter("name")', 0),
                            ('"sh", "-c", request.getParameter("command")', 1),
                            ('request.getParameter("program"), "--version"', 1)]:
            text = 'Runtime.getRuntime().exec(new String[]{' + args + '});'
            facts = self.run_profile({"App.java": text})
            self.assertEqual(count, len(facts["stack"]["profiles"]["sink_occurrences"]))
            self.assertEqual(count, facts["surface"]["sink_counts"].get("command-injection", 0))

    def test_configuration_parse_failures_expose_error_contract(self):
        for name in ('AndroidManifest.xml', 'Info.plist'):
            bad = self.run_profile({name: '<broken'})["stack"]["profiles"]
            self.assertEqual(name, bad["errors"][0]["file"])
            self.assertTrue(bad["errors"][0]["error"])
        clean = self.run_profile({'AndroidManifest.xml': '<manifest><application /></manifest>'})["stack"]["profiles"]
        self.assertEqual([], clean["errors"])

    def test_service_boundaries_are_component_safe(self):
        facts = self.run_profile({"package.json": '{}', "api/package.json": '{"dependencies":{"express":"1","pg":"1"}}',
                                  "api2/package.json": '{"dependencies":{"mongodb":"1"}}',
                                  "api/handler.js": 'db.query("SELECT " + input);',
                                  "api2/handler.js": 'db.query("SELECT " + input);'})
        inventory = facts["stack"]["service_inventory"]
        self.assertEqual("api2", service_for(inventory, "api2/handler.js")["id"])
        self.assertEqual(["api/handler.js"], facts["surface"]["sinks"]["sql-injection"]["files"])
        self.assertEqual(3, facts["stack"]["services"])

    def test_request_evidence_survives_other_service_datastore(self):
        facts = self.run_profile({"mongo/package.json": '{"dependencies":{"mongodb":"1"}}',
                                  "unknown/package.json": '{}',
                                  "unknown/server.ts": 'db.query("SELECT " + req.query.id);'})
        self.assertIn("unknown/server.ts", facts["surface"]["sinks"]["sql-injection"]["files"])

    def test_duplicate_paths_survive_across_services(self):
        facts = self.run_profile({"a/package.json": '{"dependencies":{"express":"1"}}',
                                  "b/package.json": '{"dependencies":{"express":"1"}}',
                                  "a/server.js": 'app.get("/health", handler)',
                                  "b/server.js": 'app.get("/health", handler)'})
        endpoints = facts["routes"]["endpoints"]
        self.assertEqual(2, len(endpoints))
        self.assertEqual({"a", "b"}, {r["service_id"] for r in endpoints})

    def test_spring_and_dotnet_routes(self):
        facts = self.run_profile({"java/pom.xml": '<project>spring-web</project>',
                                  "java/Controller.java": '@GetMapping("/items") public String get() {}',
                                  "dotnet/App.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web" />',
                                  "dotnet/Program.cs": 'app.MapGet("/items", () => "ok");'})
        endpoints = facts["routes"]["endpoints"]
        self.assertEqual(2, len(endpoints))
        self.assertEqual({"java", "dotnet"}, {r["service_id"] for r in endpoints})

    def test_single_class_literal_prefixes(self):
        facts = self.run_profile({"Controller.java": '@RequestMapping("/v2") class Search { @GetMapping("/entries") String entries() {} }',
                                  "Invoice.cs": '[Route("api/[controller]")] class InvoiceController { [HttpGet("{id}")] public string Get() {} }'})
        self.assertEqual({"/v2/entries", "/api/Invoice/{id}"}, {r["path"] for r in facts["routes"]["endpoints"]})

    def test_input_boundaries_and_check_counts(self):
        facts = self.run_profile({"service.go": 'package main\nfunc main(){ println(os.Args) }; // comment is ignored\n',
                                  "worker.java": '@Scheduled void run() {}',
                                  "view.swift": 'let field = UITextField()'})
        self.assertEqual({"cli", "jobs", "native"}, set(facts["stack"]["service_inventory"][0]["input_boundaries"]))
        profile = next(p for p in facts["stack"]["profiles"]["profiles"] if p["id"] == "go")
        self.assertTrue(all(c["examined"] == 1 and c["status"] == "completed" for c in profile["checks"]))

    def test_fastify_hook_cannot_guard_neighboring_service(self):
        facts = self.run_profile({"a/package.json": '{"dependencies":{"fastify":"1"}}',
                                  "b/package.json": '{"dependencies":{"express":"1"}}',
                                  "a/server.js": 'fastify.addHook("onRequest", authenticate); fastify.post("/sensitive", handler);',
                                  "b/server.js": 'app.post("/sensitive", handler);'})
        guards = {row["service_id"]: row["guarded"] for row in facts["authz"]["endpoint_guards"]}
        self.assertEqual({"a": True, "b": False}, guards)

    def test_mixed_frameworks_or_other_instance_do_not_inherit_hook(self):
        for package, source in [('{"dependencies":{"fastify":"1","express":"1"}}',
                                 'fastify.addHook("onRequest", authenticate); app.post("/secret", handler);'),
                                ('{"dependencies":{"fastify":"1"}}',
                                 'other.addHook("onRequest", authenticate); fastify.post("/secret", handler);'),
                                ('{"dependencies":{"fastify":"1"}}',
                                 'other.addHook("onRequest", requireAuth); fastify.post("/secret", handler);'),
                                ('{"dependencies":{"fastify":"1"}}',
                                 'fastify.post("/secret", handler); fastify.addHook("onRequest", authenticate);')]:
            facts = self.run_profile({"package.json": package, "server.js": source})
            self.assertFalse(facts["authz"]["endpoint_guards"][0]["guarded"])

    def test_router_factory_names_do_not_cross_services(self):
        facts = self.run_profile({"a/package.json": '{"dependencies":{"express":"1"}}',
                                  "b/package.json": '{"dependencies":{"express":"1"}}',
                                  "a/server.js": 'app.use("/", requireAuth, createSecretRouter());',
                                  "a/routes.js": 'function createSecretRouter() { router.post("/secret", handler); }',
                                  "b/routes.js": 'function createSecretRouter() { router.post("/secret", handler); }'})
        guards = {row["service_id"]: row["guarded"] for row in facts["authz"]["endpoint_guards"]}
        self.assertEqual({"a": True, "b": False}, guards)

    def test_fastify_child_hook_cannot_escape_plugin_scope(self):
        source = '''const app=require('fastify')();
app.register(async function privatePlugin(app) {
  app.addHook('onRequest', authenticate);
  app.post('/inside', handler);
});
app.post('/outside', handler);'''
        facts = self.run_profile({"package.json": '{"dependencies":{"fastify":"1"}}', "app.js": source})
        self.assertEqual({"/inside": True, "/outside": False},
                         {row["path"]: row["guarded"] for row in facts["authz"]["endpoint_guards"]})

    def test_fastify_expression_plugin_hook_is_unverified_outside(self):
        source = '''const app=require('fastify')();
app.register(app => app.addHook('onRequest', authenticate));
app.post('/outside', handler);'''
        facts = self.run_profile({"package.json": '{"dependencies":{"fastify":"1"}}', "app.js": source})
        self.assertFalse(facts["authz"]["endpoint_guards"][0]["guarded"])

    def test_fastify_same_path_in_child_and_root_stays_unverified(self):
        source = '''app.register(async function plugin(app) {
app.addHook('onRequest', authenticate); app.post('/same', handler);
}); app.post('/same', handler);'''
        facts = self.run_profile({"package.json": '{"dependencies":{"fastify":"1"}}', "app.js": source})
        self.assertFalse(facts["authz"]["endpoint_guards"][0]["guarded"])

    def test_exclusions_and_fixture_sources_remain_excluded(self):
        facts = self.run_profile({"private/handler.php": 'system($_GET["cmd"]);',
                                  "tests/fixture.php": 'system($_GET["cmd"]);'}, excludes=["private/**"])
        self.assertEqual([], facts["stack"]["profiles"]["sink_occurrences"])

    def test_catalog_does_not_imply_whole_language_analysis(self):
        catalog = capabilities()
        self.assertIn("not whole-language", catalog["scope"])
        self.assertEqual(9, len(catalog["profiles"]))
        self.assertTrue(all(row["limitations"] for row in catalog["profiles"]))

    def test_packaged_holdout_cases(self):
        cases = json.loads((Path(__file__).resolve().parents[1] / "src/websec_validator/research/profile-cases.json").read_text())
        self.assertEqual("synthetic named-check controls; not production recall", cases["scope"])
        for case in cases["cases"]:
            with self.subTest(case=case["id"]):
                analysis = self.run_profile(case["files"])["stack"]["profiles"]
                rows = analysis["findings"] + analysis["sink_occurrences"]
                observed = sum(row.get("rule_id") == case["rule_id"] for row in rows)
                self.assertEqual(case["expected_findings"], observed)


if __name__ == "__main__":
    unittest.main()

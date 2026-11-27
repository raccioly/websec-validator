"""#244: below a JVM source root, path segments are package names, not directory roles."""
import unittest

from _jvm_repo import TempRepo
from websec_validator.extractors.base import (RepoContext, is_doc_or_example, is_script_file, is_test_file,
                                               path_in_skip_dir, role_path)

CONTROLLER = """package {pkg};
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/orders")
public class OrderController {{
    private final JdbcTemplate jdbc;
    @GetMapping("/search")
    public Object search(@RequestParam String name) {{
        return jdbc.query("SELECT id FROM orders WHERE name = '" + name + "'", mapper);
    }}
}}
"""


class RolePathTests(unittest.TestCase):
    def test_package_segments_carry_no_role(self):
        for rel in ("src/main/java/com/example/shop/A.java", "svc/src/main/java/com/acme/build/A.java",
                    "src/main/kotlin/com/acme/tool/A.kt", "src/main/java/com/acme/migration/A.java",
                    "src/main/java/com/acme/ops/A.java"):
            with self.subTest(rel=rel):
                self.assertFalse(is_script_file(rel))
                self.assertFalse(is_test_file(rel))
                self.assertFalse(is_doc_or_example(rel))
                self.assertFalse(path_in_skip_dir(rel))

    def test_roles_above_the_root_still_apply(self):
        self.assertTrue(path_in_skip_dir("svc/build/generated/src/main/java/com/acme/A.java"))
        self.assertTrue(is_doc_or_example("examples/demo/src/main/java/com/acme/A.java"))
        self.assertTrue(is_test_file("svc/src/test/java/com/acme/ATest.java"))
        self.assertTrue(is_script_file("tools/gen/src/main/java/com/acme/Gen.java"))
        self.assertEqual(role_path("a/src/main/java/com/acme/build/", directory=True), "a/src/main/java/")


class PackageScanTests(TempRepo):
    def scan(self, package):
        self.pom()
        self.write(f"src/main/java/{package}/OrderController.java", CONTROLLER.format(pkg=package.replace("/", ".")))
        facts = self.facts()
        return facts, sorted((f["attack_class"], f["severity"]) for f in self.ledger(facts)
                             if f["attack_class"] in ("missing-auth", "sqli"))

    def test_every_package_name_gives_the_control_result(self):
        _facts, control = self.scan("com/acme/shop")
        self.assertIn(("sqli", "HIGH"), control)
        for package in ("com/example/shop", "com/acme/build", "com/acme/tool", "com/acme/ops",
                        "com/acme/migration", "com/acme/dist"):
            with self.subTest(package=package):
                self._dir.cleanup()
                self.setUp()
                facts, found = self.scan(package)
                self.assertEqual(found, control)
                kinds = {g["kind"] for g in facts["coverage"]["gaps"]}
                self.assertNotIn("skipped_directory_code", kinds)

    def test_real_build_output_is_still_pruned(self):
        self.pom("svc/pom.xml")
        self.write("svc/build/generated/Gen.java", "class Gen {}")
        self.write("svc/src/main/java/com/acme/A.java", "class A {}")
        ctx = RepoContext(self.root)
        self.assertEqual([ctx.rel(p) for p in ctx.code_files], ["svc/src/main/java/com/acme/A.java"])

    def test_fixture_excluded_routes_are_a_coverage_gap(self):
        self.write("package.json", '{"name":"x","dependencies":{"express":"4.21.2"}}')
        self.write("server.js", "const app = require('express')();\napp.get('/real', (q, s) => s.send('x'));\n")
        self.write("examples/demo/app.js", "const app = require('express')();\napp.post('/demo', (q, s) => s.send('x'));\n")
        facts = self.facts()
        gap = next((g for g in facts["coverage"]["gaps"] if g["kind"] == "fixture_excluded_routes"), None)
        self.assertIsNotNone(gap)
        self.assertFalse(gap["execution"])
        self.assertIn("examples/demo/app.js", gap["detail"])
        self.assertEqual(facts["coverage"]["fixture_excluded_routes"], 1)


if __name__ == "__main__":
    unittest.main()

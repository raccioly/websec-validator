"""#242: presence checks, constants, size and char checks are not timing leads; the line is kept.
#243: Java SQL sinks: literals and constants are not input; JdbcTemplate/Statement calls are sinks.
"""
import unittest

from _jvm_repo import TempRepo
from websec_validator.extractors import jvm
from websec_validator.extractors.crypto_usage import _timing_comparison

PKG = "src/main/java/com/acme/store/"


class TimingPresenceTests(unittest.TestCase):
    def test_null_and_nil_presence_checks_are_not_leads(self):
        for suffix, line in ((".java", "if (apiKey != null && !apiKey.isBlank()) {}"),
                             (".java", "this.apiKey = apiKey == null ? \"\" : apiKey.trim();"),
                             (".kt", "if (token == null) return"),
                             (".cs", "if (secret != null) {}"),
                             (".swift", "if token == nil { return }"),
                             (".rb", "return if token == nil")):
            with self.subTest(suffix=suffix, line=line):
                self.assertIsNone(_timing_comparison(line + "\n", suffix))

    def test_constants_sizes_and_chars_are_not_leads(self):
        for line in ("if (status == Result.DEAD_TOKEN) {}",
                     "if (code === AUTH_TOKEN_INVALID_ERROR) {}",
                     "if (tokens.size() == 0) {}",
                     "if (token.length() == 32) {}",
                     "if (token.charAt(0) == 'B') {}",
                     "if (passwordlessStatus === 'neutral') {}"):
            with self.subTest(line=line):
                self.assertIsNone(_timing_comparison(line + "\n", ".java" if "()" in line or "'B'" in line else ".ts"))

    def test_secret_comparisons_still_fire(self):
        cases = (('if authorization != f"Bearer {settings.api_token}":\n    raise Forbidden()\n', ".py"),
                 ("if (token.equals(expected) || token == Config.API_SECRET) {}\n", ".java"),
                 ("if (req.headers['x-api-key'] !== process.env.API_KEY) return 401;\n", ".ts"))
        for source, suffix in cases:
            with self.subTest(source=source):
                self.assertIsNotNone(_timing_comparison(source, suffix))


class TimingLedgerTests(TempRepo):
    def test_finding_carries_its_line(self):
        self.write("server/auth.ts", "export function check(req) {\n  const k = req.headers['x-api-key'];\n"
                                     "  if (k !== process.env.API_KEY) throw new Error('no');\n}\n")
        rows = [f for f in self.ledger() if f.get("attack_class") == "timing-unsafe-compare"]
        self.assertEqual([(f["file"], f["line"], f["location"]) for f in rows],
                         [("server/auth.ts", 3, "server/auth.ts:3")])

    def test_browser_form_comparison_is_not_a_lead(self):
        self.write("web/src/app/pages/signup/signup.page.ts",
                   "import { Component } from '@angular/core';\n"
                   "@Component({ selector: 'x', template: '' })\nexport class SignupPage {\n"
                   "  ok(password: string, confirmPassword: string) { return password === confirmPassword; }\n}\n")
        self.assertEqual([f for f in self.ledger() if f.get("attack_class") == "timing-unsafe-compare"], [])


CONTROLLER = """package com.acme.store;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/orders")
public class OrderController {
    private static final String COLUMNS = "id, status";
    private static final int MAX_ROWS = 200;
    private final JdbcTemplate jdbc;
    public OrderController(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @GetMapping("/a") public Object a(@RequestParam String s) {
        return named.query("SELECT " + COLUMNS + " FROM orders WHERE status = :s", params(s), mapper);
    }
    @GetMapping("/b") public Object b() {
        return named.query("SELECT id FROM orders WHERE status = 'open' "
                + "ORDER BY created_at DESC", params(), mapper);
    }
    @GetMapping("/c") public Object c() { return jdbc.query("SELECT id FROM orders LIMIT " + MAX_ROWS, mapper); }
    @GetMapping("/d") public Object d(@PathVariable long id) { return jdbc.queryForList("SELECT * FROM orders WHERE id = " + id); }
    @DeleteMapping("/e") public int e(@RequestParam String note) {
        return jdbc.update("DELETE FROM orders WHERE note = '" + note + "'");
    }
    @GetMapping("/f") public Object f(@RequestParam String name) {
        String sql = "SELECT * FROM orders WHERE name = '" + name + "'";
        return jdbc.queryForObject(sql, Integer.class);
    }
    @PostMapping("/g") public int g(@RequestParam String before) throws Exception {
        return statement.executeUpdate(String.format("UPDATE orders SET archived = true WHERE created_at < '%s'", before));
    }
    public void h(String table) { jdbc.execute("TRUNCATE " + table); }
    public void i() { executor.execute(() -> run("x" + y)); cache.update("k" + id); }
}
"""


class JavaSqlTests(unittest.TestCase):
    def rows(self):
        return {CONTROLLER.count("\n", 0, row["offset"]) + 1: row for row in jvm.sql_sinks(CONTROLLER)}

    def test_constants_literals_and_numeric_params_are_safe(self):
        lines = self.rows()
        for line in (13, 16, 19, 20):
            self.assertNotIn(line, lines)

    def test_injectable_calls_are_found_with_request_parameters(self):
        lines = self.rows()
        self.assertEqual(lines[22]["request_bound"], ["note"])
        self.assertEqual(lines[26]["request_bound"], ["name"])       # one-hop variable
        self.assertEqual(lines[29]["request_bound"], ["before"])     # String.format argument
        self.assertEqual((lines[31]["dynamic"], lines[31]["request_bound"]), (["table"], []))

    def test_non_sql_update_and_execute_are_not_sinks(self):
        self.assertNotIn(32, self.rows())


class JavaSqlLedgerTests(TempRepo):
    def test_ledger_severity(self):
        self.pom()
        self.write(PKG + "OrderController.java", CONTROLLER)
        rows = {f["location"]: f for f in self.ledger() if f.get("attack_class") == "sqli"}
        self.assertEqual(rows[PKG + "OrderController.java:22"]["severity"], "HIGH")
        self.assertEqual(rows[PKG + "OrderController.java:31"]["severity"], "MEDIUM")
        self.assertNotIn(PKG + "OrderController.java:13", rows)


if __name__ == "__main__":
    unittest.main()

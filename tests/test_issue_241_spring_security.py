"""#241: Spring Security filter chains and method security are route-guard evidence.

* `anyRequest().authenticated()` (or hasRole/access) guards the routes it covers;
* the first matching rule wins, so a `permitAll()` matcher keeps its route as a named lead;
* `@PreAuthorize` on a method or class guards — only when method security enables it;
* a chain applies to its own build module and to modules that depend on it;
* an unresolved central configuration is a LOW-confidence lead, never HIGH.
"""
import unittest

from _jvm_repo import SECURITY_DEP, TempRepo
from websec_validator.extractors.spring_security import ant_regex

PKG = "src/main/java/com/acme/notes/"
CHAIN = """package com.acme.notes;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
@Configuration
{method_security}
public class SecurityConfig {{
    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {{
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/feedback/**").permitAll()
                .anyRequest().{default})
            .oauth2ResourceServer(o -> o.jwt(jwt -> {{}}));
        return http.build();
    }}
}}
"""
NOTES = """package com.acme.notes;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/notes")
public class NoteController {
    @PostMapping
    public String create(@RequestBody String body) { return body; }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('admin')")
    public void delete(@PathVariable String id) { }

    @PutMapping("/{id}")
    @PreAuthorize("permitAll()")
    public void touch(@PathVariable String id) { }
}
"""
FEEDBACK = """package com.acme.notes;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/feedback")
public class FeedbackController {
    @PostMapping
    public String submit(@RequestBody String body) { return body; }
}
"""


def guards(facts):
    return {(row["method"], row["path"]): row for row in facts["authz"]["endpoint_guards"]}


class SpringChainTests(TempRepo):
    def repo(self, default="authenticated()", method_security="@EnableMethodSecurity"):
        self.pom(extra=SECURITY_DEP)
        self.write(PKG + "SecurityConfig.java", CHAIN.format(default=default, method_security=method_security))
        self.write(PKG + "NoteController.java", NOTES)
        self.write(PKG + "FeedbackController.java", FEEDBACK)

    def test_authenticated_default_guards_and_permit_all_stays_named(self):
        self.repo()
        facts = self.facts()
        rows = guards(facts)
        self.assertTrue(rows[("POST", "/api/notes")]["guarded"])
        self.assertIn("anyRequest().authenticated()", rows[("POST", "/api/notes")]["guard_evidence"][0])
        feedback = rows[("POST", "/api/feedback")]
        self.assertFalse(feedback["guarded"])
        self.assertIn('requestMatchers(HttpMethod.POST, "/api/feedback/**").permitAll()', feedback["public_rule"])
        missing = [f for f in self.ledger(facts) if f.get("attack_class") == "missing-auth"]
        self.assertEqual([(f["method"], f["location"], f["severity"]) for f in missing],
                         [("POST", "/api/feedback", "HIGH")])
        self.assertIn("permitAll", missing[0]["evidence"][-1]["detail"])

    def test_permit_all_default_does_not_guard_but_method_security_does(self):
        self.repo(default="permitAll()")
        rows = guards(self.facts())
        self.assertFalse(rows[("POST", "/api/notes")]["guarded"])
        self.assertTrue(rows[("DELETE", "/api/notes/{id}")]["guarded"])
        self.assertEqual(rows[("DELETE", "/api/notes/{id}")]["guard_evidence"][0],
                         "@PreAuthorize on the method (NoteController.delete)")
        self.assertFalse(rows[("PUT", "/api/notes/{id}")]["guarded"])   # @PreAuthorize("permitAll()")

    def test_method_annotations_need_method_security_enabled(self):
        self.repo(default="permitAll()", method_security="")
        row = guards(self.facts())[("DELETE", "/api/notes/{id}")]
        self.assertFalse(row["guarded"])
        self.assertTrue(any("not enforced unless method security" in note for note in row["unverified_controls"]))

    def test_class_level_annotation_and_family_flags(self):
        self.pom(extra=SECURITY_DEP)
        self.write(PKG + "SecurityConfig.java", CHAIN.format(default="permitAll()",
                                                             method_security="@EnableMethodSecurity(securedEnabled = true)"))
        self.write(PKG + "ReportController.java", """package com.acme.notes;
@RestController
@RequestMapping("/api/reports")
@Secured("ROLE_analyst")
public class ReportController {
    @PostMapping("/run") public String run() { return "ok"; }
    @PatchMapping("/{id}") @RolesAllowed("admin") public String patch(@PathVariable String id) { return id; }
}
""")
        rows = guards(self.facts())
        self.assertTrue(rows[("POST", "/api/reports/run")]["guarded"])
        self.assertIn("@Secured on the class", rows[("POST", "/api/reports/run")]["guard_evidence"][0])

    def test_first_matching_rule_wins(self):
        self.pom(extra=SECURITY_DEP)
        self.write(PKG + "SecurityConfig.java", CHAIN.format(default="authenticated()", method_security="")
                   .replace('.requestMatchers("/actuator/health").permitAll()',
                            '.requestMatchers("/api/notes/**").authenticated()\n.requestMatchers("/api/**").permitAll()'))
        self.write(PKG + "NoteController.java", NOTES)
        self.write(PKG + "FeedbackController.java", FEEDBACK)
        rows = guards(self.facts())
        self.assertTrue(rows[("POST", "/api/notes")]["guarded"])
        self.assertFalse(rows[("POST", "/api/feedback")]["guarded"])


class SpringModuleTests(TempRepo):
    def test_chain_in_a_dependency_module_applies(self):
        self.write("pom.xml", "<project><artifactId>parent</artifactId><modules><module>security</module>"
                              "<module>svc</module></modules></project>")
        self.pom("security/pom.xml", artifact="acme-security", extra=SECURITY_DEP)
        self.write("security/src/main/java/com/acme/sec/SecurityConfig.java",
                   CHAIN.format(default="authenticated()", method_security=""))
        self.pom("svc/pom.xml", artifact="svc", extra="<dependency><groupId>com.acme</groupId>"
                                                      "<artifactId>acme-security</artifactId></dependency>")
        self.write("svc/src/main/java/com/acme/notes/NoteController.java", NOTES)
        self.assertTrue(guards(self.facts())[("POST", "/api/notes")]["guarded"])

    def test_chain_in_an_unrelated_module_does_not_apply_and_is_unverified(self):
        self.write("pom.xml", "<project><artifactId>parent</artifactId></project>")
        self.pom("other/pom.xml", artifact="other", extra=SECURITY_DEP)
        self.write("other/src/main/java/com/acme/sec/SecurityConfig.java",
                   CHAIN.format(default="authenticated()", method_security=""))
        self.pom("svc/pom.xml", artifact="svc", extra=SECURITY_DEP)
        self.write("svc/src/main/java/com/acme/notes/NoteController.java", NOTES)
        facts = self.facts()
        row = guards(facts)[("POST", "/api/notes")]
        self.assertFalse(row["guarded"])
        self.assertTrue(row["central_auth_unresolved"])
        finding = next(f for f in self.ledger(facts) if f.get("location") == "/api/notes" and f["method"] == "POST")
        self.assertEqual((finding["severity"], finding["confidence"]), ("MEDIUM", "LOW"))

    def test_no_spring_security_keeps_the_high_lead(self):
        self.pom()
        self.write(PKG + "NoteController.java", NOTES)
        finding = next(f for f in self.ledger() if f.get("location") == "/api/notes" and f["method"] == "POST")
        self.assertEqual(finding["severity"], "HIGH")


class AntPatternTests(unittest.TestCase):
    def test_patterns(self):
        cases = [("/api/feedback/**", "/api/feedback", True), ("/api/feedback/**", "/api/feedback/x/y", True),
                 ("/api/feedback/**", "/api/feedbacks", False), ("/api/*/run", "/api/reports/run", True),
                 ("/api/*/run", "/api/a/b/run", False), ("/api/{id}", "/api/_p_", True), ("/**", "/anything", True)]
        for pattern, path, expected in cases:
            with self.subTest(pattern=pattern, path=path):
                self.assertEqual(bool(ant_regex(pattern).match(path)), expected)


if __name__ == "__main__":
    unittest.main()

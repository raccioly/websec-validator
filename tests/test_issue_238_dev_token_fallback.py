"""#238: a `dev-` fallback principal name is not a token backdoor.

`dev-token-backdoor` needs request credential material compared against a literal or prefix. A
`dev-user` literal used as the identity when no principal exists is reported as a LOW
`anonymous-fallback-principal` instead.
"""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from websec_validator.extractors.auth import AuthExtractor  # noqa: E402
from websec_validator.extractors.base import RepoContext  # noqa: E402

CONTROLLER = """@RestController
@RequestMapping("/api/notes")
public class NotesController {
  @PostMapping
  public String create(@AuthenticationPrincipal Jwt jwt, @RequestBody String body) {
    return "saved by " + owner(jwt);
  }
  private static String owner(Jwt jwt) {
    return jwt != null ? Objects.requireNonNullElse(jwt.getSubject(), "dev-user") : "dev-user";
  }
}
"""


class DevTokenFallbackTests(unittest.TestCase):
    def broken_auth(self, files):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel, body in files.items():
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body)
            return AuthExtractor().extract(RepoContext(root), {"stack": {}, "routes": {}})["broken_auth"]

    def kinds(self, files):
        return {(row["kind"], row["severity"]) for row in self.broken_auth(files)}

    def test_null_principal_fallback_is_low_not_a_backdoor(self):
        rows = self.broken_auth({"src/main/java/NotesController.java": CONTROLLER})
        self.assertEqual([(r["kind"], r["severity"], r["line"]) for r in rows],
                         [("anonymous-fallback-principal", "LOW", 9)])

    def test_js_fallback_forms_are_low(self):
        for line in ("const owner = req.user?.id ?? 'dev-user';",
                     "const owner = session.user || 'dev-admin';",
                     "String who = Optional.ofNullable(principal).map(Principal::getName).orElse(\"dev-user\");"):
            with self.subTest(line=line):
                self.assertEqual(self.kinds({"app.ts": line + "\n"}), {("anonymous-fallback-principal", "LOW")})

    def test_literal_argument_without_principal_context_is_silent(self):
        self.assertEqual(self.broken_auth({"app.ts": "log('dev-user', 3);\nconst x = y ?? 'dev-user';\n"}), [])

    def test_credential_comparisons_stay_critical(self):
        for line in ("if (token.startsWith('dev-')) { return { role: 'dev-admin' }; }",
                     "if (token === 'dev-token') return admin;",
                     "if ('dev-token' === authHeader) return admin;",
                     "if (\"dev-token\".equals(token)) return admin;",
                     "if (token.equals(\"dev-admin\")) return admin;",
                     "if (bearer.equalsIgnoreCase(\"backdoor\")) return admin;",
                     "if (['dev-token', 'dev-admin'].includes(token)) return admin;"):
            with self.subTest(line=line):
                self.assertIn(("dev-token-backdoor", "CRITICAL"), self.kinds({"auth.ts": line + "\n"}))

    def test_backdoor_and_fallback_in_one_file_report_only_the_backdoor(self):
        text = "if (token === 'dev-token') return admin;\nconst o = req.user ?? 'dev-user';\n"
        self.assertEqual(self.kinds({"auth.ts": text}), {("dev-token-backdoor", "CRITICAL")})


if __name__ == "__main__":
    unittest.main()

"""#201 (GraphQL field suggestions) and #202 (client_integrity FPs), integrated with hardening.

Each fix is paired with the true positive the PR as written would have lost.
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator.extractors.base import RepoContext                          # noqa: E402
from websec_validator.extractors.client_integrity import ClientIntegrityExtractor  # noqa: E402
from websec_validator.extractors.graphql import GraphQLExtractor                   # noqa: E402

SUGGEST = "field suggestions not disabled"


def scan(extractor, files):
    with tempfile.TemporaryDirectory() as td:
        for rel, text in files.items():
            path = Path(td) / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        return extractor().extract(RepoContext(Path(td)), {})


def graphql_app(extra=""):
    return {"app.py": "import graphene\nfrom flask_graphql import GraphQLView\nschema = graphene.Schema()\n"
                      "app.add_url_rule('/graphql', view_func=GraphQLView.as_view('graphql', schema=schema, "
                      f"introspection=False){extra})\n"}


def issues(out):
    return [f["issue"] for f in out.get("findings", [])]


class FieldSuggestionTests(unittest.TestCase):
    def test_disabled_introspection_with_suggestions_on_is_reported(self):
        self.assertTrue(any(SUGGEST in i for i in issues(scan(GraphQLExtractor, graphql_app()))))

    def test_a_real_control_silences_it(self):
        for files in (graphql_app() | {"armor.js": "import { ApolloArmor } from '@escape.tech/graphql-armor';\n"},
                      graphql_app() | {"plug.js": "const p = blockFieldSuggestions({ enabled: true });\n"},
                      graphql_app() | {"cfg.py": "SETTINGS = dict(disable_field_suggestions=True)\n"}):
            self.assertFalse(any(SUGGEST in i for i in issues(scan(GraphQLExtractor, files))), list(files))

    def test_false_flags_and_unrelated_settings_are_not_a_control(self):
        # #201 as written: `max_errors` and a bare option name both counted as "disabled".
        for files in (graphql_app() | {"cfg.py": "SETTINGS = dict(disable_field_suggestions=False)\n"},
                      graphql_app() | {"cfg.py": "max_errors = 50\n"}):
            self.assertTrue(any(SUGGEST in i for i in issues(scan(GraphQLExtractor, files))), list(files))

    def test_not_reported_when_introspection_is_on_the_schema_is_already_public(self):
        files = {"app.py": "import graphene\nschema = graphene.Schema()\nGraphQLView.as_view('graphql', "
                           "schema=schema, introspection=True)\n"}
        out = scan(GraphQLExtractor, files)
        self.assertFalse(any(SUGGEST in i for i in issues(out)))
        self.assertTrue(any("introspection ENABLED" in i for i in issues(out)))


class ClientIntegrityTests(unittest.TestCase):
    def kinds(self, files):
        return [f["attack_class"] for f in scan(ClientIntegrityExtractor, files).get("findings", [])]

    def test_windows_in_a_comment_is_not_a_cookie_authenticated_socket(self):
        files = {"app/ws.ts": "'use client'\nconst ws = new WebSocket(url);\nconst c = document.cookie;\n"
                              "// Windows OS check\n"}
        self.assertNotIn("cswsh", self.kinds(files))

    def test_a_cookie_read_feeding_a_socket_still_fires(self):
        for snippet in ("const t = document.cookie; const ws = new WebSocket(`wss://x?c=${t}`);",
                        "const t = document.cookie; socketUrl = `wss://x?c=${t}`; new WebSocket(socketUrl);",
                        "const t = document.cookie; io.socket.connect(t); new WebSocket(u);"):
            self.assertIn("cswsh", self.kinds({"app/rt.ts": "'use client'\n" + snippet + "\n"}), snippet)

    def test_a_100_percent_secure_claim_on_a_client_control_is_still_an_overclaim(self):
        # #202 removed this alternative; the detector's own definition calls it a genuine finding.
        files = {"app/verify.tsx": "'use client'\nexport const V = () => <p>Address check is 100% secure</p>;\n"}
        self.assertIn("overclaimed-control", self.kinds(files))


if __name__ == "__main__":
    unittest.main()

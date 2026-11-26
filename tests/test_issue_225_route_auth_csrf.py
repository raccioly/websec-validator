"""#225: a media-URL assertion is not a route, and CSRF needs a route that can change state.

Three layers, each pinned on its own:
  * raw-server route harvest only takes path literals compared against the request;
  * the auth scheme names the files behind each signal, and test files are not evidence;
  * `no-csrf-protection` needs a route that may change state, and names it.
"""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from websec_validator.extractors import run_all  # noqa: E402
from websec_validator.extractors.transport_security import _may_change_state  # noqa: E402

LISTENER = """import http from 'node:http';
const server = http.createServer((req, res) => {
  if (req.method !== 'GET') { res.writeHead(405); return res.end(); }
  res.writeHead(200); res.end('ok');
});
server.listen(0, '127.0.0.1');
"""
MEDIA_ASSERTION = """import assert from 'node:assert';
export function check(report) {
  assert.ok(report.mediaEvents
    .filter(event => event.kind === 'playing' &&
      new URL(event.src).pathname === '/media/ending.mp3')
    .every(event => event.loop === false), 'ending cue must not loop');
}
"""


class _Repo(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)

    def tearDown(self):
        self._dir.cleanup()

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def facts(self):
        return run_all(self.root, "t")

    def routes(self):
        return [(row["method"], row["path"]) for row in self.facts()["routes"]["endpoints"]]


class RawRouteHarvestTests(_Repo):
    def test_media_url_assertion_is_not_a_route(self):
        self.write("scripts/diagnostic.mjs", LISTENER + MEDIA_ASSERTION)
        self.assertNotIn(("ANY", "/media/ending.mp3"), self.routes())

    def test_request_derived_paths_remain_routes(self):
        self.write("server.mjs", LISTENER.replace(
            "if (req.method", "const { pathname } = new URL(req.url, 'http://x');\n"
            "  const url = new URL(request.url ?? req.url, 'http://x');\n"
            "  if (pathname === '/api/a') {}\n  if (url.pathname === '/api/b') {}\n"
            "  if (new URL(req.url, 'http://x').pathname === '/api/c') {}\n"
            "  if (req.url === '/api/d') {}\n  if (req.method"))
        routes = self.routes()
        for path in ("/api/a", "/api/b", "/api/c", "/api/d"):
            with self.subTest(path=path):
                self.assertIn(("ANY", path), routes)

    def test_url_of_another_value_and_test_oracles_are_skipped(self):
        self.write("server.mjs", LISTENER + "const a = new URL(item.href).pathname === '/x/item';\n"
                   "expect(new URL(req.url, 'http://x').pathname === '/x/expected').toBe(true);\n")
        routes = self.routes()
        self.assertNotIn(("ANY", "/x/item"), routes)
        self.assertNotIn(("ANY", "/x/expected"), routes)

    def test_negated_method_check_names_the_served_method(self):
        self.write("server.mjs", LISTENER)
        rows = self.facts()["routes"]["endpoints"]
        self.assertEqual([row.get("methods_detected") for row in rows], [["GET"]])


class CsrfNeedsAStateChangingRouteTests(_Repo):
    COOKIE_HMAC = ("import { createHmac } from 'node:crypto';\n"
                   "export const sign = (v) => createHmac('sha256', process.env.K).update(v).digest('hex');\n"
                   "export const read = (req) => req.cookies.sid;\n")

    def csrf(self):
        findings = (self.facts().get("transport_security") or {}).get("findings", [])
        return [row for row in findings if row["kind"] == "no-csrf-protection"]

    def test_read_only_cookie_app_has_nothing_to_forge(self):
        self.write("lib/session.mjs", self.COOKIE_HMAC)
        self.write("server.mjs", LISTENER)
        self.assertEqual(self.csrf(), [])

    def test_write_route_keeps_the_finding_and_names_its_evidence(self):
        self.write("lib/session.mjs", self.COOKIE_HMAC)
        self.write("server.mjs", LISTENER.replace("!== 'GET'", "!== 'POST'"))
        rows = self.csrf()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["write_routes"], ["ANY /*"])
        self.assertIn("lib/session.mjs", rows[0]["detail"])
        self.assertIn("lib/session.mjs", rows[0]["auth_basis"])

    def test_unknown_methods_stay_possible_writes(self):
        self.assertTrue(_may_change_state({"method": "ANY"}))
        self.assertTrue(_may_change_state({"method": "ALL"}))
        self.assertTrue(_may_change_state({"method": "ANY", "methods_detected": ["GET", "DELETE"]}))
        self.assertTrue(_may_change_state({"method": "post"}))
        self.assertFalse(_may_change_state({"method": "ANY", "methods_detected": ["GET"]}))
        # A framework GET handler may still change state; only detected raw dispatch is proof.
        self.assertTrue(_may_change_state({"method": "GET"}))


class SchemeEvidenceTests(_Repo):
    def test_test_files_do_not_establish_a_cookie_scheme(self):
        self.write("server.mjs", LISTENER.replace("!== 'GET'", "!== 'POST'"))
        self.write("tests/session.test.mjs", CsrfNeedsAStateChangingRouteTests.COOKIE_HMAC)
        auth = self.facts()["auth"]
        self.assertNotEqual(auth["scheme"], "hmac-signed-cookie")
        self.assertNotIn("hmac", auth["scheme_evidence"])

    def test_basis_names_the_files_behind_the_scheme(self):
        self.write("lib/session.mjs", CsrfNeedsAStateChangingRouteTests.COOKIE_HMAC)
        self.write("server.mjs", LISTENER)
        auth = self.facts()["auth"]
        self.assertEqual(auth["scheme"], "hmac-signed-cookie")
        self.assertEqual(auth["scheme_evidence"]["hmac"], ["lib/session.mjs"])
        self.assertIn("hmac: lib/session.mjs", auth["scheme_basis"])


if __name__ == "__main__":
    unittest.main()

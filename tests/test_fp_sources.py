"""Three systematic false-positive sources found by labelling the corpus, and their controls.

Measured on the pinned corpus (VAmPI, NodeGoat, DVGA): 184 findings, of which 121 were false.
Each fix below is paired with the control that must KEEP firing, because the dangerous direction
for a security tool is the false negative — a guard credited too generously hides the finding the
tool exists to produce.

  1. Vendored third-party assets. 100 of DVGA's 128 findings were inside jQuery and Bootstrap.
  2. Spec-as-handler. VAmPI's OpenAPI document was read as every route's handler file, so no code
     guard could ever match and all 12 routes reported missing-auth; 6 of them validate a token.
  3. Express per-route middleware. `app.get("/x", isLoggedIn, handler)` was uncredited, so all 20
     NodeGoat routes reported unguarded when 12 are protected.

@req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-007
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator import openapi
from websec_validator.extractors.authz import (operation_body, route_middleware_guarded,
                                               _authn_middleware_names, INLINE_AUTHN, AUTHN_REJECT)
from websec_validator.extractors.base import is_vendored_asset

JQUERY = ("/*!\n * jQuery JavaScript Library v3.5.1\n * Copyright JS Foundation\n */\n"
          "function x(){ return /((a+)+)+b/.test(s); }\n")
# Real minifier output strips whitespace: measured density on the corpus bundles is 0.97-0.98.
MINIFIED = "(function(){" + "a=1,b=2,c=a+b,d=c*2;" * 80 + "})();\n"
APP_SOURCE = "const express = require('express');\nmodule.exports = { run() { return 1; } };\n"


class VendoredAssetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def test_library_banner_is_vendored(self):
        self.assertTrue(is_vendored_asset(self.write("static/jquery/jquery.js", JQUERY)))

    def test_minified_by_name_is_vendored_without_reading(self):
        self.assertTrue(is_vendored_asset(self.write("static/x.min.js", "anything")))
        self.assertTrue(is_vendored_asset(self.write("static/x.min.css", "anything")))

    def test_minified_by_long_dense_line_is_vendored(self):
        self.assertTrue(is_vendored_asset(self.write("static/bundle.js", MINIFIED)))

    def test_ordinary_application_source_is_not_vendored(self):
        self.assertFalse(is_vendored_asset(self.write("app/routes.js", APP_SOURCE)))

    def test_a_long_line_of_WHITESPACE_is_not_minified(self):
        """The control for the density rule: an oversized scope must still be analysed.

        `tests/test_remaining_control_scope` builds exactly this — a real function padded with
        25,000 spaces — and it must not be mistaken for a generated bundle.
        """
        padded = "async function login(p){" + " " * 25000 + "if(!p)return null;}\n"
        self.assertFalse(is_vendored_asset(self.write("app/login.js", padded)))

    def test_non_vendorable_extensions_are_never_skipped(self):
        """Python and other source is never classified this way, whatever it contains."""
        self.assertFalse(is_vendored_asset(self.write("app.py", "x = '" + "a" * 3000 + "'\n")))

    def test_an_unreadable_file_is_analysed_rather_than_skipped(self):
        self.assertFalse(is_vendored_asset(self.root / "does-not-exist.js"))


SPEC_YAML = """openapi: 3.0.0
paths:
  /me:
    get:
        security:
          - bearerAuth: []
        operationId: api_views.users.me
        responses:
          '200':
            description: ok
  /users/v1/_debug:
    get:
      operationId: api_views.users.debug
      responses:
        '200':
          description: ok
  /public:
    get:
      security: []
      operationId: api_views.users.public_thing
"""

HANDLERS = '''
def me():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype="application/json")
    return jsonify(user)

def debug():
    users = User.query.all()
    return jsonify(users)

def public_thing():
    return jsonify({"ok": True})
'''


class SpecAsHandlerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.spec = Path(self.tmp.name) / "openapi.yml"
        self.spec.write_text(SPEC_YAML)

    def test_operation_map_reads_every_operation(self):
        ops = openapi.operation_map(self.spec)
        self.assertEqual(ops[("/me", "GET")]["operation_id"], "api_views.users.me")
        self.assertEqual(ops[("/users/v1/_debug", "GET")]["operation_id"], "api_views.users.debug")

    def test_security_is_attributed_per_operation(self):
        ops = openapi.operation_map(self.spec)
        self.assertTrue(ops[("/me", "GET")]["declares_security"])
        self.assertFalse(ops[("/users/v1/_debug", "GET")]["declares_security"])

    def test_empty_security_list_is_an_explicit_opt_out_not_a_guard(self):
        self.assertFalse(openapi.operation_map(self.spec)[("/public", "GET")]["declares_security"])

    def test_varying_indentation_is_tolerated(self):
        """The corpus spec puts operation keys at 6 spaces under one path and 8 under another."""
        ops = openapi.operation_map(self.spec)
        self.assertEqual(len(ops), 3)

    def test_operation_id_resolves_to_the_implementing_file(self):
        known = ["api_views/users.py", "app.py", "README.md"]
        self.assertEqual(
            openapi.resolve_operation_file("api_views.users.me", known), "api_views/users.py")

    def test_unresolvable_operation_id_returns_empty_never_a_guess(self):
        self.assertEqual(openapi.resolve_operation_file("nowhere.at.all", ["app.py"]), "")
        self.assertEqual(openapi.resolve_operation_file("", ["app.py"]), "")

    def test_guard_decision_is_scoped_to_the_named_function(self):
        """The control: one file, three operations, only one of which authenticates."""
        guarded = {}
        for name in ("me", "debug", "public_thing"):
            body = operation_body(HANDLERS, name, ".py")
            self.assertTrue(body, f"{name} body must be locatable")
            guarded[name] = bool(INLINE_AUTHN.search(body) and AUTHN_REJECT.search(body))
        self.assertTrue(guarded["me"], "inline token validation + 401 is a guard")
        self.assertFalse(guarded["debug"], "an unauthenticated user dump must still be reported")
        self.assertFalse(guarded["public_thing"])

    def test_a_missing_function_yields_no_body_so_the_caller_falls_back(self):
        self.assertEqual(operation_body(HANDLERS, "not_defined", ".py"), "")

    def test_unparseable_source_yields_no_body_rather_than_raising(self):
        self.assertEqual(operation_body("def broken(:\n", "broken", ".py"), "")

    def test_validator_call_without_a_rejection_is_not_credited(self):
        """Calling an auth helper and ignoring its verdict is not a guard."""
        body = "def x():\n    resp = token_validator(request.headers.get('Authorization'))\n    return jsonify(all_users)\n"
        scoped = operation_body(body, "x", ".py")
        self.assertFalse(bool(INLINE_AUTHN.search(scoped) and AUTHN_REJECT.search(scoped)))


ROUTES_JS = '''
const sessionHandler = new SessionHandler(db);
const isLoggedIn = sessionHandler.isLoggedInMiddleware;
const isAdmin = sessionHandler.isAdminUserMiddleware;
const rateLimit = require("express-rate-limit");

app.get("/", sessionHandler.displayWelcomePage);
app.get("/login", sessionHandler.displayLoginPage);
app.post("/login", sessionHandler.handleLoginRequest);
app.get("/dashboard", isLoggedIn, sessionHandler.displayWelcomePage);
app.post("/memos", isLoggedIn, memosHandler.addMemos);
app.get("/allocations/:userId", isLoggedIn, allocationsHandler.displayAllocations);
app.post("/report", rateLimit, reportHandler.submit);
app.get("/admin", isLoggedIn, isAdmin, adminHandler.show);
'''


class RouteMiddlewareTests(unittest.TestCase):
    def test_authn_binding_names_are_collected(self):
        names = _authn_middleware_names(ROUTES_JS)
        self.assertIn("isLoggedIn", names)

    def test_guarded_routes_are_credited(self):
        for method, path in (("GET", "/dashboard"), ("POST", "/memos"),
                             ("GET", "/allocations/{userId}"), ("GET", "/admin")):
            with self.subTest(path=path):
                self.assertTrue(route_middleware_guarded(ROUTES_JS, method, path))

    def test_unguarded_routes_in_the_SAME_FILE_still_report(self):
        """The control that matters: file-level crediting would clear all of these."""
        for method, path in (("GET", "/"), ("GET", "/login"), ("POST", "/login")):
            with self.subTest(path=path):
                self.assertFalse(route_middleware_guarded(ROUTES_JS, method, path))

    def test_a_non_auth_middleware_does_not_count_as_a_guard(self):
        """`rateLimit` is middleware, but it establishes no identity."""
        self.assertFalse(route_middleware_guarded(ROUTES_JS, "POST", "/report"))

    def test_path_params_match_across_notations(self):
        self.assertTrue(route_middleware_guarded(ROUTES_JS, "GET", "/allocations/{userId}"))

    def test_an_absent_route_is_not_reported_as_guarded(self):
        self.assertFalse(route_middleware_guarded(ROUTES_JS, "GET", "/never-registered"))

    def test_every_registration_of_a_path_must_be_guarded(self):
        """One protected copy cannot vouch for an unprotected twin."""
        both = ROUTES_JS + '\napp.get("/dashboard", sessionHandler.displayWelcomePage);\n'
        self.assertFalse(route_middleware_guarded(both, "GET", "/dashboard"))

    def test_empty_inputs_are_safe(self):
        self.assertFalse(route_middleware_guarded("", "GET", "/x"))
        self.assertFalse(route_middleware_guarded(ROUTES_JS, "", ""))


if __name__ == "__main__":
    unittest.main()

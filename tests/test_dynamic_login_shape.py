"""The login credential FIELD NAME belongs to the target app, not to websec.

`mint()` sent `{"email": ..., "password": ...}` unconditionally, so any API that authenticates with
`username` — VAmPI, and a large share of real ones — could never mint a token. The BOLA matrix was
then skipped with "could not mint both agent tokens", which reads like a network or credential
problem rather than a shape mismatch websec imposed itself.

@req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-007
"""
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator import dynamic


class _Resp(io.BytesIO):
    def __init__(self, payload):
        super().__init__(json.dumps(payload).encode())


class LoginShapeTests(unittest.TestCase):
    def _mint(self, roles, response):
        sent = {}

        def _open(req, timeout=None):
            sent["body"] = json.loads(req.data.decode())
            sent["url"] = req.full_url
            return _Resp(response)

        cfg = {"target": "http://127.0.0.1:5001", "login_path": "/users/v1/login",
               "token_json_path": "auth_token", "roles": roles}
        with patch.object(dynamic._NO_REDIRECT_OPENER, "open", _open):
            return dynamic.mint(cfg, "agentA"), sent

    def test_a_username_login_is_sent_verbatim(self):
        out, sent = self._mint({"agentA": {"username": "name1", "password": "pass1"}},
                               {"auth_token": "t0ken"})
        self.assertEqual(sent["body"], {"username": "name1", "password": "pass1"})
        self.assertEqual(out["token"], "t0ken")

    def test_the_email_shape_still_works_unchanged(self):
        out, sent = self._mint({"agentA": {"email": "a@example.com", "password": "p"}},
                               {"auth_token": "t0ken"})
        self.assertEqual(sent["body"], {"email": "a@example.com", "password": "p"})
        self.assertEqual(out["token"], "t0ken")

    def test_extra_credential_fields_are_forwarded(self):
        """Some APIs need a tenant slug or realm alongside the credential."""
        _, sent = self._mint(
            {"agentA": {"username": "u", "password": "p", "realm": "staging"}},
            {"auth_token": "t"})
        self.assertEqual(sent["body"]["realm"], "staging")

    def test_underscore_prefixed_keys_are_treated_as_comments(self):
        _, sent = self._mint({"agentA": {"_comment": "note", "username": "u", "password": "p"}},
                             {"auth_token": "t"})
        self.assertNotIn("_comment", sent["body"])

    def test_identity_falls_back_to_the_credential_when_no_user_object(self):
        """VAmPI's login returns only a token; the two agents must stay distinguishable."""
        out, _ = self._mint({"agentA": {"username": "name1", "password": "pass1"}},
                            {"auth_token": "t"})
        self.assertEqual(out["email"], "name1")

    def test_a_user_object_still_wins_over_the_credential(self):
        out, _ = self._mint({"agentA": {"username": "name1", "password": "p"}},
                            {"auth_token": "t", "user": {"email": "real@example.com"}})
        self.assertEqual(out["email"], "real@example.com")

    def test_a_login_redirect_is_still_reported_not_followed(self):
        """The bug-208 discipline must survive this change."""
        import urllib.error

        def _open(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 302, "Found",
                                         {"Location": "/dashboard"}, None)

        cfg = {"target": "http://x", "roles": {"agentA": {"username": "u", "password": "p"}}}
        with patch.object(dynamic._NO_REDIRECT_OPENER, "open", _open):
            out = dynamic.mint(cfg, "agentA")
        self.assertIn("302", out["error"])
        self.assertNotIn("token", out)


if __name__ == "__main__":
    unittest.main()

"""False-positive fixes from #128 and #143, each with the control the original PR omitted.

Both PRs asserted only `assertEqual(len(findings), 0)` — they proved the false positive was gone
and nothing else. For a security detector that is the wrong half: an over-broad suppression becomes
a FALSE NEGATIVE, and a zero-findings assertion passes just as happily if the detector had been
switched off. Spec 001 FR-002 asks for "a reproduced failure plus safe AND unsafe neighbouring
cases"; the unsafe side lives here.

@req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-007
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.crypto_usage import CryptoUsageExtractor
from websec_validator.extractors.webext import _sender_control


def _crypto(files):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for name, text in files.items():
            (root / name).write_text(text)
        return CryptoUsageExtractor().extract(RepoContext(root), {})


def _classes(files, attack_class):
    return [f for f in _crypto(files)["findings"] if f["attack_class"] == attack_class]


class TimingCompareTests(unittest.TestCase):
    """#128: a length or a zero sentinel is not a secret comparison."""

    def test_length_and_type_comparisons_are_not_secret_compares(self):
        for source in ("if (password.length === 0) return false;\n",
                       "if (api_key.type === 'test') return false;\n",
                       "if (token.byteLength === 32) return false;\n"):
            with self.subTest(source=source.strip()):
                self.assertEqual(_classes({"a.js": source}, "timing-unsafe-compare"), [])

    def test_zero_sentinel_is_a_presence_check(self):
        for source in ("if (password === 0) return false;\n", "if (password == '0') return;\n"):
            with self.subTest(source=source.strip()):
                self.assertEqual(_classes({"b.js": source}, "timing-unsafe-compare"), [])

    # --- the controls #128 did not ship -------------------------------------------------------
    def test_a_real_secret_comparison_STILL_FIRES(self):
        self.assertTrue(_classes({"c.js": "if (password === req.body.password) return ok();\n"},
                                 "timing-unsafe-compare"),
                        "suppressing this would be a false negative, not a precision win")

    def test_a_real_token_comparison_STILL_FIRES(self):
        self.assertTrue(_classes({"d.js": "if (apiKey === suppliedKey) grant();\n"},
                                 "timing-unsafe-compare"))

    def test_a_length_guard_beside_a_real_compare_does_not_mask_it(self):
        """The near miss: both shapes in one file. The secret compare must survive."""
        source = "if (password.length !== supplied.length) return false;\nif (password === supplied) return ok();\n"
        self.assertTrue(_classes({"e.js": source}, "timing-unsafe-compare"))


class WeakPasswordHashTests(unittest.TestCase):
    """#128: hashing an identifier is not hashing a password."""

    def test_hashing_an_identifier_is_not_a_password_hash(self):
        source = ("function verifyPassword(req, res) {\n"
                  "const cacheKey = crypto.createHash('md5').update(req.body.id).digest('hex');\n}\n")
        self.assertEqual(_classes({"f.js": source}, "weak-password-hash"), [])

    # --- the control #128 did not ship --------------------------------------------------------
    def test_a_real_weak_password_hash_STILL_FIRES(self):
        source = ("function setPassword(u) {\n"
                  "const h = crypto.createHash('md5').update(password).digest('hex');\n}\n")
        self.assertTrue(_classes({"g.js": source}, "weak-password-hash"))

    def test_an_exempt_argument_does_not_clear_a_real_weak_hash_beside_it(self):
        """The exemption belongs to its own argument, never to the whole function.

        Writing `weak = False` for the exempt argument (rather than leaving it untouched) lets a
        later `md5(user.id)` clobber a real `md5(password)` found above it — silently turning a
        true positive into silence. Both orderings are checked because the bug is order-dependent.
        """
        real = "const h = crypto.createHash('md5').update(password).digest('hex');\n"
        exempt_pkce = "const c = crypto.createHash('sha256').update(codeVerifier).digest('base64url');\n"
        exempt_id = "const k = crypto.createHash('md5').update(req.body.id).digest('hex');\n"
        for label, body in (("real then pkce", real + exempt_pkce),
                            ("pkce then real", exempt_pkce + real),
                            ("real then identifier", real + exempt_id),
                            ("identifier then real", exempt_id + real)):
            with self.subTest(order=label):
                source = "function setPassword(req) {\n" + body + "}\n"
                self.assertTrue(_classes({"i.js": source}, "weak-password-hash"),
                                f"the real weak hash was lost when ordered: {label}")

    def test_a_pkce_verifier_is_still_exempt(self):
        """Pre-existing behaviour that must not regress: a PKCE verifier is hashed by design."""
        source = ("function setPassword(u) {\n"
                  "const h = crypto.createHash('sha256').update(codeVerifier).digest('hex');\n}\n")
        self.assertEqual(_classes({"h.js": source}, "weak-password-hash"), [])


class SenderControlTests(unittest.TestCase):
    """#143: more condition shapes count as a sender check — without crediting more than that."""

    def scope(self, body):
        return {"params": ["msg", "sender"], "body": body}

    def test_the_condition_shapes_are_recognised(self):
        for label, body in (
            ("optional chaining", 'if (sender?.origin !== "https://ok.example") return;\ndo();'),
            ("logical NOT", 'if (!(sender.origin === "https://ok.example")) return;\ndo();'),
            ("loose inequality", 'if (sender.origin != "https://ok.example") return;\ndo();'),
            ("loose equality", 'if (sender.origin == "https://ok.example") { return do(); }'),
            ("yoda", 'if ("https://ok.example" !== sender.origin) return;\ndo();'),
            ("strict, pre-existing", 'if (sender.origin === "https://ok.example") { do(); }'),
        ):
            with self.subTest(label=label):
                self.assertTrue(_sender_control(self.scope(body)))

    # --- the controls #143 did not ship -------------------------------------------------------
    def test_a_handler_with_NO_sender_check_still_reports(self):
        self.assertFalse(_sender_control(self.scope("do(msg);")))

    def test_a_wildcard_origin_is_not_a_control(self):
        self.assertFalse(_sender_control(self.scope('if (sender.origin !== "*") return;\ndo();')))

    def test_a_check_on_the_MESSAGE_is_not_a_check_on_the_sender(self):
        self.assertFalse(_sender_control(
            self.scope('if (msg.claimedOrigin !== "https://ok.example") return;\ndo();')))

    def test_a_reassigned_sender_is_not_authorized_by_an_earlier_check(self):
        """Pre-existing guard that must survive the predicate rewrite."""
        self.assertFalse(_sender_control(
            self.scope('if (sender.origin !== "https://ok.example") return;\nsender = other;\ndo();')))

    def test_an_inert_alias_prologue_is_resolved_back_to_the_sender(self):
        """`const { origin } = sender;` before the guard is the common modern shape.

        `guarded_body` requires the body to START with `if (`, so any binding in front of the check
        made the handler read as unvalidated. The prologue is now rewritten back to a direct
        `sender.<prop>` read — but only while every statement in it is an inert sender alias.
        """
        for label, body in (
            ("destructured", 'const { origin } = sender;\nif (origin !== "https://ok.example") return;\ndo();'),
            ("renamed", 'const { origin: o } = sender;\nif (o !== "https://ok.example") return;\ndo();'),
            ("assigned", 'const o = sender.origin;\nif (o !== "https://ok.example") return;\ndo();'),
            ("optional-chained", 'const o = sender?.origin;\nif (o !== "https://ok.example") return;\ndo();'),
            ("two props", 'const { id, origin } = sender;\nif (origin !== "https://ok.example") return;\ndo();'),
        ):
            with self.subTest(label=label):
                self.assertTrue(_sender_control(self.scope(body)))

    def test_a_REBOUND_alias_is_not_credited(self):
        """The control that makes alias support safe: checked value != used value."""
        body = ('let { origin } = sender;\norigin = "https://ok.example";\n'
                'if (origin === "https://ok.example") { do(); }')
        self.assertFalse(_sender_control(self.scope(body)))

    def test_a_call_before_the_guard_abandons_the_rewrite(self):
        """A guard that runs after something acted on untrusted input is too late."""
        body = ('const o = sender.origin;\nsideEffect(msg);\n'
                'if (o !== "https://ok.example") return;\ndo();')
        self.assertFalse(_sender_control(self.scope(body)))

    def test_an_alias_of_something_other_than_the_sender_is_not_credited(self):
        body = 'const o = msg.claimedOrigin;\nif (o !== "https://ok.example") return;\ndo();'
        self.assertFalse(_sender_control(self.scope(body)))

    def test_a_wildcard_reached_through_an_alias_is_still_not_a_control(self):
        body = 'const o = sender.origin;\nif (o !== "*") return;\ndo();'
        self.assertFalse(_sender_control(self.scope(body)))

    def test_alias_support_does_not_weaken_the_direct_forms(self):
        """Direct reads must behave exactly as before the prologue rewrite existed."""
        self.assertTrue(_sender_control(
            self.scope('if (sender.origin === "https://ok.example") { do(); }')))
        self.assertFalse(_sender_control(self.scope("do(msg);")))

    def test_a_literal_allowlist_still_resolves(self):
        body = 'if (!["https://a.example","https://b.example"].includes(sender.origin)) return;\ndo();'
        self.assertTrue(_sender_control(self.scope(body)))


if __name__ == "__main__":
    unittest.main()

"""Timing comparisons remain local advisory evidence, not blanket safety verdicts."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.crypto_usage import CryptoUsageExtractor, _timing_comparison, MAX_COMPARISON_OPERAND


class CryptoComparisonTests(unittest.TestCase):
    def scan(self, source, suffix='.js'):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ('app' + suffix)).write_text(source)
            return CryptoUsageExtractor().extract(RepoContext(root), {})['findings']

    def timing(self, source, suffix='.js'):
        return [row for row in self.scan(source, suffix) if row['kind'] == 'timing-unsafe-compare']

    def test_missing_and_type_checks_are_not_credential_comparisons(self):
        for expression in ("req.headers.authorization === null", "null !== req.headers.authorization",
                           "req.headers.authorization === ''", "'' != req.headers.authorization",
                           "req.headers.authorization === false", "true === token",
                           "typeof req.headers.authorization === 'string'", "'string' === typeof token",
                           "typeof(req.headers['authorization']) !== 'string'"):
            with self.subTest(expression=expression):
                self.assertEqual(self.timing('if (' + expression + ') return;'), [])

    def test_nonempty_literals_and_concatenations_remain_leads_both_directions(self):
        for expression in ("req.headers.authorization === 'Bearer synthetic-credential'",
                           "'Bearer synthetic-credential' === req.headers.authorization",
                           "token === 'string'", "'string' !== password",
                           "req.header('authorization') === 'Basic ' + secret",
                           "typeof token + secret === providedToken", "secret === typeof token"):
            with self.subTest(expression=expression):
                self.assertEqual(len(self.timing('if (' + expression + ') grant();')), 1)

    def test_member_bracket_and_reversed_credential_operands(self):
        for expression in ("validSignature === req.headers.signature", "providedToken !== expectedToken",
                           "req.body.password == storedHash", "req.body['password'] != storedHash",
                           "request.headers['x-api-key'] === configured", "req.header('authorization') === configured",
                           "config.secret === provided", "provided === config['secret']"):
            with self.subTest(expression=expression):
                self.assertEqual(len(self.timing('if (' + expression + ') grant();')), 1)

    def test_javascript_undefined_may_be_shadowed(self):
        for source in ("if (token === undefined) grant();",
                       "function check(token, undefined) { return token === undefined; }",
                       "const undefined = expectedToken; if(undefined === token) grant();"):
            with self.subTest(source=source):
                self.assertEqual(len(self.timing(source)), 1)

    def test_python_keywords_and_credential_equality(self):
        for expression in ("token == None", "None != token", "secret == True", "False == password", "password == ''"):
            with self.subTest(expression=expression):
                self.assertEqual(self.timing('if ' + expression + ':\n pass\n', '.py'), [])
        for expression in ("request.headers['authorization'] == expected", "expected == token", "token == 'None'", "token == undefined"):
            with self.subTest(expression=expression):
                self.assertEqual(len(self.timing('if ' + expression + ':\n grant()\n', '.py')), 1)

    def test_timing_safe_call_or_comment_elsewhere_cannot_hide_comparison(self):
        unsafe = 'if (req.headers.authorization === expectedToken) grant();'
        for extra in ('// crypto.timingSafeEqual is recommended\n',
                      'function other(a,b){return crypto.timingSafeEqual(a,b);}',
                      'import { timingSafeEqual } from "crypto";',
                      'const message="use compare_digest";'):
            with self.subTest(extra=extra):
                self.assertEqual(len(self.timing(extra + '\n' + unsafe)), 1)
        source = 'if token == expected:\n grant()\ndef other(a,b):\n return hmac.compare_digest(a,b)\n'
        self.assertEqual(len(self.timing(source, '.py')), 1)

    def test_real_comparison_helpers_do_not_create_raw_equality_leads(self):
        self.assertEqual(self.timing("if (!crypto.timingSafeEqual(Buffer.from(req.header('authorization')||''),Buffer.from(expected))) deny();"), [])
        self.assertEqual(self.timing('return hmac.compare_digest(providedToken, expectedToken)', '.py'), [])
        # This is a boolean-result check; no claim that a similarly named function
        # actually implements a constant-time operation is made.
        self.assertEqual(self.timing('if (crypto.timingSafeEqual(token, expected) === false) deny();'), [])

    def test_comments_and_quoted_sample_code_do_not_create_comparisons(self):
        for source in ('// token === expected\n', '/* req.headers.authorization != expected */',
                       'const example="token === expected";', "const example='secret !== expected';",
                       'const example=`password === expected`;'):
            with self.subTest(source=source):
                self.assertEqual(self.timing(source), [])
        self.assertEqual(self.timing('# token == expected\nexample="token == expected"\n', '.py'), [])
        self.assertEqual(self.timing('sample="""token == expected"""\n', '.py'), [])

    def test_one_safe_comparison_does_not_hide_later_unsafe_comparison(self):
        rows = self.timing('if(token === null) return;\nif(token === expected) grant();')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['line'], 2)
        self.assertEqual(rows[0]['severity'], 'LOW')
        self.assertIn('unverified', rows[0]['control_scope'])
        self.assertIn('does not prove', rows[0]['detail'])
        self.assertEqual(len(self.timing('if(token === null || token === expected) grant();')), 1)

    def test_executable_string_interpolations_are_not_quoted_sample_code(self):
        self.assertEqual(len(self.timing('const result=`allowed: ${providedToken === expectedToken}`;')), 1)
        self.assertEqual(len(self.timing('result=f"allowed: {providedToken == expectedToken}"', '.py')), 1)
        self.assertEqual(self.timing('const result=`missing: ${token === null}`;'), [])
        self.assertEqual(self.timing('result=f"missing: {token == None}"', '.py'), [])
        self.assertEqual(self.timing('const example=`quoted \\${token === expected}`;'), [])
        self.assertEqual(len(self.timing(r'const result=`slash \\${token === expected}`;')), 1)
        self.assertEqual(self.timing('example=f"quoted {{token == expected}}"', '.py'), [])

    def test_large_or_unclosed_operand_does_not_prove_presence_check(self):
        long_name = 'x' * (MAX_COMPARISON_OPERAND + 1) + 'token'
        self.assertIsNotNone(_timing_comparison(long_name + ' === null', '.js'))
        self.assertEqual(len(self.timing('if (token === expected')), 1)
        self.assertEqual(len(self.timing('if (token === null + expected) grant();')), 1)

    def test_noncredential_state_and_relational_checks_are_outside_this_rule(self):
        for source in ("if(state === 'token') next();", 'if(count === 3) next();',
                       'if(password.length < 12) reject();'):
            self.assertEqual(self.timing(source), [])

    def test_triple_quoted_fstrings_keep_executable_comparisons(self):
        for quote in ('"""', "'''"):
            with self.subTest(quote=quote):
                for prefix in ('f', 'rf', 'fr'):
                    source = 'result=' + prefix + quote + 'allowed: {providedToken == expectedToken}' + quote
                    self.assertEqual(len(self.timing(source, '.py')), 1)
                self.assertEqual(self.timing('sample=' + quote + 'providedToken == expectedToken' + quote, '.py'), [])
                self.assertEqual(self.timing('sample=r' + quote + '{providedToken == expectedToken}' + quote, '.py'), [])
                self.assertEqual(self.timing('sample=f' + quote + '{{providedToken == expectedToken}}' + quote, '.py'), [])
                self.assertEqual(self.timing('result=f' + quote + 'missing: {token == None}' + quote, '.py'), [])

    def test_division_expression_is_not_assumed_to_be_a_regex_literal(self):
        rows = self.timing('if (providedToken / divisor === expectedToken) grant();')
        self.assertEqual(len(rows), 1)
        self.assertIn('JavaScript regex literals are unresolved', rows[0]['control_scope'])

    def test_password_hash_and_jwt_rules_are_unchanged(self):
        source = "const options={}; jwt.verify(token,key,options); function login(req){return crypto.createHash('sha256').update(req.body['password']).digest('hex');}"
        kinds = {row['kind'] for row in self.scan(source)}
        self.assertIn('weak-password-hash', kinds)
        self.assertIn('jwt-verify-no-algorithms', kinds)


if __name__ == '__main__':
    unittest.main()

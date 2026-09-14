"""Password comparisons must enforce acceptance in the same login function."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator.extractors.auth import AuthExtractor
from websec_validator.extractors.base import RepoContext


class AuthControlScopeTests(unittest.TestCase):
    def scan(self, body, extra="", parameters="email, password"):
        return self.source('export async function login(' + parameters + '){' + body + '}' + extra)

    def source(self, text):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "auth.js").write_text(text)
            return [f for f in AuthExtractor().extract(RepoContext(root), {})["broken_auth"]
                    if f["kind"] == "login-without-hash-compare"]

    def test_original_comment_and_other_scope_repros(self):
        body = 'if(password.length >= 8) return issueSession(email); return null;'
        for extra in ('', '// bcrypt.compare is available\n',
                      'async function other(a,b){return bcrypt.compare(a,b);}',
                      'const note="bcrypt.compare(password,storedHash)";'):
            with self.subTest(extra=extra):
                self.assertEqual(len(self.scan(body, extra)), 1)

    def test_supported_comparisons_enforce_password_acceptance(self):
        for body in ('if(password.length >= 8 && await bcrypt.compare(password,storedHash)) return issueSession(email); return null;',
                     'if(password.length >= 8 && bcrypt.compareSync(password,storedHash)) return issueSession(email); return null;',
                     'if(!(await argon2.verify(storedHash,password))) return null; if(password.length >= 8) return issueSession(email); return null;',
                     'if(!(await bcrypt.compare(password,storedHash))) {return false;} if(password.length >= 8) return issueSession(email); return null;'):
            with self.subTest(body=body):
                self.assertEqual(self.scan(body), [])
        self.assertEqual(self.source('import bcrypt from "bcrypt"; async function authorize(c){if(c.password.length>=8 && await bcrypt.compare(c.password,u.passwordHash))return u;return null;}'), [])

    def test_ignored_promise_inverted_or_reassigned_comparisons(self):
        unsafe = 'if(password.length >= 8) return issueSession(email); return null;'
        for body in ('await bcrypt.compare(password,storedHash);' + unsafe,
                     'if(password.length >= 8 && bcrypt.compare(password,storedHash)) return issueSession(email); return null;',
                     'if(password.length >= 8 && !(await bcrypt.compare(password,storedHash))) return issueSession(email); return null;',
                     'if(password.length >= 8 || await bcrypt.compare(password,storedHash)) return issueSession(email); return null;',
                     'if(!(await bcrypt.compare(password,storedHash))) return null; password=other;' + unsafe,
                     'if(password.length >= 8 && await bcrypt.compare(other,storedHash)) return issueSession(email); return null;',
                     'if(password.length >= 8 && await checkPassword(password)) return issueSession(email); return null;',
                     'async function other(){return bcrypt.compare(password,storedHash);}' + unsafe):
            with self.subTest(body=body):
                self.assertEqual(len(self.scan(body)), 1)

    def test_shadowed_library_and_mixed_login_functions(self):
        safe = 'async function authorize(c){if(c.password.length>=8 && await bcrypt.compare(c.password,u.hash))return u;return null;}'
        unsafe = 'async function login(password){if(password.length>=8)return issueSession();return null;}'
        self.assertEqual(len(self.source(safe + unsafe)), 1)
        self.assertEqual(len(self.source(safe + 'function bcrypt(){return true;}')), 1)
        self.assertEqual(len(self.source(safe + 'bcrypt.compare=async()=>true;')), 1)

    def test_supplied_credentials_cannot_establish_stored_hash(self):
        for compare in ('bcrypt.compare(credentials.password,credentials.hash)',
                        'argon2.verify(credentials.hash,credentials.password)'):
            text = 'async function authorize(credentials){if(credentials.password.length>=8 && await ' + compare + ')return issueSession();return null;}'
            self.assertEqual(len(self.source(text)), 1)
        self.assertEqual(self.source('async function authorize(credentials){if(credentials.password.length>=8 && await bcrypt.compare(credentials.password,dbUser.passwordHash))return issueSession();return null;}'), [])

    def test_nested_and_string_length_checks_do_not_create_fake_login(self):
        self.assertEqual(self.source('async function login(){function helper(password){if(password.length>=8)return true;}return null;}'), [])
        self.assertEqual(self.source('async function login(){const s="password.length>=8";return null;}'), [])

    def test_unsupported_typed_and_concise_arrow_scopes_stay_visible(self):
        for text in ('async function login(password: string): Promise<User> {if(password.length>=8)return user;return null;}',
                     'const login = password => password.length>=8 ? user : null;',
                     'async function other(){return bcrypt.compare(x,y);} async function login(password): User {if(password.length>=8)return user;}'):
            self.assertEqual(len(self.source(text)), 1)


if __name__ == "__main__":
    unittest.main()

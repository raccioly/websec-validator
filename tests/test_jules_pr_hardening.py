"""Hardened integration of seven Jules-authored detector PRs (#181 #182 #184 #186 #188 #189 #191).

Every class pairs the PR's own false-positive regression (now suppressed) with negative controls
proving the true positives the PR as written would have lost still fire — the repo's
quality-monotonic bar: no false-negative regression, no FP comeback.
"""

import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from websec_validator.extractors.authz import AuthzExtractor                # noqa: E402
from websec_validator.extractors.base import RepoContext                    # noqa: E402
from websec_validator.extractors.crypto_usage import CryptoUsageExtractor   # noqa: E402
from websec_validator.extractors.graphql import GraphQLExtractor            # noqa: E402
from websec_validator.extractors.integrations import IntegrationsExtractor  # noqa: E402
from websec_validator.extractors.surface import (                           # noqa: E402
    SurfaceExtractor, _redos_literal_candidates)
from websec_validator.extractors.tenant import TenantExtractor              # noqa: E402


def repo(files: dict) -> RepoContext:
    d = Path(tempfile.mkdtemp())
    for rel, body in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return RepoContext(d)


class TenantKeyIdentifierTests(unittest.TestCase):
    """#191: `organizationIdentifier` is not `organizationId`; composites and plurals still count."""

    def _keys(self, source):
        out = TenantExtractor().extract(repo({"a.ts": source}), {})
        return {c["key"]: c["occurrences"] for c in out["candidates"]}

    def test_pr191_identifier_words_are_not_tenant_keys(self):
        files = {"1.ts": "const organizationIdentifier = 1;", "2.ts": "const companyIdentifier = 1;",
                 "3.ts": "const projectIdentity = 1;", "4.ts": "const teamIdentifier = 1;",
                 "5.ts": "const deviceIdentifier = 1;", "6.ts": "const visitorIdentity = 1;",
                 "7.ts": "const subscriptionIdentifier = 1;", "8.py": "tenant_identifier = 1"}
        self.assertEqual(TenantExtractor().extract(repo(files), {})["candidates"], [])

    def test_snake_case_composites_still_count(self):
        # a `\b...\b` match (the PR as written) drops every one of these
        self.assertEqual(self._keys("const current_tenant_id = 1;"), {"tenant_id": 1})
        self.assertEqual(self._keys("session_tenant_id = x"), {"tenant_id": 1})
        self.assertEqual(self._keys("user_org_id = x"), {"org_id": 1})

    def test_member_access_destructuring_and_plurals_still_count(self):
        self.assertEqual(self._keys("if (user.groupId !== row.groupId) deny();"), {"groupId": 2})
        self.assertEqual(self._keys("prisma.doc.findMany({ where: { orgId } })"), {"orgId": 1})
        # a membership LIST compared against the boundary is a tenant reference, as before
        self.assertEqual(self._keys("if (!user.groupIds.includes(id)) deny();"), {"groupId": 1})

    def test_mixed_line_counts_only_the_real_key(self):
        self.assertEqual(self._keys("const organizationIdentifier = row.organizationId;"),
                         {"organizationId": 1})


class WeakPasswordHashMetadataTests(unittest.TestCase):
    """#189: exact metadata suffixes are exempt; a bare credential-shaped name is not."""

    def _weak(self, files):
        out = CryptoUsageExtractor().extract(repo(files), {})
        return [f for f in out["findings"] if f["kind"] == "weak-password-hash"]

    def test_pr189_metadata_suffixes_suppressed(self):
        self.assertEqual(self._weak({
            "a.py": "url_hash = hashlib.md5(db_password_url.encode()).hexdigest()\n",
            "b.py": "link_hash = hashlib.sha256(password_reset_code.encode()).hexdigest()\n",
            "c.js": "const id = createHash('md5').update(passwordFileName).digest('hex');\n",
            "e.js": "const k = createHash('sha256').update(smtp_password_secret_arn).digest('hex');\n",
            "f.js": "const etag = createHash('md5').update(password_updated_date).digest('hex');\n",
            "g.js": "const sig = createHash('sha256').update(passwordless_token).digest('hex');\n",
            "h.js": "const p = createHash('md5').update(password_prompt_msg).digest('hex');\n"}), [])

    def test_bare_password_and_credential_names_still_flagged(self):
        for name, source in {
                "md5.js": "const h = createHash('md5').update(password).digest('hex');\n",
                "md5.py": "h = hashlib.md5(password.encode()).hexdigest()\n",
                "member.js": "const h = createHash('sha256').update(user.password).digest('hex');\n",
                # `password_secret` IS the secret: the PR's optional `secret_?(?:arn|id|name)?` exempted it
                "secret.py": "h = hashlib.md5(password_secret.encode()).hexdigest()\n",
                "secretCamel.js": "const h = createHash('md5').update(passwordSecret).digest('hex');\n",
                # `passwordFile` may be the password bytes read from a file; only *_path/_name/_id is metadata
                "file.js": "const h = createHash('md5').update(passwordFile).digest('hex');\n"}.items():
            with self.subTest(name=name):
                self.assertTrue(self._weak({name: source}))


class WeakPasswordHashNonceArgumentTests(unittest.TestCase):
    """#182: inside a password-named function, a digest of a pure random source is a nonce."""

    def _weak(self, source):
        out = CryptoUsageExtractor().extract(repo({"x.js": source}), {})
        return [f for f in out["findings"] if f["kind"] == "weak-password-hash"]

    def test_pr182_random_sources_suppressed(self):
        # The PR's own snippet used non-password function names, which main never flagged;
        # these names put the digest on the PW_CONTEXT path where the FP actually occurs.
        self.assertEqual(self._weak(
            "function hashPasswordResetNonce() { return crypto.createHash('md5').update(uuid.v4()).digest('hex'); }\n"
            "function hashPasswordSalt() { return crypto.createHash('sha256').update(Math.random().toString()).digest('hex'); }\n"
            "function hashPasswordSeed() { return crypto.createHash('md5').update(crypto.randomBytes(16)).digest('hex'); }\n"
            "function hashPasswordU() { return crypto.createHash('md5').update(crypto.randomUUID()).digest('hex'); }\n"
            "function hashPasswordV() { return crypto.createHash('md5').update(uuidv4()).digest('hex'); }\n"
            "function hashPasswordS() { return crypto.createHash('md5').update(Math.random().toString(36).slice(2)).digest('hex'); }\n"), [])

    def test_pr182_stringified_outer_config_suppressed(self):
        self.assertEqual(self._weak(
            "const config = load();\n"
            "function setPasswordPolicy() { return crypto.createHash('md5').update(JSON.stringify(config)).digest('hex'); }\n"), [])

    def test_renamed_password_wrapped_in_conversion_still_flagged(self):
        for name, source in {
                # an unanchored `.toString\(` exemption (the PR as written) hid this
                "toString": "function hashPassword(input) { return crypto.createHash('md5').update(input.toString()).digest('hex'); }",
                # an unanchored `JSON\.stringify` exemption hid these
                "stringify-literal": "function hashPassword(p) { return crypto.createHash('md5').update(JSON.stringify({password})).digest('hex'); }",
                "stringify-param": "function hashPassword(pw) { return crypto.createHash('md5').update(JSON.stringify(pw)).digest('hex'); }",
                "stringify-local": "function hashPassword(req) { const p = req.body.p; return crypto.createHash('md5').update(JSON.stringify(p)).digest('hex'); }",
                "stringify-destructured": "function hashPassword({ pw }) { return crypto.createHash('md5').update(JSON.stringify(pw)).digest('hex'); }",
                "stringify-credential": "function hashPassword() { return crypto.createHash('md5').update(JSON.stringify(creds.passwordData)).digest('hex'); }",
                "String()": "function hashPassword(input) { return crypto.createHash('md5').update(String(input)).digest('hex'); }",
                "random-plus-password": "function hashPassword(pw) { return crypto.createHash('md5').update(Math.random() + pw).digest('hex'); }",
                "randomBytes-plus-password": "function hashPassword(pw) { return crypto.createHash('md5').update(crypto.randomBytes(8) + pw).digest('hex'); }",
                "direct-toString": "const h = createHash('md5').update(password.toString()).digest('hex');",
                "direct-stringify": "const h = createHash('md5').update(JSON.stringify({password})).digest('hex');",
                "direct-String": "const h = createHash('md5').update(String(password)).digest('hex');"}.items():
            with self.subTest(name=name):
                self.assertTrue(self._weak(source))


class ModernAuthnIdiomTests(unittest.TestCase):
    """#188: Clerk `protect()` and Supabase `auth.getUser()` credit; record lookups never do."""

    FACTS = {"routes": {"endpoints": [{"method": "POST", "path": "/api/do", "code_path": "api/route.ts"}]}}

    def _guarded(self, source):
        return AuthzExtractor().extract(repo({"api/route.ts": source}), self.FACTS)["endpoint_guards"][0]["guarded"]

    def test_pr188_clerk_and_supabase_credited(self):
        for name, source in {
                "clerk-v5": "export async function POST() { auth().protect(); }",
                "clerk-v5-await": "export async function POST() { await auth().protect(); }",
                "clerk-v6": "export async function POST() { await auth.protect(); }",
                "clerk-v6-role": "export async function POST() { await auth.protect({ role: 'org:admin' }); }",
                "supabase-401": ("export async function POST() { const {data} = await supabase.auth.getUser(); "
                                 "if (!data.user) return new Response('Unauthorized', {status: 401}); }")}.items():
            with self.subTest(name=name):
                self.assertTrue(self._guarded(source))

    def test_pr188_look_alikes_not_credited(self):
        for name, source in {
                "protectOther-v5": "export async function POST() { auth().protectOther(); }",
                "protectOther-v6": "export async function POST() { await auth.protectOther(); }",
                "member-auth": "export async function POST() { await session.auth.protect(); }",
                "supabase-no-reject": ("export async function POST() { const {data} = await supabase.auth.getUser(); "
                                       "return new Response('OK'); }"),
                "supabase-getUsers": ("export async function POST() { const {data} = await supabase.auth.getUsers(); "
                                      "if (!data.user) return new Response('Unauthorized', {status: 401}); }")}.items():
            with self.subTest(name=name):
                self.assertFalse(self._guarded(source))

    def test_record_lookup_named_getUser_is_not_authentication(self):
        # the PR's bare `getUser\s*\(` credited all of these, hiding missing-auth findings
        for name, source in {
                "db-401": ("export async function POST(req) { const user = await db.getUser(id); "
                           "if (!user) return new Response('Unauthorized', {status: 401}); }"),
                "db-403": ("export async function POST(req) { const user = await db.getUser(id); "
                           "if (!user) return NextResponse.json({}, {status: 403}); }"),
                "users-401": ("export async function POST(req) { const u = await users.getUser(req.id); "
                              "if (!u) return new Response('x', {status: 401}); }"),
                "bare-401": ("export async function POST(req) { const u = await getUser(req.id); "
                             "if (!u) return new Response('x', {status: 401}); }")}.items():
            with self.subTest(name=name):
                self.assertFalse(self._guarded(source))


def _handler(body: str) -> str:
    return "export default async function handler(req) {\n" + body + "\n}\n"


class EntitlementRequestSideFlagTests(unittest.TestCase):
    """#186: request/form validation flags are not provider verdicts; provider replies still fire."""

    def _kinds(self, files):
        out = IntegrationsExtractor().extract(repo(files), {"routes": {"endpoints": []}})
        return {f["kind"] for f in out["findings"]}

    def test_pr186_request_side_flags_do_not_grant(self):
        kinds = self._kinds({
            "src/api/license1.js": ("import { verify_license } from 'utils';\n"
                                    "export const POST = async (req, res) => {\n"
                                    "  if (req.body.valid) return res.send('OK');\n"
                                    "  if (req.form.valid) return res.send('OK');\n}\n"),
            "src/api/license2.ts": ("import { check_subscription } from 'utils';\n"
                                    "export async function POST(req) { if (schema.valid) return; if (form.valid) return;"
                                    " if (input.valid) return; }\n"),
            "src/api/license3.js": ("import { verify_subscription } from 'utils';\n"
                                    "export async function handler(req) { if (req.body.success) return;"
                                    " if (request.query.valid) return; }\n")})
        self.assertNotIn("entitlement-revocation-not-checked", kinds)

    def test_provider_reply_verdicts_still_fire(self):
        for name, verdict in {"lemonsqueezy-data": "data.valid", "keygen-meta": "data.meta.valid",
                              "response": "response.valid", "res": "res.valid", "payload": "payload.success",
                              "parsed-body": "body.valid", "result": "result.valid"}.items():
            root = verdict.split(".")[0]
            with self.subTest(name=name):
                kinds = self._kinds({"api/lic.ts": _handler(
                    f"const {root} = await (await fetch('https://api.lemonsqueezy.com/v1/licenses/validate')).json();\n"
                    f"if ({verdict}) return grant();")})
                self.assertIn("entitlement-revocation-not-checked", kinds)
                self.assertIn("no-per-license-usage-cap", kinds)

    def test_usage_cap_does_not_require_a_truthy_grant_tell(self):
        # the PR gated this finding on GRANT_ON_SUCCESS; a status-based grant has no `.valid`
        kinds = self._kinds({"api/lic.ts": _handler(
            "const lic = await db.licenses.find(licenseKey);\n"
            "if (lic.status !== 'active') return deny();\nreturn grant();")})
        self.assertIn("no-per-license-usage-cap", kinds)


class RedundantSecretFetchLocalFileTests(unittest.TestCase):
    """#186: an explicit local path is not a secret-manager key; extension alone proves nothing."""

    def _dup(self, files):
        out = IntegrationsExtractor().extract(repo(files), {})
        return [f for f in out["findings"] if f["kind"] == "redundant-secret-fetch"]

    def test_pr186_explicit_local_paths_suppressed(self):
        self.assertEqual(self._dup({
            "src/a.js": "const s1 = read_secret('./secrets/db.txt'); const s2 = read_secret('./secrets/db.txt');",
            "src/b.py": "s1 = read_secret('../conf/env.yml'); s2 = read_secret('../conf/env.yml')",
            "src/c.py": "k1 = read_secret('~/.app/key.pem'); k2 = read_secret('~/.app/key.pem')"}), [])

    def test_secret_names_with_file_extensions_still_fire(self):
        # AWS Secrets Manager / SSM and Vault names legally contain dots; the PR's extension
        # lookahead also backtracked past the rejected quote and captured garbage keys.
        for name, source in {
                "aws-json": ("await sm.send(new GetSecretValueCommand({ SecretId: 'prod/firebase-adminsdk.json' }));"
                             " await sm.send(new GetSecretValueCommand({ SecretId: 'prod/firebase-adminsdk.json' }));"),
                "ssm-yaml": "ssm.getParameter({Name: '/app/config.yaml'}); ssm.getParameter({Name: '/app/config.yaml'});",
                "vault-pem": "a = read_secret('tls/server.pem'); b = read_secret('tls/server.pem')",
                "plain": "const a = await getSecret('db-pass'); const b = await getSecret('db-pass');"}.items():
            with self.subTest(name=name):
                found = self._dup({"src/s.ts": source})
                self.assertTrue(found)
                self.assertNotIn("read_secret(", found[0]["detail"])
                self.assertNotIn("SecretId:", found[0]["detail"])


class RegexLiteralRedosTests(unittest.TestCase):
    """#184: nested-quantifier regex LITERALS, never arithmetic, strings or comments."""

    def _redos(self, source, name="app.js"):
        out = SurfaceExtractor().extract(repo({name: source}), {})
        return name in out["sinks"].get("redos", {}).get("files", [])

    def test_pr184_nested_quantifier_literal_flagged(self):
        self.assertTrue(self._redos("const regexPattern = /([0-9]+)+\\#/;"))
        self.assertFalse(self._redos("const safe = /[0-9]+\\#/;"))

    def test_catastrophic_literals_in_every_literal_position(self):
        for source in ["const r = /(a*)*b/;", "if (s.match(/(\\w+)+$/)) {}", "return /^(\\d+)*$/.test(x);",
                       "const ok = cond && /(a+)+/.test(s);", "const o = { re: /((ab)+)+c/ };",
                       "const r = x ? /(a{1,})+/ : null;", "  /(x+)+y/.test(input)",
                       "const r = /(a\\/+)+$/;", "const r = /([a-z]+)+[/]/;"]:
            with self.subTest(source=source):
                self.assertTrue(self._redos(source))
        self.assertTrue(self._redos("if s =~ /(a+)+$/ then end", "a.rb"))

    def test_division_strings_comments_and_safe_literals_not_flagged(self):
        for source in ["const r = width / (a+b)*scale / 2;", "const r = x / (a+b)*c / (d+e)*f / 2;",
                       "x /= (a+b)*c / 2;", "arr[i] / (a+b)*c / 2", "const r = (y) / (a+b)*c / 2;",
                       "const z = a\n  ? b / (c+d)*e / f\n  : 0;",
                       "const u = '/api/(v1+)*/x/';", 'fetch("/users/(id+)*/x/")', "const t = `${base}/(a+b)*/c/`;",
                       "// (a+b)* and /(a+)+/ in a comment\nconst k = 1;", "/* /(a+)+/ */ const k = 1;",
                       "const s = /\\(a+\\)+/;", "const s = /([+*])+/;", "const s = /(a+)?b/;"]:
            with self.subTest(source=source):
                self.assertFalse(self._redos(source))
        self.assertFalse(self._redos("r = a / (b+c)*d / 2\n", "a.py"))  # Python has no regex literals

    def test_literal_scan_is_linear_on_adversarial_lines(self):
        for line in ["=/" * 5000, "= /[" + "a" * 10000, "x = /" + "(" * 5000 + "a+" + ")+" * 5000 + "/",
                     "(" * 10000, "= /" + "\\a" * 5000, "=" + " /(a+b)*" * 1250, "= /" + "(a+" * 3300]:
            started = time.perf_counter()
            _redos_literal_candidates(line)
            self.assertLess(time.perf_counter() - started, 0.5, line[:20])


class GraphqlKwargsTests(unittest.TestCase):
    """#181: Python kwargs are read; app-specific mode-conditional middleware is not a control."""

    SCHEMA = "import graphene\nschema = graphene.Schema(query=Query)\n"

    def _gql(self, source, name="app.py"):
        return GraphQLExtractor().extract(repo({name: source}), {})

    def test_pr181_python_kwargs(self):
        out = self._gql(self.SCHEMA + "GraphQLView.as_view('graphql', schema=schema, graphiql=True, introspection=True)")
        self.assertTrue(out["present"])
        self.assertTrue(out["playground_enabled"])
        self.assertEqual(out["introspection"], "enabled")
        self.assertEqual(self._gql(self.SCHEMA + "GraphQLView.as_view('graphql', schema=schema, introspection=False)")
                         ["introspection"], "disabled")

    def test_negated_kwarg_names_do_not_flip_state(self):
        self.assertEqual(self._gql(self.SCHEMA + "view(schema=schema, disable_introspection=False)")["introspection"],
                         "unknown")
        self.assertEqual(self._gql(self.SCHEMA + "view(schema=schema, disable_introspection=True)")["introspection"],
                         "unknown")

    def test_js_object_keys_unchanged(self):
        self.assertEqual(self._gql("const s = new ApolloServer({ introspection: false })", "s.js")["introspection"],
                         "disabled")
        out = self._gql("const s = new ApolloServer({ introspection: true, playground: true })", "s.js")
        self.assertEqual(out["introspection"], "enabled")
        self.assertTrue(out["playground_enabled"])

    def test_dvga_mode_conditional_middleware_is_not_a_control(self):
        # Shape of DVGA core/views.py at the corpus-pinned revision a961308c02d1: these middlewares
        # `return next(...)` unless the server is hardened (seeded False), so the reviewed truth —
        # introspection on, no depth limit — must survive.
        out = self._gql(
            "from graphene import Schema\nimport graphene\nschema = graphene.Schema(query=Query)\n"
            "gql_middlew = [\n  middleware.CostProtectionMiddleware(),\n  middleware.DepthProtectionMiddleware(),\n"
            "  middleware.IntrospectionMiddleware(),\n]\n"
            "app.add_url_rule('/graphql', view_func=OverriddenView.as_view('graphql', schema=schema,"
            " middleware=gql_middlew, batch=True))\n"
            "app.add_url_rule('/graphiql', view_func=OverriddenView.as_view('graphiql', schema = schema,"
            " graphiql = True))\n")
        issues = {f["issue"] for f in out["findings"]}
        self.assertNotEqual(out["introspection"], "disabled")
        self.assertFalse(out["query_limiting_detected"])
        self.assertIn("no query depth/complexity limiting detected", issues)
        self.assertIn("introspection not explicitly disabled", issues)
        self.assertTrue(out["playground_enabled"])


if __name__ == "__main__":
    unittest.main()

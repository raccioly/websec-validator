"""Cookie and output controls must belong to the actual setter or response."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.pii_exposure import PiiExposureExtractor
from websec_validator.extractors.transport_security import TransportSecurityExtractor
from websec_validator import briefing


class OutputControlScopeTests(unittest.TestCase):
    def scan(self, files, extractor=TransportSecurityExtractor, routes=None):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name, source in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source)
            facts = {"stack": {"frameworks": ["express"], "service_inventory": [
                {"id": "a", "root": "a"}, {"id": "b", "root": "b"}]},
                "routes": {"endpoints": routes if routes is not None else [
                    {"method": "POST", "path": "/login", "code_path": "a/app.js"}]},
                "auth": {"token_location": "cookie", "cookie_names": ["sid"]}}
            return extractor().extract(RepoContext(root), facts)

    def cookie_leads(self, result):
        return [f for f in result["findings"] if f["kind"] == "cookie-flags"]

    def test_comments_strings_and_unrelated_cookie_cannot_supply_flags(self):
        unsafe = "res.cookie('sid', token);"
        for extra in ("// httpOnly:true secure:true sameSite:'strict'\n",
                      'const note="httpOnly:true secure:true sameSite:strict";',
                      "function other(){res.cookie('other',x,{httpOnly:true,secure:true,sameSite:'strict'});}"):
            with self.subTest(extra=extra):
                out = self.scan({"a/app.js": unsafe + extra})
                self.assertEqual(len(self.cookie_leads(out)), 1)
                self.assertEqual(out["passes"], [])
                self.assertIn("no-csrf-protection", [f["kind"] for f in out["findings"]])

    def test_false_unknown_duplicate_and_spread_options_are_not_passes(self):
        for options in ("{httpOnly:false,secure:true,sameSite:'strict'}",
                        "{httpOnly:true,secure:isProduction(),sameSite:'lax'}",
                        "{httpOnly:true,secure:true,sameSite:'none'}",
                        "{httpOnly:true,secure:true,secure:false,sameSite:'strict'}",
                        "{httpOnly:true,secure:true,sameSite:'strict',...options}", "options"):
            with self.subTest(options=options):
                out = self.scan({"a/app.js": "res.cookie('sid',token," + options + ");"})
                self.assertEqual(len(self.cookie_leads(out)), 1)
                self.assertEqual(out["passes"], [])
        out = self.scan({"a/app.js": "res.cookie('sid',token,{httpOnly:true,secure:config.secure,sameSite:'lax'});"})
        self.assertIsNone(out["cookie_security"]["secure"])

    def test_literal_flags_on_each_supported_setter(self):
        for source in ("res.cookie('sid',token,{httpOnly:true,secure:true,sameSite:'strict'});",
                       "reply.setCookie('sid',token,{httpOnly:true,secure:true,sameSite:true});",
                       "cookies.set({name:'sid',value:token,httpOnly:true,secure:true,sameSite:'lax'});",
                       "res.headers.set('Set-Cookie','sid=x; HttpOnly; Secure; SameSite=Lax');"):
            with self.subTest(source=source):
                out = self.scan({"a/app.js": source})
                self.assertEqual(self.cookie_leads(out), [])
                self.assertTrue(out["passes"])
        out = self.scan({"a/app.js": "res.setHeader('Set-Cookie',buildCookie());"})
        self.assertIsNone(out["cookie_security"]["secure"])
        self.assertTrue(self.cookie_leads(out))
        out = self.scan({"a/app.js": "res.setHeader('Set-Cookie','sid=x; HttpOnly; Secure; SameSite=Lax' + dynamic + '');"})
        self.assertIsNone(out["cookie_security"]["secure"])
        self.assertEqual(out["passes"], [])

    def test_separate_services_keep_distinct_cookie_evidence(self):
        out = self.scan({"a/app.js": "res.cookie('sid',token);", "b/app.js":
                         "res.cookie('sid',token,{httpOnly:true,secure:true,sameSite:'strict'});"})
        self.assertEqual([f["file"] for f in self.cookie_leads(out)], ["a/app.js"])
        self.assertEqual([f["service_id"] for f in out["cookie_occurrences"]], ["a", "b"])
        self.assertEqual(out["passes"], [])

    def test_header_maps_and_subscript_assignments_preserve_unknown_values(self):
        for rel, unsafe, safe in (
                ("a/app.js", "new Response(body,{headers:{'Set-Cookie':'sid='+token}});",
                 "new Response(body,{headers:{'Set-Cookie':'sid=x; HttpOnly; Secure; SameSite=Lax'}});"),
                ("a/app.py", "response.headers['Set-Cookie'] = value\n",
                 "response.headers['Set-Cookie'] = 'sid=x; HttpOnly; Secure; SameSite=Lax'\n")):
            out = self.scan({rel: unsafe})
            self.assertIsNone(out["cookie_security"]["secure"])
            self.assertEqual(len(self.cookie_leads(out)), 1)
            out = self.scan({rel: safe})
            self.assertEqual(self.cookie_leads(out), [])
            self.assertTrue(out["passes"])
        for source in ('const text="headers:{\'Set-Cookie\':\'sid=x\'}";',
                       '// response.headers["Set-Cookie"] = value\n'):
            self.assertIsNone(self.scan({"a/app.js": source})["cookie_security"])

    def test_briefing_does_not_assert_unknown_flag_is_absent(self):
        facts = {"transport_security": {"cookie_security": {
            "httponly": True, "secure": None, "samesite": True}}}
        text = briefing.render(facts, {}, [], [])
        self.assertIn("flags missing or unverified: Secure", text)
        self.assertNotIn("cookie set WITHOUT Secure", text)

    def test_nextauth_defaults_apply_only_to_its_initialized_auth_routes(self):
        source = "import NextAuth from 'next-auth'; const handler=NextAuth({providers:[]}); export {handler as GET, handler as POST};"
        auth_route = {"method": "POST", "path": "/api/auth/[...nextauth]", "code_path": "a/auth.js"}
        out = self.scan({"a/auth.js": source}, routes=[auth_route])
        self.assertNotIn("no-csrf-protection", [f["kind"] for f in out["findings"]])
        for files, routes in (({"a/auth.js": source, "b/app.js": "res.cookie('sid',token);"}, [auth_route]),
                              ({"a/auth.js": source}, [dict(auth_route, code_path="b/app.js")]),
                              ({"a/auth.js": source}, [dict(auth_route, path="/payments")]),
                              ({"a/auth.js": source.replace("{providers:[]}", "options")}, [auth_route]),
                              ({"a/auth.js": 'const text="import NextAuth from \'next-auth\'"; NextAuth({providers:[]});'}, [auth_route]),
                              ({"a/auth.js": "import NextAuth from 'next-auth'; function configure(NextAuth){NextAuth({providers:[]});}"}, [auth_route])):
            with self.subTest(files=files, routes=routes):
                out = self.scan(files, routes=routes)
                self.assertIn("no-csrf-protection", [f["kind"] for f in out["findings"]])

    def test_unused_nextauth_initializer_does_not_own_custom_handler(self):
        route = {"method": "POST", "path": "/api/auth/change-email", "code_path": "a/auth.js"}
        source = "import NextAuth from 'next-auth'; const unused=NextAuth({providers:[]}); export function POST(req){changeEmail(req.cookies.sid,req.body.email);return new Response('ok');}"
        out = self.scan({"a/auth.js": source}, routes=[route])
        self.assertIn("no-csrf-protection", [f["kind"] for f in out["findings"]])
        for source in ("import NextAuth from 'next-auth'; export const POST=NextAuth({providers:[]});",
                       "import NextAuth from 'next-auth'; const handler=NextAuth({providers:[]}); export {handler as POST};"):
            out = self.scan({"a/auth.js": source}, routes=[route])
            self.assertNotIn("no-csrf-protection", [f["kind"] for f in out["findings"]])
            out = self.scan({"a/auth.js": source}, routes=[dict(route, method="GET")])
            self.assertIn("no-csrf-protection", [f["kind"] for f in out["findings"]])

    def pii(self, source, extra=None):
        files = {"a/app.js": source}
        files.update(extra or {})
        return [f for f in self.scan(files, PiiExposureExtractor)["findings"]
                if f["kind"] == "raw-entity-pii-response"]

    def test_unrelated_pii_controls_do_not_suppress_raw_response(self):
        raw = "app.get('/customers/:id',async(req,res)=>{const customer=await db.customer.findById(req.params.id).select('email phone ssn');res.json(customer);});"
        for extra in ("// TODO toPublicCustomer(customer)\n", "interface ButtonProps {title:string}",
                      "function summary(users){return users.map(x=>({id:x.id}));}",
                      "function other(customer){return toPublicCustomer(customer);}"):
            with self.subTest(extra=extra):
                self.assertEqual(len(self.pii(raw + extra)), 1)
        self.assertEqual(len(self.pii(raw, {"b/app.js": "function summary(users){return users.map(x=>({id:x.id}));}"})), 1)

    def test_actual_response_projection_and_direct_transform(self):
        prefix = "function show(req,res){const customer=repo.findOne(req.params.id); /* email phone */ "
        for response in ("res.json({id:customer.id});", "res.json(toPublicCustomer(customer));",
                         "const view={id:customer.id};res.json(view);"):
            self.assertEqual(self.pii(prefix + response + "}"), [])
        self.assertEqual(len(self.pii(prefix + "res.json(customer);}")), 1)

    def test_ambiguous_projection_bindings_remain_review_leads(self):
        prefix = "function show(req,res){const customer=repo.findOne(req.params.id); /* email phone */ "
        for response in ("const view={...customer};res.json(view);",
                         "let view={id:customer.id};view=customer;res.json(view);",
                         "const view={id:customer.id};mutate(view);res.json(view);",
                         "const view=customer;function other(){const view={id:customer.id};}res.json(view);"):
            with self.subTest(response=response):
                self.assertEqual(len(self.pii(prefix + response + "}")), 1)

    def test_multiple_responses_preserve_each_raw_site(self):
        out = self.pii("function a(req,res){/* email */res.json(customer);}\nfunction b(req,res){res.json(customer);}")
        self.assertEqual([f["line"] for f in out], [1, 2])
        self.assertEqual(self.pii('const sample="res.json(customer)"; // email phone\n'), [])


if __name__ == "__main__":
    unittest.main()

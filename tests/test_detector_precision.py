"""Paired, synthetic regression cases for expression-scoped detector evidence."""
import tempfile
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.surface import SurfaceExtractor
from websec_validator.extractors.llm_security import LlmSecurityExtractor
from websec_validator.extractors.authz_dataflow import AuthzDataflowExtractor


class DetectorPrecisionTests(unittest.TestCase):
    def scan(self, text, name="app.ts", extractor=SurfaceExtractor, facts=None):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            return extractor().extract(RepoContext(root), facts or {"stack": {"datastores": ["postgres"]}})

    def kinds(self, text, extractor):
        return {item["kind"] for item in self.scan(text, extractor=extractor)["findings"]}

    def test_unrelated_sanitizers_comments_imports_never_hide_xss(self):
        vulnerable = "document.write(location.search);"
        for extra in ("// DOMPurify would help here\n", "/* sanitizeHtml */\n",
                      "import DOMPurify from 'dompurify';\n", "DOMPurify.sanitize(other);\n",
                      "function safe(){return DOMPurify.sanitize(other);}\n"):
            with self.subTest(extra=extra):
                self.assertEqual(self.scan(extra + vulnerable)["sink_counts"]["xss"], 1)
        self.assertNotIn("xss", self.scan("document.write(DOMPurify.sanitize(location.search));")["sinks"])

    def test_alias_reassignment_and_branch_uncertainty_keep_html_leads(self):
        for text in ("let output = DOMPurify.sanitize(location.search); el.innerHTML=output;",
                     "let output = DOMPurify.sanitize(location.search); output=location.hash; el.innerHTML=output;",
                     "if(flag){output=DOMPurify.sanitize(location.search);} el.innerHTML=output;",
                     "DOMPurify.sanitize = x=>x; el.innerHTML=DOMPurify.sanitize(location.search);",
                     "el.innerHTML=DOMPurify.sanitize(location.search)\n + location.hash;"):
            with self.subTest(text=text):
                self.assertIn("xss", self.scan(text)["sinks"])

    def test_mixed_html_sinks_have_distinct_occurrences(self):
        result = self.scan("document.write(location.search);\ndocument.write(location.hash);\n"
                           "document.write(DOMPurify.sanitize(location.search));")
        occurrences = [o for o in result["sink_occurrences"] if o["sink_class"] == "xss"]
        self.assertEqual(len(occurrences), 2)
        self.assertEqual([o["line"] for o in occurrences], [1, 2])
        self.assertEqual(len({o["semantic_id"] for o in occurrences}), 2)
        self.assertEqual(result["sinks"]["xss"]["files"], ["app.ts"])

    def test_occurrence_identity_survives_line_and_comment_changes(self):
        a = self.scan("document.write(location.search);")["sink_occurrences"][0]
        b = self.scan("// new comment\n\ndocument.write( location.search );")["sink_occurrences"][0]
        self.assertEqual(a["semantic_id"], b["semantic_id"])
        self.assertNotEqual(a["line"], b["line"])
        duplicate = self.scan("document.write(location.search);document.write(location.search);")
        ids = [o["semantic_id"] for o in duplicate["sink_occurrences"]]
        self.assertEqual(len(set(ids)), 2)

    def test_template_and_module_intake_has_paired_safe_unsafe_cases(self):
        cases = (("view.vue", '<div v-html="content"></div>', '<div v-html="DOMPurify.sanitize(content)"></div>'),
                 ("view.svelte", '<p>{@html content}</p>', '<p>{@html DOMPurify.sanitize(content)}</p>'),
                 ("view.html", '{{ user_bio | safe }}', '{{ user_bio }}'),
                 ("view.jinja2", '{{ user_bio | safe }}', '{{ user_bio }}'),
                 ("app.mts", 'document.write(location.search)', 'document.write("fixed")'),
                 ("app.cts", 'el.innerHTML = data', 'el.innerHTML = "fixed"'))
        for name, bad, good in cases:
            with self.subTest(name=name):
                self.assertIn("xss", self.scan(bad, name)["sinks"])
                self.assertNotIn("xss", self.scan(good, name)["sinks"])

    def test_template_comments_are_not_runtime_sinks(self):
        self.assertNotIn("xss", self.scan('<!-- <div v-html="content"/> -->', "view.html")["sinks"])

    def test_subprocess_false_applies_only_to_same_argv_call(self):
        safe = "subprocess.run(['echo',request.args['x']], shell=False)\n"
        bad = "subprocess.run('echo '+request.args['x'], shell=True)\n"
        self.assertNotIn("command-injection", self.scan(safe, "app.py")["sinks"])
        for prefix in (safe, "# shell=False\n", "def safe():\n    " + safe):
            with self.subTest(prefix=prefix):
                self.assertIn("command-injection", self.scan(prefix + bad, "app.py")["sinks"])

    def test_same_call_redirect_settings_only(self):
        bad = "axios.get(mediaUrl);"
        for extra in ("axios.get(other,{maxRedirects:0});", "// maxRedirects:0\n",
                      "function validateRedirect(url){return true;}\n"):
            with self.subTest(extra=extra):
                self.assertEqual(self.scan(extra + bad)["ssrf_redirect_unguarded"], ["app.ts"])
        for safe in ("axios.get(mediaUrl,{maxRedirects:0});",
                     "axios.get(mediaUrl,{beforeRedirect:(o)=>{if(!isAllowedUrl(o.href)) throw Error();}});"):
            self.assertEqual(self.scan(safe)["ssrf_redirect_unguarded"], [])
        self.assertTrue(self.scan("axios.get(mediaUrl,{beforeRedirect:(o)=>isAllowedUrl(o.href)});")["ssrf_redirect_unguarded"])

    def test_nested_redirect_control_cannot_protect_outer_call(self):
        result = self.scan("axios.get(mediaUrl,{debug:axios.get(other,{maxRedirects:0})});")
        self.assertTrue(result["ssrf_redirect_unguarded"])

    def test_following_client_not_hidden_by_other_safe_client(self):
        result = self.scan("requests.get(first,allow_redirects=False)\nrequests.get(second,allow_redirects=True)", "app.py")
        self.assertEqual(result["follows_redirect_no_allowlist"], ["app.py"])

    def test_host_allowlist_unrelated_or_reassigned_is_unverified(self):
        source = "const host=req.headers['host'];\n"
        for extra in ("const allowedHosts=['example.test'];\n", "function safe(){return allowedHosts.includes(host);}\n"):
            self.assertTrue(self.scan(source + extra + "res.redirect(host);")["host_header_redirect"])
        safe = source + "const base=allowedHosts.includes(host)?host:publicWebOrigin;\nres.redirect(base);"
        self.assertEqual(self.scan(safe)["host_header_redirect"], [])
        self.assertTrue(self.scan(safe.replace("res.redirect", "base=host;res.redirect"))["host_header_redirect"])

    def test_server_tsx_and_unknown_service_keep_request_evidence(self):
        text = "export async function GET(req){ return fetch(req.query.url); }"
        self.assertIn("ssrf", self.scan(text, "app/page.tsx")["sinks"])
        self.assertNotIn("ssrf", self.scan("'use client';\n" + text, "app/page.tsx")["sinks"])
        facts = {"stack": {"languages": ["javascript"], "frameworks": []}}
        self.assertIn("ssrf", self.scan(text, "services/unknown/app.ts", facts=facts)["sinks"])

    def test_llm_cap_is_per_invocation_not_comment_import_or_other_call(self):
        unsafe = "generateText({model,prompt});"
        for prefix in ("// maxOutputTokens:512\n", "import {maxOutputTokens} from './config';",
                       "generateText({model,prompt,maxOutputTokens:512});"):
            self.assertIn("llm-unbounded-generation", self.kinds(prefix + unsafe, LlmSecurityExtractor))
        self.assertNotIn("llm-unbounded-generation", self.kinds("generateText({model,prompt,maxOutputTokens:512});", LlmSecurityExtractor))
        self.assertIn("llm-unbounded-generation", self.kinds("generateText({model,prompt,debug:{maxOutputTokens:512}});", LlmSecurityExtractor))

    def test_prompt_guard_must_transform_the_prompt_value(self):
        unsafe = "generateText({model,prompt:`Data: ${excerptText}`});"
        for prefix in ("// sanitizePromptString\n", "sanitizePromptString(other);",
                       "function unrelated(){return sanitizePromptString(excerptText);}"):
            self.assertIn("llm-indirect-prompt-injection", self.kinds(prefix + unsafe, LlmSecurityExtractor))
        safe = "const c=sanitizePromptString(excerptText); generateText({model,prompt:`Data: ${c}`});"
        self.assertNotIn("llm-indirect-prompt-injection", self.kinds(safe, LlmSecurityExtractor))
        self.assertIn("llm-indirect-prompt-injection", self.kinds(safe.replace("generateText", "c=excerptText;generateText"), LlmSecurityExtractor))

    def test_human_gate_must_enclose_the_action(self):
        bad = "const tools={send:tool(()=>{sendEmail(args);})};"
        for prefix in ("// requireApproval\n", "function requireApproval(){return true;}",
                       "if(await confirmAction(other)){ sendMessage(other); }"):
            self.assertIn("llm-excessive-agency", self.kinds(prefix + bad, LlmSecurityExtractor))
        good = "const tools={send:tool(()=>{if(await confirmAction(args)){sendEmail(args);}})};"
        self.assertNotIn("llm-excessive-agency", self.kinds(good, LlmSecurityExtractor))
        self.assertIn("llm-excessive-agency", self.kinds(good + bad, LlmSecurityExtractor))

    def test_transaction_must_enclose_setting_on_same_receiver(self):
        setting = "SELECT set_config('app.user_id', ${id}, true)"
        bad = f"db.execute(sql`{setting}`);"
        for prefix in ("// BEGIN transaction tx.\n", "db.transaction(async(tx)=>{tx.execute('select 1')});",
                       "function unrelated(){db.transaction(async(tx)=>{tx.execute('select 1')});}"):
            self.assertIn("rls-context-no-transaction", self.kinds(prefix + bad, AuthzDataflowExtractor))
        good = f"db.transaction(async(tx)=>{{tx.execute(sql`{setting}`);}});"
        self.assertNotIn("rls-context-no-transaction", self.kinds(good, AuthzDataflowExtractor))
        self.assertIn("rls-context-no-transaction", self.kinds(good.replace("tx.execute", "db.execute"), AuthzDataflowExtractor))
        self.assertIn("rls-context-no-transaction", self.kinds(good + bad, AuthzDataflowExtractor))

    def test_verification_must_wrap_the_cookie_used_for_authorization(self):
        bad = "const role=req.cookies.get('access-role'); if(role!=='admin') return 403;"
        self.assertIn("unsigned-cookie-authz", self.kinds("jwtVerify(other,key);" + bad, AuthzDataflowExtractor))
        good = "const role=jwtVerify(req.cookies.get('access-role'),key); if(role!=='admin') return 403;"
        self.assertNotIn("unsigned-cookie-authz", self.kinds(good, AuthzDataflowExtractor))

    def test_renaming_dynamic_html_values_preserves_detection(self):
        for variable in ("content", "renamedPayload", "accountSummary"):
            with self.subTest(variable=variable):
                code = f"const {variable}=location.search; document.write({variable});"
                self.assertIn("xss", self.scan(code)["sinks"])

    def test_prompt_alias_chain_is_unverified(self):
        code = "const first=excerptText; const second=first; generateText({model,prompt:second});"
        self.assertIn("llm-indirect-prompt-injection", self.kinds(code, LlmSecurityExtractor))

    def test_approval_of_other_arguments_and_shadowed_guard_are_unverified(self):
        code = "const tools={send:tool(()=>{if(await confirmAction(other)){sendEmail(args);}})};"
        self.assertIn("llm-excessive-agency", self.kinds(code, LlmSecurityExtractor))
        shadowed = "function confirmAction(args){return true;}" + code.replace("confirmAction(other)", "confirmAction(args)")
        self.assertIn("llm-excessive-agency", self.kinds(shadowed, LlmSecurityExtractor))

    def test_deferred_or_reassigned_transaction_receiver_is_unverified(self):
        setting = "tx.execute(sql`SELECT set_config('app.user_id', ${id}, true)`);"
        for prefix in ("return ()=>", "tx=db; "):
            code = "db.transaction(async(tx)=>{" + prefix + setting + "});"
            self.assertIn("rls-context-no-transaction", self.kinds(code, AuthzDataflowExtractor))

    def test_shadowed_cookie_verifier_cannot_hide_unsigned_value(self):
        code = "function jwtVerify(x,key){return x;} const role=jwtVerify(req.cookies.get('access-role'),key); if(role!=='admin') return 403;"
        self.assertIn("unsigned-cookie-authz", self.kinds(code, AuthzDataflowExtractor))

    def test_later_or_hoisted_sanitizer_definition_remains_unverified(self):
        for suffix in ("function escapeHtml(x){return x;}", "const escapeHtml=x=>x;"):
            code = "document.write(escapeHtml(location.search)); " + suffix
            self.assertIn("xss", self.scan(code)["sinks"])
        self.assertNotIn("xss", self.scan("document.write(DOMPurify.sanitize(location.search));")["sinks"])

    def test_raw_host_operand_and_literal_guard_text_cannot_hide_redirect(self):
        for code in (
            "const host=req.headers.host; const base=allowedHosts.includes(host)?host:publicOrigin; res.redirect(host + base);",
            'const host=req.headers.host; const base=host; const note="const base=allowedHosts.includes(host)?host:publicOrigin;"; res.redirect(base);',
        ):
            self.assertTrue(self.scan(code)["host_header_redirect"])
        safe = "const host=req.headers.host; const base=allowedHosts.includes(host)?host:publicOrigin; res.redirect(base);"
        self.assertEqual(self.scan(safe)["host_header_redirect"], [])

    def test_inverted_approval_and_postapproval_mutation_are_not_controls(self):
        for body in ("if(confirmAction(args) === false){sendEmail(args);}",
                     "if(confirmAction(args)){args=modelArgs;sendEmail(args);}",
                     "if(confirmAction(args)){mutate(args);sendEmail(args);}"):
            code = "const t=tool({execute:async(args)=>{" + body + "}});"
            self.assertIn("llm-excessive-agency", self.kinds(code, LlmSecurityExtractor))
        safe = "const t=tool({execute:async(args)=>{if(confirmAction(args)){sendEmail(args);}}});"
        self.assertNotIn("llm-excessive-agency", self.kinds(safe, LlmSecurityExtractor))

    def test_inner_scope_binding_does_not_overwrite_outer_prompt_source(self):
        code = "const c=excerptText; function unrelated(){const c='safe';} generateText({model,prompt:c});"
        self.assertIn("llm-indirect-prompt-injection", self.kinds(code, LlmSecurityExtractor))


if __name__ == "__main__":
    unittest.main()

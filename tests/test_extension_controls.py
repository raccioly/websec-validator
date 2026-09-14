"""External message controls must enforce the listener's own sender identity."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.webext import WebExtExtractor
from websec_validator.extractors.syntax import guarded_body, js_functions, without_comments


class ExtensionControlsTests(unittest.TestCase):
    def scan(self, body, parameters="message, sender", extra=""):
        return self.source("chrome.runtime.onMessageExternal.addListener((" + parameters + ") => {" + body + "});" + extra)

    def source(self, text):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "background.js").write_text(text)
            return [f for f in WebExtExtractor().extract(RepoContext(root), {})["findings"]
                    if f["kind"] == "unvalidated-external-message"]

    def test_comments_logging_and_other_functions_do_not_validate(self):
        action = "chrome.tabs.create({url:message.url});"
        for extra in ("// validate sender.origin here\n", "console.log(sender.origin);",
                      'function other(sender){if(sender.id !== "trusted") return;}',
                      'const text = "if(sender.id === \'trusted\')";'):
            with self.subTest(extra=extra):
                self.assertEqual(len(self.scan(extra + action)), 1)

    def test_supported_positive_and_rejecting_guards(self):
        for body in ('if(sender.id !== "trusted") return; chrome.tabs.create({url:message.url});',
                     'if(sender.origin === "https://trusted.example") {chrome.tabs.create({url:message.url});}',
                     'if(!["first", "second"].includes(sender.id)) {return false;} chrome.tabs.create({url:message.url});'):
            self.assertEqual(self.scan(body), [])
        self.assertEqual(self.scan('if(peer.id !== "trusted") return; chrome.tabs.create({url:message.url});', "message, peer"), [])

    def test_named_and_anonymous_function_callbacks(self):
        self.assertEqual(self.source('function handle(message, sender) {if(sender.id !== "trusted") return; chrome.tabs.create({url:message.url});} chrome.runtime.onMessageExternal.addListener(handle);'), [])
        self.assertEqual(self.source('chrome.runtime.onMessageExternal.addListener(function(message, sender) {if(sender.id !== "trusted") return; chrome.tabs.create({url:message.url});});'), [])

    def test_unproven_variants_remain_leads(self):
        action = "chrome.tabs.create({url:message.url});"
        for body in ('if(sender.id) {' + action + '}', 'if(sender.id.startsWith("trusted")) {' + action + '}',
                     'if(sender.id === "*") {' + action + '}', 'if(sender.id === "trusted") return;' + action,
                     'if(sender.id !== "trusted") console.log(sender.id);' + action,
                     'if(checkSender(sender)) {' + action + '}',
                     'if(sender.id !== "trusted") return; sender=other;' + action,
                     'function helper(){if(sender.id !== "trusted") return;}' + action,
                     action + 'if(sender.id !== "trusted") return;'):
            with self.subTest(body=body):
                self.assertEqual(len(self.scan(body)), 1)

    def test_separate_callbacks_and_reassignment(self):
        safe = 'chrome.runtime.onMessageExternal.addListener((message,sender)=>{if(sender.id !== "trusted") return; chrome.tabs.create({url:message.url});});'
        unsafe = 'chrome.runtime.onMessageExternal.addListener((message,sender)=>{chrome.tabs.create({url:message.url});});'
        self.assertEqual(len(self.source(safe + unsafe)), 1)
        self.assertEqual(len(self.source('function handle(m,s){if(s.id !== "trusted")return; work(m);} handle=other;chrome.runtime.onMessageExternal.addListener(handle);')), 1)
        for shadow in ('function register(handle){chrome.runtime.onMessageExternal.addListener(handle);}',
                       'function register(){const handle=other;chrome.runtime.onMessageExternal.addListener(handle);}',
                       'function register({handle}){chrome.runtime.onMessageExternal.addListener(handle);}',
                       'function register(options){const {handle}=options;chrome.runtime.onMessageExternal.addListener(handle);}',
                       'function register(options){const [handle]=options;chrome.runtime.onMessageExternal.addListener(handle);}'):
            self.assertEqual(len(self.source('function handle(m,s){if(s.id !== "trusted")return;work(m);}' + shadow)), 1)
        self.assertEqual(self.source('const handle=(m,s)=>{if(s.id !== "trusted")return;work(m);};chrome.runtime.onMessageExternal.addListener(handle);'), [])

    def test_scope_helper_nested_sibling_and_parse_failure(self):
        scopes = js_functions(without_comments('function a(x){const nested=(y)=>{work(y);};} const b=(z)=>{work(z);};'))
        self.assertEqual([scope["name"] for scope in scopes], ["a", "nested", "b"])
        self.assertEqual(scopes[1]["params"], ["y"])
        self.assertEqual(js_functions('const concise=(x)=>work(x);'), [])
        self.assertEqual(js_functions('function broken(x){work(x);'), [])
        self.assertFalse(guarded_body('if (trusted) { work();', lambda _: 1))
        self.assertEqual(len(self.source('chrome.runtime.onMessageExternal.addListener((m,s)=>work(m));')), 1)


if __name__ == "__main__":
    unittest.main()

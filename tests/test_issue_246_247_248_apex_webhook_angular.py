"""#246 Apex is analysed in a Salesforce DX project and only there; #247 Java HMAC webhook
verification is recognised; #248 Angular browser code gets no server-only rules."""
import unittest

from _jvm_repo import TempRepo
from websec_validator.extractors import apex
from websec_validator.extractors.base import RepoContext, is_client_file

APEX_CLASS = """public without sharing class AccountSearchController {
    private static final String BASE = 'SELECT Id FROM Account';
    @AuraEnabled
    public static List<Account> search(String name) {
        String soql = 'SELECT Id, Name FROM Account WHERE Name LIKE \\'%' + name + '%\\'';
        return Database.query(soql);
    }
    @AuraEnabled
    public static List<Account> safe(String name) {
        return Database.query(BASE + ' WHERE Name = \\'' + String.escapeSingleQuotes(name) + '\\'');
    }
    public static void internal(String field) { Database.query('SELECT ' + field + ' FROM Account'); }
    @AuraEnabled
    public static void remove(Id accountId) { delete [SELECT Id FROM Account WHERE Id = :accountId]; }
}
"""


class ApexTests(TempRepo):
    def sfdx(self):
        self.write("sfdx-project.json", '{"packageDirectories":[{"path":"force-app","default":true}]}')

    def test_apex_is_read_only_in_a_salesforce_context(self):
        self.write("pkg/classes/A.cls", APEX_CLASS)
        self.write("pkg/triggers/T.trigger", "trigger T on Account (before insert) {}")
        self.assertEqual(RepoContext(self.root).code_files, [])          # a LaTeX-style .cls stays out
        self.sfdx()
        ctx = RepoContext(self.root)
        self.assertEqual(sorted(ctx.rel(p) for p in ctx.code_files), ["pkg/classes/A.cls", "pkg/triggers/T.trigger"])

    def test_meta_sibling_or_force_app_is_enough(self):
        self.write("force-app/main/default/classes/A.cls", "public class A {}")
        self.write("lib/B.cls", "public class B {}")
        self.write("lib/B.cls-meta.xml", "<ApexClass/>")
        self.write("tex/C.cls", "\\ProvidesClass{c}")
        rels = sorted(RepoContext(self.root).rel(p) for p in RepoContext(self.root).code_files)
        self.assertEqual(rels, ["force-app/main/default/classes/A.cls", "lib/B.cls"])

    def test_checks(self):
        result = apex.analyze(APEX_CLASS, "A.cls")
        lines = {row["line"]: row for row in result["queries"]}
        self.assertEqual(lines[6]["request_bound"], ["name"])
        self.assertNotIn(10, lines)                                     # escapeSingleQuotes + constant
        self.assertEqual((lines[12]["dynamic"], lines[12]["request_bound"]), (["field"], []))
        self.assertEqual({row["rule_id"] for row in result["findings"]},
                         {"apex-without-sharing-entrypoint", "apex-crud-fls"})
        self.assertEqual([e["method"] for e in result["entrypoints"]], ["search", "safe", "remove"])
        enforced = APEX_CLASS.replace("delete [SELECT Id FROM Account WHERE Id = :accountId]",
                                      "delete [SELECT Id FROM Account WHERE Id = :accountId WITH USER_MODE]")
        self.assertNotIn("apex-crud-fls", {row["rule_id"] for row in apex.analyze(enforced, "A.cls")["findings"]})
        with_sharing = APEX_CLASS.replace("without sharing", "with sharing")
        self.assertNotIn("apex-without-sharing-entrypoint",
                         {row["rule_id"] for row in apex.analyze(with_sharing, "A.cls")["findings"]})

    def test_end_to_end_profile_and_ledger(self):
        self.sfdx()
        self.write("force-app/main/default/classes/AccountSearchController.cls", APEX_CLASS)
        self.write("force-app/main/default/classes/AccountSearchControllerTest.cls",
                   "@isTest private class T { @isTest static void t() { Database.query('SELECT Id FROM A WHERE x = ' + y); } }")
        facts = self.facts()
        self.assertIn("salesforce", facts["stack"]["frameworks"])
        profile = next(p for p in facts["coverage"]["profiles"] if p["id"] == "salesforce-apex")
        self.assertTrue(all(check["status"] == "completed" for check in profile["checks"]))
        self.assertNotIn("apex", facts["coverage"]["files"]["unanalyzed_languages"])
        sqli = [f for f in self.ledger(facts) if f["attack_class"] == "sqli"]
        self.assertEqual(sorted((f["location"].rsplit(":", 1)[1], f["severity"]) for f in sqli),
                         [("12", "MEDIUM"), ("6", "HIGH")])
        self.assertEqual(len(facts["stack"]["profiles"]["apex_entrypoints"]), 3)


HOOK = """package com.acme.hooks;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
@RestController
@RequestMapping("/api/public/webhooks")
public class GitWebhookController {
    private final HookVerifier verifier;
    @PostMapping("/git")
    public ResponseEntity<Void> receive(@RequestHeader("X-Hub-Signature-256") String signature,
                                        @RequestBody byte[] body) throws Exception {
        if (!CHECK) { return ResponseEntity.status(401).build(); }
        return ResponseEntity.accepted().build();
    }
    VALID
}
"""
LOCAL = """private boolean valid(byte[] body, String signature) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(), "HmacSHA256"));
        return MessageDigest.isEqual(mac.doFinal(body), signature.getBytes());
    }"""


class JavaWebhookTests(TempRepo):
    def webhook_findings(self):
        return [f for f in self.ledger() if f["attack_class"] == "webhook-forgery"]

    def test_local_hmac_verification(self):
        self.pom()
        self.write("src/main/java/com/acme/hooks/GitWebhookController.java",
                   HOOK.replace("CHECK", "valid(body, signature)").replace("VALID", LOCAL))
        self.assertEqual(self.webhook_findings(), [])

    def test_delegated_verifier_one_hop(self):
        self.pom()
        self.write("src/main/java/com/acme/hooks/GitWebhookController.java",
                   HOOK.replace("CHECK", "verifier.verify(body, signature)").replace("VALID", ""))
        self.write("src/main/java/com/acme/hooks/HookVerifier.java",
                   "package com.acme.hooks;\npublic class HookVerifier {\n    " + LOCAL.replace("valid(", "verify(") + "\n}\n")
        self.assertEqual(self.webhook_findings(), [])

    def test_header_read_without_hmac_or_reject_is_still_a_lead(self):
        self.pom()
        self.write("src/main/java/com/acme/hooks/GitWebhookController.java",
                   HOOK.replace("if (!CHECK) { return ResponseEntity.status(401).build(); }", "log(signature);")
                   .replace("VALID", ""))
        self.assertEqual(len(self.webhook_findings()), 1)
        self._dir.cleanup()
        self.setUp()
        self.pom()
        self.write("src/main/java/com/acme/hooks/GitWebhookController.java",
                   HOOK.replace("CHECK", "verifier.verify(body, signature)").replace("VALID", ""))
        self.write("src/main/java/com/acme/hooks/HookVerifier.java",
                   "package com.acme.hooks;\npublic class HookVerifier { boolean verify(byte[] b, String s) { return true; } }\n")
        self.assertEqual(len(self.webhook_findings()), 1)


NG = """import { Component } from '@angular/core';
@Component({ selector: 'app-notes', standalone: true, template: '<div [innerHTML]="html"></div>' })
export class NotesComponent {
  html = '';
  constructor(private sanitizer: DomSanitizer) {}
  render(raw: string): void {
    const doc = new DOMParser().parseFromString(`<div>${raw}</div>`, 'text/html');
    this.html = doc.body.innerHTML;
  }
  async openFile(parts: string[]): Promise<Blob> {
    const path = parts.join('/');
    const res = await fetch(`/api/files/${path}`);
    return res.blob();
  }
  merge(state: any, updates: any) { return { ...state, ...updates }; }
}
"""


class AngularScopeTests(TempRepo):
    def test_content_classifies_angular_as_browser(self):
        self.assertTrue(is_client_file("src/app/pages/notes/notes.component.ts", NG))
        self.assertTrue(is_client_file("src/App.vue", ""))
        self.assertFalse(is_client_file("src/server.ts", "import { CommonEngine } from '@angular/ssr';\n"
                                                         "import express from 'express';\n"))
        self.assertFalse(is_client_file("src/app.service.ts", "import { Injectable } from '@nestjs/common';\n"))

    def test_server_only_classes_do_not_fire_in_any_folder(self):
        self.write("package.json", '{"name":"web","dependencies":{"@angular/core":"18.2.0"}}')
        for folder in ("pages/notes", "components/notes", "features/notes", "notes"):
            self.write(f"src/app/{folder}/notes.component.ts", NG)
        classes = {f["attack_class"] for f in self.ledger()}
        for server_only in ("proxy-escape", "xxe", "mass-assignment", "path-traversal", "ssrf"):
            self.assertNotIn(server_only, classes)


if __name__ == "__main__":
    unittest.main()

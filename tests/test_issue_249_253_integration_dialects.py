"""#249 dialect disclosure, #250 Mule profile, #251 Salesforce metadata profile, #252 open() sink,
#253 osv-scanner Maven resolution fallback. Synthetic `acme` fixtures only; all values are made up."""
import json
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from _jvm_repo import TempRepo
from websec_validator import scanners
from websec_validator.extractors import mule, salesforce_metadata as sf
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.surface import SINKS

MULE_POM = ("<project><modelVersion>4.0.0</modelVersion><groupId>acme</groupId><artifactId>orders-api</artifactId>"
            "<version>1.0.0</version><packaging>mule-application</packaging></project>")
FLOW = """<?xml version="1.0" encoding="UTF-8"?>
<mule xmlns="http://www.mulesoft.org/schema/mule/core" xmlns:http="http://www.mulesoft.org/schema/mule/http">
  <http:listener-config name="api" basePath="/v1"><http:listener-connection host="0.0.0.0" port="8081"/></http:listener-config>
  <http:request-config name="partner"><http:request-connection host="p.example.test" protocol="HTTPS">
    <tls:context><tls:trust-store insecure="true"/></tls:context></http:request-connection></http:request-config>
  <db:config name="db"><db:generic-connection url="jdbc:postgresql://db/o" user="o" password="Hx7kQ2vLp9zRw4Tn"/></db:config>
  <db:config name="db2"><db:generic-connection url="jdbc:postgresql://db/o" user="o" password="${secure::db.password}"/></db:config>
  <flow name="get-order">
    <http:listener config-ref="api" path="/orders/{id}" allowedMethods="GET"/>
    <db:select config-ref="db"><db:sql>#["SELECT * FROM orders WHERE id = " ++ attributes.uriParams.id]</db:sql></db:select>
  </flow>
  <flow name="safe-order">
    <http:listener config-ref="api" path="/safe/{id}"/>
    <db:select config-ref="db"><db:sql>SELECT * FROM orders WHERE id = :id</db:sql></db:select>
  </flow>
  <flow name="proxy">
    <http:listener config-ref="api" path="/proxy"/>
    <http:request method="GET" config-ref="partner" url="#[attributes.queryParams.target]"/>
  </flow>
</mule>
"""


class MuleProfileTests(unittest.TestCase):
    def test_flow_checks(self):
        result = mule.analyze_flow(FLOW, "src/main/mule/orders.xml")
        self.assertEqual([(r["method"], r["path"]) for r in result["routes"]],
                         [("GET", "/v1/orders/{id}"), ("ANY", "/v1/safe/{id}"), ("ANY", "/v1/proxy")])
        self.assertEqual(sorted((s["kind"], s["flow"]) for s in result["sinks"]),
                         [("sql-injection", "get-order"), ("ssrf", "proxy")])
        rules = sorted(r["rule_id"] for r in result["findings"])
        self.assertEqual(rules, ["mule-insecure-tls", "mule-listener-no-tls", "mule-plaintext-credential"])
        self.assertNotIn("Hx7kQ2vLp9zRw4Tn", json.dumps(result["findings"]))

    def test_dataweave_and_properties(self):
        rows = mule._dataweave('%dw 2.0\n---\n{ a: readUrl(vars.u, "application/json"), b: readUrl("classpath://x.json") }')
        self.assertEqual([r["rule_id"] for r in rows], ["dataweave-readurl"])
        props = mule.analyze_properties('db.password: "Zq81LmP0rT"\napi.token: "${secure::t}"\nhost: x\n', "c.yaml")
        self.assertEqual([r["line"] for r in props], [1])


class MuleRepoTests(TempRepo):
    def test_mule_app_is_profiled_routed_and_not_java(self):
        self.write("pom.xml", MULE_POM)
        self.write("src/main/mule/orders.xml", FLOW)
        self.write("src/main/resources/dwl/to-order.dwl", '%dw 2.0\n---\nreadUrl(vars.templateUrl)\n')
        facts = self.facts()
        self.assertEqual(facts["stack"]["languages"], ["mule"])
        self.assertEqual([p["id"] for p in facts["coverage"]["profiles"]], ["mule"])
        self.assertIn(("GET", "/v1/orders/{id}"), [(e["method"], e["path"]) for e in facts["routes"]["endpoints"]])
        ledger = self.ledger(facts)
        sqli = [f for f in ledger if f["attack_class"] == "sqli"]
        self.assertEqual([f["severity"] for f in sqli], ["HIGH"])
        guards = [f for f in ledger if f["attack_class"] == "missing-auth"]
        self.assertTrue(guards and all(f["confidence"] == "LOW" for f in guards))


class SalesforceMetadataTests(unittest.TestCase):
    FLOW = """<Flow xmlns="http://soap.sforce.com/2006/04/metadata">
    <processType>Flow</processType>
    <runInMode>SystemModeWithoutSharing</runInMode>
    <screens><name>Pick</name><fields><name>orderIdInput</name><fieldType>InputField</fieldType></fields></screens>
    <recordDeletes><name>Delete_Order</name><filters><value><elementReference>orderIdInput</elementReference></value></filters></recordDeletes>
    <recordUpdates><name>Assign</name><inputAssignments><field>OwnerId</field><value><stringValue>0055g00000AbCdEAAZ</stringValue></value></inputAssignments></recordUpdates>
    <variables><name>apiToken</name><value><stringValue>q8Wd3LmZx2Rt7Kp</stringValue></value></variables>
</Flow>"""

    def test_flow(self):
        rows = {r["rule_id"]: r for r in sf.analyze_flow(self.FLOW, "f.flow-meta.xml")}
        self.assertEqual(rows["flow-system-mode"]["severity"], "HIGH")
        self.assertIn("orderIdInput", rows["flow-screen-input-dml"]["title"])
        self.assertIn("flow-hardcoded-id", rows)
        self.assertIn("flow-literal-credential", rows)
        user_mode = self.FLOW.replace("<runInMode>SystemModeWithoutSharing</runInMode>", "")
        self.assertNotIn("flow-system-mode", {r["rule_id"] for r in sf.analyze_flow(user_mode, "f")})
        with_decision = self.FLOW.replace("<screens>", "<decisions><name>D</name></decisions><screens>")
        self.assertNotIn("flow-screen-input-dml", {r["rule_id"] for r in sf.analyze_flow(with_decision, "f")})

    def test_visualforce_aura_lwc(self):
        vf = sf.analyze_visualforce('<apex:page><apex:outputText value="{!$CurrentPage.parameters.msg}" escape="false"/>'
                                    '<script>var a = "{!JSENCODE(x)}"; var b = "{!y}";</script></apex:page>', "p.page")
        self.assertEqual([(r["severity"], r["title"][:20]) for r in vf],
                         [("HIGH", "Visualforce output w"), ("MEDIUM", "Visualforce merge fi")])
        self.assertEqual(len(sf.analyze_aura('<aura:unescapedHtml value="{!v.note}"/>', "c.cmp")), 1)
        links = sf.lwc_apex_links("import search from '@salesforce/apex/OrderSearchController.search';", "o.js")
        self.assertEqual((links[0]["apex_class"], links[0]["method"]), ("OrderSearchController", "search"))
        self.assertEqual(len(sf.lwc_manual_dom('<div lwc:dom="manual"></div>', "this.t.innerHTML = x;", "o.js")), 1)


class DialectDisclosureTests(TempRepo):
    def test_ampscript_is_unanalyzed_and_require_analyzed_trips(self):
        self.write("cloudpages/unsubscribe.html", "%%[ SET @e = RequestParameter(\"email\") ]%%\n<p>%%=v(@e)=%%</p>\n")
        self.write("site/index.html", "<p>plain page</p>\n")
        ctx = RepoContext(self.root)
        self.assertEqual([ctx.rel(p) for p in ctx.code_files], ["site/index.html"])
        cov = self.facts()["coverage"]
        self.assertEqual(cov["files"]["unanalyzed_languages"], {"ampscript": 1})
        self.write("site/index.html", "%%[ x ]%%")
        self.assertTrue(self.facts()["coverage"]["files"]["no_analyzable_source"])

    def test_dialects_are_classified_and_pom_is_not(self):
        self.write("pom.xml", MULE_POM)
        self.write("src/main/mule/a.xml", FLOW)
        self.write("lib/b.xml", FLOW)                                    # Mule root outside src/main/mule
        self.write("config/log4j2.xml", "<Configuration/>")
        self.write("force-app/main/default/flows/X.flow-meta.xml", "<Flow/>")
        self.write("force-app/main/default/pages/V.page", "<apex:page/>")
        self.write("force-app/main/default/aura/c/c.cmp", "<aura:component/>")
        self.write("docs/print.page", "not visualforce")
        ctx = RepoContext(self.root)
        got = {k: sorted(ctx.rel(p) for p in v) for k, v in ctx.dialect_files.items()}
        self.assertEqual(got, {"mule-flow-xml": ["lib/b.xml", "src/main/mule/a.xml"],
                               "salesforce-flow": ["force-app/main/default/flows/X.flow-meta.xml"],
                               "visualforce": ["force-app/main/default/pages/V.page"],
                               "aura-markup": ["force-app/main/default/aura/c/c.cmp"]})


class OpenSinkTests(unittest.TestCase):
    def test_dialog_open_is_not_a_file_sink(self):
        rx = SINKS["path-traversal"][2]
        for text in ("await LightningConfirm.open({ message: `Remove ${row.name}?` })",
                     "ConfirmDialog.open({ message: `x ${a}` })", "dialog.open(Component, { data: `${x}` })",
                     "window.open(`/x/${id}`)"):
            with self.subTest(text=text):
                self.assertIsNone(rx.search(text))
        for text in ("open(req.query.f)", "fs.open(req.params.p, 'r')", "os.open(request.args['p'], os.O_RDONLY)",
                     "fs.promises.open(req.query.f)", "File.open(params[:f])"):
            with self.subTest(text=text):
                self.assertIsNotNone(rx.search(text))


class OsvRecoveryTests(unittest.TestCase):
    def proc(self, code, stderr=""):
        return subprocess.CompletedProcess(["osv-scanner"], code, "", stderr)

    def test_no_package_sources_is_no_applicable_input(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "osv.json"
            proc, meta = scanners._osv_recover(["osv-scanner", "scan", "--recursive", tmp], self.proc(128, "No package sources found"),
                                              out, 10, Path(tmp))
            self.assertEqual(proc.returncode, 0)
            self.assertTrue(meta["no_applicable_input"])
            self.assertEqual(json.loads(out.read_text()), {"results": []})

    def test_failed_resolution_retries_with_no_resolve(self):
        import tempfile
        stderr = ("failed resolution for /x/pom.xml: failed resolving {Maven:acme:orders[Concrete:1.0.0] {}}: "
                  "version Maven:org.acme.connectors:acme-http-connector[Concrete:1.10.2]: not found")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "osv.json"
            calls = []

            def fake_run(argv, **kwargs):
                calls.append(argv)
                out.write_text('{"results": []}')
                return subprocess.CompletedProcess(argv, 0, "", "")
            with mock.patch.object(scanners.subprocess, "run", side_effect=fake_run):
                proc, meta = scanners._osv_recover(["osv-scanner", "scan", "--recursive", "--format", "json", tmp],
                                                  self.proc(127, stderr), out, 10, Path(tmp))
            self.assertEqual(proc.returncode, 0)
            self.assertIn("--no-resolve", calls[0])
            self.assertEqual(meta["dependency_resolution"]["unresolved"], ["org.acme.connectors:acme-http-connector"])
            self.assertEqual(meta["dependency_resolution"]["mode"], "direct-only")

    def test_other_failures_are_left_alone(self):
        proc, meta = scanners._osv_recover(["osv-scanner"], self.proc(127, "segfault"), Path("/nonexistent/x"), 10, Path("/"))
        self.assertEqual((proc.returncode, meta), (127, {}))


if __name__ == "__main__":
    unittest.main()

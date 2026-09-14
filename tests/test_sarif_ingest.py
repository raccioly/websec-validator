"""Data-only SARIF import controls, including producer failure and path boundaries."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator import sarif_ingest as sarif


def location(uri="src/app.py", line=7):
    return {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}


def result(uri="src/app.py", fingerprint="site-one", **extras):
    return {"ruleId": "python/sql-injection", "message": {"text": "User input reaches query execution"},
            "locations": [location(uri)], "partialFingerprints": {"primaryLocationLineHash/v1": fingerprint}, **extras}


def document(results=None):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ExampleAnalyzer", "version": "1.2.3",
            "rules": [{"id": "python/sql-injection", "name": "SqlInjection", "shortDescription": {"text": "SQL injection"},
                       "help": {"text": "Use query parameters."}, "properties": {"security-severity": "8.1", "tags": ["external/cwe/cwe-089"]}}]}},
            "invocations": [{"executionSuccessful": True}], "results": [result()] if results is None else results}]}


class SarifImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "input.sarif"
        self.target = self.root / "target"
        self.target.mkdir()

    def load(self, doc, **kwargs):
        self.path.write_text(json.dumps(doc))
        return sarif.load_report(self.path, self.target, **kwargs)

    def test_positive_identity_provenance_and_unverified_source(self):
        imported = self.load(document())
        row = imported["findings"][0]
        report = imported["report"]
        self.assertEqual((row["file"], row["line"], row["severity"]), ("src/app.py", 7, "HIGH"))
        self.assertTrue(row["rule_id"].endswith(":python/sql-injection"))
        self.assertEqual(row["sarif"]["partial_fingerprints"], {"primaryLocationLineHash/v1": "site-one"})
        self.assertTrue(report["execution_complete"])
        self.assertEqual(report["source_freshness"], "unverified")
        self.assertEqual(report["sha256"], "sha256:" + hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertEqual(report["tool_scope"][0]["rules"][0]["name"], "SqlInjection")
        self.assertNotIn("analyzed_input_digest", report)

    def test_report_hash_changes_but_native_identity_and_tool_scope_do_not(self):
        doc = document()
        before = self.load(doc)
        doc["runs"][0]["results"][0]["message"]["text"] = "Updated wording"
        doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] = 42
        after = self.load(doc)
        self.assertNotEqual(before["report"]["sha256"], after["report"]["sha256"])
        self.assertEqual(before["findings"][0]["semantic_id"], after["findings"][0]["semantic_id"])
        self.assertEqual(before["report"]["tool_scope"], after["report"]["tool_scope"])

    def test_tools_rule_namespaces_and_native_sites_stay_distinct(self):
        doc = document([result(fingerprint="first"), result(fingerprint="second")])
        second = copy.deepcopy(doc["runs"][0])
        second["tool"]["driver"]["name"] = "OtherAnalyzer"
        doc["runs"].append(second)
        rows = self.load(doc)["findings"]
        self.assertEqual(len(rows), 4)
        self.assertEqual(len({row["semantic_id"] for row in rows}), 4)
        self.assertEqual(len({row["rule_id"] for row in rows}), 2)

    def test_empty_success_null_and_unknown_are_distinct(self):
        empty = self.load(document([]))
        self.assertTrue(empty["report"]["execution_complete"])
        self.assertTrue(empty["report"]["tool_scope"][0]["rules"])
        doc = document([])
        doc["runs"][0]["results"] = None
        self.assertFalse(self.load(doc)["report"]["execution_complete"])
        doc = document()
        del doc["runs"][0]["invocations"]
        loaded = self.load(doc)
        self.assertEqual(len(loaded["findings"]), 1)
        self.assertEqual(loaded["report"]["analysis_outcome"], "unknown")
        self.assertFalse(loaded["report"]["execution_complete"])

    def test_invocation_failure_notifications_and_invalid_status_keep_results(self):
        for invocation in ({"executionSuccessful": False}, {"executionSuccessful": "true"},
                           {"executionSuccessful": True, "toolExecutionNotifications": [{"level": "error", "message": {"text": "Analysis timeout"}}]}):
            with self.subTest(invocation=invocation):
                doc = document()
                doc["runs"][0]["invocations"] = [invocation]
                loaded = self.load(doc)
                self.assertEqual(len(loaded["findings"]), 1)
                self.assertFalse(loaded["report"]["execution_complete"])

    def test_invalid_invocation_collection_and_unused_rule_preserve_good_results(self):
        for invalid in (None, {}, "invalid"):
            doc = document()
            doc["runs"][0]["invocations"] = invalid
            loaded = self.load(doc)
            self.assertEqual(len(loaded["findings"]), 1)
            self.assertFalse(loaded["report"]["execution_complete"])
        for unused in (None, {"id": "unused", "help": {"text": "a" * (sarif.MAX_TEXT + 1)}}):
            doc = document()
            doc["runs"][0]["tool"]["driver"]["rules"].append(unused)
            loaded = self.load(doc)
            self.assertEqual(len(loaded["findings"]), 1)
            self.assertFalse(loaded["report"]["execution_complete"])

    def test_same_line_backwards_columns_rejected_valid_multiline_retained(self):
        for region, valid in (({"startLine": 7, "endLine": 7, "startColumn": 20, "endColumn": 1}, False),
                              ({"startLine": 7, "startColumn": 20, "endColumn": 1}, False),
                              ({"startLine": 7, "endLine": 8, "startColumn": 20, "endColumn": 1}, True),
                              ({"startLine": 7, "endLine": 7, "startColumn": 1, "endColumn": 20}, True)):
            with self.subTest(region=region):
                doc = document()
                doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"] = region
                loaded = self.load(doc)
                self.assertEqual(loaded["report"]["execution_complete"], valid)
                self.assertEqual(len(loaded["findings"]), int(valid))

    def test_pass_absent_not_applicable_are_observations_and_suppressed_fail_stays_active(self):
        rows = [result(kind="pass"), result(kind="notApplicable"), result(baselineState="absent"),
                result(suppressions=[{"kind": "external", "status": "accepted", "justification": "Producer acceptance"}])]
        loaded = self.load(document(rows))
        self.assertEqual(len(loaded["observations"]), 3)
        self.assertEqual(len(loaded["findings"]), 1)
        self.assertEqual(loaded["findings"][0]["sarif"]["suppressions"][0]["status"], "accepted")
        self.assertNotIn("acknowledged", loaded)

    def test_relative_base_and_artifact_index_resolve_without_source_read(self):
        doc = document()
        run = doc["runs"][0]
        run["originalUriBaseIds"] = {"ROOT": {"uri": "src/"}}
        run["artifacts"] = [{"location": {"uri": "app.py", "uriBaseId": "ROOT"}}]
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {"index": 0}
        self.assertEqual(self.load(doc)["findings"][0]["file"], "src/app.py")
        self.assertEqual(list(self.target.iterdir()), [])

    def test_escaping_remote_and_encoded_paths_are_incomplete(self):
        for uri in ("../outside.py", "%2e%2e/outside.py", "%252e%252e/outside.py", "file:///etc/passwd",
                    "https://example.test/source.py", "//host/share.py", "C:\\source.py", "src/../../outside.py", "bad\x00.py"):
            with self.subTest(uri=uri):
                loaded = self.load(document([result(uri), result("safe.py", "safe")]))
                self.assertEqual([row["file"] for row in loaded["findings"]], ["safe.py"])
                self.assertFalse(loaded["report"]["execution_complete"])

    def test_absolute_ci_base_unknown_base_and_cycles_are_incomplete(self):
        for bases in ({"ROOT": {"uri": "file:///old/workspace/"}}, {"ROOT": {"uri": "src", "uriBaseId": "ROOT"}}, {}):
            with self.subTest(bases=bases):
                doc = document()
                doc["runs"][0]["originalUriBaseIds"] = bases
                doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] = "ROOT"
                self.assertFalse(self.load(doc)["report"]["execution_complete"])
        doc = document()
        doc["runs"][0]["artifacts"] = [{"location": {"index": 0}}]
        doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {"index": 0}
        self.assertFalse(self.load(doc)["report"]["execution_complete"])

    def test_private_user_and_fixture_exclusions_are_scope_omissions(self):
        doc = document([result(".local/private.py"), result("vendor/source.py"), result("tests/test_app.py"), result("src/app.py")])
        loaded = self.load(doc, excludes=["vendor/**"])
        self.assertEqual(len(loaded["findings"]), 1)
        self.assertEqual(loaded["report"]["counts"]["excluded"], 3)
        self.assertTrue(loaded["report"]["execution_complete"])
        self.assertEqual(len(self.load(doc, excludes=["vendor/**"], include_fixtures=True)["findings"]), 2)

    def test_trace_and_related_locations_preserve_order_and_grouping(self):
        doc = document()
        row = doc["runs"][0]["results"][0]
        row["relatedLocations"] = [{**location("src/source.py", 3), "id": 1, "message": {"text": "Input"}}]
        row["codeFlows"] = [{"threadFlows": [{"locations": [
            {"location": {**location("src/source.py", 3), "message": {"text": "User input"}}, "executionOrder": 1},
            {"location": location("src/app.py", 7), "executionOrder": 2}]}]}]
        native = self.load(doc)["findings"][0]["sarif"]
        flow = native["code_flows"][0]
        self.assertEqual((flow["flow_index"], flow["thread_index"]), (0, 0))
        self.assertEqual([item["file"] for item in flow["locations"]], ["src/source.py", "src/app.py"])
        self.assertEqual(native["related_locations"][0]["message"], "Input")

    def test_external_references_and_commands_never_trigger_actions(self):
        doc = document()
        run = doc["runs"][0]
        run["externalPropertyFileReferences"] = {"results": [{"location": {"uri": "https://example.test/results.json"}}]}
        run["invocations"][0].update(commandLine="touch marker", responseFiles=[{"uri": "../secret"}])
        run["results"][0]["fixes"] = [{"description": {"text": "Run dangerous command"}}]
        self.path.write_text(json.dumps(doc))
        with patch("subprocess.run", side_effect=AssertionError("execution forbidden")), \
             patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")), \
             patch.object(Path, "read_text", side_effect=AssertionError("source read forbidden")):
            loaded = sarif.load_report(self.path, self.target)
        self.assertEqual(len(loaded["findings"]), 1)
        self.assertFalse(loaded["report"]["execution_complete"])
        self.assertFalse(loaded["report"]["source_references_read"])
        self.assertEqual(list(self.target.iterdir()), [])

    def test_rule_index_extension_and_message_lookup(self):
        doc = document()
        run = doc["runs"][0]
        run["tool"]["extensions"] = [{"name": "RulesPack", "rules": [{"id": "security/check", "messageStrings": {"m": {"text": "Unsafe {0}"}}}]}]
        run["results"] = [{"rule": {"index": 0, "toolComponent": {"index": 0}}, "message": {"id": "m", "arguments": ["query"]}}]
        row = self.load(doc)["findings"][0]
        self.assertEqual(row["title"], "Unsafe query")
        self.assertEqual(row["sarif"]["namespace"]["component"], "RulesPack")
        self.assertEqual((row["file"], row["line"]), ("", 0))

    def test_missing_rule_invalid_indexes_and_malformed_results_keep_good_sibling(self):
        for bad in ({"message": {"text": "No rule"}}, result(ruleIndex=100), result(kind=[]), result(locations="bad"), 7):
            with self.subTest(bad=bad):
                loaded = self.load(document([bad, result()]))
                self.assertEqual(len(loaded["findings"]), 1)
                self.assertFalse(loaded["report"]["execution_complete"])

    def test_duplicated_rule_references_must_agree_and_preserve_good_sibling(self):
        for extras in ({"rule": {"id": "different/rule"}}, {"ruleIndex": 0, "rule": {"index": 1}}):
            with self.subTest(extras=extras):
                loaded = self.load(document([result(**extras), result(fingerprint="good")]))
                self.assertFalse(loaded["report"]["execution_complete"])
                self.assertEqual(len(loaded["findings"]), 1)
        loaded = self.load(document([result(ruleIndex=0, rule={"id": "python/sql-injection", "index": 0})]))
        self.assertTrue(loaded["report"]["execution_complete"])
        self.assertEqual(len(loaded["findings"]), 1)

    def test_component_index_name_and_guid_must_all_agree(self):
        for selector in ({"name": "Pack", "guid": "wrong"}, {"index": 0, "name": "OtherPack"},
                         {"index": 0, "guid": "wrong"}, {"index": 0, "name": "Pack", "guid": "actual"}):
            with self.subTest(selector=selector):
                doc = document()
                run = doc["runs"][0]
                run["tool"]["extensions"] = [{"name": "Pack", "guid": "actual", "rules": [{"id": "ext/check"}]}]
                run["results"] = [{"rule": {"id": "ext/check", "toolComponent": selector}, "message": {"text": "Candidate"}}, result()]
                loaded = self.load(doc)
                valid = selector == {"index": 0, "name": "Pack", "guid": "actual"}
                self.assertEqual(loaded["report"]["execution_complete"], valid)
                self.assertEqual(len(loaded["findings"]), 2 if valid else 1)

    def test_missing_native_identity_is_disclosed_report_local(self):
        first = result()
        del first["partialFingerprints"]
        loaded = self.load(document([first, copy.deepcopy(first)]))
        self.assertEqual(len({row["semantic_id"] for row in loaded["findings"]}), 2)
        self.assertTrue(all(row["sarif"]["identity_basis"] == "report-local-occurrence" for row in loaded["findings"]))

    def test_repeated_partial_fingerprint_does_not_hide_second_site(self):
        first, second = result(), result()
        second["locations"] = [location(line=19)]
        loaded = self.load(document([first, second]))
        self.assertEqual(len({row["semantic_id"] for row in loaded["findings"]}), 2)
        self.assertEqual(loaded["findings"][1]["sarif"]["identity_occurrence"], 2)

    def test_source_symlink_is_never_read_or_attested_contained(self):
        outside = self.root / "outside.py"
        outside.write_text("private source must not be read")
        (self.target / "link.py").symlink_to(outside)
        loaded = self.load(document([result("link.py")]))
        self.assertEqual(loaded["findings"][0]["file"], "link.py")
        self.assertIn("containment unverified", loaded["report"]["location_binding"])
        self.assertFalse(loaded["report"]["source_references_read"])

    def test_colliding_fingerprints_cannot_migrate_between_changed_reports(self):
        first, second = result(locations=[location(line=10)]), result(locations=[location(line=20)])
        before = self.load(document([first, second]))
        reversed_report = self.load(document([second, first]))
        added_site = self.load(document([first, second, copy.deepcopy(first)]))
        original_ids = {row["semantic_id"] for row in before["findings"]}
        for loaded in (reversed_report, added_site):
            self.assertTrue(original_ids.isdisjoint(row["semantic_id"] for row in loaded["findings"]))
            self.assertEqual(len({row["semantic_id"] for row in loaded["findings"]}), len(loaded["findings"]))
        self.assertTrue(all(row["sarif"]["identity_basis"] == "ambiguous-producer-fingerprint-report-bound" for row in before["findings"]))
        self.assertTrue(any("Colliding" in gap["detail"] for gap in before["report"]["gaps"]))
        self.assertTrue(before["report"]["execution_complete"])

    def test_kind_level_defaults_and_contradictions(self):
        for kind in ("review", "open", "pass", "notApplicable", "informational"):
            with self.subTest(kind=kind):
                loaded = self.load(document([result(kind=kind)]))
                row = (loaded["findings"] + loaded["observations"])[0]
                self.assertTrue(loaded["report"]["execution_complete"])
                self.assertEqual((row["sarif"]["level"], row["severity"]), ("none", "INFO"))
                self.assertEqual(row["sarif"]["rule_properties"]["security-severity"], "8.1")
        for kind, level in (("fail", "none"), ("review", "warning"), ("pass", "error")):
            loaded = self.load(document([result(kind=kind, level=level), result(fingerprint="valid")]))
            self.assertFalse(loaded["report"]["execution_complete"])
            self.assertEqual(len(loaded["findings"]), 1)
            self.assertEqual(loaded["findings"][0]["severity"], "HIGH")

    def test_global_shared_trace_expansion_and_step_budgets(self):
        doc = document([result(fingerprint=str(i), codeFlows=[{"threadFlows": [{"locations": [{"index": 0}] * 10}]}]) for i in range(5)])
        shared = location()
        shared["message"] = {"text": "m" * 2000}
        doc["runs"][0]["threadFlowLocations"] = [{"location": shared}]
        with patch.object(sarif, "MAX_EXPANDED_BYTES", 20000):
            loaded = self.load(doc)
            self.assertFalse(loaded["report"]["execution_complete"])
            self.assertLessEqual(loaded["report"]["counts"]["expanded_bytes"], 20000)
            self.assertLess(len(json.dumps(loaded)), 40000)
        with patch.object(sarif, "MAX_RETAINED_TRACE_STEPS", 3):
            loaded = self.load(doc)
            self.assertFalse(loaded["report"]["execution_complete"])
            self.assertEqual(len(loaded["findings"]), 5)
            self.assertEqual(loaded["report"]["counts"]["retained_trace_steps"], 3)
        small = document([result(codeFlows=[{"threadFlows": [{"locations": [{"location": location()}]}]}])])
        loaded = self.load(small)
        self.assertTrue(loaded["report"]["execution_complete"])
        self.assertEqual(loaded["report"]["counts"]["retained_trace_steps"], 1)

    def test_repeated_rule_help_and_component_catalog_are_bounded(self):
        doc = document([result(fingerprint=str(i)) for i in range(20)])
        doc["runs"][0]["tool"]["driver"]["rules"][0]["help"]["text"] = "h" * 2000
        with patch.object(sarif, "MAX_EXPANDED_BYTES", 12000):
            loaded = self.load(doc)
            self.assertFalse(loaded["report"]["execution_complete"])
            self.assertLessEqual(loaded["report"]["counts"]["expanded_bytes"], 12000)
            self.assertLess(len(json.dumps(loaded)), 20000)
        doc = document()
        doc["runs"][0]["tool"]["extensions"] = [{"name": str(i)} for i in range(5)]
        with patch.object(sarif, "MAX_TOOL_COMPONENTS", 2):
            loaded = self.load(doc)
            self.assertFalse(loaded["report"]["execution_complete"])
            self.assertEqual(len(loaded["report"]["tool_scope"]), 2)
            self.assertEqual(len(loaded["findings"]), 1)

    def test_byte_result_rule_run_depth_and_trace_caps_are_visible(self):
        self.path.write_text(" " * 101)
        with patch.object(sarif, "MAX_BYTES", 100):
            self.assertFalse(sarif.load_report(self.path, self.target)["report"]["execution_complete"])
        with patch.object(sarif, "MAX_RESULTS", 1):
            loaded = self.load(document([result(), result(fingerprint="second")]))
            self.assertEqual(len(loaded["findings"]), 1)
            self.assertFalse(loaded["report"]["execution_complete"])
        with patch.object(sarif, "MAX_RULES", 0):
            self.assertFalse(self.load(document())["report"]["execution_complete"])
        doc = document()
        doc["runs"].append(copy.deepcopy(doc["runs"][0]))
        with patch.object(sarif, "MAX_RUNS", 1):
            self.assertFalse(self.load(doc)["report"]["execution_complete"])
        with patch.object(sarif, "MAX_DEPTH", 2):
            self.assertFalse(self.load(document())["report"]["execution_complete"])
        doc = document()
        doc["runs"][0]["results"][0]["codeFlows"] = [{"threadFlows": [{"locations": [{"location": location()}, {"location": location()}]}]}]
        with patch.object(sarif, "MAX_TRACE_STEPS", 1):
            loaded = self.load(doc)
            self.assertEqual(len(loaded["findings"]), 1)
            self.assertFalse(loaded["report"]["execution_complete"])

    def test_missing_special_and_invalid_json_reports_are_incomplete(self):
        self.assertFalse(sarif.load_report(self.path, self.target)["report"]["execution_complete"])
        for text in ('{"version":"2.1.0","version":"2.1.0","runs":[]}', '{"version":"2.1.0","runs":NaN}', "[]", "not json"):
            self.path.write_text(text)
            self.assertFalse(sarif.load_report(self.path, self.target)["report"]["execution_complete"])
        self.path.unlink()
        if hasattr(os, "mkfifo"):
            os.mkfifo(self.path)
            self.assertFalse(sarif.load_report(self.path, self.target)["report"]["execution_complete"])


if __name__ == "__main__":
    unittest.main()

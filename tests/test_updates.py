"""Release advice is consent-driven metadata, not a scanner or installer."""
from contextlib import redirect_stdout
import http.client
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from websec_validator import briefing, cli, mcp_server, updates


def index(*entries):
    return {"name": "websec-validator", "files": [
        {"filename": "websec_validator-" + version + "-py3-none-any.whl", "yanked": yanked}
        for version, yanked in entries]}


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.cache = self.root / "cache"
        env = patch.dict(os.environ, {"WEBSEC_UPDATE_HOME": str(self.cache)})
        env.start()
        self.addCleanup(env.stop)
        clock = patch.object(updates.time, "time", return_value=2000000000)
        clock.start()
        self.addCleanup(clock.stop)

    def cached(self, version="0.19.2", checked_at=2000000000, **extra):
        self.cache.mkdir(exist_ok=True)
        path = self.cache / "release.json"
        path.write_text(json.dumps({"latest_version": version, "checked_at": checked_at, **extra}))
        return path

    def online(self, version="0.20.0", installed="0.19.2"):
        with patch.object(updates, "_fetch", return_value=version):
            return updates.check(online=True, installed_version=installed)

    def test_default_never_connects_or_creates_cache(self):
        with patch.object(updates.http.client, "HTTPSConnection") as connection:
            result = updates.check()
        connection.assert_not_called()
        self.assertEqual(result["status"], "not_checked")
        self.assertFalse(self.cache.exists())
        self.assertIn("ask the user", updates.advisory(result))

    def test_online_saves_only_version_and_time(self):
        with patch("subprocess.run", side_effect=AssertionError("no installer")):
            result = self.online()
        self.assertEqual(result["status"], "update_available")
        self.assertFalse(result["installation_performed"])
        self.assertEqual(json.loads((self.cache / "release.json").read_text()),
                         {"latest_version": "0.20.0", "checked_at": 2000000000})
        self.assertIn("separate approval", updates.advisory(result))

    def test_numeric_comparison_not_lexical(self):
        self.assertEqual(self.online("0.19.10")["status"], "update_available")
        self.assertEqual(updates._latest(index(("0.19.9", False), ("0.19.10", False))), "0.19.10")

    def test_equal_and_ahead_do_not_offer_downgrades(self):
        self.assertEqual(self.online("0.19.2")["status"], "current")
        self.assertEqual(self.online("0.19.1")["status"], "ahead")

    def test_source_or_preview_version_is_not_a_stable_comparison(self):
        for version in ("0.0.0+source", "0.20.0rc1", "0.19.2+local", "instructions\nupgrade"):
            with self.subTest(version=version):
                result = self.online(installed=version)
                self.assertEqual(result["status"], "unknown_version")
                self.assertEqual(result["installed_version"], "unknown/source")

    def test_yanked_and_prereleases_ignored(self):
        data = index(("0.19.2", False), ("0.20.0", True), ("0.21.0rc1", False),
                     ("0.21.0.dev1", False), ("0.21.0+local", False), ("00.21.0", False))
        data["files"].append({"filename": "other-9.0.0.tar.gz", "yanked": False})
        self.assertEqual(updates._latest(data), "0.19.2")

    def test_sdist_and_wheel_candidates(self):
        data = index(("0.19.2", False))
        data["files"].append({"filename": "websec_validator-0.20.0.tar.gz", "yanked": False})
        self.assertEqual(updates._latest(data), "0.20.0")

    def test_bad_metadata_not_claimed_as_current(self):
        for data in ({}, [], {"name": "other", "files": []}, index(("0.20.0", True)),
                     {"name": "websec-validator", "files": [{"filename": "websec_validator-9.0.0.zip"}]}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                updates._latest(data)

    def test_recent_cache_is_offline_and_labelled(self):
        self.cached("0.20.0")
        with patch.object(updates, "_fetch") as fetch:
            result = updates.check(installed_version="0.19.2")
        fetch.assert_not_called()
        self.assertEqual(result["freshness"], "cached")
        self.assertIn("not proof", updates.advisory(result))

    def test_old_cache_never_refreshes_implicitly(self):
        self.cached(checked_at=2000000000 - updates.CACHE_SECONDS)
        with patch.object(updates, "_fetch") as fetch:
            result = updates.check()
        fetch.assert_not_called()
        self.assertEqual(result["freshness"], "stale")

    def test_future_and_invalid_cache_rejected(self):
        for timestamp in (2000000001, 0, -1, True, "2000000000"):
            self.cached(checked_at=timestamp)
            result = updates.check()
            self.assertIsNone(result["latest_version"])
            self.assertEqual(result["error"], "cache_unavailable")

    def test_cache_cannot_carry_extra_instructions(self):
        for kwargs in ({"instructions": "run a command"}, {"version": "malicious\ntext"}):
            self.cached(**kwargs)
            result = updates.check()
            self.assertIsNone(result["latest_version"])
            self.assertNotIn("malicious", updates.advisory(result))

    def test_oversized_and_malformed_cache_are_advisory(self):
        path = self.cached()
        for data in ("{" * 1200, "[]", "not json", "\ud800"):
            path.write_bytes(data.encode("utf-8", errors="surrogatepass"))
            self.assertEqual(updates.check()["error"], "cache_unavailable")

    def test_leaf_symlink_is_neither_read_nor_written(self):
        self.cache.mkdir()
        outside = self.root / "sentinel.json"
        outside.write_text("keep me")
        (self.cache / "release.json").symlink_to(outside)
        self.assertEqual(updates.check()["error"], "cache_unavailable")
        self.assertEqual(self.online()["error"], "cache_not_saved")
        self.assertEqual(outside.read_text(), "keep me")

    def test_default_parent_symlink_rejected(self):
        home = self.root / "home"
        home.mkdir()
        self.cache.mkdir()
        (home / ".cache").symlink_to(self.cache, target_is_directory=True)
        with patch.dict(os.environ, {"WEBSEC_UPDATE_HOME": ""}), patch.object(Path, "home", return_value=home):
            self.assertEqual(self.online()["error"], "cache_not_saved")
        self.assertFalse((self.cache / "websec-validator").exists())

    def test_explicit_base_alias_supported(self):
        self.cache.mkdir()
        alias = self.root / "alias"
        alias.symlink_to(self.cache, target_is_directory=True)
        with patch.dict(os.environ, {"WEBSEC_UPDATE_HOME": str(alias)}):
            self.assertIsNone(self.online()["error"])
        self.assertTrue((self.cache / "release.json").is_file())

    def test_private_or_relative_cache_base_refused(self):
        for path in (str(self.root / ".LOCAL"), "relative-cache"):
            with patch.dict(os.environ, {"WEBSEC_UPDATE_HOME": path}):
                self.assertEqual(self.online()["error"], "cache_not_saved")
        self.assertFalse((self.root / ".LOCAL").exists())

    def test_hardlink_peer_preserved_on_cache_replace(self):
        path = self.cached()
        peer = self.root / "peer.json"
        os.link(path, peer)
        before = peer.read_bytes()
        self.online()
        self.assertEqual(peer.read_bytes(), before)
        self.assertNotEqual(path.read_bytes(), before)

    def test_special_cache_file_refused_without_blocking(self):
        self.cache.mkdir()
        os.mkfifo(self.cache / "release.json")
        self.assertEqual(updates.check()["error"], "cache_unavailable")
        self.assertEqual(self.online()["error"], "cache_not_saved")

    def test_network_failure_preserves_cache_and_omits_error_text(self):
        path = self.cached()
        before = path.read_bytes()
        with patch.object(updates, "_fetch", side_effect=OSError("secret reflected message")):
            result = updates.check(online=True)
        self.assertEqual(result["status"], "unavailable")
        self.assertIsNone(result["latest_version"])
        self.assertEqual(path.read_bytes(), before)
        self.assertNotIn("secret", json.dumps(result))

    def test_online_must_be_a_real_boolean(self):
        for value in (1, "true", None, [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                updates.check(online=value)

    def response(self, body=None, status=200, encoding="identity"):
        response = Mock(status=status)
        stream = io.BytesIO(json.dumps(body or index(("0.19.2", False))).encode())
        response.read1.side_effect = stream.read1
        response.getheader.return_value = encoding
        connection = Mock()
        connection.getresponse.return_value = response
        return connection, response

    def test_transport_is_fixed_https_metadata_only(self):
        connection, _ = self.response()
        with patch.object(http.client, "HTTPSConnection", return_value=connection) as factory:
            self.assertEqual(updates._fetch(), "0.19.2")
        factory.assert_called_once_with("pypi.org", timeout=5)
        method, path = connection.request.call_args.args
        self.assertEqual((method, path), ("GET", "/simple/websec-validator/"))
        headers = connection.request.call_args.kwargs["headers"]
        self.assertNotIn("Authorization", headers)
        self.assertNotIn("Cookie", headers)
        connection.close.assert_called_once()

    def test_redirect_rate_limit_or_encoded_body_rejected(self):
        for status, encoding in ((302, "identity"), (429, "identity"), (200, "gzip")):
            connection, response = self.response(status=status, encoding=encoding)
            with patch.object(http.client, "HTTPSConnection", return_value=connection), self.assertRaises(ValueError):
                updates._fetch()
            response.read1.assert_not_called()
            connection.request.assert_called_once()
            connection.close.assert_called_once()

    def test_response_size_and_deadline_bounded(self):
        connection, response = self.response()
        response.read1.side_effect = None
        response.read1.return_value = b"x" * 65536
        with patch.object(http.client, "HTTPSConnection", return_value=connection), self.assertRaises(ValueError):
            updates._fetch()
        self.assertLessEqual(response.read1.call_count, 17)
        connection, response = self.response()
        with patch.object(http.client, "HTTPSConnection", return_value=connection), \
                patch.object(updates.time, "monotonic", side_effect=[0, 11]), self.assertRaises(TimeoutError):
            updates._fetch()
        response.read1.assert_not_called()

    def test_cli_offline_and_online_are_explicit_advisory(self):
        for argv, expected in ((["update-check", "--format", "json"], False),
                               (["update-check", "--online", "--format", "json"], True)):
            stream = io.StringIO()
            with patch.object(updates, "_fetch", side_effect=OSError("offline")) as fetch, redirect_stdout(stream):
                self.assertEqual(cli.main(argv), 0)
            self.assertEqual(fetch.called, expected)
            self.assertFalse(json.loads(stream.getvalue())["installation_performed"])

    def test_briefing_advisory_never_fetches(self):
        with patch.object(updates, "_fetch") as fetch:
            text = briefing._update_advisory({"version": "0.19.2"})
        fetch.assert_not_called()
        self.assertIn("ask the user", text)
        self.assertIn("separate approval", text)

    def mcp(self, arguments, name="websec_check_updates"):
        return mcp_server.process({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                   "params": {"name": name, "arguments": arguments}},
                                  allowed_roots=(self.root,))["result"]

    def test_mcp_offline_metadata_tool_needs_no_repo_path(self):
        with patch.object(updates, "_fetch") as fetch:
            result = self.mcp({})
        fetch.assert_not_called()
        self.assertNotIn("isError", result)
        self.assertEqual(json.loads(result["content"][0]["text"])["status"], "not_checked")

    def test_mcp_online_and_strict_input_contract(self):
        with patch.object(updates, "_fetch", return_value="0.20.0") as fetch:
            result = self.mcp({"online": True})
        fetch.assert_called_once()
        self.assertFalse(json.loads(result["content"][0]["text"])["installation_performed"])
        for arguments in ({"online": "true"}, {"online": 1}, {"url": "https://other/"},
                          {"path": str(self.root)}, {"online": True, "install": True}):
            with patch.object(updates, "_fetch") as fetch:
                self.assertTrue(self.mcp(arguments)["isError"])
            fetch.assert_not_called()

    def test_mcp_existing_repo_tools_retain_root_guard(self):
        for name in ("websec_recon", "websec_findings", "websec_sarif", "websec_briefing"):
            self.assertTrue(self.mcp({}, name)["isError"])
            self.assertTrue(self.mcp({"path": str(self.root.parent)}, name)["isError"])

    def test_mcp_notifications_cannot_trigger_online_check(self):
        with patch.object(updates, "_fetch") as fetch:
            result = mcp_server.process({"jsonrpc": "2.0", "method": "tools/call",
                                        "params": {"name": "websec_check_updates", "arguments": {"online": True}}})
        self.assertIsNone(result)
        fetch.assert_not_called()

    def test_standing_guidance_preserves_consent_and_decline(self):
        from websec_validator import install
        shipped = (Path(__file__).resolve().parents[1] / "skills/security-pass/SKILL.md").read_text()
        for text in (install._INSTRUCTION_BODY, shipped):
            self.assertIn("At the start of each security review, ask", text)
            self.assertIn("only after approval use `websec update-check --online`", text)
            self.assertIn("Offer any upgrade for separate", text)
            self.assertIn("A declined or unavailable check does not block review", text)

    def test_lexical_private_alias_is_refused(self):
        self.cache.mkdir()
        alias = self.root / ".local"
        alias.symlink_to(self.cache, target_is_directory=True)
        with patch.dict(os.environ, {"WEBSEC_UPDATE_HOME": str(alias)}):
            self.assertEqual(self.online()["error"], "cache_not_saved")
        self.assertFalse((self.cache / "release.json").exists())

    def test_malformed_nested_network_json_is_advisory(self):
        connection, response = self.response()
        stream = io.BytesIO(("[" * 2000 + "]" * 2000).encode())
        response.read1.side_effect = stream.read1
        with patch.object(http.client, "HTTPSConnection", return_value=connection):
            result = updates.check(online=True)
        self.assertEqual(result["status"], "unavailable")
        self.assertFalse(self.cache.exists())

    def test_doctor_advice_is_offline_and_preserves_toolchain_exit(self):
        detected = {"available": [], "missing": [], "incompatible": [{"name": "test", "version": "0"}]}
        with patch.object(cli.scanners, "detect", return_value=detected), \
                patch.object(http.client, "HTTPSConnection") as connection, redirect_stdout(io.StringIO()) as stream:
            self.assertEqual(cli.main(["doctor"]), cli.EXIT_USAGE)
        connection.assert_not_called()
        self.assertIn("ask the user", stream.getvalue())

    def test_full_briefing_is_offline_with_advisory_banner(self):
        from websec_validator import recon
        fixture = Path(__file__).resolve().parent / "fixtures" / "py_app"
        with patch.object(http.client, "HTTPSConnection") as connection:
            facts = recon.build_facts(fixture, "0.19.2")
            text = briefing.render(facts, {"available": [], "missing": []}, [], [])
        connection.assert_not_called()
        self.assertIn("Tool maintenance (advisory, separate from scan findings)", text)
        self.assertIn("ask the user", text)


if __name__ == "__main__":
    unittest.main()

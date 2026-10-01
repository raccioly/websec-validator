"""Staged drafts enforce transport safety even when launched without the CLI."""
import ast
import asyncio
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import types
import unittest
import urllib.error
from unittest.mock import AsyncMock, Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from websec_validator import dynamic, probes
TEMPLATES = ROOT / "src/websec_validator/templates/probes"
spec = importlib.util.spec_from_file_location("probe_lib_test", TEMPLATES / "_lib.py")
lib = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lib)


class ProbeTransportTests(unittest.TestCase):
    def test_a_copied_shell_draft_without_its_guard_never_falls_back_to_curl(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unauth-baseline.sh"
            path.write_bytes((TEMPLATES / path.name).read_bytes())
            proc = subprocess.run(["bash", str(path)], env=dict(os.environ, TARGET="https://remote.example"), capture_output=True, text=True, timeout=10)
            self.assertEqual(proc.returncode, 2)
            self.assertIn("_lib.bash", proc.stderr)

    def test_every_mutating_method_is_refused_before_curl(self):
        for method in ("POST", "put", "PATCH", "DELETE", "CUSTOM"):
            for url in ("https://remote.example/path", "http://localhost.attacker.example/", "http://127.0.0.1@remote.example/"):
                with self.subTest(method=method, url=url), patch.object(lib.subprocess, "run") as run:
                    with self.assertRaises(ValueError):
                        lib.curl(method, url, body={})
                    run.assert_not_called()

    def test_remote_get_and_loopback_write_remain_available_without_curl_config(self):
        for method, url in (("GET", "https://remote.example/x"), ("POST", "http://127.0.0.1:9000/x"), ("DELETE", "http://[::1]:9000/x")):
            with patch.object(lib.subprocess, "run", return_value=types.SimpleNamespace(stdout="ok\nHTTP_CODE:200")) as run:
                self.assertEqual(lib.curl(method, url)[0], 200)
                argv = run.call_args.args[0]
                self.assertEqual(argv[:2], ["curl", "-q"])
                self.assertIn("--noproxy", argv)

    def test_shell_implicit_posts_and_unknown_transport_options_fail_closed(self):
        for args in (["-d", "{}", "https://remote.example/"], ["-F", "file=@test", "https://remote.example/"],
                     ["-X", "DELETE", "https://remote.example/"], ["-L", "http://localhost/x"],
                     ["-X", "POST", "-I", "https://remote.example/"],
                     ["-I", "-X", "POST", "https://remote.example/"],
                     ["--config", "input", "http://localhost/x"], ["--next", "http://localhost/x"]):
            with self.subTest(args=args), patch.object(lib.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    lib.shell_curl(args)
                run.assert_not_called()

    def test_shell_allowed_controls_call_real_transport_once(self):
        for args in (["-s", "https://remote.example/x"], ["-F", "file=@test", "http://localhost/x"],
                     ["-X", "GET", "-d", "{}", "https://remote.example/x"]):
            with patch.object(lib.subprocess, "run", return_value=types.SimpleNamespace(returncode=0)) as run:
                self.assertEqual(lib.shell_curl(args), 0)
                run.assert_called_once()

    def test_shell_function_guard_runs_when_sourced_independently(self):
        proc = subprocess.run(["bash", "-c", 'source "$1"; curl -X POST https://remote.example/x', "probe", str(TEMPLATES / "_lib.bash")], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("mutating probes require localhost", proc.stderr)

    def test_all_shell_curl_drafts_use_shared_transport_and_stage_helper(self):
        for template in TEMPLATES.glob("*.sh"):
            text = template.read_text()
            if "curl -" in text:
                self.assertIn('source "$(dirname "$0")/_lib.bash" || exit 2', text, template.name)
        with tempfile.TemporaryDirectory() as directory:
            probes.stage({}, Path(directory))
            self.assertTrue((Path(directory) / "probes" / "_lib.bash").exists())

    def test_stdlib_race_transport_refuses_remote_before_request(self):
        environment = {"TARGET": "https://remote.example", "OBJ_A": "1", "TOKEN_A": "test-token"}
        context = {"endpoints": {"writes": ["POST /item/{id}"]}}
        with patch.dict(os.environ, environment), patch.dict(sys.modules, {"_lib": lib, "httpx": types.SimpleNamespace()}), patch.object(lib, "context", return_value=context):
            module = runpy.run_path(str(TEMPLATES / "race-conditions.py"), run_name="probe_test")
        client = types.SimpleNamespace(open=Mock())
        with self.assertRaises(ValueError):
            module["fire"]({"method": "POST", "url": "https://remote.example/", "payload": {}}, opener=client)
        client.open.assert_not_called()
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.status = 201
        client.open.return_value = response
        result = module["fire"]({"method": "POST", "url": "http://localhost/x", "payload": {}}, opener=client)
        self.assertEqual(result, (201, None))
        response.read.assert_not_called()

    def test_race_rejects_invalid_concurrency_and_large_payload_before_transport(self):
        with patch.dict(sys.modules, {'_lib': lib}):
            module = runpy.run_path(str(TEMPLATES / 'race-conditions.py'), run_name='probe_test')
        target = {'method': 'POST', 'url': 'http://localhost/x', 'payload': {}}
        for count in (0, -1, 17, True):
            with self.subTest(count=count), self.assertRaises(ValueError):
                module['run_target'](target, parallel=count)
        client = types.SimpleNamespace(open=Mock())
        with self.assertRaises(ValueError):
            module['fire'](dict(target, payload={'too_large': 'x' * 17000}), opener=client)
        client.open.assert_not_called()

    def test_race_actual_loopback_pool_is_bounded_and_does_not_follow_redirects(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        import time
        with patch.dict(sys.modules, {'_lib': lib}):
            module = runpy.run_path(str(TEMPLATES / 'race-conditions.py'), run_name='probe_test')
        lock = threading.Lock()
        observed = {'active': 0, 'peak': 0, 'calls': 0, 'followed': 0}
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                with lock:
                    observed['active'] += 1
                    observed['peak'] = max(observed['peak'], observed['active'])
                    observed['calls'] += 1
                time.sleep(0.02)
                self.send_response(302)
                self.send_header('Location', '/followed?credential=REFLECTED_TEST_SECRET')
                self.end_headers()
                with lock:
                    observed['active'] -= 1
            def do_GET(self):
                observed['followed'] += 1
                self.send_response(200)
                self.end_headers()
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = {'method': 'POST', 'url': f'http://127.0.0.1:{server.server_port}/race',
                      'payload': {}, 'name': 'owned race', 'expected_unique': 1, 'note': 'owned'}
            with patch.dict(os.environ, {'http_proxy': 'http://remote.invalid:1'}), contextlib.redirect_stdout(io.StringIO()):
                result = module['run_target'](target, parallel=4)
            self.assertEqual(observed['calls'], 4)
            self.assertLessEqual(observed['peak'], 4)
            self.assertGreater(observed['peak'], 1)
            self.assertEqual(observed['followed'], 0)
            self.assertEqual(result['status_counts'], {302: 4})
            self.assertNotIn('REFLECTED_TEST_SECRET', json.dumps(result))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_webhook_direct_curl_is_guarded_before_execution(self):
        with patch.dict(os.environ, {"TARGET": "https://remote.example"}), patch.dict(sys.modules, {"_lib": lib}), patch("subprocess.run") as run, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError):
                runpy.run_path(str(TEMPLATES / "webhook-forgery.py"), run_name="probe_test")
            run.assert_not_called()

    def test_saved_response_previews_are_metadata_only(self):
        secret = "REFLECTED_TEST_SECRET"
        with tempfile.TemporaryDirectory() as directory, patch.object(lib, "_HERE", Path(directory)):
            path = lib.save("test", [{"status": 200, "preview": secret, "nested": {"body_preview": secret}, "sample_responses": [[200, secret]]}])
            data = path.read_text()
            self.assertNotIn(secret, data)
            self.assertEqual(json.loads(data)[0]["status"], 200)


class DynamicPrivacyTests(unittest.TestCase):
    def test_dynamic_transport_does_not_inherit_remote_proxy_configuration(self):
        command = "from websec_validator import dynamic; import urllib.request; assert not any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in dynamic._NO_REDIRECT_OPENER.handlers)"
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), http_proxy="http://remote.example:8080", https_proxy="http://remote.example:8080")
        proc = subprocess.run([sys.executable, "-c", command], env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_redirect_and_exception_errors_do_not_persist_reflected_credentials(self):
        secret = "REFLECTED_TEST_SECRET"
        config = {"target": "https://authorized-test.example", "roles": {"a": {"username": "test", "password": secret}}}
        for error in (urllib.error.HTTPError(config["target"], 302, "redirect", {"Location": "/login?password=" + secret}, None), RuntimeError(secret)):
            with patch.object(dynamic._NO_REDIRECT_OPENER, "open", side_effect=error):
                result = dynamic.mint(config, "a")
            self.assertNotIn(secret, json.dumps(result))
            self.assertIn("error_kind", result)

    def test_explicit_remote_login_remains_permitted_and_keeps_credential_fields(self):
        response = io.StringIO('{"tokens":{"accessToken":"test-token"},"user":{"groupIds":[1]}}')
        config = {"target": "https://authorized-test.example", "roles": {"a": {"username": "test", "password": "test-password", "_note": "private"}}}
        with patch.object(dynamic._NO_REDIRECT_OPENER, "open", return_value=response) as request:
            self.assertEqual(dynamic.mint(config, "a")["token"], "test-token")
        sent = request.call_args.args[0]
        self.assertEqual(sent.get_method(), "POST")
        self.assertEqual(json.loads(sent.data), {"username": "test", "password": "test-password"})

    def test_dynamic_write_transport_blocks_before_opener(self):
        with patch.object(dynamic._NO_REDIRECT_OPENER, "open") as request:
            with self.assertRaises(ValueError):
                dynamic._request("POST", "https://remote.example/x", "token", data=b"{}")
            request.assert_not_called()


class S3TemporaryTests(unittest.TestCase):
    def test_private_reservation_cleans_owned_files_on_success_and_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            # Mock commands: no AWS, HTTP or shared /tmp files are touched by this regression.
            commands = base / "bin"
            commands.mkdir()
            aws = commands / "aws"
            aws.write_text('#!/bin/sh\ncase "$*" in *head-bucket*) exit "${MOCK_HEAD_FAIL:-0}";; esac\nprintf "false\\n"\n')
            aws.chmod(0o700)
            curl = commands / "curl"
            curl.write_text('#!/bin/sh\nprintf 403\n')
            curl.chmod(0o700)
            reserved = base / "reserved"
            reserved.mkdir()
            sentinel = reserved / "_s3err"
            sentinel.write_text("unowned")
            for fail in ("0", "1"):
                environment = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ["PATH"], TMPDIR=str(reserved), MOCK_HEAD_FAIL=fail)
                proc = subprocess.run(["bash", str(TEMPLATES / "s3-assess.sh"), "test-bucket"], env=environment, capture_output=True, text=True, timeout=15)
                self.assertIn(proc.returncode, (0, 1))
                self.assertEqual(sentinel.read_text(), "unowned")
                self.assertEqual([p.name for p in reserved.iterdir()], ["_s3err"])
            self.assertNotIn("/tmp/_s3err", (TEMPLATES / "s3-assess.sh").read_text())


if __name__ == "__main__":
    unittest.main()

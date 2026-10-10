"""Field reports #195 and #197.

#195 — `websec emit-context` on a hand-rolled Node `http` router stated "auth: jwt (bearer)" as fact
although the app has no JWT (HMAC webhook signatures, HttpOnly cookie sessions, one Bearer API key),
and "1 route(s)" with no caveat although the briefing flags route discovery as incomplete. The JWT
label came from name-only mentions (a comment naming jsonwebtoken, a 'token_required' error code)
that the permissive JWT signal counted as library use.

#197 — `websec init` proposed `tests/` as a scope glob although its own header recommends
`fingerprint:` acknowledgements; for secrets a glob also hides a REAL credential committed later.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from websec_validator import cli, findings, init_scope  # noqa: E402
from websec_validator.extractors.auth import AuthExtractor  # noqa: E402
from websec_validator.extractors.base import RepoContext  # noqa: E402

# The app described in #195: `if (path === '/x' && req.method === 'POST')` dispatch to named
# handlers, an X-Hub-Signature-256 HMAC check, an HttpOnly cookie session, one route comparing
# `Authorization: Bearer <api key>` against an env key — and no JWT library anywhere. The comment
# naming jsonwebtoken and the 'token_required' error code are the name-only mentions that used to
# make the primary scheme read "jwt (bearer)".
HAND_ROLLED_SERVER = """\
// Hand-rolled router. Auth is deliberately NOT a JWT (no jsonwebtoken): HMAC webhook
// signatures, HttpOnly cookie sessions and one ingest route that takes a static API key.
import http from 'node:http';
import crypto from 'node:crypto';

const INGEST_API_KEY = process.env.INGEST_API_KEY;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const sessions = new Map();

function verifySignature(req, body) {
  const sig = req.headers['x-hub-signature-256'] || '';
  const expected = 'sha256=' + crypto.createHmac('sha256', WEBHOOK_SECRET).update(body).digest('hex');
  return sig.length === expected.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}

function sessionFrom(req) {
  const m = (req.headers.cookie || '').match(/sid=([a-f0-9]+)/);
  return m ? sessions.get(m[1]) : null;
}

function deny(res) { res.statusCode = 401; res.end(JSON.stringify({ error: 'token_required' })); }

async function handleLogin(req, res) {
  const sid = crypto.randomBytes(16).toString('hex');
  sessions.set(sid, { user: 'u' });
  res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; Secure; SameSite=Strict; Path=/`);
  res.end('ok');
}
async function handleWebhook(req, res, body) {
  if (!verifySignature(req, body)) return deny(res);
  res.end('accepted');
}
async function handleIngest(req, res) {
  const auth = req.headers['authorization'] || '';
  if (auth !== `Bearer ${INGEST_API_KEY}`) return deny(res);
  res.end('ingested');
}
async function handleMe(req, res) {
  const s = sessionFrom(req);
  if (!s) return deny(res);
  res.end(JSON.stringify(s));
}
async function handleNotes(req, res) {
  if (!sessionFrom(req)) return deny(res);
  res.end('saved');
}
async function handleLogout(req, res) {
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/');
  res.end('bye');
}

const server = http.createServer(async (req, res) => {
  const path = new URL(req.url, 'http://localhost').pathname;
  let body = '';
  for await (const chunk of req) body += chunk;
  if (path === '/login' && req.method === 'POST') return handleLogin(req, res);
  if (path === '/webhook' && req.method === 'POST') return handleWebhook(req, res, body);
  if (path === '/ingest' && req.method === 'POST') return handleIngest(req, res);
  if (path === '/me' && req.method === 'GET') return handleMe(req, res);
  if (path === '/notes' && req.method === 'POST') return handleNotes(req, res);
  if (path === '/logout' && req.method === 'POST') return handleLogout(req, res);
  res.statusCode = 404;
  res.end();
});

server.listen(3000);
"""


def _write(root: Path, files: dict) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _auth(files: dict, facts: dict | None = None) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        return AuthExtractor().extract(RepoContext(_write(Path(tmp), files)), facts or {})


def _main(argv: list) -> tuple:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------------------------------------
# #195 (a) — auth inference: JWT only on JWT evidence
# ---------------------------------------------------------------------------------------------
class AuthSchemeEvidenceTests(unittest.TestCase):

    def test_hand_rolled_router_is_not_called_jwt(self):
        out = _auth({"server.mjs": HAND_ROLLED_SERVER, "package.json": '{"name":"x","type":"module"}'})
        self.assertFalse(out["scheme"].startswith("jwt"), out["scheme"])
        self.assertNotIn("jwt (bearer)", out["schemes_detected"])
        self.assertEqual(out["scheme"], "hmac-signed-cookie")
        self.assertEqual(out["token_location"], "cookie")

    def test_name_only_jwt_mention_is_kept_but_ranked_last(self):
        # Never silently dropped — the reader can still see it — but it cannot outrank real evidence.
        out = _auth({"server.mjs": HAND_ROLLED_SERVER})
        weak = [s for s in out["schemes_detected"] if s.startswith("jwt")]
        self.assertEqual(len(weak), 1)
        self.assertEqual(out["schemes_detected"][-1], weak[0])
        self.assertIn("weak evidence", weak[0])

    def test_comment_naming_a_jwt_library_is_not_jwt_evidence(self):
        out = _auth({"src/auth.js": "// we do not use jsonwebtoken here, sessions only\n"
                                    "const s = require('express-session');\n"})
        self.assertEqual(out["scheme"], "session-cookie")

    def test_token_required_error_code_is_not_jwt_evidence(self):
        out = _auth({"src/api.js": "const API_KEY = process.env.API_KEY;\n"
                                   "if (req.headers['x-api-key'] !== API_KEY) "
                                   "return res.status(401).json({error: 'token_required'});\n"})
        self.assertEqual(out["scheme"], "api-key")

    def test_bare_bearer_header_is_not_jwt_evidence(self):
        out = _auth({"src/ingest.js": "const auth = req.headers.authorization || '';\n"
                                      "if (auth !== `Bearer ${process.env.INGEST_KEY}`) deny(res);\n"})
        self.assertFalse(any(s.startswith("jwt") for s in out["schemes_detected"]), out["schemes_detected"])

    def test_real_jwt_idioms_still_read_as_jwt(self):
        # The no-false-negative side: every idiom the permissive signal caught as real JWT use stays
        # JWT evidence, now with high confidence.
        idioms = {
            "src/a.js": "const jwt = require('jsonwebtoken');\nmodule.exports = (t) => jwt.verify(t, k);\n",
            "src/b.ts": "import jwt from 'jsonwebtoken';\nexport const s = (p: object) => jwt.sign(p, k);\n",
            "src/c.ts": "import { jwtVerify } from 'jose';\nawait jwtVerify(token, key);\n",
            "src/d.ts": "import * as jose from 'jose';\nconst { payload } = await jose.jwtVerify(t, k);\n",
            "src/e.ts": "import { SignJWT } from 'jose';\nawait new SignJWT({}).sign(k);\n",
            "app/f.py": "import jwt\npayload = jwt.decode(tok, KEY, algorithms=['HS256'])\n",
            "app/g.py": "from flask_jwt_extended import get_jwt_identity, jwt_required\n",
            "app/h.py": "from jose import jwt\nclaims = jwt.decode(t, k)\n",
            "app/i.py": "# requires PyJWT\nimport jwt as pyjwt\n",
            "app/j.py": "@jwt_required()\ndef me():\n    return get_jwt_identity()\n",
        }
        for rel, text in idioms.items():
            with self.subTest(rel=rel):
                out = _auth({rel: text}, {"routes": {"endpoints": [{"method": "GET", "path": "/x"}]}})
                self.assertEqual(out["scheme"], "jwt (bearer)", out["schemes_detected"])
                self.assertEqual(out["scheme_confidence"], "high")
                self.assertTrue(out["signal_counts"]["jwt"] >= 1)

    def test_jose_alg_or_jwks_corroborates_a_mention(self):
        # A @token_required decorator alone is a name; verified against a JWKS / with a JOSE alg it is
        # a JWT check.
        for extra in ("JWKS = os.environ['JWKS_URI']\n", "ALG = {'alg': 'RS256'}\n"):
            with self.subTest(extra=extra):
                out = _auth({"app/auth.py": "def token_required(f):\n    " + extra.replace("\n", "\n    ")
                             + "return f\n"}, {"routes": {"endpoints": [{"method": "GET", "path": "/x"}]}})
                self.assertEqual(out["scheme"], "jwt (bearer)")

    def test_corroboration_alone_never_creates_a_jwt_reading(self):
        # An App Store Connect script signs an OUTBOUND ES256 token; a JWKS URL may be a provider's.
        # Neither is the app's own auth scheme, and neither read as JWT before — no new false claims.
        for text in ("const token = sign({ alg: 'ES256', kid }, key);\n",
                     "const cfg = { jwksUri: 'https://login.example/.well-known/jwks.json' };\n"):
            with self.subTest(text=text):
                out = _auth({"scripts/asc.mjs": text})
                self.assertFalse(any(s.startswith("jwt") for s in out["schemes_detected"]))
                self.assertEqual(out["signal_counts"]["jwt"], 0)

    def test_a_person_called_jose_is_not_a_jwt_library(self):
        out = _auth({"src/seed.js": "export const users = [{ name: 'Jose' }, { name: 'jose' }];\n"
                                    "const s = require('express-session');\n"})
        self.assertEqual(out["scheme"], "session-cookie")

    def test_jwt_outranks_other_schemes_when_it_is_real(self):
        out = _auth({"src/a.ts": "import jwt from 'jsonwebtoken';\njwt.verify(t, S);\n",
                     "src/b.ts": "const k = req.headers['x-api-key'];\nconst h = createHmac('sha256', s);\n"
                                 "res.setHeader('Set-Cookie', c);\n"})
        self.assertEqual(out["scheme"], "jwt (bearer)")

    def test_weak_only_jwt_is_preserved_as_a_low_confidence_primary(self):
        # A Flask app whose only signal is a @token_required decorator still reads as JWT-ish (the
        # label consumers match on `jwt` is preserved), but no longer as a high-confidence fact.
        out = _auth({"app/views.py": "@token_required\ndef me():\n    return 'ok'\n"},
                    {"routes": {"endpoints": [{"method": "GET", "path": "/me"}]}})
        self.assertTrue(out["scheme"].startswith("jwt"), out["scheme"])
        self.assertEqual(out["scheme_confidence"], "low")
        self.assertEqual(out["token_location"], "bearer")

    def test_legacy_jwt_signal_count_is_unchanged_for_probe_staging(self):
        # signal_counts.jwt stages the JWT probes and escalates forgeable-secret findings; a weak
        # mention still counts there (narrowing it could drop a real JWT lead).
        out = _auth({"server.mjs": HAND_ROLLED_SERVER})
        self.assertEqual(out["signal_counts"]["jwt"], 1)
        self.assertEqual(out["signal_counts"]["jwt_strong"], 0)

    def test_confidence_is_low_without_a_mapped_route(self):
        out = _auth({"src/a.ts": "import jwt from 'jsonwebtoken';\njwt.verify(t, S);\n"})
        self.assertEqual(out["scheme"], "jwt (bearer)")
        self.assertEqual(out["scheme_confidence"], "low")
        self.assertIn("no HTTP route mapped", out["scheme_basis"])


# ---------------------------------------------------------------------------------------------
# #195 (b) — the emit-context block carries the caveats
# ---------------------------------------------------------------------------------------------
class EmitContextCaveatTests(unittest.TestCase):

    def test_issue_repro_block_flags_routes_and_does_not_state_jwt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _write(Path(tmp), {"server.mjs": HAND_ROLLED_SERVER,
                                      "package.json": '{"name":"x","type":"module"}'})
            code, out, _err = _main(["emit-context", str(root), "--markdown"])
        self.assertEqual(code, 0)
        surface = next(line for line in out.splitlines() if line.startswith("- Attack surface:"))
        self.assertNotIn("jwt (bearer)", surface)
        self.assertIn("route discovery likely INCOMPLETE", surface)
        self.assertIn("count is a floor", surface)
        self.assertIn("inferred, unverified", surface)

    def _facts(self, **routes):
        base = {"count": 4, "engine": "noir", "noir": {"state": "ok", "reason": ""}, "coverage_warning": None}
        base.update(routes)
        return {"stack": {}, "routes": base, "authz": {}, "tenant": {}, "surface": {},
                "auth": {"scheme": "jwt (bearer)", "scheme_confidence": "high",
                         "scheme_basis": "JWT library import/call in 2 file(s)",
                         "schemes_detected": ["jwt (bearer)"]}}

    def _surface(self, facts):
        block = cli._security_context_md(facts, {"findings": []})
        return block, next(line for line in block.splitlines() if line.startswith("- Attack surface:"))

    def test_clean_evidence_is_stated_plainly(self):
        # Compactness: no hedging when nothing is uncertain.
        _block, surface = self._surface(self._facts())
        self.assertIn("4 route(s) · auth: jwt (bearer) · ", surface)
        self.assertNotIn("⚠", surface)

    def test_low_confidence_scheme_is_marked_as_a_guess(self):
        facts = self._facts()
        facts["auth"].update({"scheme": "api-key", "scheme_confidence": "low",
                              "scheme_basis": "api-key header/variable name only",
                              "schemes_detected": ["api-key"]})
        _block, surface = self._surface(facts)
        self.assertIn("auth: api-key (LOW-CONFIDENCE guess, unverified: api-key header/variable name only)",
                      surface)

    def test_surface_coverage_warning_caveats_count_and_auth(self):
        facts = self._facts(count=1, handler_signals=13,
                            coverage_warning="⚠ surface-coverage: mapped 1 route(s) but found ~13 ...")
        _block, surface = self._surface(facts)
        self.assertIn("1 route(s) [⚠ route discovery likely INCOMPLETE (~13 handler-ish functions", surface)
        self.assertIn("auth: jwt (bearer) (inferred, unverified — route discovery incomplete)", surface)

    def test_noir_failure_and_regex_fallback_caveat_the_count(self):
        for routes, needle in (({"noir": {"state": "failed", "reason": "x"}, "engine": "regex-fallback (…)"},
                                "OWASP Noir failed"),
                               ({"engine": "regex-fallback (install OWASP Noir for full coverage)"},
                                "regex-fallback route engine"),
                               ({"engine": "noir (0 routes) → regex-fallback backstop"},
                                "regex-fallback route engine")):
            with self.subTest(needle=needle):
                _block, surface = self._surface(self._facts(**routes))
                self.assertIn(needle, surface)
                # the scheme itself is not demoted by the engine alone
                self.assertIn("auth: jwt (bearer) · ", surface)

    def test_weak_jwt_primary_is_shown_as_a_guess_with_its_basis(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _write(Path(tmp), {"app/views.py": "@token_required\ndef me():\n    return 'ok'\n"})
            code, out, _err = _main(["emit-context", str(root), "--markdown"])
        self.assertEqual(code, 0)
        surface = next(line for line in out.splitlines() if line.startswith("- Attack surface:"))
        self.assertIn("auth: jwt? (LOW-CONFIDENCE guess, unverified:", surface)

    def test_block_stays_compact(self):
        # The caveats are inline: the block gains no lines (it is injected into every session).
        plain, _ = self._surface(self._facts())
        warned, _ = self._surface(self._facts(count=1, handler_signals=13,
                                              coverage_warning="⚠ surface-coverage: mapped 1 ..."))
        self.assertEqual(len(plain.splitlines()), len(warned.splitlines()))


# ---------------------------------------------------------------------------------------------
# #197 — init: warned globs, fingerprint acks for test-fixture secrets
# ---------------------------------------------------------------------------------------------
TODAY = date(2026, 10, 10)


def _secret(rel: str, fp: str, **extra) -> dict:
    return {"fingerprint": fp, "category": "static-secret", "attack_class": "secret", "severity": "LOW",
            "file": rel, "location": rel, "line": 1, "title": "secret: generic", **extra}


class InitScopeAcknowledgementTests(unittest.TestCase):

    def _repo(self, tmp) -> Path:
        return _write(Path(tmp), {"tests/fixtures/users.ts": "export const pw = 'hunter2-fixture';\n",
                                  "tests/a.test.ts": "test('x', () => {});\n",
                                  "src/app.ts": "export const x = 1;\n"})

    def _ledger(self, root: Path, rows: list, *, target: str | None = None) -> dict:
        return {"path": str(root / init_scope.LEDGER_REL), "findings": rows,
                **({"target": target} if target else {})}

    def _write_ledger(self, base: Path, target: Path, rows: list) -> Path:
        path = base / init_scope.LEDGER_REL
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"target": str(target), "findings": rows}), encoding="utf-8")
        return path

    def _entry(self, proposal, path="tests/"):
        return next(e for e in proposal["entries"] if e["path"] == path)

    def test_every_active_glob_line_warns_about_future_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            text = init_scope.render(init_scope.propose(root))
        glob_lines = [line for line in text.splitlines() if line.startswith("tests/")]
        self.assertEqual(len(glob_lines), 1)
        self.assertIn("also suppresses FUTURE findings here, including real secrets", glob_lines[0])
        self.assertIn("prefer fingerprint: acks", glob_lines[0])

    def test_warned_glob_still_parses_as_the_same_suppression(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            init_scope.write(root, init_scope.propose(root))
            self.assertEqual(list(findings.load_suppressions(root)), ["tests/"])
            self.assertEqual(dict(findings.load_acknowledgements(root)), {})

    def test_secret_only_directory_becomes_fingerprint_acknowledgements(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            ledger = self._ledger(root, [_secret("tests/fixtures/users.ts", "9ff8da3937b6b5f4")])
            proposal = init_scope.propose(root, ledger=ledger, today=TODAY)
            entry = self._entry(proposal)
            self.assertEqual(entry["mode"], "acknowledge")
            self.assertEqual(proposal["covered_files"], 0)
            init_scope.write(root, proposal)
            text = (root / ".websec-ignore").read_text()
            self.assertIn("fingerprint:9ff8da3937b6b5f4 expires:2027-01-08  # REVIEW:", text)
            # the glob is offered, commented out, with the warning — not applied
            self.assertNotIn("tests/", list(findings.load_suppressions(root)))
            self.assertRegex(text, r"(?m)^# tests/ .*NOT applied.*also suppresses FUTURE findings")
            acks = findings.load_acknowledgements(root, today=TODAY)
            record = acks.records["9ff8da3937b6b5f4"]
            self.assertEqual(record["state"], "active")
            self.assertEqual(record["expires"], "2027-01-08")
            self.assertTrue(record["reason"].startswith("REVIEW:"))

    def test_reinit_after_a_reviewed_run_reproposes_the_acknowledgements(self):
        # After the acks land, the next ledger carries those findings under `acknowledged`, not
        # `findings`; `init --force` must not fall back to the glob and discard them.
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            path = root / init_scope.LEDGER_REL
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({"target": str(root), "findings": [],
                                        "acknowledged": [_secret("tests/fixtures/users.ts", "9ff8da3937b6b5f4")]}))
            entry = self._entry(init_scope.propose(root, ledger=init_scope.load_prior_ledger(root)))
            self.assertEqual(entry["mode"], "acknowledge")
            self.assertEqual([a["fingerprint"] for a in entry["acks"]], ["9ff8da3937b6b5f4"])

    def test_placeholder_reason_satisfies_the_parser_and_claimspec(self):
        self.assertNotIn("#", init_scope.ACK_REASON)
        self.assertGreaterEqual(len(init_scope.ACK_REASON), findings.CLAIMSPEC_REASON_MIN)
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            proposal = init_scope.propose(root, ledger=self._ledger(
                root, [_secret("tests/fixtures/users.ts", "9ff8da3937b6b5f4")]), today=TODAY)
            init_scope.write(root, proposal)
            doc, report = findings.to_claimspec_ignore(root)
            self.assertEqual(report["omitted_acknowledgements"], [])

    def test_new_secret_in_the_directory_still_gates(self):
        """The field-note outcome: acknowledged fixtures stop gating, a new secret there does not."""
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            _write(root, {"tests/fixtures/new.ts": "export const k = 'ghp_x';\n"})
            row = {"category": "secret", "key": "generic-api-key", "file": "tests/fixtures/users.ts",
                   "title": "secret: generic", "severity": "LOW", "tools": ["gitleaks"], "line": 1}
            first = findings.build_ledger({}, {"all": [row]}, None, [])
            self.assertEqual(len(first["findings"]), 1)
            proposal = init_scope.propose(root, ledger={"path": "x", "findings": first["findings"]})
            self.assertEqual(self._entry(proposal)["mode"], "acknowledge")
            init_scope.write(root, proposal)
            new = dict(row, file="tests/fixtures/new.ts", title="secret: github pat")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                second = findings.build_ledger({}, {"all": [row, new]}, None,
                                               findings.load_suppressions(root),
                                               findings.load_acknowledgements(root))
            self.assertEqual([f["file"] for f in second["acknowledged"]], ["tests/fixtures/users.ts"])
            self.assertEqual([f["file"] for f in second["findings"]], ["tests/fixtures/new.ts"])

    def test_directory_with_non_secret_findings_keeps_the_warned_glob(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            rows = [_secret("tests/fixtures/users.ts", "9ff8da3937b6b5f4"),
                    {"fingerprint": "aaaabbbbccccdddd", "category": "static-sast", "attack_class": "sast",
                     "file": "tests/a.test.ts", "location": "tests/a.test.ts:1", "title": "eval"}]
            entry = self._entry(init_scope.propose(root, ledger=self._ledger(root, rows)))
            self.assertEqual(entry["mode"], "glob")
            self.assertEqual(entry["findings"], 2)

    def test_unsafe_fingerprints_are_never_written_into_the_policy(self):
        for fp in ("abc123\ntests/", "abc123 # x", "../../etc", "", "category:static-secret"):
            with self.subTest(fp=fp), tempfile.TemporaryDirectory() as tmp:
                root = self._repo(tmp)
                proposal = init_scope.propose(root, ledger=self._ledger(
                    root, [_secret("tests/fixtures/users.ts", fp)]))
                self.assertEqual(self._entry(proposal)["mode"], "glob")
                text = init_scope.render(proposal)
                self.assertEqual([line for line in text.splitlines() if line.startswith("fingerprint:")], [])
                init_scope.write(root, proposal)
                self.assertEqual(list(findings.load_suppressions(root)), ["tests/"])

    def test_secret_whose_file_is_gone_keeps_the_glob(self):
        # History-only: the claim that it sits under tests/ cannot be checked against the tree.
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            entry = self._entry(init_scope.propose(root, ledger=self._ledger(
                root, [_secret("tests/fixtures/deleted.ts", "9ff8da3937b6b5f4")])))
            self.assertEqual(entry["mode"], "glob")

    def test_absolute_paths_are_judged_relative_to_the_repo(self):
        # Working-tree scanners record absolute paths. A `tests` directory ABOVE the repo must not
        # make a src/ secret look like a test fixture (it would be acknowledged as one).
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(Path(tmp) / "tests" / "repo")
            src_secret = _secret(str((root / "src/app.ts").resolve()), "1111222233334444")
            fixture = _secret(str((root / "tests/fixtures/users.ts").resolve()), "5555666677778888")
            entry = self._entry(init_scope.propose(root, ledger=self._ledger(root, [src_secret, fixture])))
            self.assertEqual(entry["mode"], "acknowledge")
            self.assertEqual([a["fingerprint"] for a in entry["acks"]], ["5555666677778888"])
            self.assertEqual(entry["acks"][0]["file"], "tests/fixtures/users.ts")

    def test_ledger_is_read_from_the_target_then_the_cwd_and_must_match_the_target(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as elsewhere:
            root = self._repo(tmp)
            rows = [_secret("tests/fixtures/users.ts", "9ff8da3937b6b5f4")]
            self.assertIsNone(init_scope.load_prior_ledger(root))
            self._write_ledger(root, Path(elsewhere), rows)          # another repo's ledger
            self.assertIsNone(init_scope.load_prior_ledger(root))
            self._write_ledger(root, root, rows)
            self.assertEqual(init_scope.load_prior_ledger(root)["findings"], rows)
            (root / init_scope.LEDGER_REL).unlink()
            self._write_ledger(Path(elsewhere), root, rows)          # `websec run` from another cwd
            cwd = os.getcwd()
            try:
                os.chdir(elsewhere)
                self.assertEqual(init_scope.load_prior_ledger(root)["findings"], rows)
            finally:
                os.chdir(cwd)

    def test_cli_dry_run_prints_acks_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            self._write_ledger(root, root, [_secret("tests/fixtures/users.ts", "9ff8da3937b6b5f4")])
            code, out, _err = _main(["init", str(root), "--dry-run"])
            self.assertEqual(code, 0)
            self.assertFalse((root / ".websec-ignore").exists())
            self.assertIn("NOT globbed: only secret findings here", out)
            self.assertRegex(out, r"(?m)^fingerprint:9ff8da3937b6b5f4 expires:\d{4}-\d{2}-\d{2}  # REVIEW:")

    def test_cli_does_not_clobber_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            (root / ".websec-ignore").write_text("fingerprint:abc expires:2030-01-01 # reviewed\n")
            self._write_ledger(root, root, [_secret("tests/fixtures/users.ts", "9ff8da3937b6b5f4")])
            code, _out, _err = _main(["init", str(root)])
            self.assertNotEqual(code, 0)
            self.assertEqual((root / ".websec-ignore").read_text(),
                             "fingerprint:abc expires:2030-01-01 # reviewed\n")

    def test_cli_explicit_ledger_for_another_target_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as elsewhere:
            root = self._repo(tmp)
            path = self._write_ledger(Path(elsewhere), Path(elsewhere), [])
            code, _out, err = _main(["init", str(root), "--dry-run", "--ledger", str(path)])
            self.assertNotEqual(code, 0)
            self.assertIn("not a readable findings ledger", err)


if __name__ == "__main__":
    unittest.main()

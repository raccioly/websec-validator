"""Mounted tRPC procedures and local middleware evidence, not identifier names."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.routes import RoutesExtractor
from websec_validator.extractors.authz import AuthzExtractor

PREFIX = ('import {initTRPC,TRPCError} from "@trpc/server";\n'
          'import {createExpressMiddleware} from "@trpc/server/adapters/express";\n'
          'import express from "express";\nconst app=express();\nconst t=initTRPC.create();\n')
GUARD = 't.middleware(({ctx,next})=>{if(!ctx.user){throw new TRPCError({code:"UNAUTHORIZED"});}return next();})'


class TrpcRouteTests(unittest.TestCase):
    def scan(self, body, *, mount=True, prefix=PREFIX):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = prefix + body + ('\napp.use("/trpc",createExpressMiddleware({router:api}));' if mount else '')
            (root / 'app.ts').write_text(source)
            ctx = RepoContext(root)
            with patch('websec_validator.extractors.routes._noir_scan', return_value=None):
                facts = {'routes': RoutesExtractor().extract(ctx, {})}
            facts['authz'] = AuthzExtractor().extract(ctx, facts)
            return facts

    # @req specs/001-continuous-security-improvement/spec.md#FR-002
    def test_guard_chain_is_local_and_public_sibling_keeps_lead(self):
        body = ('const auth=' + GUARD + ';const protectedProcedure=t.procedure.use(auth);'
                'const api=t.router({private:protectedProcedure.mutation(()=>"private"),'
                'public:t.procedure.mutation(()=>"public")});')
        facts = self.scan(body)
        rows = {row['path']: row for row in facts['authz']['endpoint_guards']}
        self.assertTrue(rows['/trpc/private']['guarded'])
        self.assertFalse(rows['/trpc/public']['guarded'])

    def test_named_noop_imported_or_unreachable_middleware_is_not_enforcement(self):
        for guard in ('t.middleware(({ctx,next})=>{return next();})',
                      't.middleware(({ctx,next})=>{if(false){throw new TRPCError({code:"UNAUTHORIZED"});}return next();})',
                      't.middleware(({ctx,next})=>{if(!ctx.user){logger.warn("unauthorized");}return next();})',
                      'externalGuard'):
            with self.subTest(guard=guard):
                facts = self.scan('const protectedProcedure=t.procedure.use('+guard+');'
                                  'const api=t.router({private:protectedProcedure.mutation(()=>"ok")});')
                self.assertFalse(facts['authz']['endpoint_guards'][0]['guarded'])

    def test_unmounted_router_is_candidate_not_http_probe_target(self):
        facts = self.scan('const api=t.router({write:t.procedure.mutation(()=>"ok")});', mount=False)
        self.assertEqual(facts['routes']['endpoints'], [])
        self.assertTrue(facts['routes']['trpc']['candidates'])

    def test_mutated_relative_or_fake_primitives_never_register(self):
        for prefix in (PREFIX.replace('"@trpc/server"', '"./fake"'),
                       PREFIX + 'initTRPC.create=other;\n',
                       PREFIX + 'app.use=other;\n',
                       PREFIX + 'createExpressMiddleware=other;\n'):
            with self.subTest(prefix=prefix):
                self.assertEqual(self.scan('const api=t.router({write:t.procedure.mutation(()=>"ok")});',
                                           prefix=prefix)['routes']['endpoints'], [])

    def test_nested_router_names_are_transport_segments_and_queries_are_get(self):
        facts = self.scan('const api=t.router({users:t.router({read:t.procedure.query(()=>"ok"),'
                          'write:t.procedure.mutation(()=>"ok")})});')
        self.assertEqual({(row['method'],row['path']) for row in facts['routes']['endpoints']},
                         {('GET','/trpc/users.read'),('POST','/trpc/users.write')})

    def test_shadowed_error_or_caught_rejection_does_not_credit_chain(self):
        for guard in (GUARD.replace('{if', '{try{if').replace('return next();}', '}catch(e){}return next();}'),
                      GUARD.replace('{ctx,next}', '{ctx,next,TRPCError}')):
            facts = self.scan('const auth='+guard+';const api=t.router({write:t.procedure.use(auth).mutation(()=>"ok")});')
            self.assertFalse(facts['authz']['endpoint_guards'][0]['guarded'])

    def test_parser_budget_is_disclosed(self):
        from unittest.mock import patch
        from websec_validator.extractors import trpc_routes
        with patch.object(trpc_routes, 'MAX_BINDINGS', 1):
            facts = self.scan('const api=t.router({write:t.procedure.mutation(()=>"ok")});')
        self.assertTrue(facts['routes']['trpc']['errors'])

    def test_short_circuit_or_unknown_prefix_cannot_borrow_later_auth(self):
        for earlier in ('externalGuard', 't.middleware(({ctx,next})=>{return {secret:"public"};})'):
            facts = self.scan('const auth='+GUARD+';const api=t.router({write:t.procedure.use('
                              +earlier+').use(auth).mutation(()=>"ok")});')
            self.assertFalse(facts['authz']['endpoint_guards'][0]['guarded'])

    def test_nested_primitive_mutation_and_expression_mount_are_unverified(self):
        body = 'const auth='+GUARD+';const api=t.router({write:t.procedure.use(auth).mutation(()=>"ok")});'
        self.assertEqual(self.scan(body, prefix=PREFIX+'t.procedure.use=other;')['routes']['trpc']['routes'], [])
        for mount in ('if(false) app.use("/trpc",createExpressMiddleware({router:api}));',
                      'const unused=()=>app.use("/trpc",createExpressMiddleware({router:api}));'):
            facts = self.scan(body+mount, mount=False)
            self.assertEqual(facts['routes']['trpc']['routes'], [])
            self.assertTrue(facts['routes']['trpc']['candidates'])

    def test_late_receiver_or_alias_does_not_manufacture_transport(self):
        for body, prefix in (('const api=t.router({write:t.procedure.mutation(()=>"ok")});const t=initTRPC.create();',
                             PREFIX.replace('const t=initTRPC.create();', '')),
                             ('const api=t.router({write:publicProcedure.mutation(()=>"ok")});const publicProcedure=t.procedure;', PREFIX)):
            self.assertEqual(self.scan(body, prefix=prefix)['routes']['trpc']['routes'], [])

    def test_unsupported_generic_instance_has_explicit_scope_gap(self):
        facts = self.scan('const api=t.router({write:t.procedure.mutation(()=>"ok")});',
                          prefix=PREFIX.replace('initTRPC.create()', 'initTRPC.context<Context>().create()'))
        self.assertEqual(facts['routes']['trpc']['routes'], [])
        self.assertTrue(facts['routes']['trpc']['gaps'])

    def test_cli_persists_guarded_and_unguarded_procedures(self):
        import json
        import os
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            owner = Path(td)
            root = owner / 'target'
            root.mkdir()
            (root / 'app.ts').write_text(PREFIX + 'const auth='+GUARD+';'
                'const api=t.router({private:t.procedure.use(auth).mutation(()=>"ok"),'
                'write:t.procedure.mutation(()=>"ok")});'
                'app.use("/trpc",createExpressMiddleware({router:api}));')
            out = owner / 'out'
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'),
                       PATH=str(owner / 'no-tools'), WEBSEC_CALIBRATION_HOME=str(owner / 'calibration'),
                       WEBSEC_UPDATE_HOME=str(owner / 'release-metadata'))
            run = subprocess.run([sys.executable, '-m', 'websec_validator.cli', 'run', str(root), '--out', str(out),
                                  '--format', 'json', '--fail-on', 'high'], env=env, cwd=owner,
                                 capture_output=True, text=True, timeout=20)
            self.assertEqual(run.returncode, 1, run.stderr)
            directory = out / 'runs' / json.loads(run.stdout)['generated']
            facts = json.loads((directory / 'FACTS.json').read_text())
            self.assertEqual(facts['coverage']['route_discovery']['trpc']['routes'], 2)
            ledger = json.loads((directory / 'findings-ledger.json').read_text())
            self.assertEqual({row['location'] for row in ledger['findings'] if row['attack_class'] == 'missing-auth'}, {'/trpc/write'})


if __name__ == '__main__':
    unittest.main()

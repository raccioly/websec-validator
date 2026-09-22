"""Assigned Python queries retain request provenance and honest execution limits."""
from pathlib import Path
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator import cli, recon
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.surface import SurfaceExtractor
from websec_validator.extractors import sql_flow


class SqlFlowTests(unittest.TestCase):
    def scan(self, source):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'app.py').write_text(source)
            return SurfaceExtractor().extract(RepoContext(root), {'stack': {'datastores': ['postgres']}})

    def rows(self, source):
        return [r for r in self.scan(source)['sink_occurrences'] if r['sink_class'] == 'sql-injection']

    def handler(self, body):
        return 'from sqlalchemy import text\ndef handler(request):\n' + ''.join('    '+line+'\n' for line in body.splitlines())

    def test_assigned_interpolation_and_raw_queries_reach_actual_sink(self):
        for query in ('f"SELECT * FROM users WHERE name=\'{request.args[\'name\']}\'"',
                      '"SELECT * FROM users WHERE name=" + request.args["name"]',
                      '"SELECT %s" % request.args["name"]',
                      '"SELECT {}".format(request.args["name"])', 'request.args["query"]'):
            rows = self.rows(self.handler('query='+query+'\ndb.execute(text(query))'))
            self.assertEqual(len(rows), 1, query)
            self.assertEqual(rows[0]['source_lines'], [3])
            self.assertEqual(rows[0]['assignment_lines'], [3])
            self.assertEqual(rows[0]['line'], 4)

    def test_aliases_request_import_and_text_aliases(self):
        source = 'from flask import request as incoming\nfrom sqlalchemy import text as sqltext\ndef handler():\n q=incoming.args["query"]\n alias=q\n db.execute(sqltext(alias))\n'
        rows = self.rows(source)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['assignment_lines'], [4, 5])
        self.assertEqual(len(self.rows(self.handler('q=wrap(request.args["q"])\ndb.execute(text(q))'))), 1)
        self.assertEqual(len(self.rows(self.handler('text=custom\nq=request.args["q"]\ndb.execute(text(q))'))), 1)

    def test_safe_bound_values_and_literal_reassignment(self):
        for body in ('q=text("SELECT * FROM users WHERE name=:name")\ndb.execute(q,{"name":request.args["name"]})',
                     'q=text("SELECT :name").bindparams(name=request.args["name"])\ndb.execute(q)',
                     'q=request.args["query"]\nq="SELECT 1"\ndb.execute(text(q))',
                     'q="SELECT 1"\nrequest=object()\nq=request.args["query"]\ndb.execute(text(q))'):
            self.assertEqual(self.rows(self.handler(body)), [], body)
        self.assertEqual(len(self.rows(self.handler('q=request.args["query"]\ndb.execute(text(q), {"name":"safe"})'))), 1)

    def test_matched_unpack_keeps_query_and_bound_values_separate(self):
        for body in ('q, params = "SELECT * FROM users WHERE name=?", (request.args["name"],)\ndb.execute(q, params)',
                     '(q, (name,)) = "SELECT * FROM users WHERE name=?", (request.args["name"],)\ndb.execute(q, (name,))',
                     'q=request.args["query"]\nsafe="SELECT 1"\nq,safe=safe,q\ndb.execute(q)'):
            self.assertEqual(self.rows(self.handler(body)), [])
        for body in ('q, params=request.args["query"], ("name",)\ndb.execute(q,params)',
                     'q, params=unknown(request.args["query"])\ndb.execute(q,params)',
                     'first,*q=("safe",request.args["query"])\ndb.execute(q)'):
            self.assertEqual(len(self.rows(self.handler(body))), 1)

    def test_loop_carried_query_has_explicit_review_gap(self):
        for body in ('q="SELECT 1"\nfor item in range(2):\n db.execute(q)\n q=request.args["query"]',
                     'q="SELECT 1"\nwhile flag:\n db.execute(text(q))\n q=request.args["query"]',
                     'q="SELECT 1"\nq1="SELECT 1"\nfor item in range(3):\n db.execute(q)\n q=q1\n q1=request.args["query"]'):
            out=self.scan(self.handler(body))
            self.assertTrue(out['sql_flow']['unverified_queries'])
            self.assertIn('later iterations',out['sql_flow']['unverified_queries'][0]['reason'])
            self.assertNotIn('error',out)
        out=self.scan(self.handler('q="SELECT name FROM users WHERE name=?"\nfor item in range(2):\n db.execute(q,(request.args["name"],))'))
        self.assertEqual(out['sql_flow']['unverified_queries'],[])
        self.assertNotIn('sql-injection',out['sinks'])

    def test_branches_preserve_may_taint_but_both_safe_overwrites_clear(self):
        for body in ('q=request.args["q"]\nif flag:\n q="SELECT 1"\ndb.execute(text(q))',
                     'q="SELECT 1"\nif flag:\n q=request.args["q"]\ndb.execute(text(q))',
                     'q="SELECT 1"\nif flag:\n q="SELECT 2"\nelse:\n q=request.args["q"]\ndb.execute(text(q))'):
            self.assertEqual(len(self.rows(self.handler(body))), 1)
        self.assertEqual(self.rows(self.handler('q=request.args["q"]\nif flag:\n q="SELECT 1"\nelse:\n q="SELECT 2"\ndb.execute(text(q))')), [])

    def test_comments_logging_and_sibling_bindings_do_not_taint_safe_query(self):
        for body in ('# q=request.args["q"]\nq="SELECT 1"\ndb.execute(text(q))',
                     'msg=f"SELECT {request.args[\'q\']}"\nlogger.info(msg)\nq="SELECT 1"\ndb.execute(text(q))',
                     'q="SELECT 1"\nq_name="request.args[\'q\']"\ndb.execute(text(q))'):
            self.assertEqual(self.rows(self.handler(body)), [])
        source = self.handler('q=request.args["q"]\nlogger.info(q)') + '\ndef safe():\n q="SELECT 1"\n db.execute(text(q))\n'
        self.assertEqual(self.rows(source), [])
        source = self.handler('q=request.args["q"]\ndef other():\n q="SELECT 1"\ndb.execute(text(q))')
        self.assertEqual(len(self.rows(source)), 1)

    def test_direct_sites_dedup_unicode_byte_columns_and_line_stability(self):
        source = self.handler('label="café🔐"; db.execute(text(f"SELECT {request.args[\'q\']}"))')
        rows = self.rows(source)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['line'], 3)
        shifted = self.rows('# added comment\n'+source)
        self.assertEqual(rows[0]['semantic_id'], shifted[0]['semantic_id'])
        rows = self.rows(self.handler('q=request.args["q"]\ndb.execute(text(q))\ndb.execute(text(q))'))
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({r['semantic_id'] for r in rows}), 2)

    def test_supported_keyword_query_and_separate_parameter_arguments(self):
        for keyword in ('statement', 'query', 'sql'):
            self.assertEqual(len(self.rows(self.handler('q=request.args["q"]\ndb.execute('+keyword+'=text(q))'))), 1)
        self.assertEqual(self.rows(self.handler('q=text("SELECT :q")\ndb.execute(statement=q,parameters={"q":request.args["q"]})')), [])

    def test_import_bound_builders_distinguish_scalar_values_from_raw_text(self):
        prefix='from sqlalchemy import select, text\n'
        for expression in ('select(User).where(User.name == request.args["name"])',
                           'select(User).filter_by(name=request.args["name"])'):
            self.assertEqual(self.rows(prefix+self.handler('q='+expression+'\ndb.execute(q)')), [])
        for expression in ('select(text(request.args["query"]))',
                           'select(User).where(text(f"name={request.args[\'name\']}"))'):
            self.assertEqual(len(self.rows(prefix+self.handler('q='+expression+'\ndb.execute(q)'))),1)
        for assignment in ('select=custom', 'text=custom'):
            self.assertEqual(len(self.rows(prefix+self.handler(assignment+'\nq=select(text(request.args["query"]))\ndb.execute(q)'))),1)
        source='import sqlalchemy as sa\ndef handler(request):\n q=sa.select(User).where(User.name==request.args["name"])\n db.execute(q)\n'
        self.assertEqual(self.rows(source),[])
        for mutation in ('sa.select=custom',):
            out=self.scan(source+mutation+'\n')
            self.assertTrue(out['sql_flow']['unverified_queries'])
        source=prefix+self.handler('q=select(User).where(User.name==request.args["name"])\ndb.execute(q)')
        self.assertTrue(self.scan(source+'\nselect=custom\n')['sql_flow']['unverified_queries'])
        self.assertEqual(self.rows(self.handler('q=User.name==request.args["name"]\ndb.execute(q)')), [])

    def test_candidate_parse_and_work_limits_are_visible_with_other_sinks_retained(self):
        self.assertFalse(sql_flow.analyze('invalid python [')['candidate'])
        out = self.scan('db.execute(query)\ninvalid python [')
        self.assertTrue(out['error'])
        self.assertTrue(out['sql_flow']['errors'])
        for constant, value, source in (
                ('MAX_NODES', 10, self.handler('q=request.args["q"]\ndb.execute(text(q))')),
                ('MAX_SCOPES', 1, 'def one():\n db.execute(q)\ndef two():\n db.execute(q)'),
                ('MAX_STEPS', 20, self.handler('q=request.args["q"]\n' + 'if flag:\n q=q\n'*20 + 'db.execute(q)')),
                ('MAX_FINDINGS', 1, self.handler('q=request.args["q"]\ndb.execute(q)\ndb.execute(q)'))):
            with self.subTest(constant=constant), patch.object(sql_flow, constant, value):
                out = self.scan(source)
                self.assertTrue(out['error'])
                self.assertTrue(out['sql_flow']['errors'])
        with patch.object(sql_flow, 'MAX_NODES', 1):
            out = self.scan('db.execute(f"SELECT {request.args[\'q\']}")')
            self.assertIn('sql-injection', out['sinks'])
            self.assertTrue(out['error'])

    def test_real_recon_and_cli_require_complete_preserve_query_diagnostics(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)/'target'; root.mkdir()
            output=Path(td)/'output'
            path=root/'app.py'; path.write_text(self.handler('q=request.args["q"]\ndb.execute(text(q))'))
            with patch('shutil.which', return_value=None):
                facts=recon.build_facts(root,'test')
                self.assertTrue(facts['coverage']['execution_complete'])
                self.assertEqual(len(facts['surface']['sink_occurrences']),1)
                path.write_text('db.execute(q)\ninvalid python [')
                stdout,stderr=io.StringIO(),io.StringIO()
                with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
                    status=cli.main(['run',str(root),'--out',str(output),'--format','json','--require-complete'])
                self.assertEqual(status,3)
                envelope=json.loads(stdout.getvalue())
                self.assertFalse(envelope['coverage']['execution_complete'])
                saved=json.loads((output/'runs'/envelope['generated']/'FACTS.json').read_text())
                self.assertTrue(saved['surface']['sql_flow']['errors'])

    def test_global_budgets_preserve_sibling_results_and_source_trace_is_bounded(self):
        source = self.handler('q=request.args["q"]\ndb.execute(text(q))')
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            for index in range(5):
                (root/f'app{index}.py').write_text(source)
            with patch.object(sql_flow, 'MAX_TOTAL_NODES', 100):
                out=SurfaceExtractor().extract(RepoContext(root), {})
            self.assertTrue(out['error'])
            self.assertTrue(out['sink_occurrences'])
            self.assertLessEqual(out['sql_flow']['nodes'], 101)
            self.assertEqual(out['sql_flow']['candidate_files'], 5)
        for constant in ('MAX_TOTAL_STEPS', 'MAX_TOTAL_SOURCE_BYTES', 'MAX_SOURCE_BYTES', 'MAX_BINDINGS'):
            with self.subTest(constant=constant), patch.object(sql_flow, constant, 1):
                self.assertTrue(self.scan(source)['error'])
        body='q=request.args["q"]\n' + ''.join(f'if flag{index}:\n q=request.args["q{index}"]\n' for index in range(30)) + 'db.execute(q)'
        rows=self.rows(self.handler(body))
        self.assertEqual(len(rows),1)
        self.assertLessEqual(len(rows[0]['source_lines']),8)
        self.assertLessEqual(len(rows[0]['assignment_lines']),8)

    def test_large_ast_and_nested_branch_budget_finish_in_subprocess(self):
        script = '''from websec_validator.extractors.sql_flow import analyze
large='db.execute(q)\\n' + 'x=1\\n'*15000
out=analyze(large)
assert out['errors']
nested='q=request.args["q"]\\n' + ''.join(' '*i+'if flag:\\n' for i in range(80)) + ' '*80+'db.execute(q)\\n'
out=analyze(nested)
assert out['errors']
'''
        script='import sys\nsys.path.insert(0, '+repr(str(Path(sql_flow.__file__).resolve().parents[2]))+')\n'+script
        result=subprocess.run([sys.executable, '-I', '-c', script], capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode,0,result.stderr)


if __name__ == '__main__':
    unittest.main()

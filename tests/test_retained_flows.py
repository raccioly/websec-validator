"""Retained request flows: actual sink argument, local scope, safe overwrite and bound values."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.surface import SurfaceExtractor


class RetainedFlowTests(unittest.TestCase):
    def scan(self, source, suffix='.js'):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ('app' + suffix)).write_text(source)
            return SurfaceExtractor().extract(RepoContext(root), {'stack': {'datastores': ['postgres']}})

    def rows(self, source, kind, suffix='.js'):
        return [row for row in self.scan(source, suffix)['sink_occurrences'] if row['sink_class'] == kind]

    def test_import_bound_needle_method_and_aliases(self):
        for import_ in ('import client from "needle";', 'const client=require("needle");'):
            source = import_ + 'app.get("/x",(req,res)=>{client.get(req.query.url);});'
            self.assertEqual(len(self.rows(source, 'ssrf')), 1)
        for source in ('const client={get:x=>x};client.get(req.query.url);',
                       'import client from "needle";client.get("https://fixed.example/");',
                       'import client from "needle";function handler(client,req){client.get(req.query.url);}',
                       'import client from "needle";client=local;client.get(req.query.url);'):
            self.assertEqual(self.rows(source, 'ssrf'), [], source)

    def test_assigned_js_sql_and_command_reach_their_actual_argument(self):
        for source, kind in (('function handler(req){const name=req.query.name;const q="SELECT "+name;db.query(q);}', 'sql-injection'),
                             ('function handler(req){const part=req.body.command;const command="echo "+part;child_process.exec(command);}', 'command-injection')):
            rows = self.rows(source, kind)
            self.assertEqual(len(rows), 1)
            self.assertTrue(rows[0]['source_lines'])
            self.assertTrue(rows[0]['assignment_lines'])

    def test_js_literal_overwrites_bound_parameters_and_siblings(self):
        for source in ('function handler(req){let q=req.query.q;q="SELECT 1";db.query(q);}',
                       'function handler(req){const name=req.query.name;const q="SELECT * WHERE name=?";db.query(q,[name]);}',
                       'function handler(req){const q=req.query.q;logger.info(q);}function other(){const q="SELECT 1";db.query(q);}',
                       'function handler(req){const message="req.query.q";db.query(message);}'):
            self.assertEqual(self.rows(source, 'sql-injection'), [], source)
        self.assertEqual(self.rows('function handler(req){const cmd=req.body.cmd;child_process.spawn("echo",[cmd],{shell:false});}', 'command-injection'), [])

    def test_branch_overwrite_cannot_erase_request_may_flow(self):
        for source in ('function handler(req){let q=req.query.q;if(flag){q="SELECT 1";}db.query(q);}',
                       'function handler(req){let q=req.query.q;if(flag) q="SELECT 1";db.query(q);}',
                       'function handler(req){let q="SELECT ";q+=req.query.q;db.query(q);}'):
            self.assertEqual(len(self.rows(source, 'sql-injection')), 1, source)

    def test_assigned_python_command_and_safe_vector(self):
        for body in ('cmd="echo "+request.args["cmd"]\nos.system(cmd)',
                     'cmd=request.args["cmd"]\nsubprocess.run(cmd,shell=True)',
                     'cmd=request.args["cmd"]\nif flag:\n cmd="fixed"\nos.system(cmd)'):
            source = 'import os, subprocess\ndef handler(request):\n' + ''.join(' '+line+'\n' for line in body.splitlines())
            self.assertEqual(len(self.rows(source, 'command-injection', '.py')), 1, body)
        for body in ('cmd=request.args["cmd"]\ncmd="echo fixed"\nos.system(cmd)',
                     'argv=["echo",request.args["cmd"]]\nsubprocess.run(argv,shell=False)',
                     'argv=["echo",request.args["cmd"]]\nsubprocess.run(argv)'):
            source = 'import os, subprocess\ndef handler(request):\n' + ''.join(' '+line+'\n' for line in body.splitlines())
            self.assertEqual(self.rows(source, 'command-injection', '.py'), [], body)

    def test_assignment_flow_limit_is_disclosed_not_success(self):
        from websec_validator.extractors import assigned_flow
        with patch.object(assigned_flow, 'MAX_EVENTS', 1):
            result = self.scan('function handler(req){const a=req.query.q;const b=a;db.query(b);}')
        self.assertTrue(result['error'])
        self.assertTrue(result['assigned_flow']['errors'])

    def test_unknown_shell_options_and_mutated_runner_cannot_credit_vector(self):
        for body in ('argv=["echo",request.args["cmd"]]\nsubprocess.run(argv,**options)',
                     'argv=["echo",request.args["cmd"]]\nsubprocess.run=lambda a:os.system(a[1])\nsubprocess.run(argv)',
                     'argv=["echo",request.args["cmd"]]\nsetattr(subprocess,"run",custom)\nsubprocess.run(argv)'):
            source = 'import os, subprocess\ndef handler(request):\n' + ''.join(' '+line+'\n' for line in body.splitlines())
            self.assertEqual(len(self.rows(source, 'command-injection', '.py')), 1, body)

    def test_vector_can_still_execute_a_shell_or_request_selected_program(self):
        for argv in ('[request.args["exe"]]', '["sh","-c",request.args["cmd"]]', '["python","-c",request.args["code"]]'):
            source = 'import subprocess\ndef handler(request):\n argv=' + argv + '\n subprocess.run(argv,shell=False)\n'
            self.assertEqual(len(self.rows(source, 'command-injection', '.py')), 1, argv)

    def test_distinct_repeated_sites_and_outer_call_classification(self):
        source = 'function handler(req){const q=req.query.q;db.query(q);db.query(q);}'
        rows = self.rows(source, 'sql-injection')
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({row['semantic_id'] for row in rows}), 2)
        source = 'function handler(req){const c=req.body.cmd;child_process.exec(c+db.query("SELECT 1"));}'
        self.assertEqual(self.rows(source, 'sql-injection'), [])
        self.assertEqual(len(self.rows(source, 'command-injection')), 1)

    def test_escaped_template_and_computed_client_mutation(self):
        self.assertEqual(self.rows(r'function handler(req){const q=`literal \${req.query.q}`;db.query(q);}', 'sql-injection'), [])
        self.assertEqual(self.rows('import client from "needle";client["get"]=x=>x;client.get(req.query.url);', 'ssrf'), [])

    def test_actual_cli_persists_assigned_sink_and_imported_client_leads(self):
        import json
        import os
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as td:
            owner = Path(td)
            target = owner / 'target'
            target.mkdir()
            (target / 'app.js').write_text('import client from "needle";app.post("/x",(req,res)=>{'
                'const q="SELECT "+req.query.name;db.query(q);'
                'const cmd=req.body.cmd;child_process.exec(cmd);client.get(req.query.url);});')
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'),
                       PATH=str(owner / 'no-tools'), WEBSEC_CALIBRATION_HOME=str(owner / 'calibration'),
                       WEBSEC_UPDATE_HOME=str(owner / 'release-metadata'))
            out = owner / 'out'
            result = subprocess.run([sys.executable, '-m', 'websec_validator.cli', 'run', str(target),
                '--out', str(out), '--format', 'json', '--fail-on', 'medium'], cwd=owner, env=env,
                capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 1, result.stderr)
            envelope = json.loads(result.stdout)
            ledger = json.loads((out / 'runs' / envelope['generated'] / 'findings-ledger.json').read_text())
            self.assertTrue({'sqli', 'command-injection', 'ssrf'} <= {row['attack_class'] for row in ledger['findings']})


if __name__ == '__main__':
    unittest.main()

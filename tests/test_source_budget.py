"""Raw source accounting covers safe aliases and a bounded per-context cache."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from websec_validator import cli, coverage, repairs, proof
from websec_validator.extractors import base


class SourceBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()

    def write(self,name,content=b'123456'):
        path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(content);return path

    def test_every_alias_is_hashed_in_both_orders_including_empty_and_raw_bytes(self):
        for content in (b'',b'print(1)\n',b'\xffraw\xfe'):
            real=self.write('real.py',content);alias=self.root/'alias.py'
            if not alias.is_symlink(): alias.symlink_to('real.py')
            for paths in ((real,alias),(alias,real)):
                ctx=base.RepoContext(self.root)
                with patch.object(ctx,'_open_file',wraps=ctx._open_file) as opened:
                    for path in paths: ctx.text(path)
                self.assertEqual(opened.call_count,1)
                self.assertEqual(ctx.input_hashes,{name:hashlib.sha256(content).hexdigest() for name in ('real.py','alias.py')})
                self.assertEqual(ctx.cached_source_bytes,len(content))
                self.assertEqual(coverage.from_context(ctx,{})['files']['read'],2)

    def test_excluded_alias_or_target_never_enters_hash_inventory(self):
        real=self.write('real.py');alias=self.root/'alias.py';alias.symlink_to('real.py')
        ctx=base.RepoContext(self.root,excludes=['alias.py'])
        ctx.text(alias);ctx.text(real)
        self.assertEqual(set(ctx.input_hashes),{'real.py'})
        ctx=base.RepoContext(self.root,excludes=['real.py'])
        with patch.object(ctx,'_open_file',side_effect=AssertionError('excluded read')):
            self.assertEqual(ctx.text(alias),'')
        self.assertEqual(ctx.input_hashes,{})

    def test_cached_failures_are_visible_for_each_alias_and_never_hashed(self):
        real=self.write('real.py');alias=self.root/'alias.py';alias.symlink_to('real.py')
        for error in ('oversized','unreadable'):
            ctx=base.RepoContext(self.root)
            with patch.object(ctx,'_open_file',side_effect=PermissionError('synthetic')):
                for path in (alias,real):ctx.text(path,max_bytes=2 if error=='oversized' else 10)
            self.assertEqual(set(getattr(ctx,error)),{'real.py','alias.py'})
            self.assertEqual(ctx.input_hashes,{})
            self.assertEqual(ctx.cached_source_bytes,0)

    def test_budget_charges_cache_entries_once_and_stops_before_opening_next_file(self):
        first=self.write('first.py');second=self.write('second.py');alias=self.root/'alias.py';alias.symlink_to('first.py')
        with patch.object(base,'MAX_SOURCE_BYTES',8):ctx=base.RepoContext(self.root)
        self.assertEqual(ctx.text(first),'123456');self.assertEqual(ctx.text(alias),'123456')
        with patch.object(ctx,'_open_file',side_effect=AssertionError('budget-exhausted read')):
            self.assertEqual(ctx.text(second),'')
        self.assertEqual(ctx.cached_source_bytes,6)
        self.assertEqual(ctx.byte_budget_exceeded,['second.py'])
        self.assertEqual(set(ctx.input_hashes),{'first.py','alias.py'})
        cov=coverage.from_context(ctx,{})
        self.assertFalse(cov['execution_complete']);self.assertEqual(cov['files']['source_bytes'],6)
        self.assertEqual(cov['files']['read_policy']['max_cached_raw_bytes_per_context'],8)
        self.assertIn('Narrow the target',coverage.render_md({'coverage':cov}))

    def test_custom_caps_charge_separate_entries_and_empty_files_fit_full_budget(self):
        path=self.write('source.py',b'abcd');empty=self.write('empty.py',b'')
        with patch.object(base,'MAX_SOURCE_BYTES',8):ctx=base.RepoContext(self.root)
        self.assertEqual(ctx.text(path,max_bytes=3),'');self.assertEqual(ctx.cached_source_bytes,0)
        self.assertEqual(ctx.text(path,max_bytes=4),'abcd');self.assertEqual(ctx.text(path,max_bytes=5),'abcd')
        self.assertEqual(ctx.cached_source_bytes,8)
        self.assertEqual(ctx.text(path,max_bytes=6),'');self.assertEqual(ctx.text(empty),'')
        self.assertEqual(ctx.input_hashes['empty.py'],hashlib.sha256(b'').hexdigest())
        self.assertEqual(ctx.byte_budget_exceeded,['source.py'])

    def test_growth_between_stat_and_open_cannot_exceed_remaining_budget(self):
        path=self.write('grow.py',b'ab')
        with patch.object(base,'MAX_SOURCE_BYTES',4):ctx=base.RepoContext(self.root)
        original=ctx._open_file
        def grow(resolved,expected):
            path.write_bytes(b'abcdef');return original(resolved,expected)
        with patch.object(ctx,'_open_file',side_effect=grow):self.assertEqual(ctx.text(path),'')
        self.assertEqual(ctx.byte_budget_exceeded,['grow.py']);self.assertEqual(ctx.cached_source_bytes,0)
        self.assertEqual(ctx.input_hashes,{})

    def test_auxiliary_coverage_records_separate_bounded_context_and_failures(self):
        first=self.write('first.py');second=self.write('second.py')
        with patch.object(base,'MAX_SOURCE_BYTES',6):ctx=base.RepoContext(self.root)
        ctx.text(first);ctx.text(second)
        cov={'execution_complete':True,'inputs':{},'files':{},'gaps':[]}
        coverage.include_reads(cov,ctx,input_prefix='graph:')
        self.assertFalse(cov['execution_complete'])
        self.assertEqual(cov['files']['byte_budget_exceeded'],['graph:second.py'])
        self.assertEqual(cov['files']['auxiliary_source_bytes'],{'graph:':6})
        self.assertEqual(set(cov['inputs']),{'graph:first.py'})

    def test_budget_policy_changes_scope_but_consumption_does_not(self):
        self.write('first.py');ctx=base.RepoContext(self.root);list(ctx.iter_code())
        cov=coverage.from_context(ctx,{});original=repairs.scope_digest(cov)
        cov['files']['source_bytes']+=1
        self.assertEqual(original,repairs.scope_digest(cov))
        cov['files']['read_policy']['max_cached_raw_bytes_per_context']-=1
        self.assertNotEqual(original,repairs.scope_digest(cov))
        self.assertEqual(coverage.execution_errors({'execution_complete':True,'files':{}}),[])
        for fields in ({'byte_budget_exceeded':['x.py']}, {'source_bytes':False},
                       {'read_policy':[]}, {'read_policy':{'max_cached_raw_bytes_per_context':4},'source_bytes':5}):
            self.assertTrue(coverage.execution_errors({'execution_complete':True,'files':fields}))

    def test_exhaustion_preserves_previous_latest_and_strict_gate_fails(self):
        repo=self.root/'repo';repo.mkdir();(repo/'app.py').write_text('print("synthetic")\n');out=self.root/'out'
        def invoke():
            with patch('shutil.which',return_value=None),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                return cli.main(['run',str(repo),'--out',str(out),'--require-complete'])
        self.assertEqual(invoke(),0);latest=(out/'latest').resolve()
        with patch.object(base,'MAX_SOURCE_BYTES',1):self.assertEqual(invoke(),3)
        self.assertEqual((out/'latest').resolve(),latest)
        attempt=max((out/'runs').iterdir(),key=lambda p:p.stat().st_mtime_ns)
        cov=json.loads((attempt/'coverage.json').read_text())
        self.assertEqual(cov['files']['byte_budget_exceeded'],['app.py'])
        self.assertEqual(cov['inputs'],{})

    def test_private_directory_case_aliases_are_rejected_before_open(self):
        # Synthetic empty markers only; private file content is never read.
        private=self.root/'.local';private.mkdir();(private/'synthetic.py').touch()
        alias=self.root/'public.py';alias.symlink_to('.LOCAL/synthetic.py')
        ctx=base.RepoContext(self.root,walk=False)
        with patch.object(ctx,'_open_file',side_effect=AssertionError('private open forbidden')):
            for path in (self.root/'.LOCAL'/'synthetic.py',self.root/'.LoCaL'/'synthetic.py',alias):
                self.assertEqual(ctx.text(path),'')
        self.assertEqual(ctx.input_hashes,{})
        self.assertIsNone(ctx._allowed(self.root/'.LOCAL'/'synthetic.py'))
        if (self.root/'.LOCAL').exists():self.assertIsNone(ctx._allowed(alias))

    def test_walk_prunes_mixed_case_private_directories_before_inventory(self):
        for name in ('.LOCAL','.LoCaL'):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);private=root/name;private.mkdir();(private/'synthetic.py').touch()
                with patch.object(base.RepoContext,'_open_file',side_effect=AssertionError('private read forbidden')):
                    ctx=base.RepoContext(root)
                    self.assertEqual(list(ctx.iter_code()),[])
                self.assertEqual(ctx._files,[]);self.assertEqual(ctx.files_seen,0)
                self.assertEqual(ctx.skip_counts.get('private'),1)

    def test_proof_rejects_private_tracked_alias_before_blob_read(self):
        for name in ('.local','.LOCAL','.LoCaL'):
            listing='100644 blob '+('a'*40)+'\t'+name+'/synthetic.py\0'
            with patch.object(proof,'_git',return_value=listing), patch.object(proof.os,'open',side_effect=AssertionError('private blob read forbidden')):
                self.assertFalse(proof._clean_tree(self.root))
        private=self.root/'.LOCAL';private.mkdir();(private/'synthetic.py').touch()
        # An untracked private directory is neither read nor inventoried.
        with patch.object(proof,'_git',return_value=''), patch.object(proof.os,'open',side_effect=AssertionError('private read forbidden')):
            self.assertTrue(proof._clean_tree(self.root))

    def test_detector_revision_prunes_mixed_case_private_source_without_reading(self):
        private=self.root/'.LOCAL';private.mkdir();(private/'synthetic.py').touch()
        with patch.object(coverage,'__file__',str(self.root/'coverage.py')), patch.object(Path,'read_bytes',side_effect=AssertionError('private source read forbidden')):
            self.assertEqual(coverage.detector_revision(),'sha256:'+hashlib.sha256().hexdigest())


if __name__=='__main__':unittest.main()

"""Probe accepts an explicitly registered replacement, never arbitrary data."""
import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('operational_probe_tests',Path(__file__).parents[1]/'remote/probe.py')
probe=importlib.util.module_from_spec(spec)
with patch.dict(sys.modules,{'pwd':N()} if sys.platform=='win32' else {}): spec.loader.exec_module(probe)


class OperationalProbe(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.account=Path(temp.name)/'replacement'; self.target=self.account/'streams-aio'
        self.runner=self.account/'.local/share/streams-aio-recovery'
        self.runner.mkdir(parents=True); self.target.mkdir()
        self.checkpoint=self.runner/'state.json'
        self.data=dict(schema=1,runner_version='0.2.0',target=str(self.target),machine_id='new-machine',
            tag='dr-20261010T043000Z',public_commit='a'*40,tooling_commit='a'*40,in_progress=None,
            completed=sorted(probe.FIRST_BOOT_STAGES),application_start_attempted=False)
        self.data['operational_deployment']=dict(schema=1,routing_mode='parallel_test',
            domain_target_address='192.0.2.42',uid=1000,gid=1000,user='replacement',home=str(self.account),
            target=str(self.target),machine_id='new-machine',tag=self.data['tag'],
            public_commit='a'*40,tooling_commit='a'*40)
        self.original_stat=Path.stat; self.original_read=Path.read_text
        def metadata(path,*args,**kw):
            if path==self.checkpoint: return N(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1)
            return self.original_stat(path,*args,**kw)
        def read(path,*args,**kw):
            if path==Path('/etc/machine-id'): return 'new-machine'
            return self.original_read(path,*args,**kw)
        patches=[patch.object(Path,'stat',metadata),patch.object(Path,'read_text',read),
                 patch.object(probe.pwd,'getpwuid',return_value=N(pw_gid=1000,pw_name='replacement',
                    pw_dir=str(self.account)),create=True)]
        for item in patches: item.start(); self.addCleanup(item.stop)
        self.save()

    def save(self): self.checkpoint.write_text(json.dumps(self.data))

    def test_dynamic_verified_release_and_commit_are_bound_to_actual_replacement(self):
        probe.operational_checkpoint(self.target,self.runner,self.data)
        self.data['operational_deployment']['public_commit']='b'*40; self.save()
        with self.assertRaisesRegex(ValueError,'OPERATIONAL_DEPLOYMENT_REFUSED'):
            probe.operational_checkpoint(self.target,self.runner,self.data)

    def test_stale_in_progress_state_needs_checked_runner_reconciliation(self):
        self.data['in_progress']='NPM'; self.save()
        with self.assertRaisesRegex(ValueError,'RECOVERY_OPERATION_INCOMPLETE'):
            probe.operational_checkpoint(self.target,self.runner,self.data)

    def test_target_identity_record_unknown_fields_and_other_machine_are_refused(self):
        record=self.data['operational_deployment']
        for field,value in (('user','original'),('machine_id','original-machine'),('unexpected','secret')):
            old=record.get(field); record[field]=value; self.save()
            with self.subTest(field=field), self.assertRaisesRegex(ValueError,'OPERATIONAL_DEPLOYMENT_REFUSED'):
                probe.operational_checkpoint(self.target,self.runner,self.data)
            if old is None: record.pop(field)
            else: record[field]=old

    def test_partial_preparation_accepts_only_no_containers_or_nonempty_volumes(self):
        calls=[]
        def run(args,**kw):
            calls.append(args)
            raw=(json.dumps({'name':'streams-aio','services':{'postgres':{}},'volumes':{}}).encode()
                 if 'config' in args else b'')
            return N(stdout=raw,returncode=0)
        with patch.object(probe.subprocess,'run',run):
            probe.checked_stack_runtime(self.target,self.runner,self.data)
            self.data['completed'].remove('EMPTY_STATE'); self.save()
            with self.assertRaisesRegex(ValueError,'FRESH_DOCKER_HOST_REQUIRED'):
                probe.checked_stack_runtime(self.target,self.runner,self.data)
        self.assertFalse(any('up' in args or 'rm' in args or 'down' in args for args in calls))

    def test_new_summary_contains_only_flags_and_old_summary_stays_exact(self):
        self.data.update(private_canary='never show this',aio_mode='snapshot',completed=['AIO'],
            public_domain_recovery='VERIFIED',public_controllers_enabled=False,
            runtime_profile={'id':'PG18_DNS_UID_AIO_OAUTH_PGBOUNCER_GROUP_PUBLIC_DOMAINS_V3'})
        summary=probe.checkpoint_summary(self.data)
        self.assertTrue(summary['aio_snapshot_completed']); self.assertTrue(summary['public_domains_verified'])
        self.assertFalse(summary['controllers_enabled']); self.assertNotIn('canary',json.dumps(summary))
        self.assertTrue(all(type(value) is bool for value in summary.values()))
        self.assertEqual(len(probe.checkpoint_summary({})),6)


if __name__=='__main__': unittest.main()

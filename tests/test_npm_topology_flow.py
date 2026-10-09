"""Native encrypted-payload contract -> real SQLite relocation -> safe resume."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from recovery_gui import backend

ROOT=Path(__file__).resolve().parents[1]
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module
remote=load(ROOT/'remote/recover.py','topology_flow_recover')
native_fixture=load(ROOT/'tests/test_aio_snapshot.py','topology_native_fixture')
npm_fixture=load(ROOT/'tests/test_npm_topology.py','topology_npm_fixture')


@unittest.skipUnless(os.name == 'nt' or os.geteuid() == 0,
                     'Real native/NPM ownership integration runs in the dedicated CI ownership step')
class NativeNPMFlow(unittest.TestCase):
    def setUp(self):
        self.native=native_fixture.NativeAIO('runTest');self.native.setUp()
        self.addCleanup(self.native.doCleanups)
        self.npm=npm_fixture.NPMTopology('runTest');self.npm.setUp()
        self.addCleanup(self.npm.doCleanups)
        self.value=copy.deepcopy(self.npm.value)
        self.value['stack_commit']=native_fixture.COMMIT
        self.root=self.native.target
        target=self.root/npm_fixture.topology.DATABASE
        target.parent.mkdir(parents=True)
        shutil.copyfile(self.npm.db,target);target.chmod(0o600)
        if os.name!='nt' and os.geteuid()==0:os.chown(target,1000,1000)
        self.home=self.native.base/'recovery';self.home.mkdir(mode=0o700)
        self.job=remote.Recovery.__new__(remote.Recovery)
        self.job.root,self.job.home,self.job.tooling=self.root,self.home,ROOT/'remote'
        self.job.state_path=self.home/'state.json'
        self.job.config={'operational_profile':True,'npm_upstream_targets':dict(self.npm.targets)}
        self.job.state={'public_commit':native_fixture.COMMIT,'tag':'dr-'+native_fixture.RUN,
            'aio_recovery':'NATIVE_SNAPSHOT_RESTORED','npm_upstream_targets':dict(self.npm.targets)}
        self.calls=[]
    def restore(self,deployment=True):
        self.native.capture(**({'deployment':self.value} if deployment else {}))
        evidence=native_fixture.aio.restore_capsule(self.native.archive,self.root,
            run_id=native_fixture.RUN,source_commit=native_fixture.COMMIT,
            model=self.native.model_for(self.root),run=self.native.empty,uid=1000,gid=1000)
        self.job.state['aio_snapshot']=evidence
        return evidence
    def command(self,args,code,**kwargs):
        self.calls.append(list(args))
        if args[:2]==['docker','compose']:return json.dumps(self.native.model_for(self.root)).encode()
        self.assertEqual(args,['docker','ps','-aq'])
        return b''
    def prepare(self):
        with patch.object(remote,'command',side_effect=self.command):self.job.prepare_topology()
    def test_real_native_capsule_and_application_database_prepare_remap_offline(self):
        evidence=self.restore();self.prepare()
        saved=npm_fixture.topology.verify(self.root,self.job.state['npm_topology'],stack_commit=native_fixture.COMMIT)
        self.assertEqual(saved['targets'],self.npm.targets)
        self.assertEqual(saved['after'][0]['routing']['forward_host'],'192.0.2.29')
        self.assertEqual(saved['after'][1]['routing']['forward_host'],'192.0.2.30')
        self.assertEqual(saved['after'][2],saved['before'][2])
        self.assertTrue(native_fixture.aio.verify_restored(self.root,evidence,self.native.model_for(self.root),
            before_start=True,uid=1000,gid=1000))
        self.assertNotIn('192.0.2.',json.dumps(self.job.state['npm_topology']))
        self.assertFalse(any('up' in args or 'rm' in args for args in self.calls))
    def test_capsule_without_topology_cannot_claim_operational_restore(self):
        self.restore(deployment=False)
        with self.assertRaisesRegex(remote.Refused,'^NPM_TOPOLOGY_BACKUP_REQUIRED$'):self.prepare()
        self.assertEqual(self.calls,[])
        self.assertNotIn('npm_topology',self.job.state)
    def test_completed_sql_journal_reconciles_when_checkpoint_save_was_interrupted(self):
        self.restore();original=copy.deepcopy(self.job.state)
        with patch.object(remote,'save',side_effect=OSError('synthetic checkpoint interruption')):
            with self.assertRaises(OSError):self.prepare()
        expected=copy.deepcopy(self.job.state['npm_topology'])
        self.job.state=original
        self.prepare()
        self.assertEqual(self.job.state['npm_topology'],expected)
    def test_started_owned_checkpoint_is_verified_without_trying_offline_mutation(self):
        self.restore();self.prepare()
        expected=copy.deepcopy(self.job.state['npm_topology'])
        self.job.state['application_start_attempted']=True
        self.calls.clear();self.prepare()
        self.assertEqual(self.job.state['npm_topology'],expected)
        self.assertFalse(any(args[:3]==['docker','ps','-aq'] for args in self.calls))
    def test_started_without_relocation_evidence_refuses_even_with_valid_capsule(self):
        self.restore();self.job.state['application_start_attempted']=True
        with self.assertRaisesRegex(remote.Refused,'^NPM_TOPOLOGY_EVIDENCE_REQUIRED$'):self.prepare()
        self.assertFalse((self.root/npm_fixture.topology.JOURNAL).exists())
    def test_resume_cannot_replace_pinned_upstream_destinations(self):
        self.restore();self.prepare()
        self.job.config['npm_upstream_targets']['infisical']='192.0.2.99'
        with self.assertRaisesRegex(remote.Refused,'^NPM_TOPOLOGY_TARGET_INVALID$'):self.prepare()
    def test_runtime_started_before_mapping_never_gets_an_in_place_sql_change(self):
        self.restore();database=self.root/npm_fixture.topology.DATABASE
        original=database.read_bytes()
        def mounted(args,code,**kwargs):
            if args==['docker','ps','-aq']:return b'a'
            if args[:2]==['docker','inspect']:
                return json.dumps([{'Mounts':[{'Source':str(database.parent)}]}]).encode()
            return self.command(args,code,**kwargs)
        with patch.object(remote,'command',side_effect=mounted),self.assertRaisesRegex(
                remote.Refused,'^NPM_TOPOLOGY_ALREADY_MOUNTED$'):
            self.job.prepare_topology()
        self.assertEqual(original,database.read_bytes())


class AuthenticatedUpstreamTargets(unittest.TestCase):
    def client(self,peer):
        from types import SimpleNamespace as N
        return N(client=N(get_transport=lambda:N(getpeername=lambda:peer)))
    def test_target_pair_comes_from_authenticated_sockets_not_dns_or_public_domain(self):
        pair=backend.authenticated_upstream_targets(self.client(('192.0.2.29',22)),self.client(('192.0.2.30',22)))
        self.assertEqual(pair,{'stack':'192.0.2.29','infisical':'192.0.2.30'})
        self.assertEqual(remote.upstream_targets(pair),pair)
    def test_nonconcrete_shared_or_loopback_targets_are_refused(self):
        for first,second in (('unknown','192.0.2.30'),('127.0.0.1','192.0.2.30'),
                ('192.0.2.29','192.0.2.29'),('0.0.0.0','192.0.2.30')):
            with self.subTest(first=first,second=second),self.assertRaisesRegex(
                    backend.Failure,'^NPM_TOPOLOGY_TARGET_INVALID$'):
                backend.authenticated_upstream_targets(self.client((first,22)),self.client((second,22)))


if __name__=='__main__':unittest.main()

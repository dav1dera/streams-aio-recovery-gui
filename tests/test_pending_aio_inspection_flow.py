"""Real capsule/journal -> standalone probe -> trusted policy -> AIO retry.

Only Linux account metadata and Docker transport are adapted on Windows. The
encrypted-release bookkeeping, native SQLite bytes, journal validation and
runner phase transitions are the real implementations.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(path, name):
    spec = importlib.util.spec_from_file_location(name,path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


flow_fixture = module(ROOT/'tests/test_snapshot_recovery_flow.py','pending_native_flow_fixture')
remote = flow_fixture.remote
policy = module(ROOT/'remote/runtime_profile.py','pending_native_runtime_policy')
with patch.dict(sys.modules,{'pwd':N()} if os.name == 'nt' else {}):
    probe = module(ROOT/'remote/probe.py','pending_native_probe')


class PendingNativeFlow(unittest.TestCase):
    include_deployment = False
    interrupted_link = 2

    def setUp(self):
        unprivileged_posix = os.name != 'nt' and os.geteuid() != 0
        self.flow = flow_fixture.SnapshotRecoveryFlow('runTest')
        self.flow.setUp()
        self.addCleanup(self.flow.doCleanups)
        if self.include_deployment:
            self.flow.native.archive.unlink()
            self.flow.native.capture(deployment=flow_fixture.native_fixture.deployment_fixture())
        self.account = self.flow.base/'replacement'
        self.root = self.account/'streams-aio'
        self.home = self.account/'.local/share/streams-aio-recovery'
        self.home.parent.mkdir(parents=True)
        self.flow.root.rmdir()
        self.root.mkdir()
        shutil.move(self.flow.home,self.home)
        self.flow.root = self.flow.native.target = self.root
        self.flow.home = self.home
        self.flow.model = self.flow.native.model_for(self.root)
        self.flow.model.update(name='streams-aio',volumes={})
        job = self.job = self.flow.job
        job.root, job.home = self.root,self.home
        job.manager = self.home/'manager'
        job.private, job.bundle = self.home/'private',self.home/'ciphertext'
        job.state_path = self.home/'state.json'
        job.state['target'] = str(self.root)
        self.flow.prepare_native()
        job.state.update(schema=1,runner_version='0.2.0',tooling_commit=flow_fixture.COMMIT,
            completed=sorted(probe.FIRST_BOOT_STAGES | {'NPM'}),input_aio_mode='snapshot',
            application_start_attempted=False,
            runtime_profile={'id':policy.OPERATIONAL_PROFILE,'origin':'FIRST_BOOT'},
            npm_upstream_targets={'stack':'192.0.2.29','infisical':'192.0.2.30'})
        job.config.update(operational_profile=True,routing_mode='parallel_test',domain_target_address='192.0.2.42',
                          npm_upstream_targets=dict(job.state['npm_upstream_targets']))
        self.user = N(pw_name='replacement',pw_gid=1000,pw_dir=str(self.account))
        with patch.dict(sys.modules,{'pwd':N(getpwuid=lambda uid:self.user)}):
            job.state['operational_deployment'] = policy.deployment_record(
                self.root,job.state,'parallel_test','192.0.2.42')
        original_stat, original_read = Path.stat,Path.read_text
        def metadata(path,*args,**kwargs):
            info = original_stat(path,*args,**kwargs)
            if os.name != 'nt' and not unprivileged_posix:
                return info
            values = {name:getattr(info,name) for name in dir(info) if name.startswith('st_')}
            if path == self.home:
                values.update(st_mode=stat.S_IFDIR|0o700,st_uid=1000,st_gid=1000)
            elif path.is_relative_to(self.home) or path.name.startswith('aio-snapshot-') \
                    or path.name in ('deployment.json','npm-deployment.json'):
                if stat.S_ISREG(info.st_mode):
                    values.update(st_mode=stat.S_IFREG|0o600,st_uid=0,st_gid=0)
            elif path.name == 'db.sqlite':
                values.update(st_mode=stat.S_IFREG|0o600,st_uid=1000,st_gid=1000)
            return N(**values)
        def read(path,*args,**kwargs):
            if path == Path('/etc/machine-id'):
                return 'snapshot-test-machine'
            if path == Path('/etc/os-release'):
                return 'ID=ubuntu\nVERSION_ID="26.04"\nVERSION_CODENAME=resolute\n'
            return original_read(path,*args,**kwargs)
        self.commands = []
        self.docker_containers = b''
        self.docker_volumes = []
        def docker(args,**kwargs):
            self.commands.append(list(args))
            if args[:2] == ['docker','compose']:
                raw = json.dumps(self.flow.model).encode()
            elif args[:3] == ['docker','ps','-aq']:
                raw = self.docker_containers
            elif args[:4] == ['docker','volume','ls','-q']:
                raw = '\n'.join(row['Name'] for row in self.docker_volumes).encode()
            elif args[:3] == ['docker','volume','inspect']:
                raw = json.dumps(self.docker_volumes).encode()
            else:
                self.fail('Unexpected Docker read: ' + str(args[:3]))
            return N(returncode=0,stdout=raw)
        patches = [patch.object(Path,'stat',metadata),patch.object(Path,'read_text',read),
            patch.object(probe.pwd,'getpwuid',return_value=self.user,create=True),
            patch.dict(sys.modules,{'pwd':N(getpwuid=lambda uid:self.user)}),
            patch.object(os,'geteuid',return_value=0,create=True),
            patch.object(os,'getegid',return_value=0,create=True),
            patch.object(os,'uname',return_value=N(machine='x86_64'),create=True),
            patch.object(probe.shutil,'which',return_value='docker'),
            patch.object(policy.subprocess,'run',side_effect=docker)]
        if unprivileged_posix:
            # The recovery process runs as root against UID/GID 1000. Ordinary
            # GitHub safety CI cannot chown. Adapt only ownership inside this
            # synthetic fixture; real modes, bytes, links and journals remain.
            def fixture_chown(path,uid,gid,**kwargs):
                self.assertTrue(Path(path).absolute().is_relative_to(self.flow.base))
                self.assertIn((uid,gid),((0,0),(1000,1000)))
            patches.append(patch.object(os,'chown',side_effect=fixture_chown))
        for item in patches:
            item.start();self.addCleanup(item.stop)
        if os.name != 'nt':
            os.chown(self.home,1000,1000)
        self.home.chmod(0o700)
        self.interrupt()

    def interrupt(self):
        actual_link,count = os.link,0
        class PowerLoss(BaseException):
            pass
        def interrupted(source,destination):
            nonlocal count
            count += 1
            if count == self.interrupted_link:
                raise PowerLoss()
            return actual_link(source,destination)
        with patch.object(os,'link',interrupted),self.assertRaises(PowerLoss):
            self.flow.restore()
        self.assertEqual(self.job.state['in_progress'],'AIO')

    def reloaded(self):
        args = N(target=str(self.root),state_home=str(self.home),config_data=self.job.config)
        result = remote.Recovery(args)
        result.manager,self.job = self.home/'manager',result
        result.tooling = ROOT/'remote'
        self.flow.job = result
        return result

    def test_exact_partial_journal_passes_real_probe_policy_and_runner_retry(self):
        before = self.job.state_path.read_bytes()
        journal = self.root/'.generated/aio-snapshot-pending.json'
        journal_before = journal.read_bytes()
        first = self.root/'data/aiostreams/data/db.sqlite'
        installed = first.read_bytes()
        result = probe.probe(self.root,self.home,fresh=True)
        self.assertTrue(result['existing_recovery'])
        self.assertFalse(result['recovery']['aio_completed'])
        self.assertEqual(self.job.state_path.read_bytes(),before)
        job = self.reloaded()
        self.assertIsNone(job.state['in_progress'])
        self.assertEqual(self.job.state_path.read_bytes(),before)
        probe.checked_stack_runtime(self.root,self.home,job.state)
        policy.deployment_scope(self.root,self.home,job.state)
        self.assertEqual(self.job.state_path.read_bytes(),before)
        self.assertEqual(journal.read_bytes(),journal_before)
        self.assertTrue(journal.exists())
        self.flow.restore()
        self.assertEqual(first.read_bytes(),installed)
        self.assertIn('AIO',job.state['completed'])
        self.assertEqual(job.state['aio_recovery'],'NATIVE_SNAPSHOT_RESTORED')
        self.assertFalse(journal.exists())
        self.assertTrue((self.root/'.generated/aio-snapshot-complete.json').exists())
        self.assertFalse(any('up' in args or 'down' in args or 'rm' in args for args in self.commands))

    def test_changed_journal_or_capsule_cannot_pass_detection(self):
        journal = self.root/'.generated/aio-snapshot-pending.json'
        original = journal.read_bytes()
        value = json.loads(original);value['evidence']['source_commit'] = 'd'*40
        journal.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,'RECOVERY_OPERATION_INCOMPLETE'):
            probe.probe(self.root,self.home,fresh=True)
        journal.write_bytes(original)
        (self.job.private/'aio-state.tar.gz').write_bytes(b'changed-capsule')
        with self.assertRaisesRegex(ValueError,'RECOVERY_OPERATION_INCOMPLETE'):
            probe.probe(self.root,self.home,fresh=True)

    def test_runtime_requires_current_encryption_binding_even_when_capsule_is_intact(self):
        self.reloaded()
        self.flow.model['services']['aiostreams']['environment']['SECRET_KEY'] = 'changed-private-key'
        before = self.job.state_path.read_bytes()
        with self.assertRaisesRegex(policy.Refused,'OPERATIONAL_DEPLOYMENT_REFUSED'):
            policy.deployment_scope(self.root,self.home,self.job.state)
        self.assertEqual(self.job.state_path.read_bytes(),before)
        self.assertNotIn('AIO',self.job.state['completed'])

    def test_first_start_or_foreign_container_never_uses_pending_retry(self):
        before = self.job.state_path.read_bytes()
        state = json.loads(before);state['application_start_attempted'] = True
        self.job.state_path.write_text(json.dumps(state))
        with self.assertRaisesRegex(ValueError,'RECOVERY_OPERATION_INCOMPLETE'):
            probe.probe(self.root,self.home,fresh=True)
        self.job.state_path.write_bytes(before)
        self.docker_containers = b'foreign-container'
        with self.assertRaisesRegex(ValueError,'FRESH_DOCKER_HOST_REQUIRED'):
            probe.probe(self.root,self.home,fresh=False)

    def test_reconciliation_cannot_change_any_other_checkpoint_field(self):
        self.reloaded()
        self.job.state['private_hashes']['npm.tar.gz'] = 'f'*64
        with self.assertRaisesRegex(policy.Refused,'OPERATIONAL_DEPLOYMENT_REFUSED'):
            policy.deployment_scope(self.root,self.home,self.job.state)

    def test_foreign_volume_is_refused_by_both_readonly_gates(self):
        self.docker_volumes = [{'Name':'unrelated-data','Labels':{},'Driver':'local'}]
        before = self.job.state_path.read_bytes()
        with self.assertRaisesRegex(ValueError,'FOREIGN_VOLUME_REFUSED'):
            probe.probe(self.root,self.home,fresh=False)
        self.reloaded()
        with self.assertRaisesRegex(policy.Refused,'OPERATIONAL_DEPLOYMENT_REFUSED'):
            policy.deployment_scope(self.root,self.home,self.job.state)
        self.assertEqual(self.job.state_path.read_bytes(),before)

    def test_changed_partial_database_refuses_without_removing_journal(self):
        first = self.root/'data/aiostreams/data/db.sqlite'
        first.write_bytes(b'foreign-database-bytes')
        journal = self.root/'.generated/aio-snapshot-pending.json'
        before = journal.read_bytes()
        with self.assertRaisesRegex(ValueError,'RECOVERY_OPERATION_INCOMPLETE'):
            probe.probe(self.root,self.home,fresh=False)
        self.assertEqual(journal.read_bytes(),before)
        self.assertEqual(first.read_bytes(),b'foreign-database-bytes')


class PendingDeploymentFlow(PendingNativeFlow):
    """The operational four-member capsule follows the same strict retry gates."""
    include_deployment = True
    interrupted_link = 3

    def test_installed_topology_before_marker_is_verified_then_resumed(self):
        actual_open = os.open
        marker = self.root/'.generated/aio-snapshot-complete.json'
        class PowerLoss(BaseException):
            pass
        def before_marker(path,*args,**kwargs):
            if isinstance(path,(str,os.PathLike)) and Path(path) == marker:
                raise PowerLoss()
            return actual_open(path,*args,**kwargs)
        with patch.object(os,'open',before_marker),self.assertRaises(PowerLoss):
            self.flow.restore()
        deployment = self.root/'.generated/npm-deployment.json'
        installed = deployment.read_bytes()
        before = self.job.state_path.read_bytes()
        journal = self.root/'.generated/aio-snapshot-pending.json'
        journal_before = journal.read_bytes()
        probe.probe(self.root,self.home,fresh=True)
        self.reloaded()
        policy.deployment_scope(self.root,self.home,self.job.state)
        self.assertEqual(before,self.job.state_path.read_bytes())
        self.assertEqual(journal_before,journal.read_bytes())
        deployment.write_bytes(b'foreign-route-settings')
        with self.assertRaisesRegex(ValueError,'RECOVERY_OPERATION_INCOMPLETE'):
            probe.probe(self.root,self.home,fresh=True)
        self.assertEqual(journal_before,journal.read_bytes())
        deployment.write_bytes(installed)
        self.flow.restore()
        self.assertEqual(deployment.read_bytes(),installed)
        self.assertEqual(self.job.state['aio_snapshot']['deployment']['sha256'],probe.hashlib.sha256(installed).hexdigest())
        self.assertFalse(journal.exists())


if __name__ == '__main__':
    unittest.main()

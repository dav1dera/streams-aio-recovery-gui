"""Local preparation uses actual identity/pins and grants no full-stack start."""
import copy
import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

from tests import test_runtime_profile as fixtures


ROOT = Path(__file__).resolve().parents[1]
policy = fixtures.profile
spec = importlib.util.spec_from_file_location('lab_recovery_runner', ROOT/'remote/recover.py')
recover = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recover)
spec = importlib.util.spec_from_file_location('lab_start_runner', ROOT/'remote/start.py')
start = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {'fcntl': N()} if sys.platform == 'win32' else {}):
    spec.loader.exec_module(start)


class LabScope(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(self.temp.cleanup)
        self.account_home = Path(self.temp.name)/'fresh-account'
        self.root = self.account_home/'streams-aio'
        self.home = self.account_home/'.local/share/streams-aio-recovery'
        self.root.mkdir(parents=True)
        self.home.mkdir(parents=True)
        self.account = N(pw_name='another-host', pw_gid=1000, pw_dir=str(self.account_home))
        self.machine = '7' * 32
        self.commit = 'd' * 40
        self.tag = 'dr-20261020T174233Z'
        self.state = dict(schema=1, runner_version='0.2.0', machine_id=self.machine,
            target=str(self.root), public_commit=self.commit, tooling_commit=self.commit,
            tag=self.tag, completed=sorted(policy.FIRST_BOOT_STAGES), in_progress=None)
        self.metadata = N(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o600, st_nlink=1)
        read_text = Path.read_text
        def text(path, *args, **kwargs):
            return self.machine if path == Path('/etc/machine-id') else read_text(path, *args, **kwargs)
        for item in (patch.dict(sys.modules, {'pwd': N(getpwuid=lambda uid: self.account)}),
                     patch.object(policy.os, 'geteuid', return_value=0, create=True),
                     patch.object(policy, 'regular', side_effect=self.regular),
                     patch.object(Path, 'read_text', text)):
            item.start()
            self.addCleanup(item.stop)
        self.state['lab_deployment'] = policy.lab_record(self.root, self.state)
        self.save()

    def regular(self, path):
        self.assertTrue(Path(path).is_file())
        return N(**vars(self.metadata), st_size=Path(path).stat().st_size)

    def save(self):
        (self.home/'state.json').write_text(json.dumps(self.state))

    def test_current_tag_commit_and_new_account_have_real_nonlegacy_scope(self):
        self.assertNotEqual(self.tag, policy.TAG)
        self.assertNotEqual(self.commit, policy.COMMIT)
        self.assertNotEqual(self.account.pw_name, 'test')
        self.assertEqual(policy.identity_scope(self.root, self.home, self.state), (self.root, self.home))
        self.assertEqual(policy.first_boot_scope(self.root, self.home, self.state, installing=True),
                         (self.root, self.home))
        self.assertEqual(policy.state_commit(self.root), self.commit)
        self.assertEqual(policy.source_identity(self.root), ('another-host', self.commit))
        self.assertNotIn('routing_mode', self.state['lab_deployment'])
        self.assertNotIn('domain_target_address', self.state['lab_deployment'])

    def test_changed_record_machine_paths_or_pins_are_refused(self):
        initial = copy.deepcopy(self.state)
        for field, value in (('user', 'someone-else'), ('home', '/home/elsewhere'),
                             ('target', '/home/elsewhere/streams-aio'), ('machine_id', '3' * 32),
                             ('tag', 'dr-20261019T010000Z'), ('public_commit', 'e' * 40),
                             ('tooling_commit', 'e' * 40), ('publications_disabled', False),
                             ('kind', 'production'), ('schema', True)):
            with self.subTest(field=field):
                self.state = copy.deepcopy(initial)
                self.state['lab_deployment'][field] = value
                self.save()
                with self.assertRaisesRegex(policy.Refused, '^LAB_RUNTIME_SCOPE_REFUSED$'):
                    policy.identity_scope(self.root, self.home, self.state)
        self.state = initial
        self.save()
        for root, home in ((self.root.parent/'other-stack', self.home),
                           (self.root, self.home.parent/'other-runner')):
            with self.assertRaisesRegex(policy.Refused, '^LAB_RUNTIME_SCOPE_REFUSED$'):
                policy.identity_scope(root, home, self.state)

    def test_actual_machine_account_and_root_private_checkpoint_are_required(self):
        original = copy.deepcopy(self.state)
        for change in (dict(machine_id='8' * 32), dict(tag='bad-tag'),
                       dict(public_commit='not-a-sha'), dict(tooling_commit='b' * 40)):
            self.state = dict(copy.deepcopy(original), **change)
            self.state['lab_deployment'] = policy.lab_record(self.root, self.state)
            self.save()
            with self.assertRaisesRegex(policy.Refused, '^LAB_RUNTIME_SCOPE_REFUSED$'):
                policy.lab_scope(self.root, self.home, self.state)
        self.state = original
        self.save()
        for uid, mode in ((1000, 0o600), (0, 0o640), (0, 0o644)):
            self.metadata.st_uid, self.metadata.st_mode = uid, stat.S_IFREG | mode
            with self.assertRaisesRegex(policy.Refused, '^LAB_RUNTIME_SCOPE_REFUSED$'):
                policy.lab_scope(self.root, self.home, self.state)
        self.metadata.st_uid, self.metadata.st_mode = 0, stat.S_IFREG | 0o600
        self.account.pw_gid = 1001
        with self.assertRaisesRegex(policy.Refused, '^LAB_RUNTIME_SCOPE_REFUSED$'):
            policy.lab_scope(self.root, self.home, self.state)

    def test_disk_must_match_in_memory_and_scope_cannot_mix_or_start_apps(self):
        original = copy.deepcopy(self.state)
        for change in (dict(operational_deployment={}), dict(application_start_attempted=True),
                       dict(application_recovery='STARTED_NEEDS_FUNCTIONAL_TEST'),
                       dict(timers_installed=True), dict(public_controllers_enabled=True),
                       dict(in_progress='NPM')):
            self.state = dict(copy.deepcopy(original), **change)
            self.save()
            with self.assertRaisesRegex(policy.Refused, '^LAB_RUNTIME_SCOPE_REFUSED$'):
                policy.lab_scope(self.root, self.home, self.state)
        self.state = original
        self.save()
        with self.assertRaisesRegex(policy.Refused, '^LAB_RUNTIME_SCOPE_REFUSED$'):
            policy.lab_scope(self.root, self.home, dict(self.state, extra='unsaved'))

    def test_pending_aio_requires_the_existing_closed_journal_validator(self):
        self.state['in_progress'] = 'AIO'
        self.save()
        in_memory = dict(self.state, in_progress=None)
        with patch.object(policy, 'validate_pending_native_aio') as validate:
            self.assertEqual(policy.lab_scope(self.root, self.home, in_memory), (self.root, self.home))
            validate.assert_called_once_with(self.root, self.home, self.state)
        with patch.object(policy, 'validate_pending_native_aio',
                          side_effect=policy.Refused('OPERATIONAL_DEPLOYMENT_REFUSED')):
            with self.assertRaisesRegex(policy.Refused, 'OPERATIONAL_DEPLOYMENT_REFUSED'):
                policy.lab_scope(self.root, self.home, in_memory)

    def test_missing_lab_record_keeps_legacy_guard_intact(self):
        del self.state['lab_deployment']
        self.save()
        with self.assertRaisesRegex(policy.Refused, '^RUNTIME_PROFILE_SCOPE_REFUSED$'):
            policy.identity_scope(self.root, self.home, self.state)
        self.assertIsNone(policy.state_commit(self.root))

    def test_old_registered_profile_keeps_fixed_pins_only_after_source_validation(self):
        self.state['runtime_profile'] = dict(schema=1, id=policy.COMETNET_TRIAL_PROFILE)
        self.save()
        changed = {'name': 'streams-aio', 'services': {
            'postgres': {'image': 'postgres@sha256:' + 'c' * 64},
            'dnscrypt-proxy': {'image': policy.DNS_IMAGE}}}
        before = (self.home/'state.json').read_bytes()
        with patch.object(policy, 'validate', return_value=True) as validate:
            self.assertEqual(policy.selected_runtime_images(self.root, changed)['postgres'], policy.PG_IMAGE)
            validate.assert_called_once_with(self.root, self.home, self.state)
            with self.assertRaisesRegex(policy.Refused, '^RUNTIME_PROFILE_IMAGE_CHANGED$'):
                policy.base_model(self.root, changed)
        with patch.object(policy, 'validate', side_effect=policy.Refused('RUNTIME_PROFILE_SOURCE_CHANGED')):
            with self.assertRaisesRegex(policy.Refused, '^RUNTIME_PROFILE_SOURCE_CHANGED$'):
                policy.selected_runtime_images(self.root, changed)
        self.assertEqual((self.home/'state.json').read_bytes(), before)

    def test_profile_absent_uses_current_lock_instead_of_legacy_pins(self):
        self.assertNotIn('runtime_profile', self.state)
        refs = dict(zip(policy.FIRST_BOOT_SERVICES, policy.FIRST_BOOT_IMAGES))
        refs['pgbouncer'] = 'edoburu/pgbouncer@sha256:' + 'b' * 64
        model = dict(services={name: dict(image=image, platform='linux/amd64') for name, image in refs.items()})
        (self.root/'config').mkdir()
        (self.root/'config/image-lock.json').write_text(json.dumps({name: {'image': image} for name, image in refs.items()}))
        (self.root/'config/compose.dr.yaml').write_text(json.dumps(model))
        with patch.object(policy, 'validate', side_effect=AssertionError('new prep treated as old profile')):
            self.assertEqual(policy.first_boot_images(self.root, model), tuple(refs[name] for name in policy.FIRST_BOOT_SERVICES))
        self.assertNotEqual(refs['pgbouncer'], policy.PGBOUNCER_IMAGE)

    def test_full_start_and_operational_promotion_refuse_before_any_command(self):
        self.state['preparation'] = 'PASS'
        self.save()
        # The start entry checks POSIX mode via Path.stat before reading state.
        # Model only that metadata on Windows; all checkpoint bytes are real.
        old_stat = Path.stat
        def metadata(path, *args, **kwargs):
            info = old_stat(path, *args, **kwargs)
            if path == self.home/'state.json':
                return N(st_mode=stat.S_IFREG | 0o600)
            return info
        with patch.object(Path, 'stat', metadata), patch.object(start, 'call') as command, \
             patch.object(start.importlib.util, 'spec_from_file_location') as load:
            for operational in (False, True):
                with self.assertRaisesRegex(ValueError, '^LAB_APPLICATION_START_REFUSED$'):
                    start.start(self.root, self.home, operational=operational, tls=True)
            command.assert_not_called()
            load.assert_not_called()
        run = Mock(side_effect=AssertionError('mutation attempted'))
        with self.assertRaisesRegex(policy.Refused, '^LAB_APPLICATION_START_REFUSED$'):
            policy.promote_operational(self.root, self.home, self.state, {}, run,
                                       'parallel_test', '192.0.2.1')
        run.assert_not_called()

    def recovery(self):
        runner = recover.Recovery.__new__(recover.Recovery)
        runner.root, runner.home, runner.state_path = self.root, self.home, self.home/'state.json'
        runner.state = self.state
        runner.config = dict(onboarding_lab=True, role='stack', native_agent=True,
                             aio_mode='snapshot', dr_tag=self.tag, public_commit=self.commit)
        runner.tooling = ROOT/'remote'
        runner.manager, runner.bundle, runner.private = self.home/'manager', self.home/'ciphertext', self.home/'private'
        return runner

    def test_legacy_preprofile_checkpoint_is_validated_before_lab_registration(self):
        del self.state['lab_deployment']
        self.state['completed'] = sorted(policy.FIRST_BOOT_STAGES)
        self.state['private_hashes'] = {'aio-state.tar.gz': 'a' * 64}
        self.save()
        (self.root/'.generated').mkdir()
        (self.root/'.generated/dr-render-complete.json').write_text(json.dumps(
            dict(root=str(self.root), outputs=[])))
        runner = self.recovery()
        timeline = []
        runner.auth = lambda: timeline.append('auth')
        runner.verify_seeded_envs = lambda: timeline.append('render-verified')
        def first_boot():
            self.assertIn('private-verified', timeline)
            self.assertIn('render-verified', timeline)
            self.assertNotIn('operational_deployment', self.state)
            policy.first_boot_scope(self.root, self.home, self.state, installing=True)
            timeline.append('runtime-scope-verified')
        runner.prepare_first_boot = first_boot
        runner.npm = lambda: timeline.append('npm-restore')
        runner.aio = lambda: timeline.append('aio-restore')
        def digest(path):
            timeline.append('private-verified')
            return 'a' * 64
        def command(args, *unused, **kwargs):
            self.assertFalse(set(map(str, args)) & {'up', 'start', 'run', 'push', 'restart'})
            if 'rev-parse' in args:
                return (self.commit if Path(args[2]) == self.root else 'e' * 40).encode()
            return b''
        self.state['manager_commit'] = 'e' * 40
        with patch.object(recover, 'load_module', return_value=policy), \
             patch.object(recover, 'command', side_effect=command), \
             patch.object(recover, 'event'), patch.object(recover, 'stack_preflight'), \
             patch.object(recover, 'validate_bundle', return_value=dict(schema=2, stack_commit=self.commit)), \
             patch.object(recover, 'encrypted_assets', return_value={recover.AIO_ASSET: 'aio-state.tar.gz'}), \
             patch.object(recover, 'private_file', side_effect=lambda path: path), \
             patch.object(recover, 'digest', side_effect=digest):
            runner.prepare()
        self.assertEqual(self.state['lab_deployment'], policy.lab_record(self.root, self.state))
        self.assertLess(timeline.index('private-verified'), timeline.index('runtime-scope-verified'))
        self.assertEqual(self.state['preparation'], 'PASS')
        self.assertFalse(self.state['timers_installed'])
        self.assertNotIn('npm_upstream_targets', self.state)
        self.assertNotIn('application_start_attempted', self.state)

    def test_failed_resume_validation_never_records_a_lab_intent(self):
        del self.state['lab_deployment']
        self.save()
        runner = self.recovery()
        runner.auth = lambda: None
        runner.verify_seeded_envs = Mock(side_effect=recover.Refused('PRIVATE_MATERIAL_CHANGED'))
        with patch.object(recover, 'command', return_value=b''), patch.object(recover, 'save') as save:
            with self.assertRaisesRegex(recover.Refused, '^PRIVATE_MATERIAL_CHANGED$'):
                runner.prepare()
        self.assertNotIn('lab_deployment', self.state)
        save.assert_not_called()

    def test_existing_resources_pass_selected_lab_point_before_registering_scope(self):
        del self.state['lab_deployment']
        self.save()
        runner = self.recovery()
        probe = N(checked_stack_runtime=Mock())
        runner.auth = Mock(side_effect=recover.Refused('STOP_AFTER_READONLY_GUARD'))
        with patch.object(recover, 'command', return_value=b'streams-aio_pgdata\n'), \
             patch.object(recover, 'load_module', return_value=probe), \
             patch.object(recover, 'save') as save:
            with self.assertRaisesRegex(recover.Refused, '^STOP_AFTER_READONLY_GUARD$'):
                runner.prepare()
        probe.checked_stack_runtime.assert_called_once_with(self.root, self.home, self.state,
            lab_point=(self.tag, self.commit))
        self.assertNotIn('lab_deployment', self.state)
        save.assert_not_called()

    def test_existing_nonlab_resources_keep_the_original_probe_contract(self):
        del self.state['lab_deployment']
        self.save()
        runner = self.recovery()
        del runner.config['onboarding_lab']
        probe = N(checked_stack_runtime=Mock())
        runner.auth = Mock(side_effect=recover.Refused('STOP_AFTER_READONLY_GUARD'))
        with patch.object(recover, 'command', return_value=b'owned-resource\n'), \
             patch.object(recover, 'load_module', return_value=probe):
            with self.assertRaisesRegex(recover.Refused, '^STOP_AFTER_READONLY_GUARD$'):
                runner.prepare()
        probe.checked_stack_runtime.assert_called_once_with(self.root, self.home, self.state)


class LabFirstBootSource(unittest.TestCase):
    def test_image_and_renderer_checks_use_real_lab_user_and_selected_commit(self):
        harness = fixtures.FirstBootChecks(methodName='runTest')
        harness.setUp()
        self.addCleanup(harness.doCleanups)
        root = harness.root
        home = root.parent/'.local/share/streams-aio-recovery'
        home.mkdir(parents=True)
        account = N(pw_name='new-lab-user', pw_gid=1000, pw_dir=str(root.parent))
        commit, machine = 'f' * 40, '9' * 32
        state = dict(schema=1, runner_version='0.2.0', machine_id=machine, target=str(root),
                     tag='dr-20261021T120000Z', public_commit=commit, tooling_commit=commit,
                     in_progress=None, completed=sorted(policy.FIRST_BOOT_STAGES))
        # A scoped backup has an explicit pin/platform for every service,
        # unlike the older four-image-only compatibility fixture above.
        for name, service in harness.model['services'].items():
            service.setdefault('image', ('ghcr.io/sonicx161/aiomanager' if name == 'aiomanager'
                                        else 'g0ldyy/comet') + '@sha256:' + 'c' * 64)
            service['platform'] = 'linux/amd64'
        pins = {name: {'image': row['image']} for name, row in harness.model['services'].items()}
        override = {'services': {name: dict(row, platform='linux/amd64') for name, row in pins.items()}}
        (root/'config').mkdir(exist_ok=True)
        (root/'config/image-lock.json').write_text(json.dumps(pins))
        (root/'config/compose.dr.yaml').write_text(json.dumps(override))
        old_text, old_regular = Path.read_text, policy.regular
        def text(path, *args, **kwargs):
            return machine if path == Path('/etc/machine-id') else old_text(path, *args, **kwargs)
        def regular(path):
            if Path(path) == home/'state.json':
                return N(st_uid=0, st_mode=stat.S_IFREG | 0o600)
            if Path(path) in (root/'config/image-lock.json', root/'config/compose.dr.yaml'):
                return N(st_size=Path(path).stat().st_size)
            return old_regular(path)
        commands = []
        def run(args):
            commands.append(args)
            if args[0] == 'sudo':
                return harness.renderer if 'show' in args else commit.encode()
            return harness.docker_run(args)
        with patch.dict(sys.modules, {'pwd': N(getpwuid=lambda uid: account)}), \
             patch.object(policy.os, 'geteuid', return_value=0, create=True), \
             patch.object(policy, 'regular', side_effect=regular), patch.object(Path, 'read_text', text):
            state['lab_deployment'] = policy.lab_record(root, state)
            (home/'state.json').write_text(json.dumps(state))
            policy.readonly_first_boot_checks(root, harness.model, run)
        source_checks = [args for args in commands if args[0] == 'sudo']
        self.assertTrue(source_checks)
        self.assertTrue(all(args[3] == 'new-lab-user' for args in source_checks))
        self.assertIn(commit + ':scripts/dr.py', source_checks[-1])
        self.assertFalse(any(policy.COMMIT in str(value) for args in source_checks for value in args))


if __name__ == '__main__':
    unittest.main()

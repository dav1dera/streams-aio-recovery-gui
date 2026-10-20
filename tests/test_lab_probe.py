"""Selected-point lab resume exercises the actual standalone read-only guard."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('lab_probe_contract', ROOT/'remote/probe.py')
probe = importlib.util.module_from_spec(SPEC)
with patch.dict(sys.modules, {'pwd': N()} if sys.platform == 'win32' else {}):
    SPEC.loader.exec_module(probe)

TAG, COMMIT = 'dr-20261020T023700Z', 'c'*40
MACHINE = 'synthetic-lab-machine'


class LabProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.account = self.base/'replacement'
        self.target = self.account/'streams-aio'
        self.runner = self.account/'.local/share/streams-aio-recovery'
        self.target.mkdir(parents=True)
        self.runner.mkdir(parents=True)
        self.checkpoint = self.runner/'state.json'
        self.data = dict(schema=1, runner_version='0.2.0', tag=TAG, public_commit=COMMIT,
            tooling_commit=COMMIT, target=str(self.target), machine_id=MACHINE,
            in_progress=None, completed=sorted(probe.FIRST_BOOT_STAGES))
        self.model = dict(name='streams-aio', services={'postgres': {}},
                          volumes={'pgdata': {'name': 'streams-aio_pgdata'}})
        self.volume_root = self.base/'docker-volumes'
        self.volume = self.volume_root/'streams-aio_pgdata'/'_data'
        self.volume.mkdir(parents=True)
        self.items = [dict(Name='streams-aio_pgdata', Driver='local', Options=None,
            Mountpoint=str(self.volume), Labels={'com.docker.compose.project': 'streams-aio',
                                                'com.docker.compose.volume': 'pgdata'})]
        self.ids, self.calls = [], []
        self.metadata_changes = {}
        original_stat, original_text = Path.stat, Path.read_text
        def checked_metadata(path, *args, **kwargs):
            value = original_stat(path, *args, **kwargs)
            if path == self.checkpoint:
                values = dict(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0,
                              st_nlink=1, st_size=value.st_size)
                values.update(self.metadata_changes)
                return N(**values)
            return value
        def text(path, *args, **kwargs):
            if path == Path('/etc/machine-id'):
                return MACHINE
            if path == Path('/etc/os-release'):
                return 'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n'
            return original_text(path, *args, **kwargs)
        patches = [patch.object(Path, 'stat', checked_metadata), patch.object(Path, 'read_text', text),
            patch.object(probe.pwd, 'getpwuid', return_value=N(pw_uid=1000, pw_gid=1000,
                pw_name='replacement', pw_dir=str(self.account)), create=True),
            patch.object(os, 'geteuid', return_value=0, create=True),
            patch.object(os, 'uname', return_value=N(machine='x86_64'), create=True),
            patch.object(probe.shutil, 'which', return_value='/usr/bin/docker'),
            patch.object(probe, 'DOCKER_VOLUME_ROOT', self.volume_root),
            patch.object(probe.subprocess, 'run', side_effect=self.docker)]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        self.save()

    def save(self):
        self.checkpoint.write_text(json.dumps(self.data), encoding='utf-8')

    def docker(self, args, **kwargs):
        self.calls.append(args)
        operation = args[1:]
        if operation == ['compose', '--profile', 'all', 'config', '--format', 'json']:
            raw = json.dumps(self.model).encode()
        elif operation == ['ps', '-aq']:
            raw = '\n'.join(self.ids).encode()
        elif operation == ['volume', 'ls', '-q']:
            raw = '\n'.join(item['Name'] for item in self.items).encode()
        elif operation[:2] == ['volume', 'inspect']:
            raw = json.dumps(self.items).encode()
        else:
            self.fail('Only readonly commands are allowed: ' + repr(args))
        return N(returncode=0, stdout=raw)

    def check(self):
        return probe.probe(self.target, self.runner, fresh=True, lab_point=(TAG, COMMIT))

    def record(self):
        self.data['lab_deployment'] = dict(schema=1, kind='onboarding_lab', uid=1000, gid=1000,
            user='replacement', home=str(self.account), target=str(self.target), machine_id=MACHINE,
            tag=TAG, public_commit=COMMIT, tooling_commit=COMMIT, publications_disabled=True)
        self.save()

    def test_exact_failed_pre_runtime_attempt_resumes_current_point_without_mutation(self):
        before = self.checkpoint.read_bytes()
        self.data['private_canary'] = 'synthetic-private-value-never-output'
        self.save()
        before = self.checkpoint.read_bytes()
        result = self.check()
        self.assertTrue(result['lab_preparation_resume'])
        self.assertTrue(result['existing_recovery'])
        self.assertEqual((result['containers'], result['volumes']), (0, 1))
        self.assertNotIn('synthetic-private-value', json.dumps(result))
        self.assertEqual(self.checkpoint.read_bytes(), before)
        self.assertEqual(list(self.volume.iterdir()), [])
        self.assertFalse(any(set(args) & {'up', 'down', 'rm', 'pull', 'restart'} for args in self.calls))

    def test_same_attempt_without_selected_lab_scope_keeps_legacy_refusal(self):
        with self.assertRaisesRegex(ValueError, '^FRESH_DOCKER_HOST_REQUIRED$'):
            probe.checked_stack_runtime(self.target, self.runner, self.data)
        self.assertFalse(self.calls)

    def test_wrong_point_scope_state_or_started_workload_is_refused_before_docker(self):
        original = copy.deepcopy(self.data)
        changes = ({'tag': 'dr-20261019T010000Z'}, {'public_commit': 'a'*40},
            {'tooling_commit': 'a'*40}, {'machine_id': 'another-machine'}, {'schema': True},
            {'runner_version': 'unknown'}, {'application_start_attempted': True},
            {'application_start_attempted': 0}, {'preparation': 'PASS'}, {'in_progress': 'RENDER'},
            {'completed': sorted(probe.FIRST_BOOT_STAGES) + ['NPM']},
            {'operational_deployment': {}}, {'timers_installed': True}, {'native_agent': {}})
        for change in changes:
            with self.subTest(change=change):
                self.data = dict(original, **change)
                self.save(); self.calls.clear()
                with self.assertRaisesRegex(ValueError, '^LAB_RUNTIME_SCOPE_REFUSED$'):
                    self.check()
                self.assertFalse(self.calls)

    def test_checkpoint_permissions_links_and_owner_are_verified_before_reading_json(self):
        for change in ({'st_uid': 1000}, {'st_nlink': 2}, {'st_mode': stat.S_IFREG | 0o640},
                       {'st_size': 1024**2 + 1}):
            self.metadata_changes = change
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, '^LAB_RUNTIME_SCOPE_REFUSED$'):
                probe.lab_checkpoint(self.target, self.runner, self.data, 'stack', (TAG, COMMIT))
        self.assertFalse(self.calls)

    def test_orphan_compatibility_artifacts_are_never_adopted(self):
        directory = self.target/'.generated'
        directory.mkdir()
        for name in ('recovery-runtime.compose.yaml', 'cometnet-trial.password', 'tailscale-recovery.env'):
            artifact = directory/name
            artifact.write_bytes(b'synthetic preserved bytes')
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, '^LAB_RUNTIME_SCOPE_REFUSED$'):
                self.check()
            self.assertEqual(artifact.read_bytes(), b'synthetic preserved bytes')
            artifact.unlink()
        self.assertFalse(self.calls)

    def test_owned_but_nonempty_volume_and_any_container_are_refused(self):
        path = self.volume/'preserved.db'
        path.write_bytes(b'synthetic-data')
        with self.assertRaisesRegex(ValueError, '^FRESH_DOCKER_HOST_REQUIRED$'):
            self.check()
        self.assertEqual(path.read_bytes(), b'synthetic-data')
        path.unlink(); self.ids = ['owned-container']
        with self.assertRaisesRegex(ValueError, '^FRESH_DOCKER_HOST_REQUIRED$'):
            self.check()

    def test_registered_lab_record_matches_actual_identity_and_selected_point(self):
        self.record()
        self.assertTrue(self.check()['lab_preparation_resume'])
        for field, value in (('user', 'old-user'), ('publications_disabled', False),
                             ('tag', 'dr-20261001T000000Z'), ('extra', 'untrusted')):
            original = copy.deepcopy(self.data['lab_deployment'])
            self.data['lab_deployment'][field] = value; self.save()
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, '^LAB_RUNTIME_SCOPE_REFUSED$'):
                self.check()
            self.data['lab_deployment'] = original
        self.save()

    def test_pending_aio_accepts_only_runner_reconciliation_and_validates_disk_journal(self):
        self.record()
        self.data.update(in_progress='AIO', runtime_profile={'id': 'synthetic-profile'})
        self.data['completed'] = sorted(probe.FIRST_BOOT_STAGES | {'NPM'})
        self.save()
        resumed = dict(self.data, in_progress=None)
        with patch.object(probe, 'pending_aio_checkpoint') as journal:
            probe.lab_checkpoint(self.target, self.runner, resumed, 'stack', (TAG, COMMIT))
        journal.assert_called_once_with(self.target, self.runner, self.data, lab=True)
        with patch.object(probe, 'pending_aio_checkpoint', side_effect=ValueError('RECOVERY_OPERATION_INCOMPLETE')):
            with self.assertRaisesRegex(ValueError, '^RECOVERY_OPERATION_INCOMPLETE$'):
                probe.lab_checkpoint(self.target, self.runner, resumed, 'stack', (TAG, COMMIT))
        with self.assertRaisesRegex(ValueError, '^LAB_RUNTIME_SCOPE_REFUSED$'):
            probe.lab_checkpoint(self.target, self.runner, dict(resumed, extra='unsaved'), 'stack', (TAG, COMMIT))

    def test_infisical_completed_restore_binds_tooling_commit_without_public_commit(self):
        self.runner = self.account/'.local/share/streams-aio-infisical-recovery'
        self.runner.mkdir(parents=True)
        self.checkpoint = self.runner/'state.json'
        target = Path('/opt/infisical')
        self.data.update(target=str(target), completed=['CLONES', 'DOWNLOAD', 'DECRYPT',
            'INFISICAL_CONFIG', 'INFISICAL_DATABASE', 'INFISICAL_SERVER'],
            server_restore='PASS_NEEDS_SECRET_READ_TEST')
        self.data.pop('public_commit')
        self.save()
        probe.lab_checkpoint(target, self.runner, self.data, 'infisical', (TAG, COMMIT))
        for change in ({'tooling_commit': 'a'*40}, {'public_commit': 'a'*40},
                       {'server_restore': None}, {'completed': ['INFISICAL_CONFIG']}):
            original = copy.deepcopy(self.data)
            self.data.update(change); self.save()
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, '^LAB_RUNTIME_SCOPE_REFUSED$'):
                probe.lab_checkpoint(target, self.runner, self.data, 'infisical', (TAG, COMMIT))
            self.data = original
        self.save()

    def test_infisical_existing_runtime_keeps_config_hashes_and_resource_ownership_gates(self):
        model = dict(services={'app': {}, 'postgres': {}, 'redis': {}},
                     volumes={'pgdata': {'name': 'infisical_pgdata'}})
        names = ('.env', 'docker-compose.prod.yml', 'recovery-compose.json', 'recovery-bootstrap-compose.json')
        hashes = {}
        paths = set()
        for name in names:
            path = self.target/name
            raw = json.dumps(model).encode() if name.endswith('.json') else b'synthetic-installed-config'
            path.write_bytes(raw)
            paths.add(path)
            hashes[name] = hashlib.sha256(raw).hexdigest()
        self.data['installed_config_hashes'] = hashes
        labels = {'com.docker.compose.project': 'infisical',
                  'com.docker.compose.project.working_dir': str(self.target),
                  'com.docker.compose.service': 'app'}
        volumes = [dict(Name='infisical_pgdata', Labels={
            'com.docker.compose.project': 'infisical', 'com.docker.compose.volume': 'pgdata'})]
        calls = []
        def docker(args, **kwargs):
            calls.append(args)
            operation = args[1:]
            if operation == ['ps', '-aq']: raw = b'container'
            elif operation == ['inspect', 'container']: raw = json.dumps([dict(Config=dict(Labels=labels))]).encode()
            elif operation == ['volume', 'ls', '-q']: raw = b'infisical_pgdata'
            elif operation == ['volume', 'inspect', 'infisical_pgdata']: raw = json.dumps(volumes).encode()
            else: self.fail('Unexpected mutation: ' + repr(args))
            return N(returncode=0, stdout=raw)
        original_stat = Path.stat
        def metadata(path, *args, **kwargs):
            value = original_stat(path, *args, **kwargs)
            return N(st_mode=stat.S_IFREG | 0o600) if path in paths else value
        with patch.object(Path, 'stat', metadata), patch.object(probe.subprocess, 'run', side_effect=docker):
            probe.checked_infisical_runtime(self.target, self.data)
            labels['com.docker.compose.project'] = 'foreign'
            with self.assertRaisesRegex(ValueError, '^FOREIGN_CONTAINER_REFUSED$'):
                probe.checked_infisical_runtime(self.target, self.data)
            labels['com.docker.compose.project'] = 'infisical'
            volumes[0]['Name'] = 'foreign-volume'
            with self.assertRaisesRegex(ValueError, '^FOREIGN_VOLUME_REFUSED$'):
                probe.checked_infisical_runtime(self.target, self.data)
            (self.target/'.env').write_bytes(b'changed-config')
            calls.clear()
            with self.assertRaisesRegex(ValueError, '^INFISICAL_CONFIG_CHANGED$'):
                probe.checked_infisical_runtime(self.target, self.data)
            self.assertFalse(calls)

    def test_empty_vm_without_checkpoint_stays_fresh_not_resumed(self):
        self.checkpoint.unlink(); self.target.rmdir(); self.items = []
        result = self.check()
        self.assertFalse(result['existing_recovery'])
        self.assertFalse(result.get('lab_preparation_resume', False))

    def test_selected_point_arguments_are_validated_together(self):
        for point in ((TAG, None), (None, COMMIT), ('wrong', COMMIT), (TAG, 'short'), (TAG, COMMIT, 'extra')):
            with self.subTest(point=point), self.assertRaisesRegex(ValueError, '^LAB_RUNTIME_SCOPE_REFUSED$'):
                probe.probe(self.target, self.runner, fresh=True, lab_point=point)


if __name__ == '__main__':
    unittest.main()

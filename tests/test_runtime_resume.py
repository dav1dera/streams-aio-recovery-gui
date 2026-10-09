import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('runtime_probe', ROOT/'remote/probe.py')
# pwd is POSIX-only; checked_stack_runtime itself uses no passwd lookup.
with patch.dict(sys.modules, {'pwd': N()} if sys.platform == 'win32' else {}):
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)


class Resume(unittest.TestCase):
    def fixture(self, foreign=False):
        self.target = Path('/synthetic/streams-aio')
        model = dict(name='streams-aio', services={'comet': {}},
                     volumes={'cache': {'name': 'streams-aio_cache'}})
        labels = {'com.docker.compose.project': 'streams-aio',
                  'com.docker.compose.project.working_dir': str(self.target),
                  'com.docker.compose.service': 'comet'}
        if foreign:
            labels['com.docker.compose.project'] = 'production'
        objects = [dict(Config=dict(Labels=labels))]
        volumes = [dict(Name='streams-aio_cache', Labels={
            'com.docker.compose.project': 'streams-aio', 'com.docker.compose.volume': 'cache'})]
        def run(args, **kw):
            self.assertEqual(kw['cwd'], self.target)
            if 'compose' in args:
                value = json.dumps(model).encode()
            elif args[1] == 'ps':
                value = b'id\n'
            elif args[1] == 'inspect':
                value = json.dumps(objects).encode()
            elif args[2] == 'ls':
                value = b'streams-aio_cache\n'
            else:
                value = json.dumps(volumes).encode()
            return N(stdout=value, returncode=0)
        return run, model, volumes

    def check(self, state, foreign=False):
        run, model, volumes = self.fixture(foreign)
        with patch.object(probe.subprocess, 'run', run):
            probe.checked_stack_runtime(self.target, Path('/synthetic/state'), state)

    def test_owned_partial_start_can_resume(self):
        self.check(dict(preparation='PASS', application_start_attempted=True))

    def test_unstarted_or_unprepared_checkpoint_cannot_adopt_containers(self):
        for state in ({}, dict(preparation='PASS'), dict(application_start_attempted=True)):
            with self.subTest(state=state), self.assertRaisesRegex(ValueError, 'FRESH_DOCKER_HOST_REQUIRED'):
                self.check(state)

    def test_other_project_is_always_refused(self):
        with self.assertRaisesRegex(ValueError, 'FOREIGN_CONTAINER_REFUSED'):
            self.check(dict(preparation='PASS', application_start_attempted=True), foreign=True)

    def test_foreign_volume_and_external_volume_still_refused(self):
        for external in (False, True):
            run, model, volumes = self.fixture()
            if external:
                model['volumes']['cache']['external'] = True
            else:
                volumes[0]['Name'] = 'old-cache'
            with self.subTest(external=external), patch.object(probe.subprocess, 'run', run), \
                    self.assertRaisesRegex(ValueError, 'EXTERNAL_VOLUME_REFUSED' if external else 'FOREIGN_VOLUME_REFUSED'):
                probe.checked_stack_runtime(self.target, Path('/synthetic/state'),
                                            dict(preparation='PASS', application_start_attempted=True))


class PrestartResume(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target, self.runner = self.root/'streams-aio', self.root/'runner'
        self.target.mkdir()
        self.runner.mkdir()
        self.volume_root = self.root/'docker-volumes'
        self.volume = self.volume_root/'streams-aio_pgdata'/'_data'
        self.volume.mkdir(parents=True)
        self.state = dict(schema=1, runner_version='0.2.0', tag=probe.FIRST_BOOT_TAG,
                          public_commit=probe.FIRST_BOOT_COMMIT, tooling_commit=probe.FIRST_BOOT_COMMIT,
                          target=str(self.target), machine_id='synthetic-machine', in_progress=None,
                          preparation='PASS', application_start_attempted=False,
                          completed=sorted(probe.FIRST_BOOT_STAGES)+['NPM', 'AIO'])
        self.model = dict(name='streams-aio', services={'postgres': {}},
                          volumes={'pgdata': {'name': 'streams-aio_pgdata'}})
        self.ids = []
        self.items = [dict(Name='streams-aio_pgdata', Driver='local', Options=None,
                           Mountpoint=str(self.volume), Labels={
                               'com.docker.compose.project': 'streams-aio',
                               'com.docker.compose.volume': 'pgdata'})]
        self.calls = []
        original_read = Path.read_text
        self.patches = (
            patch.object(probe, 'FIRST_BOOT_TARGET', self.target),
            patch.object(probe, 'DOCKER_VOLUME_ROOT', self.volume_root),
            patch.object(Path, 'read_text', lambda path, *a, **kw:
                'synthetic-machine\n' if path == Path('/etc/machine-id') else original_read(path, *a, **kw)),
            patch.object(probe.subprocess, 'run', self.docker))
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def docker(self, args, **kw):
        self.calls.append(args)
        self.assertEqual(kw.get('cwd', self.target), self.target)
        operation = args[1:]
        if operation == ['compose', '--profile', 'all', 'config', '--format', 'json']:
            output = json.dumps(self.model).encode()
        elif operation == ['ps', '-aq']:
            output = ('\n'.join(self.ids)).encode()
        elif operation == ['volume', 'ls', '-q']:
            output = ('\n'.join(item['Name'] for item in self.items)).encode()
        elif operation[:2] == ['volume', 'inspect']:
            output = json.dumps(self.items).encode()
        else:
            self.fail('Prestart guard must use read-only Compose/list/inspect only: ' + repr(operation))
        return N(stdout=output, returncode=0)

    def check(self):
        probe.checked_stack_runtime(self.target, self.runner, self.state)

    def test_prepared_checkpoint_with_owned_empty_volume_can_resume_without_mutation(self):
        marker = self.target/'preserved-runtime.sqlite'
        marker.write_bytes(b'synthetic preserved private database')
        before_state = json.dumps(self.state, sort_keys=True)
        for absent in (False, True):
            if absent:
                self.state.pop('application_start_attempted')
            self.check()
            self.assertEqual(list(self.volume.iterdir()), [])
            self.assertEqual(marker.read_bytes(), b'synthetic preserved private database')
            if not absent:
                self.assertEqual(json.dumps(self.state, sort_keys=True), before_state)
        self.assertFalse(any('up' in row or 'rm' in row or 'pull' in row for row in self.calls))

    def test_nonempty_volume_is_never_adopted_or_changed(self):
        for filename in ('PG_VERSION', 'cached-credential', 'unexpected.db'):
            path = self.volume/filename
            path.write_bytes(b'synthetic data must remain untouched')
            with self.subTest(filename=filename), self.assertRaisesRegex(ValueError, '^FRESH_DOCKER_HOST_REQUIRED$'):
                self.check()
            self.assertEqual(path.read_bytes(), b'synthetic data must remain untouched')
            path.unlink()

    def test_fresh_gui_probe_accepts_only_the_empty_owned_prestart_runtime(self):
        checkpoint = self.runner/'state.json'
        self.state['private-canary'] = 'synthetic private value must not be returned'
        checkpoint.write_text(json.dumps(self.state))
        before = checkpoint.read_bytes()
        previous_read, previous_stat = Path.read_text, Path.stat
        def read(path, *a, **kw):
            if path == Path('/etc/os-release'):
                return 'ID=ubuntu\nVERSION_ID="26.04"\nVERSION_CODENAME=resolute\n'
            return previous_read(path, *a, **kw)
        def metadata(path, *a, **kw):
            value = previous_stat(path, *a, **kw)
            return N(st_mode=value.st_mode & ~0o077) if path == checkpoint else value
        with patch.object(Path, 'read_text', read), patch.object(Path, 'stat', metadata), \
             patch.object(probe.pwd, 'getpwuid', return_value=N(pw_gid=1000, pw_name='test',
                                                               pw_dir=str(self.root)), create=True), \
             patch.object(os, 'uname', return_value=N(machine='x86_64'), create=True), \
             patch.object(probe.shutil, 'which', return_value='/usr/bin/docker'):
            result = probe.probe(self.target, self.runner, fresh=True)
            self.assertTrue(result['existing_recovery'])
            self.assertEqual((result['containers'], result['volumes']), (0, 1))
            self.assertIs(result['recovery']['application_start_attempted'], False)
            self.assertNotIn('canary', json.dumps(result))
            hidden = self.volume/'secret.db'
            hidden.write_bytes(b'synthetic volume data')
            with self.assertRaisesRegex(ValueError, '^FRESH_DOCKER_HOST_REQUIRED$'):
                probe.probe(self.target, self.runner, fresh=True)
            self.assertEqual(hidden.read_bytes(), b'synthetic volume data')
        self.assertEqual(checkpoint.read_bytes(), before)

    def test_unstarted_checkpoint_with_any_container_is_refused_before_inspection(self):
        self.ids = ['owned-but-unexpected-container']
        with self.assertRaisesRegex(ValueError, '^FRESH_DOCKER_HOST_REQUIRED$'):
            self.check()
        self.assertEqual(self.calls[-1], ['docker', 'ps', '-aq'])

    def test_incompatible_checkpoint_fails_before_any_runtime_query(self):
        valid = json.loads(json.dumps(self.state))
        changes = ({'application_start_attempted': None}, {'application_start_attempted': 0},
                   {'preparation': 'FAILED'}, {'schema': True}, {'runner_version': 'new'},
                   {'tag': 'another-tag'}, {'public_commit': '0'*40}, {'tooling_commit': '0'*40},
                   {'target': str(self.root/'other')}, {'machine_id': 'other-machine'},
                   {'in_progress': 'NPM'}, {'completed': ['RENDER']},
                   {'completed': valid['completed']+['STARTED']},
                   {'completed': valid['completed']+['NPM']}, {'completed': valid['completed']+[1]})
        for change in changes:
            self.state = dict(valid, **change)
            self.calls.clear()
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, '^FRESH_DOCKER_HOST_REQUIRED$'):
                self.check()
            self.assertEqual(self.calls, [])

    def test_external_foreign_plugin_and_mislocated_volumes_are_refused(self):
        item = json.loads(json.dumps(self.items[0]))
        cases = (
            ('EXTERNAL_VOLUME_REFUSED', None, True),
            ('FOREIGN_VOLUME_REFUSED', {'Name': 'old-pgdata'}, False),
            ('FOREIGN_VOLUME_REFUSED', {'Labels': {'com.docker.compose.project': 'other',
                                                  'com.docker.compose.volume': 'pgdata'}}, False),
            ('FOREIGN_VOLUME_REFUSED', {'Driver': 'plugin'}, False),
            ('FOREIGN_VOLUME_REFUSED', {'Options': {'type': 'none'}}, False),
            ('FOREIGN_VOLUME_REFUSED', {'Mountpoint': str(self.root)}, False))
        for code, changed, external in cases:
            self.items = [dict(item, **(changed or {}))]
            self.model['volumes']['pgdata']['external'] = external
            with self.subTest(changed=changed, external=external), self.assertRaisesRegex(ValueError, '^'+code+'$'):
                self.check()
            self.assertEqual(list(self.volume.iterdir()), [])

    def test_missing_or_regular_file_mountpoint_cannot_resume(self):
        self.volume.rmdir()
        with self.assertRaisesRegex(ValueError, '^FRESH_DOCKER_HOST_REQUIRED$'):
            self.check()
        self.volume.write_bytes(b'synthetic file')
        with self.assertRaisesRegex(ValueError, '^FRESH_DOCKER_HOST_REQUIRED$'):
            self.check()
        self.assertEqual(self.volume.read_bytes(), b'synthetic file')

    @unittest.skipUnless(os.name == 'posix', 'Real symlink creation requires the Linux helper')
    def test_symlink_volume_or_ancestor_is_never_followed(self):
        outside = self.root/'outside'
        outside.mkdir()
        private = outside/'secret.db'
        private.write_bytes(b'synthetic outside data')
        self.volume.rmdir()
        self.volume.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, '^SYMLINK_PATH_REFUSED$'):
            self.check()
        self.volume.unlink()
        parent = self.volume.parent
        parent.rmdir()
        parent.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, '^SYMLINK_PATH_REFUSED$'):
            self.check()
        self.assertEqual(private.read_bytes(), b'synthetic outside data')


if __name__ == '__main__':
    unittest.main()

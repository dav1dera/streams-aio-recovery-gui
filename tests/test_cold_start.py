"""Cold startup must pull before inherited health and preserve refusal details."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location('cold_start', ROOT / 'remote/start.py')
start = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {'fcntl': N()} if sys.platform == 'win32' else {}):
    spec.loader.exec_module(start)

IMAGE = 'example.invalid/app@sha256:' + 'a' * 64
OTHER = 'example.invalid/pooler@sha256:' + 'b' * 64
METADATA = json.dumps(dict(id='sha256:' + 'c' * 64, os='linux', arch='amd64')).encode()


class ColdStart(unittest.TestCase):
    def test_empty_cache_pulls_pinned_images_once(self):
        calls, cache = [], set()
        def runner(args, root):
            calls.append(args)
            if args[1] == 'pull':
                cache.add(args[-1])
                return b''
            if args[-1] not in cache:
                raise ValueError('private error must not be logged')
            return METADATA
        model = {'services': {'one': {'image': IMAGE}, 'two': {'image': IMAGE},
                              'watchtower': {'image': 'ignored-tag'}}}
        with contextlib.redirect_stdout(io.StringIO()) as log:
            start.prepare_images(model, Path('/synthetic'), runner)
        self.assertEqual([args for args in calls if args[1] == 'pull'], [['docker', 'pull', IMAGE]])
        self.assertNotIn('private', log.getvalue())
        self.assertNotIn(IMAGE, log.getvalue())

    def test_cached_image_does_not_pull(self):
        calls = []
        start.prepare_images({'services': {'one': {'image': IMAGE}}}, Path('/synthetic'),
                             lambda args, root: calls.append(args) or METADATA)
        self.assertTrue(all(args[1] != 'pull' for args in calls))

    def test_all_references_validated_before_any_download(self):
        for service in ({'image': 'example:latest'}, {'image': IMAGE, 'build': '.'}):
            calls = []
            with self.subTest(service=service), self.assertRaisesRegex(ValueError, 'APPLICATION_PINNED_IMAGES_REQUIRED'):
                start.prepare_images({'services': {'good': {'image': IMAGE}, 'bad': service}},
                                     Path('/synthetic'), lambda args, root: calls.append(args))
            self.assertEqual(calls, [])

    def test_wrong_platform_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'APPLICATION_IMAGE_PLATFORM_REFUSED'):
            start.prepare_images({'services': {'one': {'image': IMAGE}}}, Path('/synthetic'),
                                 lambda args, root: json.dumps(dict(id='sha256:'+'c'*64, os='linux', arch='arm64')))

    def test_download_exception_replaced_by_fixed_code(self):
        def fail(args, root):
            raise RuntimeError('credential-canary')
        with self.assertRaisesRegex(ValueError, '^APPLICATION_IMAGE_DOWNLOAD_FAILED$'):
            start.prepare_images({'services': {'one': {'image': IMAGE}}}, Path('/synthetic'), fail)

    def exercise(self, pooler_failure=False, foreign=False, missing_profile=False):
        with tempfile.TemporaryDirectory() as temp:
            root, home = Path(temp)/'stack', Path(temp)/'recovery'
            root.mkdir(); home.mkdir(); (root/'config').mkdir()
            state_file = home/'state.json'
            state_file.write_text(json.dumps(dict(target=str(root), machine_id='synthetic', preparation='PASS')))
            (root/'config/dr-manifest.yaml').write_text(json.dumps(dict(restore_waves=[['pgbouncer'], ['app']])))
            events, cache = [], set()
            model = dict(name='streams-aio', services={'pgbouncer': {'image': OTHER}, 'app': {'image': IMAGE}})
            def runner(args, cwd):
                self.assertEqual(cwd, root)
                events.append(args)
                if args[:2] == ['docker', 'pull']:
                    cache.add(args[-1]); return b''
                if args[:3] == ['docker', 'image', 'inspect']:
                    if args[-1] not in cache:
                        raise ValueError('not cached')
                    return METADATA
                if args[:2] == ['docker', 'ps']:
                    return b'foreign' if foreign else b''
                if args[:2] == ['docker', 'inspect'] and '--format' in args:
                    return b'\n'.join(json.dumps(dict(service=name, project=model['name'], directory=str(root),
                                                running=True, health='healthy')).encode() for name in model['services'])
                if args[:2] == ['docker', 'inspect']:
                    return b'[{"Config":{"Labels":{}}}]'
                if args[:3] == ['docker', 'volume', 'ls']:
                    return b''
                if 'config' in args:
                    return json.dumps(model).encode()
                if 'compose' in args and 'ps' in args:
                    return b'pooler\napp\n'
                if 'exec' in args and pooler_failure:
                    raise ValueError('private-canary')
                return b''
            checks = N(stack_preflight=lambda *a: events.append('preflight'),
                       save=lambda path, value: path.write_text(json.dumps(value)))
            def health(*args):
                events.append('inherited-health')
                self.assertEqual(cache, {IMAGE, OTHER})
                return [], []
            profile = N(validate=lambda *a: events.append('profile') or not missing_profile,
                        derived_waves=lambda model, waves: waves, health_dependency_issues=health)
            original_stat, original_text = Path.stat, Path.read_text
            def stat(path, *args, **kwargs):
                if path == state_file:
                    return N(st_mode=0o100600)
                return original_stat(path, *args, **kwargs)
            def text(path, *args, **kwargs):
                if path.as_posix() == '/etc/machine-id':
                    return 'synthetic'
                return original_text(path, *args, **kwargs)
            loader = N(loader=N(exec_module=lambda module: None))
            with patch.object(Path, 'stat', stat), patch.object(Path, 'read_text', text), \
                    patch.object(start.importlib.util, 'spec_from_file_location', return_value=loader), \
                    patch.object(start.importlib.util, 'module_from_spec', side_effect=[checks, profile]), \
                    patch.object(start, 'call', runner), contextlib.redirect_stdout(io.StringIO()):
                if pooler_failure or foreign or missing_profile:
                    error = ('RUNTIME_PROFILE_PRESTART_CHECKPOINT_REQUIRED' if missing_profile else
                             'PGBOUNCER_NOT_READY' if pooler_failure else 'FOREIGN_CONTAINER_REFUSED')
                    with self.assertRaisesRegex(ValueError, error):
                        start.start(root, home)
                else:
                    start.start(root, home)
            return events, json.loads(state_file.read_bytes())

    def test_fresh_path_pulls_before_health_and_starts_in_dependency_order(self):
        events, state = self.exercise()
        health = events.index('inherited-health')
        self.assertTrue(all(events.index(item) < health for item in events if isinstance(item, list) and item[1]=='pull'))
        up = [item for item in events if isinstance(item, list) and 'up' in item]
        self.assertEqual([item[-1] for item in up], ['pgbouncer', 'app'])
        pooler = next(item for item in events if isinstance(item, list) and 'exec' in item)
        self.assertEqual(pooler[-5:], ['pg_isready', '-h', '127.0.0.1', '-p', '6432'])
        self.assertLess(events.index(pooler), events.index(up[1]))
        self.assertEqual(state['application_recovery'], 'STARTED_NEEDS_FUNCTIONAL_TEST')

    def test_pooler_failure_blocks_dependents_and_preserves_wave(self):
        events, state = self.exercise(pooler_failure=True)
        self.assertEqual(len([item for item in events if isinstance(item, list) and 'up' in item]), 1)
        self.assertEqual(state['application_wave'], ['pgbouncer'])

    def test_foreign_workload_refused_before_download_or_start(self):
        events, state = self.exercise(foreign=True)
        self.assertFalse(any(isinstance(item, list) and ('pull' in item or 'up' in item) for item in events))
        self.assertNotIn('application_start_attempted', state)

    def test_start_button_cannot_skip_an_absent_compatibility_profile(self):
        events, state = self.exercise(missing_profile=True)
        self.assertFalse(any(isinstance(item, list) for item in events))
        self.assertNotIn('application_start_attempted', state)

    def test_public_codes_preserved_but_unknown_exception_is_redacted(self):
        self.assertEqual(start.failure_code(ValueError('PGBOUNCER_NOT_READY')), 'PGBOUNCER_NOT_READY')
        self.assertEqual(start.failure_code(ValueError('private-canary')), 'APPLICATION_START_REFUSED')
        self.assertEqual(start.failure_code(BlockingIOError()), 'RECOVERY_ALREADY_RUNNING')

    def test_startup_codes_and_scoped_choices_reach_the_gui_safely(self):
        from recovery_gui.codes import ERROR_CODES
        from recovery_gui.app import validate_first_boot_choice
        from recovery_gui.backend import Failure, parse_event
        self.assertLessEqual(start.STARTUP_CODES, ERROR_CODES)
        for stage in ('RUNTIME_PROFILE', 'IMAGES', 'APPLICATION_CHECKS'):
            self.assertEqual(parse_event('RECOVERY_EVENT '+json.dumps(dict(stage=stage, status='PASS'))),
                             dict(stage=stage, status='PASS'))
        choice = dict(user='test', dr_tag='dr-20261006T210601Z',
                      public_commit='28f6ca7cc6f5fd10418fc0af2926815927ef98c8')
        validate_first_boot_choice(choice)
        for field in choice:
            with self.subTest(field=field), self.assertRaisesRegex(Failure, '^RUNTIME_PROFILE_SCOPE_REFUSED$'):
                validate_first_boot_choice(dict(choice, **{field: 'different'}))

    def test_complete_service_check_catches_earlier_service_failure(self):
        model = dict(name='streams-aio', services={'one': {}, 'two': {}, 'watchtower': {}})
        for failure in ('missing', 'stopped', 'unhealthy', 'foreign'):
            rows = [dict(service=name, project='streams-aio', directory='/synthetic', running=True, health='healthy')
                    for name in ('one', 'two')]
            if failure == 'missing': rows.pop()
            if failure == 'stopped': rows[0]['running'] = False
            if failure == 'unhealthy': rows[0]['health'] = 'unhealthy'
            if failure == 'foreign': rows[0]['directory'] = '/other'
            def runner(args, root):
                return b'a\nb' if 'ps' in args else b'\n'.join(json.dumps(row).encode() for row in rows)
            with self.subTest(failure=failure), self.assertRaisesRegex(ValueError, '^APPLICATION_FINAL_CHECK_FAILED$'):
                start.final_service_check(model, Path('/synthetic'), runner)


if __name__ == '__main__':
    unittest.main()

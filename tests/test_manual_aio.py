"""Explicit manual AIO keeps the real pinned preflight for every other service."""
import importlib.util
import contextlib
import gc
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from recovery_gui.backend import SSH, parse_event
spec = importlib.util.spec_from_file_location('manual_aio_remote', ROOT / 'remote/recover.py')
remote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remote)
PINNED = ROOT / 'tests/fixtures/pinned_dr_preflight.py'


class ManualAIO(unittest.TestCase):
    def fixture(self, root):
        (root / 'config').mkdir()
        (root / 'scripts').mkdir()
        (root / 'scripts/dr.py').write_bytes(PINNED.read_bytes())
        (root / '.dr-fresh-target.json').write_text(json.dumps({'root': str(root)}))
        self.plan = {'readiness_blockers': []}
        self.manifest = {'references': [], 'state_units': [
            {'id': 'npm-routing', 'classification': 'REQUIRED_USER_STATE', 'services': ['npm'],
             'read_only_check': {'file': 'npm.sqlite', 'nonempty_tables': ['proxy_host', 'user']}},
            {'id': 'aio-profile', 'classification': 'REQUIRED_USER_STATE', 'services': ['aiostreams'],
             'read_only_check': {'file': 'data/aiostreams/data/db.sqlite', 'nonempty_tables': ['users']}}]}
        with contextlib.closing(sqlite3.connect(root / 'npm.sqlite')) as db:
            db.executescript('CREATE TABLE proxy_host(id INTEGER); INSERT INTO proxy_host VALUES(1);'
                             'CREATE TABLE user(id INTEGER); INSERT INTO user VALUES(1);')
        self.write_fixture(root)
        return {'target': str(root), 'machine_id': 'synthetic-machine', 'completed': ['NPM', 'AIO'],
                'aio_mode': 'manual', 'aio_recovery': 'MANUAL_PENDING'}

    def write_fixture(self, root):
        (root / 'config/dr-manifest.yaml').write_text(json.dumps(self.manifest))
        (root / 'config/dr-render-plan.json').write_text(json.dumps(self.plan))

    def check(self, root, state):
        original = Path.read_text
        def text(path, *args, **kwargs):
            return 'synthetic-machine' if path.as_posix() == '/etc/machine-id' else original(path, *args, **kwargs)
        with patch.object(Path, 'read_text', text):
            try:
                remote.stack_preflight(root, state)
            finally:
                gc.collect()

    def test_real_preflight_allows_only_the_missing_aio_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = self.fixture(root)
            npm = (root / 'npm.sqlite').read_bytes()
            self.check(root, state)
            self.assertEqual((root / 'npm.sqlite').read_bytes(), npm)
            self.assertFalse((root / '.generated/aio-import-complete.json').exists())
            self.assertFalse((root / 'data/aiostreams/data/db.sqlite').exists())

    def test_npm_empty_or_missing_still_blocks_manual_aio(self):
        for mode in ('empty', 'missing'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                state = self.fixture(root)
                if mode == 'empty':
                    with contextlib.closing(sqlite3.connect(root / 'npm.sqlite')) as db:
                        db.execute('DELETE FROM user')
                        db.commit()
                else:
                    (root / 'npm.sqlite').unlink()
                with self.assertRaisesRegex(remote.Refused, '^FRESH_RENDERER_REFUSED$'):
                    self.check(root, state)

    def test_other_required_source_host_and_blockers_still_block(self):
        for kind in ('source', 'host', 'blocker', 'mixed'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                state = self.fixture(root)
                if kind == 'source':
                    self.manifest['references'].append({'SOURCE': 'missing-config', 'SERVICE': 'comet',
                       'TYPE': 'BIND', 'RESTORE_METHOD': 'TRACKED_PUBLIC'})
                elif kind == 'host':
                    self.manifest['references'].append({'SOURCE': '/missing-preflight-test/device', 'SERVICE': 'vpn',
                       'TYPE': 'HOST_PREREQUISITE', 'RESTORE_METHOD': 'HOST_PREREQUISITE'})
                elif kind == 'blocker':
                    self.plan['readiness_blockers'].append({'component': 'vpn', 'code': 'REVIEW_REQUIRED'})
                else:
                    self.manifest['state_units'][1]['services'].append('npm')
                self.write_fixture(root)
                with self.assertRaisesRegex(remote.Refused, '^FRESH_RENDERER_REFUSED$'):
                    self.check(root, state)

    def test_manual_checkpoint_and_existing_import_marker_are_verified(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = self.fixture(root)
            for update in ({'target': '/foreign'}, {'machine_id': 'foreign'}, {'completed': ['AIO']},
                           {'aio_mode': 'import'}):
                with self.subTest(update=update), self.assertRaises(remote.Refused):
                    self.check(root, dict(state, **update))
            (root / '.generated').mkdir()
            (root / '.generated/aio-import-complete.json').write_text('{}')
            with self.assertRaisesRegex(remote.Refused, 'MANUAL_AIO_IMPORT_CONFLICT'):
                self.check(root, state)

    def test_skip_creates_no_database_or_import_marker_and_reports_pending(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            job = remote.Recovery.__new__(remote.Recovery)
            job.root = root
            job.config = {'aio_mode': 'manual', 'aio_payload': 'ignored-private-payload'}
            job.state = {'completed': ['NPM'], 'in_progress': 'AIO'}
            job.state_path = root / 'state.json'
            events = []
            with patch.object(remote, 'event', side_effect=lambda *args: events.append(args)):
                job.step('AIO', job.aio)
                job.step('AIO', lambda: self.fail('completed manual choice must not run an importer'))
            self.assertEqual(job.state['aio_recovery'], 'MANUAL_PENDING')
            self.assertIn(('AIO', 'SKIPPED'), events)
            self.assertNotIn(('AIO', 'PASS'), events)
            self.assertEqual(list(root.iterdir()), [root / 'state.json'])

    def test_skip_never_deletes_an_existing_aio_database(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / 'data/aiometadata/data/db.sqlite'
            path.parent.mkdir(parents=True)
            path.write_bytes(b'private-database-canary')
            job = remote.Recovery.__new__(remote.Recovery)
            job.root, job.config, job.state = root, {'aio_mode': 'manual'}, {}
            with self.assertRaisesRegex(remote.Refused, 'MANUAL_AIO_IMPORT_CONFLICT'):
                job.aio()
            self.assertEqual(path.read_bytes(), b'private-database-canary')
            self.assertNotIn('aio_recovery', job.state)

    def test_skipped_event_is_specific_to_aio(self):
        self.assertEqual(parse_event('RECOVERY_EVENT {"stage":"AIO","status":"SKIPPED"}'),
                         {'stage': 'AIO', 'status': 'SKIPPED'})
        self.assertIsNone(parse_event('RECOVERY_EVENT {"stage":"NPM","status":"SKIPPED"}'))

    def test_manual_upload_does_not_touch_export_or_payload_files(self):
        job = SSH.__new__(SSH)
        job.check = MagicMock(return_value={'home': '/home/test'})
        job.run = MagicMock()
        job.client = MagicMock()
        request = {name: 'synthetic' for name in ('github_token', 'public_commit', 'dr_tag',
                           'infisical_address', 'project_id', 'environment')}
        request.update(aio_mode='manual', age_identity='/private/identity',
                       aio_payload='/not-selected-payload', aiostreams_exports=['/not-selected-streams'],
                       aiometadata_exports=['/not-selected-metadata'])
        with patch.object(SSH, '_put') as transfer:
            directory, raw = job.upload(request)
        config = json.loads(raw)
        self.assertNotIn('aio_payload', config)
        self.assertEqual(config['aiometadata_exports'], [])
        self.assertEqual(config['aiostreams_exports'], [])
        sources = [Path(call.args[1]).as_posix() for call in transfer.call_args_list]
        self.assertIn('/private/identity', sources)
        self.assertNotIn('/not-selected-payload', sources)
        self.assertTrue(job.run.call_args.kwargs['sudo'])

    def test_companion_is_uploaded_only_to_the_stack(self):
        for role in ('stack', 'infisical'):
            with self.subTest(role=role):
                job = SSH.__new__(SSH)
                job.check = MagicMock(return_value={'home': '/home/test'})
                job.run, job.client = MagicMock(), MagicMock()
                request = {name: 'synthetic' for name in ('github_token', 'public_commit', 'dr_tag',
                           'infisical_address', 'project_id', 'environment')}
                request.update(role=role, aio_mode='manual', supplemental_inputs='/private/companion.age')
                with patch.object(SSH, '_put') as transfer:
                    directory, raw = job.upload(request)
                config = json.loads(raw)
                sources = [Path(call.args[1]).as_posix() for call in transfer.call_args_list]
                self.assertEqual('/private/companion.age' in sources, role == 'stack')
                self.assertEqual('supplemental_inputs' in config, role == 'stack')


if __name__ == '__main__':
    unittest.main()

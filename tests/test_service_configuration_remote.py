"""Existing public configuration updates stay transactional and lifecycle-free."""
from contextlib import contextmanager
import base64
import copy
import json
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml
from remote import service_configuration as update
from tests.test_service_resources_remote import bundle, BundleRunner
from tests.test_service_onboarding_remote import FakeEngine, MemoryStore, ROOT, LAYOUT, COMPOSE, AGENT, remote


class ConfigurationRunner(BundleRunner):
    def __init__(self, store):
        super().__init__(store)
        self.started = True
        self.preflights = []
        self.private_refusal = False
        self.head = '7' * 40

    def api(self, suffix, binary=False):
        if suffix.endswith('/git/ref/heads/main'):
            return {'object': {'sha': self.head}}
        return super().api(suffix, binary)

    def public_preflight(self, candidate):
        self.preflights.append(copy.deepcopy(candidate))
        if self.private_refusal:
            raise remote.Refused('ONBOARDING_PUBLIC_PREFLIGHT_FAILED', dict(schema=1, stage='GITHUB',
                code='PRIVATE_VALUE_IN_PUBLIC_FILE', path='data/demo/public/config/settings.yaml', lines=[1], retryable=False))
        return dict(schema=1, status='PASS', stage='PUBLIC_EXPORT')


class ConfigurationUpdateTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.runner = ConfigurationRunner(self.store)
        self.engine = FakeEngine(LAYOUT, self.runner, self.store)
        self.original = bundle()
        self.normalized, _ = remote.plan_document(self.original)
        self.store.put(ROOT/'docker-compose.yml', remote.merge_compose(COMPOSE, self.normalized), 1001, 1001, 0o640)
        rows = [{key: row[key] for key in ('path', 'mode', 'sha256')} for row in self.normalized['configuration_files']]
        self.inventory = dict(schema=1, resources=copy.deepcopy(self.normalized['resources']), configuration_files=rows)
        self.store.put(ROOT/'config/service-resources.json', remote.canonical_json(self.inventory)+b'\n', 1001, 1001, 0o640)
        for child in remote.components(self.normalized):
            self.store.put(ROOT/child['public_env_path'], child['public_env_text'].encode(), 1001, 1001, 0o640)
        for row in self.normalized['configuration_files']:
            self.store.put(ROOT/row['path'], row['content'].encode(), 1001, 1001, row['mode'])
        self.store.put(ROOT/'.secrets/redis.env', b"EXISTING='private-existing-value'\n", 0, 1001, 0o640)
        self.next = copy.deepcopy(self.original)
        self.next['configuration_files'][0]['content'] = 'title: Reviewed new public theme\n'
        self.request = dict(action='apply_configuration', root=str(ROOT), plan=self.next, project_id='',
                            environment='', probe_url='', job_id='8'*32, verification_scope='full')
        self.events = []
        @contextmanager
        def locks(engine):
            self.events.append('lock')
            try: yield
            finally: self.events.append('unlock')
        self.patch = patch.object(update, '_worker_locks', locks)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.store.writes.clear()

    def inspect(self):
        result = update.inspect_configuration(self.engine, self.request)
        self.request['fingerprint'] = result['fingerprint']
        return result

    def apply(self):
        if 'fingerprint' not in self.request: self.inspect()
        return update.apply_configuration(self.engine, self.request)

    def assert_code(self, code, fn):
        with self.assertRaises(remote.Refused) as raised: fn()
        self.assertEqual(str(raised.exception), code)

    def assert_no_lifecycle(self):
        for arguments, _ in self.runner.calls:
            self.assertFalse(arguments[:2] == ['systemctl', 'restart'])
            self.assertFalse(arguments[:2] == ['systemctl', 'stop'])
            self.assertFalse(arguments[:2] == ['systemctl', 'start'])
            if arguments[:2] == ['docker', 'compose']:
                self.assertNotIn(arguments[6], ('up', 'down', 'restart', 'stop', 'pull', 'rm'))

    def journal(self):
        return self.store.json(self.engine.journal_path(self.request['job_id']))

    def test_preview_checks_public_overlay_and_does_not_write(self):
        before = copy.deepcopy(self.store.files)
        result = self.inspect()
        self.assertEqual((result['status'], result['operation_kind'], result['configuration_updated']),
                         ('PREVIEW', 'configuration', False))
        self.assertEqual(self.store.files, before)
        self.assertEqual(self.store.writes, [])
        candidate = self.runner.preflights[-1]
        self.assertEqual(set(candidate['files']), {'config/service-resources.json', 'data/demo/public/config/settings.yaml'})
        inventory = json.loads(base64.b64decode(candidate['files']['config/service-resources.json']))
        raw = base64.b64decode(candidate['files']['data/demo/public/config/settings.yaml'])
        self.assertEqual(inventory['configuration_files'][0]['sha256'], remote.digest(raw))
        self.assertTrue(all(not path.startswith('/') for path in result['public_files']))
        self.assert_no_lifecycle()

    def test_apply_updates_only_config_and_inventory_preserving_other_bytes_metadata(self):
        before = copy.deepcopy(self.store.files)
        result = self.apply()
        self.assertEqual((result['status'], result['operation_kind'], result['configuration_updated']),
                         ('SERVICE_READY', 'configuration', True))
        changed = {'data/demo/public/config/settings.yaml', 'config/service-resources.json'}
        for name, old in before.items():
            if name not in {str(ROOT/path) for path in changed}:
                self.assertEqual(self.store.files[name], old)
        actual = json.loads(self.store.read(ROOT/'config/service-resources.json'))
        self.assertEqual(actual['resources'], self.inventory['resources'])
        self.assertEqual(actual['configuration_files'][0]['sha256'], remote.digest(self.next['configuration_files'][0]['content'].encode()))
        self.assertEqual(self.events, ['lock', 'unlock'])
        self.assert_no_lifecycle()

    def test_private_preflight_refusal_prevents_all_remote_writes(self):
        self.inspect()
        self.runner.private_refusal = True
        before = copy.deepcopy(self.store.files)
        self.assert_code('ONBOARDING_PUBLIC_PREFLIGHT_FAILED', self.apply)
        self.assertEqual(self.store.files, before)
        self.assertFalse(self.store.writes)
        self.assert_no_lifecycle()

    def test_existing_manual_config_drift_is_closed_before_any_write(self):
        self.store.put(ROOT/'data/demo/public/config/settings.yaml', b'title: Foreign edit\n', 1001, 1001, 0o644)
        self.assert_code('ONBOARDING_CONFIGURATION_SOURCE_CHANGED', self.inspect)
        self.assertFalse(self.store.writes)

    def test_configuration_mode_change_is_outside_first_scope(self):
        self.next['configuration_files'][0]['mode'] = 0o640
        self.assert_code('ONBOARDING_CONFIGURATION_MODE_CHANGED', self.inspect)
        self.assertFalse(self.store.writes)

    def test_add_or_remove_config_paths_is_refused(self):
        self.next['configuration_files'].append(dict(path='data/demo/public/config/extra.css', content='x{}', mode=0o644))
        self.assert_code('ONBOARDING_CONFIGURATION_PATH_SET_CHANGED', self.inspect)
        self.assertFalse(self.store.writes)

    def test_different_compose_is_refused_without_application_changes(self):
        self.next['components'][0]['compose_fragment'] = self.next['components'][0]['compose_fragment'].replace('18321', '18322')
        self.next['compose_fragment'] = self.next['components'][0]['compose_fragment'] + self.next['components'][1]['compose_fragment']
        self.assert_code('ONBOARDING_CONFIGURATION_STATIC_CHANGED', self.inspect)
        self.assertFalse(self.store.writes)

    def test_public_env_change_is_refused(self):
        self.next['components'][0]['public_env_text'] += 'EXTRA=public\n'
        self.next['public_env_text'] = self.next['components'][0]['public_env_text']
        self.assert_code('ONBOARDING_CONFIGURATION_STATIC_CHANGED', self.inspect)
        self.assertFalse(self.store.writes)

    def test_storage_policy_change_is_refused(self):
        self.next['resources'][0]['recovery']['method'] = 'external'
        self.next['resources'][0]['role'] = 'external'
        self.assert_code('ONBOARDING_CONFIGURATION_STATIC_CHANGED', self.inspect)
        self.assertFalse(self.store.writes)

    def test_stale_preview_cannot_apply(self):
        self.inspect()
        self.store.put(ROOT/'data/sidecar/.env', b'CHANGED=1\n', 1001, 1001, 0o640)
        self.assert_code('ONBOARDING_CONFIGURATION_STATIC_CHANGED', self.apply)
        self.assertFalse(self.store.writes)

    def test_source_race_after_preflight_is_preserved(self):
        self.inspect()
        @contextmanager
        def raced(engine):
            self.store.put(ROOT/'data/demo/public/config/settings.yaml', b'title: Concurrent edit\n', 1001, 1001, 0o644)
            yield
        with patch.object(update, '_worker_locks', raced):
            self.assert_code('ONBOARDING_SOURCE_CHANGED', self.apply)
        self.assertEqual(self.store.read(ROOT/'data/demo/public/config/settings.yaml'), b'title: Concurrent edit\n')
        self.assertFalse(self.store.writes)

    def test_public_head_race_after_preflight_prevents_writes(self):
        self.inspect()
        @contextmanager
        def raced(engine):
            self.runner.head = '9'*40
            yield
        with patch.object(update, '_worker_locks', raced):
            self.assert_code('ONBOARDING_CONFIGURATION_PUBLIC_BASE_MOVED', self.apply)
        self.assertFalse(self.store.writes)

    def test_compose_failure_rolls_back_only_owned_configuration_outputs(self):
        before = copy.deepcopy(self.store.files)
        self.runner.fail_config = True
        result = self.apply()
        self.assertEqual(result['status'], 'REFUSED')
        self.assertEqual(self.journal()['phase'], 'ROLLED_BACK')
        for name, item in before.items():
            self.assertEqual(self.store.read(name), item.raw)
        compose_writes = [path for path, _ in self.store.writes if path == str(ROOT/'docker-compose.yml')]
        self.assertFalse(compose_writes)
        self.assert_no_lifecycle()

    def test_rollback_preserves_concurrent_foreign_edit_for_review(self):
        self.runner.fail_config = True
        self.runner.before_config_failure = lambda: self.store.put(ROOT/'data/demo/public/config/settings.yaml', b'foreign-after-write\n', 1001, 1001, 0o644)
        result = self.apply()
        self.assertEqual(result['status'], 'REFUSED')
        self.assertEqual(self.journal()['phase'], 'REVIEW_REQUIRED')
        self.assertEqual(self.store.read(ROOT/'data/demo/public/config/settings.yaml'), b'foreign-after-write\n')
        self.assert_no_lifecycle()

    def test_public_acl_watcher_and_non_acl_metadata_are_preserved(self):
        name = ROOT/'data/demo/public/config/settings.yaml'
        self.store.put(name, self.store.read(name), 1001, 1001, 0o674,
            {'system.posix_acl_access': b'old-public-acl', 'user.fixture': b'public-note'})
        self.store.public_acl_watcher = True
        result = self.apply()
        self.assertEqual(result['status'], 'SERVICE_READY')
        item = self.store.snapshot(name)
        self.assertEqual((item.uid, item.gid, item.mode), (1001, 1001, 0o674))
        self.assertEqual(item.attributes['user.fixture'], b'public-note')
        self.engine.unchanged(self.journal())

    def test_reapply_same_job_does_not_write_or_restart(self):
        self.apply()
        before = copy.deepcopy(self.store.files)
        self.store.writes.clear()
        repeated = self.apply()
        self.assertEqual(repeated['status'], 'SERVICE_READY')
        self.assertEqual(self.store.files, before)
        self.assertFalse(self.store.writes)
        self.assert_no_lifecycle()

    def test_fresh_desktop_discovers_only_configuration_job(self):
        self.apply()
        request = dict(self.request)
        request.pop('fingerprint')
        resumed = update.discover_configuration(self.engine, request)
        self.assertEqual((resumed['status'], resumed['job_id'], resumed['operation_kind'], resumed['configuration_updated']),
                         ('SERVICE_READY', self.request['job_id'], 'configuration', True))
        self.assertEqual(resumed['fingerprint'], self.request['fingerprint'])
        self.assert_no_lifecycle()

    def test_old_complete_addition_journal_is_not_changed_or_adopted(self):
        path = self.engine.journal_path('f'*32)
        old = dict(schema=2, job_id='f'*32, root=str(ROOT), owner=LAYOUT.user, phase='COMPLETE',
            verification_scope='full', plan=self.normalized, fingerprint='a'*64)
        self.store.put(path, remote.canonical_json(old))
        raw = self.store.read(path)
        self.assertEqual(update.discover_configuration(self.engine, self.request)['status'], 'NO_JOB')
        self.apply()
        self.assertEqual(self.store.read(path), raw)

    def test_interrupted_write_is_restored_before_fresh_preview(self):
        before = copy.deepcopy(self.store.files)
        self.inspect()
        original_write = self.store.write
        def interrupted(path, raw, *args, **kwargs):
            result = original_write(path, raw, *args, **kwargs)
            if str(path) == str(ROOT/'data/demo/public/config/settings.yaml'):
                raise SystemExit('synthetic termination')
            return result
        with patch.object(self.store, 'write', interrupted):
            with self.assertRaises(SystemExit): self.apply()
        self.assertEqual(self.journal()['phase'], 'PREPARED')
        request = dict(self.request)
        request.pop('fingerprint')
        recovered = update.discover_configuration(self.engine, request)
        self.assertEqual(recovered['status'], 'NO_JOB')
        self.assertEqual(self.journal()['phase'], 'ROLLED_BACK')
        for name, item in before.items(): self.assertEqual(self.store.read(name), item.raw)
        self.assertEqual(self.inspect()['status'], 'PREVIEW')
        self.assert_no_lifecycle()

    def test_crash_recovery_does_not_overwrite_foreign_bytes(self):
        self.inspect()
        original_write = self.store.write
        def interrupted(path, raw, *args, **kwargs):
            result = original_write(path, raw, *args, **kwargs)
            if str(path) == str(ROOT/'data/demo/public/config/settings.yaml'): raise SystemExit()
            return result
        with patch.object(self.store, 'write', interrupted):
            with self.assertRaises(SystemExit): self.apply()
        self.store.put(ROOT/'data/demo/public/config/settings.yaml', b'foreign-after-crash\n', 1001, 1001, 0o644)
        request = dict(self.request)
        request.pop('fingerprint')
        self.assert_code('ONBOARDING_CONFIGURATION_RECOVERY_REQUIRED', lambda: update.discover_configuration(self.engine, request))
        self.assertEqual(self.journal()['phase'], 'REVIEW_REQUIRED')
        self.assertEqual(self.store.read(ROOT/'data/demo/public/config/settings.yaml'), b'foreign-after-crash\n')

    def test_managed_theme_a_b_a_keeps_history_and_can_resume_latest_equivalent_job(self):
        self.apply()
        first_path = self.engine.journal_path(self.request['job_id'])
        first = self.journal()
        first.update(phase='COMPLETE', backup_tag='dr-20261020T120001Z')
        self.engine.save(first)
        original_history = self.store.read(first_path)
        theme_a = copy.deepcopy(self.request['plan'])
        self.request.update(job_id='9'*32, plan=copy.deepcopy(theme_a))
        self.request['plan']['configuration_files'][0]['content'] = 'title: Managed second theme\n'
        self.request.pop('fingerprint')
        self.apply()
        second = self.journal()
        second.update(phase='COMPLETE', backup_tag='dr-20261020T120002Z')
        self.engine.save(second)
        self.request.update(job_id='a'*32, plan=theme_a)
        self.request.pop('fingerprint')
        self.assertEqual(update.discover_configuration(self.engine, self.request)['status'], 'NO_JOB')
        self.apply()
        third = self.journal()
        third.update(phase='COMPLETE', backup_tag='dr-20261020T120003Z')
        self.engine.save(third)
        self.request.pop('fingerprint')
        resumed = update.discover_configuration(self.engine, self.request)
        self.assertEqual(resumed['job_id'], 'a'*32)
        self.assertEqual(self.store.read(first_path), original_history)
        self.assert_no_lifecycle()

    def test_manual_drift_after_complete_cannot_be_bypassed_by_fresh_preview(self):
        self.apply()
        finished = self.journal()
        finished.update(phase='COMPLETE', backup_tag='dr-20261020T120001Z')
        self.engine.save(finished)
        self.store.put(ROOT/'data/demo/public/config/settings.yaml', b'foreign-after-complete\n', 1001, 1001, 0o644)
        self.request.pop('fingerprint')
        self.assertEqual(update.discover_configuration(self.engine, self.request)['status'], 'NO_JOB')
        self.assert_code('ONBOARDING_CONFIGURATION_SOURCE_CHANGED', self.inspect)
        self.assertEqual(self.store.read(ROOT/'data/demo/public/config/settings.yaml'), b'foreign-after-complete\n')

    def test_private_binding_plans_are_rejected_before_readback_or_writes(self):
        child = self.next['components'][0]
        child['private_bindings'] = {'ApiToken': {'folder': '/demo', 'key': 'ApiToken'}}
        child['value_names'] = {'ApiToken': 'ApiToken'}
        child_service = yaml.safe_load('services:\n'+child['compose_fragment'])['services']['demo']
        child_service['env_file'].append('./.secrets/demo.env')
        child['compose_fragment'] = ''.join('  '+line+'\n' for line in yaml.safe_dump({'demo': child_service}, sort_keys=False).splitlines())
        self.next['private_bindings'] = copy.deepcopy(child['private_bindings'])
        self.next['compose_fragment'] = child['compose_fragment'] + self.next['components'][1]['compose_fragment']
        self.assert_code('ONBOARDING_CONFIGURATION_SCOPE_REQUIRED', self.inspect)
        self.assertFalse(self.runner.preflights)
        self.assertFalse(self.store.writes)

    def test_full_public_readback_and_new_backup_can_finalize_same_journal(self):
        self.apply()
        normalized, _ = remote.plan_document(self.next)
        self.runner.public_files = {'docker-compose.yml': self.store.read(ROOT/'docker-compose.yml'),
            'config/service-resources.json': self.store.read(ROOT/'config/service-resources.json')}
        locks, override = {}, {'services': {}}
        for child in remote.components(normalized):
            self.runner.public_files[child['public_env_path']] = child['public_env_text'].encode()
            pinned = child['image'].rsplit(':', 1)[0]+'@sha256:'+'3'*64
            locks[child['service_name']] = {'image': pinned, 'configured_image': child['image'], 'platform': 'linux/amd64'}
            override['services'][child['service_name']] = {'image': pinned}
        for row in normalized['configuration_files']:
            self.runner.public_files[row['path']] = row['content'].encode()
        self.runner.public_files['config/image-lock.json'] = json.dumps(locks).encode()
        self.runner.public_files['config/compose.dr.yaml'] = json.dumps(override).encode()
        result = self.engine.finalize(self.request)
        self.assertEqual(result['status'], 'BACKUP_RUNNING')
        result = self.engine.finalize(self.request)
        self.assertEqual(result['status'], 'COMPLETE')
        self.assertTrue(result['backup_integrity_verified'])
        self.assertEqual(self.journal()['kind'], 'configuration')
        self.assertTrue(self.journal()['configuration_updated'])

    def test_local_lab_skips_public_api_and_worker_locks(self):
        self.request['verification_scope'] = 'local_lab'
        self.store.directory(LAYOUT.state, 0, 0, 0o700, create=True)
        marker = dict(schema=1, kind='prepared_onboarding_lab', root=str(ROOT), owner=LAYOUT.user,
            machine_id=self.store.read('/etc/machine-id').decode().strip(), publications_disabled=True)
        self.store.put(LAYOUT.state/'lab.json', json.dumps(marker).encode())
        with patch.object(self.runner, 'api', side_effect=AssertionError('No GitHub in local lab')):
            result = self.apply()
        self.assertEqual(result['status'], 'SERVICE_READY')
        self.assertEqual(self.runner.preflights, [])
        self.assert_no_lifecycle()


class WorkerLockTests(unittest.TestCase):
    def setUp(self):
        self.engine = SimpleNamespace(verification_scope='full', layout=LAYOUT,
            store=SimpleNamespace(safe=lambda path: path), request_identity=remote.Engine.request_identity.__get__(None, remote.Engine))
        # A normal bound Engine method supplies the API globals without imports.
        self.engine.request_identity = remote.Engine.request_identity.__get__(self.engine, type(self.engine))
        self.opened, self.closed, self.locked = [], [], []
        self.fcntl = SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=lambda fd, mode: self.locked.append((fd, mode)))

    def run_locks(self, info=None):
        info = info or SimpleNamespace(st_mode=stat.S_IFREG|0o640, st_nlink=1, st_uid=LAYOUT.uid)
        def opening(path, flags):
            self.opened.append((str(path), flags))
            return len(self.opened)
        with patch.dict(sys.modules, {'fcntl': self.fcntl}), patch.object(update.os, 'open', opening), \
                patch.object(update.os, 'fstat', return_value=info), patch.object(update.os, 'close', self.closed.append):
            with update._worker_locks(self.engine): pass

    def test_lock_order_is_dr_then_public_and_all_nonblocking(self):
        self.run_locks()
        self.assertIn('/streams-aio-dr/', self.opened[0][0])
        self.assertIn('/streams-aio-public-sync/', self.opened[1][0])
        self.assertEqual(self.locked, [(1, 6), (2, 6)])
        self.assertEqual(self.closed, [2, 1])

    def test_invalid_lock_owner_is_refused_and_fd_closed(self):
        with self.assertRaisesRegex(remote.Refused, '^ONBOARDING_CONFIGURATION_LOCK_INVALID$'):
            self.run_locks(SimpleNamespace(st_mode=stat.S_IFREG|0o640, st_nlink=1, st_uid=999))
        self.assertEqual(self.closed, [1])

    def test_busy_second_lock_releases_every_fd(self):
        def lock(fd, mode):
            if fd == 2: raise BlockingIOError()
        self.fcntl.flock = lock
        with self.assertRaisesRegex(remote.Refused, '^ONBOARDING_OTHER_OPERATION_RUNNING$'): self.run_locks()
        self.assertEqual(self.closed, [2, 1])


if __name__ == '__main__':
    unittest.main()

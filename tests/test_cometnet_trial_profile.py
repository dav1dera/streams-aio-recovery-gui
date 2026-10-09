"""Meaningful transaction and scope regressions for the local CometNet trial."""
import copy
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cometnet_trial_policy', ROOT/'remote/runtime_profile.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
fixture_spec = importlib.util.spec_from_file_location('cometnet_trial_base_fixture', ROOT/'tests/test_runtime_profile.py')
fixtures = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixtures)


class TrialProfile(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)/'stack'
        self.home = Path(self.temporary.name)/'runner'
        (self.root/'.generated').mkdir(parents=True)
        (self.home/'runtime-profile').mkdir(parents=True)
        names = ('docker-compose.yml', 'config/compose.dr.yaml', 'config/dr-manifest.yaml',
                 'data/postgres/.env', 'data/postgres/postgresql.conf', 'data/postgres/init/init.sql',
                 'data/dnscrypt-proxy/data/dnscrypt-proxy.toml', 'data/oauth2-proxy/allowed-emails.txt',
                 'data/pgbouncer/data/pgbouncer.ini', '.generated/pgbouncer/userlist.txt', 'scripts/dr.py')
        for name in names:
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('synthetic private source: ' + name).encode())
        self.base = fixtures.model(self.root, first_boot=True)
        self.base['services']['comet'].update(image=policy.COMETNET_IMAGE,
            environment={'DATABASE_URL': 'postgresql://private-user:private-password@postgres/private-db'})
        self.base['services']['gluetun'] = dict(image='synthetic-pinned-gluetun')
        self.base['services']['cometnet'] = dict(image=policy.COMETNET_IMAGE,
            entrypoint=['python', '-m', 'comet.cometnet.standalone'], network_mode='service:gluetun',
            user='1000:1000', healthcheck={'test': ['CMD', 'public-health-probe']},
            environment={'COMETNET_ADVERTISE_URL': 'wss://private-original.example/cometnet',
                         'COMETNET_LISTEN_PORT':'8765', 'COMETNET_HTTP_PORT':'8766',
                         'DATABASE_URL': 'postgresql://private-user:private-password@postgres/private-db'})
        self.model = fixtures.effective(self.root, self.base, first_boot=True)
        self.base_env = ("PRIVATE_ROOT=private-root-value\nCOMPOSE_FILE='" + policy.BASE_COMPOSE + "'\n").encode()
        self.effective_env = policy.compose_line(self.base_env, policy.BASE_COMPOSE, policy.EFFECTIVE_COMPOSE)
        (self.root/'.env').write_bytes(self.effective_env)
        (self.home/policy.BACKUP).write_bytes(self.base_env)
        self.old_artifact = policy.overlay(self.root, first_boot=True)
        (self.root/policy.ARTIFACT).write_bytes(self.old_artifact)
        self.state = dict(schema=1, completed=sorted(policy.FIRST_BOOT_STAGES | {'NPM', 'AIO'}),
            preparation='PASS', application_start_attempted=True, application_wave=['cometnet'],
            application_recovery='NOT_VERIFIED', aio_recovery='MANUAL_PENDING',
            native_agent={'completed': True, 'private_hash': 'preserved-agent-hash'},
            runtime_profile=dict(schema=1, id=policy.FIRST_BOOT_PROFILE, origin='FIRST_BOOT',
                artifact=policy.ARTIFACT, artifact_sha256=policy.sha(self.old_artifact),
                base_env_sha256=policy.sha(self.base_env), effective_env_sha256=policy.sha(self.effective_env),
                env_backup=policy.BACKUP, source_hashes=policy.source_hashes(self.root, first_boot=True),
                preserved_volumes={'pgdata':'streams-aio_pgdata', 'postgres-cluster':'streams-aio_postgres-cluster'}))
        self.save_state()
        self.containers = [dict(Id=format(index, '064x'), Config=dict(Image=policy.COMETNET_IMAGE,
            Labels={'com.docker.compose.project':'streams-aio',
                    'com.docker.compose.project.working_dir':str(self.root),
                    'com.docker.compose.service':name}))
            for index, name in enumerate(('postgres', 'pgbouncer', 'gluetun', 'comet', 'cometnet'), 1)]
        self.volumes = [dict(Name='streams-aio_' + key, Driver='local', Options=None,
            Mountpoint=str(policy.DOCKER_VOLUME_ROOT/('streams-aio_' + key)/'_data'),
            Labels={'com.docker.compose.project':'streams-aio', 'com.docker.compose.volume':key})
            for key in ('pgdata', 'postgres-cluster')]
        self.calls = []
        self.writes = []
        self.fail_state_commit = False
        self.fail_artifact_commit = False
        self.bad_candidate = False
        self.resource_race = False
        self.drift_after_candidate = False
        self.patches = [patch.object(policy, 'identity_scope',
                    lambda root, home, state: (Path(root), Path(home))),
                patch.object(policy, 'regular', self.file_info),
                patch.object(policy, 'private_directory', lambda path: None),
                patch.object(policy, 'atomic', self.atomic)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def save_state(self):
        (self.home/'state.json').write_bytes((json.dumps(self.state, indent=2) + '\n').encode())

    def file_info(self, path):
        path = Path(path)
        self.assertTrue(path.is_file())
        if path == self.root/'.env':
            uid, gid, mode = 0, 1000, 0o640
        elif path in (self.root/policy.ARTIFACT, self.root/policy.TRIAL_PASSWORD):
            uid, gid, mode = 1000, 1000, 0o600
        else:
            uid, gid, mode = 0, 0, 0o600
        return SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=stat.S_IFREG | mode, st_nlink=1)

    def atomic(self, path, raw, mode, uid, gid):
        path = Path(path)
        self.writes.append((path, mode, uid, gid))
        if path == self.home/'state.json' and self.fail_state_commit:
            self.fail_state_commit = False
            raise OSError('synthetic checkpoint commit failure')
        if path == self.root/policy.ARTIFACT and raw != self.old_artifact and self.fail_artifact_commit:
            self.fail_artifact_commit = False
            raise OSError('synthetic overlay commit failure')
        path.write_bytes(raw)

    def runner(self, args):
        self.calls.append(args)
        self.assertFalse(any(value in args for value in ('up', 'stop', 'down', 'rm', 'exec')))
        if args[:3] == ['docker', 'compose', '--profile']:
            return json.dumps(self.model).encode()
        if args[:3] == ['docker', 'compose', '--env-file']:
            path = Path(args[args.index('-f', args.index('-f', args.index('-f') + 1) + 1) + 1])
            text = path.read_text()
            password = json.loads(next(line.split(': ', 1)[1] for line in text.splitlines()
                                       if line.strip().startswith('COMETNET_NETWORK_PASSWORD:')))
            desired = copy.deepcopy(self.model)
            desired['services']['cometnet']['environment'].update(policy.COMETNET_TRIAL_ENV)
            desired['services']['cometnet']['environment']['COMETNET_NETWORK_PASSWORD'] = password
            if self.bad_candidate:
                desired['services']['comet']['environment']['DATABASE_URL'] = 'changed-secret'
            if self.resource_race:
                self.containers[-1]['Id'] = 'f'*64
            if self.drift_after_candidate:
                (self.root/'data/postgres/init/init.sql').write_bytes(b'changed private SQL')
            return json.dumps(desired).encode()
        if args == ['docker', 'ps', '-aq']:
            return ('\n'.join(row['Id'] for row in self.containers)).encode()
        if args[:2] == ['docker', 'inspect']:
            return json.dumps(self.containers).encode()
        if args == ['docker', 'volume', 'ls', '-q']:
            return ('\n'.join(row['Name'] for row in self.volumes)).encode()
        if args[:3] == ['docker', 'volume', 'inspect']:
            return json.dumps(self.volumes).encode()
        self.fail('Unexpected runtime operation')

    def migrate(self, **kwargs):
        return policy.migrate_cometnet_trial(self.root, self.home, self.state, self.model, self.runner, **kwargs)

    def test_v1_still_validates_identical_bytes_without_trial_password(self):
        self.assertTrue(policy.validate(self.root, self.home, self.state))

    def test_trial_listener_and_health_ports_must_match_the_pinned_public_values(self):
        for key, value in (('COMETNET_LISTEN_PORT','9999'), ('COMETNET_HTTP_PORT','8765'),
                           ('COMETNET_HTTP_PORT',None)):
            with self.subTest(key=key,value=value):
                changed = copy.deepcopy(self.model)
                changed['services']['cometnet']['environment'][key] = value
                with self.assertRaisesRegex(policy.Refused,'COMETNET_TRIAL_SCOPE_REFUSED'):
                    policy.cometnet_trial_model(changed)
        policy.cometnet_trial_model(self.model)
        self.assertEqual((self.root/policy.ARTIFACT).read_bytes(), self.old_artifact)

    def test_migration_preserves_private_sources_pointer_agent_and_completion_flags(self):
        before = copy.deepcopy(self.state)
        before_sources = policy.source_hashes(self.root, first_boot=True)
        before_runtime = copy.deepcopy((self.containers, self.volumes))
        result = self.migrate()
        self.assertEqual(result, dict(applied=True, profile=policy.COMETNET_TRIAL_PROFILE))
        self.assertEqual({key:value for key,value in self.state.items() if key != 'runtime_profile'},
                         {key:value for key,value in before.items() if key != 'runtime_profile'})
        self.assertEqual(policy.source_hashes(self.root, first_boot=True), before_sources)
        self.assertEqual((self.root/'.env').read_bytes(), self.effective_env)
        self.assertEqual((self.containers, self.volumes), before_runtime)
        password = (self.root/policy.TRIAL_PASSWORD).read_bytes()
        self.assertRegex(password, rb'^[0-9a-f]{64}\n$')
        self.assertNotIn(password[:-1].decode(), json.dumps(self.state))
        self.assertTrue(policy.validate(self.root, self.home, self.state))
        archived = list((self.home/policy.COMETNET_MIGRATION_BACKUP).iterdir())
        self.assertEqual(len(archived), 1)
        self.assertEqual((archived[0]/'runtime.compose.yaml').read_bytes(), self.old_artifact)
        self.assertEqual(json.loads((archived[0]/'state.json').read_bytes()), before)
        for path, mode, uid, gid in self.writes:
            if path.is_relative_to(self.home/policy.COMETNET_MIGRATION_BACKUP):
                self.assertEqual((mode, uid, gid), (0o600, 0, 0))

    def test_idempotent_v2_reuses_password_without_runtime_calls(self):
        self.migrate()
        password = (self.root/policy.TRIAL_PASSWORD).read_bytes()
        result = policy.migrate_cometnet_trial(self.root, self.home, self.state, {},
            lambda args:self.fail('Idempotent migration must not query or change Docker'))
        self.assertEqual(result, dict(applied=False, profile=policy.COMETNET_TRIAL_PROFILE))
        self.assertEqual((self.root/policy.TRIAL_PASSWORD).read_bytes(), password)

    def test_wrong_phase_complete_recovery_or_tls_refuses_before_writes(self):
        original = copy.deepcopy(self.state)
        changes = ({'preparation':None}, {'application_start_attempted':1},
                   {'application_wave':['comet']}, {'application_recovery':'STARTED_NEEDS_FUNCTIONAL_TEST'},
                   {'tls_verified':True}, {'tls_verified':0})
        for changed in changes:
            with self.subTest(changed=changed):
                self.state = {**copy.deepcopy(original), **changed}
                self.save_state()
                with self.assertRaisesRegex(policy.Refused, 'COMETNET_TRIAL_SCOPE_REFUSED'):
                    self.migrate()
                self.assertEqual(self.writes, [])
        self.state = original
        self.save_state()
        with self.assertRaisesRegex(policy.Refused, 'COMETNET_TRIAL_TLS_REFUSED'):
            self.migrate(tls=True)
        self.assertEqual(self.writes, [])

    def test_unstarted_prepared_v1_migrates_only_with_no_resources(self):
        self.state['application_start_attempted'] = False
        self.state.pop('application_wave')
        self.save_state()
        with self.assertRaisesRegex(policy.Refused, 'COMETNET_TRIAL_SCOPE_REFUSED'):
            self.migrate()
        self.assertEqual(self.writes, [])
        self.containers, self.volumes = [], []
        self.assertEqual(self.migrate()['profile'], policy.COMETNET_TRIAL_PROFILE)

    def test_foreign_container_or_volume_refuses_before_private_backup(self):
        for rows in (self.containers, self.volumes):
            row = rows[0]
            labels = row['Config']['Labels'] if rows is self.containers else row['Labels']
            labels['com.docker.compose.project'] = 'foreign-private-project'
            with self.assertRaisesRegex(policy.Refused, 'DOCKER_OWNERSHIP_REFUSED'):
                self.migrate()
            labels['com.docker.compose.project'] = 'streams-aio'
            self.assertEqual(self.writes, [])

    def test_candidate_may_not_change_database_credentials_other_services_or_health(self):
        self.bad_candidate = True
        original = (self.home/'state.json').read_bytes()
        with self.assertRaisesRegex(policy.Refused, 'CANDIDATE_REFUSED'):
            self.migrate()
        self.assertEqual((self.home/'state.json').read_bytes(), original)
        self.assertEqual((self.root/policy.ARTIFACT).read_bytes(), self.old_artifact)
        self.assertFalse((self.root/policy.TRIAL_PASSWORD).exists())

    def test_failed_state_or_artifact_commit_rolls_back_and_preserves_backup(self):
        original = (self.home/'state.json').read_bytes()
        for attribute in ('fail_artifact_commit', 'fail_state_commit'):
            with self.subTest(attribute=attribute):
                setattr(self, attribute, True)
                with self.assertRaisesRegex(policy.Refused, 'COMETNET_TRIAL_TRANSACTION_FAILED'):
                    self.migrate()
                self.assertEqual((self.home/'state.json').read_bytes(), original)
                self.assertEqual((self.root/policy.ARTIFACT).read_bytes(), self.old_artifact)
                self.assertEqual((self.root/'.env').read_bytes(), self.effective_env)
                self.assertFalse((self.root/policy.TRIAL_PASSWORD).exists())
                self.assertTrue(policy.validate(self.root, self.home, self.state))
                self.assertTrue(list((self.home/policy.COMETNET_MIGRATION_BACKUP).iterdir()))

    def test_second_ownership_check_detects_container_replacement(self):
        self.resource_race = True
        original = (self.home/'state.json').read_bytes()
        with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_CHANGED'):
            self.migrate()
        self.assertEqual((self.home/'state.json').read_bytes(), original)
        self.assertFalse((self.root/policy.TRIAL_PASSWORD).exists())

    def test_second_source_check_detects_private_source_drift(self):
        self.drift_after_candidate = True
        original = (self.home/'state.json').read_bytes()
        with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_SOURCE_CHANGED'):
            self.migrate()
        self.assertEqual((self.home/'state.json').read_bytes(), original)
        self.assertEqual((self.root/policy.ARTIFACT).read_bytes(), self.old_artifact)
        self.assertFalse((self.root/policy.TRIAL_PASSWORD).exists())

    def test_private_password_or_overlay_tampering_is_refused(self):
        self.migrate()
        path = self.root/policy.TRIAL_PASSWORD
        original = path.read_bytes()
        path.write_bytes(b'0'*64+b'\n')
        with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_CHANGED'):
            policy.validate(self.root, self.home, self.state)
        path.write_bytes(original)
        artifact = self.root/policy.ARTIFACT
        artifact.write_bytes(artifact.read_bytes()+b' # unauthorized drift\n')
        with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_CHANGED'):
            policy.validate(self.root, self.home, self.state)

    def test_orphan_password_is_not_adopted_by_v1(self):
        (self.root/policy.TRIAL_PASSWORD).write_bytes(b'1'*64+b'\n')
        with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_CHANGED'):
            policy.validate(self.root, self.home, self.state)

    def prepare_empty_fresh_checkpoint(self):
        (self.root/policy.ARTIFACT).unlink()
        (self.root/'.env').write_bytes(self.base_env)
        self.state.pop('runtime_profile')
        self.state['application_start_attempted'] = False
        self.state.pop('application_wave')
        self.save_state()

    def test_new_fresh_restore_creates_v2_and_private_password_before_any_container(self):
        self.prepare_empty_fresh_checkpoint()
        before = copy.deepcopy(self.state)
        with patch.object(policy, 'readonly_first_boot_checks', return_value={
                'pgdata':'streams-aio_pgdata', 'postgres-cluster':'streams-aio_postgres-cluster'}) as inspections:
            result = policy.apply_fresh(self.root, self.home, self.state, self.base, self.runner)
        self.assertEqual(result, dict(applied=True, profile=policy.COMETNET_TRIAL_PROFILE))
        self.assertEqual(inspections.call_count, 2)
        self.assertEqual({key:value for key,value in self.state.items() if key != 'runtime_profile'}, before)
        self.assertTrue(policy.validate(self.root, self.home, self.state))
        self.assertNotIn('COMETNET_NETWORK_PASSWORD', json.dumps(self.state))
        self.assertFalse(any(args[:3] == ['docker', 'ps', '-aq'] for args in self.calls))
        password_write = next(row for row in self.writes if row[0] == self.root/policy.TRIAL_PASSWORD)
        self.assertEqual(password_write[1:], (0o600, 1000, 1000))

    def test_failed_fresh_commit_removes_only_uncommitted_password_and_overlay(self):
        self.prepare_empty_fresh_checkpoint()
        original_state = (self.home/'state.json').read_bytes()
        original_sources = policy.source_hashes(self.root, first_boot=True)
        self.fail_state_commit = True
        with patch.object(policy, 'readonly_first_boot_checks', return_value={
                'pgdata':'streams-aio_pgdata', 'postgres-cluster':'streams-aio_postgres-cluster'}):
            with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_TRANSACTION_FAILED'):
                policy.apply_fresh(self.root, self.home, self.state, self.base, self.runner)
        self.assertEqual((self.home/'state.json').read_bytes(), original_state)
        self.assertEqual((self.root/'.env').read_bytes(), self.base_env)
        self.assertEqual(policy.source_hashes(self.root, first_boot=True), original_sources)
        self.assertFalse((self.root/policy.TRIAL_PASSWORD).exists())
        self.assertFalse((self.root/policy.ARTIFACT).exists())

    def test_trial_password_permissions_and_closed_record_fields_are_rechecked(self):
        self.migrate()
        original_regular = policy.regular
        def bad_mode(path):
            info = original_regular(path)
            if Path(path) == self.root/policy.TRIAL_PASSWORD:
                info.st_mode = stat.S_IFREG | 0o644
            return info
        with patch.object(policy, 'regular', bad_mode):
            with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_CHANGED'):
                policy.validate(self.root, self.home, self.state)
        self.state['runtime_profile']['password_value'] = 'private-not-allowed'
        self.save_state()
        with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_CHANGED'):
            policy.validate(self.root, self.home, self.state)


if __name__ == '__main__':
    unittest.main()

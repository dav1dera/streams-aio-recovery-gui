"""Native SQLite round trips and fail-closed encrypted-capsule boundaries."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_aio_test', ROOT / 'remote/aio_snapshot.py')
aio = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aio)
RUN = '20261009T120000Z'
COMMIT = 'c' * 40


def deployment_fixture():
    routes = [{'table':'proxy_host', 'id':1, 'routing':{'domain_names':['aio.example.invalid'],
        'forward_host':'192.0.2.11', 'forward_port':3000, 'forward_scheme':'http',
        'locations':[], 'advanced_config':''}}]
    return {'schema':1, 'format':'streams-aio-npm-topology', 'stack_commit':COMMIT,
        'source':{'stack_addresses':['192.0.2.11'], 'infisical_address':'192.0.2.28','infisical_port':80},
        'routes':routes, 'bindings':[{'table':'proxy_host','id':1,'path':['forward_host'],
            'role':'stack','service':'aiostreams'}], 'routes_sha256':hashlib.sha256(aio.canonical(routes)).hexdigest()}


class NativeAIO(unittest.TestCase):
    def setUp(self):
        if os.name == 'nt':
            # Remote deployment uses Linux hard links. The desktop sandbox
            # disallows creating hard links, so these portable SQLite/contract
            # tests use an exclusive copy with the same no-replace semantics.
            # The actual Linux hard-link primitive has its own integration test.
            def exclusive_copy(source, target):
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'wb') as out, open(source, 'rb') as inp:
                    shutil.copyfileobj(inp, out)
            link_patch = patch.object(aio.os, 'link', side_effect=exclusive_copy)
            link_patch.start()
            self.addCleanup(link_patch.stop)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source, self.target = self.base / 'source', self.base / 'target'
        self.source.mkdir()
        self.target.mkdir()
        self.archive = self.base / 'aio-state.tar.gz'
        self.containers = []
        for service in aio.SERVICES:
            path = self.source / aio.PATHS[service]
            path.parent.mkdir(parents=True)
            with contextlib.closing(sqlite3.connect(path)) as db:
                if service == 'aiostreams':
                    db.executescript("CREATE TABLE users(uuid TEXT PRIMARY KEY,password_hash TEXT,config TEXT,config_salt TEXT);"
                                     "INSERT INTO users VALUES('same-uuid','same-bcrypt','same-encrypted-profile','same-salt');"
                                     "CREATE TABLE config_profiles(id TEXT,owner TEXT,encrypted_password TEXT,alias TEXT);"
                                     "INSERT INTO config_profiles VALUES('same-profile','same-owner','same-password','same-alias');"
                                     "CREATE TABLE linked_accounts(id TEXT, token TEXT);"
                                     "INSERT INTO linked_accounts VALUES('same-link','same-token');")
                else:
                    db.executescript("CREATE TABLE user_configs(user_uuid TEXT PRIMARY KEY,password_hash TEXT,config_data TEXT);"
                                     "INSERT INTO user_configs VALUES('same-metadata-uuid','same-bcrypt','same-config');"
                                     "CREATE TABLE oauth_tokens(id TEXT,token TEXT);"
                                     "INSERT INTO oauth_tokens VALUES('same-oauth','same-refresh-token');"
                                     "CREATE TABLE user_aliases(alias TEXT,user_uuid TEXT);"
                                     "INSERT INTO user_aliases VALUES('same-alias','same-metadata-uuid');")
                db.execute('PRAGMA user_version=37')
                db.commit()
            path.chmod(0o600)
        self.model = self.model_for(self.source)
        for index, service in enumerate(aio.SERVICES):
            self.containers.append({'Id': 'c' + str(index), 'Image': 'sha256:' + str(index) * 64,
                'Config': {'Env': [k + '=' + v for k, v in self.model['services'][service]['environment'].items()],
                           'Labels': {'com.docker.compose.service': service,
                                      'com.docker.compose.project.working_dir': str(self.source)}},
                'State': {'Running': True, 'Paused': False, 'StartedAt': '2026-10-09T10:00:00Z'},
                'Mounts': [{'Type': 'bind', 'Source': str((self.source / aio.PATHS[service]).parent),
                            'Destination': aio.TARGETS[service]}]})

    def model_for(self, root):
        return {'services': {service: {'image': 'example/' + service + '@sha256:' + str(index + 1) * 64,
            'environment': {'DATABASE_URI': sorted(aio.URIS[service])[0], 'SECRET_KEY': 'private-key',
                            'JWT_SECRET': 'private-jwt', 'HOST_NAME': 'https://private-domain.invalid'},
            'volumes': [{'type': 'bind', 'source': str((root / aio.PATHS[service]).parent),
                         'target': aio.TARGETS[service]}]} for index, service in enumerate(aio.SERVICES)}}

    def live(self, args, code):
        if args[:3] == ['docker', 'ps', '-aq']:
            return b'c0 c1'
        if args[:2] == ['docker', 'inspect']:
            return json.dumps(self.containers).encode()
        if args[:3] == ['docker', 'image', 'inspect']:
            index = 0 if args[-1] == 'sha256:' + '0' * 64 else 1
            return json.dumps({'Id': self.containers[index]['Image'],
                'RepoDigests': [self.model['services'][aio.SERVICES[index]]['image']]}).encode()
        self.fail('Unexpected command shape')

    def empty(self, args, code):
        self.assertEqual(args, ['docker', 'ps', '-aq'])
        return b''

    def capture(self, **kwargs):
        return aio.capture_capsule(self.source, self.archive, run_id=RUN, source_commit=COMMIT,
                                   model=self.model, run=self.live, **kwargs)

    def restore(self, **kwargs):
        return aio.restore_capsule(self.archive, self.target, run_id=RUN, source_commit=COMMIT,
            model=kwargs.pop('model', self.model_for(self.target)), run=kwargs.pop('run', self.empty),
            uid=os.getuid() if hasattr(os, 'getuid') else 1000,
            gid=os.getgid() if hasattr(os, 'getgid') else 1000, **kwargs)

    def refusal(self, code, action):
        with self.assertRaisesRegex(aio.Refused, '^' + code + '$'):
            action()

    def assert_no_installed(self):
        self.assertFalse((self.target / aio.MARKER).exists())
        for path in aio.PATHS.values():
            self.assertFalse((self.target / path).exists())

    def test_native_roundtrip_preserves_all_profile_password_oauth_bytes(self):
        manifest = self.capture()
        evidence = self.restore()
        self.assertEqual(manifest['applications'], evidence['applications'])
        for service, rel in aio.PATHS.items():
            # SQLite's online backup may rewrite header change counters; all
            # original schema and row values are preserved natively.
            with contextlib.closing(sqlite3.connect(self.source / rel)) as source, contextlib.closing(
                    sqlite3.connect(self.target / rel)) as target:
                tables = source.execute("SELECT name FROM sqlite_schema WHERE type='table'").fetchall()
                for (table,) in tables:
                    self.assertEqual(source.execute('SELECT * FROM "' + table + '"').fetchall(),
                                     target.execute('SELECT * FROM "' + table + '"').fetchall())
        self.assertTrue(aio.verify_restored(self.target, evidence, self.model_for(self.target), before_start=True,
            uid=os.getuid() if hasattr(os, 'getuid') else 1000, gid=os.getgid() if hasattr(os, 'getgid') else 1000))
        self.assertFalse((self.target / '.generated/aio-import-complete.json').exists())
        self.assertNotIn('versions', evidence)
        encoded = json.dumps(evidence)
        self.assertNotIn('private-key', encoded)
        self.assertNotIn('same-token', encoded)
        self.assertNotIn('same-uuid', encoded)

    def test_online_wal_snapshot_includes_committed_records(self):
        path = self.source / aio.PATHS['aiostreams']
        with contextlib.closing(sqlite3.connect(path)) as writer:
            writer.execute('PRAGMA journal_mode=WAL')
            writer.execute("INSERT INTO users VALUES('committed-in-wal','hash','encrypted','salt')")
            writer.commit()
            self.assertTrue(Path(str(path) + '-wal').exists())
            original = path.read_bytes()
            self.capture()
            self.assertEqual(original, path.read_bytes())
            self.restore()
            with contextlib.closing(sqlite3.connect(self.target / aio.PATHS['aiostreams'])) as restored:
                self.assertEqual(restored.execute('SELECT count(*) FROM users').fetchone()[0], 2)

    def test_private_deployment_roundtrip_is_exact_root_control_evidence(self):
        value = deployment_fixture()
        manifest = self.capture(deployment=value)
        evidence = self.restore()
        path = self.target / aio.DEPLOYMENT
        self.assertEqual(json.loads(path.read_bytes()), value)
        self.assertEqual(manifest['deployment'], evidence['deployment'])
        self.assertEqual(aio.digest(path), evidence['deployment']['sha256'])
        self.assertNotIn('aio.example.invalid', json.dumps(evidence))
        self.assertTrue(aio.verify_restored(self.target, evidence, self.model_for(self.target), before_start=True,
            uid=os.getuid() if hasattr(os, 'getuid') else 1000, gid=os.getgid() if hasattr(os, 'getgid') else 1000))
        if os.name != 'nt':
            self.assertEqual((path.stat().st_uid, path.stat().st_gid, path.stat().st_mode & 0o777),
                             (os.geteuid(), os.getegid(), 0o600))

    def test_changed_private_deployment_is_refused_on_prestart(self):
        self.capture(deployment=deployment_fixture())
        evidence = self.restore()
        (self.target / aio.DEPLOYMENT).write_bytes(b'{}\n')
        self.refusal('AIO_SNAPSHOT_DEPLOYMENT_INVALID', lambda: aio.verify_restored(
            self.target, evidence, self.model_for(self.target), before_start=True))

    def test_capsule_cannot_omit_declared_deployment_member(self):
        self.capture(deployment=deployment_fixture())
        self.rewrite(lambda files: files.pop('deployment.json'))
        self.refusal('AIO_SNAPSHOT_ARCHIVE_UNSAFE', self.restore)
        self.assert_no_installed()

    def test_capsule_rejects_deployment_for_other_public_commit(self):
        value = deployment_fixture();value['stack_commit'] = 'd' * 40
        self.refusal('AIO_SNAPSHOT_DEPLOYMENT_INVALID', lambda: self.capture(deployment=value))
        self.assertFalse(self.archive.exists())

    def test_current_uppercase_sqlite_tables_preserve_schema_and_canonical_counts(self):
        before = aio.database_metadata(self.source / aio.PATHS['aiostreams'], 'aiostreams')
        for service, name in (('aiostreams', 'users'), ('aiometadata', 'user_configs')):
            with contextlib.closing(sqlite3.connect(self.source / aio.PATHS[service])) as db:
                db.execute('ALTER TABLE "' + name + '" RENAME TO temporary_case_conversion')
                db.execute('ALTER TABLE temporary_case_conversion RENAME TO "' + name.upper() + '"')
                db.commit()
        manifest = self.capture()
        self.assertEqual(manifest['applications']['aiostreams']['required_counts'], {'users': 1})
        self.assertEqual(manifest['applications']['aiometadata']['required_counts'], {'user_configs': 1})
        self.assertNotEqual(manifest['applications']['aiostreams']['schema_sha256'], before['schema_sha256'])
        evidence = self.restore()
        for service, name in (('aiostreams', 'USERS'), ('aiometadata', 'USER_CONFIGS')):
            with contextlib.closing(sqlite3.connect(self.target / aio.PATHS[service])) as db:
                self.assertEqual(db.execute('SELECT name FROM sqlite_schema WHERE name=?', (name,)).fetchone(), (name,))
                self.assertEqual(db.execute('SELECT count(*) FROM "' + name + '"').fetchone()[0], 1)
        self.assertTrue(aio.verify_restored(self.target, evidence, self.model_for(self.target), before_start=True,
            uid=os.getuid() if hasattr(os, 'getuid') else 1000, gid=os.getgid() if hasattr(os, 'getgid') else 1000))

    def test_source_image_mismatch_refuses_without_archive(self):
        self.model['services']['aiostreams']['image'] = 'example/aiostreams@sha256:' + '9' * 64
        original = self.live
        def run(args, code):
            result = original(args, code)
            if args[:3] == ['docker', 'image', 'inspect']:
                image = json.loads(result)
                image['RepoDigests'] = ['example/aiostreams@sha256:' + '1' * 64]
                return json.dumps(image).encode()
            return result
        self.refusal('AIO_SNAPSHOT_SOURCE_IMAGE_CHANGED', lambda: aio.capture_capsule(
            self.source, self.archive, run_id=RUN, source_commit=COMMIT, model=self.model, run=run))
        self.assertFalse(self.archive.exists())

    def test_source_recreated_during_capture_is_inconsistent(self):
        calls = 0
        def run(args, code):
            nonlocal calls
            if args[:2] == ['docker', 'inspect']:
                calls += 1
                if calls == 2:
                    self.containers[0]['Id'] = 'replaced'
            return self.live(args, code)
        self.refusal('AIO_SNAPSHOT_SOURCE_CHANGED', lambda: aio.capture_capsule(
            self.source, self.archive, run_id=RUN, source_commit=COMMIT, model=self.model, run=run))
        self.assertFalse(self.archive.exists())

    def test_source_env_drift_refuses(self):
        self.containers[0]['Config']['Env'] = ['SECRET_KEY=wrong']
        self.refusal('AIO_SNAPSHOT_SOURCE_ENV_CHANGED', self.capture)
        self.assertFalse(self.archive.exists())

    def test_database_corruption_is_detected_before_install(self):
        (self.source / aio.PATHS['aiometadata']).write_bytes(b'private-broken-database')
        self.refusal('AIO_SNAPSHOT_DATABASE_INVALID', self.capture)
        self.assertFalse(self.archive.exists())

    def test_empty_profile_table_is_not_a_complete_backup(self):
        with contextlib.closing(sqlite3.connect(self.source / aio.PATHS['aiostreams'])) as db:
            db.execute('DELETE FROM users')
            db.commit()
        self.refusal('AIO_SNAPSHOT_CONFIGURATION_MISSING', self.capture)
        self.assertFalse(self.archive.exists())

    def test_foreign_key_corruption_refuses(self):
        with contextlib.closing(sqlite3.connect(self.source / aio.PATHS['aiostreams'])) as db:
            db.executescript("CREATE TABLE dependencies(user TEXT REFERENCES users(uuid));"
                             "INSERT INTO dependencies VALUES('missing-user');")
        self.refusal('AIO_SNAPSHOT_FOREIGN_KEY_INVALID', self.capture)

    def test_restore_refuses_different_image_and_preserves_empty_target(self):
        self.capture()
        model = self.model_for(self.target)
        model['services']['aiometadata']['image'] = 'example/aiometadata@sha256:' + '9' * 64
        self.refusal('AIO_SNAPSHOT_IMAGE_MISMATCH', lambda: self.restore(model=model))
        self.assert_no_installed()

    def test_restore_refuses_different_secret_key(self):
        self.capture()
        model = self.model_for(self.target)
        model['services']['aiostreams']['environment']['SECRET_KEY'] = 'changed'
        self.refusal('AIO_SNAPSHOT_ENCRYPTION_KEY_MISMATCH', lambda: self.restore(model=model))
        self.assert_no_installed()

    def test_missing_empty_fanart_placeholder_matches_original_fingerprint(self):
        self.model['services']['aiometadata']['environment']['FANART_API_KEY'] = ''
        self.containers[1]['Config']['Env'].append('FANART_API_KEY=')
        manifest = self.capture()
        self.assertIn('FANART_API_KEY', manifest['applications']['aiometadata']['bindings']['keys'])
        model = self.model_for(self.target)
        evidence = self.restore(model=model)
        aio.verify_restored(self.target, evidence, model, before_start=True,
            uid=os.getuid() if hasattr(os, 'getuid') else 1000,
            gid=os.getgid() if hasattr(os, 'getgid') else 1000)
        self.assertEqual(evidence['applications'], manifest['applications'])

    def test_missing_nonempty_fanart_key_is_still_refused(self):
        self.model['services']['aiometadata']['environment']['FANART_API_KEY'] = 'private-fanart-value'
        self.containers[1]['Config']['Env'].append('FANART_API_KEY=private-fanart-value')
        self.capture()
        self.refusal('AIO_SNAPSHOT_ENCRYPTION_KEY_MISMATCH', self.restore)
        self.assert_no_installed()

    def test_changed_fanart_key_is_still_refused(self):
        self.model['services']['aiometadata']['environment']['FANART_API_KEY'] = ''
        self.containers[1]['Config']['Env'].append('FANART_API_KEY=')
        self.capture()
        model = self.model_for(self.target)
        model['services']['aiometadata']['environment']['FANART_API_KEY'] = 'different'
        self.refusal('AIO_SNAPSHOT_ENCRYPTION_KEY_MISMATCH', lambda: self.restore(model=model))
        self.assert_no_installed()

    def test_empty_fanart_compatibility_does_not_excuse_changed_encryption_key(self):
        self.model['services']['aiometadata']['environment']['FANART_API_KEY'] = ''
        self.containers[1]['Config']['Env'].append('FANART_API_KEY=')
        self.capture()
        model = self.model_for(self.target)
        model['services']['aiometadata']['environment']['JWT_SECRET'] = 'changed'
        self.refusal('AIO_SNAPSHOT_ENCRYPTION_KEY_MISMATCH', lambda: self.restore(model=model))
        self.assert_no_installed()

    def test_other_missing_empty_secrets_are_not_normalized(self):
        self.model['services']['aiometadata']['environment']['ANOTHER_SECRET'] = ''
        self.containers[1]['Config']['Env'].append('ANOTHER_SECRET=')
        self.capture()
        self.refusal('AIO_SNAPSHOT_ENCRYPTION_KEY_MISMATCH', self.restore)
        self.assert_no_installed()

    def test_wrong_snapshot_commit_and_run_refuse(self):
        self.capture()
        self.refusal('AIO_SNAPSHOT_SCOPE_CHANGED', lambda: aio.restore_capsule(self.archive, self.target,
            run_id='20261008T120000Z', source_commit=COMMIT, model=self.model_for(self.target), run=self.empty))
        self.refusal('AIO_SNAPSHOT_SCOPE_CHANGED', lambda: aio.restore_capsule(self.archive, self.target,
            run_id=RUN, source_commit='d' * 40, model=self.model_for(self.target), run=self.empty))
        self.assert_no_installed()

    def test_existing_database_and_sidecar_never_overwritten(self):
        self.capture()
        target = self.target / aio.PATHS['aiostreams']
        target.parent.mkdir(parents=True)
        for suffix in ('', '-wal', '-shm', '-journal'):
            path = Path(str(target) + suffix)
            path.write_bytes(b'existing private data')
            self.refusal('AIO_SNAPSHOT_EXISTING_DATABASE_REFUSED', self.restore)
            self.assertEqual(path.read_bytes(), b'existing private data')
            path.unlink()

    def test_existing_marker_refuses_before_docker_calls(self):
        self.capture()
        marker = self.target / '.generated/aio-import-complete.json'
        marker.parent.mkdir()
        marker.write_bytes(b'legacy-version-import')
        self.refusal('AIO_SNAPSHOT_EXISTING_DATABASE_REFUSED', self.restore)
        self.assertEqual(marker.read_bytes(), b'legacy-version-import')

    def test_target_mount_by_any_container_refuses(self):
        self.capture()
        def mounted(args, code):
            if args[:3] == ['docker', 'ps', '-aq']:
                return b'foreign-container'
            return json.dumps([{'Mounts': [{'Type': 'bind', 'Source': str(self.target)}]}]).encode()
        self.refusal('AIO_SNAPSHOT_TARGET_MOUNTED', lambda: self.restore(run=mounted))
        self.assert_no_installed()

    def test_second_link_failure_rolls_back_only_created_database(self):
        self.capture()
        original = os.link
        links = 0
        def link(source, target):
            nonlocal links
            links += 1
            if links == 2:
                raise OSError('simulated filesystem failure')
            return original(source, target)
        with patch.object(aio.os, 'link', side_effect=link):
            self.refusal('AIO_SNAPSHOT_INSTALL_FAILED', self.restore)
        self.assert_no_installed()

    def test_completed_native_restore_is_idempotent_without_overwriting(self):
        self.capture()
        evidence = self.restore()
        before = {(self.target / rel).stat().st_ino for rel in aio.PATHS.values()}
        self.assertEqual(self.restore(), evidence)
        self.assertEqual({(self.target / rel).stat().st_ino for rel in aio.PATHS.values()}, before)

    def test_forced_interruption_after_first_install_can_resume_from_journal(self):
        self.capture()
        original = os.link
        count = 0
        def interrupted(source, target):
            nonlocal count
            count += 1
            result = original(source, target)
            if count == 1:
                raise KeyboardInterrupt('simulated process interruption')
            return result
        with patch.object(aio.os, 'link', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.restore()
        first = self.target / aio.PATHS['aiostreams']
        inode = first.stat().st_ino
        self.assertTrue((self.target / aio.PENDING).exists())
        self.assertFalse((self.target / aio.PATHS['aiometadata']).exists())
        evidence = self.restore()
        self.assertEqual(first.stat().st_ino, inode)
        self.assertTrue((self.target / aio.MARKER).exists())
        self.assertFalse((self.target / aio.PENDING).exists())
        self.assertEqual(evidence['stable_ids'], 'PRESERVED')

    def test_forced_interruption_after_marker_recovers_same_commit(self):
        self.capture()
        original = aio.exclusive
        def interrupted(path, data, mode=0o600):
            result = original(path, data, mode)
            if Path(path) == self.target / aio.MARKER:
                raise KeyboardInterrupt('simulated checkpoint gap')
            return result
        with patch.object(aio, 'exclusive', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.restore()
        self.assertTrue((self.target / aio.MARKER).exists())
        self.assertTrue((self.target / aio.PENDING).exists())
        self.assertEqual(self.pending_proof()['run'], RUN)
        self.assertEqual(self.restore()['run'], RUN)
        self.assertFalse((self.target / aio.PENDING).exists())

    def test_changed_partial_database_refuses_and_preserves_journal(self):
        self.capture()
        original = os.link
        def interrupted(source, target):
            original(source, target)
            raise KeyboardInterrupt()
        with patch.object(aio.os, 'link', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.restore()
        first = self.target / aio.PATHS['aiostreams']
        first.write_bytes(b'foreign data written after interruption')
        self.refusal('AIO_SNAPSHOT_EXISTING_DATABASE_REFUSED', self.restore)
        self.assertEqual(first.read_bytes(), b'foreign data written after interruption')
        self.assertTrue((self.target / aio.PENDING).exists())
        self.assertFalse((self.target / aio.PATHS['aiometadata']).exists())

    def test_journal_for_foreign_run_refuses_before_any_install(self):
        self.capture()
        original = os.link
        def interrupted(source, target):
            raise KeyboardInterrupt()
        with patch.object(aio.os, 'link', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.restore()
        journal = self.target / aio.PENDING
        data = json.loads(journal.read_bytes())
        data['evidence']['run'] = '20261008T120000Z'
        journal.write_text(json.dumps(data))
        self.refusal('AIO_SNAPSHOT_JOURNAL_INVALID', self.restore)
        self.assert_no_installed()

    def test_corrupt_journal_is_never_treated_as_empty_destination(self):
        self.capture()
        journal = self.target / aio.PENDING
        journal.parent.mkdir()
        journal.write_bytes(b'not json')
        journal.chmod(0o600)
        self.refusal('AIO_SNAPSHOT_JOURNAL_INVALID', self.restore)
        self.assert_no_installed()

    def test_power_loss_staging_links_retired_without_replacing_completed_db(self):
        self.capture()
        evidence = self.restore()
        (self.target / aio.MARKER).unlink()
        previous = self.target / '.generated/aio-restore-power-loss'
        previous.mkdir(mode=0o700)
        for service in aio.SERVICES:
            target = self.target / aio.PATHS[service]
            shutil.copyfile(target, previous / (service + '.sqlite'))
            (previous / (service + '.sqlite')).chmod(0o600)
            target.unlink()
        first = self.target / aio.PATHS['aiostreams']
        os.link(previous / 'aiostreams.sqlite', first)
        identity = first.stat().st_ino
        aio.exclusive(self.target / aio.PENDING,
            aio.canonical({'schema': 1, 'evidence': evidence, 'staging': str(previous)}))
        self.assertEqual(self.restore(), evidence)
        self.assertEqual(first.stat().st_ino, identity)
        self.assertFalse(previous.exists())
        self.assertEqual(first.stat().st_nlink, 1)

    def test_unknown_files_in_old_staging_are_preserved_and_refuse_cleanup(self):
        self.capture()
        evidence = self.restore()
        (self.target / aio.MARKER).unlink()
        previous = self.target / '.generated/aio-restore-power-loss'
        previous.mkdir(mode=0o700)
        foreign = previous / 'foreign-private-file'
        foreign.write_bytes(b'never delete this')
        aio.exclusive(self.target / aio.PENDING,
            aio.canonical({'schema': 1, 'evidence': evidence, 'staging': str(previous)}))
        self.refusal('AIO_SNAPSHOT_JOURNAL_INVALID', self.restore)
        self.assertEqual(foreign.read_bytes(), b'never delete this')

    def test_competing_file_never_removed_on_rollback(self):
        self.capture()
        original = os.link
        links = 0
        victim = self.target / aio.PATHS['aiostreams']
        def link(source, target):
            nonlocal links
            links += 1
            if links == 2:
                victim.unlink()
                victim.write_bytes(b'foreign replacement')
                raise OSError('concurrent replacement')
            return original(source, target)
        with patch.object(aio.os, 'link', side_effect=link):
            self.refusal('AIO_SNAPSHOT_INSTALL_FAILED', self.restore)
        self.assertEqual(victim.read_bytes(), b'foreign replacement')

    def pending_proof(self, **kwargs):
        return aio.validate_pending_capsule(self.archive, self.target, run_id=RUN, source_commit=COMMIT,
            model=kwargs.pop('model', self.model_for(self.target)), run=kwargs.pop('run', self.empty),
            uid=os.getuid() if hasattr(os, 'getuid') else 1000,
            gid=os.getgid() if hasattr(os, 'getgid') else 1000, **kwargs)

    def make_pending(self):
        self.capture()
        original = os.link
        count = 0
        def interrupted(source, target):
            nonlocal count
            count += 1
            if count == 2:
                raise KeyboardInterrupt()
            return original(source, target)
        with patch.object(aio.os, 'link', side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.restore()

    def test_pending_proof_is_readonly_and_then_real_restore_resumes(self):
        self.make_pending()
        before = {str(p.relative_to(self.target)): p.read_bytes()
                  for p in self.target.rglob('*') if p.is_file()}
        evidence = self.pending_proof()
        self.assertEqual(evidence['run'], RUN)
        self.assertEqual(before, {str(p.relative_to(self.target)): p.read_bytes()
                                  for p in self.target.rglob('*') if p.is_file()})
        self.assertEqual(self.restore(), evidence)

    def test_pending_proof_rejects_changed_database_without_cleanup(self):
        self.make_pending()
        path = self.target / aio.PATHS['aiostreams']
        path.write_bytes(b'foreign replacement')
        self.refusal('AIO_SNAPSHOT_JOURNAL_INVALID', self.pending_proof)
        self.assertEqual(path.read_bytes(), b'foreign replacement')
        self.assertTrue((self.target / aio.PENDING).exists())

    def test_pending_proof_refuses_mounted_database(self):
        self.make_pending()
        def mounted(args, code):
            if args == ['docker', 'ps', '-aq']:
                return b'existing'
            return json.dumps([{'Mounts': [{'Type': 'bind',
                'Source': str((self.target / aio.PATHS['aiostreams']).parent)}]}]).encode()
        self.refusal('AIO_SNAPSHOT_TARGET_MOUNTED', lambda: self.pending_proof(run=mounted))
        self.assertTrue((self.target / aio.PENDING).exists())

    def test_pending_proof_refuses_different_encryption_bindings(self):
        self.make_pending()
        model = self.model_for(self.target)
        model['services']['aiostreams']['environment']['SECRET_KEY'] = 'foreign-key'
        self.refusal('AIO_SNAPSHOT_ENCRYPTION_KEY_MISMATCH', lambda: self.pending_proof(model=model))

    def rewrite(self, alter):
        with tarfile.open(self.archive, 'r:gz') as archive:
            files = {member.name: archive.extractfile(member).read() for member in archive.getmembers()}
        alter(files)
        replacement = self.base / 'replacement.tar.gz'
        with tarfile.open(replacement, 'w:gz', format=tarfile.USTAR_FORMAT) as archive:
            for name, data in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        self.archive.unlink()
        replacement.rename(self.archive)
        self.archive.chmod(0o600)

    def test_database_digest_tampering_refuses_all_outputs(self):
        self.capture()
        self.rewrite(lambda files: files.update({'aiometadata.sqlite': files['aiometadata.sqlite'][:-1] + b'x'}))
        self.refusal('AIO_SNAPSHOT_DIGEST_MISMATCH', self.restore)
        self.assert_no_installed()

    def test_extra_archive_path_traversal_member_refused(self):
        self.capture()
        self.rewrite(lambda files: files.update({'../comet.sqlite': b'never install'}))
        self.refusal('AIO_SNAPSHOT_ARCHIVE_UNSAFE', self.restore)
        self.assert_no_installed()
        self.assertFalse((self.base / 'comet.sqlite').exists())

    def test_archive_symlink_member_refused(self):
        self.capture()
        self.archive.unlink()
        with tarfile.open(self.archive, 'w:gz') as archive:
            item = tarfile.TarInfo('manifest.json')
            item.type = tarfile.SYMTYPE
            item.linkname = '/etc/shadow'
            archive.addfile(item)
        self.archive.chmod(0o600)
        self.refusal('AIO_SNAPSHOT_ARCHIVE_UNSAFE', self.restore)
        self.assert_no_installed()

    def test_application_mutation_after_start_is_not_a_false_hash_failure(self):
        self.capture()
        evidence = self.restore()
        with contextlib.closing(sqlite3.connect(self.target / aio.PATHS['aiostreams'])) as db:
            db.execute("UPDATE users SET config='legitimate application edit'")
            db.commit()
        identity = dict(uid=os.getuid() if hasattr(os, 'getuid') else 1000,
                        gid=os.getgid() if hasattr(os, 'getgid') else 1000)
        self.assertTrue(aio.verify_restored(self.target, evidence, self.model_for(self.target), **identity))
        self.refusal('AIO_SNAPSHOT_RESTORED_DATABASE_CHANGED', lambda: aio.verify_restored(
            self.target, evidence, self.model_for(self.target), before_start=True, **identity))

    def test_all_non_aio_datasets_excluded(self):
        for name in ('comet', 'cometnet', 'stremthru', 'postgres', 'redis'):
            path = self.source / 'data' / name
            path.mkdir(parents=True)
            (path / 'not-backed-up').write_bytes(b'excluded dataset')
        self.capture()
        with tarfile.open(self.archive) as archive:
            self.assertEqual(set(archive.getnames()), {'manifest.json', 'aiostreams.sqlite', 'aiometadata.sqlite'})
        self.restore()
        self.assertFalse((self.target / 'data/postgres').exists())
        self.assertFalse((self.target / 'data/comet').exists())

    @unittest.skipUnless(os.name == 'posix', 'Linux hard-link installation primitive')
    def test_linux_native_install_uses_regular_single_link_private_files(self):
        self.capture()
        evidence = self.restore()
        for rel in aio.PATHS.values():
            info = (self.target / rel).stat()
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual(info.st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()

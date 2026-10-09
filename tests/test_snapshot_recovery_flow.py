"""Actual recovery runner + release manager + native SQLite capsule boundaries.

Only GitHub, age and Docker transports are replaced. The downloader, manifest
checks, hash bookkeeping, AIO installer/journal and pinned preflight all run.
No real VM, account, key material or release is used by these tests.
"""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
DR_FIXTURE = ROOT / 'tests/fixtures/dr-manager'
DR_SIBLING = ROOT.parent / 'streams-aio-dr'
DR_FILES = ('scripts/dr-releases.py', 'tests/test_dr_releases.py')
DR = DR_SIBLING if all((DR_SIBLING / name).is_file() for name in DR_FILES) else DR_FIXTURE


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


remote = module(ROOT / 'remote/recover.py', 'snapshot_flow_recovery')
native_fixture = module(ROOT / 'tests/test_aio_snapshot.py', 'snapshot_flow_native_fixture')
release_fixture = module(DR / 'tests/test_dr_releases.py', 'snapshot_flow_release_fixture')
RUN, COMMIT = native_fixture.RUN, native_fixture.COMMIT


class SnapshotRecoveryFlow(unittest.TestCase):
    def test_vendored_release_manager_matches_reviewed_sibling(self):
        for name in DR_FILES:
            self.assertTrue((DR_FIXTURE / name).is_file())
            if DR == DR_SIBLING:
                self.assertEqual((DR_FIXTURE / name).read_bytes(), (DR_SIBLING / name).read_bytes())

    def setUp(self):
        fixture = self.native = native_fixture.NativeAIO('runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.capture()
        self.base = fixture.base
        self.root = fixture.target
        self.model = fixture.model_for(self.root)
        self.home = self.base / 'recovery'
        self.home.mkdir(mode=0o700)
        self.manager = self.home / 'manager'
        (self.manager / 'scripts').mkdir(parents=True)
        shutil.copyfile(DR / 'scripts/dr-releases.py', self.manager / 'scripts/dr-releases.py')
        self.job = remote.Recovery.__new__(remote.Recovery)
        self.job.root, self.job.home, self.job.manager = self.root, self.home, self.manager
        self.job.tooling = ROOT / 'remote'
        self.job.private, self.job.bundle = self.home / 'private', self.home / 'ciphertext'
        self.job.state_path = self.home / 'state.json'
        self.job.config = {'dr_tag': 'dr-' + RUN, 'aio_mode': 'snapshot', 'public_commit': COMMIT}
        self.job.state = {'public_commit': COMMIT, 'tag': 'dr-' + RUN, 'completed': [],
                          'target': str(self.root), 'machine_id': 'snapshot-test-machine'}
        self.commands = []
        if os.name == 'nt':
            # Linux mode 0600 is not expressible through Windows chmod. Keep
            # the real symlink/location/file checks, adapting this one boundary.
            def private(path, outside=()):
                path = remote.safe_path(path)
                remote.require(path.is_file(), 'PRIVATE_INPUT_FILE_REQUIRED')
                remote.require(all(not path.is_relative_to(p) for p in outside),
                               'PRIVATE_INPUT_MUST_BE_OUTSIDE_CLONES')
                return path
            for target, name, value in ((remote, 'private_file', private),
                                        (remote.os, 'geteuid', lambda: 1000)):
                adapter = patch.object(target, name, value, create=True)
                adapter.start()
                self.addCleanup(adapter.stop)

    def bundle(self, native=True, stack_commit=COMMIT):
        directory = self.base / ('new-release' if native else 'old-release')
        legacy = release_fixture.make_bundle(directory, RUN)
        if not native:
            return legacy
        component = directory / 'aio'
        component.mkdir()
        asset = component / 'state.tar.gz.age'
        asset.write_bytes(release_fixture.ENVELOPE)
        (component / 'SHA256SUMS').write_text(remote.digest(asset) + '  state.tar.gz.age\n')
        (component / 'manifest.txt').write_text('snapshot=' + RUN + '\ncomponent=aio-native-sqlite\n'
            'encryption=age\nrecipients=2\nbackup_method=sqlite-online-backup\nstack_commit=' + stack_commit + '\n')
        sources = {name: directory / name for name in release_fixture.dr.COMPONENTS}
        sources['aio'] = component
        destination = directory / 'complete'
        release_fixture.dr.prepare(RUN, RUN, release_fixture.COMMIT, sources, destination,
                                   stack_commit=stack_commit)
        return destination

    def transport(self, args, code, **kwargs):
        self.commands.append((list(args), code))
        if args[:2] == ['docker', 'compose']:
            return json.dumps(self.model).encode()
        if args == ['docker', 'ps', '-aq']:
            return b''
        if args[:2] == ['gh', 'api']:
            return json.dumps(self.meta).encode()
        if args[:3] == ['gh', 'release', 'download']:
            destination = Path(args[args.index('--dir') + 1])
            for path in self.available.iterdir():
                shutil.copyfile(path, destination / path.name)
            return b''
        self.fail('Unexpected external command shape: ' + str(args[:3]))

    def download(self, bundle):
        self.available = bundle
        self.meta = {'draft': False, 'tag_name': 'dr-' + RUN,
            'assets': [{'name': path.name, 'size': path.stat().st_size, 'state': 'uploaded'}
                       for path in bundle.iterdir()]}
        with patch.object(remote, 'command', self.transport):
            self.job.download()

    def decrypt(self):
        identity = self.base / 'synthetic-identity.txt'
        identity.write_text('AGE-SECRET-KEY-1SYNTHETIC\n')
        identity.chmod(0o600)
        self.job.config['age_identity'] = str(identity)
        requested = []
        def age(args, code):
            if args[0] == 'age-keygen':
                return b'age1synthetic'
            self.assertEqual(args[:2], ['age', '--decrypt'])
            name = Path(args[-1]).name
            requested.append(name)
            target = Path(args[args.index('--output') + 1])
            target.write_bytes(self.native.archive.read_bytes() if name == remote.AIO_ASSET
                               else ('synthetic-' + name).encode())
            target.chmod(0o600)
            return b''
        actual_decrypt = remote.decrypt_all
        with patch.object(remote, 'decrypt_all', side_effect=lambda *args:
                          actual_decrypt(*args, run=age)):
            self.job.decrypt()
        self.assertEqual(set(requested), set(remote.encrypted_assets(self.job.bundle)))

    def restore(self):
        with patch.object(remote, 'command', self.transport), patch.object(remote, 'event'):
            self.job.step('AIO', self.job.aio)

    def prepare_native(self):
        self.download(self.bundle())
        self.decrypt()

    def pinned_preflight(self):
        (self.root / 'config').mkdir(exist_ok=True)
        (self.root / 'scripts').mkdir(exist_ok=True)
        shutil.copyfile(ROOT / 'tests/fixtures/pinned_dr_preflight.py', self.root / 'scripts/dr.py')
        (self.root / '.dr-fresh-target.json').write_text(json.dumps({'root': str(self.root)}))
        (self.root / 'config/dr-render-plan.json').write_text(json.dumps({'readiness_blockers': []}))
        units = [{'id': 'native-' + service, 'classification': 'REQUIRED_USER_STATE',
                  'services': [service], 'read_only_check': {'file': rel,
                  'nonempty_tables': sorted(native_fixture.aio.REQUIRED_TABLES[service])}}
                 for service, rel in native_fixture.aio.PATHS.items()]
        units.append({'id': 'npm-routing', 'classification': 'REQUIRED_USER_STATE',
            'services': ['npm'], 'read_only_check': {'file': 'npm.sqlite', 'nonempty_tables': ['user']}})
        (self.root / 'config/dr-manifest.yaml').write_text(json.dumps({'references': [], 'state_units': units}))
        with contextlib.closing(sqlite3.connect(self.root / 'npm.sqlite')) as db:
            db.executescript('CREATE TABLE user(id INTEGER); INSERT INTO user VALUES(1);')
        self.job.state['completed'] = ['NPM', 'AIO']

    def preflight(self):
        original = Path.read_text
        def text(path, *args, **kwargs):
            if path.as_posix() == '/etc/machine-id':
                return 'snapshot-test-machine'
            return original(path, *args, **kwargs)
        with patch.object(remote, 'command', self.transport), patch.object(Path, 'read_text', text):
            remote.stack_preflight(self.root, self.job.state)

    def test_schema_two_download_decrypt_install_and_real_pinned_preflight(self):
        self.prepare_native()
        self.assertEqual(len(self.job.state['private_hashes']), 6)
        self.assertIn(remote.AIO_PLAINTEXT, self.job.state['private_hashes'])
        self.restore()
        self.assertEqual(self.job.state['aio_recovery'], 'NATIVE_SNAPSHOT_RESTORED')
        self.pinned_preflight()
        self.preflight()
        for service, table in (('aiostreams', 'linked_accounts'), ('aiometadata', 'oauth_tokens')):
            with contextlib.closing(sqlite3.connect(self.root / native_fixture.aio.PATHS[service])) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM ' + table).fetchone()[0], 1)
        self.assertFalse((self.root / '.generated/aio-import-complete.json').exists())
        self.assertNotIn('versions', self.job.state['aio_snapshot'])

    def test_schema_one_still_downloads_and_decrypts_in_manual_mode(self):
        self.job.config['aio_mode'] = 'manual'
        self.download(self.bundle(native=False))
        self.decrypt()
        self.assertEqual(len(self.job.state['private_hashes']), 5)
        self.assertNotIn(remote.AIO_PLAINTEXT, self.job.state['private_hashes'])
        self.restore()
        self.assertEqual(self.job.state['aio_recovery'], 'MANUAL_PENDING')

    def test_schema_one_cannot_claim_automatic_snapshot_recovery(self):
        with self.assertRaisesRegex(remote.Refused, '^AIO_SNAPSHOT_BACKUP_REQUIRED$'):
            self.download(self.bundle(native=False))
        self.assertFalse(self.job.bundle.exists())
        self.assertFalse(self.job.private.exists())

    def test_schema_two_public_commit_mismatch_never_installs_bundle(self):
        with self.assertRaisesRegex(remote.Refused, '^DR_STACK_COMMIT_MISMATCH$'):
            self.download(self.bundle(stack_commit='d' * 40))
        self.assertFalse(self.job.bundle.exists())

    def test_checksum_tampering_is_rejected_by_real_release_manager(self):
        bundle = self.bundle()
        target = bundle / remote.AIO_ASSET
        target.write_bytes(target.read_bytes()[:-1] + b'!')
        with self.assertRaisesRegex(remote.Refused, '^DR_BUNDLE_VERIFICATION_FAILED$'):
            self.download(bundle)
        self.assertFalse(self.job.bundle.exists())

    def test_native_asset_inventory_cannot_be_downgraded_to_legacy(self):
        bundle = self.bundle()
        (bundle / remote.AIO_ASSET).unlink()
        with self.assertRaisesRegex(remote.Refused, '^DR_BUNDLE_VERIFICATION_FAILED$'):
            self.download(bundle)

    def test_release_manifest_root_list_is_refused_without_unhandled_exception(self):
        bundle = self.bundle()
        (bundle / 'manifest.json').write_text('[]\n')
        with self.assertRaisesRegex(remote.Refused, '^DR_BUNDLE_VERIFICATION_FAILED$'):
            self.download(bundle)
        self.assertFalse(self.job.bundle.exists())

    def test_downloaded_sizes_must_match_metadata_before_checkpoint(self):
        self.available = self.bundle()
        self.meta = {'draft': False, 'tag_name': 'dr-' + RUN,
            'assets': [{'name': path.name, 'size': path.stat().st_size + 1, 'state': 'uploaded'}
                       for path in self.available.iterdir()]}
        with patch.object(remote, 'command', self.transport), self.assertRaisesRegex(
                remote.Refused, '^DOWNLOADED_ASSET_SIZE_MISMATCH$'):
            self.job.download()
        self.assertFalse(self.job.bundle.exists())

    def test_native_plaintext_mutation_is_rejected_on_resume(self):
        self.prepare_native()
        self.job.state['completed'] = ['DOWNLOAD', 'DECRYPT']
        (self.job.private / remote.AIO_PLAINTEXT).write_bytes(b'changed-private-capsule')
        with self.assertRaisesRegex(remote.Refused, '^PRIVATE_MATERIAL_CHANGED$'):
            self.job.validate_resume()

    def test_native_digest_cannot_disappear_from_decrypt_checkpoint(self):
        self.prepare_native()
        self.job.state['completed'] = ['DOWNLOAD', 'DECRYPT']
        del self.job.state['private_hashes'][remote.AIO_PLAINTEXT]
        (self.job.private / remote.AIO_PLAINTEXT).write_bytes(b'changed-private-capsule')
        with self.assertRaisesRegex(remote.Refused, '^PRIVATE_MATERIAL_CHANGED$'):
            self.job.validate_resume()

    def test_checkpoint_without_any_private_hashes_cannot_resume(self):
        self.prepare_native()
        self.job.state['completed'] = ['DOWNLOAD', 'DECRYPT']
        self.job.state['private_hashes'] = {}
        with self.assertRaisesRegex(remote.Refused, '^PRIVATE_MATERIAL_CHANGED$'):
            self.job.validate_resume()

    def test_malformed_private_hash_inventory_is_always_refused(self):
        self.prepare_native()
        self.job.state['completed'] = ['DOWNLOAD', 'DECRYPT']
        original = dict(self.job.state['private_hashes'])
        invalid = [None, [], dict(original, **{'../outside': '0' * 64})]
        for value in (None, 3, '0' * 63, 'G' * 64, 'A' * 64):
            invalid.append(dict(original, **{remote.AIO_PLAINTEXT: value}))
        for hashes in invalid:
            with self.subTest(shape=type(hashes).__name__):
                self.job.state['private_hashes'] = hashes
                with self.assertRaisesRegex(remote.Refused, '^PRIVATE_MATERIAL_CHANGED$'):
                    self.job.validate_resume()

    def test_unchanged_native_bundle_and_private_material_resume(self):
        self.prepare_native()
        self.job.state['completed'] = ['DOWNLOAD', 'DECRYPT']
        self.job.validate_resume()
        self.restore()
        self.assertIn('AIO', self.job.state['completed'])

    def test_resume_cannot_switch_the_selected_release(self):
        self.prepare_native()
        self.job.state['completed'] = ['DOWNLOAD', 'DECRYPT']
        self.job.config['dr_tag'] = 'dr-20261008T120000Z'
        with self.assertRaisesRegex(remote.Refused, '^RECOVERY_TAG_CHANGED$'):
            self.job.validate_resume()

    def test_power_loss_native_journal_resumes_through_real_runner(self):
        self.prepare_native()
        actual_link = os.link
        count = 0
        class PowerLoss(BaseException):
            pass
        def interrupted(source, destination):
            nonlocal count
            count += 1
            if count == 2:
                raise PowerLoss()
            return actual_link(source, destination)
        with patch.object(os, 'link', interrupted), self.assertRaises(PowerLoss):
            self.restore()
        self.assertEqual(self.job.state['in_progress'], 'AIO')
        first = self.root / native_fixture.aio.PATHS['aiostreams']
        original = first.read_bytes()
        self.assertTrue((self.root / native_fixture.aio.PENDING).is_file())
        self.assertFalse((self.root / native_fixture.aio.MARKER).exists())
        self.restore()
        self.assertEqual(first.read_bytes(), original)
        self.assertFalse((self.root / native_fixture.aio.PENDING).exists())
        self.assertIn('AIO', self.job.state['completed'])

    def test_forged_pending_journal_never_authorizes_existing_database(self):
        self.prepare_native()
        directory = self.root / '.generated'
        directory.mkdir()
        journal = directory / Path(native_fixture.aio.PENDING).name
        journal.write_text('{}')
        journal.chmod(0o600)
        destination = self.root / native_fixture.aio.PATHS['aiostreams']
        destination.parent.mkdir(parents=True)
        destination.write_bytes(b'foreign-private-database')
        with self.assertRaisesRegex(remote.Refused, '^AIO_SNAPSHOT_JOURNAL_INVALID$'):
            self.restore()
        self.assertEqual(destination.read_bytes(), b'foreign-private-database')
        self.assertNotIn('AIO', self.job.state['completed'])

    def test_docker_refusal_keeps_fixed_code_and_installs_nothing(self):
        self.prepare_native()
        def failed(args, code, **kwargs):
            if args == ['docker', 'ps', '-aq']:
                raise remote.Refused(code)
            return self.transport(args, code, **kwargs)
        with patch.object(remote, 'command', failed), self.assertRaisesRegex(
                remote.Refused, '^AIO_SNAPSHOT_DOCKER_CHECK_FAILED$'):
            self.job.aio()
        self.assertFalse((self.root / native_fixture.aio.MARKER).exists())

    def test_snapshot_preflight_never_excuses_missing_npm_state(self):
        self.prepare_native()
        self.restore()
        self.pinned_preflight()
        (self.root / 'npm.sqlite').unlink()
        with self.assertRaisesRegex(remote.Refused, '^FRESH_RENDERER_REFUSED$'):
            self.preflight()

    def test_native_preflight_requires_same_encryption_key(self):
        self.prepare_native()
        self.restore()
        self.pinned_preflight()
        self.model['services']['aiostreams']['environment']['SECRET_KEY'] = 'different-key'
        with self.assertRaisesRegex(remote.Refused, '^AIO_SNAPSHOT_ENCRYPTION_KEY_MISMATCH$'):
            self.preflight()

    def test_native_db_change_before_first_start_is_rejected(self):
        self.prepare_native()
        self.restore()
        self.pinned_preflight()
        with contextlib.closing(sqlite3.connect(self.root / native_fixture.aio.PATHS['aiostreams'])) as db:
            db.execute("UPDATE linked_accounts SET token='unexpected-token'")
            db.commit()
        with self.assertRaisesRegex(remote.Refused, '^AIO_SNAPSHOT_RESTORED_DATABASE_CHANGED$'):
            self.preflight()

    def test_healthy_application_writes_after_start_do_not_reimport_database(self):
        self.prepare_native()
        self.restore()
        self.pinned_preflight()
        with contextlib.closing(sqlite3.connect(self.root / native_fixture.aio.PATHS['aiostreams'])) as db:
            db.execute("INSERT INTO users VALUES('new-user','hash','encrypted','salt')")
            db.commit()
        self.job.state['application_start_attempted'] = True
        self.preflight()
        self.assertEqual(self.job.state['aio_recovery'], 'NATIVE_SNAPSHOT_RESTORED')

    def test_snapshot_inputs_drop_obsolete_registry_but_keep_oauth_allowlist(self):
        plan = {'required_values': [remote.AIO_BINDINGS_REF, remote.OAUTH_ALLOWLIST_REF],
                'additional_input_folders': ['/dr', '/oauth2-proxy'], 'files': [],
                'private_dr_bindings_ref': remote.AIO_BINDINGS_REF}
        effective = remote.input_plan(plan, 'snapshot')
        self.assertEqual(effective['required_values'], [remote.OAUTH_ALLOWLIST_REF])
        self.assertEqual(plan['required_values'], [remote.AIO_BINDINGS_REF, remote.OAUTH_ALLOWLIST_REF])
        renderer = N(all_paths=lambda p: p['additional_input_folders'], folder_file=lambda f: 'oauth.goenv')
        client = N(secrets=N(list_secrets=lambda **kwargs: N(imports=[], secrets=[])))
        with self.assertRaisesRegex(remote.Refused, '^OAUTH_ALLOWLIST_SUPPLEMENT_REQUIRED$'):
            remote.collect_inputs(plan, renderer, client, 'project', 'prod', aio_mode='snapshot')
        result = remote.collect_inputs(plan, renderer, client, 'project', 'prod', aio_mode='snapshot',
            supplemental={remote.OAUTH_ALLOWLIST_REF: 'recovery-test@example.invalid'})
        self.assertEqual(set(result), {'oauth.goenv'})


if __name__ == '__main__':
    unittest.main()

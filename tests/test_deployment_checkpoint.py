import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'remote'))
import recover
with patch.dict(sys.modules, {'fcntl': N()} if sys.platform == 'win32' else {}):
    import infisical_server as server


def checkpoint(raw):
    return dict(schema=1, postgres_bootstrap_user='recovery_existing',
                deployment_profile_sha256=hashlib.sha256(raw).hexdigest(),
                completed=['CLONES', 'DOWNLOAD', 'DECRYPT', 'INFISICAL_CONFIG',
                           'INFISICAL_DATABASE', 'INFISICAL_SERVER'],
                in_progress=None, api_port=80, tag='dr-20261006T210601Z',
                private_hashes={'archive': 'preserved'},
                installed_config_hashes={'config': 'preserved'})


class DeploymentCheckpoint(unittest.TestCase):
    def test_shipped_lf_and_crlf_profiles_have_identical_settings(self):
        raw = server.PROFILE_PATH.read_bytes().replace(b'\r\n', b'\n')
        variants = (raw, raw.replace(b'\n', b'\r\n'))
        self.assertEqual({hashlib.sha256(v).hexdigest() for v in variants},
                         server.LEGACY_PROFILE_HASHES)
        self.assertEqual(server.deployment_fingerprint(json.loads(raw)),
                         server.LEGACY_PROFILE_CANONICAL_SHA256)
        self.assertEqual(json.loads(variants[0]), json.loads(variants[1]))

    def test_legacy_resume_preserves_all_completed_steps_and_material(self):
        raw = server.PROFILE_PATH.read_bytes().replace(b'\r\n', b'\n')
        for original in (raw, raw.replace(b'\n', b'\r\n')):
            with self.subTest(crlf=b'\r\n' in original), tempfile.TemporaryDirectory() as tmp:
                home = Path(tmp)
                state = checkpoint(original)
                before = copy.deepcopy(state)
                state_path = home / 'state.json'
                recover.save(state_path, state)
                material = home / 'database-canary'
                material.write_bytes(b'existing-database-canary')
                server.validate_profile_checkpoint(state, state_path, server.profile())
                self.assertEqual(json.loads(state_path.read_bytes()), state)
                self.assertEqual({k: v for k, v in state.items()
                                  if k != 'deployment_profile_canonical_sha256'}, before)
                self.assertEqual(material.read_bytes(), b'existing-database-canary')
                saved = state_path.read_bytes()
                with patch.object(server, 'save') as save:
                    server.validate_profile_checkpoint(state, state_path, server.profile())
                    save.assert_not_called()
                self.assertEqual(state_path.read_bytes(), saved)

    def test_canonical_resume_accepts_layout_key_order_and_service_order(self):
        original = server.profile()
        state = checkpoint(server.PROFILE_PATH.read_bytes())
        state['deployment_profile_canonical_sha256'] = server.deployment_fingerprint(original)
        rearranged = dict(reversed(list(original.items())))
        rearranged['services'] = list(reversed(original['services']))
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'profile.json'
            for raw in (json.dumps(rearranged).encode(),
                        json.dumps(rearranged, indent=4).replace('\n', '\r\n').encode()):
                source.write_bytes(raw)
                with patch.object(server, 'save') as save:
                    server.validate_profile_checkpoint(state, Path(tmp) / 'state.json',
                                                       server.profile(source))
                    save.assert_not_called()

    def test_actual_profile_changes_refused_before_checkpoint_write(self):
        original = server.profile()
        mutations = [
            lambda p: p['images'].update(backend='infisical/infisical@sha256:' + 'a' * 64),
            lambda p: p['images'].update(db='postgres@sha256:' + 'b' * 64),
            lambda p: p['images'].update(redis='redis@sha256:' + 'c' * 64),
            lambda p: p.update(database='other_database'),
            lambda p: p.update(database_user='other_role'),
            lambda p: p.update(postgres_major=15),
            lambda p: p.update(source_directory='/opt/other'),
        ]
        for canonical in (False, True):
            for change in mutations:
                with tempfile.TemporaryDirectory() as tmp:
                    state = checkpoint(server.PROFILE_PATH.read_bytes())
                    if canonical:
                        state['deployment_profile_canonical_sha256'] = server.deployment_fingerprint(original)
                    before = copy.deepcopy(state)
                    path = Path(tmp) / 'state.json'
                    recover.save(path, state)
                    saved = path.read_bytes()
                    modified = copy.deepcopy(original)
                    change(modified)
                    with self.assertRaisesRegex(server.Refused, 'INFISICAL_DEPLOYMENT_PROFILE_CHANGED'), \
                         patch.object(server, 'save') as save:
                        server.validate_profile_checkpoint(state, path, modified)
                    save.assert_not_called()
                    self.assertEqual(state, before)
                    self.assertEqual(path.read_bytes(), saved)

    def test_unknown_or_missing_legacy_fingerprint_never_migrates(self):
        for old in (None, '', 'a' * 64, {}):
            state = dict(postgres_bootstrap_user='existing')
            if old is not None:
                state['deployment_profile_sha256'] = old
            before = copy.deepcopy(state)
            with patch.object(server, 'save') as save, \
                 self.assertRaisesRegex(server.Refused, 'INFISICAL_DEPLOYMENT_PROFILE_CHANGED'):
                server.validate_profile_checkpoint(state, Path('unused'), server.profile())
            save.assert_not_called()
            self.assertEqual(state, before)

    def test_invalid_canonical_fingerprint_does_not_fall_back_to_legacy(self):
        for current in (None, '', 'f' * 64):
            state = checkpoint(server.PROFILE_PATH.read_bytes())
            state['deployment_profile_canonical_sha256'] = current
            with patch.object(server, 'save') as save, \
                 self.assertRaisesRegex(server.Refused, 'INFISICAL_DEPLOYMENT_PROFILE_CHANGED'):
                server.validate_profile_checkpoint(state, Path('unused'), server.profile())
            save.assert_not_called()

    @unittest.skipIf(sys.platform == 'win32', 'The remote constructor requires a Linux absolute target')
    def test_prepare_reuses_restored_database_after_legacy_profile_migration(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            old = server.PROFILE_PATH.read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
            state = checkpoint(old)
            def initialize(instance, args):
                instance.state = copy.deepcopy(state)
                instance.state_path = home / 'state.json'
                instance.root = home / 'installed'
                instance.root.mkdir()
            with patch.object(recover.Recovery, '__init__', initialize):
                runner = server.InfisicalRecovery(N(target='/opt/infisical'))
            for name in ('auth', 'validate_server_resume', 'clones', 'download', 'decrypt',
                         'configuration', 'database', 'start_server'):
                setattr(runner, name, Mock())
            with patch.object(server, 'event'):
                runner.prepare()
            runner.validate_server_resume.assert_called_once_with()
            for name in ('clones', 'download', 'decrypt', 'configuration', 'database'):
                getattr(runner, name).assert_not_called()
            runner.start_server.assert_called_once_with()
            self.assertEqual(runner.state['completed'], state['completed'])
            self.assertEqual(runner.state['postgres_bootstrap_user'], state['postgres_bootstrap_user'])

    @unittest.skipIf(sys.platform == 'win32', 'The remote constructor requires a Linux absolute target')
    def test_fresh_checkpoint_records_canonical_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            def initialize(instance, args):
                instance.state = dict(completed=[], in_progress=None)
                instance.state_path = home / 'state.json'
                instance.root = home / 'installed'
            with patch.object(recover.Recovery, '__init__', initialize):
                runner = server.InfisicalRecovery(N(target='/opt/infisical'))
            self.assertEqual(runner.state['deployment_profile_canonical_sha256'],
                             server.deployment_fingerprint(server.profile()))
            saved = json.loads((home / 'state.json').read_bytes())
            self.assertEqual(saved, runner.state)


if __name__ == '__main__':
    unittest.main()

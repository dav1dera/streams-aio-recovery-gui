"""Desktop lab intent survives upload and reaches the actual runtime scope.

Only Docker, source transfer, render and import operations are simulated. The
request builder, upload serializer, Recovery.prepare, identity_scope and source
identity lookup are the real implementations, with synthetic Linux metadata.
"""
import json
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

from recovery_gui import backend
from tests.test_age_upload import SFTP
from tests.test_lab_prepare import Harness, PASTED_IDENTITY, TAG, COMMIT
from tests import test_lab_runtime_scope as runtime_fixture
from tests import test_runtime_image_selection as image_fixture

recover, policy = runtime_fixture.recover, runtime_fixture.policy


class LabRequestContractTests(unittest.TestCase):
    def test_current_lab_request_upload_registers_real_nonlegacy_runtime_scope(self):
        filesystem = runtime_fixture.LabScope('test_current_tag_commit_and_new_account_have_real_nonlegacy_scope')
        filesystem.setUp()
        self.addCleanup(filesystem.doCleanups)
        filesystem.account.pw_name = 'test'
        filesystem.tag, filesystem.commit = TAG, COMMIT
        filesystem.state.update(tag=TAG, public_commit=COMMIT, tooling_commit=COMMIT)
        del filesystem.state['lab_deployment']
        filesystem.save()

        desktop = Harness()
        desktop.snapshot.update(dr_tag=filesystem.tag, public_commit=filesystem.commit,
            age_identity_mode='paste', age_identity_text=PASTED_IDENTITY)
        desktop.point.update(tag=filesystem.tag, public_commit=filesystem.commit)
        desktop.prepare()
        self.assertEqual([request['role'] for request in desktop.requests], ['infisical', 'stack'])

        configs = {}
        for request in desktop.requests:
            self.assertIs(request['lab_preparation'], True)
            role = request['role']
            user = 'test' if role == 'stack' else 'test2'
            connection = backend.SSH.__new__(backend.SSH)
            connection.host = N(user=user)
            connection.check = Mock(return_value={'home': '/home/' + user})
            connection.run = Mock(return_value=b'')
            connection.client = N(open_sftp=Mock(return_value=SFTP()))
            connection._put = Mock()  # Public program upload is unrelated to the config contract.
            with patch.object(backend, 'validate_remote_shell_scripts'):
                area, raw = connection.upload(request)
            config = json.loads(raw)
            self.assertNotIn(PASTED_IDENTITY.encode(), raw)
            self.assertNotIn('age_identity_text', config)
            self.assertNotIn('lab_preparation', config)
            self.assertEqual(config['age_identity'], area + '/age_identity')
            self.assertNotIn('operational_profile', config)
            self.assertNotIn('domain_target_address', config)
            self.assertNotIn('routing_mode', config)
            if role == 'stack':
                self.assertIs(config['onboarding_lab'], True)
            else:
                self.assertNotIn('onboarding_lab', config)
            configs[role] = config

        runner = filesystem.recovery()
        runner.config = configs['stack']
        runner.auth = Mock()
        runner.validate_resume = Mock()  # Source/private validation is covered by its transaction tests.
        runner.npm = Mock()
        runner.aio = Mock()
        model = image_fixture.backup_model(filesystem.root)
        (filesystem.root/'config').mkdir(exist_ok=True)
        pins_path = filesystem.root/'config/image-lock.json'
        override_path = filesystem.root/'config/compose.dr.yaml'
        pins_path.write_text(json.dumps({name: {'image': image}
            for name, image in image_fixture.PINS.items()}))
        override_path.write_text(json.dumps({'services': {name: dict(image=image, platform='linux/amd64')
            for name, image in image_fixture.PINS.items()}}))
        original_regular = policy.regular
        def regular(path):
            if path in (pins_path, override_path):
                return N(st_size=path.stat().st_size)
            return original_regular(path)
        observed = []
        def scoped_apply(root, home, state, model, run):
            # In particular, neither of these functions is patched to accept
            # arbitrary state. The old hardcoded release fails this boundary.
            self.assertEqual(policy.first_boot_scope(root, home, state, installing=True), (root, home))
            observed.append(policy.source_identity(root))
            self.assertEqual(state['lab_deployment'], policy.lab_record(root, state))
            self.assertNotIn('operational_deployment', state)
        def command(args, *unused, **kwargs):
            self.assertFalse(set(map(str, args)) & {'up', 'start', 'run', 'push', 'restart'})
            return json.dumps(model).encode() if 'config' in args else b''
        with patch.object(recover, 'load_module', return_value=policy), \
                patch.object(recover, 'command', side_effect=command), \
                patch.object(recover, 'first_boot_cached_image', return_value=True), \
                patch.object(recover, 'event'), patch.object(recover, 'stack_preflight'), \
                patch.object(policy, 'regular', side_effect=regular), \
                patch.object(policy, 'apply_fresh', side_effect=scoped_apply):
            runner.prepare()
        self.assertEqual(observed, [('test', filesystem.commit)])
        self.assertNotEqual(filesystem.commit, policy.COMMIT)
        self.assertNotEqual(filesystem.tag, policy.TAG)
        self.assertEqual(filesystem.state['preparation'], 'PASS')
        self.assertIs(filesystem.state['timers_installed'], False)
        self.assertNotIn('application_start_attempted', filesystem.state)
        self.assertNotIn('operational_deployment', filesystem.state)


if __name__ == '__main__':
    unittest.main()

"""Selected laboratory scope survives transport without becoming DNS intent."""
import json
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock

from recovery_gui import backend
from tests import test_age_upload as age_fixture


class LabTransport(unittest.TestCase):
    def setUp(self):
        age_fixture.AgeUploadTests.setUp(self)

    def test_stack_upload_binds_the_selected_point_and_forwards_only_lab_scope(self):
        request = dict(self.request, role='stack', lab_preparation=True, onboarding_lab=True,
                       routing_mode='production_recovery', domain_target_address='192.0.2.55',
                       npm_upstream_targets={'stack': '192.0.2.55'})
        _, raw = self.connection.upload(request)
        config = json.loads(raw)
        self.connection.check.assert_called_once_with(role='stack',
            lab_point=(request['dr_tag'], request['public_commit']))
        self.assertIs(config['onboarding_lab'], True)
        self.assertEqual(config['role'], 'stack')
        self.assertFalse({'lab_preparation', 'routing_mode', 'domain_target_address',
                          'npm_upstream_targets', 'operational_profile'} & set(config))

    def test_infisical_uses_the_same_point_without_a_stack_runtime_flag(self):
        request = dict(self.request, role='infisical', lab_preparation=True)
        _, raw = self.connection.upload(request)
        config = json.loads(raw)
        self.connection.check.assert_called_once_with(role='infisical',
            lab_point=(request['dr_tag'], request['public_commit']))
        self.assertNotIn('onboarding_lab', config)
        self.assertNotIn('lab_preparation', config)

    def test_mixed_or_unbound_lab_flags_are_refused_before_remote_reads_or_writes(self):
        for changes in ({'onboarding_lab': True}, {'lab_preparation': 'true'},
                        {'lab_preparation': True},
                        {'lab_preparation': True, 'onboarding_lab': True, 'operational_profile': True},
                        {'lab_preparation': True, 'onboarding_lab': True, 'role': 'infisical'}):
            with self.subTest(changes=changes), self.assertRaisesRegex(backend.Failure,
                    '^LAB_RUNTIME_SCOPE_REFUSED$'):
                self.connection.upload(dict(self.request, **changes))
        self.connection.check.assert_not_called()
        self.connection.run.assert_not_called()
        self.connection.client.open_sftp.assert_not_called()


class LabReadOnlyProbeTransport(unittest.TestCase):
    def test_probe_receives_the_selected_public_scope_and_no_credentials(self):
        connection = backend.SSH.__new__(backend.SSH)
        connection.host = N(user='new-user')
        connection.run = Mock(side_effect=[b'/home/new-user', json.dumps(dict(
            user='new-user', home='/home/new-user', existing_recovery=True,
            lab_preparation_resume=True)).encode()])
        point = ('dr-20261020T123456Z', 'd' * 40)
        result = connection.check(role='stack', lab_point=point)
        self.assertIs(result['lab_preparation_resume'], True)
        args = connection.run.call_args_list[-1].args[0]
        self.assertEqual(args[-5:], ['--fresh', '--lab-tag', point[0], '--lab-commit', point[1]])
        self.assertIs(connection.run.call_args_list[-1].kwargs['sudo'], True)
        self.assertFalse(any(value in repr(args) for value in ('github_token', 'age_identity_text')))

    def test_invalid_point_cannot_fall_back_to_unscoped_detection(self):
        connection = backend.SSH.__new__(backend.SSH)
        connection.run = Mock()
        for point in ((), ['dr-20261020T123456Z', 'd' * 40], ('latest', 'd' * 40),
                      ('dr-20261020T123456Z', 'short')):
            with self.assertRaisesRegex(backend.Failure, '^LAB_RUNTIME_SCOPE_REFUSED$'):
                connection.check(lab_point=point)
        connection.run.assert_not_called()


if __name__ == '__main__':
    unittest.main()

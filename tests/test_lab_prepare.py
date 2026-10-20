"""Lab orchestration contracts. All connections, key metadata and files are fake."""
import json
from types import SimpleNamespace
import threading
import unittest
from unittest.mock import Mock, patch

from recovery_gui import backend, lab_prepare as lab


SECRET = 'synthetic-credential-never-in-report'
COMMIT = 'b' * 40
TAG = 'dr-20261020T120100Z'


class FakeGitHub:
    def __init__(self, harness, token):
        self.harness = harness
        assert token == SECRET

    def point(self, tag):
        self.harness.timeline.append(('github-read', tag))
        return self.harness.point


class FakeSSH:
    def __init__(self, harness, host, *args, **kwargs):
        self.harness, self.host = harness, host
        self.closed = 0
        self.client = Mock()
        key = self.client.get_transport.return_value.get_remote_server_key.return_value
        key.get_name.return_value, key.get_base64.return_value = 'ssh-ed25519', 'AAAAsyntheticPublicKey'
        self.harness.timeline.append(('connect', host.address))

    def check(self, fresh=True, role='stack'):
        assert fresh is True
        self.harness.timeline.append(('check', role))
        return self.harness.infos[role]

    def prepare(self, request, callback):
        role = request['role']
        self.harness.timeline.append(('prepare', role))
        self.harness.requests.append(request)
        callback(dict(stage='INFISICAL_TRANSFER' if role == 'infisical' else 'STACK_TRANSFER',
                      status='RUNNING', message=SECRET, output=SECRET))
        if self.harness.prepare_failure == role:
            raise RuntimeError(SECRET)

    def restored_port(self):
        return 18180

    def native(self, action, home, target, callback=None, metadata=None):
        self.harness.timeline.append(('native', action))
        if action == 'key':
            return json.dumps({'public_key': 'ssh-ed25519 AAAAsyntheticPublicKey'}).encode()
        self.harness.native_metadata.append((action, metadata))
        return b''

    def run(self, args, **kwargs):
        assert args == ['python3', '-B', '-c', lab.LAB_MARKER]
        assert kwargs['sudo'] is True
        raw = kwargs['input']
        assert raw.startswith(b'STREAMS_LAB_V1\n')
        self.harness.marker = json.loads(raw.split(b'STREAMS_LAB_V1\n', 1)[1])
        self.harness.timeline.append(('lab-marker', self.host.address))
        return json.dumps({'schema': 1, 'status': self.harness.marker_status}).encode()

    def start(self, *args, **kwargs):
        raise AssertionError('A lab preparation must never start applications')

    def configure_host_dns(self, *args, **kwargs):
        raise AssertionError('A lab preparation must never modify DNS')

    def close(self):
        self.closed += 1


class FakeBridge:
    def __init__(self, harness, stack, server, port):
        self.harness = harness
        assert stack.host.address == '192.168.178.30'
        assert server.host.address == '192.168.178.33'
        assert port == 18180

    def __enter__(self):
        self.harness.timeline.append(('bridge-open',))
        return 'http://127.0.0.1:33123'

    def __exit__(self, *args):
        self.harness.timeline.append(('bridge-closed',))


class Harness:
    def __init__(self):
        self.timeline, self.requests, self.connections, self.events, self.native_metadata = [], [], [], [], []
        self.marker, self.marker_status, self.prepare_failure = None, 'PASS', None
        self.point = dict(tag=TAG, public_commit=COMMIT, aio_snapshot=True)
        self.infos = {
            'stack': dict(existing_recovery=False, containers=0, volumes=0,
                          user='test', home='/home/test', machine_id='1' * 32),
            'infisical': dict(existing_recovery=False, containers=0, volumes=0,
                             user='test2', home='/home/test2', machine_id='2' * 32),
        }
        self.snapshot = dict(host='192.168.178.30', user='test', port='22', password=SECRET,
            ssh_key='', key_password='', sudo_password='', infisical_host='192.168.178.33',
            infisical_user='test2', infisical_port='22', infisical_password=SECRET,
            infisical_key='', infisical_key_password='', infisical_sudo_password='',
            github_token=SECRET, dr_tag=TAG, public_commit=COMMIT, age_identity='synthetic.agekey',
            operational_profile=True, routing_mode='production_recovery', domain_target_address='192.0.2.1',
            dns_server='192.0.2.2', supplemental_inputs='private-legacy-file',
            project_id='must-not-copy', environment='must-not-copy', client_secret_file='must-not-copy')
        self.cancelled = threading.Event()

    def ssh(self, host, *args, **kwargs):
        connection = FakeSSH(self, host, *args, **kwargs)
        self.connections.append(connection)
        return connection

    def github(self, token):
        return FakeGitHub(self, token)

    def prepare(self, callback=None):
        fake_identity = Mock()
        fake_identity.is_file.return_value = True
        fake_identity.is_symlink.return_value = False
        fake_identity.stat.return_value = SimpleNamespace(st_size=1024)
        with patch.object(lab, 'Path', return_value=fake_identity), \
                patch.object(backend, 'validate_remote_shell_scripts'), \
                patch.object(backend, 'APIBridge', side_effect=lambda *args: FakeBridge(self, *args)):
            return lab.prepare_lab(self.snapshot, lambda *_: False, self.cancelled,
                progress_callback=callback or self.events.append, ssh_factory=self.ssh, github_factory=self.github)


class LabPreparationTests(unittest.TestCase):
    def setUp(self):
        self.harness = Harness()

    def test_both_hosts_are_proven_empty_before_any_upload_or_install(self):
        result = self.harness.prepare()
        timeline = self.harness.timeline
        first_write = next(index for index, entry in enumerate(timeline) if entry[0] == 'prepare')
        self.assertIn(('check', 'stack'), timeline[:first_write])
        self.assertIn(('check', 'infisical'), timeline[:first_write])
        self.assertEqual([entry for entry in timeline if entry[0] == 'prepare'],
                         [('prepare', 'infisical'), ('prepare', 'stack')])
        self.assertEqual(result['status'], 'PREPARED_LAB')
        self.assertFalse(result['applications_started'])
        self.assertFalse(result['publications_enabled'])
        self.assertFalse(result['backup_verified'])
        self.assertTrue(all(result['checks'].values()))
        self.assertEqual([connection.closed for connection in self.harness.connections], [1, 1])

    def test_progress_precedes_backup_network_read_and_each_ssh_preflight(self):
        observed = []
        original_point, original_check = FakeGitHub.point, FakeSSH.check
        def point(client, tag):
            observed.append(self.harness.events[-1])
            return original_point(client, tag)
        def check(connection, fresh=True, role='stack'):
            observed.append(self.harness.events[-1])
            return original_check(connection, fresh, role)
        with patch.object(FakeGitHub, 'point', point), patch.object(FakeSSH, 'check', check):
            self.harness.prepare()
        self.assertEqual(self.harness.events[0], dict(stage='HOST', status='RUNNING',
                                                    code='SERVICE_LAB_CHECKING_INPUTS'))
        self.assertEqual([event['code'] for event in observed],
                         ['SERVICE_LAB_READING_BACKUP', 'SERVICE_LAB_CHECKING_STACK',
                          'SERVICE_LAB_CHECKING_INFISICAL'])
        self.assertTrue(all(event['status'] == 'RUNNING' for event in observed))
        self.assertNotIn(SECRET, json.dumps(self.harness.events))

    def test_failed_backup_read_still_emits_visible_progress_before_failure(self):
        with patch.object(FakeGitHub, 'point', side_effect=RuntimeError(SECRET)):
            with self.assertRaisesRegex(lab.LabFailure, '^LAB_PREPARATION_FAILED$'):
                self.harness.prepare()
        self.assertEqual(self.harness.events[-1], dict(stage='HOST', status='RUNNING',
                                                     code='SERVICE_LAB_READING_BACKUP'))
        self.assertFalse(self.harness.connections)
        self.assertFalse(self.harness.requests)
        self.assertNotIn(SECRET, json.dumps(self.harness.events))

    def test_native_agent_install_uses_only_recovered_scope_and_then_protected_marker(self):
        self.harness.prepare()
        self.assertEqual([entry[1] for entry in self.harness.timeline if entry[0] == 'native'],
                         ['key', 'authorize', 'install'])
        install = dict(self.harness.native_metadata)['install']
        self.assertEqual(install, dict(host='192.168.178.33', port=22, api_port=18180,
                                      host_key='ssh-ed25519 AAAAsyntheticPublicKey'))
        self.assertEqual(self.harness.marker, dict(schema=1, kind='prepared_onboarding_lab',
            root='/home/test/streams-aio', owner='test', machine_id='1' * 32, publications_disabled=True))
        self.assertEqual(self.harness.timeline[-1], ('lab-marker', '192.168.178.30'))

    def test_no_dns_cutover_api_origin_or_extra_private_files_are_copied(self):
        self.harness.prepare()
        allowed = {'github_token', 'public_commit', 'dr_tag', 'age_identity', 'infisical_address',
                   'project_id', 'environment', 'native_agent', 'aio_mode', 'client_id_file',
                   'client_secret_file', 'aio_payload', 'supplemental_inputs', 'aiostreams_exports',
                   'aiometadata_exports', 'role', 'ssh_bridge'}
        for request in self.harness.requests:
            self.assertLessEqual(set(request), allowed)
            self.assertEqual(request['project_id'], '')
            self.assertEqual(request['environment'], '')
            self.assertEqual(request['client_secret_file'], '')
            self.assertEqual(request['supplemental_inputs'], '')
            self.assertEqual(request['aio_mode'], 'snapshot')
            self.assertTrue(request['native_agent'])
        self.assertEqual(self.harness.requests[-1]['infisical_address'], 'http://127.0.0.1:33123')
        self.assertTrue(self.harness.requests[-1]['ssh_bridge'])
        self.assertNotIn(SECRET, json.dumps(self.harness.events))
        self.assertNotIn('must-not-copy', json.dumps(self.harness.requests))

    def test_dirty_or_existing_recovery_is_refused_before_all_mutations(self):
        for role, change in (('stack', {'containers': 1}), ('infisical', {'volumes': 1}),
                             ('stack', {'existing_recovery': True}), ('stack', {'containers': False})):
            with self.subTest(role=role, change=change):
                harness = Harness()
                harness.infos[role].update(change)
                with self.assertRaisesRegex(lab.LabFailure, '^LAB_EMPTY_VMS_REQUIRED$'):
                    harness.prepare()
                self.assertFalse(harness.requests)
                self.assertFalse(harness.native_metadata)
                self.assertEqual([connection.closed for connection in harness.connections], [1, 1])

    def test_same_machine_and_wrong_home_are_refused_before_upload(self):
        self.harness.infos['infisical']['machine_id'] = '1' * 32
        with self.assertRaisesRegex(lab.LabFailure, '^SEPARATE_RECOVERY_VMS_REQUIRED$'):
            self.harness.prepare()
        self.assertFalse(self.harness.requests)
        harness = Harness()
        harness.infos['stack']['home'] = '/home/someone-else'
        with self.assertRaisesRegex(lab.LabFailure, '^LAB_HOST_IDENTITY_INVALID$'):
            harness.prepare()
        self.assertFalse(harness.requests)

    def test_backup_must_include_native_snapshot_and_exact_selected_commit(self):
        for change, code in (({'aio_snapshot': False}, 'AIO_SNAPSHOT_BACKUP_REQUIRED'),
                             ({'public_commit': 'c' * 40}, 'DR_STACK_COMMIT_MISMATCH')):
            with self.subTest(change=change):
                harness = Harness()
                harness.point.update(change)
                with self.assertRaisesRegex(lab.LabFailure, '^' + code + '$'):
                    harness.prepare()
                self.assertFalse(harness.connections)

    def test_cancellation_after_readonly_checks_never_uploads(self):
        def progress(event):
            if event == dict(stage='HOST', status='PASS'):
                self.harness.cancelled.set()
        with self.assertRaisesRegex(lab.LabFailure, '^SERVICE_OPERATION_STOPPED$'):
            self.harness.prepare(progress)
        self.assertFalse(self.harness.requests)
        self.assertEqual([connection.closed for connection in self.harness.connections], [1, 1])

    def test_failure_inside_bridge_closes_every_session_and_redacts_transport_error(self):
        self.harness.prepare_failure = 'stack'
        with self.assertRaisesRegex(lab.LabFailure, '^LAB_PREPARATION_FAILED$') as error:
            self.harness.prepare()
        self.assertNotIn(SECRET, str(error.exception))
        self.assertIn(('bridge-closed',), self.harness.timeline)
        self.assertEqual([connection.closed for connection in self.harness.connections], [1, 1])
        self.assertIsNone(self.harness.marker)

    def test_marker_refusal_is_never_advertised_as_a_ready_lab(self):
        self.harness.marker_status = 'REFUSED'
        with self.assertRaisesRegex(lab.LabFailure, '^LAB_MARKER_REFUSED$'):
            self.harness.prepare()
        self.assertEqual([connection.closed for connection in self.harness.connections], [1, 1])

    def test_unknown_backend_failure_is_closed_and_known_code_can_be_displayed(self):
        for code, expected in ((SECRET, 'LAB_PREPARATION_FAILED'), ('SSH_CONNECTION_FAILED', 'SSH_CONNECTION_FAILED')):
            with self.subTest(code=code):
                harness = Harness()
                with patch.object(FakeSSH, 'check', side_effect=backend.Failure(code)):
                    with self.assertRaisesRegex(lab.LabFailure, '^' + expected + '$'):
                        harness.prepare()
                self.assertEqual([connection.closed for connection in harness.connections], [1, 1])


if __name__ == '__main__':
    unittest.main()

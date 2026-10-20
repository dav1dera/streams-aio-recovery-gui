import json
from pathlib import Path
import threading
import unittest

from recovery_gui.onboarding import (OnboardingError, PRIVATE_PROOF, ServiceController,
                                     ONBOARDING_FRAME, PRIVATE_PROOF_FRAME)
from recovery_gui.onboarding_infisical import InfisicalFailure
from recovery_gui.service_plan import analyze_inputs


SECRET = 'synthetic-private-$-value'
TOKEN = 'synthetic-api-access-token'
FINGERPRINT = 'a' * 64
COMMIT = 'b' * 40
TAG = 'dr-20261020T120000Z'
RESOURCE = Path(__file__).resolve().parents[1] / 'remote'


class FakeSSH:
    def __init__(self):
        self.calls, self.closed = [], 0
        self.preview = FINGERPRINT
        self.complete = True
        self.proof = True
        self.job = None
        self.started = False
        self.agent_output = dict(uid=0, gid=1000, mode=0o640)
        self.api_address = ''

    def run(self, args, **kwargs):
        frame = PRIVATE_PROOF_FRAME if args[-1] == PRIVATE_PROOF else ONBOARDING_FRAME
        request = json.loads(kwargs['input'].rpartition(frame)[2])
        self.calls.append((args, request))
        if args[-1] == PRIVATE_PROOF:
            return json.dumps({'status': 'PASS' if self.proof else 'REFUSED'}).encode()
        action = request['action']
        if action == 'inspect':
            result = dict(schema=1, status='PREVIEW', fingerprint=self.preview,
                          agent_output=self.agent_output, api_address=self.api_address)
        else:
            self.job = request['job_id']
            if action == 'apply':
                self.started = True
            result = dict(schema=1, status='SERVICE_READY' if action in ('apply', 'status') else 'COMPLETE',
                          job_id=self.job, application_verified=True, backup_integrity_verified=self.complete,
                          public_commit=COMMIT, backup_tag=TAG, agent_output=self.agent_output,
                          api_address=self.api_address)
        return json.dumps(result).encode()

    def close(self):
        self.closed += 1


class FakeAPI:
    def __init__(self):
        self.calls = []
        self.failure = None

    def inspect(self, service, values):
        self.calls.append(('inspect', service, values))
        return {'status': 'PASS'}

    def ensure(self, service, values):
        self.calls.append(('ensure', service, values))
        if self.failure:
            raise InfisicalFailure(self.failure)
        return {'status': 'PASS'}


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.analysis = analyze_inputs('demo:\n  image: example/demo:latest\n',
                                      'PORT=8080\nPASSWORD=' + SECRET + '\n', private_names=['PASSWORD'])
        self.connection = dict(host='192.0.2.10', user='pi', port=22, password='ssh-password',
                               ssh_key='', key_password='', sudo_password='', stack_root='/home/pi/streams-aio')
        self.infisical = dict(endpoint='https://infisical.example.test',
                              project_id='f80601b1-73fb-49bd-9373-f3687cd5c8eb',
                              environment='prod', access_token=TOKEN)
        self.ssh, self.api = FakeSSH(), FakeAPI()
        self.events = []
        self.controller = ServiceController(lambda *_: False,
            ssh_factory=lambda *_args, **_kw: self.ssh, api_factory=lambda *_args, **_kw: self.api,
            resource_dir=RESOURCE, sleeper=lambda _: None)

    def inspect(self):
        return self.controller.inspect(self.analysis, self.connection, self.infisical, self.events.append)

    def apply(self, receipt):
        return self.controller.apply(self.analysis, self.connection, self.infisical, receipt, self.events.append)

    def test_inspection_has_no_remote_mutation_or_api_write(self):
        receipt = self.inspect()
        self.assertEqual([x[1]['action'] for x in self.ssh.calls], ['inspect'])
        self.assertEqual([x[0] for x in self.api.calls], ['inspect'])
        self.assertNotIn(SECRET, repr(receipt))
        self.assertEqual(self.ssh.closed, 1)

    def test_complete_only_with_service_agent_public_and_backup_proofs(self):
        result = self.apply(self.inspect())
        self.assertEqual(result['checks'], dict(service=True, agent=True, github=True, backup=True))
        self.assertEqual(result['backup_tag'], TAG)
        self.assertEqual([x[0] for x in self.api.calls], ['inspect', 'ensure'])
        self.assertEqual(sum(x[0][-1] == PRIVATE_PROOF for x in self.ssh.calls), 2)
        wire = json.dumps(self.ssh.calls)
        for private in (SECRET, TOKEN, 'ssh-password'):
            self.assertNotIn(private, wire)
            self.assertNotIn(private, json.dumps(self.events))
            self.assertNotIn(private, json.dumps(result))

    def test_changed_inputs_refuse_before_writes(self):
        receipt = self.inspect()
        self.infisical['access_token'] = 'changed-token'
        with self.assertRaisesRegex(OnboardingError, '^SERVICE_INPUTS_CHANGED$'):
            self.apply(receipt)
        self.assertFalse(self.ssh.started)

    def test_recovered_agent_output_metadata_passes_to_private_proof(self):
        self.ssh.agent_output = dict(uid=1000, gid=1000, mode=0o600)
        self.assertEqual(self.apply(self.inspect())['status'], 'PASS')
        proofs = [request for args, request in self.ssh.calls if args[-1] == PRIVATE_PROOF]
        self.assertTrue(proofs)
        self.assertTrue(all(row['metadata'] == self.ssh.agent_output for row in proofs))

    def test_agent_output_profile_change_refuses_before_api_write(self):
        receipt = self.inspect()
        self.ssh.agent_output = dict(uid=1000, gid=1000, mode=0o600)
        with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_AGENT_PROFILE_CHANGED$'):
            self.apply(receipt)
        self.assertNotIn('ensure', [row[0] for row in self.api.calls])

    def test_agent_output_metadata_cannot_request_loose_permissions(self):
        self.ssh.agent_output = dict(uid=1000, gid=1000, mode=0o644)
        with self.assertRaisesRegex(OnboardingError, '^SERVICE_RESPONSE_INVALID$'):
            self.inspect()
        self.assertFalse(self.api.calls)

    def test_agent_api_tunnel_change_refuses_before_writes(self):
        receipt = self.inspect()
        self.ssh.api_address = 'http://127.0.0.1:8080'
        with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_AGENT_PROFILE_CHANGED$'):
            self.apply(receipt)
        self.assertNotIn('ensure', [row[0] for row in self.api.calls])

    def test_agent_api_cannot_redirect_desktop_to_another_host(self):
        self.ssh.api_address = 'http://192.0.2.44:8080'
        with self.assertRaisesRegex(OnboardingError, '^SERVICE_RESPONSE_INVALID$'):
            self.inspect()
        self.assertFalse(self.api.calls)

    def test_local_lab_never_publishes_or_returns_full_success(self):
        self.connection['verification_scope'] = 'local_lab'
        result = self.apply(self.inspect())
        self.assertEqual(result['status'], 'PASS_LOCAL')
        self.assertEqual(result['checks'], dict(service=True, agent=True, github=False, backup=False))
        self.assertNotIn('backup_tag', result)
        self.assertFalse(any(row[1].get('action') == 'finalize' for row in self.ssh.calls))
        self.assertEqual([row for row in self.events if row['stage'] == 'BACKUP'][-1]['status'], 'SKIPPED')

    def test_unknown_scope_refused_before_ssh(self):
        self.connection['verification_scope'] = 'pretend_success'
        with self.assertRaisesRegex(OnboardingError, '^SERVICE_VERIFICATION_SCOPE_INVALID$'):
            self.inspect()
        self.assertFalse(self.ssh.calls)

    def test_remote_drift_refuses_before_api_writes(self):
        receipt = self.inspect()
        self.ssh.preview = 'f' * 64
        with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_PREVIEW_STALE$'):
            self.apply(receipt)
        self.assertNotIn('ensure', [x[0] for x in self.api.calls])
        self.assertFalse(self.ssh.started)

    def test_api_failure_never_starts_container(self):
        receipt = self.inspect()
        self.api.failure = 'INFISICAL_PERMISSION_DENIED'
        with self.assertRaisesRegex(InfisicalFailure, '^INFISICAL_PERMISSION_DENIED$'):
            self.apply(receipt)
        self.assertFalse(self.ssh.started)

    def test_agent_value_mismatch_is_not_success(self):
        receipt = self.inspect()
        self.ssh.proof = False
        with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_AGENT_VALUE_READBACK_FAILED$'):
            self.apply(receipt)
        self.assertFalse(any(x[1].get('action') == 'finalize' for x in self.ssh.calls))

    def test_no_success_without_backup_integrity(self):
        receipt = self.inspect()
        self.ssh.complete = False
        with self.assertRaisesRegex(OnboardingError, '^SERVICE_OPERATION_INCOMPLETE$'):
            self.apply(receipt)

    def test_failed_backup_can_be_resumed_in_same_session(self):
        receipt = self.inspect()
        self.ssh.complete = False
        with self.assertRaises(OnboardingError):
            self.apply(receipt)
        self.ssh.complete = True
        again = self.inspect()
        self.assertTrue(again.resume)
        self.assertEqual(again.job_id, receipt.job_id)
        self.assertEqual(self.apply(again)['status'], 'PASS')

    def test_cancellation_before_inspect_opens_nothing(self):
        self.controller.cancelled.set()
        with self.assertRaisesRegex(OnboardingError, '^SERVICE_OPERATION_STOPPED$'):
            self.inspect()
        self.assertFalse(self.ssh.calls)

    def test_public_only_service_does_not_request_infisical_access(self):
        self.analysis = analyze_inputs('demo:\n  image: example/demo:latest\n', 'PORT=8080\n')
        self.infisical = {}
        self.assertEqual(self.apply(self.inspect())['status'], 'PASS')
        self.assertFalse(self.api.calls)
        self.assertFalse(any(x[0][-1] == PRIVATE_PROOF for x in self.ssh.calls))


if __name__ == '__main__':
    unittest.main()

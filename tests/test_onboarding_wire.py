"""Real bundle previews cross the remote JSON boundary into the desktop.

Filesystem, Docker, SSH, and Infisical are represented by the existing memory
fixtures. The response itself is produced by the real remote handle function.
"""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import yaml

from recovery_gui.onboarding import ONBOARDING_FRAME, OnboardingError, ServiceController
from recovery_gui.service_plan import analyze_inputs
from tests.test_onboarding_controller import FakeAPI
from tests.test_service_resources_remote import BundleRunner, bundle
from tests.test_service_onboarding_remote import FakeEngine, LAYOUT, MemoryStore, ROOT, remote

RESOURCES = Path(__file__).resolve().parents[1] / 'remote'
PUBLIC_CONTENT = 'public-configuration-content-is-not-a-response-field'
PRIVATE_VALUE = 'private-wire-fixture-value'


class EngineWireSSH:
    """Deliver the actual Engine response bytes, preserving its wire schema."""
    def __init__(self, engine, runner, store):
        self.engine, self.runner, self.store = engine, runner, store
        self.requests, self.raw_responses = [], []
        self.response_transform = None
        self.closed = 0

    def run(self, arguments, **kwargs):
        request = remote.framed_request(kwargs['input'])
        self.requests.append(request)
        with patch.object(remote, 'Engine', return_value=self.engine):
            response = remote.handle(request, runner=self.runner, store=self.store, layout=LAYOUT)
        if self.response_transform:
            response = self.response_transform(copy.deepcopy(response))
        raw = json.dumps(response, sort_keys=True).encode()
        self.raw_responses.append(raw)
        return raw

    def close(self):
        self.closed += 1


class OnboardingWireTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.store.put(remote.PurePosixPath('/usr/local/sbin/streams-aio-services-dr-backup'),
                       b'# synthetic installed capability\n', 0, 0, 0o755)
        self.runner = BundleRunner(self.store)
        self.engine = FakeEngine(LAYOUT, self.runner, self.store)
        self.ssh = EngineWireSSH(self.engine, self.runner, self.store)
        self.api = FakeAPI()
        self.controller = ServiceController(lambda *_: False,
            ssh_factory=lambda *_args, **_kwargs: self.ssh,
            api_factory=lambda *_args, **_kwargs: self.api,
            resource_dir=RESOURCES, sleeper=lambda _: None)
        self.connection = dict(host='192.0.2.10', user='operator', port=22,
            password='synthetic-ssh-password', ssh_key='', key_password='', sudo_password='',
            stack_root=str(ROOT), verification_scope='full')
        self.infisical = dict(endpoint='https://example.invalid', project_id='example-project',
                             environment='prod', access_token='synthetic-api-token')
        self.events = []

    def analysis(self, private=False, large=False):
        selected = bundle()
        files = copy.deepcopy(selected['configuration_files'])
        files[0]['content'] = 'title: ' + PUBLIC_CONTENT + '\n'
        if large:
            files.append(dict(path='data/demo/public/config/custom.css',
                              content='/* synthetic large stylesheet */\n' + 'x' * (256 * 1024 - 64), mode=0o644))
        document = yaml.safe_load('services:\n' + selected['compose_fragment'])
        # The shared fixture is a deployment plan; let the source planner add
        # its managed env_file references just as for a newly imported bundle.
        for service in document['services'].values():
            service.pop('env_file', None)
        document.update(selected['compose_resources'])
        compose = yaml.safe_dump(document, sort_keys=False)
        env = 'PORT=8080\n' + ('API_KEY=' + PRIVATE_VALUE + '\n' if private else '')
        return analyze_inputs(compose, env, private_names=['API_KEY'] if private else [],
                              configuration_files=files)

    def inspect(self, analysis):
        return self.controller.inspect(analysis, self.connection, self.infisical, self.events.append)

    def test_actual_bundle_preview_uses_v1_envelope_and_desktop_accepts_it(self):
        analysis = self.analysis()
        receipt = self.inspect(analysis)
        response = json.loads(self.ssh.raw_responses[-1])
        self.assertEqual(response['status'], 'PREVIEW')
        self.assertIs(type(response['schema']), int)
        self.assertEqual(response['schema'], 1)
        self.assertEqual(self.ssh.requests[-1]['plan']['schema'], 2)
        self.assertEqual(response['services'], ['demo', 'sidecar'])
        self.assertEqual(receipt.fingerprint, response['fingerprint'])
        self.assertEqual(receipt.agent_output, ())
        self.assertEqual(self.ssh.closed, 1)
        self.assertFalse(self.store.writes)
        self.assertFalse(self.runner.started)
        self.assertEqual(self.api.calls, [])
        for raw in self.ssh.raw_responses:
            self.assertNotIn(PUBLIC_CONTENT.encode(), raw)
            self.assertFalse(any(key.startswith('_') for key in json.loads(raw)))
        self.assertNotIn(PUBLIC_CONTENT, repr(receipt))
        self.assertNotIn(PUBLIC_CONTENT, json.dumps(self.events))

    def test_real_apply_response_keeps_same_wire_version_as_bundle_preview(self):
        analysis = self.analysis()
        receipt = self.inspect(analysis)
        request = self.controller._request('apply', analysis, self.connection, self.infisical, receipt)
        result = self.controller._remote(self.ssh, request)
        self.assertEqual(result['schema'], 1)
        self.assertEqual(result['status'], 'SERVICE_READY')
        self.assertEqual(result['job_id'], receipt.job_id)
        self.assertTrue(result['application_verified'])
        self.assertTrue(self.runner.started)
        self.assertNotIn(PUBLIC_CONTENT, json.dumps(result))

    def test_large_public_file_affects_request_not_bounded_preview_response(self):
        analysis = self.analysis(large=True)
        receipt = self.inspect(analysis)
        request_bytes = ONBOARDING_FRAME + json.dumps(self.ssh.requests[-1], ensure_ascii=False).encode() + b'\n'
        self.assertGreater(len(request_bytes), 256 * 1024)
        self.assertLess(len(request_bytes), 2 * remote.MAX_FILE)
        self.assertLess(len(self.ssh.raw_responses[-1]), 256 * 1024)
        self.assertEqual(len(receipt.fingerprint), 64)

    def test_private_bundle_routes_original_keys_without_echoing_secret_values(self):
        analysis = self.analysis(private=True)
        receipt = self.inspect(analysis)
        response = json.loads(self.ssh.raw_responses[-1])
        self.assertEqual(response['schema'], 1)
        self.assertEqual(receipt.agent_output, (0, LAYOUT.gid, 0o640))
        self.assertEqual([call[0:2] for call in self.api.calls], [('inspect', 'demo')])
        self.assertNotIn(PRIVATE_VALUE, json.dumps(self.ssh.requests))
        self.assertNotIn(PRIVATE_VALUE.encode(), b''.join(self.ssh.raw_responses))
        self.assertNotIn(PRIVATE_VALUE, json.dumps(self.events))

    def test_unknown_and_missing_wire_schema_are_still_rejected(self):
        for schema in (3, '1', None, True, 1.0):
            with self.subTest(schema=schema):
                self.setUp()
                def corrupt(response):
                    if schema is None:
                        response.pop('schema')
                    else:
                        response['schema'] = schema
                    return response
                self.ssh.response_transform = corrupt
                with self.assertRaisesRegex(OnboardingError, '^SERVICE_RESPONSE_INVALID$'):
                    self.inspect(self.analysis())
                self.assertFalse(self.store.writes)
                self.assertFalse(self.api.calls)

    def test_private_preview_requires_complete_strict_agent_metadata(self):
        for metadata in (None, {}, {'uid': False, 'gid': LAYOUT.gid, 'mode': 0o640},
                         {'uid': 0, 'gid': LAYOUT.gid, 'mode': 0o666}):
            with self.subTest(metadata=metadata):
                self.setUp()
                self.ssh.response_transform = lambda response: dict(response, agent_output=metadata)
                with self.assertRaisesRegex(OnboardingError, '^SERVICE_RESPONSE_INVALID$'):
                    self.inspect(self.analysis(private=True))
                self.assertFalse(self.store.writes)
                self.assertFalse(self.api.calls)


if __name__ == '__main__':
    unittest.main()

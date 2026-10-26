"""Onboarding resumes from verified VM records and exposes only safe metadata."""
import ast
import copy
import re
import hashlib
import hmac
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

from recovery_gui.onboarding import (ServiceController, OnboardingError, safe_service_diagnostic,
    service_diagnostic_paths, verify_public_private_separation, PRIVATE_PROOF, ONBOARDING_FRAME)
from recovery_gui.service_plan import analyze_inputs, inspect_inputs
from tests import test_onboarding_controller as controller_fixtures
from tests.test_onboarding_controller import (FakeSSH, FakeAPI, SECRET,
    FINGERPRINT, RESOURCE, TOKEN)
from tests import test_web_bridge as bridge_fixtures
from tests.test_web_bridge import EXECUTION


class TransformSSH(FakeSSH):
    transform = None

    def run(self, args, **kwargs):
        raw = super().run(args, **kwargs)
        if args[-1] == PRIVATE_PROOF or self.transform is None:
            return raw
        request = json.loads(kwargs['input'].rpartition(ONBOARDING_FRAME)[2])
        return json.dumps(self.transform(request, json.loads(raw))).encode()


class DurableControllerTests(unittest.TestCase):
    setUp = controller_fixtures.ControllerTests.setUp

    def fresh_controller(self):
        return ServiceController(lambda *_: False,
            ssh_factory=lambda *_args, **_kwargs: self.ssh,
            api_factory=lambda *_args, **_kwargs: self.api,
            resource_dir=RESOURCE, sleeper=lambda _: None)

    def inspect(self, controller):
        return controller.inspect(self.analysis, self.connection, self.infisical, self.events.append)

    def apply(self, controller, receipt):
        return controller.apply(self.analysis, self.connection, self.infisical, receipt, self.events.append)

    def actions(self):
        return [request['action'] for args, request in self.ssh.calls if args[-1] != PRIVATE_PROOF]

    def test_new_process_discovers_job_and_resumes_without_new_inspect(self):
        original = self.fresh_controller()
        first = self.inspect(original)
        self.apply(original, first)
        self.ssh.calls.clear()
        restarted = self.fresh_controller()
        receipt = self.inspect(restarted)
        self.assertTrue(receipt.resume)
        self.assertEqual(receipt.resume_phase, 'SERVICE_READY')
        self.assertEqual(receipt.job_id, first.job_id)
        self.assertEqual(receipt.fingerprint, first.fingerprint)
        self.assertNotEqual(receipt.binding, first.binding)
        self.assertEqual(self.actions(), ['discover'])
        self.assertEqual(self.apply(restarted, receipt)['status'], 'PASS')
        self.assertEqual(self.actions(), ['discover', 'apply', 'finalize'])
        wire = json.dumps(self.ssh.calls)
        for private in (SECRET, TOKEN, 'ssh-password'):
            self.assertNotIn(private, wire)
            self.assertNotIn(private, repr(receipt))
            self.assertNotIn(private, json.dumps(self.events))

    def test_absent_job_continues_to_read_only_preview(self):
        receipt = self.inspect(self.fresh_controller())
        self.assertFalse(receipt.resume)
        self.assertEqual(self.actions(), ['discover', 'inspect'])
        self.assertFalse(self.ssh.started)
        self.assertEqual([call[0] for call in self.api.calls], ['inspect'])

    def test_changed_private_input_cannot_resume_or_write_infisical(self):
        old = self.fresh_controller()
        self.apply(old, self.inspect(old))
        before = list(self.api.calls)
        self.ssh.proof = False
        with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_AGENT_VALUE_READBACK_FAILED$'):
            self.inspect(self.fresh_controller())
        self.assertEqual(self.api.calls, before)

    def test_incomplete_ambiguous_or_changed_server_state_is_not_a_fresh_install(self):
        for code in ('ONBOARDING_RESUME_AMBIGUOUS', 'ONBOARDING_RESUME_CHANGED',
                     'ONBOARDING_INTERRUPTED_REVIEW_REQUIRED'):
            with self.subTest(code=code):
                self.setUp()
                self.ssh = TransformSSH()
                self.ssh.transform = lambda request, result: (
                    dict(schema=1, status='REFUSED', code=code) if request['action'] == 'discover' else result)
                with self.assertRaisesRegex(OnboardingError, '^' + code + '$'):
                    self.inspect(self.fresh_controller())
                self.assertEqual(self.actions(), ['discover'])
                self.assertFalse(self.api.calls)
                self.assertFalse(self.ssh.started)

    def test_discovered_job_metadata_is_bound_to_service_scope_and_verified_phase(self):
        variants = [dict(fingerprint=None), dict(job_id='not-a-job'), dict(application_verified=False),
                    dict(service='other'), dict(services=['other']), dict(verification_scope='local_lab'),
                    dict(status='PREPARED')]
        for changes in variants:
            with self.subTest(changes=changes):
                self.setUp()
                self.ssh = TransformSSH()
                self.ssh.job = '5' * 32
                self.ssh.transform = lambda request, result: dict(result, **changes) if request['action'] == 'discover' else result
                with self.assertRaisesRegex(OnboardingError, '^SERVICE_RESPONSE_INVALID$'):
                    self.inspect(self.fresh_controller())
                self.assertEqual(self.actions(), ['discover'])
                self.assertFalse(self.api.calls)

    def test_tooling_preparation_is_a_separate_explicit_action(self):
        result = self.fresh_controller().prepare_tools(self.analysis, self.connection, self.infisical, self.events.append)
        self.assertEqual(result, {'status': 'TOOLS_READY'})
        self.assertEqual(self.actions(), ['update_tools'])
        self.assertFalse(self.api.calls)
        self.assertFalse(self.ssh.started)

    def test_apply_proof_is_fresh_scoped_keyed_and_absent_from_other_requests(self):
        controller = self.fresh_controller()
        first = controller._request('apply', self.analysis, self.connection, self.infisical)
        second = controller._request('apply', self.analysis, self.connection, self.infisical)
        self.assertEqual(set(first['private_proof']), {'demo'})
        proof = first['private_proof']['demo']
        self.assertEqual(len(proof['challenge']), 64)
        self.assertNotEqual(proof['challenge'], second['private_proof']['demo']['challenge'])
        expected = hmac.digest(bytes.fromhex(proof['challenge']), ('PASSWORD\0' + SECRET).encode(), 'sha256').hex()
        self.assertEqual(proof['expected'], {'PASSWORD': expected})
        self.assertNotIn(SECRET, json.dumps(first))
        self.assertNotIn(hashlib.sha256(SECRET.encode()).hexdigest(), json.dumps(first))
        for action in ('discover', 'inspect', 'finalize', 'update_tools'):
            self.assertNotIn('private_proof', controller._request(action, self.analysis, self.connection, self.infisical))

    def test_bundle_apply_proof_keeps_original_env_names_per_service(self):
        source = ('services:\n  first:\n    image: example/first:1\n    environment:\n      PASSWORD: ${PASSWORD}\n'
                  '  second:\n    image: example/second:1\n    environment:\n      PASSWORD: ${PASSWORD}\n')
        env = 'PASSWORD=' + SECRET + '\n'
        names = [row.name for row in inspect_inputs(source, env)]
        analysis = analyze_inputs(source, env, private_names=names)
        request = self.fresh_controller()._request('apply', analysis, self.connection, self.infisical)
        self.assertEqual(set(request['private_proof']), {'first', 'second'})
        for proof in request['private_proof'].values():
            self.assertEqual(set(proof['expected']), {'PASSWORD'})
        self.assertNotIn(SECRET, json.dumps(request))


class ServiceDiagnosticTests(unittest.TestCase):
    def diagnostic(self):
        return dict(schema=1, stage='GITHUB', code='PRIVATE_VALUE_IN_PUBLIC_FILE',
                    path='data/demo/public/settings.yaml', lines=[3, 1],
                    references=['/demo/PASSWORD'], retryable=True)

    def test_remote_service_codes_always_have_a_closed_gui_presentation(self):
        from recovery_gui import backend
        from recovery_gui.web_bridge import DIAGNOSTIC_CODES, WEB_ERRORS
        from recovery_gui.ui_onboarding import ERROR_TEXT
        source = '\n'.join((RESOURCE / name).read_text(encoding='utf-8')
                           for name in ('service_onboarding.py', 'service_tooling.py'))
        codes = {node.value for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Constant) and isinstance(node.value, str)
                 and re.fullmatch(r'ONBOARDING_[A-Z0-9]+(?:_[A-Z0-9]+)*', node.value)}
        known = backend.ERROR_CODES | DIAGNOSTIC_CODES | set(WEB_ERRORS) | set(ERROR_TEXT)
        self.assertFalse(codes - known, 'Every remote refusal needs a reviewed GUI code/message')
    def test_diagnostic_is_bounded_copied_and_value_free(self):
        source = self.diagnostic()
        result = safe_service_diagnostic(source, allowed_paths={source['path']})
        source['lines'].append(99)
        source['references'].append('/other/KEY')
        self.assertEqual(result['lines'], [1, 3])
        self.assertEqual(result['references'], ['/demo/PASSWORD'])
        self.assertNotIn(SECRET, json.dumps(result))

    def test_new_closed_backend_reason_falls_back_without_echoing_unknown_text(self):
        source = dict(self.diagnostic(), code='FUTURE_BACKEND_CHECK')
        result = safe_service_diagnostic(source, allowed_paths={source['path']})
        self.assertEqual(result['code'], 'PUBLIC_EXPORT_REFUSED')
        self.assertEqual(result['lines'], [1, 3])
        self.assertNotIn('FUTURE_BACKEND_CHECK', json.dumps(result))

    def test_unknown_output_fields_and_unreviewed_paths_are_refused(self):
        for changes in (dict(stdout=SECRET), dict(message=SECRET), dict(path='.secrets/demo.env'),
                        dict(lines=[True]), dict(lines=[0]), dict(code=SECRET), dict(stage=[]),
                        dict(references=['/demo/' + SECRET]), dict(retryable=1)):
            with self.subTest(changes=changes):
                source = dict(self.diagnostic(), **changes)
                with self.assertRaisesRegex(OnboardingError, '^SERVICE_RESPONSE_INVALID$') as error:
                    safe_service_diagnostic(source, allowed_paths={'data/demo/public/settings.yaml'})
                self.assertNotIn(SECRET, str(error.exception))

    def test_public_private_separation_ignores_variable_names_and_simple_references(self):
        plan = dict(compose_fragment='demo:\n  environment:\n    PASSWORD: ${PASSWORD}\n',
                    public_env_path='data/demo/.env', public_env_text='',
                    configuration_files=[dict(path='data/demo/public/settings.yaml',
                        content='PASSWORD: "{{PASSWORD}}"\n')])
        verify_public_private_separation(plan, {'PASSWORD': 'PASSWORD'})
        verify_public_private_separation(plan, {'PASSWORD': 'pi'})
        plan['configuration_files'][0]['content'] = 'token: ${PASSWORD:-' + SECRET + '}\n'
        with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_PUBLIC_PREFLIGHT_FAILED$') as raised:
            verify_public_private_separation(plan, {'PASSWORD': SECRET})
        self.assertEqual(raised.exception.diagnostic['lines'], [1])
        self.assertNotIn(SECRET, json.dumps(raised.exception.diagnostic))

    def test_mutated_public_config_is_rechecked_before_any_ssh_connection(self):
        source = ('services:\n  demo:\n    image: example/demo:1\n    environment:\n      PASSWORD: ${PASSWORD}\n'
                  '    volumes:\n      - ./data/demo/public:/config:ro\n')
        analysis = analyze_inputs(source, 'PASSWORD=' + SECRET + '\n', private_names=['PASSWORD'],
            configuration_files=[dict(path='data/demo/public/settings.yaml', content='title: Public\n', mode=0o644)])
        analysis.plan.configuration_files[0]['content'] = 'title: Public\ntoken: ' + SECRET + '\n'
        opened = []
        controller = ServiceController(lambda *_: False, ssh_factory=lambda *args, **kwargs: opened.append(args))
        connection = dict(host='192.0.2.1', user='pi', stack_root='/home/pi/streams-aio')
        with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_PUBLIC_PREFLIGHT_FAILED$') as raised:
            controller.inspect(analysis, connection, {})
        self.assertEqual(opened, [])
        self.assertEqual(raised.exception.diagnostic['path'], 'data/demo/public/settings.yaml')
        self.assertEqual(raised.exception.diagnostic['lines'], [2])
        self.assertNotIn(SECRET, json.dumps(raised.exception.diagnostic))


class DurableBridgeTests(unittest.TestCase):
    setUp = bridge_fixtures.BridgeTests.setUp
    tearDown = bridge_fixtures.BridgeTests.tearDown
    prepare = bridge_fixtures.BridgeTests.prepare
    drain = bridge_fixtures.BridgeTests.drain

    def test_inspected_event_exposes_only_resume_phase(self):
        self.prepare()
        self.controller.inspect = lambda *args: SimpleNamespace(resume=True, resume_phase='SERVICE_READY', accidental=SECRET)
        self.assertTrue(self.bridge.inspect_service(EXECUTION)['ok'])
        events = self.drain()
        inspected = next(event for event in events if event['kind'] == 'inspected')
        self.assertIs(inspected['resume'], True)
        self.assertEqual(inspected['resume_phase'], 'SERVICE_READY')
        self.assertNotIn(SECRET, json.dumps(self.bridge._report()))

    def test_safe_error_diagnostic_survives_report_but_foreign_metadata_does_not(self):
        self.prepare()
        diagnostic = dict(schema=1, stage='GITHUB', code='PUBLIC_EXPORT_REFUSED',
                          path='data/demo/.env', lines=[1], retryable=True)
        self.controller.failure = OnboardingError('ONBOARDING_PUBLIC_PREFLIGHT_FAILED', diagnostic=diagnostic)
        self.assertTrue(self.bridge.inspect_service(EXECUTION)['ok'])
        events = self.drain()
        failure = next(event for event in events if event['kind'] == 'error')
        self.assertEqual(failure['diagnostic'], diagnostic)
        foreign = ValueError(SECRET)
        foreign.diagnostic = diagnostic
        self.assertNotIn('diagnostic', self.bridge._error(foreign))
        self.assertNotIn(SECRET, json.dumps([failure, self.bridge._error(foreign), self.bridge._report()]))

    def test_update_tools_is_explicit_keeps_plan_and_requires_a_new_inspection(self):
        self.prepare()
        original = self.bridge._analysis
        calls = []
        self.controller.prepare_tools = lambda *args: calls.append(args) or dict(status='TOOLS_READY')
        self.bridge._receipt, self.bridge._service_signature = object(), b'old'
        self.assertTrue(self.bridge.update_service_tools(EXECUTION)['ok'])
        events = self.drain()
        self.assertIn('tools_prepared', [event['kind'] for event in events])
        self.assertEqual(len(calls), 1)
        self.assertIs(self.bridge._analysis, original)
        self.assertIsNone(self.bridge._receipt)
        self.assertFalse(self.bridge.apply_service(EXECUTION)['ok'])
        self.assertNotIn(SECRET, json.dumps(self.bridge._report()))


if __name__ == '__main__':
    unittest.main()
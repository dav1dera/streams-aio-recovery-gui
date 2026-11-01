"""Public configuration updates stay distinct from adding a service."""
from dataclasses import replace
import ast
import re
import json
from types import SimpleNamespace
import unittest

from recovery_gui.onboarding import (ServiceController, OnboardingError, ONBOARDING_FRAME)
from recovery_gui.service_plan import analyze_inputs
from recovery_gui.web_bridge import WEB_ERRORS, WebBridge
from tests import test_onboarding_controller as controller_fixtures
from tests import test_web_bridge as bridge_fixtures


FINGERPRINT = 'a' * 64
JOB = 'b' * 32
COMMIT = 'c' * 40
TAG = 'dr-20261020T120000Z'


def analysis():
    return analyze_inputs('demo:\n  image: example/demo:1\n  volumes:\n    - ./data/demo/public:/config:ro\n',
        'PORT=8080\n', configuration_files=[dict(path='data/demo/public/settings.yaml',
        content='title: Revised public configuration\n', mode=0o644)])


class ConfigurationSSH:
    def __init__(self):
        self.requests = []
        self.installed = False
        self.kind = 'configuration'
        self.closed = 0
        self.fingerprint = FINGERPRINT
        self.complete = True

    def run(self, args, **kwargs):
        request = json.loads(kwargs['input'].rpartition(ONBOARDING_FRAME)[2])
        self.requests.append(request)
        plan = request['plan']
        action = request['action']
        if action == 'configuration_discover' and not self.installed:
            result = dict(schema=1, status='NO_JOB', operation_kind='configuration')
        elif action == 'inspect_configuration':
            result = dict(schema=1, status='PREVIEW', fingerprint=self.fingerprint,
                          operation_kind=self.kind, configuration_updated=False)
        else:
            if action == 'apply_configuration': self.installed = True
            status = 'COMPLETE' if action == 'finalize' and self.complete else 'SERVICE_READY'
            result = dict(schema=1, status=status, fingerprint=self.fingerprint,
                job_id=request.get('job_id', JOB), service=plan['service_name'],
                services=plan.get('service_names') or [plan['service_name']],
                verification_scope=request.get('verification_scope', 'full'),
                operation_kind=self.kind, configuration_updated=True, application_verified=True,
                backup_integrity_verified=self.complete, public_commit=COMMIT, backup_tag=TAG)
        return json.dumps(result).encode()

    def close(self): self.closed += 1


class ConfigurationControllerTests(unittest.TestCase):
    def setUp(self):
        base = controller_fixtures.ControllerTests(); base.setUp()
        self.connection, self.infisical = base.connection, base.infisical
        self.analysis, self.ssh, self.events = analysis(), ConfigurationSSH(), []
        self.api_calls = []
        self.controller = self.new_controller()

    def new_controller(self):
        return ServiceController(lambda *_: False, ssh_factory=lambda *_a, **_k: self.ssh,
            api_factory=lambda *_a, **_k: self.api_calls.append('forbidden'),
            resource_dir=controller_fixtures.RESOURCE, sleeper=lambda _: None)

    def inspect(self):
        return self.controller.inspect_configuration(self.analysis, self.connection, self.infisical, self.events.append)

    def apply(self, receipt):
        return self.controller.apply_configuration(self.analysis, self.connection, self.infisical, receipt, self.events.append)

    def test_inspect_is_public_read_only_and_issues_a_distinct_receipt(self):
        receipt = self.inspect()
        self.assertEqual(receipt.kind, 'configuration')
        self.assertEqual([row['action'] for row in self.ssh.requests], ['configuration_discover', 'inspect_configuration'])
        self.assertFalse(self.ssh.installed)
        self.assertEqual(self.api_calls, [])
        self.assertTrue(all('private_proof' not in row for row in self.ssh.requests))
        self.assertTrue(all(row.get('project_id') == '' and row.get('environment') == '' for row in self.ssh.requests))

    def test_full_update_waits_for_publication_and_backup_without_agent_or_api(self):
        result = self.apply(self.inspect())
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['operation_kind'], 'configuration')
        self.assertEqual(result['backup_tag'], TAG)
        self.assertEqual([row['action'] for row in self.ssh.requests],
            ['configuration_discover', 'inspect_configuration', 'inspect_configuration', 'apply_configuration', 'finalize'])
        self.assertEqual(self.api_calls, [])
        self.assertTrue(all('private_proof' not in row for row in self.ssh.requests))
        for stage in ('INFISICAL', 'AGENT'):
            self.assertTrue(all(row['status'] == 'SKIPPED' for row in self.events if row['stage'] == stage))

    def test_local_lab_never_finalizes_or_claims_publication(self):
        self.connection['verification_scope'] = 'local_lab'
        result = self.apply(self.inspect())
        self.assertEqual(result['status'], 'PASS_LOCAL')
        self.assertEqual(result['checks'], dict(service=True, agent=True, github=False, backup=False))
        self.assertNotIn('finalize', [row['action'] for row in self.ssh.requests])

    def test_kinds_and_hmac_binding_prevent_cross_applying_receipts(self):
        receipt = self.inspect()
        with self.assertRaisesRegex(OnboardingError, '^SERVICE_INPUTS_CHANGED$'):
            self.controller.apply(self.analysis, self.connection, self.infisical, receipt)
        with self.assertRaisesRegex(OnboardingError, '^SERVICE_INPUTS_CHANGED$'):
            self.apply(replace(receipt, kind='add'))
        # Merely changing the public kind does not turn a differently signed add receipt into configuration.
        _, add_binding, _ = self.controller._validate(self.analysis, self.connection, self.infisical)
        with self.assertRaisesRegex(OnboardingError, '^SERVICE_INPUTS_CHANGED$'):
            self.apply(replace(receipt, binding=add_binding))
        self.assertFalse(self.ssh.installed)

    def test_changed_inputs_require_a_new_preview(self):
        receipt = self.inspect()
        self.connection['probe_url'] = 'http://127.0.0.1:8080/'
        with self.assertRaisesRegex(OnboardingError, '^SERVICE_INPUTS_CHANGED$'): self.apply(receipt)
        self.assertFalse(self.ssh.installed)

    def test_restart_discovers_only_a_configuration_receipt(self):
        self.ssh.installed = True
        self.controller = self.new_controller()
        receipt = self.inspect()
        self.assertTrue(receipt.resume)
        self.assertEqual(receipt.kind, 'configuration')
        self.assertEqual([row['action'] for row in self.ssh.requests], ['configuration_discover'])
        self.ssh.kind = 'add'
        with self.assertRaisesRegex(OnboardingError, '^SERVICE_RESPONSE_INVALID$'): self.inspect()

    def test_missing_final_backup_proof_is_not_success(self):
        receipt = self.inspect()
        original = self.ssh.run
        def response(*args, **kwargs):
            result = json.loads(original(*args, **kwargs))
            if result.get('status') == 'COMPLETE': result['backup_integrity_verified'] = False
            return json.dumps(result).encode()
        self.ssh.run = response
        with self.assertRaisesRegex(OnboardingError, '^SERVICE_OPERATION_INCOMPLETE$'): self.apply(receipt)

    def test_private_service_scope_is_refused_before_any_connection(self):
        self.analysis = analyze_inputs('demo:\n  image: example/demo:1\n',
            'PASSWORD=synthetic-private-value\n', private_names=['PASSWORD'])
        with self.assertRaisesRegex(OnboardingError, '^SERVICE_CONFIGURATION_UPDATE_SCOPE_REQUIRED$'): self.inspect()
        self.assertEqual(self.ssh.requests, [])
        self.assertEqual(self.api_calls, [])


class ConfigurationBridgeTests(unittest.TestCase):
    setUp = bridge_fixtures.BridgeTests.setUp
    tearDown = bridge_fixtures.BridgeTests.tearDown
    prepare = bridge_fixtures.BridgeTests.prepare
    drain = bridge_fixtures.BridgeTests.drain

    def test_mode_routes_distinct_controller_and_is_bound_to_apply(self):
        self.prepare()
        self.bridge._analysis = analysis()
        calls = []
        self.controller.inspect_configuration = lambda *a: calls.append('inspect_configuration') or SimpleNamespace(kind='configuration')
        self.controller.apply_configuration = lambda *a: calls.append('apply_configuration') or dict(self.controller.result, operation_kind='configuration')
        payload = dict(bridge_fixtures.EXECUTION, mode='configuration')
        self.assertTrue(self.bridge.inspect_service(payload)['ok'])
        event = next(row for row in self.drain() if row['kind'] == 'inspected')
        self.assertEqual(event['mode'], 'configuration')
        self.assertTrue(self.bridge.apply_service(payload)['ok'])
        event = next(row for row in self.drain() if row['kind'] == 'completed')
        self.assertEqual(event['mode'], 'configuration')
        self.assertEqual(calls, ['inspect_configuration', 'apply_configuration'])
        self.assertEqual(self.controller.calls, [])

    def test_changing_mode_invalidates_receipt_instead_of_calling_add(self):
        self.prepare()
        self.bridge._analysis = analysis()
        self.controller.inspect_configuration = lambda *a: SimpleNamespace(kind='configuration')
        self.assertTrue(self.bridge.inspect_service(dict(bridge_fixtures.EXECUTION, mode='configuration'))['ok'])
        self.drain()
        result = self.bridge.apply_service(bridge_fixtures.EXECUTION)
        self.assertFalse(result['ok'])
        self.assertEqual(result['code'], 'SERVICE_INPUTS_CHANGED')
        self.assertEqual(self.controller.calls, [])

    def test_unknown_mode_is_rejected_before_background_job(self):
        self.prepare()
        result = self.bridge.inspect_service(dict(bridge_fixtures.EXECUTION, mode='reinstall'))
        self.assertFalse(result['ok'])
        self.assertEqual(self.controller.calls, [])


class ConfigurationErrorPresentationTests(unittest.TestCase):
    def presentation(self, code):
        case = ConfigurationControllerTests(); case.setUp()
        case.ssh.run = lambda *args, **kwargs: json.dumps(dict(schema=1, status='REFUSED', code=code)).encode()
        with self.assertRaisesRegex(OnboardingError, '^' + code + '$') as raised:
            case.inspect()
        bridge = WebBridge(case.controller)
        try:
            result = bridge._error(raised.exception)
            self.assertFalse(result['ok'])
            self.assertEqual(result['code'], code)
            self.assertEqual(case.api_calls, [])
            self.assertFalse(case.ssh.installed)
            return result
        finally:
            bridge._close()

    def test_all_configuration_module_refusals_have_fixed_user_messages(self):
        source = (controller_fixtures.RESOURCE / 'service_configuration.py').read_text(encoding='utf-8')
        codes = {node.value for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Constant)
            and isinstance(node.value, str) and re.fullmatch(r'ONBOARDING_CONFIGURATION_[A-Z_]+', node.value)}
        self.assertGreaterEqual(len(codes), 11)
        self.assertEqual(codes - set(WEB_ERRORS), set())

    def test_compose_or_data_change_keeps_its_actionable_scope_message(self):
        result = self.presentation('ONBOARDING_CONFIGURATION_STATIC_CHANGED')
        self.assertIn('Compose, variabili o dati', result['description'])
        self.assertIn('servizio esistente', result['description'])
        self.assertNotIn('SERVICE_RESPONSE_INVALID', json.dumps(result))

    def test_restored_partial_attempt_instructs_reverification_without_reinstalling(self):
        result = self.presentation('ONBOARDING_CONFIGURATION_RETRY_REQUIRED')
        self.assertIn('ripristinati', result['description'])
        self.assertIn('Verifica di nuovo', result['description'])
        self.assertNotIn('SERVICE_RESPONSE_INVALID', json.dumps(result))


if __name__ == '__main__': unittest.main()

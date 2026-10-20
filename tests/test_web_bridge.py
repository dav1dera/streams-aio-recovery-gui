"""The browser bridge is tested offline with synthetic controllers/transports."""
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from recovery_gui import backend
from recovery_gui.onboarding import OnboardingError, ServiceController
from recovery_gui.web_bridge import WebBridge, KEYS, SENSITIVE, MAX_EVENTS


SECRET = 'never-return-this-password-or-token'
PASTED_IDENTITY = 'AGE-SECRET-KEY-1SYNTHETICNOTAPRIVATEKEY1234'
TAG = 'dr-20261020T120000Z'
COMMIT = 'a' * 40
SETTINGS = dict(host='192.0.2.20', user='test', password=SECRET, port='22',
                infisical_host='192.0.2.31', infisical_user='test2', infisical_password=SECRET,
                infisical_port='22', github_token=SECRET, dr_tag=TAG, public_commit=COMMIT,
                domain_target_address='192.0.2.20')
SOURCE = dict(compose='demo:\n  image: example/demo:latest\n',
              env='PORT=8080\nPASSWORD=' + SECRET + '\n', service_name='')
EXECUTION = dict(stack_root='/home/test/streams-aio', probe_url='', verification_scope='full',
                 infisical=dict(endpoint='https://infisical.example.test', project_id='example-project',
                                environment='prod', access_token=SECRET))


class FakeController:
    def __init__(self):
        self.calls = []
        self.block = None
        self.failure = None
        self.result = dict(status='PASS', checks=dict(service=True, agent=True, github=True, backup=True),
                           public_commit=COMMIT, backup_tag=TAG)

    def inspect(self, analysis, connection, infisical, progress):
        self.calls.append(('inspect', connection, infisical))
        progress(dict(stage='HOST', status='PASS', accidental_secret=SECRET))
        if self.block:
            self.block.wait(2)
        if self.failure:
            raise self.failure
        return object()

    def apply(self, analysis, connection, infisical, receipt, progress):
        self.calls.append(('apply', connection, infisical))
        if self.failure:
            raise self.failure
        return dict(self.result, accidental_secret=SECRET)

    def prepare_lab(self, snapshot, progress):
        self.calls.append(('prepare_lab', snapshot))
        progress(dict(stage='HOST', status='RUNNING', code='SERVICE_LAB_CHECKING_INPUTS'))
        if self.block:
            self.block.wait(2)
        if self.failure:
            raise self.failure
        return dict(status='PREPARED_LAB', applications_started=False, publications_enabled=False,
            backup_verified=False, accidental_secret=SECRET,
            checks=dict(infisical_restored=True, stack_prepared=True, agent_installed=True, lab_scope_recorded=True))


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.controller = FakeController()
        self.bridge = WebBridge(self.controller)
        self.assertTrue(self.bridge.update_settings(SETTINGS)['ok'])

    def tearDown(self):
        if self.controller.block:
            self.controller.block.set()
        self.bridge._close()

    def drain(self):
        events, deadline = [], time.monotonic() + 2
        while time.monotonic() < deadline:
            result = self.bridge.poll()
            self.assertTrue(result['ok'])
            events += result['events']
            if not result['busy']:
                break
            time.sleep(0.002)
        self.assertFalse(self.bridge._is_busy())
        self.assertNotIn(SECRET, json.dumps(events))
        return events

    def prepare(self):
        payload = dict(SOURCE, private_names=['PASSWORD'], private_values={}, reviewed=True)
        result = self.bridge.prepare_service(payload)
        self.assertTrue(result['ok'], result)
        self.assertNotIn(SECRET, json.dumps(result))
        return result

    def inspect(self, execution=None):
        self.prepare()
        self.assertTrue(self.bridge.inspect_service(execution or EXECUTION)['ok'])
        self.assertIn('inspected', [event['kind'] for event in self.drain()])

    def test_initialize_never_returns_settings_secrets_or_starts_connections(self):
        result = self.bridge.initialize()
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['defaults']['routing_mode'], 'parallel_test')
        self.assertFalse(SENSITIVE & result['defaults'].keys())
        self.assertEqual(result['progress_text']['SERVICE_LAB_CONNECTING_STACK'],
                         'Collegamento SSH alla VM stack di collaudo in corso.')
        self.assertIn('INFISICAL_SERVER', result['phase_stages']['Infisical'])
        self.assertIn('OPERATIONAL_READY', result['finished_stages'])
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(self.controller.calls, [])

    def test_settings_accept_only_explicit_string_keys_and_never_echo(self):
        self.assertFalse(self.bridge.update_settings({'command': 'arbitrary'})['ok'])
        self.assertFalse(self.bridge.update_settings({'host': 20})['ok'])
        self.assertEqual(self.bridge.update_settings({'password': SECRET})['ok'], True)
        self.assertNotIn(SECRET, json.dumps(self.bridge.update_settings({'password': SECRET})))

    def test_pasted_identity_is_absent_from_initialize_events_reports_and_plan(self):
        self.prepare()
        result = self.bridge.update_settings(dict(age_identity_mode='paste', age_identity_text=PASTED_IDENTITY))
        self.assertTrue(result['ok'])
        self.assertEqual(self.bridge._settings['age_identity_text'], PASTED_IDENTITY)
        initialized = self.bridge.initialize()
        self.assertNotIn('age_identity_text', initialized['defaults'])
        self.bridge._progress(dict(stage='HOST', status='RUNNING', message=PASTED_IDENTITY,
                                   age_identity_text=PASTED_IDENTITY, output=PASTED_IDENTITY))
        for safe_value in (result, initialized, self.bridge.poll(), self.bridge._report(), self.bridge._public_plan()):
            self.assertNotIn(PASTED_IDENTITY, json.dumps(safe_value))

    def test_switching_back_to_file_clears_pasted_identity_in_bridge_memory(self):
        self.assertTrue(self.bridge.update_settings(dict(age_identity_mode='paste',
                                                        age_identity_text=PASTED_IDENTITY))['ok'])
        result = self.bridge.update_settings(dict(age_identity_mode='file', age_identity='synthetic.agekey'))
        self.assertTrue(result['ok'])
        self.assertEqual(self.bridge._settings['age_identity_mode'], 'file')
        self.assertEqual(self.bridge._settings['age_identity_text'], '')
        self.assertEqual(self.bridge._settings['age_identity'], 'synthetic.agekey')
        for safe_value in (result, self.bridge.initialize(), self.bridge.poll(), self.bridge._report()):
            self.assertNotIn(PASTED_IDENTITY, json.dumps(safe_value))

    def test_paste_lab_snapshot_passes_through_real_controller_without_public_echo(self):
        self.bridge._controller = ServiceController(self.bridge._confirm_key,
            confirm_changed_key=self.bridge._confirm_changed_key, cancelled=self.bridge._cancelled,
            ssh_factory=Mock())
        received = []
        def prepare(snapshot, **kwargs):
            received.append(snapshot)
            kwargs['progress_callback'](dict(stage='HOST', status='RUNNING',
                code='SERVICE_LAB_CHECKING_INPUTS', accidental_identity=PASTED_IDENTITY))
            return dict(status='PREPARED_LAB', applications_started=False, publications_enabled=False,
                backup_verified=False, accidental_identity=PASTED_IDENTITY,
                checks=dict(infisical_restored=True, stack_prepared=True, agent_installed=True,
                            lab_scope_recorded=True))
        settings = dict(SETTINGS, age_identity_mode='paste', age_identity_text=PASTED_IDENTITY,
                        age_identity='inactive-file-must-not-be-opened')
        with patch('recovery_gui.lab_prepare.prepare_lab', side_effect=prepare):
            result = self.bridge.prepare_lab(settings)
            self.assertTrue(result['ok'])
            events = self.drain()
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]['age_identity_mode'], 'paste')
        self.assertEqual(received[0]['age_identity_text'], PASTED_IDENTITY)
        self.assertIn('lab_prepared', [event['kind'] for event in events])
        for safe_value in (result, events, self.bridge._report(), self.bridge.initialize()):
            self.assertNotIn(PASTED_IDENTITY, json.dumps(safe_value))

    def test_analysis_and_plan_return_metadata_without_any_env_values(self):
        result = self.bridge.analyze_service(SOURCE)
        self.assertTrue(result['ok'])
        password = next(value for value in result['variables'] if value['name'] == 'PASSWORD')
        self.assertTrue(password['suggested_private'])
        self.assertNotIn(SECRET, json.dumps(result))
        result = self.prepare()
        self.assertEqual(result['plan']['private_env_path'], '.secrets/demo.env')
        self.assertNotIn('compose_fragment', result['plan'])
        self.assertNotIn('8080', json.dumps(result))

    def test_prepare_requires_explicit_review_and_failure_clears_old_plan(self):
        self.prepare()
        result = self.bridge.prepare_service(dict(SOURCE, reviewed=False))
        self.assertEqual(result['code'], 'SERVICE_REVIEW_REQUIRED')
        self.assertIsNone(self.bridge._public_plan())
        self.assertEqual(self.bridge.inspect_service(EXECUTION)['code'], 'SERVICE_ANALYSIS_REQUIRED')

    def test_full_service_completion_checks_all_evidence_and_redacts_extra_fields(self):
        self.inspect()
        self.assertTrue(self.bridge.apply_service(EXECUTION)['ok'])
        events = self.drain()
        completed = next(event for event in events if event['kind'] == 'completed')
        self.assertEqual(completed['status'], 'PASS')
        self.assertEqual(completed['checks'], dict(service=True, agent=True, github=True, backup=True))
        self.assertEqual(completed['backup_tag'], TAG)
        self.assertNotIn('accidental_secret', completed)
        self.assertIsNone(self.bridge._public_plan())
        self.assertNotIn(SECRET, json.dumps(self.bridge._report()))

    def test_local_completion_never_claims_publication_or_backup(self):
        execution = dict(EXECUTION, verification_scope='local_lab')
        self.inspect(execution)
        self.controller.result = dict(status='PASS_LOCAL',
            checks=dict(service=True, agent=True, github=False, backup=False))
        self.bridge.apply_service(execution)
        result = next(event for event in self.drain() if event['kind'] == 'completed')
        self.assertEqual(result['status'], 'PASS_LOCAL')
        self.assertFalse(result['checks']['github'])
        self.assertNotIn('backup_tag', result)

    def test_generic_pass_is_not_a_verified_completion(self):
        self.inspect()
        self.controller.result = dict(status='PASS')
        self.bridge.apply_service(EXECUTION)
        events = self.drain()
        self.assertNotIn('completed', [event['kind'] for event in events])
        self.assertEqual(next(event['code'] for event in events if event['kind'] == 'error'), 'SERVICE_OPERATION_INCOMPLETE')

    def test_changed_execution_inputs_or_settings_invalidate_inspection(self):
        self.inspect()
        changed = dict(EXECUTION, probe_url='http://127.0.0.1:8080/health')
        self.assertEqual(self.bridge.apply_service(changed)['code'], 'SERVICE_INPUTS_CHANGED')
        self.assertFalse(any(call[0] == 'apply' for call in self.controller.calls))
        self.bridge.inspect_service(EXECUTION); self.drain()
        self.bridge.update_settings({'password': 'different-password'})
        self.assertEqual(self.bridge.apply_service(EXECUTION)['code'], 'SERVICE_INSPECTION_REQUIRED')

    def test_unchanged_settings_preserve_receipt(self):
        self.inspect()
        self.bridge.update_settings(SETTINGS)
        self.assertTrue(self.bridge.apply_service(EXECUTION)['ok'])
        self.assertIn('completed', [event['kind'] for event in self.drain()])

    def test_global_busy_prevents_second_job_and_input_mutation(self):
        self.controller.block = threading.Event()
        self.prepare()
        self.assertTrue(self.bridge.inspect_service(EXECUTION)['ok'])
        self.assertEqual(self.bridge.prepare_lab(SETTINGS)['code'], 'SERVICE_OPERATION_BUSY')
        self.assertEqual(self.bridge.update_settings({'host': 'elsewhere'})['code'], 'SERVICE_OPERATION_BUSY')
        self.assertEqual(self.bridge.invalidate_service()['code'], 'SERVICE_OPERATION_BUSY')
        self.controller.block.set(); self.drain()

    def test_error_is_safe_and_releases_busy_and_failed_inspect_has_no_receipt(self):
        self.controller.failure = RuntimeError(SECRET)
        self.prepare(); self.bridge.inspect_service(EXECUTION)
        events = self.drain()
        self.assertEqual(next(event['code'] for event in events if event['kind'] == 'error'), 'SERVICE_TOOL_FAILED')
        self.assertEqual(self.bridge.apply_service(EXECUTION)['code'], 'SERVICE_INSPECTION_REQUIRED')
        self.assertFalse(self.bridge._is_busy())

    def test_unknown_uppercase_exception_text_and_stage_codes_cannot_be_returned(self):
        self.controller.failure = OnboardingError('UNLISTED_PRIVATE_CANARY')
        self.prepare(); self.bridge.inspect_service(EXECUTION)
        events = self.drain()
        self.assertNotIn('UNLISTED_PRIVATE_CANARY', json.dumps(events))
        self.assertEqual(next(event['code'] for event in events if event['kind'] == 'error'), 'SERVICE_TOOL_FAILED')
        self.bridge._progress(dict(stage='HOST', status='RUNNING', code='SERVICE_UNLISTED_PRIVATE_CANARY'))
        self.assertNotIn('SERVICE_UNLISTED_PRIVATE_CANARY', json.dumps(self.bridge.poll()))

    def test_cancelled_inspection_cannot_install_a_receipt_even_if_controller_returns(self):
        self.controller.block = threading.Event()
        self.prepare(); self.bridge.inspect_service(EXECUTION)
        self.bridge.cancel(); self.controller.block.set()
        events = self.drain()
        self.assertNotIn('inspected', [event['kind'] for event in events])
        self.assertEqual(self.bridge.apply_service(EXECUTION)['code'], 'SERVICE_INSPECTION_REQUIRED')

    def test_failed_apply_requires_reinspection_for_safe_controller_resume(self):
        self.inspect()
        self.controller.failure = OnboardingError('ONBOARDING_BACKUP_PENDING')
        self.bridge.apply_service(EXECUTION); self.drain()
        self.assertEqual(self.bridge.apply_service(EXECUTION)['code'], 'SERVICE_INSPECTION_REQUIRED')
        self.controller.failure = None
        self.bridge.inspect_service(EXECUTION); self.drain()
        self.assertTrue(self.bridge.apply_service(EXECUTION)['ok'])
        self.assertIn('completed', [event['kind'] for event in self.drain()])

    def test_prepare_lab_uses_real_flow_contract_without_recovery_or_generic_pass(self):
        self.assertTrue(self.bridge.prepare_lab(SETTINGS)['ok'])
        events = self.drain()
        result = next(event for event in events if event['kind'] == 'lab_prepared')
        self.assertEqual(result['stack_root'], '/home/test/streams-aio')
        self.assertEqual(result['verification_scope'], 'local_lab')
        self.assertFalse(result['applications_started'])
        self.assertFalse(result['backup_verified'])
        self.assertNotIn('completed', [event['kind'] for event in events])

    def test_host_key_prompt_requires_explicit_answer_and_cancel_unblocks(self):
        answers = []
        thread = threading.Thread(target=lambda: answers.append(self.bridge._confirm_key('192.0.2.20:22', 'SHA256:' + 'a' * 43)))
        thread.start()
        deadline, prompt = time.monotonic() + 1, None
        while time.monotonic() < deadline and prompt is None:
            prompt = next((event for event in self.bridge.poll()['events'] if event['kind'] == 'host_key'), None)
            if prompt is None: time.sleep(0.002)
        self.assertIsNotNone(prompt)
        self.assertTrue(self.bridge.answer_host_key(prompt['id'], True)['ok'])
        thread.join(1)
        self.assertEqual(answers, [True])
        self.assertEqual(self.bridge.answer_host_key(prompt['id'], True)['code'], 'WEB_HOST_KEY_INVALID')
        thread = threading.Thread(target=lambda: answers.append(self.bridge._confirm_key('192.0.2.20:22', 'SHA256:' + 'b' * 43)))
        thread.start(); self.bridge.cancel(); thread.join(1)
        self.assertEqual(answers, [True, False])

    def test_close_cancels_waiters_clears_credentials_and_analysis(self):
        self.prepare()
        self.bridge._close()
        self.assertIsNone(self.bridge._public_plan())
        self.assertFalse(any(self.bridge._settings[key] for key in SENSITIVE))
        self.assertEqual(self.bridge.update_settings({})['code'], 'WEB_CLOSED')

    def test_stage_filter_drops_unknown_or_secret_fields_and_poll_is_bounded(self):
        for _ in range(MAX_EVENTS + 100):
            self.bridge._progress(dict(stage='HOST', status='RUNNING', details=SECRET))
        self.bridge._progress(dict(stage=SECRET, status='RUNNING'))
        result = self.bridge.poll()
        self.assertLessEqual(len(result['events']), 64)
        self.assertLessEqual(len(self.bridge._events), MAX_EVENTS)
        self.assertNotIn(SECRET, json.dumps(result))

    def test_validated_diagnostics_are_frozen_before_backend_can_mutate_them(self):
        diagnostic = dict(schema=1, total=3, unavailable=[2])
        self.bridge._progress(dict(stage='EXTERNAL_UPSTREAMS', status='WARNING', diagnostic=diagnostic))
        diagnostic['secret_after_callback'] = SECRET
        diagnostic['unavailable'].append(SECRET)
        result = self.bridge.poll()
        self.assertEqual(result['events'][0]['diagnostic'], dict(schema=1, total=3, unavailable=[2]))
        self.assertNotIn(SECRET, json.dumps(self.bridge._report()))

    def test_backup_choices_and_point_are_revalidated_and_metadata_only(self):
        class Github:
            def __init__(self, token): assert token == SECRET
            def choices(self): return [TAG], COMMIT
            def point(self, tag): return dict(tag=tag, public_commit=COMMIT, aio_snapshot=True, token=SECRET)
        with patch('recovery_gui.web_bridge.backend.GitHub', Github):
            self.bridge.load_backups(SETTINGS)
            events = self.drain()
        self.assertEqual([event['kind'] for event in events], ['choices', 'point', 'done'])
        self.assertEqual(events[1]['tag'], TAG)
        self.assertNotIn('token', events[1])

    def test_pasted_identity_recovery_uses_ram_request_without_a_local_identity_file(self):
        connections = [Mock(), Mock()]
        detected = dict(stack=dict(containers=0, volumes=0, existing_recovery=False),
                        infisical=dict(containers=0, volumes=0, existing_recovery=False))
        captured = []
        def restore(stack, server, request, callback, tls):
            self.assertTrue(tls)
            self.assertEqual((stack, server), tuple(connections))
            self.assertEqual(request['age_identity_mode'], 'paste')
            self.assertEqual(request['age_identity_text'], PASTED_IDENTITY)
            captured.append(request)
            callback(dict(stage='OPERATIONAL_READY', status='PASS', accidental_identity=PASTED_IDENTITY))
        settings = dict(SETTINGS, age_identity_mode='paste', age_identity_text=PASTED_IDENTITY,
                        age_identity='inactive-file-must-not-be-opened')
        with patch('recovery_gui.web_bridge.Path', side_effect=AssertionError('No local identity file is needed')), \
                patch('recovery_gui.web_bridge.backend.SSH', side_effect=connections), \
                patch('recovery_gui.web_bridge.backend.inspect_recovery', return_value=detected), \
                patch('recovery_gui.web_bridge.backend.restore_all', side_effect=restore):
            result = self.bridge.recover(settings, 'fresh')
            self.assertTrue(result['ok'], result)
            events = self.drain()
        self.assertEqual(len(captured), 1)
        self.assertIn('completed', [event['kind'] for event in events])
        for connection in connections:
            connection.close.assert_called_once_with()
        for safe_value in (result, events, self.bridge.initialize(), self.bridge._report()):
            self.assertNotIn(PASTED_IDENTITY, json.dumps(safe_value))

    def test_pasted_public_key_recovery_is_refused_before_any_network_access(self):
        public_key = 'age1SYNTHETICPUBLICRECIPIENTNOTAPRIVATEKEY'
        settings = dict(SETTINGS, age_identity_mode='paste', age_identity_text=public_key,
                        age_identity='inactive-file-must-not-be-opened')
        with patch('recovery_gui.web_bridge.Path', side_effect=AssertionError('No local file read')), \
                patch('recovery_gui.web_bridge.backend.SSH') as ssh, \
                patch('recovery_gui.web_bridge.backend.GitHub') as github, \
                patch('recovery_gui.web_bridge.backend.inspect_recovery') as inspect, \
                patch('recovery_gui.web_bridge.backend.restore_all') as restore:
            result = self.bridge.recover(settings, 'fresh')
        self.assertFalse(result['ok'])
        self.assertEqual(result['code'], 'AGE_PUBLIC_KEY_NOT_IDENTITY')
        for network_operation in (ssh, github, inspect, restore):
            network_operation.assert_not_called()
        self.assertFalse(self.bridge._is_busy())
        for safe_value in (result, self.bridge.poll(), self.bridge.initialize(), self.bridge._report()):
            self.assertNotIn(public_key, json.dumps(safe_value))

    def test_recovery_calls_guarded_backend_and_requires_operational_ready(self):
        class SSH:
            instances = []
            def __init__(self, *args, **kwargs): self.closed = False; self.instances.append(self)
            def close(self): self.closed = True
        def restore(stack, server, request, callback, tls):
            self.assertTrue(tls)
            self.assertTrue(request['native_agent'])
            self.assertNotIn('dns_server', request)
            callback(dict(stage='OPERATIONAL_READY', status='PASS', private=SECRET))
        detected = dict(stack=dict(containers=0, volumes=0, existing_recovery=False),
                        infisical=dict(containers=0, volumes=0, existing_recovery=False))
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            identity = Path(directory) / 'synthetic-age.txt'; identity.write_text('synthetic-nonkey')
            settings = dict(SETTINGS, age_identity=str(identity))
            with patch('recovery_gui.web_bridge.backend.SSH', SSH), \
                    patch('recovery_gui.web_bridge.backend.inspect_recovery', return_value=detected), \
                    patch('recovery_gui.web_bridge.backend.restore_all', side_effect=restore):
                self.assertTrue(self.bridge.recover(settings, 'fresh')['ok'])
                events = self.drain()
        result = next(event for event in events if event['kind'] == 'completed')
        self.assertEqual(result['operation'], 'recovery')
        self.assertFalse(result['checks']['functional'])
        self.assertTrue(all(client.closed for client in SSH.instances))


if __name__ == '__main__':
    unittest.main()

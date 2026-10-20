"""Headless workflow tests: no Tk window, live VM or credentials are used."""
import ast
from pathlib import Path
import queue
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from recovery_gui.ui_onboarding import (
    InputFailure, OnboardingState, ServiceOnboardingPanel, STAGES,
    connection_from_snapshot, infisical_from_fields, safe_code,
    safe_stage_event, verified_completion, verified_local_completion,
)


COMMIT = 'a' * 40
TAG = 'dr-20261020T120000Z'
SECRET = 'not-a-real-private-fixture'


def complete_result():
    return dict(status='PASS', checks=dict(service=True, agent=True, github=True, backup=True),
                public_commit=COMMIT, backup_tag=TAG)


def local_result():
    return dict(status='PASS_LOCAL', checks=dict(service=True, agent=True, github=False, backup=False))


def poll_view():
    view = Mock()
    view._alive = True
    view.events = queue.Queue()
    view.state = OnboardingState(analysis=object(), inspection=object(), private_values={'TOKEN': SECRET})
    view.stage_labels = {stage: Mock() for stage in STAGES}
    view.safe_events = []
    view.app.busy = True
    view.local_lab.get.return_value = False
    return view


class WorkflowStateTests(unittest.TestCase):
    def test_state_repr_does_not_disclose_analysis_receipt_or_private_values(self):
        state = OnboardingState(analysis={'private': SECRET}, inspection={'token': SECRET}, private_values={'TOKEN': SECRET})
        self.assertNotIn(SECRET, repr(state))
        self.assertNotIn('TOKEN', repr(state))

    def test_edit_clears_stale_inspection_and_connection_edit_preserves_analysis(self):
        analysis = object()
        state = OnboardingState(analysis=analysis, inspection=object())
        state.invalidate(analysis=False)
        self.assertIs(state.analysis, analysis)
        self.assertIsNone(state.inspection)
        with self.assertRaisesRegex(InputFailure, 'SERVICE_INPUTS_CHANGED'):
            state.record_inspection(object(), 0)
        state.record_inspection(object(), 1)
        state.invalidate()
        self.assertIsNone(state.analysis)
        self.assertIsNone(state.inspection)

    def test_clear_removes_sensitive_buffers(self):
        state = OnboardingState(analysis=object(), inspection=object(), private_values={'TOKEN': SECRET})
        state.clear()
        self.assertEqual(state.private_values, {})
        self.assertIsNone(state.analysis)
        self.assertIsNone(state.inspection)

    def test_green_container_and_generic_pass_never_complete_the_workflow(self):
        self.assertFalse(verified_completion({'status': 'PASS'}))
        self.assertFalse(verified_completion({'status': 'PASS', 'checks': {'service': True}}))
        for key in ('service', 'agent', 'github', 'backup'):
            result = complete_result()
            result['checks'][key] = False
            self.assertFalse(verified_completion(result), key)
            result['checks'][key] = 'true'
            self.assertFalse(verified_completion(result), key)
        for key in ('public_commit', 'backup_tag'):
            result = complete_result()
            result[key] = SECRET
            self.assertFalse(verified_completion(result))
        self.assertTrue(verified_completion(complete_result()))

    def test_local_completion_cannot_be_confused_with_github_and_backup_proofs(self):
        self.assertTrue(verified_local_completion(local_result()))
        self.assertFalse(verified_completion(local_result()))
        self.assertFalse(verified_local_completion(complete_result()))
        for key in ('github', 'backup'):
            result = local_result()
            result['checks'][key] = True
            self.assertFalse(verified_local_completion(result))
            result['checks'][key] = 0
            self.assertFalse(verified_local_completion(result))
        result = local_result()
        result['backup_tag'] = TAG
        self.assertFalse(verified_local_completion(result))


class PrivatePresentationTests(unittest.TestCase):
    def test_arbitrary_exception_text_is_never_a_user_visible_error(self):
        self.assertEqual(safe_code(RuntimeError(SECRET)), 'SERVICE_TOOL_FAILED')
        self.assertEqual(safe_code(ValueError('ALLCAPSPRIVATEVALUE')), 'SERVICE_TOOL_FAILED')
        self.assertEqual(safe_code(InputFailure('SERVICE_INPUTS_CHANGED')), 'SERVICE_INPUTS_CHANGED')

    def test_progress_discards_private_text_and_unrecognized_fields(self):
        event = safe_stage_event(dict(stage='PUBLIC_SYNC', status='PASS', value=SECRET,
                                      output=SECRET, message=SECRET, code='PUBLIC_SYNC_VERIFIED'))
        self.assertEqual(event, dict(stage='GITHUB', status='PASS', code='PUBLIC_SYNC_VERIFIED'))
        self.assertNotIn(SECRET, repr(event))
        self.assertEqual(safe_stage_event(dict(stage='AGENT', status='RUNNING', code='PRIVATESECRET')),
                         dict(stage='AGENT', status='RUNNING'))
        self.assertIsNone(safe_stage_event(dict(stage=SECRET, status='PASS')))
        self.assertIsNone(safe_stage_event(dict(stage='BACKUP', status=SECRET)))

    def test_laboratory_restore_progress_maps_only_fixed_stages_without_raw_text(self):
        mappings = dict(DEPENDENCIES='HOST', INFISICAL_CONFIG='INFISICAL',
            INFISICAL_DATABASE='INFISICAL', INFISICAL_SERVER='INFISICAL', INFISICAL_TRANSFER='INFISICAL',
            STACK_TRANSFER='FILES', CLONES='FILES', DOWNLOAD='FILES', DECRYPT='FILES',
            RENDER='FILES', EMPTY_STATE='FILES', RUNTIME_PROFILE='FILES', NPM='FILES',
            AIO='FILES', NPM_TOPOLOGY='FILES', PREPARED='FILES', NATIVE_AGENT='AGENT')
        for original, stage in mappings.items():
            with self.subTest(original=original):
                event = safe_stage_event(dict(stage=original, status='RUNNING', output=SECRET, message=SECRET))
                self.assertEqual(event, dict(stage=stage, status='RUNNING'))
                self.assertNotIn(SECRET, repr(event))

    def test_connection_contains_no_recovery_or_second_vm_credentials(self):
        snapshot = dict(host='192.0.2.10', user='pi', port='22', password=SECRET,
                        ssh_key='', key_password='', sudo_password=SECRET,
                        github_token=SECRET, age_identity='private-identity.txt',
                        infisical_password=SECRET, infisical_host='192.0.2.11')
        result = connection_from_snapshot(snapshot, '/home/pi/streams-aio/')
        self.assertEqual(result['port'], 22)
        self.assertEqual(result['stack_root'], '/home/pi/streams-aio')
        self.assertEqual(set(result), {'host', 'user', 'port', 'password', 'ssh_key',
                                      'key_password', 'sudo_password', 'stack_root', 'probe_url', 'verification_scope'})
        self.assertEqual(result['verification_scope'], 'full')
        self.assertEqual(result['password'], SECRET)
        for root in ('/', '/home', '/home/pi/../other', '/home//pi/streams-aio', '/home/pi\nother',
                     '/root/streams-aio', '/opt/streams-aio', '/home/pi/different-stack'):
            with self.assertRaisesRegex(InputFailure, 'SERVICE_STACK_ROOT_REQUIRED'):
                connection_from_snapshot(snapshot, root)
        with self.assertRaisesRegex(InputFailure, '^SERVICE_STACK_OWNER_MISMATCH$'):
            connection_from_snapshot(snapshot, '/home/another-user/streams-aio')

    def test_probe_is_explicit_loopback_and_never_a_credentialed_external_url(self):
        snapshot = dict(host='192.0.2.10', user='pi', port='22', password=SECRET)
        good = connection_from_snapshot(snapshot, '/home/pi/streams-aio', probe_url='http://127.0.0.1:8080/health')
        self.assertEqual(good['probe_url'], 'http://127.0.0.1:8080/health')
        for url in ('https://example.test/health', 'http://192.0.2.1:8080/health',
                    'http://user:pass@127.0.0.1:8080/health', 'http://127.0.0.1/health',
                    'http://127.0.0.1:8080/health?token=example'):
            with self.assertRaisesRegex(InputFailure, 'SERVICE_PROBE_URL_INVALID'):
                connection_from_snapshot(snapshot, '/home/pi/streams-aio', probe_url=url)

    def test_private_api_access_prefers_agent_tunnel_but_fallback_requires_https(self):
        for endpoint in ('http://example.test', 'https://user:pass@example.test',
                         'https://example.test/api', 'https://example.test/?token=x',
                         'https://example.test/#fragment', 'https://example.test:99999'):
            with self.assertRaisesRegex(InputFailure, 'SERVICE_INFISICAL_ADDRESS_REQUIRED'):
                infisical_from_fields(endpoint, 'project', 'prod', SECRET, private_required=True)
        with self.assertRaisesRegex(InputFailure, 'SERVICE_INFISICAL_ACCESS_REQUIRED'):
            infisical_from_fields('https://example.test', 'project', 'prod', '', private_required=True)
        result = infisical_from_fields('https://example.test/', 'project', 'prod', SECRET, private_required=True)
        self.assertEqual(result, dict(endpoint='https://example.test', project_id='project',
                                      environment='prod', access_token=SECRET))
        self.assertEqual(infisical_from_fields('', 'project', 'prod', SECRET, private_required=True)['endpoint'], '')
        with self.assertRaisesRegex(InputFailure, 'SERVICE_INFISICAL_ACCESS_REQUIRED'):
            infisical_from_fields('', 'project', 'prod', '', private_required=True)
        self.assertEqual(infisical_from_fields('', '', 'prod', '', private_required=False)['endpoint'], '')


class MainThreadFlowTests(unittest.TestCase):
    def test_capture_carries_local_scope_and_can_use_agent_tunnel_without_https_field(self):
        view = Mock()
        view.state = OnboardingState(analysis=object())
        view._scan_sources = ('compose', 'env', 'example')
        view._sources.return_value = view._scan_sources
        view.app.snapshot.return_value = dict(host='192.0.2.10', user='pi', port='22', password=SECRET)
        view.stack_root.get.return_value = '/home/pi/streams-aio'
        view.probe_url.get.return_value = ''
        view.local_lab.get.return_value = True
        view.endpoint.get.return_value = ''
        view.project_id.get.return_value = 'project'
        view.environment.get.return_value = 'prod'
        view.access_token.get.return_value = SECRET
        view.private_names = {'API_KEY'}
        analysis, connection, infisical = ServiceOnboardingPanel._capture(view)
        self.assertIs(analysis, view.state.analysis)
        self.assertEqual(connection['verification_scope'], 'local_lab')
        self.assertEqual(infisical['endpoint'], '')
        self.assertEqual(infisical['access_token'], SECRET)

    def test_laboratory_preparation_does_not_require_a_service_plan_or_call_apply(self):
        view = Mock()
        view._operation_running.return_value = False
        snapshot = {'host': '192.0.2.10', 'user': 'pi', 'password': SECRET, 'github_token': SECRET}
        view.app.snapshot.return_value = snapshot
        view.state = OnboardingState()
        view.events = queue.Queue()
        view.app.cancelled = threading.Event()
        view.stage_labels = {stage: Mock() for stage in STAGES}
        view.local_lab.get.return_value = False
        view.controller.prepare_lab.return_value = {'status': 'PREPARED_LAB'}
        class InlineThread:
            def __init__(self, target, daemon): self.target = target
            def start(self): self.target()
        with patch('recovery_gui.ui_onboarding.threading.Thread', InlineThread):
            ServiceOnboardingPanel._start_job(view, 'prepare_lab')
        view._capture.assert_not_called()
        view.controller.prepare_lab.assert_called_once()
        self.assertIs(view.controller.prepare_lab.call_args.args[0], snapshot)
        view.controller.apply.assert_not_called()
        view.controller.inspect.assert_not_called()
        events = [view.events.get_nowait() for _ in range(view.events.qsize())]
        self.assertEqual(events, [('prepare_lab', (0, {'status': 'PREPARED_LAB'})), ('done', None)])
        self.assertNotIn(SECRET, repr(events))
        for stage in ('GITHUB', 'BACKUP'):
            self.assertEqual(view.stage_labels[stage].configure.call_args.kwargs['text'], 'Escluso dal collaudo')

    def test_verified_laboratory_preparation_sets_local_scope_and_owner_root(self):
        view = poll_view()
        view._app_value.return_value = 'pi'
        view.events.put(('prepare_lab', (0, {'status': 'PREPARED_LAB'})))
        ServiceOnboardingPanel.poll(view)
        view.local_lab.set.assert_called_once_with(True)
        view.stack_root.set.assert_called_once_with('/home/pi/streams-aio')
        self.assertIn('Stack completo non avviato', view.lab_hint.set.call_args.args[0])
        self.assertIsNone(view.state.analysis)
        self.assertIsNone(view.state.inspection)
        view.access_token.set.assert_not_called()

    def test_incomplete_or_stale_laboratory_preparation_does_not_enable_local_scope(self):
        for revision, result, expected in ((0, {'status': 'PASS'}, 'SERVICE_LAB_PREPARATION_INCOMPLETE'),
                                           (1, {'status': 'PREPARED_LAB'}, 'SERVICE_INPUTS_CHANGED')):
            view = poll_view()
            view.events.put(('prepare_lab', (revision, result)))
            ServiceOnboardingPanel.poll(view)
            self.assertEqual(str(view._show_error.call_args.args[0]), expected)
            view.local_lab.set.assert_not_called()
            view.stack_root.set.assert_not_called()

    def test_local_success_marks_publication_and_backup_excluded_and_clears_private_buffers(self):
        view = poll_view()
        view.local_lab.get.return_value = True
        view.events.put(('apply', (0, local_result())))
        ServiceOnboardingPanel.poll(view)
        self.assertIn('GitHub e backup non eseguiti', view.status.set.call_args.args[0])
        for stage in ('GITHUB', 'BACKUP'):
            self.assertEqual(view.stage_labels[stage].configure.call_args.kwargs['text'], 'Escluso dal collaudo')
            self.assertNotEqual(view.stage_labels[stage].configure.call_args.kwargs['foreground'], '#1e8069')
        self.assertEqual(view.state.private_values, {})
        view.access_token.set.assert_called_once_with('')
        self.assertFalse(verified_completion(local_result()))

    def test_local_scope_rejects_full_success_and_suppresses_green_backup_events(self):
        view = poll_view()
        view.local_lab.get.return_value = True
        view.events.put(('stage', {'stage': 'BACKUP', 'status': 'PASS'}))
        view.events.put(('apply', (0, complete_result())))
        ServiceOnboardingPanel.poll(view)
        self.assertEqual(str(view._show_error.call_args.args[0]), 'SERVICE_OPERATION_INCOMPLETE')
        self.assertEqual(view.safe_events, [{'stage': 'BACKUP', 'status': 'SKIPPED'}])
        self.assertNotEqual(view.stage_labels['BACKUP'].configure.call_args.kwargs['foreground'], '#1e8069')
        view.access_token.set.assert_not_called()

    def test_reanalysis_discards_private_override_when_variable_returns_to_public(self):
        view = Mock()
        view._operation_running.return_value = False
        view._sources.return_value = ('services:\n  example:\n    image: example:latest', '', 'example')
        view._planner.return_value.inspect_inputs.return_value = (
            SimpleNamespace(name='CUSTOM', suggested_private=False),
            SimpleNamespace(name='API_KEY', suggested_private=True),
        )
        view.state = OnboardingState(private_values={'CUSTOM': SECRET, 'API_KEY': SECRET})
        ServiceOnboardingPanel.analyse_variables(view)
        self.assertEqual(view.private_names, {'API_KEY'})
        self.assertEqual(view.state.private_values, {'API_KEY': SECRET})
        self.assertIsNone(view.state.analysis)
        view._show_error.assert_not_called()

    def test_inspection_from_stale_draft_is_not_accepted(self):
        view = poll_view()
        view.state.inspection = None
        view.state.revision = 3
        view.events.put(('inspect', (2, object())))
        ServiceOnboardingPanel.poll(view)
        self.assertIsNone(view.state.inspection)
        self.assertEqual(str(view._show_error.call_args.args[0]), 'SERVICE_INPUTS_CHANGED')

    def test_partial_apply_does_not_display_completed_or_mark_all_stages_green(self):
        view = poll_view()
        view.events.put(('apply', (0, dict(status='PASS', checks={'service': True}))))
        ServiceOnboardingPanel.poll(view)
        self.assertIsNone(view.state.inspection)
        self.assertEqual(str(view._show_error.call_args.args[0]), 'SERVICE_OPERATION_INCOMPLETE')
        for label in view.stage_labels.values():
            label.configure.assert_not_called()
        view.access_token.set.assert_not_called()

    def test_completion_from_stale_draft_cannot_mark_current_plan_complete(self):
        view = poll_view()
        view.state.revision = 2
        view.events.put(('apply', (1, complete_result())))
        ServiceOnboardingPanel.poll(view)
        self.assertEqual(str(view._show_error.call_args.args[0]), 'SERVICE_INPUTS_CHANGED')
        for label in view.stage_labels.values():
            label.configure.assert_not_called()
        view.access_token.set.assert_not_called()
        self.assertEqual(view.state.private_values, {'TOKEN': SECRET})

    def test_verified_apply_clears_sensitive_values_and_shows_verified_backup(self):
        view = poll_view()
        view.events.put(('apply', (0, complete_result())))
        view.events.put(('done', None))
        ServiceOnboardingPanel.poll(view)
        self.assertEqual(view.state.private_values, {})
        self.assertIsNone(view.state.analysis)
        self.assertIsNone(view.state.inspection)
        view.access_token.set.assert_called_once_with('')
        self.assertIn(TAG, view.status.set.call_args.args[0])
        self.assertFalse(view.app.busy)
        self.assertFalse(view._busy)

    def test_worker_queues_protocol_without_touching_tk(self):
        view = Mock()
        view._operation_running.return_value = False
        analysis = object()
        connection = {'password': SECRET}
        infisical = {'access_token': SECRET}
        receipt = object()
        view._capture.return_value = analysis, connection, infisical
        view.state = OnboardingState(analysis=analysis, inspection=receipt)
        view.events = queue.Queue()
        view.app.cancelled = threading.Event()
        view.local_lab.get.return_value = False
        view.stage_labels = {stage: Mock() for stage in STAGES}
        calls = []
        def apply(a, c, i, r, progress):
            calls.append((a, c, i, r))
            progress({'stage': 'AGENT', 'status': 'PASS', 'message': SECRET})
            return complete_result()
        view.controller.apply.side_effect = apply
        class InlineThread:
            def __init__(self, target, daemon): self.target = target
            def start(self): self.target()
        with patch('recovery_gui.ui_onboarding.threading.Thread', InlineThread):
            ServiceOnboardingPanel._start_job(view, 'apply')
        self.assertEqual(calls, [(analysis, connection, infisical, receipt)])
        events = [view.events.get_nowait() for _ in range(view.events.qsize())]
        self.assertEqual(events[0], ('stage', {'stage': 'AGENT', 'status': 'PASS'}))
        self.assertEqual(events[-1], ('done', None))
        self.assertNotIn(SECRET, repr(events))
        # Tk updates happen before thread.start; callbacks only put safe events.
        view._show_error.assert_not_called()

    def test_plan_export_calls_only_value_free_public_serializer(self):
        view = Mock()
        view._operation_running.return_value = False
        view.state = OnboardingState(analysis=Mock())
        view.state.analysis.plan.to_public_dict.return_value = {'schema': 1, 'service_name': 'example'}
        view.state.analysis.sensitive.as_dict.return_value = {'TOKEN': SECRET}
        temporary_root = Path(__file__).parents[1] / '.testtmp'
        temporary_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=temporary_root) as folder:
            path = Path(folder) / 'plan.json'
            with patch('recovery_gui.ui_onboarding.filedialog.asksaveasfilename', return_value=str(path)):
                ServiceOnboardingPanel.export_plan(view)
            text = path.read_text(encoding='utf-8')
        self.assertNotIn(SECRET, text)
        view.state.analysis.sensitive.as_dict.assert_not_called()
        view.state.analysis.plan.to_public_dict.assert_called_once()

    def test_module_does_not_create_native_window_or_connection_on_import(self):
        source = Path(__file__).parents[1] / 'recovery_gui' / 'ui_onboarding.py'
        tree = ast.parse(source.read_text(encoding='utf-8'))
        top_calls = [node for statement in tree.body if isinstance(statement, (ast.Expr, ast.Assign))
                     for node in ast.walk(statement) if isinstance(node, ast.Call)]
        names = [ast.unparse(call.func) for call in top_calls]
        self.assertNotIn('tk.Tk', names)
        self.assertNotIn('SSH', names)
        self.assertNotIn('subprocess.run', names)


if __name__ == '__main__':
    unittest.main()

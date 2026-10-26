"""Desktop restart discovery against the actual remote JSON handler and journal."""
import copy
import json
import unittest
from unittest.mock import patch

from remote.service_tooling import ToolingFailure

from recovery_gui.onboarding import ServiceController, OnboardingError, PRIVATE_PROOF
from tests import test_onboarding_wire as wire_fixture
from tests.test_service_onboarding_remote import ROOT, LAYOUT, remote


class ActualDiscoveryWireTests(unittest.TestCase):
    setUp = wire_fixture.OnboardingWireTests.setUp
    analysis = wire_fixture.OnboardingWireTests.analysis

    def new_controller(self):
        return ServiceController(lambda *_: False,
            ssh_factory=lambda *_args, **_kwargs: self.ssh,
            api_factory=lambda *_args, **_kwargs: self.api,
            resource_dir=wire_fixture.RESOURCES, sleeper=lambda _: None)

    def install(self):
        analysis = self.analysis()
        receipt = self.controller.inspect(analysis, self.connection, self.infisical)
        request = self.controller._request('apply', analysis, self.connection, self.infisical, receipt)
        result = self.controller._remote(self.ssh, request)
        self.assertEqual(result['status'], 'SERVICE_READY')
        return analysis, receipt, request

    def journal(self, receipt):
        return self.store.json(self.engine.journal_path(receipt.job_id))

    def discover(self, analysis, **changes):
        controller = self.new_controller()
        request = controller._request('discover', analysis, self.connection, self.infisical)
        request.update(changes)
        return controller._remote(self.ssh, request)

    def test_new_controller_adopts_actual_vm_journal_without_local_saved_ids(self):
        analysis, previous, _ = self.install()
        before_writes, before_calls, before_requests = len(self.store.writes), len(self.runner.calls), len(self.ssh.requests)
        restarted = self.new_controller()
        receipt = restarted.inspect(analysis, self.connection, self.infisical)
        self.assertTrue(receipt.resume)
        self.assertEqual(receipt.job_id, previous.job_id)
        self.assertEqual(receipt.fingerprint, previous.fingerprint)
        self.assertEqual(receipt.resume_phase, 'SERVICE_READY')
        self.assertEqual([row['action'] for row in self.ssh.requests[before_requests:]], ['discover'])
        self.assertEqual(len(self.store.writes), before_writes)
        for args, _ in self.runner.calls[before_calls:]:
            self.assertFalse(any(action in args for action in ('up', 'pull', 'restart', 'start')))
        journal = json.dumps(self.journal(receipt))
        for private in ('synthetic-ssh-password', 'synthetic-api-token'):
            self.assertNotIn(private, journal)
            self.assertNotIn(private, b''.join(self.ssh.raw_responses).decode())

    def test_changed_installed_content_refuses_resume_instead_of_reinstalling(self):
        analysis, receipt, _ = self.install()
        file = ROOT / analysis.plan.configuration_files[0]['path']
        old = self.store.snapshot(file)
        self.store.put(file, old.raw + b'changed', old.uid, old.gid, old.mode, old.attributes)
        before = len(self.store.writes)
        with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_RESUME_CHANGED$'):
            self.new_controller().inspect(analysis, self.connection, self.infisical)
        self.assertEqual(len(self.store.writes), before)

    def test_two_matching_durable_jobs_require_review(self):
        analysis, receipt, _ = self.install()
        duplicate = self.journal(receipt)
        duplicate['job_id'] = '8' * 32
        self.engine.save(duplicate)
        before = len(self.store.writes)
        with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_RESUME_AMBIGUOUS$'):
            self.new_controller().inspect(analysis, self.connection, self.infisical)
        self.assertEqual(len(self.store.writes), before)

    def test_incomplete_operation_is_not_silently_treated_as_a_fresh_plan(self):
        analysis, receipt, _ = self.install()
        journal = self.journal(receipt)
        journal['phase'] = 'FILES_WRITTEN'
        self.engine.save(journal)
        with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_INTERRUPTED_REVIEW_REQUIRED$'):
            self.new_controller().inspect(analysis, self.connection, self.infisical)

    def test_rolled_back_and_foreign_operations_are_not_adopted(self):
        analysis, receipt, _ = self.install()
        journal = self.journal(receipt)
        for changes in (dict(phase='ROLLED_BACK'), dict(root='/home/other/streams-aio'), dict(owner='other')):
            with self.subTest(changes=changes):
                self.engine.save(dict(journal, **changes))
                self.assertEqual(self.discover(analysis)['status'], 'NO_JOB')

    def test_changed_public_plan_and_private_binding_plan_do_not_adopt_public_job(self):
        self.install()
        for changed in (self.analysis(large=True), self.analysis(private=True)):
            with self.subTest(private=bool(changed.plan.private_bindings)):
                self.assertEqual(self.discover(changed)['status'], 'NO_JOB')

    def test_verification_scope_is_not_relaxed(self):
        analysis, _, _ = self.install()
        marker = dict(schema=1, kind='prepared_onboarding_lab', root=str(ROOT), owner=LAYOUT.user,
                      machine_id='0123456789abcdef0123456789abcdef', publications_disabled=True)
        self.store.put(LAYOUT.state / 'lab.json', remote.canonical_json(marker), 0, 0, 0o600)
        self.assertEqual(self.discover(analysis, verification_scope='local_lab')['status'], 'NO_JOB')

    def test_legacy_public_job_can_resume_when_unused_infisical_fields_change(self):
        analysis, receipt, _ = self.install()
        self.infisical['project_id'] = 'different-unused-project'
        self.infisical['environment'] = 'different-unused-environment'
        resumed = self.new_controller().inspect(analysis, self.connection, self.infisical)
        self.assertTrue(resumed.resume)
        self.assertEqual(resumed.job_id, receipt.job_id)

    def test_many_preflight_positions_and_references_remain_a_valid_gui_diagnostic(self):
        analysis = self.analysis()
        path = analysis.plan.configuration_files[0]['path']
        references = ['/demo/KEY_' + str(i).zfill(2) for i in range(25)]
        diagnostic = dict(schema=1, stage='GITHUB', code='PRIVATE_VALUE_IN_PUBLIC_FILE',
            path=path, lines=list(range(1, 26)), references=references, retryable=False)
        with patch.object(self.runner, 'public_preflight', side_effect=remote.Refused(
                'ONBOARDING_PUBLIC_PREFLIGHT_FAILED', diagnostic)):
            with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_PUBLIC_PREFLIGHT_FAILED$') as raised:
                self.controller.inspect(analysis, self.connection, self.infisical)
        self.assertEqual(raised.exception.diagnostic['path'], path)
        self.assertEqual(raised.exception.diagnostic['lines'], list(range(1, 21)))
        self.assertEqual(raised.exception.diagnostic['references'], references[:20])
        self.assertFalse(self.runner.started)
        self.assertFalse(self.store.writes)
        self.assertFalse(self.api.calls)

    def test_remote_diagnostic_references_match_desktop_length_and_depth_limits(self):
        analysis = self.analysis()
        path = analysis.plan.configuration_files[0]['path']
        references = ['/valid/KEY', '/' + 'f' * 65 + '/KEY', '/demo/' + 'k' * 129,
                      '/root/' + '/'.join('part' for _ in range(9)), 17]
        diagnostic = dict(schema=1, stage='GITHUB', code='PRIVATE_VALUE_IN_PUBLIC_FILE',
            path=path, lines=[], references=references, retryable=False)
        with patch.object(self.runner, 'public_preflight', side_effect=remote.Refused(
                'ONBOARDING_PUBLIC_PREFLIGHT_FAILED', diagnostic)):
            with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_PUBLIC_PREFLIGHT_FAILED$') as raised:
                self.controller.inspect(analysis, self.connection, self.infisical)
        self.assertEqual(raised.exception.diagnostic['references'], ['/valid/KEY'])

    def test_explicit_tooling_button_crosses_real_remote_dispatch_without_application_changes(self):
        analysis = self.analysis()
        before = len(self.store.writes)
        with patch.object(remote, 'prepare_tooling', return_value=dict(schema=1, status='TOOLS_READY')) as prepare:
            result = self.controller.prepare_tools(analysis, self.connection, self.infisical, self.events.append)
        self.assertEqual(result, dict(status='TOOLS_READY'))
        self.assertEqual([row['action'] for row in self.ssh.requests], ['update_tools'])
        prepare.assert_called_once_with(LAYOUT, self.runner, self.store, self.ssh.requests[0])
        self.assertEqual(len(self.store.writes), before)
        self.assertFalse(self.runner.started)
        self.assertFalse(self.api.calls)
        self.assertEqual(self.ssh.closed, 1)

    def test_tooling_failure_crosses_real_remote_dispatch_with_safe_retry_metadata(self):
        with patch.object(remote, 'prepare_tooling', side_effect=remote.ToolingFailure('ONBOARDING_TOOLING_LOCAL_CHANGES')):
            with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_TOOLING_LOCAL_CHANGES$') as raised:
                self.controller.prepare_tools(self.analysis(), self.connection, self.infisical)
        self.assertEqual(raised.exception.diagnostic,
            dict(schema=1, stage='HOST', code='TOOLING_UPDATE_REQUIRED', retryable=True, references=[]))
        self.assertFalse(self.runner.started)
        self.assertFalse(self.api.calls)

    def test_private_job_never_uses_unused_public_scope_relaxation(self):
        _, receipt, request = self.install()
        private = self.analysis(private=True)
        journal = self.journal(receipt)
        normalized, _ = remote.plan_document(private.plan.deployment_payload())
        journal['plan'] = normalized
        private_request = dict(request, plan=private.plan.deployment_payload())
        journal['request_identity'] = self.engine.request_identity(private_request)
        self.engine.save(journal)
        self.assertEqual(self.discover(private, project_id='other-project')['status'], 'NO_JOB')
        self.assertEqual(self.discover(private, environment='other-environment')['status'], 'NO_JOB')


if __name__ == '__main__':
    unittest.main()
"""Configuration updates cross the actual remote JSON wire and durable journal."""
from contextlib import contextmanager
import copy
import json
import unittest
from unittest.mock import patch

import yaml
from recovery_gui.onboarding import ServiceController, OnboardingError
from recovery_gui.service_plan import analyze_inputs
from remote import service_configuration as update
from tests.test_onboarding_controller import FakeAPI
from tests import test_onboarding_wire as wire_fixture
from tests.test_service_configuration_remote import ConfigurationRunner
from tests.test_service_resources_remote import bundle
from tests.test_service_onboarding_remote import FakeEngine, MemoryStore, ROOT, LAYOUT, remote


class ConfigurationWireTests(unittest.TestCase):
    def setUp(self):
        base = wire_fixture.OnboardingWireTests(); base.setUp()
        self.connection, self.infisical = base.connection, base.infisical
        self.store = MemoryStore()
        self.store.put(remote.PurePosixPath('/usr/local/sbin/streams-aio-services-dr-backup'), b'# installed\n', 0, 0, 0o755)
        self.runner = ConfigurationRunner(self.store)
        self.runner.started = False
        self.engine = FakeEngine(LAYOUT, self.runner, self.store)
        self.ssh = wire_fixture.EngineWireSSH(self.engine, self.runner, self.store)
        self.api = FakeAPI()
        self.events = []
        @contextmanager
        def locks(engine): yield
        patcher = patch.object(update, '_worker_locks', locks)
        patcher.start(); self.addCleanup(patcher.stop)
        self.original = self.analysis('title: Original public theme\n')
        self.updated = self.analysis('title: Revised public theme\n')
        controller = self.new_controller()
        receipt = controller.inspect(self.original, self.connection, self.infisical)
        self.add_receipt = receipt
        result = controller._remote(self.ssh, controller._request('apply', self.original, self.connection, self.infisical, receipt))
        self.assertEqual(result['status'], 'SERVICE_READY')
        self.store.writes.clear()
        self.ssh.requests.clear()
        self.ssh.raw_responses.clear()
        self.runner.calls.clear()

    def analysis(self, content):
        selected = bundle()
        files = copy.deepcopy(selected['configuration_files'])
        files[0]['content'] = content
        document = remote.yaml_document('services:\n'+selected['compose_fragment'])
        for service in document['services'].values(): service.pop('env_file', None)
        document.update(selected['compose_resources'])
        return analyze_inputs(yaml.safe_dump(document, sort_keys=False), 'PORT=8080\n', configuration_files=files)

    def new_controller(self):
        return ServiceController(lambda *_: False, ssh_factory=lambda *_a, **_k: self.ssh,
            api_factory=lambda *_a, **_k: self.api, resource_dir=wire_fixture.RESOURCES, sleeper=lambda _: None)

    def enable_local_scope(self):
        self.connection['verification_scope'] = 'local_lab'
        self.store.directory(LAYOUT.state, 0, 0, 0o700, create=True)
        marker = dict(schema=1, kind='prepared_onboarding_lab', root=str(ROOT), owner=LAYOUT.user,
            machine_id=self.store.read('/etc/machine-id').decode().strip(), publications_disabled=True)
        self.store.put(LAYOUT.state/'lab.json', remote.canonical_json(marker))

    def publish(self, analysis):
        plan, _ = remote.plan_document(analysis.plan.deployment_payload())
        self.runner.public_files = {'docker-compose.yml': self.store.read(ROOT/'docker-compose.yml')}
        inventory = remote.load_json(self.store.read(ROOT/'config/service-resources.json'))
        for row in inventory['configuration_files']:
            row['sha256'] = remote.digest(next(x for x in plan['configuration_files'] if x['path']==row['path'])['content'].encode())
        self.runner.public_files['config/service-resources.json'] = remote.canonical_json(inventory)+b'\n'
        lock, override = {}, {'services': {}}
        for child in remote.components(plan):
            self.runner.public_files[child['public_env_path']] = child['public_env_text'].encode()
            pinned = child['image'].rsplit(':',1)[0]+'@sha256:'+'3'*64
            lock[child['service_name']] = {'image': pinned, 'configured_image': child['image'], 'platform': 'linux/amd64'}
            override['services'][child['service_name']] = {'image': pinned}
        for row in plan['configuration_files']:
            self.runner.public_files[row['path']] = row['content'].encode()
        self.runner.public_files['config/image-lock.json'] = json.dumps(lock).encode()
        self.runner.public_files['config/compose.dr.yaml'] = json.dumps(override).encode()

    def test_actual_local_configuration_update_and_fresh_controller_resume(self):
        self.enable_local_scope()
        before_compose = self.store.snapshot(ROOT/'docker-compose.yml')
        before_env = self.store.snapshot(ROOT/'data/demo/.env')
        controller = self.new_controller()
        receipt = controller.inspect_configuration(self.updated, self.connection, self.infisical, self.events.append)
        self.assertEqual(receipt.kind, 'configuration')
        self.assertFalse(self.store.writes)
        result = controller.apply_configuration(self.updated, self.connection, self.infisical, receipt, self.events.append)
        self.assertEqual(result['status'], 'PASS_LOCAL')
        self.assertEqual(self.store.snapshot(ROOT/'docker-compose.yml'), before_compose)
        self.assertEqual(self.store.snapshot(ROOT/'data/demo/.env'), before_env)
        self.assertEqual(self.api.calls, [])
        restarted = self.new_controller()
        resumed = restarted.inspect_configuration(self.updated, self.connection, self.infisical)
        self.assertTrue(resumed.resume)
        self.assertEqual(resumed.job_id, receipt.job_id)
        before = len(self.store.writes)
        repeated = restarted.apply_configuration(self.updated, self.connection, self.infisical, resumed)
        self.assertEqual(repeated['status'], 'PASS_LOCAL')
        self.assertEqual(len(self.store.writes), before)
        self.assertTrue(all(row['action'] in ('configuration_discover','inspect_configuration','apply_configuration') for row in self.ssh.requests))
        for arguments, _ in self.runner.calls:
            self.assertFalse(arguments[:2] == ['systemctl','restart'])
            if arguments[:2] == ['docker','compose']:
                self.assertNotIn(arguments[6], ('up','stop','restart','down','pull'))

    def test_actual_full_update_public_readback_and_backup_complete(self):
        self.publish(self.updated)
        controller = self.new_controller()
        receipt = controller.inspect_configuration(self.updated, self.connection, self.infisical)
        result = controller.apply_configuration(self.updated, self.connection, self.infisical, receipt, self.events.append)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result.get('operation_kind'), 'configuration')
        self.assertTrue(all(result['checks'].values()))
        self.assertEqual(self.api.calls, [])
        journal = self.store.json(self.engine.journal_path(receipt.job_id))
        self.assertEqual(journal['kind'], 'configuration')
        self.assertEqual(journal['phase'], 'COMPLETE')
        self.assertTrue(journal['configuration_updated'])
        self.assertEqual(self.store.json(self.engine.journal_path(self.add_receipt.job_id))['phase'], 'SERVICE_READY')
        self.assertNotIn('synthetic-ssh-password', b''.join(self.ssh.raw_responses).decode())
        self.assertNotIn('synthetic-api-token', b''.join(self.ssh.raw_responses).decode())

    def test_add_mode_does_not_adopt_configuration_journal(self):
        self.enable_local_scope()
        updater = self.new_controller()
        receipt = updater.inspect_configuration(self.updated, self.connection, self.infisical)
        updater.apply_configuration(self.updated, self.connection, self.infisical, receipt)
        before = len(self.store.writes)
        with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_SERVICE_ALREADY_EXISTS$'):
            self.new_controller().inspect(self.updated, self.connection, self.infisical)
        self.assertEqual(len(self.store.writes), before)
        self.assertEqual(self.api.calls, [])

    def test_missing_remote_configuration_proof_is_refused_then_durable_resume_works(self):
        self.enable_local_scope()
        controller = self.new_controller()
        receipt = controller.inspect_configuration(self.updated, self.connection, self.infisical)
        def omit_proof(response):
            if response.get('status') == 'SERVICE_READY': response.pop('configuration_updated', None)
            return response
        self.ssh.response_transform = omit_proof
        with self.assertRaisesRegex(OnboardingError, '^SERVICE_OPERATION_INCOMPLETE$'):
            controller.apply_configuration(self.updated, self.connection, self.infisical, receipt)
        self.ssh.response_transform = None
        restarted = self.new_controller()
        resumed = restarted.inspect_configuration(self.updated, self.connection, self.infisical)
        self.assertTrue(resumed.resume)
        self.assertEqual(resumed.job_id, receipt.job_id)
        self.assertEqual(restarted.apply_configuration(self.updated, self.connection, self.infisical, resumed)['status'], 'PASS_LOCAL')

    def test_preview_with_add_kind_is_rejected_before_apply(self):
        def wrong_kind(response):
            if response.get('status') == 'PREVIEW': response['operation_kind'] = 'add'
            return response
        self.ssh.response_transform = wrong_kind
        with self.assertRaisesRegex(OnboardingError, '^SERVICE_RESPONSE_INVALID$'):
            self.new_controller().inspect_configuration(self.updated, self.connection, self.infisical)
        self.assertFalse(self.store.writes)


if __name__ == '__main__': unittest.main()

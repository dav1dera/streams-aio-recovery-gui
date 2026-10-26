"""Candidate readiness must finish before live onboarding side effects."""
import base64
import copy
import json
import unittest
from unittest.mock import patch

from recovery_gui.service_plan import analyze_inputs
from tests.test_service_onboarding_remote import FakeEngine, FakeRunner, LAYOUT, MemoryStore, ROOT, COMPOSE, remote, plan
from tests.test_service_resources_remote import BundleRunner, bundle

PRIVATE_VALUE = 'readiness-private-value-never-transported'
PUBLIC_CONTENT = 'readiness-public-configuration-canary'


class ReadinessRunner(BundleRunner):
    def __init__(self, store):
        super().__init__(store)
        self.failure = None
        self.readiness_calls = []
        self.candidate_compose = []
        self.candidates = []
        self.checkpoints = []

    def checkpoint(self, stage):
        self.readiness_calls.append(stage)
        self.checkpoints.append((len(self.store.writes), self.started,
            sum(args[:3] == ['systemctl', 'restart', remote.AGENT_UNIT] for args, _ in self.calls)))
        if self.failure == stage:
            reasons = {'compose': ('ONBOARDING_PREFLIGHT_COMPOSE_FAILED', 'COMPOSE_CONFIG_FAILED', 'HOST'),
                'images': ('ONBOARDING_IMAGE_UNAVAILABLE', 'IMAGE_UNAVAILABLE', 'HOST'),
                'public': ('ONBOARDING_PUBLIC_PREFLIGHT_FAILED', 'PRIVATE_VALUE_IN_PUBLIC_FILE', 'GITHUB'),
                'tools': ('ONBOARDING_TOOLING_UPDATE_REQUIRED', 'TOOLING_UPDATE_REQUIRED', 'GITHUB')}
            code, reason, stage_name = reasons[stage]
            raise remote.Refused(code, dict(schema=1, stage=stage_name, code=reason,
                path='data/demo/public/config/settings.yaml', lines=[1],
                references=['/demo/ApiToken'], retryable=False,
                private_value=PRIVATE_VALUE, message='Never expose ' + PRIVATE_VALUE))

    def validate_candidate(self, raw):
        self.candidate_compose.append(raw)
        self.checkpoint('compose')
        return super().validate_candidate(raw)

    def check_images(self, plan_value):
        self.checkpoint('images')
        return super().check_images(plan_value)

    def public_preflight(self, candidate):
        self.candidates.append(copy.deepcopy(candidate))
        self.checkpoint('tools' if self.failure == 'tools' else 'public')
        return super().public_preflight(candidate)


class ServiceReadinessTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.store.put('/usr/local/sbin/streams-aio-services-dr-backup', b'# installed fixture\n', 0, 0, 0o755)
        self.runner = ReadinessRunner(self.store)
        self.engine = FakeEngine(LAYOUT, self.runner, self.store)
        self.selected = bundle()
        self.selected['configuration_files'][0]['content'] = 'title: ' + PUBLIC_CONTENT + '\n'
        self.request = dict(action='inspect', root=str(ROOT), plan=self.selected,
                            project_id='example-project', environment='prod', probe_url='', job_id='7' * 32)

    def handle(self, **changes):
        with patch.object(remote, 'Engine', return_value=self.engine):
            return remote.handle(dict(self.request, **changes), runner=self.runner, store=self.store, layout=LAYOUT)

    def assert_no_live_side_effects(self, before):
        self.assertEqual(self.store.files, before)
        self.assertEqual(self.store.writes, [])
        self.assertFalse(self.runner.started)
        self.assertFalse(any(args[:3] == ['systemctl', 'restart', remote.AGENT_UNIT] for args, _ in self.runner.calls))

    def test_all_readiness_checks_precede_any_live_output_and_preview_stays_metadata_only(self):
        before = copy.deepcopy(self.store.files)
        result = self.handle()
        self.assertEqual(result['status'], 'PREVIEW')
        self.assertIs(type(result['schema']), int)
        self.assertEqual(result['schema'], 1)
        self.assertEqual(self.runner.readiness_calls, ['compose', 'images', 'public'])
        self.assertEqual(self.runner.checkpoints, [(0, False, 0)] * 3)
        self.assert_no_live_side_effects(before)
        self.assertNotIn(PUBLIC_CONTENT, json.dumps(result))
        self.assertFalse(any(key.startswith('_') for key in result))
        merged = remote.yaml_document(self.runner.candidate_compose[0])
        self.assertEqual(set(merged['services']), {'redis', 'demo', 'sidecar'})
        candidate = self.runner.candidates[0]
        decoded = {path: base64.b64decode(value) for path, value in candidate['files'].items()}
        self.assertEqual(decoded['data/demo/public/config/settings.yaml'],
                         ('title: ' + PUBLIC_CONTENT + '\n').encode())
        inventory = json.loads(decoded['config/service-resources.json'])
        self.assertEqual(set(inventory['configuration_files'][0]), {'path', 'mode', 'sha256'})
        self.assertEqual(candidate['directories'], {'data/demo/state': {'uid': LAYOUT.uid, 'gid': LAYOUT.gid, 'mode': 0o750}})
        self.assertEqual(candidate['private_keys'], {})

    def test_compose_image_private_content_and_tooling_failures_stop_before_installation(self):
        for failure, code, calls in (
                ('compose', 'ONBOARDING_PREFLIGHT_COMPOSE_FAILED', ['compose']),
                ('images', 'ONBOARDING_IMAGE_UNAVAILABLE', ['compose', 'images']),
                ('public', 'ONBOARDING_PUBLIC_PREFLIGHT_FAILED', ['compose', 'images', 'public']),
                ('tools', 'ONBOARDING_TOOLING_UPDATE_REQUIRED', ['compose', 'images', 'tools'])):
            with self.subTest(failure=failure):
                self.setUp()
                before = copy.deepcopy(self.store.files)
                self.runner.failure = failure
                result = self.handle()
                self.assertEqual(result['status'], 'REFUSED')
                self.assertEqual(result['code'], code)
                self.assertEqual(self.runner.readiness_calls, calls)
                self.assert_no_live_side_effects(before)
                self.assertNotIn(PRIVATE_VALUE, json.dumps(result))
                self.assertNotIn('private_value', result['diagnostic'])
                self.assertNotIn('message', result['diagnostic'])

    def test_apply_rechecks_readiness_before_writing_even_after_an_earlier_preview(self):
        preview = self.handle()
        before = copy.deepcopy(self.store.files)
        self.runner.failure = 'images'
        self.runner.readiness_calls.clear()
        result = self.handle(action='apply', fingerprint=preview['fingerprint'])
        self.assertEqual(result['code'], 'ONBOARDING_IMAGE_UNAVAILABLE')
        self.assertEqual(self.runner.readiness_calls, ['compose', 'images'])
        self.assert_no_live_side_effects(before)

    def test_entered_private_values_never_enter_candidate_overlay_or_preview(self):
        source = ('services:\n  demo:\n    image: example/demo:latest\n'
                  '    ports: ["127.0.0.1:18321:8080"]\n'
                  '    environment:\n      API_TOKEN: ${API_TOKEN}\n')
        analysis = analyze_inputs(source, 'API_TOKEN=' + PRIVATE_VALUE + '\nPORT=8080\n',
                                  private_names=['API_TOKEN'])
        self.assertIn(PRIVATE_VALUE, analysis.sensitive.as_dict().values())
        self.request['plan'] = analysis.plan.deployment_payload()
        before = copy.deepcopy(self.store.files)
        result = self.handle()
        self.assertEqual(result['status'], 'PREVIEW')
        candidate = self.runner.candidates[0]
        self.assertEqual(candidate['private_keys'], {'.secrets/demo.env': ['API_TOKEN']})
        self.assertNotIn(PRIVATE_VALUE, json.dumps(candidate))
        self.assertNotIn(PRIVATE_VALUE, b''.join(base64.b64decode(value) for value in candidate['files'].values()).decode())
        self.assertNotIn(PRIVATE_VALUE, json.dumps(result))
        self.assertNotIn('.secrets/demo.env', candidate['files'])
        self.assert_no_live_side_effects(before)

    def test_local_lab_checks_compose_and_images_without_publication_preflight(self):
        self.store.directory(LAYOUT.state, 0, 0, 0o700, create=True)
        marker = dict(schema=1, kind='prepared_onboarding_lab', root=str(ROOT), owner=LAYOUT.user,
                      machine_id='0123456789abcdef0123456789abcdef', publications_disabled=True)
        self.store.put(LAYOUT.state / 'lab.json', remote.canonical_json(marker), 0, 0, 0o600)
        result = self.handle(verification_scope='local_lab')
        self.assertEqual(result['status'], 'PREVIEW')
        self.assertEqual(self.runner.readiness_calls, ['compose', 'images'])
        self.assertEqual(self.runner.candidates, [])
        self.assertEqual(self.store.writes, [])

    def test_resumed_ready_job_checks_current_public_source_without_reinstalling(self):
        preview = self.handle()
        ready = self.handle(action='apply', fingerprint=preview['fingerprint'])
        self.assertEqual(ready['status'], 'SERVICE_READY')
        before = copy.deepcopy(self.store.files)
        self.store.writes.clear()
        starts = sum('up' in args for args, _ in self.runner.calls)
        self.runner.readiness_calls.clear()
        result = self.handle(action='discover')
        self.assertEqual(result['status'], 'SERVICE_READY')
        self.assertEqual(result['job_id'], self.request['job_id'])
        self.assertEqual(self.runner.candidates[-1], dict(files={}, directories={}, private_keys={}))
        self.assertEqual(self.runner.readiness_calls, ['public'])
        self.assertEqual(self.store.files, before)
        self.assertEqual(self.store.writes, [])
        self.assertEqual(sum('up' in args for args, _ in self.runner.calls), starts)

    def test_resumed_public_failure_is_actionable_without_new_app_or_agent_actions(self):
        preview = self.handle()
        ready = self.handle(action='apply', fingerprint=preview['fingerprint'])
        self.assertEqual(ready['status'], 'SERVICE_READY')
        before = copy.deepcopy(self.store.files)
        self.store.writes.clear()
        calls_before = len(self.runner.calls)
        self.runner.failure = 'public'
        result = self.handle(action='discover')
        self.assertEqual(result['code'], 'ONBOARDING_PUBLIC_PREFLIGHT_FAILED')
        self.assertEqual(result['diagnostic']['code'], 'PRIVATE_VALUE_IN_PUBLIC_FILE')
        self.assertEqual(result['diagnostic']['path'], 'data/demo/public/config/settings.yaml')
        self.assertEqual(result['diagnostic']['lines'], [1])
        self.assertNotIn(PRIVATE_VALUE, json.dumps(result))
        self.assertEqual(self.store.files, before)
        self.assertEqual(self.store.writes, [])
        self.assertFalse(any('up' in args or args[:3] == ['systemctl', 'restart', remote.AGENT_UNIT]
                             for args, _ in self.runner.calls[calls_before:]))


if __name__ == '__main__':
    unittest.main()

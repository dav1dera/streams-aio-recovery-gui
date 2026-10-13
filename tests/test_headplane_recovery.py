"""Headplane TLS ordering and private, resumable local API-key bootstrap."""
import copy
import importlib.util
import json
from pathlib import Path
import os
import stat
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('headplane_recovery_tests', ROOT / 'remote/headplane_recovery.py')
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
HOST = 'controller.example.invalid'
OLD_KEY = 'SecretCanaryOldHeadscaleKey.prefix'
NEW_KEY = 'hskey-api-' + 'A' * 12 + '-' + 'B' * 64
OTHER_KEY = 'hskey-api-' + 'C' * 12 + '-' + 'D' * 64


class Runtime:
    def __init__(self, root, model, *, previous=False, responses=None):
        self.root, self.model = root, model
        self.events, self.payloads, self.commands = [], [], []
        self.previous = previous
        self.responses = list(responses if responses is not None else [401, 200])
        self.probe_error = None
        self.controller_error = None
        self.tls_error = None
        self.create_response = NEW_KEY
        self.recreate_error = None
        self.ids = dict(headplane='a' * 64, headscale='b' * 64, npm='c' * 64)
        self.image_id = 'sha256:' + 'd' * 64
        self.row = dict(Id=self.ids['headplane'], Image=self.image_id,
                        Config=dict(Image=recovery.HEADPLANE_IMAGE, Labels={
                            'com.docker.compose.project': 'streams-aio',
                            'com.docker.compose.project.working_dir': str(root),
                            'com.docker.compose.service': 'headplane'}),
                        Mounts=[dict(Type='bind', Destination=target, Source=str(root / source))
                                for target, source in (
                                    ('/etc/headplane/config.yaml', recovery.CONFIG),
                                    ('/var/lib/headplane', 'data/headplane/data'),
                                    ('/etc/headscale/config.yaml', recovery.HEADSCALE_CONFIG))])
        self.controller = types.SimpleNamespace(
            checked_container=self.checked,
            verify_controller_target=self.verify,
            ERROR_CODES=frozenset({'TAILSCALE_CONTROLLER_TARGET_MISMATCH',
                                   'TAILSCALE_CONTROLLER_OWNERSHIP_REFUSED'}))
        self.policy = types.SimpleNamespace(npm_action=self.reissue)

    def checked(self, root, model, service, run):
        self.events.append('checked:' + service)
        if self.controller_error:
            raise ValueError(self.controller_error)
        return self.ids[service]

    def verify(self, root, model, state, context, npm, run, policy):
        self.events.append('origin-proof')
        if self.tls_error:
            raise ValueError(self.tls_error)
        assert context == dict(hostname=HOST, scheme='https', port=443)
        assert npm == self.ids['npm']

    def reissue(self, root, run, action):
        assert action == 'reissue'
        self.events.append('tls')

    def run(self, args):
        args = [str(arg) for arg in args]
        self.commands.append(args)
        if args == ['docker', 'compose', '--profile', 'all', 'ps', '-aq', 'headplane']:
            return (self.ids['headplane'] if self.previous else '').encode()
        if args == ['docker', 'inspect', self.ids['headplane']]:
            return json.dumps([self.row]).encode()
        if args == ['docker', 'image', 'inspect', '--format', '{{json .Id}}', recovery.HEADPLANE_IMAGE]:
            return json.dumps(self.image_id).encode()
        if args == ['docker', 'exec', self.ids['headscale'], '/ko-app/headscale',
                    'apikeys', 'create', '--expiration', '90d', '-o', 'json']:
            self.events.append('key:create')
            return json.dumps(self.create_response).encode()
        if args == ['docker', 'compose', '--profile', 'all', 'up', '-d', '--no-deps',
                    '--force-recreate', 'headplane']:
            self.events.append('headplane:recreate')
            assert json.loads((self.root / recovery.CONFIG).read_bytes())['headscale']['api_key'] == NEW_KEY
            if self.recreate_error:
                raise ValueError(self.recreate_error)
            return b''
        raise AssertionError('Unexpected command')

    def send(self, args, root, payload):
        value = json.loads(payload)
        assert args[:8] == ['docker', 'exec', '-i', '--user', '0', '--workdir', '/app', self.ids['npm']]
        assert args[8:] == ['node', '--input-type=module', '-e', recovery.API_PROBE]
        assert value['hostname'] == HOST
        assert value['key'] not in ' '.join(args)
        self.payloads.append(value)
        self.events.append('api:probe')
        if self.probe_error:
            raise ValueError(self.probe_error)
        status = self.responses.pop(0) if self.responses else 200
        return json.dumps(dict(schema=1, status=status)).encode()


@unittest.skipUnless(os.name == 'nt' or os.geteuid() == 0,
                     'Linux integration requires trusted fixture ownership')
class HeadplaneRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'streams-aio'
        self.home = Path(self.temporary.name) / 'private'
        self.root.mkdir(mode=0o700)
        self.home.mkdir(mode=0o700)
        self.config = dict(server=dict(host='0.0.0.0', port=3000, cookie_secret='CookieCanary'),
                           headscale=dict(url='https://' + HOST, api_key=OLD_KEY,
                                          config_path='/etc/headscale/config.yaml', config_strict=True),
                           oidc=dict(enabled=False, client_secret='OidcSecretCanary'),
                           integration=dict(docker=dict(enabled=True)))
        self.config_path = self.root / recovery.CONFIG
        self.config_path.parent.mkdir(parents=True)
        self.config_path.write_text(json.dumps(self.config), encoding='utf-8')
        self.config_path.chmod(0o660)
        controller = self.root / recovery.HEADSCALE_CONFIG
        controller.parent.mkdir(parents=True)
        controller.write_text(json.dumps(dict(server_url='https://' + HOST)), encoding='utf-8')
        controller.chmod(0o660)
        database = self.root / recovery.DATABASE
        database.parent.mkdir(parents=True)
        database.write_bytes(b'SQLite format 3\0' + b'0' * 256)
        database.chmod(0o600)
        manifest = self.root / 'config/dr-manifest.yaml'
        manifest.parent.mkdir()
        self.manifest = dict(state_units=[dict(id='headscale-enrollments', services=['headscale'],
            path_or_type=recovery.DATABASE, classification='OPTIONAL_RUNTIME_STATE', backup_required=False)])
        manifest.write_text(json.dumps(self.manifest))
        manifest.chmod(0o600)
        self.state = dict(target=str(self.root), machine_id='synthetic-machine-id',
                          public_commit='f' * 40, preparation='PASS', completed=['EMPTY_STATE'],
                          runtime_profile=dict(origin='FIRST_BOOT'))
        self.save(self.home / 'state.json', self.state)
        self.model = dict(name='streams-aio', services=dict(
            headplane=dict(image=recovery.HEADPLANE_IMAGE, depends_on={'headscale': dict(condition='service_healthy')}),
            headscale=dict(image='headscale/headscale@sha256:' + 'e' * 64),
            npm=dict(image='jc21/nginx-proxy-manager@sha256:' + 'f' * 64)))
        # Windows is the GUI's development host; Linux is the remote runtime.
        # This fixed identity reader is the only OS-specific scope dependency.
        original_read = Path.read_text
        def read(path, *args, **kwargs):
            if str(path) == '/etc/machine-id':
                return self.state['machine_id']
            return original_read(path, *args, **kwargs)
        self.identity = patch.object(Path, 'read_text', read)
        self.identity.start()
        self.addCleanup(self.identity.stop)

    @staticmethod
    def save(path, value):
        path.write_text(json.dumps(value), encoding='utf-8')
        path.chmod(0o600)

    def invoke(self, runtime, save=None):
        return recovery.before_headplane(self.root, self.home, self.state, self.model,
            runtime.run, runtime.policy, lambda *args: runtime.events.append('emit:' + ':'.join(args)),
            save or self.save, controller=runtime.controller, send=runtime.send)

    def test_external_or_absent_controller_is_untouched(self):
        self.config['headscale']['url'] = 'https://external.example.invalid'
        self.config_path.write_text(json.dumps(self.config))
        runtime = Runtime(self.root, self.model)
        self.assertIs(self.invoke(runtime), self.model)
        self.assertEqual(runtime.events, [])
        for name in ('headplane', 'headscale'):
            candidate = copy.deepcopy(self.model)
            candidate['services'].pop(name)
            self.assertIsNone(recovery.controller_plan(self.root, candidate))

    def test_planning_adds_healthy_proxy_dependency_without_changing_model(self):
        original = copy.deepcopy(self.model)
        desired = recovery.planned_model(self.root, self.model)
        self.assertEqual(self.model, original)
        self.assertEqual(desired['services']['headplane']['depends_on'], {
            name: dict(condition='service_healthy', required=True) for name in ('headscale', 'npm')})
        self.model['services']['headplane']['depends_on'] = ['headscale']
        self.assertIn('npm', recovery.planned_model(self.root, self.model)['services']['headplane']['depends_on'])

    def test_oauth_started_list_dependency_is_reversed_only_in_scheduling_copy(self):
        self.model['services']['oauth2-proxy'] = dict(image='oauth-image',
            depends_on=['headplane', 'redis'], environment={'PUBLIC_OPTION': 'preserve'},
            command=['--existing-option'])
        self.model['services']['redis'] = dict(image='redis-image')
        original = copy.deepcopy(self.model)
        desired = recovery.planned_model(self.root, self.model)
        self.assertEqual(self.model, original)
        oauth = desired['services']['oauth2-proxy']
        self.assertEqual(oauth['depends_on'], ['redis'])
        self.assertEqual(oauth['environment'], original['services']['oauth2-proxy']['environment'])
        self.assertEqual(oauth['command'], original['services']['oauth2-proxy']['command'])
        self.assertEqual(desired['services']['headplane']['depends_on']['oauth2-proxy'],
                         dict(condition='service_started', required=True))
        self.assertEqual(desired['services']['headplane']['depends_on']['npm']['condition'], 'service_healthy')
        self.assertEqual(desired['services']['npm']['depends_on']['oauth2-proxy'],
                         dict(condition='service_started', required=True))

    def test_oauth_started_dict_dependency_preserves_other_edges_and_parameters(self):
        other = dict(condition='service_healthy', required=False, restart=True)
        self.model['services']['oauth2-proxy'] = dict(image='oauth-image',
            depends_on={'headplane': dict(condition='service_started', required=True),
                        'redis': other}, labels={'existing': 'preserve'})
        self.model['services']['headplane']['depends_on']['oauth2-proxy'] = dict(
            condition='service_started', required=False, restart=True)
        original = copy.deepcopy(self.model)
        desired = recovery.planned_model(self.root, self.model)
        self.assertEqual(self.model, original)
        self.assertEqual(desired['services']['oauth2-proxy']['depends_on'], {'redis': other})
        self.assertEqual(desired['services']['oauth2-proxy']['labels'], {'existing': 'preserve'})
        self.assertEqual(desired['services']['headplane']['depends_on']['oauth2-proxy'],
                         dict(condition='service_started', required=True, restart=True))

    def test_oauth_without_dependencies_still_precedes_headplane(self):
        self.model['services']['oauth2-proxy'] = dict(image='oauth-image')
        desired = recovery.planned_model(self.root, self.model)
        self.assertEqual(desired['services']['oauth2-proxy']['depends_on'], {})
        self.assertEqual(desired['services']['headplane']['depends_on']['oauth2-proxy']['condition'],
                         'service_started')

    def test_explicit_healthy_or_completion_cycle_requirements_are_not_weakened(self):
        for condition in ('service_healthy', 'service_completed_successfully'):
            for direction in ('oauth-to-headplane', 'headplane-to-oauth'):
                model = copy.deepcopy(self.model)
                model['services']['oauth2-proxy'] = dict(image='oauth-image', depends_on={})
                if direction == 'oauth-to-headplane':
                    model['services']['oauth2-proxy']['depends_on']['headplane'] = dict(condition=condition)
                else:
                    model['services']['headplane']['depends_on']['oauth2-proxy'] = dict(condition=condition)
                with self.subTest(condition=condition, direction=direction), \
                        self.assertRaisesRegex(ValueError, '^' + recovery.CONFIGURATION + '$'):
                    recovery.planned_model(self.root, model)

    def test_external_controller_keeps_oauth_dependencies_unchanged(self):
        self.model['services']['oauth2-proxy'] = dict(image='oauth-image', depends_on=['headplane'])
        self.config['headscale']['url'] = 'https://external.example.invalid'
        self.config_path.write_text(json.dumps(self.config))
        original = copy.deepcopy(self.model)
        self.assertEqual(recovery.planned_model(self.root, self.model), original)
        self.assertEqual(self.model, original)

    def test_oauth_npm_headplane_and_cometnet_graph_is_acyclic_with_original_wave_floors(self):
        profile_spec = importlib.util.spec_from_file_location('headplane_plan_profile', ROOT / 'remote/runtime_profile.py')
        profile = importlib.util.module_from_spec(profile_spec)
        profile_spec.loader.exec_module(profile)
        self.model['services']['oauth2-proxy'] = dict(image='oauth-image', depends_on=['headplane'])
        self.model['services']['cometnet'] = dict(image='cometnet-image', depends_on=['headscale'])
        original = copy.deepcopy(self.model)
        desired = recovery.planned_model(self.root, self.model)
        waves = profile.derived_waves(desired, [['headscale', 'npm'], ['headplane'], ['oauth2-proxy', 'cometnet']])
        positions = {name: index for index, wave in enumerate(waves) for name in wave}
        self.assertLess(positions['oauth2-proxy'], positions['npm'])
        self.assertLess(positions['npm'], positions['headplane'])
        self.assertLess(positions['npm'], positions['cometnet'])
        self.assertEqual(self.model, original)

    def test_npm_and_cometnet_other_dependencies_and_options_are_preserved(self):
        self.model['services']['oauth2-proxy'] = dict(image='oauth-image', depends_on=['headplane'])
        self.model['services']['npm']['depends_on'] = dict(redis=dict(condition='service_healthy', restart=True, required=False))
        self.model['services']['cometnet'] = dict(image='cometnet-image',
            depends_on=dict(comet=dict(condition='service_healthy'), npm=dict(condition='service_started', restart=True)),
            environment={'PUBLIC_OPTION': 'preserve'})
        original = copy.deepcopy(self.model)
        desired = recovery.planned_model(self.root, self.model)
        self.assertEqual(desired['services']['npm']['depends_on']['redis'],
                         original['services']['npm']['depends_on']['redis'])
        self.assertEqual(desired['services']['cometnet']['depends_on']['comet'],
                         original['services']['cometnet']['depends_on']['comet'])
        self.assertEqual(desired['services']['cometnet']['depends_on']['npm'],
                         dict(condition='service_healthy', required=True, restart=True))
        self.assertEqual(desired['services']['cometnet']['environment'], {'PUBLIC_OPTION': 'preserve'})
        self.assertEqual(self.model, original)

    def test_https_and_origin_proof_precede_auth_and_fresh_key(self):
        runtime = Runtime(self.root, self.model)
        original = copy.deepcopy(self.config)
        self.assertIs(self.invoke(runtime), self.model)
        updated = json.loads(self.config_path.read_bytes())
        updated['headscale']['api_key'] = OLD_KEY
        self.assertEqual(updated, original)
        stages = ['checked:headscale', 'checked:npm', 'tls', 'origin-proof', 'api:probe', 'key:create']
        self.assertEqual([runtime.events.index(stage) for stage in stages],
                         sorted(runtime.events.index(stage) for stage in stages))
        self.assertEqual([value['key'] for value in runtime.payloads], [OLD_KEY, NEW_KEY])
        self.assertEqual(self.state['headplane_recovery']['phase'], 'complete')
        self.assertNotIn('headplane:recreate', runtime.events)
        self.assertEqual(runtime.events[-1], 'emit:HEADPLANE')

    def test_valid_current_key_is_reused_without_private_artifact(self):
        raw = self.config_path.read_bytes()
        runtime = Runtime(self.root, self.model, responses=[200])
        self.invoke(runtime)
        self.assertEqual(raw, self.config_path.read_bytes())
        self.assertNotIn('key:create', runtime.events)
        self.assertNotIn('headplane_recovery', self.state)
        self.assertFalse((self.home / recovery.JOURNAL).exists())

    def test_explicit_403_can_bootstrap_but_other_statuses_never_create(self):
        runtime = Runtime(self.root, self.model, responses=[403, 200])
        self.invoke(runtime)
        self.assertIn('key:create', runtime.events)
        for status in (0, 301, 302, 400, 404, 429, 500, True, '401', None):
            with self.subTest(status=status):
                self.state.pop('headplane_recovery', None)
                (self.home / recovery.JOURNAL).unlink(missing_ok=True)
                self.config_path.write_text(json.dumps(self.config))
                self.save(self.home / 'state.json', self.state)
                runtime = Runtime(self.root, self.model, responses=[status])
                with self.assertRaisesRegex(ValueError, '^' + recovery.PROBE + '$'):
                    self.invoke(runtime)
                self.assertNotIn('key:create', runtime.events)

    def test_verified_existing_failed_container_is_recreated_for_new_bind_inode(self):
        runtime = Runtime(self.root, self.model, previous=True)
        old_inode = self.config_path.stat().st_ino
        self.invoke(runtime)
        self.assertIn('headplane:recreate', runtime.events)
        self.assertNotEqual(old_inode, self.config_path.stat().st_ino)
        self.assertTrue((self.root / recovery.DATABASE).exists())
        self.assertEqual([command[-1] for command in runtime.commands if '--force-recreate' in command], ['headplane'])

    def test_complete_resume_reuses_key_without_recreating(self):
        self.invoke(Runtime(self.root, self.model, previous=True))
        runtime = Runtime(self.root, self.model, previous=True, responses=[200])
        self.invoke(runtime)
        self.assertEqual([value['key'] for value in runtime.payloads], [NEW_KEY])
        self.assertNotIn('key:create', runtime.events)
        self.assertNotIn('headplane:recreate', runtime.events)

    def test_crash_after_journal_creation_resumes_same_key(self):
        atomic = recovery._atomic
        def crash(path, raw, **kwargs):
            atomic(path, raw, **kwargs)
            if path.name == recovery.JOURNAL:
                raise OSError('Synthetic crash ' + NEW_KEY)
        with patch.object(recovery, '_atomic', crash):
            with self.assertRaisesRegex(ValueError, '^' + recovery.BOOTSTRAP + '$'):
                self.invoke(Runtime(self.root, self.model))
        self.assertEqual(json.loads(self.config_path.read_bytes()), self.config)
        self.assertNotIn('headplane_recovery', self.state)
        runtime = Runtime(self.root, self.model, responses=[200])
        self.invoke(runtime)
        self.assertEqual(json.loads(self.config_path.read_bytes())['headscale']['api_key'], NEW_KEY)
        self.assertNotIn('key:create', runtime.events)

    def test_crash_after_config_promotion_recreates_old_mount_on_resume(self):
        atomic = recovery._atomic
        def crash(path, raw, **kwargs):
            atomic(path, raw, **kwargs)
            if path == self.config_path:
                raise OSError('Synthetic crash ' + NEW_KEY)
        with patch.object(recovery, '_atomic', crash):
            with self.assertRaisesRegex(ValueError, '^' + recovery.BOOTSTRAP + '$'):
                self.invoke(Runtime(self.root, self.model, previous=True))
        self.assertEqual(self.state['headplane_recovery']['phase'], 'pending')
        runtime = Runtime(self.root, self.model, previous=True, responses=[200])
        self.invoke(runtime)
        self.assertIn('headplane:recreate', runtime.events)
        self.assertNotIn('key:create', runtime.events)

    def test_failed_recreate_retains_pending_key_and_retries_without_rotation(self):
        runtime = Runtime(self.root, self.model, previous=True)
        runtime.recreate_error = 'Process failed ' + NEW_KEY
        with self.assertRaisesRegex(ValueError, '^' + recovery.RECREATE + '$'):
            self.invoke(runtime)
        self.assertEqual(self.state['headplane_recovery']['phase'], 'recreate_required')
        resumed = Runtime(self.root, self.model, previous=True, responses=[200])
        self.invoke(resumed)
        self.assertNotIn('key:create', resumed.events)
        self.assertIn('headplane:recreate', resumed.events)

    def test_unrelated_config_drift_refuses_before_tls_or_key_mutation(self):
        self.invoke(Runtime(self.root, self.model))
        config = json.loads(self.config_path.read_bytes())
        config['server']['port'] = 12345
        self.config_path.write_text(json.dumps(config))
        runtime = Runtime(self.root, self.model, responses=[200])
        with self.assertRaisesRegex(ValueError, '^' + recovery.DRIFT + '$'):
            self.invoke(runtime)
        self.assertNotIn('tls', runtime.events)
        self.assertNotIn('key:create', runtime.events)

    def test_completed_config_rollback_to_original_is_not_adopted(self):
        original = self.config_path.read_bytes()
        self.invoke(Runtime(self.root, self.model))
        self.config_path.write_bytes(original)
        with self.assertRaisesRegex(ValueError, '^' + recovery.DRIFT + '$'):
            self.invoke(Runtime(self.root, self.model, responses=[200]))

    def test_missing_or_changed_journal_checkpoint_binding_is_refused(self):
        self.invoke(Runtime(self.root, self.model))
        artifact = self.home / recovery.JOURNAL
        original = artifact.read_bytes()
        artifact.unlink()
        with self.assertRaisesRegex(ValueError, '^' + recovery.DRIFT + '$'):
            self.invoke(Runtime(self.root, self.model))
        artifact.write_bytes(original)
        artifact.chmod(0o600)
        self.state['headplane_recovery']['applied_sha256'] = 'e' * 64
        self.save(self.home / 'state.json', self.state)
        with self.assertRaisesRegex(ValueError, '^' + recovery.DRIFT + '$'):
            self.invoke(Runtime(self.root, self.model))

    def test_foreign_pin_label_image_or_mount_never_changes_tls_or_credentials(self):
        for field in ('label', 'pin', 'image', 'mount'):
            runtime = Runtime(self.root, self.model, previous=True)
            if field == 'label': runtime.row['Config']['Labels']['com.docker.compose.project'] = 'foreign'
            elif field == 'pin': runtime.row['Config']['Image'] = 'foreign:latest'
            elif field == 'image': runtime.row['Image'] = 'sha256:' + '0' * 64
            else: runtime.row['Mounts'][0]['Source'] = '/foreign/config.yaml'
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, '^' + recovery.SCOPE + '$'):
                self.invoke(runtime)
            self.assertNotIn('tls', runtime.events)
            self.assertNotIn('key:create', runtime.events)

    def test_scope_requires_bound_fresh_checkpoint_and_optional_database_contract(self):
        original = copy.deepcopy(self.state)
        for mutation in ('target', 'prepared', 'fresh', 'empty', 'checkpoint', 'manifest', 'database'):
            self.state.clear()
            self.state.update(copy.deepcopy(original))
            self.save(self.home / 'state.json', self.state)
            manifest = self.root / 'config/dr-manifest.yaml'
            manifest.write_text(json.dumps(self.manifest))
            database = self.root / recovery.DATABASE
            database.write_bytes(b'SQLite format 3\0' + b'0' * 256)
            if mutation == 'target': self.state['target'] = '/foreign'
            elif mutation == 'prepared': self.state['preparation'] = 'FAIL'
            elif mutation == 'fresh': self.state['runtime_profile']['origin'] = 'EXISTING'
            elif mutation == 'empty': self.state['completed'] = []
            elif mutation == 'checkpoint': self.state['public_commit'] = 'a' * 40
            elif mutation == 'manifest':
                changed = copy.deepcopy(self.manifest)
                changed['state_units'][0]['backup_required'] = True
                manifest.write_text(json.dumps(changed))
            else: database.write_bytes(b'Foreign runtime file')
            runtime = Runtime(self.root, self.model)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, '^' + recovery.SCOPE + '$'):
                self.invoke(runtime)
            self.assertNotIn('tls', runtime.events)
            self.assertNotIn('key:create', runtime.events)

    def test_tls_ownership_and_probe_failures_never_issue_api_key(self):
        for source, code in (('tls', 'TAILSCALE_CONTROLLER_TARGET_MISMATCH'),
                             ('owner', 'TAILSCALE_CONTROLLER_OWNERSHIP_REFUSED'),
                             ('probe', recovery.PROBE)):
            runtime = Runtime(self.root, self.model)
            if source == 'tls': runtime.tls_error = code
            elif source == 'owner': runtime.controller_error = code
            else: runtime.probe_error = 'DNS TLS timeout ' + OLD_KEY
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, '^' + code + '$'):
                self.invoke(runtime)
            self.assertNotIn('key:create', runtime.events)
            self.assertFalse((self.home / recovery.JOURNAL).exists())

    def test_new_key_must_be_exact_cli_json_string_and_authenticate(self):
        for response in (dict(key=NEW_KEY), None, 1, OLD_KEY, OTHER_KEY + '\n'):
            runtime = Runtime(self.root, self.model)
            runtime.create_response = response
            with self.subTest(response=type(response)), self.assertRaisesRegex(ValueError, '^' + recovery.BOOTSTRAP + '$'):
                self.invoke(runtime)
            self.assertFalse((self.home / recovery.JOURNAL).exists())
        runtime = Runtime(self.root, self.model, responses=[401, 403])
        with self.assertRaisesRegex(ValueError, '^' + recovery.BOOTSTRAP + '$'):
            self.invoke(runtime)
        self.assertTrue((self.home / recovery.JOURNAL).exists())
        self.assertEqual(json.loads(self.config_path.read_bytes()), self.config)

    def test_generated_key_rejection_never_silently_rotates_again(self):
        self.invoke(Runtime(self.root, self.model))
        runtime = Runtime(self.root, self.model, responses=[401])
        with self.assertRaisesRegex(ValueError, '^' + recovery.BOOTSTRAP + '$'):
            self.invoke(runtime)
        self.assertNotIn('key:create', runtime.events)

    def test_json_duplicate_keys_symlinks_and_external_key_paths_are_refused(self):
        self.config_path.write_text('{"headscale":{},"headscale":{}}')
        with self.assertRaisesRegex(ValueError, '^' + recovery.CONFIGURATION + '$'):
            recovery.controller_plan(self.root, self.model)
        self.config_path.write_text(json.dumps(self.config))
        with patch.object(Path, 'is_symlink', return_value=True), self.assertRaisesRegex(ValueError, '^' + recovery.CONFIGURATION + '$'):
            recovery.controller_plan(self.root, self.model)
        self.config['headscale']['api_key_path'] = '/external/key'
        self.config_path.write_text(json.dumps(self.config))
        with self.assertRaisesRegex(ValueError, '^' + recovery.CONFIGURATION + '$'):
            self.invoke(Runtime(self.root, self.model))

    def test_probe_has_explicit_tls_verification_deadlines_and_fixed_output(self):
        self.assertIn('rejectUnauthorized:true', recovery.API_PROBE)
        self.assertIn('timeout:15000', recovery.API_PROBE)
        self.assertIn("path:'/api/v1/user'", recovery.API_PROBE)
        self.assertIn('Array.isArray(data.users)', recovery.API_PROBE)
        self.assertNotIn('rejectUnauthorized:false', recovery.API_PROBE)
        runtime = Runtime(self.root, self.model)
        self.invoke(runtime)
        self.assertNotIn(OLD_KEY, json.dumps(runtime.events))
        self.assertNotIn(NEW_KEY, json.dumps(runtime.events))
        self.assertNotIn(NEW_KEY, json.dumps(self.state))
        self.assertNotIn(OLD_KEY, json.dumps(runtime.commands))
        self.assertNotIn(NEW_KEY, json.dumps(runtime.commands))

    def test_transport_failure_after_creation_preserves_one_time_key_for_resume(self):
        runtime = Runtime(self.root, self.model)
        send = runtime.send
        def fail_new(args, root, payload):
            if json.loads(payload)['key'] == NEW_KEY:
                raise TimeoutError('Synthetic private timeout ' + NEW_KEY)
            return send(args, root, payload)
        runtime.send = fail_new
        with self.assertRaisesRegex(ValueError, '^' + recovery.PROBE + '$'):
            self.invoke(runtime)
        self.assertTrue((self.home / recovery.JOURNAL).exists())
        self.assertEqual(json.loads(self.config_path.read_bytes()), self.config)
        resumed = Runtime(self.root, self.model, responses=[200])
        self.invoke(resumed)
        self.assertNotIn('key:create', resumed.events)
        self.assertEqual(json.loads(self.config_path.read_bytes())['headscale']['api_key'], NEW_KEY)

    def test_posix_metadata_accepts_public_644_but_not_private_644_or_writable_public(self):
        def info(mode=0o644, uid=1000, gid=1000, links=1):
            return types.SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=uid,
                                         st_gid=gid, st_size=256, st_nlink=links)
        recovery._metadata(info(), recovery.SCOPE, public=True, posix=True)
        recovery._metadata(info(uid=0, gid=0), recovery.SCOPE, public=True, posix=True)
        recovery._metadata(info(0o660), recovery.SCOPE, posix=True)
        recovery._metadata(info(0o600), recovery.SCOPE, private=True, posix=True)
        for row, kwargs in ((info(), {}), (info(), dict(private=True)),
                            (info(0o666), dict(public=True)),
                            (info(0o664), dict(public=True)),
                            (info(0o660), dict(private=True)),
                            (info(uid=65532), dict(public=True)),
                            (info(links=2), dict(public=True))):
            with self.subTest(mode=row.st_mode, kwargs=kwargs), self.assertRaisesRegex(ValueError, '^' + recovery.SCOPE + '$'):
                recovery._metadata(row, recovery.SCOPE, posix=True, **kwargs)

    def test_atomic_journal_cannot_overwrite_an_existing_file(self):
        artifact = self.home / recovery.JOURNAL
        artifact.write_bytes(b'Existing private bytes')
        with self.assertRaisesRegex(ValueError, '^' + recovery.DRIFT + '$'):
            recovery._atomic(artifact, b'Replacement private bytes')
        self.assertEqual(artifact.read_bytes(), b'Existing private bytes')

    def test_atomic_config_promotion_rejects_stale_content(self):
        info = self.config_path.stat()
        old_hash = recovery._sha(self.config_path.read_bytes())
        changed = b'{"changed":"after validation"}'
        self.config_path.write_bytes(changed)
        with self.assertRaisesRegex(ValueError, '^' + recovery.DRIFT + '$'):
            recovery._atomic(self.config_path, b'new bytes', expected=old_hash, info=info)
        self.assertEqual(self.config_path.read_bytes(), changed)

    @unittest.skipIf(os.name == 'nt', 'POSIX private-file ownership and modes are enforced on the VM')
    def test_private_journal_permissions_and_config_mode_are_preserved(self):
        self.invoke(Runtime(self.root, self.model))
        self.assertEqual(stat.S_IMODE((self.home / recovery.JOURNAL).stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.config_path.stat().st_mode), 0o660)
        (self.home / recovery.JOURNAL).chmod(0o644)
        with self.assertRaisesRegex(ValueError, '^' + recovery.DRIFT + '$'):
            self.invoke(Runtime(self.root, self.model))


if __name__ == '__main__':
    unittest.main()

"""Private local Headscale enrollment through the normal startup path."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tailscale_recovery_tests', ROOT/'remote/tailscale_recovery.py')
recovery = importlib.util.module_from_spec(spec); spec.loader.exec_module(recovery)
probe_spec = importlib.util.spec_from_file_location('tailscale_strict_nonce_policy', ROOT/'remote/operational_profile.py')
probe_policy = importlib.util.module_from_spec(probe_spec); probe_spec.loader.exec_module(probe_policy)
HOST = 'controller.example.invalid'
CANARY = 'SecretCanaryEnrollmentKey1234567890'


class Runtime:
    def __init__(self, root, model, backend='NeedsLogin', existing=True):
        self.root, self.model = root, copy.deepcopy(model)
        self.backend, self.existing = backend, existing
        self.events, self.raw_keys = [], []
        self.ids = dict(headscale='a'*64, npm='b'*64, tailscale='c'*64)
        self.images = {name: 'sha256:' + str(index)*64 for index, name in enumerate(self.ids, 1)}
        self.rows = {}
        for name, identifier in self.ids.items():
            binds = ({'/data': 'data/npm/data', '/etc/letsencrypt': 'data/npm/data/letsencrypt'}
                     if name == 'npm' else {'/etc/headscale': 'data/headscale/data/config',
                        '/var/lib/headscale': 'data/headscale/data/lib',
                        '/var/run/headscale': 'data/headscale/data/run'} if name == 'headscale' else {})
            self.rows[name] = dict(Id=identifier, Image=self.images[name],
                Config=dict(Image=recovery.PINS[name], Labels={
                    'com.docker.compose.project': 'streams-aio',
                    'com.docker.compose.project.working_dir': str(root),
                    'com.docker.compose.service': name}),
                State=dict(Running=True, Health=dict(Status='healthy')),
                HostConfig=dict(NetworkMode='host' if name == 'tailscale' else 'streams-aio_default'),
                Mounts=[dict(Type='bind', Destination=target, Source=str(root/source)) for target, source in binds.items()])
        self.users = None
        self.created_user = dict(id='7', name=recovery.USER)
        self.created_key = dict(key=CANARY)
        self.marker_failure = None
        self.probe_failure = None
        self.module = types.SimpleNamespace(verify=self.verify_topology)
        self.route = dict(id=4, routing=dict(domain_names=[HOST], forward_host='headscale',
                    forward_port=8080, forward_scheme='http'))
        self.deployment = dict(bindings=[dict(table='proxy_host', id=4, path=['forward_host'],
                                           role='compose', service='headscale')])
        self.policy = types.SimpleNamespace(npm_action=self.npm_action, topology_targets=self.topology_targets,
                                            nonce_probe_code=probe_policy.nonce_probe_code)
        self.profile = types.SimpleNamespace(migrate_tailscale=self.migrate, ERROR_CODES=frozenset())

    def run(self, args):
        args = [str(arg) for arg in args]
        if args[:7] == ['docker', 'compose', '--profile', 'all', 'ps', '-aq', args[-1]]:
            service = args[-1]; self.events.append('select:'+service)
            return (self.ids[service] if service != 'tailscale' or self.existing else '').encode()
        if args[:2] == ['docker', 'inspect']:
            name = next(name for name, identifier in self.ids.items() if identifier == args[2])
            self.events.append('inspect:'+name)
            return json.dumps([self.rows[name]]).encode()
        if args[:3] == ['docker', 'image', 'inspect']:
            self.assert_exact(args[3:5], ['--format', '{{json .Id}}'])
            name = next(name for name, image in recovery.PINS.items() if image == args[-1])
            self.events.append('image:'+name)
            return json.dumps(self.images[name]).encode()
        if args[:2] == ['docker', 'stop']:
            self.assert_exact(args[2], self.ids['tailscale'])
            self.events.append('stop'); return b''
        if args[:3] == ['docker', 'exec', self.ids['tailscale']]:
            self.assert_exact(args[3:], ['tailscale', 'status', '--json'])
            self.events.append('backend')
            return json.dumps(dict(BackendState=self.backend)).encode()
        if args[:4] == ['docker', 'exec', self.ids['headscale'], '/ko-app/headscale']:
            command = args[4:]
            if command == ['users', 'list', '-o', 'json']:
                self.events.append('users:list'); return json.dumps(self.users).encode()
            if command == ['users', 'create', recovery.USER, '-o', 'json']:
                self.events.append('users:create'); return json.dumps(self.created_user).encode()
            if command == ['preauthkeys', 'create', '--user', '7', '--expiration', '15m', '-o', 'json']:
                self.events.append('keys:create'); return json.dumps(self.created_key).encode()
            raise AssertionError('Unexpected Headscale command')
        if args[:7] == ['docker', 'compose', '--profile', 'all', 'config', '--format', 'json']:
            self.events.append('config'); return json.dumps(self.model).encode()
        if args[:2] == [sys.executable, '-c']:
            self.events.append('https')
            self.assert_exact(args[-2], HOST)
            if self.probe_failure:
                raise ValueError(self.probe_failure)
            return b''
        raise AssertionError('Unexpected command')

    @staticmethod
    def assert_exact(actual, expected):
        if actual != expected:
            raise AssertionError('Unexpected command arguments')

    def send(self, args, root, payload):
        value = json.loads(payload)
        self.events.append('marker:'+value['action'])
        self.assert_exact(value['kind'], 'headscale')
        self.assert_exact(value['forward_hosts'], [self.route['routing']['forward_host']])
        self.assert_exact(value['forward_port'], 8080)
        if value['action'] == self.marker_failure:
            raise ValueError(CANARY)
        return b'{"status":"PASS"}'

    def npm_action(self, root, run, action):
        self.assert_exact(action, 'reissue'); self.events.append('reissue')

    def topology_targets(self, root, state):
        self.events.append('topology')
        return self.module, self.deployment, {}, [self.route]

    def verify_topology(self, *args, **kwargs):
        self.events.append('topology:verify')

    def migrate(self, root, home, state, model, run, raw):
        self.events.append('migrate'); self.raw_keys.append(raw)
        state['runtime_profile']['tailscale_artifact'] = '.generated/tailscale-recovery.env'
        self.model['services']['tailscale']['environment'].update(
            TS_AUTHKEY=raw.split(b'\n')[0].split(b'=', 1)[1].decode(), TS_AUTH_ONCE='true')


class LocalControllerRecovery(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config = self.root/'data/headscale/data/config/config.yaml'
        self.config.parent.mkdir(parents=True)
        self.config.write_text(json.dumps(dict(server_url='https://'+HOST)))
        self.model = dict(name='streams-aio', services={name: dict(image=image) for name, image in recovery.PINS.items()})
        self.model['services']['tailscale'].update(network_mode='host', environment=dict(
            TS_EXTRA_ARGS='--advertise-exit-node --login-server "https://'+HOST+'"', TS_AUTHKEY=CANARY))
        self.state = dict(runtime_profile={}, operational_deployment=dict(domain_target_address='192.168.1.20'))

    def runtime(self, **kwargs):
        return Runtime(self.root, self.model, **kwargs)

    def invoke(self, runtime):
        with patch.object(recovery, 'private_run', runtime.send):
            return recovery.before_tailscale(self.root, self.root/'private', self.state, self.model,
                runtime.run, runtime.profile, runtime.policy, lambda *args: runtime.events.append('emit:'+':'.join(args)))

    def test_no_tailscale_custom_server_or_local_controller_is_a_noop(self):
        for mutation in ('absent', 'default', 'external', 'no_headscale'):
            model = copy.deepcopy(self.model)
            if mutation == 'absent': model['services'].pop('tailscale')
            elif mutation == 'default': model['services']['tailscale']['environment']['TS_EXTRA_ARGS'] = '--advertise-exit-node'
            elif mutation == 'external': model['services']['tailscale']['environment']['TS_EXTRA_ARGS'] = '--login-server=https://external.example.invalid'
            else: model['services'].pop('headscale')
            with self.subTest(mutation=mutation):
                self.assertIsNone(recovery.controller_plan(self.root, model))
                run = unittest.mock.Mock(side_effect=AssertionError('No command expected'))
                self.assertIs(recovery.before_tailscale(self.root, self.root, {}, model, run, None, None, None), model)
                recovery.preflight_dns(self.root, model, {}, run)
                run.assert_not_called()

    def test_url_and_argument_ambiguities_are_closed_errors(self):
        values = ['--login-server', '--login-server=', '--login-server=https://'+HOST+' --login-server=https://'+HOST,
                  '--login-server=http://'+HOST, '--login-server=https://'+HOST+':8443',
                  '--login-server=https://user:password@'+HOST, '--login-server=https://'+HOST+'/?private=canary',
                  '--login-server=https://'+HOST+'/#fragment', '--login-server=https://'+HOST+'/prefix',
                  '--login-server "unterminated', '--login-server=https://bad..example.invalid']
        for value in values:
            self.model['services']['tailscale']['environment']['TS_EXTRA_ARGS'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, '^'+recovery.CONFIGURATION+'$'):
                recovery.controller_plan(self.root, self.model)

    def test_headscale_config_must_be_regular_json_with_checked_parents(self):
        for value in ('not yaml or json', '{}', '{"server_url":"http://'+HOST+'"}'):
            self.config.write_text(value)
            with self.assertRaisesRegex(ValueError, '^'+recovery.CONFIGURATION+'$'):
                recovery.controller_plan(self.root, self.model)
        self.config.write_text(json.dumps(dict(server_url='https://'+HOST)))
        with patch.object(Path, 'is_symlink', return_value=True), self.assertRaisesRegex(ValueError, '^'+recovery.CONFIGURATION+'$'):
            recovery.controller_plan(self.root, self.model)

    def test_only_local_controller_adds_planning_dependencies_without_mutation(self):
        original = copy.deepcopy(self.model)
        desired = recovery.planned_model(self.root, self.model)
        self.assertEqual(self.model, original)
        self.assertEqual(desired['services']['tailscale']['depends_on'], {
            name: dict(condition='service_healthy', required=True) for name in ('headscale', 'npm')})
        self.config.write_text(json.dumps(dict(server_url='https://external.example.invalid')))
        self.assertEqual(recovery.planned_model(self.root, self.model), original)

    def test_private_dns_mismatch_is_refused_before_workload_commands(self):
        calls = []
        def run(args): calls.append(args); return b'["192.168.1.11"]'
        with self.assertRaisesRegex(ValueError, '^TAILSCALE_CONTROLLER_DNS_MISMATCH$'):
            recovery.preflight_dns(self.root, self.model, self.state, run)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], sys.executable)
        self.assertIn('timeout=8', calls[0][2])

    def test_dns_accepts_replacement_or_public_proxy_and_sanitizes_failure(self):
        for answers in (b'["192.168.1.20"]', b'["104.16.0.1"]', b'["104.16.0.1","192.168.1.11"]'):
            recovery.preflight_dns(self.root, self.model, self.state, lambda args: answers)
        def broken(args): raise ValueError(CANARY+' '+HOST)
        with self.assertRaisesRegex(ValueError, '^TAILSCALE_CONTROLLER_UNREACHABLE$'):
            recovery.preflight_dns(self.root, self.model, self.state, broken)

    def test_empty_database_uses_fixed_user_numeric_uid_and_short_lived_key_after_proof(self):
        runtime = self.runtime()
        result = self.invoke(runtime)
        self.assertEqual(result['services']['tailscale']['environment']['TS_AUTH_ONCE'], 'true')
        self.assertEqual(runtime.raw_keys, [('TS_AUTHKEY='+CANARY+'\nTS_AUTH_ONCE=true\n').encode()])
        ordered = ['image:tailscale', 'backend', 'reissue', 'marker:install', 'https', 'marker:remove',
                   'topology:verify', 'stop', 'users:list', 'users:create', 'keys:create', 'migrate', 'config']
        positions = [runtime.events.index(event) for event in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(runtime.events[-1], 'emit:TAILSCALE')

    def test_no_container_is_first_enrollment_without_stop(self):
        runtime = self.runtime(existing=False)
        runtime.users = []
        self.invoke(runtime)
        self.assertNotIn('stop', runtime.events)
        self.assertIn('users:create', runtime.events)

    def test_known_sole_user_is_reused_without_user_creation(self):
        runtime = self.runtime()
        runtime.users = [dict(id=7, name=recovery.USER)]
        self.invoke(runtime)
        self.assertNotIn('users:create', runtime.events)
        self.assertIn('keys:create', runtime.events)

    def test_populated_foreign_database_and_invalid_user_ids_never_create_keys(self):
        for users in ([dict(id='7', name='foreign')], [dict(id='7', name=recovery.USER)]*2,
                      [dict(id=True, name=recovery.USER)], [dict(id=str(2**63), name=recovery.USER)]):
            runtime = self.runtime(); runtime.users = users
            with self.subTest(users=users), self.assertRaisesRegex(ValueError, '^'+recovery.ENROLLMENT+'$'):
                self.invoke(runtime)
            self.assertNotIn('users:create', runtime.events)
            self.assertNotIn('keys:create', runtime.events)
            self.assertNotIn('migrate', runtime.events)

    def test_running_with_existing_binding_does_not_issue_or_migrate(self):
        self.state['runtime_profile']['tailscale_artifact'] = '.generated/tailscale-recovery.env'
        runtime = self.runtime(backend='Running')
        self.assertIs(self.invoke(runtime), self.model)
        for event in ('reissue', 'marker:install', 'stop', 'users:list', 'keys:create', 'migrate'):
            self.assertNotIn(event, runtime.events)

    def test_running_without_binding_registers_existing_key_without_key_creation(self):
        runtime = self.runtime(backend='Running')
        self.invoke(runtime)
        self.assertEqual(len(runtime.raw_keys), 1)
        for event in ('reissue', 'marker:install', 'stop', 'users:list', 'keys:create'):
            self.assertNotIn(event, runtime.events)

    def test_unsupported_backend_does_not_mutate(self):
        runtime = self.runtime(backend='NeedsMachineAuth')
        with self.assertRaisesRegex(ValueError, '^'+recovery.ENROLLMENT+'$'): self.invoke(runtime)
        self.assertNotIn('reissue', runtime.events)
        self.assertNotIn('stop', runtime.events)

    def test_wrong_target_proof_cleans_up_and_prevents_stop_or_key_creation(self):
        runtime = self.runtime(); runtime.probe_failure = CANARY+' '+HOST
        with self.assertRaisesRegex(ValueError, '^TAILSCALE_CONTROLLER_TARGET_MISMATCH$'): self.invoke(runtime)
        self.assertIn('marker:remove', runtime.events)
        for event in ('stop', 'users:list', 'keys:create', 'migrate'):
            self.assertNotIn(event, runtime.events)

    def test_failed_marker_install_still_cleans_up_without_enrollment(self):
        runtime = self.runtime(); runtime.marker_failure = 'install'
        with self.assertRaisesRegex(ValueError, '^TAILSCALE_CONTROLLER_PROBE_FAILED$'): self.invoke(runtime)
        self.assertIn('marker:remove', runtime.events)
        self.assertNotIn('users:list', runtime.events)

    def test_cleanup_failure_is_explicit_and_prevents_enrollment(self):
        runtime = self.runtime(); runtime.marker_failure = 'remove'
        with self.assertRaisesRegex(ValueError, '^TAILSCALE_CONTROLLER_PROBE_CLEANUP_REQUIRED$'): self.invoke(runtime)
        self.assertNotIn('users:list', runtime.events)

    def test_topology_requires_one_exact_headscale_http_binding(self):
        for change in ('foreign', 'port', 'scheme', 'duplicate'):
            runtime = self.runtime()
            if change == 'foreign': runtime.deployment['bindings'][0]['service'] = 'foreign'
            elif change == 'port': runtime.route['routing']['forward_port'] = 8765
            elif change == 'scheme': runtime.route['routing']['forward_scheme'] = 'https'
            else: runtime.deployment['bindings'].append(copy.deepcopy(runtime.deployment['bindings'][0]))
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, '^'+recovery.CONFIGURATION+'$'):
                self.invoke(runtime)
            self.assertNotIn('marker:install', runtime.events)
            self.assertNotIn('users:list', runtime.events)

    def test_foreign_container_image_drift_or_unhealthy_controller_prevents_all_later_mutations(self):
        for service, field, value, code in (
            ('npm', 'label', 'foreign', 'TAILSCALE_CONTROLLER_OWNERSHIP_REFUSED'),
            ('headscale', 'Image', 'sha256:'+'f'*64, 'TAILSCALE_CONTROLLER_IMAGE_REFUSED'),
            ('tailscale', 'Image', 'sha256:'+'f'*64, 'TAILSCALE_CONTROLLER_IMAGE_REFUSED'),
            ('npm', 'health', 'unhealthy', 'TAILSCALE_CONTROLLER_NOT_HEALTHY')):
            runtime = self.runtime(); row = runtime.rows[service]
            if field == 'label': row['Config']['Labels']['com.docker.compose.project'] = value
            elif field == 'health': row['State']['Health']['Status'] = value
            else: row[field] = value
            with self.subTest(service=service, field=field), self.assertRaisesRegex(ValueError, '^'+code+'$'):
                self.invoke(runtime)
            for event in ('reissue', 'marker:install', 'stop', 'users:list', 'keys:create', 'migrate'):
                self.assertNotIn(event, runtime.events)

    def test_marker_uses_exact_saved_upstream_and_host_namespace_tls(self):
        runtime = self.runtime(); runtime.route['routing']['forward_host'] = '192.168.1.20'
        invocations = []
        original = runtime.run
        def run(args): invocations.append(args); return original(args)
        runtime.run = run
        self.invoke(runtime)
        probe = next(args for args in invocations if args[:2] == [sys.executable, '-c'])
        self.assertIn('HTTPSConnection(host,443', probe[2])
        self.assertIn('ssl.create_default_context()', probe[2])
        self.assertNotIn('getaddrinfo', probe[2])
        self.assertNotIn('CERT_NONE', probe[2])

    def test_secret_cli_failure_and_invalid_key_never_escape_in_errors(self):
        runtime = self.runtime(); runtime.created_key = dict(key='invalid '+CANARY)
        with self.assertRaises(ValueError) as caught: self.invoke(runtime)
        self.assertEqual(str(caught.exception), recovery.ENROLLMENT)
        self.assertNotIn(CANARY, str(caught.exception))
        runtime = self.runtime()
        original = runtime.run
        def run(args):
            if 'preauthkeys' in args: raise ValueError(CANARY+' '+HOST)
            return original(args)
        runtime.run = run
        with self.assertRaises(ValueError) as caught: self.invoke(runtime)
        self.assertEqual(str(caught.exception), recovery.ENROLLMENT)


if __name__ == '__main__': unittest.main()

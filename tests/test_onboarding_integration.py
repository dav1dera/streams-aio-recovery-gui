"""Synthetic end-to-end contracts. No VM, native UI, sockets or private files.

The actual planner, controller, remote Engine and private HMAC proof execute.
Only OS/file storage, Docker, Agent, Infisical, systemd and GitHub are in-memory
test doubles. Ciphertext fixtures test the transport/checksum contract, not age.
"""
import base64
from contextlib import contextmanager, redirect_stdout
from dataclasses import replace
import datetime as dt
import hashlib
import hmac
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

from recovery_gui.onboarding import OnboardingError, PRIVATE_PROOF, ServiceController
from recovery_gui.service_plan import analyze_inputs


RESOURCE = Path(__file__).resolve().parents[1] / 'remote'
SPEC = importlib.util.spec_from_file_location('_onboarding_integration_remote', RESOURCE / 'service_onboarding.py')
REMOTE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = REMOTE
SPEC.loader.exec_module(REMOTE)

SECRET = 'synthetic-$Unicode-é-€-🔑-credential'
COMMIT = 'b' * 40
TAG = 'dr-20261020T120100Z'
PROJECT = 'f80601b1-73fb-49bd-9373-f3687cd5c8eb'
ROOT = PurePosixPath('/home/pi/streams-aio')
PRIVATE_PATH = ROOT / '.secrets/demo.env'


def execute_private_proof(request, raw, *, metadata=None, symlink=False):
    """Run the real shipped program with no possibility of opening a real path."""
    class ProofPath(PurePosixPath):
        def is_symlink(self):
            return symlink

    info = dict(st_mode=stat.S_IFREG | 0o640, st_uid=0, st_size=len(raw), st_nlink=1)
    info.update(metadata or {})
    output = io.StringIO()
    with patch('pathlib.Path', ProofPath), patch('os.open', return_value=47) as opened, \
            patch('os.fstat', return_value=SimpleNamespace(**info)), patch('os.read', return_value=raw), \
            patch('os.O_NOFOLLOW', 0x20000, create=True), patch('os.O_NONBLOCK', 0x800, create=True), \
            patch('os.close'), patch('sys.stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps(request).encode()))), \
            redirect_stdout(output):
        exec(compile(PRIVATE_PROOF, '<synthetic-private-proof>', 'exec'), {})
    return json.loads(output.getvalue()), opened.call_count


def proof_request(values, *, path=str(PRIVATE_PATH)):
    challenge = bytes(range(32))
    return dict(path=path, challenge=challenge.hex(), expected={name: hmac.digest(
        challenge, (name + '\0' + value).encode(), 'sha256').hex() for name, value in values.items()})


class PrivateProofIntegrationTests(unittest.TestCase):
    def test_actual_proof_accepts_literal_dollar_unicode_and_key_bound_mac(self):
        raw = ("API_KEY='" + SECRET + "'\n").encode()
        result, opened = execute_private_proof(proof_request({'API_KEY': SECRET}), raw)
        self.assertEqual(result, {'status': 'PASS'})
        self.assertEqual(opened, 1)
        self.assertNotIn(SECRET, json.dumps(result))

    def test_wrong_value_or_swapped_key_mac_never_discloses_material(self):
        request = proof_request({'API_KEY': SECRET})
        for raw in (("API_KEY='" + SECRET + "-wrong'\n").encode(),
                    ("OTHER_KEY='" + SECRET + "'\n").encode(),
                    ("API_KEY='" + SECRET + "'\nAPI_KEY='duplicate'\n").encode(),
                    b"API_KEY=''\n"):
            with self.subTest(raw_length=len(raw)):
                result, _ = execute_private_proof(request, raw)
                self.assertEqual(result, {'status': 'REFUSED'})
                self.assertNotIn(SECRET, json.dumps(result))
                self.assertNotIn('API_KEY', json.dumps(result))

    def test_path_and_metadata_refuse_without_reading_real_files(self):
        raw = ("API_KEY='" + SECRET + "'\n").encode()
        for metadata in ({'st_uid': 1000}, {'st_mode': stat.S_IFREG | 0o644},
                         {'st_nlink': 2}, {'st_mode': stat.S_IFDIR | 0o640}, {'st_size': 1024 * 1024}):
            with self.subTest(metadata=metadata):
                result, _ = execute_private_proof(proof_request({'API_KEY': SECRET}), raw, metadata=metadata)
                self.assertEqual(result, {'status': 'REFUSED'})
        result, opened = execute_private_proof(proof_request({'API_KEY': SECRET}), raw, symlink=True)
        self.assertEqual(result, {'status': 'REFUSED'})
        self.assertEqual(opened, 0)
        result, opened = execute_private_proof(proof_request({'API_KEY': SECRET}, path='/etc/shadow'), raw)
        self.assertEqual(result, {'status': 'REFUSED'})
        self.assertEqual(opened, 0)


class MemoryStore:
    def __init__(self):
        self.files, self.directories, self.serial = {}, {}, 0

    def seed(self, path, raw, uid=1000, gid=1000, mode=0o640):
        self.serial += 1
        self.files[str(path)] = REMOTE.Snapshot(str(path), raw, uid, gid, mode,
                                               device=1, inode=self.serial, mtime=self.serial)
        return self.snapshot(path)

    def safe(self, path):
        return PurePosixPath(str(path))

    def exists(self, path):
        return str(path) in self.files or str(path) in self.directories

    def snapshot(self, path, limit=REMOTE.MAX_FILE):
        item = self.files[str(path)]
        REMOTE.need(len(item.raw) <= limit, 'ONBOARDING_FILE_INVALID')
        return replace(item, attributes=item.attributes.copy())

    def read(self, path, limit=REMOTE.MAX_FILE):
        return self.snapshot(path, limit).raw

    def directory(self, path, uid, gid, mode, create=False, public=False):
        if create and str(path) not in self.directories:
            self.directories[str(path)] = (uid, gid, mode)
        REMOTE.need(self.directories.get(str(path)) == (uid, gid, mode),
                    'ONBOARDING_DIRECTORY_PERMISSIONS_INVALID')

    def write(self, path, raw, uid, gid, mode, previous=None, public=False):
        if previous is None:
            REMOTE.need(not self.exists(path), 'ONBOARDING_OUTPUT_EXISTS')
        else:
            REMOTE.need(self.snapshot(path).identity() == previous.identity(), 'ONBOARDING_SOURCE_CHANGED')
        return self.seed(path, raw, uid, gid, mode)

    def unlink(self, path, expected_hash):
        REMOTE.need(REMOTE.digest(self.read(path)) == expected_hash, 'ONBOARDING_OUTPUT_CHANGED')
        del self.files[str(path)]

    def save(self, path, value):
        return self.seed(path, REMOTE.canonical_json(value) + b'\n', 0, 0, 0o600)

    def json(self, path):
        return REMOTE.load_json(self.read(path, 16 * REMOTE.MAX_FILE))


class MemoryRunner:
    def __init__(self, layout, store):
        self.layout, self.store = layout, store
        self.values, self.calls, self.public_files = {}, [], {}
        self.release, self.assets = None, {}
        self.running, self.agent_mismatch, self.mutate_public_command = False, False, False
        self.explicit_mapping, self.missing_agent_target = False, False

    def props(self, unit):
        if unit == REMOTE.AGENT_UNIT:
            return dict(ActiveState='active', User='root', Group='pi', UMask='0027',
                        KillMode='control-group', ExecStart='/usr/bin/infisical agent --config=' + str(self.layout.agent))
        return dict(ActiveState='inactive', Result='success', ExecMainStatus='0',
                    InvocationID='new-backup' if self.release else 'old-backup', User='pi',
                    ExecStart='/home/pi/streams-aio-dr/scripts/update-dr.sh')

    def run(self, args, code, timeout=120, user=False):
        args = [str(value) for value in args]
        self.calls.append(args)
        if args[:3] == ['systemctl', 'restart', REMOTE.AGENT_UNIT]:
            document = yaml.safe_load(self.store.read(self.layout.agent))
            for row in document['templates']:
                if row['destination-path'] != str(PRIVATE_PATH):
                    continue
                lines = []
                for line in row['template-content'].splitlines():
                    key = line.split('=', 1)[0]
                    value = self.values[key] + ('-wrong' if self.agent_mismatch else '')
                    lines.append(key + "='" + value + "'\n")
                self.store.seed(PRIVATE_PATH, ''.join(lines).encode(), 0, 1000, 0o640)
            return b''
        if args[:2] == ['docker', 'compose']:
            command = args[args.index('-f') + 2:]
            if command[0] in ('config', 'pull'):
                return b''
            if command[0] == 'up':
                assert command[-1] == 'demo' and '--no-deps' in command
                self.running = True
                return b''
            if command[0] == 'ps':
                return (('c' * 64 + '\n') if self.running else '').encode()
        if args[:3] == ['docker', 'image', 'inspect']:
            return b'null'
        if args[:2] == ['docker', 'inspect']:
            return json.dumps(dict(Status='running', OOMKilled=False, Health={'Status': 'healthy'})).encode()
        if any(value.endswith('/sync-public-stack.py') for value in args):
            self.publish()
            return b''
        if args[:4] == ['systemctl', 'start', '--no-block', REMOTE.DR_UNIT]:
            self.backup()
            return b''
        raise AssertionError('Unexpected synthetic runner command')

    def publish(self):
        compose = self.store.read(ROOT / 'docker-compose.yml')
        if self.mutate_public_command:
            document = yaml.safe_load(compose)
            document['services']['demo']['command'] = ['unexpected-command']
            compose = yaml.safe_dump(document).encode()
        self.public_files['docker-compose.yml'] = compose
        self.public_files['data/demo/.env'] = self.store.read(ROOT / 'data/demo/.env')
        service = yaml.safe_load(compose)['services']['demo']
        bindings = {'API_KEY': {'path': '/demo', 'key': 'API_KEY'}} if self.values else {}
        self.public_files['config/dr-render-plan.json'] = json.dumps({
            'env_files': {'.secrets/demo.env': bindings} if self.explicit_mapping else {}}).encode()
        private = ['.secrets/demo.env'] if self.values else []
        self.public_files['config/public-stack-layout.json'] = json.dumps(dict(
            schema=1, services=['existing', 'demo'], private_env_targets=private,
            private_env_targets_from_restored_agent=[] if self.missing_agent_target else private)).encode()
        self.public_files['config/dr-manifest.yaml'] = yaml.safe_dump(dict(components={
            'demo': dict(GENERATED_FILES=private, REQUIRED_BEFORE_COMPOSE_UP=private,
                         PUBLIC_REPO_FILES=['data/demo/.env'])}, references=[dict(
                SERVICE='demo', SOURCE='.secrets/demo.env', TYPE='ENV_FILE',
                RESTORE_METHOD='INFISICAL_AGENT_RENDER', RESOLVED=True)] if private else [])).encode()
        configured = service['image']
        repository = configured.rsplit(':', 1)[0]
        pinned = repository + '@sha256:' + 'd' * 64
        self.public_files['config/image-lock.json'] = json.dumps({
            'demo': {'image': pinned, 'configured_image': configured}}).encode()
        self.public_files['config/compose.dr.yaml'] = yaml.safe_dump({'services': {'demo': {'image': pinned}}}).encode()
        self.store.seed(self.layout.home / '.local/state/streams-aio-public-sync/current.json',
                        json.dumps(dict(repository=REMOTE.PUBLIC, verified=True, commit=COMMIT)).encode())

    def backup(self):
        payloads = {name: b'age-encryption.org/v1\nsynthetic-encrypted-' + name.encode()
                    for name in REMOTE.ASSETS}
        manifest = dict(schema=2, repository=REMOTE.PRIVATE, encryption='age', run=TAG[3:],
                        stack_commit=COMMIT, artifacts={name: dict(sha256=REMOTE.digest(raw), size=len(raw))
                                                      for name, raw in payloads.items()})
        payloads['manifest.json'] = json.dumps(manifest).encode()
        payloads['SHA256SUMS'] = ''.join(REMOTE.digest(raw) + '  ' + name + '\n'
                                        for name, raw in sorted(payloads.items())).encode()
        assets = []
        for index, (name, raw) in enumerate(sorted(payloads.items()), 1):
            self.assets[str(index)] = raw
            assets.append(dict(name=name, id=index, size=len(raw), state='uploaded'))
        self.release = dict(tag_name=TAG, draft=False, prerelease=False,
                            body='streams-aio-dr-managed:v1\n', published_at='2026-10-20T12:01:00Z', assets=assets)

    def api(self, suffix, binary=False):
        if '/releases/assets/' in suffix:
            return self.assets[suffix.rsplit('/', 1)[1]]
        if '/releases?' in suffix:
            return [self.release] if self.release else []
        if '/compare/' in suffix:
            return dict(status='identical', behind_by=0)
        if '/contents/' in suffix:
            key = suffix.split('/contents/', 1)[1].split('?', 1)[0]
            return dict(encoding='base64', content=base64.b64encode(self.public_files[key]).decode())
        raise AssertionError('Unexpected synthetic GitHub request')

    def now(self):
        return dt.datetime(2026, 10, 20, 12, 0, tzinfo=dt.timezone.utc)

    def asset_digest(self, suffix, expected_size):
        raw = self.api(suffix, binary=True)
        assert len(raw) == expected_size
        return dict(sha256=REMOTE.digest(raw), size=len(raw), prefix=raw[:32])

    def sleep(self, seconds):
        pass


class MemoryEngine(REMOTE.Engine):
    @contextmanager
    def operation(self):
        yield

    @contextmanager
    def locks(self):
        yield


class MemoryHost:
    def __init__(self):
        self.layout = REMOTE.Layout(ROOT, ROOT.parent, 'pi', 1000, 1000)
        self.store = MemoryStore()
        self.runner = MemoryRunner(self.layout, self.store)
        self.engine = MemoryEngine(self.layout, self.runner, self.store)
        for path, owner in ((ROOT, (1000, 1000, 0o750)), (ROOT / 'data', (1000, 1000, 0o750)),
                            (ROOT / '.secrets', (0, 1000, 0o750))):
            self.store.directories[str(path)] = owner
        self.original_compose = b'# keep original\nservices:\n  existing:\n    image: example/existing:latest\n\nnetworks:\n  default: {}\n'
        self.store.seed(ROOT / 'docker-compose.yml', self.original_compose)
        self.store.seed('/etc/machine-id', b'synthetic-machine-id\n', 0, 0, 0o444)
        self.store.seed(self.layout.agent, b'# keep Agent\ntemplates:\n- template-content: ordinary\n  destination-path: /home/pi/streams-aio/.secrets/existing.env\n', 0, 1000, 0o640)
        self.wire, self.closed = [], 0

    def run(self, args, **kwargs):
        request = json.loads(kwargs['input'])
        self.wire.append(request)
        if args[-1] == PRIVATE_PROOF:
            result, _ = execute_private_proof(request, self.store.read(PRIVATE_PATH))
        else:
            with patch.object(REMOTE, 'Engine', return_value=self.engine):
                result = REMOTE.handle(request, runner=self.runner, store=self.store, layout=self.layout)
        return json.dumps(result).encode()

    def close(self):
        self.closed += 1


class MemoryInfisical:
    def __init__(self, host):
        self.host, self.calls = host, []

    def inspect(self, service, values):
        self.calls.append(('inspect', service))
        return {'status': 'PASS'}

    def ensure(self, service, values):
        self.calls.append(('ensure', service))
        self.host.runner.values = dict(values)
        return {'status': 'PASS'}


class OnboardingEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.host = MemoryHost()
        self.api = MemoryInfisical(self.host)
        self.controller = ServiceController(lambda *_: False,
            ssh_factory=lambda *_args, **_kwargs: self.host,
            api_factory=lambda *_args: self.api, resource_dir=RESOURCE, sleeper=lambda _: None)
        self.connection = dict(host='192.0.2.10', user='pi', port=22, password='synthetic-ssh-password',
                               stack_root=str(ROOT), ssh_key='', key_password='', sudo_password='')
        self.infisical = dict(endpoint='https://infisical.example.test', project_id=PROJECT,
                              environment='prod', access_token='synthetic-api-token')

    def analysis(self, private):
        env = "# public comment\nPORT=8080\n" + ("API_KEY='" + SECRET + "'\n" if private else '')
        return analyze_inputs('demo:\n  image: example/demo:latest\n  healthcheck:\n'
                              '    test: [CMD, true]\n', env, private_names=['API_KEY'] if private else [])

    def test_real_planner_payload_is_accepted_by_real_remote_parser(self):
        for compose, env, private in (
                ('demo:\n  image: example/demo:latest\n', '', []),
                ('demo:\n  image: example/demo:latest\n', 'PORT=8080\n', []),
                ('demo:\n  image: example/demo:latest\n', "API_KEY='" + SECRET + "'\n", ['API_KEY'])):
            with self.subTest(private=bool(private), public=bool(env)):
                analysis = analyze_inputs(compose, env, private_names=private)
                plan, service = REMOTE.plan_document(analysis.plan.deployment_payload())
                self.assertEqual(plan['service_name'], 'demo')
                self.assertEqual(service['env_file'][0], './data/demo/.env')
                self.assertNotIn(SECRET, json.dumps(plan))

    def test_public_and_private_service_complete_real_engine_without_os_or_network(self):
        for private in (False, True):
            with self.subTest(private=private):
                self.setUp()
                analysis = self.analysis(private)
                events = []
                receipt = self.controller.inspect(analysis, self.connection, self.infisical, events.append)
                self.assertEqual(self.host.store.read(ROOT / 'docker-compose.yml'), self.host.original_compose)
                self.assertFalse(self.host.runner.running)
                result = self.controller.apply(analysis, self.connection, self.infisical, receipt, events.append)
                self.assertEqual(result['checks'], dict(service=True, agent=True, github=True, backup=True))
                self.assertEqual(result['backup_tag'], TAG)
                self.assertTrue(self.host.runner.running)
                self.assertNotIn(SECRET, json.dumps(self.host.wire))
                self.assertNotIn(SECRET, json.dumps(result))
                self.assertNotIn(SECRET, json.dumps(events))
                if private:
                    self.assertEqual(self.host.store.read(PRIVATE_PATH), ("API_KEY='" + SECRET + "'\n").encode())
                    proof_requests = [row for row in self.host.wire if 'challenge' in row]
                    self.assertEqual(len(proof_requests), 2)
                    self.assertNotEqual(proof_requests[0]['challenge'], proof_requests[1]['challenge'])
                self.assertTrue(self.host.store.read(ROOT / 'docker-compose.yml').startswith(
                    self.host.original_compose[:self.host.original_compose.index(b'networks:')]))

    def test_real_agent_hmac_mismatch_stops_before_github_and_backup(self):
        self.host.runner.agent_mismatch = True
        analysis = self.analysis(True)
        receipt = self.controller.inspect(analysis, self.connection, self.infisical)
        with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_AGENT_VALUE_READBACK_FAILED$') as error:
            self.controller.apply(analysis, self.connection, self.infisical, receipt)
        self.assertNotIn(SECRET, str(error.exception))
        self.assertFalse(self.host.runner.public_files)
        self.assertIsNone(self.host.runner.release)

    def test_wrong_public_command_never_becomes_successful_backup(self):
        self.host.runner.mutate_public_command = True
        analysis = self.analysis(False)
        receipt = self.controller.inspect(analysis, self.connection, self.infisical)
        with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_PUBLIC_SERVICE_READBACK_FAILED$'):
            self.controller.apply(analysis, self.connection, self.infisical, receipt)
        self.assertIsNone(self.host.runner.release)

    def test_new_agent_target_requires_dynamic_restore_inventory_before_backup(self):
        self.host.runner.missing_agent_target = True
        analysis = self.analysis(True)
        receipt = self.controller.inspect(analysis, self.connection, self.infisical)
        with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_DR_MAPPING_READBACK_FAILED$'):
            self.controller.apply(analysis, self.connection, self.infisical, receipt)
        self.assertIsNone(self.host.runner.release)

    def test_legacy_explicit_binding_remains_compatible(self):
        self.host.runner.explicit_mapping = True
        analysis = self.analysis(True)
        receipt = self.controller.inspect(analysis, self.connection, self.infisical)
        result = self.controller.apply(analysis, self.connection, self.infisical, receipt)
        self.assertEqual(result['status'], 'PASS')


if __name__ == '__main__':
    unittest.main()

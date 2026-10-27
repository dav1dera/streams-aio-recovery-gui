"""Offline safety/transaction tests. No real files, processes, network or secrets."""
from contextlib import contextmanager
import base64
import copy
import datetime as dt
import json
import io
import hmac
import re
from pathlib import PurePosixPath
import threading
import unittest
from unittest.mock import patch

import yaml

from remote import service_onboarding as remote


def template_keys(text):
    keys = re.findall(r"(?:^|\}\})([A-Za-z_][A-Za-z0-9_]*)='", text, re.M)
    return list(dict.fromkeys(keys))


def private_proof(selected, value='offline-example-token'):
    normalized, _ = remote.plan_document(selected)
    challenge = bytes.fromhex('12' * 32)
    return {child['service_name']: dict(challenge=challenge.hex(), expected={key:
            hmac.digest(challenge, (key + '\0' + value).encode(), 'sha256').hex()
            for key in child['private_bindings']})
            for child in remote.components(normalized) if child['private_bindings']}


ROOT = PurePosixPath('/home/operator/streams-aio')
LAYOUT = remote.Layout(ROOT, ROOT.parent, 'operator', 1001, 1001)
COMPOSE = (b'# Public stack, comments stay intact\nservices:\n'
           b'  redis:\n    image: redis:latest\n    # existing comment\n'
           b'    profiles: [all, database]\n\nnetworks:\n  default:\n    driver: bridge\n')
AGENT = (b'# Existing authentication and template comments\ninfisical:\n  address: http://127.0.0.1:8080\n'
         b'templates:\n- template-content: \'EXISTING="example"\'\n'
         b'  destination-path: /home/operator/streams-aio/.secrets/redis.env\n'
         b'  # preserve this comment too\n\n')


def plan(private=True):
    fragment = ('  demo:\n    image: example/demo:latest\n    profiles: [all]\n'
                '    ports: ["127.0.0.1:18321:8080"]\n    env_file:\n'
                '      - ./data/demo/.env\n')
    if private:
        fragment += '      - ./.secrets/demo.env\n'
    return dict(schema=1, service_name='demo', image='example/demo:latest',
                compose_fragment=fragment, public_env_path='data/demo/.env',
                public_env_text='# keep the explanations\nPORT=8080\n',
                private_env_path='.secrets/demo.env',
                private_bindings={'ApiToken': {'folder': '/demo', 'key': 'ApiToken'}} if private else {})


class MemoryStore(remote.Store):
    def __init__(self):
        self.files, self.directories, self.clock = {}, {}, 0
        self.lock = threading.Lock()
        self.operation_active = False
        self.public_acl_watcher = False
        self.writes = []
        self.directory(ROOT, 1001, 1001, 0o750, create=True, public=True)
        self.directory(ROOT / 'data', 1001, 1001, 0o750, create=True, public=True)
        self.directory(ROOT / '.secrets', 0, 1001, 0o750, create=True)
        self.put(ROOT / 'docker-compose.yml', COMPOSE, 1001, 1001, 0o640)
        self.put(LAYOUT.agent, AGENT)
        self.put('/etc/machine-id', b'0123456789abcdef0123456789abcdef\n')
        for path in (LAYOUT.home / '.local/share/streams-aio-public-sync/tooling/scripts/sync-public-stack.py',
                     LAYOUT.home / 'streams-aio-dr/scripts/update-dr.sh',
                     LAYOUT.home / '.local/state/streams-aio-public-sync/run.lock',
                     LAYOUT.home / '.local/state/streams-aio-dr/run.lock'):
            self.put(path, b'# offline installed worker\n', 1001, 1001, 0o640)

    def safe(self, path):
        path = PurePosixPath(path)
        remote.need(path.is_absolute() and '..' not in path.parts, 'ONBOARDING_SYMLINK_PATH_REFUSED')
        return path

    def put(self, path, raw, uid=0, gid=0, mode=0o600, attributes=None):
        path = str(self.safe(path))
        self.clock += 1
        self.files[path] = remote.Snapshot(path, raw, uid, gid, mode, 1, self.clock, self.clock, attributes or {})
        return copy.deepcopy(self.files[path])

    def exists(self, path):
        return str(self.safe(path)) in self.files or str(self.safe(path)) in self.directories

    def snapshot(self, path, limit=remote.MAX_FILE):
        item = copy.deepcopy(self.files[str(self.safe(path))])
        remote.need(len(item.raw) <= limit, 'ONBOARDING_FILE_INVALID')
        return item

    def directory(self, path, uid, gid, mode, create=False, public=False):
        name = str(self.safe(path))
        if create and name not in self.directories:
            self.directories[name] = (uid, gid, mode, {})
        actual = self.directories[name]
        remote.need(actual[:2] == (uid, gid) and (public or actual[2:] == (mode, {})),
                    'ONBOARDING_DIRECTORY_PERMISSIONS_INVALID')

    def journal_paths(self, directory):
        prefix = str(directory).rstrip('/') + '/'
        return [remote.PurePosixPath(name) for name in sorted(self.files)
                if name.startswith(prefix) and remote.JOB.fullmatch(name[len(prefix):].removesuffix('.json'))
                and name.endswith('.json')]

    def write(self, path, raw, uid, gid, mode, previous=None, public=False):
        if previous is None:
            remote.need(not self.exists(path), 'ONBOARDING_OUTPUT_EXISTS')
        else:
            remote.need(self.snapshot(path).identity() == previous.identity(), 'ONBOARDING_SOURCE_CHANGED')
        attributes = copy.deepcopy(previous.attributes) if previous else {}
        written_mode = mode
        if public and self.public_acl_watcher:
            written_mode |= 0o030
            attributes['system.posix_acl_access'] = b'public-file-watcher'
        result = self.put(path, raw, uid, gid, written_mode, attributes)
        self.writes.append((str(path), public))
        remote.need(remote.metadata_matches(result, mode, previous.attributes if previous else {}, public),
                    'ONBOARDING_WRITE_VERIFICATION_FAILED')
        return result

    def unlink(self, path, expected_hash):
        remote.need(remote.digest(self.read(path)) == expected_hash, 'ONBOARDING_OUTPUT_CHANGED')
        del self.files[str(self.safe(path))]


class FakeRunner:
    def __init__(self, store):
        self.store, self.calls = store, []
        self.started = False
        self.container_state = {'Status': 'running', 'OOMKilled': False, 'Health': {'Status': 'healthy'}}
        self.image_volumes = None
        self.empty_private = False
        self.fail_config = False
        self.before_config_failure = None
        self.public_files = {}
        self.public_commit = '1' * 40
        self.backup_commit = '2' * 40
        self.dr_started = False
        self.time = dt.datetime(2026, 10, 20, 12, 0, tzinfo=dt.timezone.utc)
        self.probe_ok = True
        self.finalize_lock_seen = []
        self.agent_kind = 'production_yaml'
        self.agent_config = LAYOUT.agent
        self.dr_load_state = 'loaded'

    def validate_candidate(self, raw):
        self.calls.append((['candidate-compose-validation'], False))

    def check_images(self, plan):
        self.calls.append((['candidate-image-validation'], False))

    def check_ports(self, plan):
        self.calls.append((['candidate-port-validation'], False))

    def public_preflight(self, candidate):
        self.calls.append((['candidate-public-validation'], False))
        return dict(schema=1, status='PASS', stage='PUBLIC_EXPORT')

    def props(self, unit):
        if unit == remote.AGENT_UNIT:
            return dict(ActiveState='active', User='operator' if self.agent_kind == 'recovered_json' else 'root',
                        Group='operator', UMask='0077' if self.agent_kind == 'recovered_json' else '0027',
                        KillMode='control-group', ExecStart='/usr/bin/infisical agent --config ' + str(self.agent_config))
        return dict(LoadState=self.dr_load_state, ActiveState='inactive', Result='success', ExecMainStatus='0',
                    InvocationID='new-invocation' if self.dr_started else 'previous-invocation',
                    User='operator', ExecStart='/home/operator/streams-aio-dr/scripts/update-dr.sh')

    def run(self, args, code, timeout=120, user=False):
        args = list(map(str, args))
        self.calls.append((args, user))
        if args[:2] == ['docker', 'compose']:
            operation = args[6:]
            if operation[:2] == ['config', '--quiet'] and self.fail_config:
                if self.before_config_failure:
                    self.before_config_failure()
                raise remote.Refused(code)
            if operation[:1] == ['up']:
                self.started = True
            if operation[:1] == ['ps']:
                return ('a' * 64).encode() if self.started else b''
            return b''
        if args[:3] == ['docker', 'image', 'inspect']:
            return json.dumps(self.image_volumes).encode()
        if args[:2] == ['docker', 'inspect']:
            return json.dumps(self.container_state).encode()
        if args[:3] == ['systemctl', 'restart', remote.AGENT_UNIT]:
            rows = yaml.safe_load(self.store.read(self.agent_config))['templates']
            row = rows[-1]
            keys = template_keys(row['template-content'])
            value = '' if self.empty_private else 'offline-example-token'
            self.store.put(row['destination-path'], ''.join(key + "='" + value + "'\n" for key in keys).encode(),
                           1001 if self.agent_kind == 'recovered_json' else 0, 1001,
                           0o600 if self.agent_kind == 'recovered_json' else 0o640)
            return b''
        if args[:3] == ['systemctl', 'start', '--no-block']:
            self.finalize_lock_seen.append(self.store.operation_active)
            self.dr_started = True
            self.build_release()
            return b''
        if args[0].endswith('/venv/bin/python'):
            self.finalize_lock_seen.append(self.store.operation_active)
            self.store.put(LAYOUT.home / '.local/state/streams-aio-public-sync/current.json',
                           json.dumps(dict(repository=remote.PUBLIC, verified=True, commit=self.public_commit)).encode(),
                           1001, 1001, 0o600)
            return b'No command output is forwarded by the engine.'
        return b''

    def publish_files(self, selected):
        normalized, service = remote.plan_document(selected)
        self.public_files = {
            'docker-compose.yml': yaml.safe_dump({'services': {'demo': service}}).encode(),
            normalized['public_env_path']: normalized['public_env_text'].encode(),
            'config/dr-render-plan.json': json.dumps({'env_files': {
                normalized['private_env_path']: {key: {'path': value['folder'], 'key': value['key']}
                                                for key, value in normalized['private_bindings'].items()}}}).encode(),
            'config/image-lock.json': json.dumps({'demo': {'image': 'example/demo@sha256:' + '3' * 64,
                                                          'configured_image': normalized['image'],
                                                          'platform': 'linux/amd64'}}).encode(),
            'config/compose.dr.yaml': json.dumps({'services': {'demo': {'image': 'example/demo@sha256:' + '3' * 64}}}).encode()
        }

    def build_release(self):
        tag = 'dr-20261020T120001Z'
        self.downloads = {name: b'age-encryption.org/v1\n' + name.encode() for name in remote.ASSETS}
        manifest = dict(schema=2, repository=remote.PRIVATE, encryption='age', run=tag[3:],
                        stack_commit=self.backup_commit,
                        artifacts={name: {'sha256': remote.digest(raw), 'size': len(raw)}
                                   for name, raw in self.downloads.items()})
        self.downloads['manifest.json'] = json.dumps(manifest).encode()
        self.downloads['SHA256SUMS'] = ''.join(remote.digest(raw) + '  ' + name + '\n'
                                              for name, raw in self.downloads.items()).encode()
        self.assets = [{'id': index + 1, 'name': name, 'size': len(raw), 'state': 'uploaded'}
                       for index, (name, raw) in enumerate(self.downloads.items())]
        self.release = dict(tag_name=tag, body='streams-aio-dr-managed:v1\n', draft=False, prerelease=False,
                            published_at='2026-10-20T12:00:01Z', assets=self.assets)

    def api(self, suffix, binary=False):
        if '/contents/' in suffix:
            path = suffix.split('/contents/', 1)[1].split('?ref=', 1)[0]
            return dict(encoding='base64', content=base64.b64encode(self.public_files[path]).decode())
        if '/compare/' in suffix:
            return dict(status='ahead', behind_by=0)
        if '/releases/assets/' in suffix:
            selected = next(item for item in self.assets if item['id'] == int(suffix.rsplit('/', 1)[1]))
            return self.downloads[selected['name']]
        if suffix.endswith('/releases?per_page=100'):
            return [self.release] if self.dr_started else []
        raise AssertionError('Unexpected public fake API endpoint')

    def asset_digest(self, suffix, expected_size):
        raw = self.api(suffix, binary=True)
        remote.need(len(raw) == expected_size, 'ONBOARDING_BACKUP_ASSET_SIZE_INVALID')
        return dict(sha256=remote.digest(raw), size=len(raw), prefix=raw[:32])

    def now(self):
        return self.time

    def sleep(self, seconds):
        self.time += dt.timedelta(seconds=seconds)

    def probe(self, url):
        return self.probe_ok


class FakeEngine(remote.Engine):
    @contextmanager
    def locks(self):
        yield

    @contextmanager
    def operation(self):
        remote.need(self.store.lock.acquire(blocking=False), 'ONBOARDING_OTHER_OPERATION_RUNNING')
        self.store.operation_active = True
        try:
            yield
        finally:
            self.store.operation_active = False
            self.store.lock.release()


class RemoteOnboardingTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.runner = FakeRunner(self.store)
        self.engine = FakeEngine(LAYOUT, self.runner, self.store)
        self.request = dict(action='apply', root=str(ROOT), plan=plan(), project_id='example-project',
                            environment='prod', probe_url='', job_id='4' * 32)

    def preview(self):
        self.request['fingerprint'] = self.engine.inspect(self.request)['fingerprint']
        self.request['private_proof'] = private_proof(self.request['plan'])
        return self.request

    def apply(self):
        return self.engine.apply(self.preview())

    def journal(self):
        return self.store.json(self.engine.journal_path(self.request['job_id']))

    def recovered_profile(self, mode=0o700, address='http://127.0.0.1:18180'):
        path = LAYOUT.home / '.local/share/streams-aio-recovery/native-agent/agent-config.json'
        document = yaml.safe_load(AGENT)
        document['infisical']['address'] = address
        raw = json.dumps(document, indent=2, ensure_ascii=False).encode() + b'\n'
        self.store.put(path, raw, 1001, 1001, 0o600)
        self.store.directories[str(ROOT / '.secrets')] = (1001, 1001, mode, {})
        self.runner.agent_kind, self.runner.agent_config = 'recovered_json', path
        return path, raw

    def local_lab(self):
        self.request['verification_scope'] = 'local_lab'
        self.store.directory(LAYOUT.state, 0, 0, 0o700, create=True)
        marker = dict(schema=1, kind='prepared_onboarding_lab', root=str(ROOT), owner='operator',
                      machine_id=self.store.read('/etc/machine-id').decode().strip(), publications_disabled=True)
        self.store.put(LAYOUT.state / 'lab.json', json.dumps(marker).encode())
        for path in list(self.store.files):
            if '/streams-aio-public-sync/' in path or '/streams-aio-dr/' in path:
                del self.store.files[path]
        return marker

    def finalize(self):
        self.runner.publish_files(self.request['plan'])
        result = self.engine.finalize(self.request)
        self.assertEqual(result['status'], 'BACKUP_RUNNING')
        return self.engine.finalize(self.request)

    def refused(self, code, fn):
        with self.assertRaises(remote.Refused) as found:
            fn()
        self.assertEqual(str(found.exception), code)

    def test_merge_preserves_all_existing_bytes_comments_and_crlf(self):
        for source in (COMPOSE, COMPOSE.replace(b'\n', b'\r\n')):
            merged = remote.merge_compose(source, plan())
            self.assertEqual(merged.count(b'# existing comment'), 1)
            self.assertEqual(merged[:source.index(b'networks:')], source[:source.index(b'networks:')])
            self.assertTrue(merged.endswith(source[source.index(b'networks:'):]))
            self.assertIn('demo', yaml.safe_load(merged)['services'])
            if b'\r\n' in source:
                self.assertNotIn(b'\n', merged.replace(b'\r\n', b''))

    def test_existing_anchor_and_comments_remain_untouched(self):
        source = b'x-common: &common\n  restart: unless-stopped\nservices:\n  redis:\n    <<: *common\n    image: redis\n'
        result = remote.merge_compose(source, plan())
        self.assertTrue(result.startswith(source))
        self.assertEqual(yaml.safe_load(result)['services']['redis']['restart'], 'unless-stopped')

    def test_existing_service_and_duplicate_yaml_keys_are_refused(self):
        source = b'services:\n  demo:\n    image: example/demo:latest\n'
        self.refused('ONBOARDING_SERVICE_ALREADY_EXISTS', lambda: remote.merge_compose(source, plan()))
        self.refused('ONBOARDING_DUPLICATE_YAML_KEY', lambda: remote.yaml_document('a: 1\na: 2\n'))

    def test_agent_append_preserves_existing_config_and_uses_supported_getter(self):
        normalized, _ = remote.plan_document(plan())
        result = remote.extend_agent(AGENT, ROOT, normalized, 'example-project', 'prod')
        self.assertTrue(result.startswith(AGENT))
        rows = yaml.safe_load(result)['templates']
        self.assertEqual(rows[-1]['destination-path'], str(ROOT / '.secrets/demo.env'))
        template = rows[-1]['template-content']
        self.assertIn('range listSecrets "example-project" "prod" "/demo"', template)
        self.assertIn('expandSecretReferences', template)
        self.assertIn('false', template)
        self.assertEqual(template_keys(template), ['ApiToken'])
        self.assertFalse(template.endswith('\n'))
        self.assertNotIn(b'offline-example-token', result)

    def test_agent_hooks_and_existing_destination_are_refused(self):
        normalized, _ = remote.plan_document(plan())
        self.refused('ONBOARDING_AGENT_HOOK_REVIEW_REQUIRED',
                     lambda: remote.extend_agent(AGENT + b'exec: dangerous\n', ROOT, normalized, 'project', 'prod'))
        once = remote.extend_agent(AGENT, ROOT, normalized, 'project', 'prod')
        self.refused('ONBOARDING_AGENT_DESTINATION_EXISTS',
                     lambda: remote.extend_agent(once, ROOT, normalized, 'project', 'prod'))

    def test_recovered_json_append_preserves_every_existing_character(self):
        path, raw = self.recovered_profile()
        normalized, _ = remote.plan_document(plan())
        node = remote.mapping_value(yaml.compose(raw.decode()), 'templates')
        position = node.value[-1].end_mark.index
        result = remote.extend_agent(raw, ROOT, normalized, 'project', 'prod', 'recovered_json')
        self.assertTrue(result.startswith(raw[:position]))
        self.assertTrue(result.endswith(raw[position:]))
        self.assertEqual(json.loads(result)['infisical'], json.loads(raw)['infisical'])
        self.assertEqual(json.loads(result)['templates'][:-1], json.loads(raw)['templates'])

    def test_recovered_user_agent_keeps_private_0600_and_selected_config(self):
        path, raw = self.recovered_profile()
        preview = self.engine.inspect(self.request)
        self.assertEqual(preview['agent_kind'], 'recovered_json')
        self.assertEqual(preview['agent_output'], dict(uid=1001, gid=1001, mode=0o600))
        self.assertEqual(preview['api_address'], 'http://127.0.0.1:18180')
        result = self.apply()
        self.assertEqual(result['status'], 'SERVICE_READY')
        self.assertEqual(result['agent_output'], preview['agent_output'])
        self.assertEqual(result['api_address'], preview['api_address'])
        self.assertEqual(self.store.read(LAYOUT.agent), AGENT)
        self.assertNotEqual(self.store.read(path), raw)
        generated = self.store.snapshot(ROOT / '.secrets/demo.env')
        self.assertEqual((generated.uid, generated.gid, generated.mode), (1001, 1001, 0o600))
        self.assertEqual(self.journal()['agent_profile']['config'], str(path))
        self.assertEqual(self.finalize()['status'], 'COMPLETE')

    def test_recovered_existing_0750_directory_is_preserved(self):
        self.recovered_profile(mode=0o750)
        self.assertEqual(self.apply()['status'], 'SERVICE_READY')
        self.assertEqual(self.store.directories[str(ROOT / '.secrets')], (1001, 1001, 0o750, {}))

    def test_recovered_agent_refuses_unproven_api_endpoint_before_writes(self):
        for address in ('https://production.invalid', 'http://192.0.2.1:8080',
                        'http://127.0.0.1:18180/?token=private', 'http://u:p@127.0.0.1:18180'):
            self.recovered_profile(address=address)
            before = copy.deepcopy(self.store.files)
            self.refused('ONBOARDING_AGENT_API_ENDPOINT_UNSUPPORTED', lambda: self.engine.inspect(self.request))
            self.assertEqual(self.store.files, before)

    def test_unknown_agent_config_path_is_not_guessed_or_rewritten(self):
        self.runner.agent_config = PurePosixPath('/etc/other-agent.json')
        self.store.put(self.runner.agent_config, b'{}')
        before = copy.deepcopy(self.store.files)
        self.refused('ONBOARDING_AGENT_PROFILE_UNSUPPORTED', lambda: self.engine.inspect(self.request))
        self.assertEqual(self.store.files, before)

    def test_readonly_preflight_refuses_missing_worker_and_unloaded_dr_unit(self):
        path = str(LAYOUT.home / '.local/share/streams-aio-public-sync/tooling/scripts/sync-public-stack.py')
        saved = self.store.files.pop(path)
        before = copy.deepcopy(self.store.files), copy.deepcopy(self.store.directories)
        self.refused('ONBOARDING_BACKUP_PIPELINE_NOT_READY', lambda: self.engine.inspect(self.request))
        self.assertEqual((self.store.files, self.store.directories), before)
        self.store.files[path] = saved
        self.runner.dr_load_state = 'not-found'
        self.refused('ONBOARDING_BACKUP_PIPELINE_NOT_READY', lambda: self.engine.inspect(self.request))
        self.assertFalse(self.runner.started)

    def test_handle_inspect_reports_missing_pipeline_before_opening_lockfiles(self):
        del self.store.files[str(LAYOUT.home / '.local/state/streams-aio-dr/run.lock')]
        request = dict(self.request, action='inspect')
        before = copy.deepcopy(self.store.files), copy.deepcopy(self.store.directories)
        result = remote.handle(request, self.runner, self.store, LAYOUT)
        self.assertEqual(result['code'], 'ONBOARDING_BACKUP_PIPELINE_NOT_READY')
        self.assertEqual((self.store.files, self.store.directories), before)

    def test_guarded_local_lab_runs_service_without_any_github_or_backup_commands(self):
        self.recovered_profile()
        self.local_lab()
        before = copy.deepcopy(self.store.files), copy.deepcopy(self.store.directories)
        request = dict(self.request, action='inspect')
        preview = remote.handle(request, self.runner, self.store, LAYOUT)
        self.assertEqual(preview['status'], 'PREVIEW')
        self.assertEqual(preview['verification_scope'], 'local_lab')
        self.assertEqual((self.store.files, self.store.directories), before)
        result = self.apply()
        self.assertEqual(result['status'], 'SERVICE_READY')
        self.assertEqual(result['verification_scope'], 'local_lab')
        self.assertTrue(result['application_verified'])
        self.assertFalse(result['backup_integrity_verified'])
        before_calls = len(self.runner.calls)
        self.refused('ONBOARDING_LAB_PUBLICATION_REFUSED', lambda: self.engine.finalize(self.request))
        self.assertEqual(len(self.runner.calls), before_calls)
        self.assertFalse(self.runner.dr_started)
        self.assertFalse(any(args[0].endswith('/venv/bin/python') for args, _ in self.runner.calls))

    def test_local_lab_requires_root_protected_machine_bound_marker(self):
        self.request['verification_scope'] = 'local_lab'
        self.refused('ONBOARDING_LAB_NOT_PREPARED', lambda: self.engine.inspect(self.request))
        marker = self.local_lab()
        for change in ({'machine_id': 'f' * 32}, {'owner': 'somebodyelse'},
                       {'root': '/home/operator/another-stack'}, {'publications_disabled': False}):
            self.store.put(LAYOUT.state / 'lab.json', json.dumps(dict(marker, **change)).encode())
            self.refused('ONBOARDING_LAB_NOT_PREPARED', lambda: self.engine.inspect(self.request))
        self.store.put(LAYOUT.state / 'lab.json', json.dumps(marker).encode(), 1001, 1001, 0o600)
        self.refused('ONBOARDING_LAB_NOT_PREPARED', lambda: self.engine.inspect(self.request))
        self.assertFalse(self.runner.started)

    def test_prepared_lab_target_cannot_be_published_by_unchecking_lab_scope(self):
        self.local_lab()
        self.request['verification_scope'] = 'full'
        self.refused('ONBOARDING_LAB_PUBLICATION_REFUSED', lambda: self.engine.inspect(self.request))
        self.assertFalse(self.runner.dr_started)

    def test_lab_scope_is_bound_to_job_and_journal_even_if_marker_is_lost(self):
        self.local_lab()
        self.assertEqual(self.apply()['status'], 'SERVICE_READY')
        self.assertEqual(self.journal()['verification_scope'], 'local_lab')
        self.store.files.pop(str(LAYOUT.state / 'lab.json'))
        request = dict(self.request, verification_scope='full')
        self.refused('ONBOARDING_JOB_PLAN_MISMATCH', lambda: self.engine.apply(request))
        self.refused('ONBOARDING_LAB_PUBLICATION_REFUSED', lambda: self.engine.finalize(request))
        self.assertFalse(self.runner.dr_started)

    def test_systemctl_structured_command_parsing_requires_exact_config_argument(self):
        args = remote.unit_arguments('{ path=/usr/bin/infisical ; argv[]=/usr/bin/infisical agent '
                                     '--config=/etc/infisical/agent-config.yaml ; ignore_errors=no ; pid=1 ; }')
        self.assertEqual(args, ['/usr/bin/infisical', 'agent', '--config=/etc/infisical/agent-config.yaml'])
        self.refused('ONBOARDING_SERVICE_COMMAND_INVALID', lambda: remote.unit_arguments(
            '{ argv[]=first ; } { argv[]=second ; }'))

    def test_public_only_service_has_no_agent_dependency_or_metadata(self):
        self.request['plan'] = plan(private=False)
        del self.store.files[str(LAYOUT.agent)]
        result = self.apply()
        self.assertEqual(result['status'], 'SERVICE_READY')
        self.assertEqual(result['agent_kind'], 'not_required')
        self.assertIsNone(result['agent_output'])
        self.assertEqual(result['api_address'], '')
        self.assertFalse(any(args[:3] == ['systemctl', 'restart', remote.AGENT_UNIT] for args, _ in self.runner.calls))

    def test_private_payload_override_and_public_private_overlap_are_refused(self):
        value = plan()
        value['private_values'] = {'ApiToken': 'not-allowed'}
        self.refused('ONBOARDING_PLAN_INVALID', lambda: remote.plan_document(value))
        value = plan()
        value['public_env_text'] += 'ApiToken=not-allowed\n'
        self.refused('ONBOARDING_PRIVATE_VARIABLE_IN_PUBLIC_ENV', lambda: remote.plan_document(value))

    def test_probe_accepts_only_loopback_port_of_new_service_without_tokens(self):
        _, service = remote.plan_document(plan())
        self.assertEqual(remote.probe_url('http://127.0.0.1:18321/health', service), 'http://127.0.0.1:18321/health')
        for url in ('https://127.0.0.1:18321/health', 'http://localhost:18321/health',
                    'http://127.0.0.1:18321/health?token=hidden', 'http://u:p@127.0.0.1:18321/health'):
            self.refused('ONBOARDING_APPLICATION_PROBE_INVALID', lambda: remote.probe_url(url, service))

    def test_probe_refuses_udp_other_interface_and_host_network_false_positives(self):
        _, service = remote.plan_document(plan())
        for port in ('18321:8080/udp', '192.0.2.1:18321:8080',
                     {'target': 8080, 'published': 18321, 'protocol': 'udp'},
                     {'target': 8080, 'published': 18321, 'host_ip': '192.0.2.1'}):
            selected = dict(service, ports=[port])
            self.refused('ONBOARDING_APPLICATION_PROBE_NOT_PUBLISHED_BY_SERVICE',
                         lambda: remote.probe_url('http://127.0.0.1:18321/health', selected))
        for port in ('18321:8080/tcp', ':18321:8080', '0.0.0.0:18321:8080',
                     {'target': 8080, 'published': 18321, 'host_ip': '127.0.0.1', 'protocol': 'tcp'}):
            self.assertTrue(remote.probe_url('http://127.0.0.1:18321/health', dict(service, ports=[port])))
        self.refused('ONBOARDING_APPLICATION_PROBE_NOT_PUBLISHED_BY_SERVICE',
                     lambda: remote.probe_url('http://127.0.0.1:18321/health', dict(service, network_mode='host')))

    def test_inspect_is_read_only_and_targets_selected_ssh_user(self):
        before = copy.deepcopy(self.store.files), copy.deepcopy(self.store.directories)
        preview = self.engine.inspect(self.request)
        self.assertEqual((self.store.files, self.store.directories), before)
        self.assertEqual(preview['stack_root'], '/home/operator/streams-aio')
        self.assertNotIn('offline-example-token', json.dumps({k: v for k, v in preview.items() if not k.startswith('_')}))

    def test_apply_preserves_existing_files_and_starts_only_new_service(self):
        result = self.apply()
        self.assertEqual(result['status'], 'SERVICE_READY')
        self.assertFalse(result['backup_integrity_verified'])
        commands = [args for args, _ in self.runner.calls]
        starts = [args for args in commands if args[:2] == ['docker', 'compose'] and 'up' in args]
        self.assertEqual(len(starts), 1)
        self.assertEqual(starts[0][-7:], ['up', '-d', '--no-deps', '--pull', 'missing', '--', 'demo'])
        self.assertEqual(self.store.read(ROOT / 'data/demo/.env'), plan()['public_env_text'].encode())
        self.assertEqual(self.store.snapshot(ROOT / '.secrets/demo.env').mode, 0o640)
        self.assertNotIn('offline-example-token', json.dumps(result))
        self.assertFalse(any(args[:2] == ['docker', 'restart'] for args in commands))

    def test_stale_preview_refuses_without_rewriting_files(self):
        self.preview()
        self.store.put(ROOT / 'docker-compose.yml', COMPOSE + b'# user edit\n', 1001, 1001, 0o640)
        before = copy.deepcopy(self.store.files)
        self.refused('ONBOARDING_PREVIEW_STALE', lambda: self.engine.apply(self.request))
        self.assertEqual(self.store.files, before)

    def test_validation_failure_rolls_back_owned_files_without_starting(self):
        self.runner.fail_config = True
        result = self.apply()
        self.assertEqual((result['status'], result['phase']), ('REFUSED', 'ROLLED_BACK'))
        self.assertEqual(self.store.read(ROOT / 'docker-compose.yml'), COMPOSE)
        self.assertEqual(self.store.read(LAYOUT.agent), AGENT)
        self.assertFalse(self.store.exists(ROOT / 'data/demo/.env'))
        self.assertFalse(self.store.exists(ROOT / '.secrets/demo.env'))
        self.assertFalse(self.runner.started)

    def test_rollback_preserves_a_concurrent_user_edit(self):
        self.runner.fail_config = True
        self.runner.before_config_failure = lambda: self.store.put(ROOT / 'data/demo/.env', b'# user changed this\n', 1001, 1001, 0o640)
        result = self.apply()
        self.assertEqual(result['phase'], 'REVIEW_REQUIRED')
        self.assertEqual(self.store.read(ROOT / 'data/demo/.env'), b'# user changed this\n')
        self.assertFalse(self.runner.started)

    def test_empty_agent_output_never_passes_or_starts_service(self):
        self.runner.empty_private = True
        result = self.apply()
        self.assertEqual(result['code'], 'ONBOARDING_AGENT_RENDER_FAILED')
        self.assertFalse(self.runner.started)
        self.assertEqual(result['phase'], 'REVIEW_REQUIRED')

    def test_anonymous_volume_in_image_refused_before_service_starts(self):
        self.runner.image_volumes = {'/var/lib/demo': {}}
        result = self.apply()
        self.assertEqual(result['code'], 'ONBOARDING_PERSISTENT_DATA_COVERAGE_REQUIRED')
        self.assertEqual(result['phase'], 'ROLLED_BACK')
        self.assertFalse(self.runner.started)

    def test_running_without_healthcheck_or_probe_is_not_success(self):
        self.runner.container_state.pop('Health')
        result = self.apply()
        self.assertEqual(result['code'], 'ONBOARDING_APPLICATION_PROBE_REQUIRED')
        self.assertEqual(result['phase'], 'REVIEW_REQUIRED')
        self.assertTrue(self.runner.started)
        self.assertNotEqual(self.store.read(ROOT / 'docker-compose.yml'), COMPOSE)

    def test_public_acl_watcher_allowed_but_private_acl_or_mode_rejected(self):
        self.store.public_acl_watcher = True
        self.assertEqual(self.apply()['status'], 'SERVICE_READY')
        self.engine.unchanged(self.journal())
        item = self.store.snapshot(ROOT / '.secrets/demo.env')
        self.store.put(item.path, item.raw, 0, 1001, 0o670, {'system.posix_acl_access': b'unwanted'})
        self.refused('ONBOARDING_PRIVATE_OUTPUT_PERMISSIONS_INVALID', lambda: self.engine.unchanged(self.journal()))

    def test_same_job_is_idempotent_but_different_plan_or_fingerprint_refused(self):
        self.apply()
        commands = len(self.runner.calls)
        self.assertEqual(self.engine.apply(self.request)['status'], 'SERVICE_READY')
        self.assertEqual(len(self.runner.calls), commands)
        for changed in ('fingerprint', 'plan'):
            request = copy.deepcopy(self.request)
            if changed == 'fingerprint':
                request['fingerprint'] = 'f' * 64
            else:
                request['plan']['public_env_text'] += 'CHANGED=true\n'
            self.refused('ONBOARDING_JOB_PLAN_MISMATCH', lambda: self.engine.apply(request))

    def test_finalize_serializes_publish_and_backup_and_reads_all_eight_assets(self):
        self.apply()
        result = self.finalize()
        self.assertEqual(result['status'], 'COMPLETE')
        self.assertEqual(self.runner.finalize_lock_seen, [True, True])
        self.assertEqual(set(self.journal()['backup_assets']), remote.FILES)
        self.assertTrue(result['backup_integrity_verified'])
        self.assertFalse(result['agent_archive_contents_verified'])
        self.assertEqual(self.journal()['backup_stack_commit'], self.runner.backup_commit)

    def test_restored_agent_inventory_contract_from_real_exporter_is_accepted(self):
        self.apply()
        self.runner.publish_files(self.request['plan'])
        target = '.secrets/demo.env'
        self.runner.public_files['config/dr-render-plan.json'] = b'{"env_files":{}}'
        self.runner.public_files['config/public-stack-layout.json'] = json.dumps(dict(
            schema=1, services=['redis', 'demo'], private_env_targets=[target],
            private_env_targets_from_restored_agent=[target])).encode()
        self.runner.public_files['config/dr-manifest.yaml'] = json.dumps(dict(
            components={'demo': {'GENERATED_FILES': [target], 'REQUIRED_BEFORE_COMPOSE_UP': [target],
                                  'PUBLIC_REPO_FILES': ['data/demo/.env']}},
            references=[dict(SERVICE='demo', SOURCE=target, TYPE='ENV_FILE',
                             RESTORE_METHOD='INFISICAL_AGENT_RENDER', RESOLVED=True)])).encode()
        self.assertEqual(self.engine.finalize(self.request)['status'], 'BACKUP_RUNNING')
        self.assertEqual(self.engine.finalize(self.request)['status'], 'COMPLETE')

    def test_missing_restored_agent_required_target_refuses_backup(self):
        self.apply()
        self.runner.publish_files(self.request['plan'])
        target = '.secrets/demo.env'
        self.runner.public_files['config/dr-render-plan.json'] = b'{"env_files":{}}'
        self.runner.public_files['config/public-stack-layout.json'] = json.dumps(dict(
            schema=1, services=['demo'], private_env_targets=[target],
            private_env_targets_from_restored_agent=[target])).encode()
        self.runner.public_files['config/dr-manifest.yaml'] = json.dumps(dict(
            components={'demo': {'GENERATED_FILES': [target], 'REQUIRED_BEFORE_COMPOSE_UP': [],
                                  'PUBLIC_REPO_FILES': ['data/demo/.env']}},
            references=[dict(SERVICE='demo', SOURCE=target, TYPE='ENV_FILE',
                             RESTORE_METHOD='INFISICAL_AGENT_RENDER', RESOLVED=True)])).encode()
        self.refused('ONBOARDING_DR_MAPPING_READBACK_FAILED', lambda: self.engine.finalize(self.request))
        self.assertFalse(self.runner.dr_started)

    def test_parallel_finalizer_refuses_instead_of_launching_another_backup(self):
        self.apply()
        with self.engine.operation():
            self.refused('ONBOARDING_OTHER_OPERATION_RUNNING', lambda: self.engine.finalize(self.request))
        self.assertFalse(self.runner.dr_started)

    def test_wrong_public_command_is_detected_even_when_env_and_image_match(self):
        self.apply()
        self.runner.publish_files(self.request['plan'])
        document = yaml.safe_load(self.runner.public_files['docker-compose.yml'])
        document['services']['demo']['command'] = ['wrong-mode']
        self.runner.public_files['docker-compose.yml'] = yaml.safe_dump(document).encode()
        self.refused('ONBOARDING_PUBLIC_SERVICE_READBACK_FAILED', lambda: self.engine.finalize(self.request))
        self.assertFalse(self.runner.dr_started)

    def test_agent_permissions_change_with_same_bytes_blocks_finalize(self):
        self.apply()
        item = self.store.snapshot(LAYOUT.agent)
        self.store.put(item.path, item.raw, item.uid, item.gid, 0o777)
        self.refused('ONBOARDING_INSTALLED_FILES_CHANGED', lambda: self.engine.finalize(self.request))

    def test_crash_during_backup_never_returns_complete(self):
        self.apply()
        self.runner.publish_files(self.request['plan'])
        self.assertEqual(self.engine.finalize(self.request)['status'], 'BACKUP_RUNNING')
        self.runner.container_state['Status'] = 'exited'
        self.refused('ONBOARDING_CONTAINER_FAILED', lambda: self.engine.finalize(self.request))
        self.assertEqual(self.journal()['phase'], 'BACKUP_RUNNING')

    def test_corrupted_encrypted_backup_asset_refuses_completion(self):
        self.apply()
        self.runner.publish_files(self.request['plan'])
        self.engine.finalize(self.request)
        name = next(iter(remote.ASSETS))
        self.runner.downloads[name] = self.runner.downloads[name][:-1] + b'!'
        self.refused('ONBOARDING_BACKUP_CHECKSUM_MISMATCH', lambda: self.engine.finalize(self.request))
        self.assertFalse(self.journal().get('backup_integrity_verified', False))

    def test_completed_job_revalidates_application_on_reentry(self):
        self.apply()
        self.assertEqual(self.finalize()['status'], 'COMPLETE')
        self.runner.container_state['Status'] = 'dead'
        self.refused('ONBOARDING_CONTAINER_FAILED', lambda: self.engine.finalize(self.request))

    def test_docker_hub_aliases_equivalent_but_other_registry_and_tag_distinct(self):
        self.assertEqual(remote.image_identity('redis'), remote.image_identity('docker.io/library/redis:latest'))
        self.assertEqual(remote.image_identity('example/demo:latest'), remote.image_identity('index.docker.io/example/demo:latest'))
        self.assertNotEqual(remote.image_identity('example/demo:stable'), remote.image_identity('example/demo:latest'))
        self.assertEqual(remote.image_repository_identity('registry.example:5000/team/demo@sha256:' + '0' * 64),
                         'registry.example:5000/team/demo')
        self.assertEqual(remote.image_repository_identity('python:3.12@sha256:' + '0' * 64),
                         'docker.io/library/python')

    def test_request_framing_accepts_consumed_or_unused_sudo_line_without_exposing_it(self):
        request = dict(action='inspect', root=str(ROOT), plan=plan())
        body = remote.REQUEST_FRAME + json.dumps(request).encode() + b'\n'
        for prefix in (b'', b'example-unused-sudo-canary\n', remote.REQUEST_FRAME):
            self.assertEqual(remote.framed_request(prefix + body), request)
        output = io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(b'example-unused-sudo-canary\n' + body), encoding='utf-8')
        with patch.object(remote.sys, 'stdin', stdin), patch.object(remote.sys, 'stdout', output), \
                patch.object(remote, 'handle', return_value=dict(schema=1, status='PREVIEW')) as handle:
            self.assertEqual(remote.main(), 0)
        handle.assert_called_once_with(request)
        self.assertEqual(json.loads(output.getvalue()), dict(schema=1, status='PREVIEW'))
        self.assertNotIn('sudo-canary', output.getvalue())

    def test_framing_refuses_unframed_or_multiple_prefix_lines(self):
        for raw in (b'{"action":"inspect"}', b'one\ntwo\n' + remote.REQUEST_FRAME + b'{}',
                    remote.REQUEST_FRAME + b'[]'):
            self.refused('ONBOARDING_REQUEST_INVALID', lambda: remote.framed_request(raw))


if __name__ == '__main__':
    unittest.main()

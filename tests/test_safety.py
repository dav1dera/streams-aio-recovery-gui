import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from recovery_gui.backend import Failure, Host, SSH, parse_event
spec = importlib.util.spec_from_file_location('remote_recover', ROOT / 'remote/recover.py')
remote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remote)
start_spec = importlib.util.spec_from_file_location('remote_start', ROOT / 'remote/start.py')
start = importlib.util.module_from_spec(start_spec)
with patch.dict(sys.modules, {'fcntl': N()} if sys.platform == 'win32' else {}):
    start_spec.loader.exec_module(start)


class Safety(unittest.TestCase):
    def setUp(self):
        if sys.platform == 'win32':
            # Remote code only runs on Linux. Windows exposes no POSIX private
            # mode bits; archive/payload tests use synthetic files, not real keys.
            def windows_fixture_file(path, outside=()):
                p = remote.safe_path(Path(path).expanduser())
                remote.require(p.is_file(), 'PRIVATE_INPUT_FILE_REQUIRED')
                remote.require(all(not p.is_relative_to(x) for x in outside), 'PRIVATE_INPUT_MUST_BE_OUTSIDE_CLONES')
                return p
            mock = patch.object(remote, 'private_file', windows_fixture_file)
            mock.start()
            self.addCleanup(mock.stop)

    def test_log_drops_raw_values_and_errors(self):
        for raw in ('secret-canary', 'Error: secret-canary', 'RECOVERY_EVENT not-json',
                    'RECOVERY_EVENT {"stage":"DECRYPT","status":"PASS","value":"secret-canary"}',
                    'RECOVERY_EVENT {"stage":"REFUSED","status":"REFUSED","code":"PRIVATE_CANARY"}',
                    'RECOVERY_EVENT {"stage":"REFUSED","status":"REFUSED","code":"secret-canary"}'):
            self.assertIsNone(parse_event(raw))
        self.assertEqual(parse_event('RECOVERY_EVENT {"stage":"DECRYPT","status":"PASS"}'),
                         dict(stage='DECRYPT', status='PASS'))

    def test_credentials_not_in_repr(self):
        h = Host('vm.example.invalid', password='private-canary', sudo_password='sudo-canary', key_password='key-canary')
        self.assertNotIn('canary', repr(h))

    def test_host_does_not_allow_shell_text(self):
        for host in ('vm;echo private', '$(command)', 'vm user', 'https://vm.invalid'):
            with self.assertRaises(Failure):
                Host(host, password='canary').validate()
        Host('vm.example.invalid', password='canary').validate()

    def test_tag_and_date(self):
        self.assertEqual(remote.valid_tag('dr-20261004T023903Z'), 'dr-20261004T023903Z')
        for tag in ('latest', '../file', 'dr-20261340T023903Z'):
            with self.assertRaises(remote.Refused):
                remote.valid_tag(tag)

    def test_release_cannot_be_draft_or_missing_assets(self):
        base = dict(tag_name='dr-20261004T023903Z', draft=False,
                    assets=[dict(name=n, state='uploaded', size=100) for n in remote.BUNDLE_FILES])
        remote.validate_release(base, base['tag_name'])
        for changed in (dict(base, draft=True), dict(base, assets=base['assets'][:-1]),
                        dict(base, assets=base['assets'] + [dict(name='../secret', size=3, state='uploaded')])):
            with self.assertRaises(remote.Refused):
                remote.validate_release(changed, base['tag_name'])

    def test_infisical_endpoint_no_credentials_query_or_http(self):
        remote.validate_address('https://infisical.example.invalid/')
        for address in ('http://host.invalid', 'https://user:private@host.invalid',
                        'https://host.invalid?token=private', 'https://host.invalid/path', 'file:///tmp/secrets'):
            with self.assertRaises(remote.Refused):
                remote.validate_address(address)

    def test_imported_or_hidden_secrets_fail_before_writes(self):
        secret = N(secretKey='TOKEN', secretValue='private-canary', secretValueHidden=False)
        self.assertEqual(remote.response_values(N(secrets=[secret], imports=[])), {'TOKEN':'private-canary'})
        for response in (N(secrets=[secret], imports=[{}]), N(secrets=[secret, secret], imports=[]),
                         N(secrets=[N(secretKey='TOKEN', secretValue='canary', secretValueHidden=True)], imports=[])):
            with self.assertRaises(remote.Refused) as e:
                remote.response_values(response)
            self.assertNotIn('canary', str(e.exception))

    def test_snapshots_roundtrip_multiline_quotes_dollars(self):
        import ast
        value = 'private\n"quoted"\\$dollars\té'
        class DR:
            all_paths = staticmethod(lambda plan: ['/service'])
            folder_file = staticmethod(lambda folder: 'service.goenv')
        client = N(secrets=N(list_secrets=lambda **kwargs:
                            N(secrets=[N(secretKey='VALUE', secretValue=value, secretValueHidden=False)], imports=[])))
        snapshots = remote.collect_inputs({'required_values':['/service/VALUE']}, DR, client, 'project', 'prod')
        encoded = snapshots['service.goenv'].decode().partition('=')[2]
        self.assertEqual(ast.literal_eval(encoded), value)

    def test_missing_required_secret_refuses_complete_set(self):
        dr = N(all_paths=lambda p: ['/service'], folder_file=lambda p:'service.goenv')
        client = N(secrets=N(list_secrets=lambda **kw:N(secrets=[], imports=[])))
        with self.assertRaises(remote.Refused):
            remote.collect_inputs({'required_values':['/service/VALUE']}, dr, client, 'project', 'prod')

    def test_archive_rejects_escape_symlink_and_duplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            for names, kind in ((['../escape'], 'file'), (['/etc/escape'], 'file'),
                                (['escape'], 'link'), (['same', 'same'], 'file')):
                base = Path(tmp)
                archive = base / 'archive.tar.gz'
                with tarfile.open(archive, 'w:gz') as t:
                    for name in names:
                        m = tarfile.TarInfo(name)
                        if kind == 'link':
                            m.type = tarfile.SYMTYPE
                            m.linkname = '/etc'
                            t.addfile(m)
                        else:
                            m.size = 6
                            t.addfile(m, io.BytesIO(b'canary'))
                with self.assertRaises(remote.Refused):
                    remote.unpack_agent(archive, base / 'output')
                self.assertFalse((base / 'output').exists())

    def test_private_archive_regular_files_and_bootstrap(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            archive = base / 'agent.tar.gz'
            config = dict(infisical={'address':'https://infisical.example.invalid'},
                          auth={'type':'universal-auth', 'config':{'client-id':'/etc/infisical/client-id',
                                                                  'client-secret':'/etc/infisical/client-secret'}},
                          templates=[{'template-content':'{{ range secret "project" "prod" "/comet" }}{{ end }}'}])
            with tarfile.open(archive, 'w:gz') as t:
                for name, content in [('etc/infisical/agent-config.json', json.dumps(config).encode()),
                                      ('etc/infisical/client-id', b'id-canary'), ('etc/infisical/client-secret', b'private-canary')]:
                    member = tarfile.TarInfo(name)
                    member.size = len(content)
                    t.addfile(member, io.BytesIO(content))
            remote.unpack_agent(archive, base / 'unpacked')
            result = remote.agent_bootstrap(base / 'unpacked')
            self.assertEqual(result['project'], 'project')
            self.assertEqual(result['environment'], 'prod')
            self.assertEqual(result['client_secret'].read_bytes(), b'private-canary')

    def test_failed_age_preserves_stage_never_promotes_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base/'key').write_bytes(b'AGE-SECRET-KEY-1CANARY\n')
            (base/'bundle').mkdir()
            for name in remote.BUNDLE_FILES:
                (base/'bundle'/name).write_bytes(b'encrypted-fixture')
            counter = []
            def fake(args, code):
                if args[0] == 'age-keygen':
                    return b''
                counter.append(args)
                if len(counter) == 2:
                    raise remote.Refused(code)
                Path(args[args.index('--output') + 1]).write_bytes(b'private-canary')
                Path(args[args.index('--output') + 1]).chmod(0o600)
            with self.assertRaises(remote.Refused):
                remote.decrypt_all(base/'key', base/'bundle', base/'private', run=fake)
            self.assertFalse((base/'private').exists())
            self.assertTrue(any(base.glob('decryption-*')))

    def test_aio_profiles_not_guessed_or_silently_discarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            streams, meta = base/'s.json', base/'m.json'
            streams.write_text(json.dumps({'UserData':{'uuid':'s-uuid', 'addons':[]}}))
            meta.write_text(json.dumps({'version':'3.3.0', 'config':{'uuid':'m-uuid'}, 'metadata':{}}))
            for p in (streams, meta):
                p.chmod(0o600)
            registry = dict(aiostreams={'primary':{'uuid':'s-uuid'}}, aiometadata={'primary':{'uuid':'m-uuid'}})
            payload = remote.logical_payload(registry, [streams], [meta])
            self.assertEqual(payload['aiostreams'][0]['profile'], 'primary')
            self.assertEqual(payload['aiometadata'][0]['version'], '3.3.0')
            registry['aiostreams']['second'] = {'uuid':'other'}
            with self.assertRaises(remote.Refused):
                remote.logical_payload(registry, [streams], [meta])

    def test_host_installation_guard_precedes_apt(self):
        shell = (ROOT/'remote/bootstrap.sh').read_text()
        self.assertLess(shell.index('probe.py'), shell.index('apt-get update'))
        self.assertNotIn('curl |', shell)
        self.assertNotIn('set -x', shell)
        self.assertNotIn('rm -rf', shell)

    def test_runtime_never_adopts_foreign_or_old_volumes(self):
        root = Path('/home/pi/streams-aio')
        compose = dict(name='streams-aio', services={'comet':{}},
                       volumes={'cache':dict(name='streams-aio_cache')})
        labels = {'com.docker.compose.project':'streams-aio',
                  'com.docker.compose.project.working_dir':str(root),
                  'com.docker.compose.service':'comet'}
        container = dict(Config=dict(Labels=labels))
        volume = dict(Name='streams-aio_cache', Labels={
                      'com.docker.compose.project':'streams-aio', 'com.docker.compose.volume':'cache'})
        start.validate_runtime(compose, root, [container], [volume])
        for bad in (dict(Name=volume['Name'], Labels={}),
                    dict(volume, Name='old_cache'),
                    dict(Name=volume['Name'], Labels={
                         'com.docker.compose.project':'production', 'com.docker.compose.volume':'cache'})):
            with self.assertRaisesRegex(ValueError, 'FOREIGN_VOLUME_REFUSED'):
                start.validate_runtime(compose, root, [], [bad])
        with self.assertRaisesRegex(ValueError, 'FOREIGN_CONTAINER_REFUSED'):
            start.validate_runtime(compose, root, [dict(Config=dict(Labels={}))], [])
        with self.assertRaisesRegex(ValueError, 'EXTERNAL_VOLUME_REFUSED'):
            start.validate_runtime(dict(compose, volumes={'old':dict(external=True)}), root, [], [])

    def test_token_sent_via_stdin_never_arguments_or_sftp(self):
        ssh = SSH.__new__(SSH)
        ssh.host = Host('vm.example.invalid', password='ssh-canary')
        ssh.check = lambda: {'home':'/home/pi'}
        ssh.run = lambda *args, **kw: None
        sftp = N(chmod=lambda *a:None, mkdir=lambda *a, **kw:None, close=lambda:None)
        # Deliberately no open/write method: token request files must never exist.
        ssh.client = N(open_sftp=lambda:sftp)
        ssh._put = lambda *a:None
        request = dict(github_token='github-private-canary', public_commit='a'*40,
                       dr_tag='dr-20261004T023903Z', infisical_address='', project_id='', environment='')
        area, raw = ssh.upload(request)
        self.assertNotIn('canary', area)
        self.assertEqual(json.loads(raw)['github_token'], 'github-private-canary')
        with patch.object(ssh, 'upload', return_value=(area, raw)), patch.object(ssh, 'run') as run:
            ssh.prepare(request, lambda e:None)
        args, kwargs = run.call_args
        self.assertNotIn('canary', repr(args))
        self.assertEqual(kwargs['input'], b'STREAMS_INPUT_V1\n' + raw)

    @unittest.skipIf(sys.platform == 'win32', 'POSIX permission bits require Linux')
    def test_real_linux_private_mode_refuses_group_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'private'
            path.write_text('fixture-canary')
            path.chmod(0o640)
            with self.assertRaisesRegex(remote.Refused, 'PRIVATE_INPUT_REQUIRES_MODE_600'):
                remote.private_file(path)
            path.chmod(0o600)
            remote.private_file(path)


if __name__ == '__main__':
    unittest.main()

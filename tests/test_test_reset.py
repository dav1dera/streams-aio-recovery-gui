import copy
from contextlib import contextmanager
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bounded_test_reset', ROOT / 'remote/test_reset.py')
reset = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reset)

# Mount/device/tmpfs-only projection of checked public source files at commit
# 28f6ca7, merged with compose.dr.yaml by mount target. The tests construct
# synthetic Docker inspection rows; they do not inspect or modify a real VM.
# /STACK replaces the deployment root. No
# environment values or runtime container configuration are part of this data.
# Verified Git blobs at 28f6ca7cc6f5fd10418fc0af2926815927ef98c8:
# docker-compose.yml: 6e75aa0c07282fbef2b03608d3115534330f9d04
# config/compose.dr.yaml: ceb28dae0cb2a3d21e146622156f81b2f7ea6b68
PUBLIC_MOUNTS_FIXTURE = json.loads((ROOT / 'tests/fixtures/pinned_stack_mounts.json').read_text())
PUBLIC_MOUNTS = PUBLIC_MOUNTS_FIXTURE['model']


def info(root, role='stack'):
    return dict(role=role, user='test' if role == 'stack' else 'test2',
                target=str(root / 'target'), runner=str(root / 'runner'), project='streams-aio',
                machine_id='a' * 32, base=str(root / 'archive'))


def model(target):
    return dict(name='streams-aio', services={'postgres': sorted([
        dict(type='volume', source='streams-aio_pgdata', target='/var/lib/postgresql/data'),
        dict(type='bind', source=str(target / 'init'), target='/docker-entrypoint-initdb.d')], key=lambda x: x['target'])},
        volumes={'pgdata': 'streams-aio_pgdata'})


def container(target):
    return dict(Id='1' * 64, Config={'Labels': {
        'com.docker.compose.project': 'streams-aio', 'com.docker.compose.service': 'postgres',
        'com.docker.compose.project.working_dir': str(target)}}, State={'Running': True, 'Restarting': False}, Mounts=[
        dict(Type='volume', Name='streams-aio_pgdata', Destination='/var/lib/postgresql/data'),
        dict(Type='bind', Source=str(target / 'init'), Destination='/docker-entrypoint-initdb.d')])


@contextmanager
def tun_device(mode=stat.S_IFCHR | 0o666, rdev=0x0ac8):
    original = Path.lstat
    expected = Path('/dev/net/tun').absolute()
    def lstat(path, *args, **kwargs):
        if path.absolute() == expected:
            return N(st_mode=mode, st_uid=0, st_rdev=rdev)
        return original(path, *args, **kwargs)
    with patch.object(Path, 'lstat', lstat), patch.object(os, 'major', lambda device: (device >> 8) & 0xfff, create=True), patch.object(os, 'minor', lambda device: device & 0xff, create=True):
        yield


@contextmanager
def socket_paths():
    original = Path.resolve
    canonical = Path('/run/docker.sock').absolute()
    aliases = {canonical, Path('/var/run/docker.sock').absolute()}
    def resolve(path, strict=False):
        if path.absolute() in aliases:
            return canonical
        return original(path, strict=strict)
    with patch.object(reset, 'local_docker_socket', return_value=canonical), patch.object(Path, 'resolve', resolve):
        yield


class ResourceGuards(unittest.TestCase):
    def fixture(self, root):
        target = root / 'target'
        volume = root / 'volumes/streams-aio_pgdata/_data'
        volume.mkdir(parents=True)
        row = dict(Name='streams-aio_pgdata', Driver='local', Options={},
                   Mountpoint=str(volume), Labels={'com.docker.compose.project': 'streams-aio',
                   'com.docker.compose.volume': 'pgdata'})
        return info(root), model(target), container(target), row

    def read(self, containers, volumes):
        def command(args, *unused, **kwargs):
            if args[1:] == ['ps', '-aq']:
                return ''.join(row['Id'][:12] + '\n' for row in containers).encode()
            if args[1] == 'inspect':
                return json.dumps(containers).encode()
            if args[1:4] == ['volume', 'ls', '-q']:
                return b'streams-aio_pgdata\n' if volumes else b''
            if args[1:3] == ['volume', 'inspect']:
                return json.dumps(volumes).encode()
            self.fail('A read-only resource check issued another operation')
        return command

    def test_own_resources_require_labels_mounts_and_local_backing_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scoped, projection, owned, volume = self.fixture(root)
            with patch.object(reset, 'VOLUME_ROOT', root / 'volumes'), patch.object(reset, 'command', self.read([owned], [volume])):
                containers, volumes = reset.resources(scoped, projection)
                self.assertEqual([x['Id'] for x in containers], ['1' * 64])
                self.assertEqual([x['Name'] for x in volumes], ['streams-aio_pgdata'])

    def test_foreign_project_service_working_directory_and_bind_never_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scoped, projection, owned, volume = self.fixture(root)
            mutations = [
                lambda row: row['Config']['Labels'].update({'com.docker.compose.project': 'production'}),
                lambda row: row['Config']['Labels'].update({'com.docker.compose.service': 'other'}),
                lambda row: row['Config']['Labels'].update({'com.docker.compose.project.working_dir': '/home/pi/streams-aio'}),
                lambda row: row['Mounts'][1].update(Source='/home/pi/private'),
                lambda row: row['Mounts'].append(dict(Type='bind', Source='/etc', Destination='/foreign')),
            ]
            for mutate in mutations:
                row = copy.deepcopy(owned)
                mutate(row)
                with self.subTest(row=row), patch.object(reset, 'VOLUME_ROOT', root / 'volumes'), patch.object(reset, 'command', self.read([row], [volume])):
                    with self.assertRaises(reset.Refused):
                        reset.resources(scoped, projection)

    def test_foreign_external_driver_options_name_and_backing_location_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scoped, projection, owned, volume = self.fixture(root)
            changes = [dict(Driver='nfs'), dict(Options={'device': '/private'}),
                       dict(Name='foreign'), dict(Mountpoint=str(root)),
                       dict(Labels={'com.docker.compose.project': 'production', 'com.docker.compose.volume': 'pgdata'})]
            for change in changes:
                row = dict(volume, **change)
                with self.subTest(change=change), patch.object(reset, 'VOLUME_ROOT', root / 'volumes'), patch.object(reset, 'command', self.read([owned], [row])):
                    with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_FOREIGN_VOLUME'):
                        reset.resources(scoped, projection)

    def test_resumption_refuses_new_container_even_in_the_same_project(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scoped, projection, owned, volume = self.fixture(root)
            with patch.object(reset, 'VOLUME_ROOT', root / 'volumes'), patch.object(reset, 'command', self.read([owned], [volume])):
                with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_FOREIGN_CONTAINER'):
                    reset.resources(scoped, projection, allowed_ids=['2' * 64], allowed_names=['streams-aio_pgdata'])

    def test_model_refuses_external_volumes_and_outside_binds(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scoped = info(root)
            raw = dict(name='streams-aio', services={'postgres': {'volumes': [
                dict(type='volume', source='pgdata', target='/data')]}}, volumes={
                'pgdata': dict(name='streams-aio_pgdata')})
            reset.model_projection(raw, scoped)
            changed = copy.deepcopy(raw)
            changed['volumes']['pgdata']['external'] = True
            with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_FOREIGN_VOLUME'):
                reset.model_projection(changed, scoped)
            raw['services']['postgres']['volumes'] = [dict(type='bind', source='/opt/private', target='/data')]
            with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_BIND_SCOPE_REFUSED'):
                reset.model_projection(raw, scoped)
            raw['services']['postgres']['volumes'] = [dict(type='bind', source=str(root / 'target/../../outside'), target='/data')]
            with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_PATH_REFUSED'):
                reset.model_projection(raw, scoped)


class PinnedSystemMounts(unittest.TestCase):
    def test_fixture_provenance_is_the_reviewed_public_commit_and_git_blobs(self):
        self.assertEqual(PUBLIC_MOUNTS_FIXTURE['source_commit'], reset.COMMIT)
        self.assertEqual(PUBLIC_MOUNTS_FIXTURE['source_files'], {
            'docker-compose.yml': '6e75aa0c07282fbef2b03608d3115534330f9d04',
            'config/compose.dr.yaml': 'ceb28dae0cb2a3d21e146622156f81b2f7ea6b68'})

    def fixture(self, root, summaries):
        scoped = info(root)
        raw = json.loads(json.dumps(PUBLIC_MOUNTS).replace('/STACK', Path(scoped['target']).as_posix()))
        projected = reset.model_projection(raw, scoped)
        containers, volumes = [], []
        for service, mounts in projected['services'].items():
            inspected = []
            for mount in mounts:
                inspected.append(dict(Type=mount['type'], Destination=mount['target'],
                                      Name=mount['source'] if mount['type'] == 'volume' else '',
                                      Source=mount['source']))
            temporary = projected['tmpfs'][service]
            if summaries:
                inspected.extend(dict(Type='tmpfs', Source='', Destination=target) for target in temporary)
            host = dict(Tmpfs={target: 'mode=01777,size=67108864' for target in temporary},
                        Devices=[dict(PathOnHost=row['source'], PathInContainer=row['target'],
                                      CgroupPermissions=row['permissions']) for row in projected['devices'][service]])
            containers.append(dict(Id=hashlib.sha256(service.encode()).hexdigest(),
                                   Config={'Labels': {'com.docker.compose.project': 'streams-aio',
                                   'com.docker.compose.project.working_dir': scoped['target'],
                                   'com.docker.compose.service': service}}, HostConfig=host,
                                   Mounts=inspected, State={'Running': False, 'Restarting': False}))
        for key, name in projected['volumes'].items():
            path = root / 'volumes' / name / '_data'
            path.mkdir(parents=True)
            volumes.append(dict(Name=name, Driver='local', Options={}, Mountpoint=str(path),
                                Labels={'com.docker.compose.project': 'streams-aio', 'com.docker.compose.volume': key}))
        return scoped, projected, containers, volumes

    def test_all_31_public_services_project_and_match_docker_with_both_tmpfs_summaries(self):
        for summaries in (False, True):
            with self.subTest(tmpfs_mount_summaries=summaries), tempfile.TemporaryDirectory() as temporary, tun_device(), socket_paths():
                root = Path(temporary)
                scoped, projected, containers, volumes = self.fixture(root, summaries)
                self.assertEqual(len(projected['services']), 31)
                self.assertEqual(len(projected['volumes']), 7)
                self.assertEqual([name for name, values in projected['tmpfs'].items() if values], ['comet', 'cometnet'])
                self.assertEqual([name for name, values in projected['devices'].items() if values], ['gluetun', 'tailscale'])
                read = ResourceGuards().read(containers, volumes)
                with patch.object(reset, 'VOLUME_ROOT', root / 'volumes'), patch.object(reset, 'command', side_effect=read):
                    actual, data = reset.resources(scoped, projected)
                self.assertEqual(len(actual), 31)
                self.assertEqual(len(data), 7)
                self.assertTrue(all(row['Name'].startswith('streams-aio_') for row in data))
                self.assertNotIn('/dev/net/tun', projected['volumes'].values())
                self.assertNotIn('/tmp', projected['volumes'].values())

    def test_tun_is_exact_root_character_device_10_200_only_on_reviewed_service_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            scoped = info(Path(temporary))
            with tun_device():
                reset.reviewed_tun(scoped, 'tailscale', '/dev/net/tun', '/dev/net/tun', bind=True)
                reset.reviewed_tun(scoped, 'gluetun', '/dev/net/tun', '/dev/net/tun')
                for service, source, target in [('comet', '/dev/net/tun', '/dev/net/tun'),
                                                 ('gluetun', '/dev/net/tun', '/dev/net/tun'),
                                                 ('tailscale', '/dev/net/tun', '/other'),
                                                 ('tailscale', '/dev/null', '/dev/net/tun')]:
                    with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_BIND_SCOPE_REFUSED'):
                        reset.reviewed_tun(scoped, service, source, target, bind=True)
                with self.assertRaises(reset.Refused):
                    reset.reviewed_tun(dict(scoped, role='infisical'), 'tailscale', '/dev/net/tun', '/dev/net/tun')
            for mode, device in [(stat.S_IFREG | 0o666, 0x0ac8), (stat.S_IFCHR | 0o666, 0x0ac9)]:
                with tun_device(mode=mode, rdev=device), self.assertRaisesRegex(reset.Refused, 'TEST_RESET_BIND_SCOPE_REFUSED'):
                    reset.reviewed_tun(scoped, 'tailscale', '/dev/net/tun', '/dev/net/tun', bind=True)

    def test_socket_aliases_require_public_destination_and_four_reviewed_services(self):
        with tempfile.TemporaryDirectory() as temporary, socket_paths():
            scoped = info(Path(temporary))
            for source in ('/run/docker.sock', '/var/run/docker.sock'):
                for service in ('headplane', 'portainer', 'watchtower', 'deunhealth'):
                    self.assertEqual(reset.reviewed_socket(scoped, service, source, '/var/run/docker.sock'), '/var/run/docker.sock')
                with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_BIND_SCOPE_REFUSED'):
                    reset.reviewed_socket(scoped, 'postgres', source, '/var/run/docker.sock')
                with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_BIND_SCOPE_REFUSED'):
                    reset.reviewed_socket(scoped, 'portainer', source, '/foreign')
            with patch.object(Path, 'resolve', return_value=Path('/foreign/docker.sock')):
                with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_BIND_SCOPE_REFUSED'):
                    reset.reviewed_socket(scoped, 'portainer', '/var/run/docker.sock', '/var/run/docker.sock')

    def test_tmpfs_configuration_and_device_changes_refuse_before_any_reset_command(self):
        with tempfile.TemporaryDirectory() as temporary, tun_device(), socket_paths():
            root = Path(temporary)
            scoped, projected, containers, volumes = self.fixture(root, True)
            mutations = [
                lambda rows: next(row for row in rows if row['Config']['Labels']['com.docker.compose.service'] == 'comet')['HostConfig']['Tmpfs'].update({'/extra': 'mode=1777,size=64m'}),
                lambda rows: next(row for row in rows if row['Config']['Labels']['com.docker.compose.service'] == 'comet')['HostConfig']['Tmpfs'].update({'/tmp': 'mode=0777,size=64m'}),
                lambda rows: next(row for row in rows if row['Config']['Labels']['com.docker.compose.service'] == 'comet')['Mounts'].append(dict(Type='tmpfs', Source='/private', Destination='/tmp')),
                lambda rows: next(row for row in rows if row['Config']['Labels']['com.docker.compose.service'] == 'comet')['HostConfig'].update(Tmpfs={}),
                lambda rows: next(row for row in rows if row['Config']['Labels']['com.docker.compose.service'] == 'gluetun')['HostConfig']['Devices'][0].update(CgroupPermissions='rw'),
                lambda rows: next(row for row in rows if row['Config']['Labels']['com.docker.compose.service'] == 'tailscale')['HostConfig']['Devices'][0].update(PathInContainer='/other'),
            ]
            for mutate in mutations:
                changed = copy.deepcopy(containers)
                mutate(changed)
                with self.subTest(mutate=mutate), patch.object(reset, 'VOLUME_ROOT', root / 'volumes'), patch.object(reset, 'command', side_effect=ResourceGuards().read(changed, volumes)):
                    with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_BIND_SCOPE_REFUSED'):
                        reset.resources(scoped, projected)

    def test_unreviewed_tmpfs_models_options_and_long_mounts_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            scoped = info(Path(temporary))
            for service, entry in [('postgres', '/tmp:size=64m,mode=1777'), ('comet', '/other:size=64m,mode=1777'),
                                   ('comet', '/tmp:size=64m,mode=1777,rw'), ('comet', '/tmp:size=128m,mode=1777'),
                                   ('comet', '/tmp:size=64m,mode=1777,mode=1777')]:
                raw = dict(name='streams-aio', services={service: dict(tmpfs=[entry])}, volumes={})
                with self.subTest(service=service, entry=entry), self.assertRaisesRegex(reset.Refused, 'TEST_RESET_BIND_SCOPE_REFUSED'):
                    reset.model_projection(raw, scoped)
            raw = dict(name='streams-aio', services={'comet': {'volumes': [dict(type='tmpfs', target='/tmp')]}}, volumes={})
            with self.assertRaises(reset.Refused):
                reset.model_projection(raw, scoped)


class ScopeAndFraming(unittest.TestCase):
    def test_docker_cannot_use_inherited_remote_context_or_token(self):
        completed = N(returncode=0, stdout=b'')
        socket = N(st_uid=0, st_mode=stat.S_IFSOCK | 0o660)
        with patch.dict(os.environ, {'DOCKER_HOST': 'tcp://production:2376', 'DOCKER_CONTEXT': 'production',
                                    'DOCKER_CONFIG': '/secret', 'GH_TOKEN': 'private-token-canary'}), patch.object(Path, 'is_symlink', return_value=False), patch.object(Path, 'lstat', return_value=socket), patch.object(reset.subprocess, 'run', return_value=completed) as run:
            reset.command(['docker', 'ps', '-aq'])
        self.assertEqual(run.call_args.args[0], ['docker', '--host', 'unix:///run/docker.sock', 'ps', '-aq'])
        environment = run.call_args.kwargs['env']
        self.assertFalse(any(key.startswith('DOCKER_') for key in environment))
        self.assertNotIn('GH_TOKEN', environment)

    def test_frame_handles_consumed_sudo_and_one_unconsumed_password_line(self):
        request = dict(tag=reset.TAG, commit=reset.COMMIT)
        encoded = b'STREAMS_TEST_RESET_V1\n' + json.dumps(request).encode() + b'\n'
        self.assertEqual(reset.parse_request(encoded), request)
        self.assertEqual(reset.parse_request(b'private-password-canary\n' + encoded), request)
        for raw in (b'private-password-canary\nnot-a-header\n{}', b'x\ny\n' + encoded, b'{}', b'x' * 65537):
            with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_SCOPE_REFUSED') as caught:
                reset.parse_request(raw)
            self.assertNotIn('canary', str(caught.exception))

    def test_scope_refuses_original_account_wrong_machine_tag_and_commit(self):
        account = N(pw_name='test', pw_gid=1000, pw_dir='/home/test')
        shim = N(getpwuid=lambda uid: account)
        posix = N(name='posix', geteuid=lambda: 0, uname=lambda: N(sysname='Linux'))
        request = dict(tag=reset.TAG, commit=reset.COMMIT, machine_id='a' * 32)
        with patch.dict(sys.modules, {'pwd': shim}), patch.object(reset, 'os', posix), patch.object(Path, 'read_text', return_value='a' * 32), patch.object(reset, 'safe', side_effect=lambda path: Path(path)):
            self.assertEqual(reset.scope('stack', request)['user'], 'test')
            for update in (dict(tag='old'), dict(commit='b' * 40), dict(machine_id='b' * 32)):
                with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_SCOPE_REFUSED'):
                    reset.scope('stack', dict(request, **update))
            account.pw_name = 'pi'
            with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_SCOPE_REFUSED'):
                reset.scope('stack', request)
            account.pw_name = 'test'
            posix.geteuid = lambda: 1000
            with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_SCOPE_REFUSED'):
                reset.scope('stack', request)

    def test_checkpoints_require_exact_scope_and_no_pending_step(self):
        with tempfile.TemporaryDirectory() as temporary:
            scoped = info(Path(temporary))
            runner = Path(scoped['runner'])
            runner.mkdir()
            state = dict(schema=1, runner_version='0.2.0', machine_id=scoped['machine_id'],
                         target=scoped['target'], tag=reset.TAG, public_commit=reset.COMMIT,
                         tooling_commit=reset.COMMIT, completed=['RENDER'], in_progress=None)
            with patch.object(reset, 'regular'):
                (runner / 'state.json').write_text(json.dumps(state))
                reset.checkpoint(scoped)
                for change in (dict(tag='old'), dict(public_commit='b' * 40), dict(machine_id='b' * 32),
                               dict(in_progress='NPM'), dict(target='/home/pi/streams-aio')):
                    (runner / 'state.json').write_text(json.dumps(dict(state, **change)))
                    with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_CHECKPOINT_REFUSED'):
                        reset.checkpoint(scoped)
                scoped['role'] = 'infisical'
                state.pop('public_commit')
                state['completed'] = ['INFISICAL_CONFIG']
                (runner / 'state.json').write_text(json.dumps(state))
                reset.checkpoint(scoped)

    def test_empty_does_not_ignore_private_runner_remnants_or_owned_units(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scoped = info(root)
            runner = Path(scoped['runner'])
            runner.mkdir()
            (runner / 'identity').write_bytes(b'synthetic identity')
            with patch.object(reset, 'command', return_value=b'') as command:
                with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_CHECKPOINT_REFUSED'):
                    reset.plan(scoped)
                command.assert_not_called()
            (runner / 'identity').unlink()
            runner.rmdir()
            systemd = root / 'systemd'
            systemd.mkdir()
            (systemd / 'infisical-agent.service').write_bytes(b'synthetic unit')
            with patch.object(reset, 'SYSTEMD', systemd), patch.object(reset, 'command', return_value=b''):
                with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_UNIT_REFUSED'):
                    reset.plan(scoped)

    def test_private_interrupted_journal_staging_is_preserved_and_can_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'pending.json'
            stale = path.with_name('pending.json.new')
            stale.write_bytes(b'interrupted journal bytes')
            with patch.object(reset, 'regular'):
                reset.save(path, {'schema': 1, 'status': 'PENDING'})
            self.assertEqual(json.loads(path.read_bytes())['status'], 'PENDING')
            copies = list(path.parent.glob('pending.json.new-preserved-*'))
            self.assertEqual(len(copies), 1)
            self.assertEqual(copies[0].read_bytes(), b'interrupted journal bytes')

    def test_loaded_foreign_dropin_is_refused_before_unit_stop(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'infisical-agent.service'
            path.write_bytes(b'validated unit bytes')
            metadata = ('LoadState=loaded\nFragmentPath=' + str(path)
                        + '\nDropInPaths=/etc/systemd/system/infisical-agent.service.d/foreign.conf\n').encode()
            with patch.object(reset, 'regular', return_value=N(st_uid=0, st_mode=stat.S_IFREG | 0o600)), patch.object(reset, 'command', return_value=metadata) as command:
                with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_UNIT_REFUSED'):
                    reset.unit_loaded(path.name, path, reset.hash_file(path))
            self.assertTrue(all('disable' not in row.args[0] for row in command.call_args_list))

    def test_nested_bind_mount_is_refused_before_private_tree_rename(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nested = root / 'nested'
            nested.mkdir()
            with patch.object(reset.os.path, 'ismount', side_effect=lambda path: Path(path) == nested):
                with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_FILESYSTEM_REFUSED'):
                    reset.rename_tree(root, root.stat().st_dev)

    def test_mountinfo_catches_same_device_bind_mounts_and_decodes_escaped_paths(self):
        raw = ('22 1 8:1 / / rw - ext4 /dev/sda1 rw\n'
               '23 22 8:1 /other /var/lib/docker/volumes/test/_data/nested\\040mount rw - ext4 /dev/sda1 rw\n')
        self.assertIn(Path('/var/lib/docker/volumes/test/_data/nested mount'), reset.parse_mountpoints(raw))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nested = root / 'nested'
            nested.mkdir()
            with patch.object(reset, 'mountpoints', return_value={nested}), patch.object(reset.os.path, 'ismount', return_value=False):
                with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_VOLUME_TREE_REFUSED'):
                    reset.tree_snapshot(root)
                with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_FILESYSTEM_REFUSED'):
                    reset.rename_tree(root, root.stat().st_dev)


class PreservationGuards(unittest.TestCase):
    def archive(self, root, path):
        with tarfile.open(path, 'w') as archive:
            archive.add(root, arcname='.', recursive=True)

    def test_archive_verification_detects_changed_bytes_and_missing_members(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'data'
            source.mkdir()
            (source / 'database').write_bytes(b'original database bytes')
            snapshot, _ = reset.tree_snapshot(source)
            archive = root / 'volume.tar'
            self.archive(source, archive)
            reset.verify_tar(archive, snapshot)
            (source / 'database').write_bytes(b'modified database bytes')
            changed, _ = reset.tree_snapshot(source)
            with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_ARCHIVE_CHANGED'):
                reset.verify_tar(archive, changed)
            with tarfile.open(archive, 'w'):
                pass
            with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_ARCHIVE_CHANGED'):
                reset.verify_tar(archive, snapshot)

    def test_tar_path_escape_and_hardlink_are_refused_without_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'escape.tar'
            for name, member_type in [('../outside', tarfile.REGTYPE), ('database', tarfile.LNKTYPE)]:
                with tarfile.open(path, 'w') as archive:
                    member = tarfile.TarInfo(name)
                    member.type = member_type
                    member.linkname = '../../outside'
                    archive.addfile(member, io.BytesIO(b''))
                snapshot = {'database': dict(type='file', uid=0, gid=0, mode=0o644, size=0,
                                           sha256=hashlib.sha256(b'').hexdigest())}
                with self.assertRaises(reset.Refused):
                    reset.verify_tar(path, snapshot)
            self.assertFalse((Path(temporary).parent / 'outside').exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX symlink and inode semantics')
    def test_external_link_hardlink_and_nested_mount_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'data'
            source.mkdir()
            outside = root / 'outside'
            outside.write_bytes(b'synthetic secret')
            (source / 'link').symlink_to(outside)
            with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_VOLUME_TREE_REFUSED'):
                reset.tree_snapshot(source)
            (source / 'link').unlink()
            os.link(outside, source / 'hardlink')
            with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_VOLUME_TREE_REFUSED'):
                reset.tree_snapshot(source)
            (source / 'hardlink').unlink()
            nested = source / 'nested'
            nested.mkdir()
            with patch.object(reset.os.path, 'ismount', side_effect=lambda path: Path(path) == nested):
                with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_VOLUME_TREE_REFUSED'):
                    reset.tree_snapshot(source)

    def test_storage_space_is_checked_before_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'data'
            source.mkdir()
            (source / 'db').write_bytes(b'database')
            with patch.object(reset.shutil, 'disk_usage', return_value=N(free=0)), patch.object(reset, 'command') as command:
                with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_SPACE_REQUIRED'):
                    reset.copy_volume(source, root / 'volume.tar')
                command.assert_not_called()

    def test_volume_copy_is_verified_and_synced_before_returning_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'data'
            source.mkdir()
            (source / 'db').write_bytes(b'synthetic persistent database')
            archive = root / 'volume.tar'
            events = []
            def command(args, *unused, **kwargs):
                events.append('COPY')
                self.archive(source, archive)
                return b''
            original_verify = reset.verify_tar
            def verify(*args):
                events.append('VERIFY')
                return original_verify(*args)
            with patch.object(reset, 'command', side_effect=command), patch.object(reset, 'regular'), patch.object(reset, 'verify_tar', side_effect=verify), patch.object(reset, 'sync_file', side_effect=lambda path: events.append('SYNC_FILE')), patch.object(reset, 'sync_directory', side_effect=lambda path: events.append('SYNC_DIRECTORY')):
                receipt = reset.copy_volume(source, archive)
            self.assertEqual(events, ['COPY', 'VERIFY', 'SYNC_FILE', 'SYNC_DIRECTORY'])
            self.assertEqual(receipt['sha256'], reset.hash_file(archive))


class Transaction(unittest.TestCase):
    """Exercise ordering and interruption with synthetic resources, never Docker."""
    def fixture(self, root):
        scoped = info(root)
        target, runner = Path(scoped['target']), Path(scoped['runner'])
        target.mkdir()
        runner.mkdir()
        (target / 'private-env').write_bytes(b'private sentinel')
        (runner / 'identity').write_bytes(b'identity sentinel')
        checkpoint = dict(schema=1, runner_version='0.2.0', machine_id=scoped['machine_id'],
                          target=scoped['target'], tag=reset.TAG, public_commit=reset.COMMIT,
                          tooling_commit=reset.COMMIT, completed=['RENDER'], in_progress=None)
        (runner / 'state.json').write_bytes(reset.canonical(checkpoint))
        source = root / 'volume'
        source.mkdir()
        (source / 'db').write_bytes(b'volume sentinel')
        unit = root / 'systemd/infisical-agent.service'
        unit.parent.mkdir()
        unit.write_bytes(b'exact validated unit')
        candidate = dict(info=scoped, empty=False, checkpoint_sha256=reset.hash_file(runner / 'state.json'),
                         model=model(target), containers=['1' * 64], volumes=['streams-aio_pgdata'],
                         files={str(unit): reset.hash_file(unit)}, units=[unit.name])
        state = dict(containers=[dict(Id='1' * 64, State={'Running': True, 'Restarting': False})],
                     volumes=[dict(Name='streams-aio_pgdata', Mountpoint=str(source))], calls=[])
        def command(args, *unused, **kwargs):
            state['calls'].append(args)
            if args[:2] == ['docker', 'stop']:
                state['containers'][0]['State']['Running'] = False
            if args[:2] == ['docker', 'rm']:
                # Both file-system state and every volume archive must exist
                # while Docker resources are removed.
                self.assertTrue((target / 'private-env').exists())
                self.assertTrue((runner / 'identity').exists())
                copies = list(Path(scoped['base']).glob('*/volumes/*.tar'))
                self.assertEqual(len(copies), 1)
                snapshot, _ = reset.tree_snapshot(source)
                reset.verify_tar(copies[0], snapshot)
                state['containers'].clear()
            if args[:3] == ['docker', 'volume', 'rm']:
                self.assertFalse(state['containers'])
                state['volumes'].clear()
            if args[:2] == ['systemctl', 'show']:
                if '--value' in args:
                    return b'not-found\n' if not unit.exists() else b'loaded\n'
                return (('LoadState=loaded\nFragmentPath=' + str(unit) + '\nDropInPaths=\n'
                        + 'ActiveState=inactive\nMainPID=0\nControlPID=0\n').encode())
            return b''
        def copies(source, destination):
            state['calls'].append(['COPY', str(source)])
            snapshot, _ = reset.tree_snapshot(source)
            with tarfile.open(destination, 'w') as archive:
                archive.add(source, arcname='.')
            return dict(sha256=reset.hash_file(destination), snapshot_sha256=reset.sha(reset.canonical(snapshot)))
        def directory(path, create=False):
            path = Path(path)
            if create:
                path.mkdir(parents=True, exist_ok=True)
            self.assertTrue(path.is_dir())
            return path
        def save(path, data):
            Path(path).write_bytes(reset.canonical(data))
        context = [patch.object(reset, 'plan', return_value=candidate),
                   patch.object(reset, 'pending', return_value=None),
                   patch.object(reset, 'resources', side_effect=lambda *args: (copy.deepcopy(state['containers']), copy.deepcopy(state['volumes']))),
                   patch.object(reset, 'command', side_effect=command), patch.object(reset, 'copy_volume', side_effect=copies),
                   patch.object(reset, 'private_directory', side_effect=directory),
                   patch.object(reset, 'regular', return_value=N(st_uid=0, st_mode=stat.S_IFREG | 0o600)),
                   patch.object(reset, 'save', side_effect=save), patch.object(reset, 'SYSTEMD', unit.parent)]
        return scoped, candidate, state, context

    def enter(self, context):
        from contextlib import ExitStack
        stack = ExitStack()
        for item in context:
            stack.enter_context(item)
        self.addCleanup(stack.close)
        return stack

    def test_reset_archives_every_private_tree_and_volume_before_removal(self):
        with tempfile.TemporaryDirectory() as temporary:
            scoped, candidate, state, context = self.fixture(Path(temporary))
            with self.enter(context):
                result = reset.reset(scoped, reset.sha(reset.canonical(candidate)))
            self.assertEqual(result['status'], 'RESET')
            archive = Path(result['archive'])
            self.assertEqual((archive / 'target/private-env').read_bytes(), b'private sentinel')
            self.assertEqual((archive / 'runner/identity').read_bytes(), b'identity sentinel')
            self.assertEqual((archive / 'system-files/0').read_bytes(), b'exact validated unit')
            self.assertFalse(Path(scoped['target']).exists())
            self.assertFalse(Path(scoped['runner']).exists())
            operations = [row[0:2] for row in state['calls']]
            self.assertLess(operations.index(['systemctl', 'disable']), operations.index(['docker', 'stop']))
            self.assertLess(next(i for i, row in enumerate(operations) if row[0] == 'COPY'), operations.index(['docker', 'rm']))
            self.assertNotIn('sentinel', json.dumps(result))

    def test_wrong_ticket_and_failed_archive_do_not_remove_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            scoped, candidate, state, context = self.fixture(Path(temporary))
            with self.enter(context):
                with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_TICKET_CHANGED'):
                    reset.reset(scoped, '0' * 64)
                self.assertFalse(state['calls'])
                with patch.object(reset, 'copy_volume', side_effect=reset.Refused('TEST_RESET_ARCHIVE_FAILED')):
                    with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_ARCHIVE_FAILED'):
                        reset.reset(scoped, reset.sha(reset.canonical(candidate)))
            self.assertFalse(any(row[:2] == ['docker', 'rm'] or row[:3] == ['docker', 'volume', 'rm'] for row in state['calls']))
            self.assertTrue(Path(scoped['target']).exists())
            self.assertTrue(Path(scoped['runner']).exists())

    def test_interrupted_unit_unlink_can_resume_without_disabling_absent_unit(self):
        with tempfile.TemporaryDirectory() as temporary:
            scoped, candidate, state, context = self.fixture(Path(temporary))
            with self.enter(context):
                # First pass reaches unit unlink and stops before directory moves.
                with patch.object(Path, 'rename', side_effect=OSError('synthetic interruption')):
                    with self.assertRaises(OSError):
                        reset.reset(scoped, reset.sha(reset.canonical(candidate)))
                journal = json.loads((Path(scoped['base']) / 'pending.json').read_bytes())
                # Model interruption immediately BEFORE its removed_files save.
                journal['removed_files'] = []
                state['calls'].clear()
                with patch.object(reset, 'pending', return_value=journal):
                    result = reset.reset(scoped, journal['ticket'])
            self.assertEqual(result['status'], 'RESET')
            self.assertFalse(any(row[:2] == ['systemctl', 'disable'] for row in state['calls']))
            self.assertEqual((Path(result['archive']) / 'runner/identity').read_bytes(), b'identity sentinel')

    def test_archived_volume_corruption_on_resume_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            scoped, candidate, state, context = self.fixture(Path(temporary))
            with self.enter(context):
                with patch.object(Path, 'rename', side_effect=OSError('synthetic interruption')):
                    with self.assertRaises(OSError):
                        reset.reset(scoped, reset.sha(reset.canonical(candidate)))
                journal = json.loads((Path(scoped['base']) / 'pending.json').read_bytes())
                path = Path(scoped['base']) / journal['operation'] / 'volumes/streams-aio_pgdata.tar'
                path.write_bytes(b'corrupted archive')
                with patch.object(reset, 'pending', return_value=journal):
                    with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_ARCHIVE_CHANGED'):
                        reset.reset(scoped, journal['ticket'])
            self.assertTrue(Path(scoped['target']).exists())

    def test_pending_inspection_rechecks_loaded_dropins_before_either_vm_reset(self):
        actual_pending = reset.pending
        with tempfile.TemporaryDirectory() as temporary:
            scoped, candidate, state, context = self.fixture(Path(temporary))
            with self.enter(context):
                with patch.object(reset, 'copy_volume', side_effect=reset.Refused('TEST_RESET_ARCHIVE_FAILED')):
                    with self.assertRaises(reset.Refused):
                        reset.reset(scoped, reset.sha(reset.canonical(candidate)))
                unit = Path(next(iter(candidate['files'])))
                response = ('LoadState=loaded\nFragmentPath=' + str(unit)
                            + '\nDropInPaths=/foreign/override.conf\n').encode()
                state['calls'].clear()
                with patch.object(reset, 'command', return_value=response) as command:
                    with self.assertRaisesRegex(reset.Refused, 'TEST_RESET_UNIT_REFUSED'):
                        actual_pending(scoped)
                self.assertTrue(all('disable' not in row.args[0] for row in command.call_args_list))


if __name__ == '__main__':
    unittest.main()

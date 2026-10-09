"""Archive and clear only the two pinned replacement-VM recovery attempts.

This is not a Docker cleanup utility. Every resource is checked against the
root-private checkpoint and resolved Compose model. Volume data is copied and
verified before any container or volume is removed. Bind data and uploaded
private inputs are moved intact into a root-private archive, never deleted.
The desktop inspects both hosts before it invokes either reset.
"""
import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import time

TAG = 'dr-20261006T210601Z'
COMMIT = '28f6ca7cc6f5fd10418fc0af2926815927ef98c8'
ROLES = {
    'stack': ('test', '/home/test/streams-aio', '/home/test/.local/share/streams-aio-recovery', 'streams-aio'),
    'infisical': ('test2', '/opt/infisical', '/home/test2/.local/share/streams-aio-infisical-recovery', 'infisical'),
}
VOLUME_ROOT = Path('/var/lib/docker/volumes')
SYSTEMD = Path('/etc/systemd/system')
MAX_ENTRIES = 200000
MAX_BYTES = 200 * 1024**3
RESERVE = 64 * 1024**2
ERROR_CODES = frozenset({
    'TEST_RESET_SCOPE_REFUSED', 'TEST_RESET_PATH_REFUSED', 'TEST_RESET_CHECKPOINT_REFUSED',
    'TEST_RESET_ALREADY_RUNNING', 'TEST_RESET_DOCKER_REFUSED', 'TEST_RESET_FOREIGN_CONTAINER',
    'TEST_RESET_FOREIGN_VOLUME', 'TEST_RESET_BIND_SCOPE_REFUSED', 'TEST_RESET_UNIT_REFUSED',
    'TEST_RESET_VOLUME_TREE_REFUSED', 'TEST_RESET_SPACE_REQUIRED', 'TEST_RESET_ARCHIVE_FAILED',
    'TEST_RESET_ARCHIVE_CHANGED', 'TEST_RESET_TICKET_CHANGED', 'TEST_RESET_JOURNAL_REFUSED',
    'TEST_RESET_CONTAINER_STOP_FAILED', 'TEST_RESET_RESOURCE_REMOVE_FAILED',
    'TEST_RESET_FILESYSTEM_REFUSED', 'TEST_RESET_OPERATION_FAILED',
})


class Refused(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Refused(code)


def safe(path):
    path = Path(path).absolute()
    require('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents))
            and path == path.resolve(strict=False), 'TEST_RESET_PATH_REFUSED')
    return path


def regular(path, private=False):
    path = safe(path)
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'TEST_RESET_PATH_REFUSED')
    if private:
        require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
                'TEST_RESET_CHECKPOINT_REFUSED')
    return info


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hash_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024**2), b''):
            digest.update(block)
    return digest.hexdigest()


def sync_file(path):
    with Path(path).open('r+b') as handle:
        os.fsync(handle.fileno())


def sync_directory(path):
    if os.name == 'posix':
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':')).encode()


def save(path, data):
    path = safe(path)
    temporary = path.with_name(path.name + '.new')
    if temporary.exists():
        # A killed atomic journal write can leave a private staging file.
        # Preserve it, rather than trusting it or making reset unretryable.
        regular(temporary, private=True)
        temporary.rename(temporary.with_name(temporary.name + '-preserved-' + os.urandom(6).hex()))
        sync_directory(path.parent)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(canonical(data))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def command(args, code='TEST_RESET_OPERATION_FAILED', cwd=None, timeout=60):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('COMPOSE_', 'INFISICAL_', 'PYTHON', 'DOCKER_'))
           and key not in ('GH_TOKEN', 'GITHUB_TOKEN')}
    args = [str(x) for x in args]
    if args and args[0] == 'docker':
        local_docker_socket()
        # Ignore saved contexts as well as environment variables. No request
        # can make this scoped reset address a daemon on another machine.
        args[1:1] = ['--host', 'unix:///run/docker.sock']
    result = subprocess.run(args, cwd=cwd, env=env,
                            capture_output=True, timeout=timeout)
    require(result.returncode == 0, code)
    return result.stdout


def local_docker_socket():
    path = safe('/run/docker.sock')
    socket_info = path.lstat()
    require(stat.S_ISSOCK(socket_info.st_mode) and socket_info.st_uid == 0
            and socket_info.st_mode & 0o002 == 0, 'TEST_RESET_DOCKER_REFUSED')
    return path


def scope(role, request):
    import pwd
    require(role in ROLES and os.name == 'posix' and os.geteuid() == 0
            and os.uname().sysname == 'Linux', 'TEST_RESET_SCOPE_REFUSED')
    user, target, runner, project = ROLES[role]
    account = pwd.getpwuid(1000)
    require(account.pw_name == user and account.pw_gid == 1000
            and account.pw_dir == '/home/' + user, 'TEST_RESET_SCOPE_REFUSED')
    machine = Path('/etc/machine-id').read_text().strip()
    require(re.fullmatch(r'[0-9a-f]{32}', machine)
            and request.get('tag') == TAG and request.get('commit') == COMMIT
            and request.get('machine_id', machine) == machine,
            'TEST_RESET_SCOPE_REFUSED')
    target, runner = safe(target), safe(runner)
    base = safe(Path('/var/lib/streams-aio-test-reset') / role)
    return dict(role=role, user=user, target=str(target), runner=str(runner),
                project=project, machine_id=machine, base=str(base))


@contextmanager
def locks(info):
    import fcntl
    with ExitStack() as stack:
        path = safe(Path('/run/lock') / ('streams-aio-test-reset-' + info['role'] + '.lock'))
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        stack.callback(os.close, descriptor)
        st = os.fstat(descriptor)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
                and stat.S_IMODE(st.st_mode) == 0o600, 'TEST_RESET_PATH_REFUSED')
        for path in (Path(info['runner']) / 'setup.lock', Path(info['runner']) / 'recovery.lock'):
            if path.exists():
                regular(path)
                handle = stack.enter_context(path.open('r+b'))
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise Refused('TEST_RESET_ALREADY_RUNNING') from None
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused('TEST_RESET_ALREADY_RUNNING') from None
        yield


def checkpoint(info, runner=None):
    path = Path(runner or info['runner']) / 'state.json'
    regular(path, private=True)
    raw = path.read_bytes()
    state = json.loads(raw)
    require(isinstance(state, dict) and type(state.get('schema')) is int and state['schema'] == 1
            and state.get('runner_version') == '0.2.0'
            and state.get('machine_id') == info['machine_id']
            and state.get('target') == info['target'] and state.get('tag') == TAG
            and state.get('tooling_commit') == COMMIT and state.get('in_progress') is None
            and (state.get('public_commit') == COMMIT if info['role'] == 'stack'
                 else state.get('public_commit') in (None, COMMIT)),
            'TEST_RESET_CHECKPOINT_REFUSED')
    completed = state.get('completed')
    require(isinstance(completed, list) and all(isinstance(x, str) for x in completed)
            and len(completed) == len(set(completed)), 'TEST_RESET_CHECKPOINT_REFUSED')
    require('RENDER' in completed if info['role'] == 'stack' else 'INFISICAL_CONFIG' in completed,
            'TEST_RESET_CHECKPOINT_REFUSED')
    return state, sha(raw)


def reviewed_tun(info, service, source, destination, bind=False):
    """The reviewed kernel device is checked, never copied or removed."""
    require(info['role'] == 'stack' and service in (('tailscale',) if bind else ('tailscale', 'gluetun'))
            and source == destination == '/dev/net/tun', 'TEST_RESET_BIND_SCOPE_REFUSED')
    device = safe(source).lstat()
    require(stat.S_ISCHR(device.st_mode) and device.st_uid == 0
            and os.major(device.st_rdev) == 10 and os.minor(device.st_rdev) == 200,
            'TEST_RESET_BIND_SCOPE_REFUSED')


def reviewed_socket(info, service, source, destination):
    require(info['role'] == 'stack' and service in ('portainer', 'headplane', 'watchtower', 'deunhealth')
            and source in ('/var/run/docker.sock', '/run/docker.sock')
            and destination == '/var/run/docker.sock', 'TEST_RESET_BIND_SCOPE_REFUSED')
    require(Path(source).resolve(strict=True) == local_docker_socket(), 'TEST_RESET_BIND_SCOPE_REFUSED')
    return '/var/run/docker.sock'


def tmpfs_options(value):
    require(isinstance(value, str), 'TEST_RESET_BIND_SCOPE_REFUSED')
    pieces = value.split(',')
    pairs = [piece.split('=', 1) for piece in pieces]
    require(all(len(pair) == 2 for pair in pairs) and len(pairs) == 2
            and len({pair[0] for pair in pairs}) == 2, 'TEST_RESET_BIND_SCOPE_REFUSED')
    options = dict(pairs)
    require(set(options) == {'size', 'mode'} and options['size'] in ('64m', '64M', '67108864')
            and options['mode'] in ('1777', '01777'), 'TEST_RESET_BIND_SCOPE_REFUSED')
    return dict(size=64 * 1024**2, mode=0o1777)


def reviewed_tmpfs(info, service, row):
    entries = row.get('tmpfs', [])
    require(isinstance(entries, list), 'TEST_RESET_BIND_SCOPE_REFUSED')
    if not entries:
        return {}
    require(info['role'] == 'stack' and service in ('comet', 'cometnet') and len(entries) == 1
            and isinstance(entries[0], str), 'TEST_RESET_BIND_SCOPE_REFUSED')
    target, separator, value = entries[0].partition(':')
    require(separator and target == '/tmp', 'TEST_RESET_BIND_SCOPE_REFUSED')
    return {target: tmpfs_options(value)}


def reviewed_devices(info, service, row):
    entries = row.get('devices', [])
    require(isinstance(entries, list), 'TEST_RESET_BIND_SCOPE_REFUSED')
    result = []
    for item in entries:
        if isinstance(item, str):
            pieces = item.split(':')
            require(len(pieces) in (2, 3), 'TEST_RESET_BIND_SCOPE_REFUSED')
            source, target = pieces[:2]
            permissions = pieces[2] if len(pieces) == 3 else 'rwm'
        else:
            require(isinstance(item, dict) and set(item) <= {'source', 'target', 'permissions'},
                    'TEST_RESET_BIND_SCOPE_REFUSED')
            source, target, permissions = item.get('source'), item.get('target'), item.get('permissions', 'rwm')
        require(permissions == 'rwm' and not result, 'TEST_RESET_BIND_SCOPE_REFUSED')
        reviewed_tun(info, service, source, target)
        result.append(dict(source=source, target=target, permissions=permissions))
    return result


def model_projection(model, info):
    require(isinstance(model, dict) and model.get('name') == info['project']
            and isinstance(model.get('services'), dict) and model['services'],
            'TEST_RESET_DOCKER_REFUSED')
    if info['role'] == 'infisical':
        require(set(model['services']) == {'backend', 'db', 'redis'}, 'TEST_RESET_DOCKER_REFUSED')
    volumes = model.get('volumes', {})
    require(isinstance(volumes, dict), 'TEST_RESET_FOREIGN_VOLUME')
    for name, row in volumes.items():
        require(isinstance(row, dict) and not row.get('external')
                and row.get('driver', 'local') == 'local' and not row.get('driver_opts')
                and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', row.get('name', '')),
                'TEST_RESET_FOREIGN_VOLUME')
    services, tmpfs, devices = {}, {}, {}
    for name, row in model['services'].items():
        require(re.fullmatch(r'[a-z0-9][a-z0-9_.-]*', name) and isinstance(row, dict),
                'TEST_RESET_DOCKER_REFUSED')
        mounts = []
        for mount in row.get('volumes', []):
            require(isinstance(mount, dict) and mount.get('type') in ('bind', 'volume'),
                    'TEST_RESET_BIND_SCOPE_REFUSED')
            source, destination = mount.get('source'), mount.get('target')
            require(isinstance(source, str) and isinstance(destination, str), 'TEST_RESET_BIND_SCOPE_REFUSED')
            if mount['type'] == 'volume':
                require(source in volumes, 'TEST_RESET_FOREIGN_VOLUME')
                source = volumes[source]['name']
            elif source in ('/var/run/docker.sock', '/run/docker.sock'):
                source = reviewed_socket(info, name, source, destination)
            elif source == '/dev/net/tun':
                reviewed_tun(info, name, source, destination, bind=True)
            else:
                require(safe(source).is_relative_to(Path(info['target'])), 'TEST_RESET_BIND_SCOPE_REFUSED')
            mounts.append(dict(type=mount['type'], source=source, target=destination))
        services[name] = sorted(mounts, key=lambda x: x['target'])
        tmpfs[name] = reviewed_tmpfs(info, name, row)
        devices[name] = reviewed_devices(info, name, row)
    return dict(name=model['name'], services=services,
                volumes={key: row['name'] for key, row in volumes.items()}, tmpfs=tmpfs, devices=devices)


def read_model(info, state):
    target = Path(info['target'])
    if info['role'] == 'stack':
        require(command(['git', '-C', target, 'rev-parse', 'HEAD']).decode().strip() == COMMIT,
                'TEST_RESET_CHECKPOINT_REFUSED')
        regular(target / 'docker-compose.yml')
        require((target / 'docker-compose.yml').read_bytes()
                == command(['git', '-C', target, 'show', COMMIT + ':docker-compose.yml']),
                'TEST_RESET_CHECKPOINT_REFUSED')
        raw = command(['docker', 'compose', '--profile', 'all', 'config', '--format', 'json'],
                      'TEST_RESET_DOCKER_REFUSED', cwd=target)
    else:
        path = target / 'recovery-compose.json'
        regular(path, private=True)
        require(state.get('installed_config_hashes', {}).get(path.name) == hash_file(path),
                'TEST_RESET_CHECKPOINT_REFUSED')
        raw = command(['docker', 'compose', '--project-directory', target, '-f', path,
                       'config', '--format', 'json'], 'TEST_RESET_DOCKER_REFUSED', cwd=target)
    return model_projection(json.loads(raw), info)


def resources(info, model, allowed_ids=None, allowed_names=None):
    ids = command(['docker', 'ps', '-aq'], 'TEST_RESET_DOCKER_REFUSED').decode().split()
    require(all(re.fullmatch(r'[0-9a-f]{12,64}', x) for x in ids), 'TEST_RESET_DOCKER_REFUSED')
    containers = json.loads(command(['docker', 'inspect', *ids], 'TEST_RESET_DOCKER_REFUSED')) if ids else []
    for row in containers:
        labels = row.get('Config', {}).get('Labels') or {}
        service = labels.get('com.docker.compose.service')
        require(labels.get('com.docker.compose.project') == info['project']
                and labels.get('com.docker.compose.project.working_dir') == info['target']
                and service in model['services'] and re.fullmatch(r'[0-9a-f]{64}', row.get('Id', ''))
                and (allowed_ids is None or row['Id'] in allowed_ids), 'TEST_RESET_FOREIGN_CONTAINER')
        expected = model['services'][service]
        actual = []
        temporary = model.get('tmpfs', {}).get(service, {})
        temporary_summaries = set()
        for mount in row.get('Mounts', []):
            require(mount.get('Type') in ('volume', 'bind', 'tmpfs'), 'TEST_RESET_BIND_SCOPE_REFUSED')
            if mount['Type'] == 'tmpfs':
                destination = mount.get('Destination')
                require(destination in temporary and destination not in temporary_summaries
                        and mount.get('Source', '') == '' and not mount.get('Name'),
                        'TEST_RESET_BIND_SCOPE_REFUSED')
                temporary_summaries.add(destination)
                continue
            source = mount.get('Name') if mount['Type'] == 'volume' else mount.get('Source')
            if mount['Type'] == 'bind' and source in ('/var/run/docker.sock', '/run/docker.sock'):
                source = reviewed_socket(info, service, source, mount.get('Destination'))
            if mount['Type'] == 'bind' and source == '/dev/net/tun':
                reviewed_tun(info, service, source, mount.get('Destination'), bind=True)
            actual.append(dict(type=mount['Type'], source=source, target=mount.get('Destination')))
        require(sorted(actual, key=lambda x: x['target']) == expected, 'TEST_RESET_BIND_SCOPE_REFUSED')
        host_config = row.get('HostConfig') or {}
        configured_tmpfs = host_config.get('Tmpfs') or {}
        require(isinstance(configured_tmpfs, dict), 'TEST_RESET_BIND_SCOPE_REFUSED')
        configured_tmpfs = {target: tmpfs_options(options) for target, options in configured_tmpfs.items()}
        require(configured_tmpfs == temporary, 'TEST_RESET_BIND_SCOPE_REFUSED')
        configured_devices = host_config.get('Devices') or []
        require(isinstance(configured_devices, list), 'TEST_RESET_BIND_SCOPE_REFUSED')
        actual_devices = []
        for device in configured_devices:
            require(isinstance(device, dict), 'TEST_RESET_BIND_SCOPE_REFUSED')
            source, target, permissions = device.get('PathOnHost'), device.get('PathInContainer'), device.get('CgroupPermissions')
            require(permissions == 'rwm', 'TEST_RESET_BIND_SCOPE_REFUSED')
            reviewed_tun(info, service, source, target)
            actual_devices.append(dict(source=source, target=target, permissions=permissions))
        require(actual_devices == model.get('devices', {}).get(service, []), 'TEST_RESET_BIND_SCOPE_REFUSED')
    names = command(['docker', 'volume', 'ls', '-q'], 'TEST_RESET_DOCKER_REFUSED').decode().split()
    volumes = json.loads(command(['docker', 'volume', 'inspect', *names], 'TEST_RESET_DOCKER_REFUSED')) if names else []
    for row in volumes:
        labels = row.get('Labels') or {}
        name, key = row.get('Name'), labels.get('com.docker.compose.volume')
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name)
                and labels.get('com.docker.compose.project') == info['project']
                and key in model['volumes'] and model['volumes'][key] == name
                and row.get('Driver') == 'local' and not row.get('Options')
                and row.get('Mountpoint') == str(VOLUME_ROOT / name / '_data')
                and (allowed_names is None or name in allowed_names), 'TEST_RESET_FOREIGN_VOLUME')
        path = safe(row['Mountpoint'])
        require(path.is_dir(), 'TEST_RESET_FOREIGN_VOLUME')
    return containers, volumes


def parse_mountpoints(raw):
    require(len(raw) <= 4 * 1024**2, 'TEST_RESET_FILESYSTEM_REFUSED')
    points = set()
    escapes = {'040': ' ', '011': '\t', '012': '\n', '134': '\\'}
    for line in raw.splitlines():
        fields = line.split(' - ', 1)[0].split()
        require(len(fields) >= 6, 'TEST_RESET_FILESYSTEM_REFUSED')
        text = re.sub(r'\\(040|011|012|134)', lambda match: escapes[match[1]], fields[4])
        point = PurePosixPath(text)
        require(point.is_absolute() and '..' not in point.parts, 'TEST_RESET_FILESYSTEM_REFUSED')
        points.add(Path(text))
    return points


def mountpoints():
    # ismount() alone misses Linux bind mounts when device IDs are identical.
    if os.name != 'posix':
        return set()
    with Path('/proc/self/mountinfo').open('r') as handle:
        return parse_mountpoints(handle.read(4 * 1024**2 + 1))


def tree_snapshot(root, include_hash=True):
    """No following links, crossing mountpoints, hardlinks or special files."""
    root = safe(root)
    require(not any(point != root and point.is_relative_to(root) for point in mountpoints()),
            'TEST_RESET_VOLUME_TREE_REFUSED')
    device = root.stat().st_dev
    result = {}
    total = 0
    pending = [root]
    while pending:
        path = pending.pop()
        relative = path.relative_to(root).as_posix()
        st = path.lstat()
        require(st.st_dev == device and len(result) < MAX_ENTRIES,
                'TEST_RESET_VOLUME_TREE_REFUSED')
        row = dict(uid=st.st_uid, gid=st.st_gid, mode=stat.S_IMODE(st.st_mode))
        if stat.S_ISDIR(st.st_mode):
            row['type'] = 'dir'
            # Nested mounts on the same device (bind mounts) are unsafe too.
            require(path == root or not os.path.ismount(path), 'TEST_RESET_VOLUME_TREE_REFUSED')
            pending.extend(sorted(path.iterdir(), reverse=True))
        elif stat.S_ISREG(st.st_mode):
            require(st.st_nlink == 1, 'TEST_RESET_VOLUME_TREE_REFUSED')
            row.update(type='file', size=st.st_size)
            total += st.st_size
            require(total <= MAX_BYTES, 'TEST_RESET_VOLUME_TREE_REFUSED')
            if include_hash:
                row['sha256'] = hash_file(path)
                after = path.lstat()
                require((st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
                        == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                        'TEST_RESET_ARCHIVE_CHANGED')
        elif stat.S_ISLNK(st.st_mode):
            link = os.readlink(path)
            require(not Path(link).is_absolute()
                    and path.resolve(strict=False).is_relative_to(root), 'TEST_RESET_VOLUME_TREE_REFUSED')
            row.update(type='link', link=link)
        else:
            raise Refused('TEST_RESET_VOLUME_TREE_REFUSED')
        result[relative] = row
    return result, total


def verify_tar(path, snapshot):
    seen = set()
    with tarfile.open(path, 'r|') as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and '..' not in name.parts,
                    'TEST_RESET_ARCHIVE_CHANGED')
            relative = name.as_posix()
            require(relative in snapshot and relative not in seen, 'TEST_RESET_ARCHIVE_CHANGED')
            seen.add(relative)
            row = snapshot[relative]
            require((member.uid, member.gid, member.mode) == (row['uid'], row['gid'], row['mode']),
                    'TEST_RESET_ARCHIVE_CHANGED')
            if row['type'] == 'file':
                require(member.isfile() and member.size == row['size'], 'TEST_RESET_ARCHIVE_CHANGED')
                digest = hashlib.sha256()
                handle = archive.extractfile(member)
                require(handle is not None, 'TEST_RESET_ARCHIVE_CHANGED')
                with handle:
                    for block in iter(lambda: handle.read(1024**2), b''):
                        digest.update(block)
                require(digest.hexdigest() == row['sha256'], 'TEST_RESET_ARCHIVE_CHANGED')
            elif row['type'] == 'dir':
                require(member.isdir(), 'TEST_RESET_ARCHIVE_CHANGED')
            else:
                require(member.issym() and member.linkname == row['link'], 'TEST_RESET_ARCHIVE_CHANGED')
    require(seen == set(snapshot), 'TEST_RESET_ARCHIVE_CHANGED')


def copy_volume(source, destination):
    before, size = tree_snapshot(source)
    require(shutil.disk_usage(destination.parent).free >= size + len(before) * 2048 + RESERVE,
            'TEST_RESET_SPACE_REQUIRED')
    require(not destination.exists(), 'TEST_RESET_ARCHIVE_FAILED')
    command(['tar', '--acls', '--xattrs', '--numeric-owner', '--format=pax', '-cf', destination,
             '-C', source, '.'], 'TEST_RESET_ARCHIVE_FAILED', timeout=1800)
    destination.chmod(0o600)
    regular(destination, private=True)
    verify_tar(destination, before)
    after, _ = tree_snapshot(source)
    require(before == after, 'TEST_RESET_ARCHIVE_CHANGED')
    sync_file(destination)
    sync_directory(destination.parent)
    return dict(sha256=hash_file(destination), snapshot_sha256=sha(canonical(after)))


def agent_unit(info):
    runner, target = info['runner'], info['target']
    return ('[Unit]\nDescription=Recovered Infisical native Agent\n'
            'Requires=streams-aio-infisical-tunnel.service\nAfter=streams-aio-infisical-tunnel.service\n'
            '[Service]\nType=simple\nUser=test\nGroup=test\nWorkingDirectory=' + target
            + '\nExecStart=/usr/local/lib/streams-aio-recovery/infisical agent --config '
            + runner + '/native-agent/agent-config.json\nRestart=always\nRestartSec=5s\n'
            'UMask=0077\nStandardOutput=null\nStandardError=null\n[Install]\nWantedBy=multi-user.target\n').encode()


def tunnel_unit(info):
    runner = info['runner']
    args = ['/usr/bin/ssh', '-N', '-T', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'ExitOnForwardFailure=yes',
            '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
            '-o', 'UserKnownHostsFile=' + runner + '/agent-known-hosts', '-i', runner + '/agent-tunnel-key',
            '-p', '22', '-L', '127.0.0.1:18180:127.0.0.1:80', 'streams-aio-tunnel@192.168.178.30']
    return ('[Unit]\nDescription=Encrypted API path to recovered Infisical\n'
            'Wants=network-online.target\nAfter=network-online.target\n[Service]\nType=simple\nUser=test\nGroup=test\nExecStart='
            + shlex.join(args) + '\nRestart=always\nRestartSec=5s\nUMask=0077\n'
            'StandardOutput=null\nStandardError=null\n[Install]\nWantedBy=multi-user.target\n').encode()


def system_files(info, state):
    """Only exact recovery-generated units and dedicated restricted SSH files."""
    files, units = {}, []
    expected = {'infisical-agent.service': agent_unit(info),
                'streams-aio-infisical-tunnel.service': tunnel_unit(info)} if info['role'] == 'stack' else {}
    for name, raw in expected.items():
        path = SYSTEMD / name
        loaded = command(['systemctl', 'show', name, '-p', 'LoadState', '-p', 'FragmentPath', '-p', 'DropInPaths'],
                         'TEST_RESET_UNIT_REFUSED').decode()
        meta = dict(line.split('=', 1) for line in loaded.splitlines() if '=' in line)
        if not path.exists():
            require(meta.get('LoadState') == 'not-found', 'TEST_RESET_UNIT_REFUSED')
            continue
        st = regular(path)
        require(st.st_uid == 0 and st.st_mode & 0o022 == 0 and path.read_bytes() == raw
                and meta.get('FragmentPath') == str(path) and not meta.get('DropInPaths'),
                'TEST_RESET_UNIT_REFUSED')
        files[str(path)] = sha(raw)
        units.append(name)
    if SYSTEMD.exists():
        for directory, _, names in os.walk(SYSTEMD, followlinks=False):
            for name in names:
                path = Path(directory) / name
                if path.is_symlink() or not path.is_file():
                    continue
                raw = path.read_bytes()
                if info['target'].encode() in raw or info['runner'].encode() in raw:
                    require(str(path) in files, 'TEST_RESET_UNIT_REFUSED')
    if info['role'] == 'infisical':
        import pwd
        account_home = Path('/var/lib/streams-aio-tunnel')
        conf = Path('/etc/ssh/sshd_config.d/70-streams-aio-tunnel.conf')
        if account_home.exists() or conf.exists():
            account = pwd.getpwnam('streams-aio-tunnel')
            require(account.pw_dir == str(account_home) and account.pw_shell == '/bin/false',
                    'TEST_RESET_UNIT_REFUSED')
            owner = account_home / 'recovery-owner'
            regular(owner, private=True)
            require(owner.read_text() == info['machine_id'], 'TEST_RESET_UNIT_REFUSED')
            port = state.get('api_port')
            require(port == 80, 'TEST_RESET_UNIT_REFUSED')
            keys = account_home / '.ssh/authorized_keys'
            key_info = regular(keys)
            require(key_info.st_uid == account.pw_uid and key_info.st_gid == account.pw_gid
                    and stat.S_IMODE(key_info.st_mode) == 0o600
                    and set(keys.parent.iterdir()) == {keys}, 'TEST_RESET_UNIT_REFUSED')
            raw = keys.read_bytes()
            require(bool(re.fullmatch(rb'restrict,port-forwarding,permitopen="127\.0\.0\.1:80",command="/bin/false" ssh-ed25519 [A-Za-z0-9+/=]+\n', raw)),
                    'TEST_RESET_UNIT_REFUSED')
            wanted = b'Match User streams-aio-tunnel\n    AllowTcpForwarding local\n    PermitOpen 127.0.0.1:80\n    PermitTTY no\n    X11Forwarding no\n    AllowAgentForwarding no\n    ForceCommand /bin/false\nMatch all\n'
            regular(conf, private=True)
            require(conf.read_bytes() == wanted, 'TEST_RESET_UNIT_REFUSED')
            files[str(keys)] = sha(raw)
            files[str(conf)] = sha(wanted)
    return files, units


def private_directory(path, create=False):
    path = safe(path)
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) == 0o700, 'TEST_RESET_PATH_REFUSED')
    return path


def existing_ancestor(path):
    path = safe(path)
    while not path.exists():
        path = path.parent
    return path


def rename_tree(path, device):
    """Renamed private trees must not contain another mounted filesystem."""
    require(path.stat().st_dev == device and not os.path.ismount(path)
            and not any(point.is_relative_to(path) for point in mountpoints()),
            'TEST_RESET_FILESYSTEM_REFUSED')
    pending_paths, count = [path], 0
    while pending_paths:
        directory = pending_paths.pop()
        require(directory.lstat().st_dev == device and not os.path.ismount(directory),
                'TEST_RESET_FILESYSTEM_REFUSED')
        for child in directory.iterdir():
            count += 1
            require(count <= MAX_ENTRIES, 'TEST_RESET_FILESYSTEM_REFUSED')
            st = child.lstat()
            require(st.st_dev == device, 'TEST_RESET_FILESYSTEM_REFUSED')
            if stat.S_ISDIR(st.st_mode):
                pending_paths.append(child)


def plan(info):
    target, runner = Path(info['target']), Path(info['runner'])
    if not target.exists() and not (runner / 'state.json').exists():
        require(not runner.exists(), 'TEST_RESET_CHECKPOINT_REFUSED')
        ids = command(['docker', 'ps', '-aq'], 'TEST_RESET_DOCKER_REFUSED').split()
        names = command(['docker', 'volume', 'ls', '-q'], 'TEST_RESET_DOCKER_REFUSED').split()
        require(not ids and not names, 'TEST_RESET_CHECKPOINT_REFUSED')
        if info['role'] == 'stack':
            for name in ('infisical-agent.service', 'streams-aio-infisical-tunnel.service'):
                require(not (SYSTEMD / name).exists(), 'TEST_RESET_UNIT_REFUSED')
                loaded = command(['systemctl', 'show', name, '-p', 'LoadState', '--value'],
                                 'TEST_RESET_UNIT_REFUSED').strip()
                require(loaded == b'not-found', 'TEST_RESET_UNIT_REFUSED')
        else:
            require(not Path('/var/lib/streams-aio-tunnel/.ssh/authorized_keys').exists()
                    and not Path('/etc/ssh/sshd_config.d/70-streams-aio-tunnel.conf').exists(),
                    'TEST_RESET_UNIT_REFUSED')
        return dict(info=info, empty=True)
    require(target.is_dir() and runner.is_dir(), 'TEST_RESET_CHECKPOINT_REFUSED')
    state, checkpoint_sha = checkpoint(info)
    model = read_model(info, state)
    containers, volumes = resources(info, model)
    files, units = system_files(info, state)
    base = Path(info['base'])
    if base.exists():
        private_directory(base)
    if base.parent.exists():
        private_directory(base.parent)
    storage = existing_ancestor(base)
    archive_device = storage.stat().st_dev
    require(target.stat().st_dev == runner.stat().st_dev == archive_device,
            'TEST_RESET_FILESYSTEM_REFUSED')
    rename_tree(target, archive_device)
    rename_tree(runner, archive_device)
    bytes_needed = 0
    for volume in volumes:
        rows, size = tree_snapshot(volume['Mountpoint'], include_hash=False)
        bytes_needed += size + len(rows) * 2048
    require(bytes_needed <= MAX_BYTES and shutil.disk_usage(storage).free >= bytes_needed + RESERVE,
            'TEST_RESET_SPACE_REQUIRED')
    return dict(info=info, empty=False, checkpoint_sha256=checkpoint_sha, model=model,
                containers=sorted(row['Id'] for row in containers),
                volumes=sorted(row['Name'] for row in volumes), files=files, units=units)


def pending(info):
    base = Path(info['base'])
    path = base / 'pending.json'
    if not path.exists():
        return None
    private_directory(base)
    regular(path, private=True)
    journal = json.loads(path.read_bytes())
    require(isinstance(journal, dict) and journal.get('schema') == 1
            and journal.get('plan', {}).get('info') == info
            and re.fullmatch(r'[0-9a-f]{64}', journal.get('ticket', ''))
            and journal['ticket'] == sha(canonical(journal['plan']))
            and re.fullmatch(r'\d{8}T\d{6}Z-[0-9a-f]{12}', journal.get('operation', '')),
            'TEST_RESET_JOURNAL_REFUSED')
    archive = private_directory(base / journal['operation'])
    require(journal.get('status') in ('PENDING', 'RESET'), 'TEST_RESET_JOURNAL_REFUSED')
    if journal['status'] == 'RESET':
        return None
    original = journal['plan']
    runner = Path(info['runner']) if Path(info['runner']).exists() else archive / 'runner'
    _, digest = checkpoint(info, runner)
    require(digest == original.get('checkpoint_sha256'), 'TEST_RESET_JOURNAL_REFUSED')
    resources(info, original['model'], original['containers'], original['volumes'])
    for name, expected in original['files'].items():
        if Path(name).exists():
            regular(name)
            require(hash_file(name) == expected, 'TEST_RESET_UNIT_REFUSED')
    for name in original['units']:
        path = safe(SYSTEMD / name)
        if path.exists():
            unit_loaded(name, path, original['files'][str(path)])
        else:
            require(journal.get('stopped') is True, 'TEST_RESET_UNIT_REFUSED')
            stopped_unit(name)
    return journal


def inspect(info):
    journal = pending(info)
    candidate = journal['plan'] if journal else plan(info)
    ticket = sha(canonical(candidate))
    return dict(role=info['role'], machine_id=info['machine_id'],
                containers=len(candidate.get('containers', [])), volumes=len(candidate.get('volumes', [])),
                ticket=ticket, status='EMPTY' if candidate['empty'] else 'READY')


def stopped_unit(name):
    raw = command(['systemctl', 'show', name, '-p', 'ActiveState', '-p', 'MainPID', '-p', 'ControlPID'],
                  'TEST_RESET_UNIT_REFUSED').decode()
    meta = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
    require(meta.get('ActiveState') in ('inactive', 'failed')
            and meta.get('MainPID') == '0' and meta.get('ControlPID') == '0',
            'TEST_RESET_UNIT_REFUSED')


def unit_loaded(name, path, digest):
    raw = command(['systemctl', 'show', name, '-p', 'LoadState', '-p', 'FragmentPath', '-p', 'DropInPaths'],
                  'TEST_RESET_UNIT_REFUSED').decode()
    meta = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
    st = regular(path)
    require(st.st_uid == 0 and st.st_mode & 0o022 == 0 and hash_file(path) == digest
            and meta.get('FragmentPath') == str(path) and not meta.get('DropInPaths')
            and meta.get('LoadState') == 'loaded', 'TEST_RESET_UNIT_REFUSED')


def reset(info, ticket):
    journal = pending(info)
    candidate = journal['plan'] if journal else plan(info)
    require(ticket == sha(canonical(candidate)), 'TEST_RESET_TICKET_CHANGED')
    if candidate['empty']:
        return dict(role=info['role'], status='RESET', archive=None)
    private_directory(Path(info['base']).parent, create=True)
    base = private_directory(info['base'], create=True)
    if journal is None:
        operation = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + os.urandom(6).hex()
        archive = private_directory(base / operation, create=True)
        journal = dict(schema=1, operation=operation, ticket=ticket, plan=candidate,
                       status='PENDING', volume_copies={}, moved=[], removed_files=[], stopped=False)
        save(base / 'pending.json', journal)
    archive = private_directory(base / journal['operation'])
    original = journal['plan']
    # Copy exact validated system files before stopping anything. Copies stay
    # private and their hashes are checked again before the originals are unlinked.
    directory = private_directory(archive / 'system-files', create=True)
    for index, (name, digest) in enumerate(sorted(original['files'].items())):
        destination = directory / str(index)
        if destination.exists():
            regular(destination, private=True)
            require(hash_file(destination) == digest, 'TEST_RESET_ARCHIVE_CHANGED')
        else:
            regular(name)
            require(hash_file(name) == digest, 'TEST_RESET_UNIT_REFUSED')
            destination.write_bytes(Path(name).read_bytes())
            destination.chmod(0o600)
            require(hash_file(destination) == digest, 'TEST_RESET_ARCHIVE_CHANGED')
        sync_file(destination)
        sync_directory(destination.parent)
    containers, volumes = resources(info, original['model'], original['containers'], original['volumes'])
    for name in original['units']:
        path = safe(SYSTEMD / name)
        if not path.exists():
            # Unlink may have succeeded immediately before interruption, even
            # if removed_files was not yet saved. The archived bytes were
            # verified above; never stop a newly loaded unit in this case.
            require(journal['stopped'], 'TEST_RESET_UNIT_REFUSED')
            command(['systemctl', 'daemon-reload'], 'TEST_RESET_UNIT_REFUSED')
            loaded = command(['systemctl', 'show', name, '-p', 'LoadState', '--value'],
                             'TEST_RESET_UNIT_REFUSED').strip()
            require(loaded == b'not-found', 'TEST_RESET_UNIT_REFUSED')
            stopped_unit(name)
            continue
        unit_loaded(name, path, original['files'][str(path)])
        command(['systemctl', 'disable', '--now', name], 'TEST_RESET_UNIT_REFUSED')
        stopped_unit(name)
    if containers:
        command(['docker', 'stop', '--time', '30', *[row['Id'] for row in containers]],
                'TEST_RESET_CONTAINER_STOP_FAILED', timeout=180)
    containers, volumes = resources(info, original['model'], original['containers'], original['volumes'])
    require(all(row.get('State', {}).get('Running') is False
                and row.get('State', {}).get('Restarting') is False for row in containers),
            'TEST_RESET_CONTAINER_STOP_FAILED')
    journal['stopped'] = True
    save(base / 'pending.json', journal)
    copies = private_directory(archive / 'volumes', create=True)
    for row in volumes:
        name = row['Name']
        destination = copies / (name + '.tar')
        if name not in journal['volume_copies']:
            # A killed copy is never trusted. Its path is retained; retrying a
            # copy under a new bounded filename preserves the incomplete copy.
            if destination.exists():
                abandoned = copies / (name + '.incomplete-' + os.urandom(6).hex() + '.tar')
                destination.rename(abandoned)
            journal['volume_copies'][name] = copy_volume(Path(row['Mountpoint']), destination)
            save(base / 'pending.json', journal)
        regular(destination, private=True)
        copied = journal['volume_copies'][name]
        snapshot, _ = tree_snapshot(Path(row['Mountpoint']))
        require(hash_file(destination) == copied['sha256']
                and sha(canonical(snapshot)) == copied['snapshot_sha256'], 'TEST_RESET_ARCHIVE_CHANGED')
        verify_tar(destination, snapshot)
    require(set(journal['volume_copies']) == set(original['volumes']), 'TEST_RESET_ARCHIVE_FAILED')
    for name in original['volumes']:
        path = copies / (name + '.tar')
        regular(path, private=True)
        require(hash_file(path) == journal['volume_copies'][name]['sha256'], 'TEST_RESET_ARCHIVE_CHANGED')
    # No remove is reached until EVERY original volume has a verified copy.
    containers, volumes = resources(info, original['model'], original['containers'], original['volumes'])
    require(all(row.get('State', {}).get('Running') is False
                and row.get('State', {}).get('Restarting') is False for row in containers),
            'TEST_RESET_CONTAINER_STOP_FAILED')
    if containers:
        command(['docker', 'rm', *[row['Id'] for row in containers]], 'TEST_RESET_RESOURCE_REMOVE_FAILED')
    for row in volumes:
        name = row['Name']
        copied = journal['volume_copies'][name]
        snapshot, _ = tree_snapshot(Path(row['Mountpoint']))
        require(sha(canonical(snapshot)) == copied['snapshot_sha256']
                and hash_file(copies / (name + '.tar')) == copied['sha256'], 'TEST_RESET_ARCHIVE_CHANGED')
        command(['docker', 'volume', 'rm', name], 'TEST_RESET_RESOURCE_REMOVE_FAILED')
        save(base / 'pending.json', journal)
    containers, volumes = resources(info, original['model'], original['containers'], original['volumes'])
    require(not containers and not volumes, 'TEST_RESET_RESOURCE_REMOVE_FAILED')
    for name, digest in original['files'].items():
        if name in journal['removed_files']:
            require(not Path(name).exists(), 'TEST_RESET_UNIT_REFUSED')
            continue
        if Path(name).exists():
            regular(name)
            require(hash_file(name) == digest, 'TEST_RESET_UNIT_REFUSED')
            Path(name).unlink()
            sync_directory(Path(name).parent)
        # The private verified system copy is present even after interrupted unlink.
        journal['removed_files'].append(name)
        save(base / 'pending.json', journal)
    if original['units']:
        command(['systemctl', 'daemon-reload'], 'TEST_RESET_UNIT_REFUSED')
    if info['role'] == 'infisical' and original['files']:
        command(['/usr/sbin/sshd', '-t'], 'TEST_RESET_UNIT_REFUSED')
        command(['systemctl', 'reload', 'ssh.service'], 'TEST_RESET_UNIT_REFUSED')
    for key in ('target', 'runner'):
        source, destination = safe(info[key]), safe(archive / key)
        if source.exists():
            require(not destination.exists() and source.stat().st_dev == archive.stat().st_dev,
                    'TEST_RESET_FILESYSTEM_REFUSED')
            source.rename(destination)
            sync_directory(source.parent)
            sync_directory(archive)
        require(destination.is_dir() and not source.exists(), 'TEST_RESET_FILESYSTEM_REFUSED')
        if key not in journal['moved']:
            journal['moved'].append(key)
            save(base / 'pending.json', journal)
    journal['status'] = 'RESET'
    save(base / 'pending.json', journal)
    save(archive / 'receipt.json', journal)
    return dict(role=info['role'], status='RESET', archive=str(archive))


def parse_request(raw):
    require(len(raw) <= 65536, 'TEST_RESET_SCOPE_REFUSED')
    lines = raw.splitlines()
    header = b'STREAMS_TEST_RESET_V1'
    offset = 0 if lines and lines[0] == header else 1
    require(len(lines) > offset and lines[offset] == header, 'TEST_RESET_SCOPE_REFUSED')
    request = json.loads(b'\n'.join(lines[offset + 1:]))
    require(isinstance(request, dict), 'TEST_RESET_SCOPE_REFUSED')
    return request


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', choices=tuple(ROLES), required=True)
    parser.add_argument('--mode', choices=('inspect', 'reset'), required=True)
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(65537)
        request = parse_request(raw)
        info = scope(args.role, request)
        with locks(info):
            result = inspect(info) if args.mode == 'inspect' else reset(info, request.get('ticket'))
        print(json.dumps(result), flush=True)
    except Exception as error:
        code = str(error)
        print(json.dumps({'error': code if code in ERROR_CODES else 'TEST_RESET_OPERATION_FAILED'}), flush=True)
        sys.exit(1)


if __name__ == '__main__':
    main()

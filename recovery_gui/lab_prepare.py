"""Prepare two empty VMs for local service tests, without an application start.

This deliberately does not call restore_all: that function starts the complete
stack. Backup downloads are read-only; DNS, router, publication workers and
timers are outside this operation. Credentials are forwarded only in memory.
"""
import json
from pathlib import Path
import re
import threading

from . import backend


class LabFailure(ValueError):
    """A closed diagnostic code; never an input or transport error excerpt."""


LAB_MARKER = r'''
import json, os, pathlib, pwd, re, stat, sys
try:
    assert sys.platform == 'linux' and os.geteuid() == 0
    raw = sys.stdin.buffer.read(65537)
    assert len(raw) <= 65536
    prefix, frame, payload = raw.rpartition(b'STREAMS_LAB_V1\n')
    assert frame and len(payload) <= 8192
    assert not prefix or (len(prefix) <= 16385 and prefix.endswith(b'\n') and prefix.count(b'\n') == 1)
    request = json.loads(payload)
    assert set(request) == {'schema','kind','root','owner','machine_id','publications_disabled'}
    assert type(request['schema']) is int and request['schema'] == 1
    assert request['kind'] == 'prepared_onboarding_lab' and request['publications_disabled'] is True
    owner, root = request['owner'], pathlib.Path(request['root'])
    assert isinstance(owner, str) and re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', owner)
    assert str(root) == '/home/' + owner + '/streams-aio'
    assert re.fullmatch(r'[0-9a-f]{32}', request['machine_id'])
    assert pathlib.Path('/etc/machine-id').read_text().strip() == request['machine_id']
    account = pwd.getpwnam(owner)
    assert account.pw_uid == 1000 and account.pw_gid == 1000 and account.pw_dir == str(root.parent)
    assert root.is_dir() and not any(p.is_symlink() for p in (root, *root.parents))
    home = root.parent
    for folder in (home / '.local', home / '.local/state'):
        assert not folder.is_symlink()
        if not folder.exists():
            folder.mkdir(mode=0o700)
            os.chown(folder, account.pw_uid, account.pw_gid)
        info = folder.stat()
        assert stat.S_ISDIR(info.st_mode) and info.st_uid in (0, account.pw_uid) and not info.st_mode & 0o022
    area = home / '.local/state/streams-aio-onboarding'
    assert not area.is_symlink()
    if not area.exists():
        area.mkdir(mode=0o700)
        os.chown(area, 0, 0)
    info = area.stat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
    assert stat.S_IMODE(info.st_mode) == 0o700 and not os.listxattr(area)
    marker = area / 'lab.json'
    expected = (json.dumps(request, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if marker.exists() or marker.is_symlink():
        fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
            assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size <= 8192
            assert os.read(fd, 8193) == expected
        finally:
            os.close(fd)
    else:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o600)
            with os.fdopen(os.dup(fd), 'wb') as writer:
                writer.write(expected)
                writer.flush()
                os.fsync(writer.fileno())
        finally:
            os.close(fd)
    print('{"schema":1,"status":"PASS"}')
except Exception:
    print('{"schema":1,"status":"REFUSED"}')
'''


def _need(value, code):
    if not value:
        raise LabFailure(code)


def _check_cancel(cancelled):
    _need(not cancelled.is_set(), 'SERVICE_OPERATION_STOPPED')


def _host(snapshot, prefix=''):
    key_names = {'key': 'infisical_key', 'key_password': 'infisical_key_password',
                 'sudo_password': 'infisical_sudo_password'} if prefix else {'key': 'ssh_key'}
    def value(name, default=''):
        return snapshot.get(key_names.get(name, prefix + name), default)
    try:
        host = backend.Host(value('host'), value('user'), int(value('port', '22') or '22'),
                            value('password'), value('key'), value('key_password'), value('sudo_password'))
        _need(all(isinstance(item, str) for item in (host.address, host.user, host.password,
                    host.key_file, host.key_password, host.sudo_password)), 'SSH_ADDRESS_REQUIRED')
        host.validate()
        return host
    except backend.Failure:
        raise
    except (TypeError, ValueError, AttributeError):
        raise LabFailure('SSH_ADDRESS_REQUIRED') from None


def _clean(info, host):
    _need(isinstance(info, dict) and info.get('existing_recovery') is False
          and type(info.get('containers')) is int and info['containers'] == 0
          and type(info.get('volumes')) is int and info['volumes'] == 0,
          'LAB_EMPTY_VMS_REQUIRED')
    _need(info.get('user') == host.user and info.get('home') == '/home/' + host.user
          and isinstance(info.get('machine_id'), str)
          and re.fullmatch(r'[0-9a-f]{32}', info['machine_id']), 'LAB_HOST_IDENTITY_INVALID')
    return info


def _progress(callback, event):
    if callback is None or not isinstance(event, dict):
        return
    if event.get('stage') not in backend.STAGES | {'HOST', 'FILES', 'AGENT', 'INFISICAL'}:
        return
    if event.get('status') not in ('RUNNING', 'PASS', 'REFUSED'):
        return
    safe = dict(stage=event['stage'], status=event['status'])
    if isinstance(event.get('code'), str) and event['code'] in backend.ERROR_CODES:
        safe['code'] = event['code']
    callback(safe)


def prepare_lab(snapshot, confirm_key, cancelled, confirm_changed_key=None, progress_callback=None,
                *, ssh_factory=backend.SSH, github_factory=backend.GitHub):
    """Prepare infrastructure only. Both hosts must be empty before any upload."""
    stack = server = None
    cancelled = cancelled or threading.Event()
    emit = lambda event: _progress(progress_callback, event)
    try:
        _need(isinstance(snapshot, dict), 'LAB_INPUTS_REQUIRED')
        _check_cancel(cancelled)
        stack_host, server_host = _host(snapshot), _host(snapshot, 'infisical_')
        _need((stack_host.address, stack_host.port) != (server_host.address, server_host.port),
              'SEPARATE_RECOVERY_VMS_REQUIRED')
        tag, commit = snapshot.get('dr_tag', ''), snapshot.get('public_commit', '')
        _need(isinstance(tag, str) and backend.TAG.fullmatch(tag)
              and isinstance(commit, str) and backend.SHA.fullmatch(commit), 'SELECT_GITHUB_RECOVERY_POINT')
        identity = snapshot.get('age_identity', '')
        _need(isinstance(identity, str) and bool(identity), 'AGE_IDENTITY_FILE_REQUIRED')
        identity_path = Path(identity)
        _need(identity_path.is_file(), 'AGE_IDENTITY_FILE_REQUIRED')
        _need(not identity_path.is_symlink() and 0 < identity_path.stat().st_size <= 65536,
              'AGE_IDENTITY_FILE_INVALID')
        token = snapshot.get('github_token', '')
        _need(isinstance(token, str) and token.strip() and '\n' not in token and '\r' not in token,
              'GITHUB_TOKEN_REQUIRED')
        point = github_factory(token).point(tag)
        _need(isinstance(point, dict) and point.get('tag') == tag and point.get('aio_snapshot') is True,
              'AIO_SNAPSHOT_BACKUP_REQUIRED')
        _need(point.get('public_commit') == commit, 'DR_STACK_COMMIT_MISMATCH')
        backend.validate_remote_shell_scripts()
        _check_cancel(cancelled)
        stack = ssh_factory(stack_host, confirm_key, cancelled, confirm_changed_key=confirm_changed_key)
        server = ssh_factory(server_host, confirm_key, cancelled, confirm_changed_key=confirm_changed_key)
        emit(dict(stage='HOST', status='RUNNING'))
        first = _clean(stack.check(fresh=True, role='stack'), stack_host)
        second = _clean(server.check(fresh=True, role='infisical'), server_host)
        _need(first['machine_id'] != second['machine_id'], 'SEPARATE_RECOVERY_VMS_REQUIRED')
        emit(dict(stage='HOST', status='PASS'))
        _check_cancel(cancelled)
        # Explicit allowlist: do not inherit DNS/cutover/controllers, legacy
        # supplemental files, API origins or unrelated credentials from the GUI.
        request = dict(github_token=token, public_commit=commit, dr_tag=tag, age_identity=identity,
                       infisical_address='', project_id='', environment='', native_agent=True,
                       aio_mode='snapshot', client_id_file='', client_secret_file='', aio_payload='',
                       supplemental_inputs='', aiostreams_exports=[], aiometadata_exports=[])
        server.prepare(dict(request, role='infisical'), emit)
        _check_cancel(cancelled)
        port = server.restored_port()
        _need(type(port) is int and 1 <= port <= 65535, 'INFISICAL_API_PORT_REQUIRES_REVIEW')
        with backend.APIBridge(stack, server, port) as address:
            _check_cancel(cancelled)
            stack.prepare(dict(request, role='stack', infisical_address=address, ssh_bridge=True), emit)
        _check_cancel(cancelled)
        emit(dict(stage='NATIVE_AGENT', status='RUNNING'))
        target = first['home'] + '/streams-aio'
        raw = stack.native('key', first['home'], target)
        key = json.loads(raw)
        _need(isinstance(key, dict) and set(key) == {'public_key'} and isinstance(key['public_key'], str)
              and len(key['public_key']) <= 8192, 'AGENT_PUBLIC_KEY_INVALID')
        _check_cancel(cancelled)
        server.native('authorize', second['home'], '/opt/infisical', callback=emit,
                      metadata={'public_key': key['public_key']})
        host_key = server.client.get_transport().get_remote_server_key()
        _check_cancel(cancelled)
        stack.native('install', first['home'], target, callback=emit,
                     metadata=dict(host=server_host.address, port=server_host.port, api_port=port,
                                   host_key=host_key.get_name() + ' ' + host_key.get_base64()))
        _check_cancel(cancelled)
        marker = dict(schema=1, kind='prepared_onboarding_lab', root=target, owner=stack_host.user,
                      machine_id=first['machine_id'], publications_disabled=True)
        result = json.loads(stack.run(['python3', '-B', '-c', LAB_MARKER], sudo=True,
                                     input=b'STREAMS_LAB_V1\n' + json.dumps(marker).encode() + b'\n', timeout=40))
        _need(result == {'schema': 1, 'status': 'PASS'}, 'LAB_MARKER_REFUSED')
        emit(dict(stage='NATIVE_AGENT', status='PASS'))
        return dict(schema=1, status='PREPARED_LAB',
                    checks=dict(infisical_restored=True, stack_prepared=True, agent_installed=True,
                                lab_scope_recorded=True), applications_started=False,
                    publications_enabled=False, backup_verified=False)
    except backend.Failure as error:
        code = str(error)
        raise LabFailure(code if code in backend.ERROR_CODES else 'LAB_PREPARATION_FAILED') from None
    except LabFailure:
        raise
    except Exception:
        raise LabFailure('LAB_PREPARATION_FAILED') from None
    finally:
        for connection in (server, stack):
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass

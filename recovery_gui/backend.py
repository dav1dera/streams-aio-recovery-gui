"""Desktop transport. Credentials stay in memory; reports contain fixed codes only."""
import base64
from dataclasses import dataclass, field
import errno
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import sys
import threading
import time
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener
import uuid
from urllib.parse import urlsplit
from .codes import ERROR_CODES
from .recovery_inspection import inspect_recovery, resolve_resume_request
from .startup_diagnostic import safe as safe_startup_diagnostic
from .external_dependencies import validate as validate_external_dependencies
from . import ssh_identity
from .upload_staging import SETUP as UPLOAD_SETUP
from .age_input import AgeInputFailure, validate_pasted_identity

PUBLIC = 'dav1dera/streams-aio-sanitized'
PRIVATE = 'dav1dera/streams-aio-dr'
STAGES = {'DEPENDENCIES', 'CLONES', 'DOWNLOAD', 'DECRYPT', 'INITIALIZE', 'INPUTS',
          'RENDER', 'EMPTY_STATE', 'NPM', 'AIO', 'PREFLIGHT', 'PREPARED', 'STARTED', 'REFUSED', 'TLS',
          'INFISICAL_CONFIG', 'INFISICAL_DATABASE', 'INFISICAL_SERVER', 'NATIVE_AGENT',
          'RUNTIME_PROFILE', 'COMETNET_TRIAL', 'IMAGES', 'APPLICATION_CHECKS', 'TEST_RESET_STACK', 'TEST_RESET_INFISICAL',
          'OPERATIONAL_PROFILE', 'PUBLIC_DOMAINS', 'PUBLIC_CONTROLLERS', 'OPERATIONAL_READY', 'AIO_BACKUP', 'NPM_TOPOLOGY', 'EXTERNAL_UPSTREAMS',
          'INFISICAL_TRANSFER', 'STACK_TRANSFER', 'TAILSCALE', 'HEADPLANE', 'HOST_DNS_STACK', 'HOST_DNS_INFISICAL',
          'LOCAL_ENDPOINTS'}
CODE = re.compile(r'[A-Z][A-Z0-9_]{0,100}\Z')
SHA = re.compile(r'[0-9a-f]{40}\Z')
TAG = re.compile(r'dr-[0-9]{8}T[0-9]{6}Z\Z')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward a GitHub token to a redirect destination.
        return None


class Failure(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Failure(code)


def dns_server_address(value):
    if value in ('', None):
        return ''
    try:
        address = ipaddress.ip_address(value)
        require(str(address) == value and not (address.is_unspecified or address.is_loopback
                or address.is_multicast or address.is_link_local or address.is_reserved) and '%' not in value,
                'HOST_DNS_CONFIGURATION_REFUSED')
        return str(address)
    except (ValueError, TypeError):
        raise Failure('HOST_DNS_CONFIGURATION_REFUSED') from None


def resources():
    return Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parents[1])) / 'remote'


def validate_remote_shell_scripts():
    """Check packaged bytes, before a remote command can change either VM."""
    try:
        folder = resources()
        scripts = list(folder.glob('*.sh'))
        require(folder.joinpath('bootstrap.sh') in scripts, 'REMOTE_SCRIPT_FORMAT_INVALID')
        for script in scripts:
            raw = script.read_bytes()
            require(raw.startswith(b'#!/usr/bin/env bash\n') and raw.endswith(b'\n')
                    and b'\r' not in raw, 'REMOTE_SCRIPT_FORMAT_INVALID')
    except OSError:
        raise Failure('REMOTE_SCRIPT_FORMAT_INVALID') from None


def parse_event(line):
    if not line.startswith('RECOVERY_EVENT '):
        return None
    try:
        item = json.loads(line[len('RECOVERY_EVENT '):])
        if (isinstance(item,dict) and set(item)=={'stage','status','diagnostic'}
                and item.get('stage')=='EXTERNAL_UPSTREAMS' and item.get('status') in ('PASS','WARNING')):
            diagnostic=validate_external_dependencies(item['diagnostic'])
            require((item['status']=='WARNING')==bool(diagnostic['unavailable']),'INVALID_EVENT')
            return dict(stage='EXTERNAL_UPSTREAMS',status=item['status'],diagnostic=diagnostic)
        if (isinstance(item, dict) and set(item) == {'stage', 'status', 'code', 'diagnostic'}
                and item.get('stage') == 'REFUSED' and item.get('status') == 'REFUSED'
                and item.get('code') == 'APPLICATION_HEALTH_WAIT_FAILED'):
            return dict(stage='REFUSED', status='REFUSED', code='APPLICATION_HEALTH_WAIT_FAILED',
                        diagnostic=safe_startup_diagnostic(item['diagnostic']))
        require(set(item) <= {'stage', 'status', 'code'} and item.get('stage') in STAGES
                and (item.get('status') in ('RUNNING', 'PASS', 'REFUSED')
                     or item.get('stage') == 'AIO' and item.get('status') == 'SKIPPED')
                and ('code' not in item or item['code'] in ERROR_CODES), 'INVALID_EVENT')
        return item
    except Exception:
        return None


def remote_failure_code(raw):
    """Only fixed public codes may cross the metadata-command boundary."""
    try:
        item = json.loads(raw)
        if isinstance(item, dict) and isinstance(item.get('error'), str) and item['error'] in ERROR_CODES:
            return item['error']
    except (ValueError, UnicodeDecodeError):
        pass
    for line in raw.decode('utf-8', 'replace').splitlines():
        item = parse_event(line.strip())
        if item and item['stage'] == 'REFUSED' and item['status'] == 'REFUSED' and item.get('code'):
            return item['code']
    return 'REMOTE_OPERATION_FAILED'


@dataclass
class Host:
    address: str
    user: str = 'pi'
    port: int = 22
    password: str = field(default='', repr=False)
    key_file: str = ''
    key_password: str = field(default='', repr=False)
    sudo_password: str = field(default='', repr=False)

    def validate(self):
        require(bool(re.fullmatch(r'[A-Za-z0-9.:-]+', self.address)) and 1 <= self.port <= 65535,
                'SSH_ADDRESS_REQUIRED')
        require(bool(re.fullmatch(r'[a-z_][a-z0-9_-]*', self.user)), 'INVALID_SSH_USER')
        require(bool(self.password or self.key_file), 'SSH_PASSWORD_OR_KEY_REQUIRED')
        if self.key_file:
            require(Path(self.key_file).is_file(), 'SSH_KEY_FILE_MISSING')
        require('\n' not in self.password + self.sudo_password, 'PASSWORD_NEWLINE_UNSUPPORTED')


class GitHub:
    def __init__(self, token):
        require(bool(token.strip()) and '\n' not in token and '\r' not in token, 'GITHUB_TOKEN_REQUIRED')
        self.token = token.strip()

    def get(self, path):
        require(path.startswith('repos/') and '..' not in path, 'INVALID_GITHUB_RESOURCE')
        request = Request('https://api.github.com/' + path,
                          headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                                   'User-Agent': 'streams-aio-recovery-gui/0.2.0', 'X-GitHub-Api-Version': '2022-11-28'})
        try:
            with build_opener(NoRedirect()).open(request, timeout=25) as response:
                raw = response.read(4 * 1024**2 + 1)
            require(len(raw) <= 4 * 1024**2, 'GITHUB_METADATA_TOO_LARGE')
            return json.loads(raw)
        except HTTPError as error:
            raise Failure({401: 'GITHUB_AUTH_FAILED', 403: 'GITHUB_ACCESS_DENIED',
                           404: 'GITHUB_REPOSITORY_OR_RELEASE_UNAVAILABLE'}.get(error.code, 'GITHUB_REQUEST_FAILED')) from None
        except Failure:
            raise
        except Exception:
            raise Failure('GITHUB_CONNECTION_FAILED') from None

    def choices(self):
        require(self.get(f'repos/{PRIVATE}').get('private') is True, 'PRIVATE_REPOSITORY_REQUIRED')
        releases = self.get(f'repos/{PRIVATE}/releases?per_page=100')
        tags = [item['tag_name'] for item in releases if item.get('draft') is False
                and isinstance(item.get('tag_name'), str) and TAG.fullmatch(item['tag_name'])]
        require(bool(tags), 'NO_PUBLISHED_DR_RELEASE')
        tags = sorted(tags, reverse=True)
        # Prefer a point containing native AIO state. Its manifest, rather than
        # an unrelated current main branch, supplies the matching stack commit.
        complete = [item['tag_name'] for item in releases if item.get('tag_name') in tags
                    and any(a.get('name') == 'aio-state.tar.gz.age' for a in item.get('assets', []))]
        if complete:
            ordered = sorted(complete, reverse=True)
            return ordered, self.point(ordered[0])['public_commit']
        commit = self.get(f'repos/{PUBLIC}/git/ref/heads/main')['object']['sha']
        require(bool(SHA.fullmatch(commit)), 'INVALID_PUBLIC_COMMIT')
        return sorted(tags, reverse=True), commit

    def asset(self, asset):
        """Read a small release metadata asset; credentials never follow redirects."""
        require(isinstance(asset, dict) and type(asset.get('id')) is int
                and type(asset.get('size')) is int and 0 < asset['size'] <= 131072,
                'DR_RELEASE_METADATA_UNAVAILABLE')
        request = Request(f'https://api.github.com/repos/{PRIVATE}/releases/assets/{asset["id"]}',
            headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/octet-stream',
                     'User-Agent': 'streams-aio-recovery-gui', 'X-GitHub-Api-Version': '2022-11-28'})
        opener = build_opener(NoRedirect())
        try:
            try:
                response = opener.open(request, timeout=25)
            except HTTPError as error:
                require(error.code in (301, 302, 303, 307, 308), 'DR_RELEASE_METADATA_UNAVAILABLE')
                url = error.headers.get('Location', '')
                destination = urlsplit(url)
                require(destination.scheme == 'https' and destination.hostname == 'release-assets.githubusercontent.com'
                        and not destination.username and not destination.password,
                        'DR_RELEASE_METADATA_UNAVAILABLE')
                # Signed GitHub asset URL only, without the Authorization header.
                response = opener.open(Request(url, headers={'User-Agent': 'streams-aio-recovery-gui'}), timeout=25)
            with response:
                raw = response.read(131073)
            require(len(raw) == asset['size'] and len(raw) <= 131072, 'DR_BUNDLE_VERIFICATION_FAILED')
            expected = asset.get('digest')
            if expected is not None:
                require(expected == 'sha256:' + hashlib.sha256(raw).hexdigest(), 'DR_BUNDLE_VERIFICATION_FAILED')
            return raw
        except Failure:
            raise
        except Exception:
            raise Failure('DR_RELEASE_METADATA_UNAVAILABLE') from None

    def point(self, tag):
        require(isinstance(tag, str) and TAG.fullmatch(tag), 'SELECT_GITHUB_RECOVERY_POINT')
        release = self.get(f'repos/{PRIVATE}/releases/tags/{tag}')
        require(release.get('tag_name') == tag and release.get('draft') is False, 'PUBLISHED_RELEASE_REQUIRED')
        assets = release.get('assets', [])
        base = {'npm-database.sqlite.age', 'infisical-agent-infisical-agent.tar.gz.age',
                'infisical-config.tar.gz.age', 'infisical-postgres.dump.age', 'infisical-postgres-globals.sql.age',
                'manifest.json', 'SHA256SUMS'}
        names = {a.get('name') for a in assets}
        require(names in (base, base | {'aio-state.tar.gz.age'}) and len(assets) == len(names),
                'UNEXPECTED_RELEASE_ASSETS')
        if 'aio-state.tar.gz.age' not in names:
            # Legacy points remain visible for diagnostics, never advertised as
            # complete automatic restores. Their old manifest has no stack pin.
            commit = self.get(f'repos/{PUBLIC}/git/ref/heads/main')['object']['sha']
            require(bool(SHA.fullmatch(commit)), 'INVALID_PUBLIC_COMMIT')
            return dict(tag=tag, public_commit=commit, aio_snapshot=False)
        by_name = {a['name']: a for a in assets}
        raw = self.asset(by_name['manifest.json'])
        sums = self.asset(by_name['SHA256SUMS']).decode('ascii')
        lines = sums.splitlines()
        expected = hashlib.sha256(raw).hexdigest() + '  manifest.json'
        require(lines.count(expected) == 1 and len(lines) == len(names) - 1, 'DR_BUNDLE_VERIFICATION_FAILED')
        try:
            manifest = json.loads(raw)
        except (ValueError, UnicodeError):
            raise Failure('DR_BUNDLE_VERIFICATION_FAILED') from None
        require(isinstance(manifest, dict) and isinstance(manifest.get('artifacts'), dict),
                'DR_BUNDLE_VERIFICATION_FAILED')
        require(manifest.get('schema') == 2 and manifest.get('run') == tag[3:]
                and manifest.get('repository') == PRIVATE
                and set(manifest.get('artifacts', {})) == names - {'manifest.json', 'SHA256SUMS'}
                and isinstance(manifest.get('stack_commit'), str) and SHA.fullmatch(manifest['stack_commit']),
                'DR_BUNDLE_VERIFICATION_FAILED')
        return dict(tag=tag, public_commit=manifest['stack_commit'], aio_snapshot=True)


def _ssh_connection_code(error, host, paramiko):
    """Classify local exception types/numbers, never exception text or replies."""
    if isinstance(error, paramiko.PasswordRequiredException):
        return 'SSH_KEY_PASSPHRASE_REQUIRED'
    if isinstance(error, paramiko.ssh_exception.NoValidConnectionsError):
        failures = getattr(error, 'errors', None)
        if isinstance(failures, dict) and 0 < len(failures) <= 32:
            codes = {_ssh_connection_code(value, host, paramiko) for value in failures.values()}
            if len(codes) == 1:
                return codes.pop()
        return 'SSH_CONNECTION_FAILED'
    if isinstance(error, socket.gaierror):
        return 'SSH_NAME_RESOLUTION_FAILED'
    if isinstance(error, (TimeoutError, socket.timeout)):
        return 'SSH_CONNECT_TIMEOUT'
    if isinstance(error, EOFError):
        return 'SSH_TRANSPORT_CLOSED'
    if isinstance(error, paramiko.pkey.UnknownKeyType):
        return 'SSH_KEY_FORMAT_INVALID'
    if isinstance(error, OSError):
        number = getattr(error, 'winerror', None) or getattr(error, 'errno', None)
        # Windows 10013 and socket EACCES are local access failures, not proof
        # that a VM is offline. A matching filename proves a local key read.
        filename = getattr(error, 'filename', None)
        if host.key_file and isinstance(filename, str):
            try:
                if Path(filename).absolute() == Path(host.key_file).absolute():
                    return 'SSH_KEY_FILE_UNAVAILABLE'
            except (OSError, ValueError):
                pass
        if isinstance(error, FileNotFoundError) and host.key_file:
            return 'SSH_KEY_FILE_UNAVAILABLE'
        if number in (errno.EACCES, errno.EPERM, 10013):
            return 'SSH_LOCAL_NETWORK_DENIED'
        if number in (errno.ECONNREFUSED, 10061):
            return 'SSH_CONNECTION_REFUSED'
        if number in (errno.ENETUNREACH, errno.EHOSTUNREACH, 10051, 10065):
            return 'SSH_NETWORK_UNREACHABLE'
        if number in (errno.ETIMEDOUT, 10060):
            return 'SSH_CONNECT_TIMEOUT'
        if number in (errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE, 10053, 10054):
            return 'SSH_TRANSPORT_CLOSED'
    if isinstance(error, paramiko.SSHException):
        return 'SSH_PROTOCOL_FAILED'
    return 'SSH_CONNECTION_FAILED'


class SSH:
    def __init__(self, host, confirm_key, cancelled=None, *, confirm_changed_key=None):
        import paramiko
        host.validate()
        self.host = host
        self.cancelled = cancelled or threading.Event()
        self.client = None
        try:
            key_home = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'StreamsAIORecovery'
            key_home.mkdir(parents=True, exist_ok=True)
            self.known_hosts = key_home / 'known_hosts'
        except Exception:
            raise Failure('SSH_HOST_KEY_STORE_FAILED') from None
        peer = ssh_identity.endpoint(host.address, host.port)
        approved = []
        class VerifiedHostPolicy(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, client, hostname, key):
                require(not self_cancelled.is_set(), 'INTERRUPTED')
                require(confirm_key(hostname, ssh_identity.fingerprint(key)), 'SSH_HOST_KEY_NOT_APPROVED')
                require(not self_cancelled.is_set(), 'INTERRUPTED')
                client.get_host_keys().add(hostname, key.get_name(), key)
                approved.append(key)
        self_cancelled = self.cancelled
        def make_client(replacement=None):
            try:
                keys = ssh_identity.trusted_keys(self.known_hosts, peer)
            except Exception:
                raise Failure('SSH_HOST_KEY_STORE_FAILED') from None
            if replacement is not None:
                keys = ssh_identity.without_peer(keys, peer)
                keys.add(peer, replacement.get_name(), replacement)
            client = paramiko.SSHClient()
            try:
                for label in keys.keys():
                    for kind, key in keys[label].items():
                        client.get_host_keys().add(label, kind, key)
                client.set_missing_host_key_policy(VerifiedHostPolicy())
            except Exception:
                try:
                    client.close()
                except Exception:
                    pass
                raise
            return client
        def connect():
            require(not self.cancelled.is_set(), 'INTERRUPTED')
            self.client.connect(host.address, port=host.port, username=host.user,
                                password=host.password or None, key_filename=host.key_file or None,
                                passphrase=host.key_password or None, look_for_keys=False, allow_agent=False,
                                timeout=15, auth_timeout=20, banner_timeout=20)
        try:
            self.client = make_client()
            try:
                connect()
            except paramiko.BadHostKeyException as changed:
                self.client.close()
                require(not self.cancelled.is_set(), 'INTERRUPTED')
                require(confirm_changed_key is not None and changed.hostname == host.address,
                        'SSH_HOST_KEY_CHANGED')
                require(confirm_changed_key(peer, ssh_identity.fingerprint(changed.expected_key),
                                            ssh_identity.fingerprint(changed.key)), 'SSH_HOST_KEY_NOT_APPROVED')
                require(not self.cancelled.is_set(), 'INTERRUPTED')
                # One reconnect, pinned to the exact newly verified key. A
                # second identity change is refused before authentication.
                self.client = make_client(changed.key)
                connect()
                approved.append(changed.key)
            try:
                transport = self.client.get_transport()
                require(transport is not None and transport.is_active(), 'SSH_TRANSPORT_CLOSED')
                require(transport.is_authenticated(), 'SSH_AUTH_FAILED')
                transport.set_keepalive(15)
            except (EOFError, OSError, paramiko.SSHException):
                raise Failure('SSH_TRANSPORT_CLOSED') from None
            if approved:
                try:
                    ssh_identity.remember(self.known_hosts, peer, approved[-1])
                except Exception:
                    raise Failure('SSH_HOST_KEY_STORE_FAILED') from None
        except paramiko.BadHostKeyException:
            self.close()
            raise Failure('SSH_HOST_KEY_CHANGED') from None
        except paramiko.PasswordRequiredException:
            self.close()
            raise Failure('SSH_KEY_PASSPHRASE_REQUIRED') from None
        except paramiko.AuthenticationException:
            self.close()
            raise Failure('SSH_AUTH_FAILED') from None
        except Failure:
            self.close()
            raise
        except Exception as error:
            self.close()
            raise Failure(_ssh_connection_code(error, host, paramiko)) from None

    def close(self):
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                # Cleanup must not replace a closed diagnostic with a raw
                # transport exception or prevent the other VM being closed.
                pass

    def configure_host_dns(self, server):
        server = dns_server_address(server)
        if not server:
            return
        try:
            raw = self.run(['python3', '-B', '-', '--server', server], sudo=True,
                           input=(resources() / 'host_dns.py').read_bytes(), timeout=90)
            result = json.loads(raw)
            require(result.get('schema') == 1 and result.get('status') == 'PASS'
                    and result.get('server') == server, 'HOST_DNS_CONFIGURATION_FAILED')
        except Failure as error:
            if str(error) in ('HOST_DNS_CONFIGURATION_REFUSED', 'HOST_DNS_CONFIGURATION_FAILED'):
                raise
            raise Failure('HOST_DNS_CONFIGURATION_FAILED') from None
        except Exception:
            raise Failure('HOST_DNS_CONFIGURATION_FAILED') from None

    def run(self, args, *, sudo=False, callback=None, timeout=1800, input=None):
        require(not self.cancelled.is_set(), 'INTERRUPTED')
        text = shlex.join([str(x) for x in args])
        if sudo:
            text = "sudo -S -p '' -- " + text
        stdin, stdout, stderr = self.client.exec_command(text, get_pty=False)
        channel = stdout.channel
        if sudo:
            stdin.write((self.host.sudo_password or self.host.password) + '\n')
        if input is not None:
            stdin.write(input)
        stdin.flush()
        channel.shutdown_write()
        collected, pending, deadline = bytearray(), bytearray(), time.monotonic() + timeout
        failure = None
        while True:
            if self.cancelled.is_set() or time.monotonic() > deadline:
                channel.close()
                raise Failure('INTERRUPTED' if self.cancelled.is_set() else 'REMOTE_COMMAND_TIMEOUT')
            if channel.recv_ready():
                data = channel.recv(32768)
                if callback:
                    pending.extend(data)
                    # Arbitrary apt/Docker/stderr output never enters GUI logs.
                    while b'\n' in pending:
                        raw, _, pending = pending.partition(b'\n')
                        item = parse_event(raw.decode('utf-8', 'replace').strip())
                        if item:
                            if item['stage'] == 'REFUSED' and item.get('code') and failure is None:
                                failure = item['code']
                            callback(item)
                    if len(pending) > 65536:
                        pending.clear()
                else:
                    collected.extend(data)
                    require(len(collected) <= 1024**2, 'REMOTE_METADATA_TOO_LARGE')
            if channel.recv_stderr_ready():
                channel.recv_stderr(32768)  # Drain, never persist or display.
            # OpenSSH may report exit status while child pipe data is still
            # pending. Wait for EOF/close before treating empty buffers as final.
            if (channel.exit_status_ready() and (channel.eof_received or channel.closed)
                    and not channel.recv_ready() and not channel.recv_stderr_ready()):
                break
            time.sleep(0.04)
        status = channel.recv_exit_status()
        # A final complete event can arrive without a trailing newline. Apply
        # the same closed schema as streaming lines; never log the raw buffer.
        if callback and pending:
            item = parse_event(pending.decode('utf-8', 'replace').strip())
            if item:
                if item['stage'] == 'REFUSED' and item.get('code') and failure is None:
                    failure = item['code']
                callback(item)
        if status != 0:
            code = failure or remote_failure_code(bytes(collected))
            if code == 'REMOTE_OPERATION_FAILED':
                # -1 means no numeric exit status was supplied (also possible
                # for exit-signal). 137/143 are values, not proof of OOM/killing.
                code = {-1: 'SSH_CHANNEL_CLOSED', 137: 'REMOTE_EXIT_137',
                        143: 'REMOTE_EXIT_143'}.get(status, code)
            raise Failure(code)
        return bytes(collected)

    def check(self, fresh=True, role='stack', lab_point=None):
        require(role in ('stack', 'infisical'), 'INVALID_RECOVERY_ROLE')
        if lab_point is not None:
            require(isinstance(lab_point, tuple) and len(lab_point) == 2
                    and isinstance(lab_point[0], str) and TAG.fullmatch(lab_point[0])
                    and isinstance(lab_point[1], str) and SHA.fullmatch(lab_point[1]),
                    'LAB_RUNTIME_SCOPE_REFUSED')
        home = self.run(['sh', '-c', 'printf %s "$HOME"']).decode()
        require(bool(re.fullmatch(r'/[A-Za-z0-9/_-]+', home)), 'UNSUPPORTED_REMOTE_HOME')
        source = (resources() / 'probe.py').read_text(encoding='utf-8')
        area = self.area(home, role)
        target = '/opt/infisical' if role == 'infisical' else home + '/streams-aio'
        args = ['python3', '-c', source, '--target', target, '--runner', area, '--role', role]
        if fresh:
            args.append('--fresh')
        if lab_point is not None:
            args.extend(['--lab-tag', lab_point[0], '--lab-commit', lab_point[1]])
        info = json.loads(self.run(args, sudo=True, timeout=40))
        require(info.get('user') == self.host.user and info.get('home') == home, 'DEPLOYMENT_USER_MISMATCH')
        return info

    @staticmethod
    def area(home, role):
        return home + '/.local/share/streams-aio-' + ('infisical-recovery' if role == 'infisical' else 'recovery')

    def upload(self, request):
        validate_remote_shell_scripts()
        laboratory = request.get('lab_preparation', False)
        require(type(laboratory) is bool, 'LAB_RUNTIME_SCOPE_REFUSED')
        if laboratory:
            require(request.get('aio_mode') == 'snapshot' and request.get('native_agent') is True
                    and request.get('operational_profile') is not True,
                    'LAB_RUNTIME_SCOPE_REFUSED')
            require(request.get('onboarding_lab', False) is (request.get('role', 'stack') == 'stack'),
                    'LAB_RUNTIME_SCOPE_REFUSED')
        else:
            require(request.get('onboarding_lab', False) is False, 'LAB_RUNTIME_SCOPE_REFUSED')
        identity_mode = request.get('age_identity_mode', 'file')
        require(identity_mode in ('file', 'paste'), 'AGE_IDENTITY_FILE_INVALID')
        pasted_identity = None
        if identity_mode == 'paste':
            try:
                pasted_identity = validate_pasted_identity(request.get('age_identity_text', ''))
            except AgeInputFailure as error:
                raise Failure(str(error)) from None
        role = request.get('role', 'stack')
        if laboratory:
            home = self.check(role=role, lab_point=(request.get('dr_tag'), request.get('public_commit')))['home']
        else:
            home = (self.check(role=role) if role != 'stack' else self.check())['home']
        area = self.area(home, role)
        remote = area + '/upload-' + uuid.uuid4().hex
        # The installer already requires sudo. Create only this new staging
        # directory with explicit ownership, even if the user's shell cannot mkdir.
        self.run(['python3', '-B', '-c', UPLOAD_SETUP, area, remote], sudo=True, timeout=40)
        sftp = self.client.open_sftp()
        try:
            sftp.chmod(area, 0o700)
            sftp.mkdir(remote + '/remote', mode=0o700)
            for name in ('bootstrap.sh', 'recover.py', 'probe.py', 'requirements-dr.txt', 'requirements-new-vm.txt', 'start.py',
                         'infisical_server.py', 'infisical_inventory.py', 'infisical-deployment.json', 'native_agent.py', 'runtime_profile.py',
                         'aio_snapshot.py', 'local_config.py', 'operational_profile.py', 'npm_runtime.py', 'npm_topology.py', 'npm-domain-probe.mjs',
                         'npm-route-probe.mjs', 'tailscale_recovery.py', 'headplane_recovery.py', 'local_endpoints.py'):
                self._put(sftp, resources() / name, remote + '/remote/' + name)
            config = {key: request[key] for key in ('github_token', 'public_commit', 'dr_tag',
                      'infisical_address', 'project_id', 'environment')}
            config.update(role=role, ssh_bridge=request.get('ssh_bridge') is True)
            if laboratory and role == 'stack':
                config['onboarding_lab'] = True
            require(type(request.get('native_agent',True)) is bool, 'INVALID_RECOVERY_REQUEST')
            config['native_agent'] = request.get('native_agent',True)
            if request.get('operational_profile') is True:
                config.update(operational_profile=True, routing_mode=request.get('routing_mode'),
                              domain_target_address=request.get('domain_target_address'),
                              npm_upstream_targets=request.get('npm_upstream_targets'))
            mode = request.get('aio_mode', 'import')
            require(mode in ('import', 'manual', 'snapshot'), 'INVALID_AIO_RECOVERY_MODE')
            config['aio_mode'] = mode
            if pasted_identity is not None:
                destination = remote + '/age_identity'
                self._put_private_bytes(sftp, pasted_identity, destination)
                config['age_identity'] = destination
            for name in ('age_identity', 'client_id_file', 'client_secret_file', 'aio_payload', 'supplemental_inputs'):
                if name == 'age_identity' and identity_mode == 'paste':
                    continue
                if (request.get(name) and not (mode in ('manual', 'snapshot') and name == 'aio_payload')
                        and not (role == 'infisical' and name == 'supplemental_inputs')):
                    destination = remote + '/' + name
                    self._put(sftp, Path(request[name]), destination)
                    config[name] = destination
            for name in ('aiostreams_exports', 'aiometadata_exports'):
                config[name] = []
                for index, file in enumerate(request.get(name, []) if mode == 'import' else []):
                    destination = remote + '/' + name + '-' + str(index) + '.json'
                    self._put(sftp, Path(file), destination)
                    config[name].append(destination)
            # Token and bootstrap choices travel on stdin, never in an SFTP
            # request file or command arguments. File inputs remain private.
            return remote, json.dumps(config).encode() + b'\n'
        finally:
            sftp.close()

    @staticmethod
    def _put_private_bytes(sftp, raw, destination):
        """Create an empty exclusive file, harden it, then write only via SFTP."""
        require(isinstance(raw, bytes) and 0 < len(raw) <= 65536, 'AGE_IDENTITY_FILE_INVALID')
        try:
            # The parent is the fresh authenticated user's 0700 upload area.
            # 'x' sets SSH_FXF_EXCL; 'w' supplies the writable create handle.
            with sftp.open(destination, 'wx') as writer:
                writer.chmod(0o600)
                info = writer.stat()
                require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                        and info.st_size == 0, 'SSH_UPLOAD_FAILED')
                writer.write(raw)
                writer.flush()
            with sftp.open(destination, 'rb') as reader:
                info = reader.stat()
                require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
                        'SSH_UPLOAD_FAILED')
                require(info.st_size == len(raw), 'SSH_UPLOAD_SHA256_MISMATCH')
                copied = reader.read(len(raw) + 1)
            require(isinstance(copied, bytes) and len(copied) == len(raw)
                    and hashlib.sha256(copied).digest() == hashlib.sha256(raw).digest(),
                    'SSH_UPLOAD_SHA256_MISMATCH')
        except Failure:
            raise
        except Exception:
            raise Failure('SSH_UPLOAD_FAILED') from None

    @staticmethod
    def _put(sftp, source, destination):
        require(source.is_file() and not source.is_symlink(), 'UPLOAD_SOURCE_FILE_REQUIRED')
        require(source.stat().st_size <= 128 * 1024**2, 'UPLOAD_SOURCE_TOO_LARGE')
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        sftp.put(str(source), destination, confirm=True)
        sftp.chmod(destination, 0o600)
        # Read back bytes over the authenticated connection. Values never leave
        # the application or enter a report, including age identities.
        h = hashlib.sha256()
        with sftp.open(destination, 'rb') as remote:
            for block in iter(lambda: remote.read(1024 * 1024), b''):
                h.update(block)
        require(h.hexdigest() == before, 'SSH_UPLOAD_SHA256_MISMATCH')

    def prepare(self, request, callback):
        stage = 'INFISICAL_TRANSFER' if request.get('role') == 'infisical' else 'STACK_TRANSFER'
        callback(dict(stage=stage,status='RUNNING'))
        try:
            remote, raw = self.upload(request)
        except Failure:
            raise
        except Exception:
            raise Failure('SSH_UPLOAD_FAILED') from None
        callback(dict(stage=stage,status='PASS'))
        args = ['bash', remote + '/remote/bootstrap.sh', self.host.user]
        if request.get('role') == 'infisical':
            args.append('infisical')
        self.run(args,
                 sudo=True, callback=callback, timeout=7200, input=b'STREAMS_INPUT_V1\n' + raw)

    def test_reset(self, mode, role, request, info, ticket=None):
        require(mode in ('inspect', 'reset') and role in ('stack', 'infisical'), 'TEST_RESET_SCOPE_REFUSED')
        payload = dict(tag=request['dr_tag'], commit=request['public_commit'], machine_id=info['machine_id'])
        if mode == 'reset':
            payload['ticket'] = ticket
        source = (resources()/'test_reset.py').read_text(encoding='utf-8')
        raw = self.run(['python3', '-B', '-c', source, '--role', role, '--mode', mode],
                       sudo=True, timeout=180 if mode == 'inspect' else 7200,
                       input=b'STREAMS_TEST_RESET_V1\n' + json.dumps(payload).encode() + b'\n')
        try:
            result = json.loads(raw)
            require(isinstance(result, dict) and result.get('role') == role, 'TEST_RESET_METADATA_REFUSED')
            if mode == 'inspect':
                require(set(result) == {'role', 'machine_id', 'containers', 'volumes', 'ticket', 'status'}
                        and result['machine_id'] == info['machine_id']
                        and result['status'] in ('READY', 'EMPTY')
                        and isinstance(result['ticket'], str) and re.fullmatch(r'[0-9a-f]{64}', result['ticket'])
                        and all(type(result[key]) is int and result[key] >= 0 for key in ('containers', 'volumes')),
                        'TEST_RESET_METADATA_REFUSED')
            else:
                require(set(result) == {'role', 'status', 'archive'} and result['status'] == 'RESET'
                        and (result['archive'] is None or isinstance(result['archive'], str)
                               and re.fullmatch(r'/var/lib/streams-aio-test-reset/'+role+r'/[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}', result['archive'])),
                        'TEST_RESET_METADATA_REFUSED')
            return result
        except (ValueError, KeyError, TypeError, UnicodeError):
            raise Failure('TEST_RESET_METADATA_REFUSED') from None

    def restored_port(self):
        home = self.check(role='infisical')['home']
        path = self.area(home, 'infisical') + '/state.json'
        source = ('import json,sys; from pathlib import Path; s=json.loads(Path(sys.argv[1]).read_bytes()); '
                  'assert s.get("server_restore")=="PASS_NEEDS_SECRET_READ_TEST"; '
                  'assert "INFISICAL_SERVER" in s["completed"]; print(json.dumps({"port":s["api_port"]}))')
        result = json.loads(self.run(['python3','-c',source,path], sudo=True, timeout=30))
        port = result.get('port')
        require(type(port) is int and 1 <= port <= 65535, 'INFISICAL_API_PORT_REQUIRES_REVIEW')
        return port

    def native(self, action, home, target, callback=None, metadata=None):
        role='infisical' if target=='/opt/infisical' else 'stack'
        area=self.area(home,role)
        sftp=self.client.open_sftp()
        try:
            for name in ('native_agent.py','recover.py','local_config.py','runtime_profile.py','aio_snapshot.py','operational_profile.py','npm_runtime.py','npm_topology.py','npm-domain-probe.mjs','npm-route-probe.mjs','tailscale_recovery.py', 'headplane_recovery.py', 'local_endpoints.py'):
                self._put(sftp,resources()/name,area+'/'+name)
        finally:
            sftp.close()
        raw=b'STREAMS_NATIVE_V1\n'+json.dumps(metadata).encode()+b'\n' if metadata is not None else None
        return self.run([area+'/venv/bin/python','-B',area+'/native_agent.py',action,
                         '--target',target,'--state-home',area],sudo=True,callback=callback,
                        timeout=1800,input=raw)

    def start(self, tls, callback, *, operational=False, cutover=False, routing_mode=None, domain_target_address=None):
        home = self.run(['sh', '-c', 'printf %s "$HOME"']).decode()
        require(bool(re.fullmatch(r'/[A-Za-z0-9/_-]+', home)), 'UNSUPPORTED_REMOTE_HOME')
        area = home + '/.local/share/streams-aio-recovery'
        sftp = self.client.open_sftp()
        try:
            for name in ('start.py','recover.py','local_config.py','runtime_profile.py','aio_snapshot.py','operational_profile.py','npm_runtime.py','npm_topology.py','npm-domain-probe.mjs','npm-route-probe.mjs','tailscale_recovery.py', 'headplane_recovery.py', 'local_endpoints.py'):
                self._put(sftp, resources() / name, area + '/' + name)
        finally:
            sftp.close()
        args = [area + '/venv/bin/python', '-B', area + '/start.py', '--target', home + '/streams-aio',
                '--state-home', area]
        if tls:
            args.append('--tls')
        if operational:
            args.append('--operational')
            require(routing_mode in ('parallel_test', 'production_recovery'), 'OPERATIONAL_DEPLOYMENT_REFUSED')
            args += ['--routing-mode', routing_mode, '--domain-target-address', domain_target_address or '']
            if cutover:
                args.append('--cutover')
        self.run(args, sudo=True, callback=callback, timeout=7200)

class APIBridge:
    """Stack loopback -> encrypted SSH -> desktop -> encrypted SSH -> Infisical.

    No desktop listener, LAN HTTP socket or API value is persisted or logged.
    Closing the context also closes every in-flight forwarded channel.
    """
    def __init__(self, stack, server, port):
        require(type(port) is int and 1 <= port <= 65535, 'INFISICAL_API_PORT_REQUIRES_REVIEW')
        self.stack, self.server, self.port = stack, server, port
        self.closed = threading.Event()
        self.channels, self.lock = [], threading.Lock()

    def __enter__(self):
        try:
            self.listen_port = self.stack.client.get_transport().request_port_forward(
                '127.0.0.1', 0, handler=self.accept)
            require(type(self.listen_port) is int and 1 <= self.listen_port <= 65535,
                    'SSH_API_FORWARDING_REQUIRED')
        except Failure:
            raise
        except Exception:
            raise Failure('SSH_API_FORWARDING_REQUIRED') from None
        return 'http://127.0.0.1:' + str(self.listen_port)

    def accept(self, incoming, origin, destination):
        def connect():
            outgoing = None
            try:
                if self.closed.is_set() or self.stack.cancelled.is_set():
                    return
                outgoing = self.server.client.get_transport().open_channel(
                    'direct-tcpip', ('127.0.0.1', self.port), ('127.0.0.1', 0), timeout=15)
                with self.lock:
                    if self.closed.is_set():
                        return
                    self.channels.extend((incoming, outgoing))
                workers = [threading.Thread(target=self.relay, args=pair, daemon=True)
                           for pair in ((incoming, outgoing),(outgoing, incoming))]
                for worker in workers:
                    worker.start()
                for worker in workers:
                    worker.join()
            except Exception:
                pass  # SDK reports a fixed failure, never tunnel bytes or errors.
            finally:
                incoming.close()
                if outgoing is not None:
                    outgoing.close()
                with self.lock:
                    for channel in (incoming, outgoing):
                        if channel in self.channels:
                            self.channels.remove(channel)
        threading.Thread(target=connect, daemon=True).start()

    def relay(self, source, destination):
        source.settimeout(0.5)
        try:
            while not self.closed.is_set() and not self.stack.cancelled.is_set():
                try:
                    data = source.recv(32768)
                except socket.timeout:
                    continue
                if not data:
                    return
                destination.sendall(data)
        except Exception:
            pass
        finally:
            source.close()
            destination.close()

    def __exit__(self, *exc):
        self.closed.set()
        try:
            self.stack.client.get_transport().cancel_port_forward('127.0.0.1', self.listen_port)
        finally:
            with self.lock:
                for channel in self.channels:
                    channel.close()


def check_first_boot_resume(info):
    """Stop a known legacy startup conflict before restoring either host."""
    phases = info.get('recovery')
    if info.get('existing_recovery') and isinstance(phases, dict):
        require(phases.get('runtime_profile_recorded') is True
                or phases.get('application_start_attempted') is False,
                'RUNTIME_PROFILE_PRESTART_CHECKPOINT_REQUIRED')


def authenticated_upstream_targets(stack, server):
    """NPM's LAN upstreams use the two authenticated SSH destinations.

    The public domain destination is a separate routing intention. It cannot
    replace the concrete stack/Infisical addresses in the recovered database.
    """
    import ipaddress
    targets = {}
    try:
        for role, connection in (('stack',stack),('infisical',server)):
            peer = connection.client.get_transport().getpeername()
            require(isinstance(peer,(tuple,list)) and len(peer) >= 2
                    and isinstance(peer[0],str), 'NPM_TOPOLOGY_TARGET_INVALID')
            address = ipaddress.ip_address(peer[0])
            require(str(address) == peer[0] and not address.is_unspecified
                    and not address.is_loopback and not address.is_multicast,
                    'NPM_TOPOLOGY_TARGET_INVALID')
            targets[role] = str(address)
    except (ValueError,TypeError,AttributeError,OSError):
        raise Failure('NPM_TOPOLOGY_TARGET_INVALID') from None
    require(targets['stack'] != targets['infisical'], 'NPM_TOPOLOGY_TARGET_INVALID')
    return targets


def validate_test_reset_choice(request, tls=False):
    """The destructive test operation has no configurable production scope."""
    require(request.get('host') == '192.168.178.29' and request.get('user') == 'test'
            and str(request.get('port', '22')) == '22'
            and request.get('infisical_host') == '192.168.178.30' and request.get('infisical_user') == 'test2'
            and str(request.get('infisical_port', '22')) == '22'
            and request.get('dr_tag') == 'dr-20261006T210601Z'
            and request.get('public_commit') == '28f6ca7cc6f5fd10418fc0af2926815927ef98c8'
            and request.get('aio_mode') == 'manual' and tls is False,
            'TEST_RESET_SCOPE_REFUSED')


def inspect_test_reset(stack, server, request, tls=False):
    validate_test_reset_choice(request, tls)
    first, second = stack.check(fresh=False), server.check(fresh=False, role='infisical')
    require(first.get('machine_id') and first['machine_id'] != second.get('machine_id'),
            'SEPARATE_RECOVERY_VMS_REQUIRED')
    plans = (stack.test_reset('inspect', 'stack', request, first),
             server.test_reset('inspect', 'infisical', request, second))
    return (first, second), plans


def test_reset_recovery_point(request):
    github = GitHub(request['github_token'])
    tags, latest_commit = github.choices()
    require(request['dr_tag'] in tags, 'PUBLISHED_RELEASE_REQUIRED')
    require(github.get(f'repos/{PUBLIC}/commits/'+request['public_commit']).get('sha') == request['public_commit'],
            'PUBLIC_COMMIT_UNAVAILABLE')
    return tags, latest_commit


def restart_test_hosts(stack, server, request, callback, tls=False):
    validate_test_reset_choice(request, tls)
    test_reset_recovery_point(request)
    infos, plans = inspect_test_reset(stack, server, request, tls)
    request['test_reset_archives'] = []
    for client, role, info, plan in zip((stack, server), ('stack', 'infisical'), infos, plans):
        stage = 'TEST_RESET_' + role.upper()
        callback(dict(stage=stage, status='RUNNING'))
        result = client.test_reset('reset', role, request, info, plan['ticket'])
        if result['archive'] is not None:
            request['test_reset_archives'].append((role, result['archive']))
        callback(dict(stage=stage, status='PASS'))
    # A retry of the subsequent restore must resume its new checkpoint.
    request['restart_test'] = False


def restore_all(stack, server, request, callback, tls=False):
    """Preflight both hosts before any upload/install; restore Infisical first."""
    validate_remote_shell_scripts()
    dns_server = dns_server_address(request.get('dns_server'))
    operational = request.get('operational_profile') is True
    if operational:
        import ipaddress
        require(request.get('recovery_action') in ('fresh', 'resume')
                and request.get('aio_mode') == 'snapshot' and request.get('native_agent') is True
                and request.get('restart_test') is not True and tls is True, 'OPERATIONAL_DEPLOYMENT_REFUSED')
        require(request.get('routing_mode') in ('parallel_test', 'production_recovery'), 'OPERATIONAL_DEPLOYMENT_REFUSED')
        try:
            address = ipaddress.ip_address(request.get('domain_target_address'))
        except (TypeError, ValueError):
            raise Failure('PUBLIC_DOMAIN_CONFIGURATION_REQUIRED') from None
        require(str(address) == request['domain_target_address'] and not address.is_unspecified
                and not address.is_multicast, 'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')
        point = GitHub(request['github_token']).point(request['dr_tag'])
        require(point['aio_snapshot'], 'AIO_SNAPSHOT_BACKUP_REQUIRED')
        require(point['public_commit'] == request['public_commit'], 'DR_STACK_COMMIT_MISMATCH')
        detected = inspect_recovery(stack, server, request)
    require(not request.get('native_agent', True) or not any(request.get(name) for name in
            ('project_id', 'environment', 'client_id_file', 'client_secret_file')),
            'NATIVE_AGENT_REQUIRES_RECOVERED_SCOPE')
    if request.get('restart_test') is True:
        restart_test_hosts(stack, server, request, callback, tls)
    first = detected['stack'] if operational else stack.check()
    check_first_boot_resume(first)
    second = detected['infisical'] if operational else server.check(role='infisical')
    require(first.get('machine_id') and first['machine_id'] != second.get('machine_id'),
            'SEPARATE_RECOVERY_VMS_REQUIRED')
    if operational:
        request = dict(request,npm_upstream_targets=authenticated_upstream_targets(stack,server))
    if dns_server:
        # Both destinations and recovery scopes have passed inspection first.
        for client, stage in ((server, 'HOST_DNS_INFISICAL'), (stack, 'HOST_DNS_STACK')):
            callback(dict(stage=stage, status='RUNNING'))
            client.configure_host_dns(dns_server)
            callback(dict(stage=stage, status='PASS'))
    server.prepare(dict(request, role='infisical', aiostreams_exports=[],
                        aiometadata_exports=[], aio_payload='', supplemental_inputs=''), callback)
    with APIBridge(stack, server, server.restored_port()) as address:
        stack.prepare(dict(request, role='stack', infisical_address=address, ssh_bridge=True), callback)
    if request.get('native_agent',True):
        callback(dict(stage='NATIVE_AGENT',status='RUNNING'))
        public=json.loads(stack.native('key',first['home'],first['home']+'/streams-aio'))['public_key']
        server.native('authorize',second['home'],'/opt/infisical',callback=callback,
                      metadata={'public_key':public})
        host_key=server.client.get_transport().get_remote_server_key()
        stack.native('install',first['home'],first['home']+'/streams-aio',callback=callback,
                     metadata={'host':server.host.address,'port':server.host.port,'api_port':server.restored_port(),
                               'host_key':host_key.get_name()+' '+host_key.get_base64()})
    if operational:
        stack.start(tls, callback, operational=True,
                    cutover=request['routing_mode'] == 'production_recovery',
                    routing_mode=request['routing_mode'], domain_target_address=request['domain_target_address'])
        callback(dict(stage='OPERATIONAL_READY', status='PASS'))
    else:
        stack.start(tls, callback)

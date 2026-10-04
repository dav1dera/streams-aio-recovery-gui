"""Desktop transport. Credentials stay in memory; reports contain fixed codes only."""
import base64
from dataclasses import dataclass, field
import hashlib
import io
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
from .codes import ERROR_CODES

PUBLIC = 'dav1dera/streams-aio-sanitized'
PRIVATE = 'dav1dera/streams-aio-dr'
STAGES = {'DEPENDENCIES', 'CLONES', 'DOWNLOAD', 'DECRYPT', 'INITIALIZE', 'INPUTS',
          'RENDER', 'EMPTY_STATE', 'NPM', 'AIO', 'PREFLIGHT', 'PREPARED', 'STARTED', 'REFUSED', 'TLS'}
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


def resources():
    return Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parents[1])) / 'remote'


def parse_event(line):
    if not line.startswith('RECOVERY_EVENT '):
        return None
    try:
        item = json.loads(line[len('RECOVERY_EVENT '):])
        require(set(item) <= {'stage', 'status', 'code'} and item.get('stage') in STAGES
                and item.get('status') in ('RUNNING', 'PASS', 'REFUSED')
                and ('code' not in item or item['code'] in ERROR_CODES), 'INVALID_EVENT')
        return item
    except Exception:
        return None


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
                                   'User-Agent': 'streams-aio-recovery-gui/0.1.0', 'X-GitHub-Api-Version': '2022-11-28'})
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
        commit = self.get(f'repos/{PUBLIC}/git/ref/heads/main')['object']['sha']
        require(bool(SHA.fullmatch(commit)), 'INVALID_PUBLIC_COMMIT')
        return sorted(tags, reverse=True), commit


class SSH:
    def __init__(self, host, confirm_key, cancelled=None):
        import paramiko
        host.validate()
        self.host = host
        self.cancelled = cancelled or threading.Event()
        self.client = paramiko.SSHClient()
        key_home = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'StreamsAIORecovery'
        key_home.mkdir(parents=True, exist_ok=True)
        self.known_hosts = key_home / 'known_hosts'
        self.client.load_system_host_keys()
        if self.known_hosts.exists():
            self.client.load_host_keys(str(self.known_hosts))
        known_hosts = self.known_hosts
        class VerifiedHostPolicy(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, client, hostname, key):
                fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
                require(confirm_key(hostname, fingerprint), 'SSH_HOST_KEY_NOT_APPROVED')
                client.get_host_keys().add(hostname, key.get_name(), key)
                client.save_host_keys(str(known_hosts))
        self.client.set_missing_host_key_policy(VerifiedHostPolicy())
        try:
            self.client.connect(host.address, port=host.port, username=host.user,
                                password=host.password or None, key_filename=host.key_file or None,
                                passphrase=host.key_password or None, look_for_keys=False, allow_agent=False,
                                timeout=15, auth_timeout=20, banner_timeout=20)
        except paramiko.BadHostKeyException:
            raise Failure('SSH_HOST_KEY_CHANGED') from None
        except paramiko.AuthenticationException:
            raise Failure('SSH_AUTH_FAILED') from None
        except Failure:
            raise
        except Exception:
            raise Failure('SSH_CONNECTION_FAILED') from None
        self.client.get_transport().set_keepalive(15)

    def close(self):
        self.client.close()

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
                            callback(item)
                    if len(pending) > 65536:
                        pending.clear()
                else:
                    collected.extend(data)
                    require(len(collected) <= 1024**2, 'REMOTE_METADATA_TOO_LARGE')
            if channel.recv_stderr_ready():
                channel.recv_stderr(32768)  # Drain, never persist or display.
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            time.sleep(0.04)
        status = channel.recv_exit_status()
        if status != 0:
            code = 'REMOTE_OPERATION_FAILED'
            if not callback:
                try:
                    item = json.loads(collected)
                    if isinstance(item, dict) and item.get('error') in ERROR_CODES:
                        code = item['error']
                except (ValueError, UnicodeDecodeError):
                    pass
            raise Failure(code)
        return bytes(collected)

    def check(self, fresh=True):
        home = self.run(['sh', '-c', 'printf %s "$HOME"']).decode()
        require(bool(re.fullmatch(r'/[A-Za-z0-9/_-]+', home)), 'UNSUPPORTED_REMOTE_HOME')
        source = (resources() / 'probe.py').read_text(encoding='utf-8')
        args = ['python3', '-c', source, '--target', home + '/streams-aio',
                '--runner', home + '/.local/share/streams-aio-recovery']
        if fresh:
            args.append('--fresh')
        info = json.loads(self.run(args, sudo=True, timeout=40))
        require(info.get('user') == self.host.user and info.get('home') == home, 'DEPLOYMENT_USER_MISMATCH')
        return info

    def upload(self, request):
        home = self.check()['home']
        area = home + '/.local/share/streams-aio-recovery'
        remote = area + '/upload-' + uuid.uuid4().hex
        self.run(['sh', '-c', 'umask 077; mkdir -p -- "$1"; mkdir -- "$2"', '_', area, remote])
        sftp = self.client.open_sftp()
        try:
            sftp.chmod(area, 0o700)
            sftp.mkdir(remote + '/remote', mode=0o700)
            for name in ('bootstrap.sh', 'recover.py', 'probe.py', 'requirements-dr.txt', 'requirements-new-vm.txt', 'start.py'):
                self._put(sftp, resources() / name, remote + '/remote/' + name)
            config = {key: request[key] for key in ('github_token', 'public_commit', 'dr_tag',
                      'infisical_address', 'project_id', 'environment')}
            for name in ('age_identity', 'client_id_file', 'client_secret_file', 'aio_payload'):
                if request.get(name):
                    destination = remote + '/' + name
                    self._put(sftp, Path(request[name]), destination)
                    config[name] = destination
            for name in ('aiostreams_exports', 'aiometadata_exports'):
                config[name] = []
                for index, file in enumerate(request.get(name, [])):
                    destination = remote + '/' + name + '-' + str(index) + '.json'
                    self._put(sftp, Path(file), destination)
                    config[name].append(destination)
            # Token and bootstrap choices travel on stdin, never in an SFTP
            # request file or command arguments. File inputs remain private.
            return remote, json.dumps(config).encode() + b'\n'
        finally:
            sftp.close()

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
        remote, raw = self.upload(request)
        self.run(['bash', remote + '/remote/bootstrap.sh', self.host.user],
                 sudo=True, callback=callback, timeout=7200, input=b'STREAMS_INPUT_V1\n' + raw)

    def start(self, tls, callback):
        home = self.run(['sh', '-c', 'printf %s "$HOME"']).decode()
        require(bool(re.fullmatch(r'/[A-Za-z0-9/_-]+', home)), 'UNSUPPORTED_REMOTE_HOME')
        area = home + '/.local/share/streams-aio-recovery'
        sftp = self.client.open_sftp()
        try:
            self._put(sftp, resources() / 'start.py', area + '/start.py')
        finally:
            sftp.close()
        args = [area + '/venv/bin/python', '-B', area + '/start.py', '--target', home + '/streams-aio',
                '--state-home', area]
        if tls:
            args.append('--tls')
        self.run(args, sudo=True, callback=callback, timeout=7200)

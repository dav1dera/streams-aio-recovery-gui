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
          'RENDER', 'EMPTY_STATE', 'NPM', 'AIO', 'PREFLIGHT', 'PREPARED', 'STARTED', 'REFUSED', 'TLS',
          'INFISICAL_CONFIG', 'INFISICAL_DATABASE', 'INFISICAL_SERVER', 'NATIVE_AGENT'}
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

    def check(self, fresh=True, role='stack'):
        require(role in ('stack', 'infisical'), 'INVALID_RECOVERY_ROLE')
        home = self.run(['sh', '-c', 'printf %s "$HOME"']).decode()
        require(bool(re.fullmatch(r'/[A-Za-z0-9/_-]+', home)), 'UNSUPPORTED_REMOTE_HOME')
        source = (resources() / 'probe.py').read_text(encoding='utf-8')
        area = self.area(home, role)
        target = '/opt/infisical' if role == 'infisical' else home + '/streams-aio'
        args = ['python3', '-c', source, '--target', target, '--runner', area, '--role', role]
        if fresh:
            args.append('--fresh')
        info = json.loads(self.run(args, sudo=True, timeout=40))
        require(info.get('user') == self.host.user and info.get('home') == home, 'DEPLOYMENT_USER_MISMATCH')
        return info

    @staticmethod
    def area(home, role):
        return home + '/.local/share/streams-aio-' + ('infisical-recovery' if role == 'infisical' else 'recovery')

    def upload(self, request):
        role = request.get('role', 'stack')
        home = (self.check(role=role) if role != 'stack' else self.check())['home']
        area = self.area(home, role)
        remote = area + '/upload-' + uuid.uuid4().hex
        self.run(['sh', '-c', 'umask 077; mkdir -p -- "$1"; mkdir -- "$2"', '_', area, remote])
        sftp = self.client.open_sftp()
        try:
            sftp.chmod(area, 0o700)
            sftp.mkdir(remote + '/remote', mode=0o700)
            for name in ('bootstrap.sh', 'recover.py', 'probe.py', 'requirements-dr.txt', 'requirements-new-vm.txt', 'start.py',
                         'infisical_server.py', 'infisical_inventory.py', 'infisical-deployment.json', 'native_agent.py'):
                self._put(sftp, resources() / name, remote + '/remote/' + name)
            config = {key: request[key] for key in ('github_token', 'public_commit', 'dr_tag',
                      'infisical_address', 'project_id', 'environment')}
            config.update(role=role, ssh_bridge=request.get('ssh_bridge') is True)
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
        args = ['bash', remote + '/remote/bootstrap.sh', self.host.user]
        if request.get('role') == 'infisical':
            args.append('infisical')
        self.run(args,
                 sudo=True, callback=callback, timeout=7200, input=b'STREAMS_INPUT_V1\n' + raw)

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
            for name in ('native_agent.py','recover.py'):
                self._put(sftp,resources()/name,area+'/'+name)
        finally:
            sftp.close()
        raw=b'STREAMS_NATIVE_V1\n'+json.dumps(metadata).encode()+b'\n' if metadata is not None else None
        return self.run([area+'/venv/bin/python','-B',area+'/native_agent.py',action,
                         '--target',target,'--state-home',area],sudo=True,callback=callback,
                        timeout=1800,input=raw)

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


def restore_all(stack, server, request, callback, tls=False):
    """Preflight both hosts before any upload/install; restore Infisical first."""
    require(not request.get('native_agent', True) or not any(request.get(name) for name in
            ('project_id', 'environment', 'client_id_file', 'client_secret_file')),
            'NATIVE_AGENT_REQUIRES_RECOVERED_SCOPE')
    first, second = stack.check(), server.check(role='infisical')
    require(first.get('machine_id') and first['machine_id'] != second.get('machine_id'),
            'SEPARATE_RECOVERY_VMS_REQUIRED')
    server.prepare(dict(request, role='infisical', aiostreams_exports=[],
                        aiometadata_exports=[], aio_payload=''), callback)
    with APIBridge(stack, server, server.restored_port()) as address:
        stack.prepare(dict(request, role='stack', infisical_address=address, ssh_bridge=True), callback)
    if request.get('native_agent',True):
        public=json.loads(stack.native('key',first['home'],first['home']+'/streams-aio'))['public_key']
        server.native('authorize',second['home'],'/opt/infisical',callback=callback,
                      metadata={'public_key':public})
        host_key=server.client.get_transport().get_remote_server_key()
        stack.native('install',first['home'],first['home']+'/streams-aio',callback=callback,
                     metadata={'host':server.host.address,'port':server.host.port,'api_port':server.restored_port(),
                               'host_key':host_key.get_name()+' '+host_key.get_base64()})
    stack.start(tls, callback)

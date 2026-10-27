"""Opt-in Linux/root onboarding against real Infisical, Agent and Docker.

The transport adapter replaces only SSH delivery and systemd process ownership:
HTTP calls, universal authentication, Agent template rendering, filesystem writes,
Compose validation/start, health checks and private readback use production code.
No production endpoint, credential, container, service or global prune is used.

Primary bootstrap/API contract pinned to Infisical v0.167.1:
https://github.com/Infisical/infisical/blob/v0.167.1/backend/src/server/routes/v1/admin-router.ts
https://github.com/Infisical/infisical/blob/v0.167.1/backend/src/server/routes/v1/project-router.ts
The native Agent archive and digest are the application's reviewed pin.
"""
from contextlib import suppress
import base64
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener
import uuid
import zlib

import yaml

from recovery_gui.onboarding import ServiceController, OnboardingError, PRIVATE_PROOF, REMOTE_LAUNCHER
from recovery_gui.onboarding_infisical import InfisicalClient, InfisicalFailure
from recovery_gui.onboarding_ssh_api import SSHInfisicalOpener, SSH_HTTP_HELPER, SSH_ORIGIN
from recovery_gui.service_plan import analyze_inputs
from remote import service_onboarding as remote

ROOT = Path(__file__).resolve().parents[1]
ENABLED = os.environ.get('RUN_ONBOARDING_INFISICAL_INTEGRATION') == '1'
SERVER_TAG = 'infisical/infisical:v0.167.1'
APPLICATION_TAG = 'busybox:1.37.0'
# Database major matches both the official deployment and the supported restore profile.
PROFILE = json.loads((ROOT / 'remote/infisical-deployment.json').read_bytes())
MAX_HTTP = 2 * 1024 * 1024


def require(condition, code):
    if not condition:
        raise AssertionError(code)


def invoke(args, code='ONBOARDING_E2E_COMMAND_FAILED', *, cwd=None, payload=None, timeout=300):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('COMPOSE_', 'DOCKER_HOST', 'DOCKER_CONTEXT'))}
    try:
        result = subprocess.run([str(part) for part in args], input=payload,
            stdin=subprocess.DEVNULL if payload is None else None, capture_output=True,
            cwd=cwd, timeout=timeout, env=env)
    except (OSError, subprocess.SubprocessError):
        raise AssertionError(code) from None
    require(result.returncode == 0, code)
    return result.stdout


def private_write(path, raw, mode=0o600, uid=0, gid=0):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(mode)
    os.chown(path, uid, gid)


def free_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.bind(('127.0.0.1', 0))
        return stream.getsockname()[1]


def http_json(origin, method, path, *, body=None, token=None, code='ONBOARDING_E2E_API_FAILED'):
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    data = None if body is None else json.dumps(body).encode()
    try:
        request = Request(origin + path, method=method, data=data, headers=headers)
        with build_opener(ProxyHandler({})).open(request, timeout=30) as response:
            require(200 <= response.status < 300, 'ONBOARDING_E2E_API_STATUS')
            raw = response.read(MAX_HTTP + 1)
        require(len(raw) <= MAX_HTTP, 'ONBOARDING_E2E_API_SIZE')
        value = json.loads(raw)
        require(isinstance(value, dict), 'ONBOARDING_E2E_API_SHAPE')
        return value
    except HTTPError as error:
        status = error.code
        error.close()
        raise AssertionError(code + '_HTTP_' + str(status)) from None
    except (URLError, OSError, ValueError, TypeError):
        # Raw upstream messages, headers and bodies can contain credentials.
        raise AssertionError(code) from None


def pinned_image(tag):
    invoke(['docker', 'pull', tag], 'ONBOARDING_E2E_IMAGE_PULL_FAILED')
    raw = invoke(['docker', 'image', 'inspect', '--format', '{{json .RepoDigests}}', tag])
    values = json.loads(raw)
    repository = remote.image_repository_identity(tag)
    selected = [value for value in values if isinstance(value, str)
                and '@sha256:' in value
                and remote.image_repository_identity(value) == repository]
    require(bool(selected), 'ONBOARDING_E2E_IMAGE_DIGEST_REQUIRED')
    return sorted(selected)[0]


class AgentProcess:
    def __init__(self, binary, config, root, gid, log):
        self.binary, self.config, self.root, self.gid, self.log = binary, config, root, gid, log
        self.process = None
        self.starts = 0

    def stop(self):
        process, self.process = self.process, None
        if process is None:
            return
        if process.poll() is None:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=15)

    def start(self):
        self.stop()
        def group_and_mask():
            os.setgid(self.gid)
            os.umask(0o027)
        cli_home = self.log.parent / 'cli-home'
        cli_home.mkdir(mode=0o700, exist_ok=True)
        if not self.log.exists(): private_write(self.log, b'')
        environment = {key: value for key, value in os.environ.items()
                       if not key.upper().startswith('INFISICAL_')
                       and key.upper() not in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY')}
        environment.update(HOME=str(cli_home), XDG_CONFIG_HOME=str(cli_home / '.config'))
        with self.log.open('ab') as output:
            self.process = subprocess.Popen([str(self.binary), 'agent', '--config', str(self.config)],
                cwd=self.root, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                start_new_session=True, preexec_fn=group_and_mask,
                env=environment)
        self.log.chmod(0o600)
        self.starts += 1

    def active(self):
        return self.process is not None and self.process.poll() is None


class ProcessRunner(remote.Runner):
    """Real Runner, with only the isolated Agent supervisor replacing systemd."""
    def __init__(self, layout, agent):
        super().__init__(layout)
        self.agent = agent

    def command(self, args, user=False):
        command, env = super().command(args, user)
        env = {key: value for key, value in env.items()
               if not key.startswith(('COMPOSE_', 'DOCKER_HOST', 'DOCKER_CONTEXT'))}
        return command, env

    def props(self, unit):
        require(unit == remote.AGENT_UNIT, 'ONBOARDING_E2E_UNEXPECTED_UNIT')
        return dict(LoadState='loaded', ActiveState='active' if self.agent.active() else 'inactive',
            User='', Group=str(self.layout.gid), UMask='0027', KillMode='control-group',
            ExecStart=str(self.agent.binary) + ' agent --config ' + str(self.agent.config),
            ExecStartPre='', ExecStartPost='', ExecStop='', ExecStopPost='')

    def run(self, args, code, timeout=120, user=False, input_data=None):
        arguments = list(map(str, args))
        if code == 'ONBOARDING_PREFLIGHT_COMPOSE_FAILED':
            # Preserve a closed actual-CLI signature for CI debugging. Upstream
            # stdout/stderr may contain file contents and are never emitted.
            command, environment = self.command(args, user)
            try:
                result = subprocess.run(command, cwd=str(self.layout.root), env=environment,
                    stdin=subprocess.DEVNULL if input_data is None else None,
                    input=input_data, capture_output=True, timeout=timeout)
            except (OSError, subprocess.SubprocessError):
                raise remote.Refused('ONBOARDING_E2E_PREFLIGHT_PROCESS_FAILED') from None
            if result.returncode:
                error = result.stderr.lower()
                reason = ('ENV_FILE_MISSING' if b'env file' in error and b'not found' in error else
                          'UNKNOWN_FLAG' if b'unknown flag' in error else
                          'INVALID_INTERPOLATION' if b'invalid interpolation' in error else
                          'OTHER_COMPOSE_ERROR')
                raise remote.Refused('ONBOARDING_E2E_PREFLIGHT_' + reason)
            return result.stdout
        if arguments[:2] == ['systemctl', 'restart']:
            require(arguments == ['systemctl', 'restart', remote.AGENT_UNIT], 'ONBOARDING_E2E_UNEXPECTED_UNIT')
            self.agent.start()
            return b''
        if arguments[:2] == ['systemctl', 'stop']:
            require(arguments == ['systemctl', 'stop', remote.AGENT_UNIT], 'ONBOARDING_E2E_UNEXPECTED_UNIT')
            self.agent.stop()
            return b''
        if arguments[:2] == ['systemctl', 'start']:
            require(arguments == ['systemctl', 'start', remote.AGENT_UNIT], 'ONBOARDING_E2E_UNEXPECTED_UNIT')
            if not self.agent.active(): self.agent.start()
            return b''
        return super().run(args, code, timeout, user, input_data)


class LoopbackSSH:
    """Exercise real fixed HTTP/proof helpers; dispatch the real Engine locally."""
    def __init__(self, layout, runner):
        self.layout, self.runner = layout, runner
        self.actions = []
        self.responses = []

    def run(self, args, **kwargs):
        if args[-1] in (SSH_HTTP_HELPER, PRIVATE_PROOF):
            return invoke(args, 'ONBOARDING_E2E_FIXED_HELPER_FAILED', payload=kwargs.get('input'),
                          timeout=kwargs.get('timeout', 60))
        try:
            self.validate_remote_command(args, self.layout.home)
        except AssertionError as error:
            # Preserve only this fixture's fixed code through controller redaction.
            raise OnboardingError(str(error)) from None
        request = remote.framed_request(kwargs['input'])
        self.actions.append(request['action'])
        result = remote.handle(request, runner=self.runner, store=remote.Store(), layout=self.layout)
        raw = json.dumps(result).encode()
        self.responses.append(raw)
        return raw

    @staticmethod
    def validate_remote_command(args, home):
        # The production launcher now carries two bounded compressed modules.
        # Validate the actual encoded bytes before replacing only SSH delivery.
        interpreter = str(home / '.local/share/streams-aio-recovery/venv/bin/python')
        require(len(args) == 7 and args[:4] == ['python3', '-I', '-c', REMOTE_LAUNCHER]
                and args[4] == interpreter, 'ONBOARDING_E2E_UNEXPECTED_REMOTE_COMMAND')
        for encoded, name in zip(args[5:], ('service_onboarding.py', 'service_tooling.py')):
            require(isinstance(encoded, str) and len(encoded) <= 120 * 1024,
                    'ONBOARDING_E2E_REMOTE_SOURCE_BOUND')
            try:
                decoder = zlib.decompressobj()
                raw = decoder.decompress(base64.b64decode(encoded, validate=True), 512 * 1024 + 1)
                require(len(raw) <= 512 * 1024 and decoder.eof and not decoder.unused_data
                        and not decoder.unconsumed_tail and raw == (ROOT / 'remote' / name).read_bytes(),
                        'ONBOARDING_E2E_UNEXPECTED_REMOTE_SOURCE')
            except (ValueError, zlib.error):
                raise AssertionError('ONBOARDING_E2E_UNEXPECTED_REMOTE_SOURCE') from None

    def close(self):
        pass  # SSH disconnection must not terminate the independently running Agent.


class DropAfterCreate:
    """One real server write followed by an ambiguous transport response."""
    def __init__(self, opener):
        self.opener, self.dropped = opener, False
        self.methods = []

    def open(self, request, timeout=30):
        self.methods.append((request.get_method(), request.full_url.split('?', 1)[0].rsplit('/', 1)[-1]))
        response = self.opener.open(request, timeout)
        if request.get_method() == 'POST' and '/api/v4/secrets/' in request.full_url and not self.dropped:
            self.dropped = True
            response.close()
            raise URLError('synthetic response interruption')
        return response


@unittest.skipUnless(ENABLED, 'Requires RUN_ONBOARDING_INFISICAL_INTEGRATION=1 on an isolated Linux/root runner')
class RealInfisicalOnboarding(unittest.TestCase):
    def test_secret_agent_compose_application_and_durable_resume(self):
        require(sys.platform == 'linux' and os.geteuid() == 0, 'ONBOARDING_E2E_LINUX_ROOT_REQUIRED')
        for command in ('docker', 'curl', 'useradd', 'userdel'):
            require(shutil.which(command) is not None, 'ONBOARDING_E2E_DEPENDENCY_REQUIRED')
        invoke(['docker', 'info', '--format', '{{.ServerVersion}}'], 'ONBOARDING_E2E_DOCKER_REQUIRED')
        invoke(['docker', 'compose', 'version'], 'ONBOARDING_E2E_COMPOSE_REQUIRED')
        suffix = uuid.uuid4().hex[:12]
        username = 'recovery-e2e-' + suffix
        home = Path('/home') / username
        user_created, projects, agent = False, [], None
        with tempfile.TemporaryDirectory(prefix='recovery-infisical-e2e-') as temporary:
            base = Path(temporary).resolve()
            base.chmod(0o700)

            def clear_fixture_acls(path):
                # Hosted runners may install inheritable ACLs on temporary/home
                # parents. Normalize only directories newly owned by this test;
                # production private-ACL checks remain unchanged.
                require(not path.is_symlink() and (path == base or path.is_relative_to(base)
                        or path == home or path.is_relative_to(home)), 'ONBOARDING_E2E_ACL_SCOPE')
                for attribute in remote.ACL_ATTRIBUTES & set(os.listxattr(path)):
                    os.removexattr(path, attribute)
                require(not remote.ACL_ATTRIBUTES & set(os.listxattr(path)), 'ONBOARDING_E2E_ACL_SETUP_FAILED')

            clear_fixture_acls(base)
            try:
                # Fail quickly at the real Compose boundary before downloading
                # or bootstrapping Infisical. Future env files must stay absent.
                probe_root = base / 'compose-probe'
                probe_root.mkdir(mode=0o700)
                probe_layout = remote.Layout(PurePosixPath(probe_root), PurePosixPath(base), 'root', 0, 0)
                probe = {'name': 'recovery-onboarding-probe', 'services': {'probe': {
                    'image': APPLICATION_TAG, 'env_file': ['./future-public.env', './future-private.env']}}}
                ProcessRunner(probe_layout, None).validate_candidate(yaml.safe_dump(probe).encode())
                require(not any(probe_root.iterdir()), 'ONBOARDING_E2E_PREFLIGHT_CREATED_FILES')
                backend_image = pinned_image(SERVER_TAG)
                application_image = pinned_image(APPLICATION_TAG)
                database_image, redis_image = PROFILE['images']['db'], PROFILE['images']['redis']
                for image in (database_image, redis_image):
                    invoke(['docker', 'pull', image], 'ONBOARDING_E2E_IMAGE_PULL_FAILED')
                server_root = base / 'server'
                server_root.mkdir(mode=0o700)
                server_project = 'recovery-infisical-' + suffix
                port = free_loopback_port()
                origin = 'http://127.0.0.1:' + str(port)
                database_password = secrets.token_hex(24)
                server = {'name': server_project, 'services': {
                    'db': {'image': database_image, 'environment': {
                        'POSTGRES_DB': 'infisical', 'POSTGRES_USER': 'infisical',
                        'POSTGRES_PASSWORD': database_password},
                        'volumes': ['database:/var/lib/postgresql/data'],
                        'healthcheck': {'test': ['CMD', 'pg_isready', '-U', 'infisical', '-d', 'infisical'],
                                        'interval': '2s', 'timeout': '3s', 'retries': 60}},
                    'redis': {'image': redis_image, 'command': ['redis-server', '--save', '', '--appendonly', 'no']},
                    'backend': {'image': backend_image, 'ports': ['127.0.0.1:' + str(port) + ':8080'],
                        'depends_on': {'db': {'condition': 'service_healthy'}, 'redis': {'condition': 'service_started'}},
                        'environment': {'NODE_ENV': 'production', 'ENCRYPTION_KEY': secrets.token_hex(16),
                            'AUTH_SECRET': secrets.token_urlsafe(48), 'HTTPS_ENABLED': 'false', 'SITE_URL': origin,
                            'DB_CONNECTION_URI': 'postgres://infisical:' + database_password + '@db:5432/infisical',
                            'REDIS_URL': 'redis://redis:6379', 'TELEMETRY_ENABLED': 'false'}}},
                    'volumes': {'database': {}}}
                private_write(server_root / 'docker-compose.yml', json.dumps(server).encode())
                projects.append((server_root, server_project))
                self.compose(server_root, server_project, 'up', '-d')
                for _ in range(90):
                    try:
                        if isinstance(http_json(origin, 'GET', '/api/v1/admin/config').get('config'), dict): break
                    except AssertionError:
                        pass
                    time.sleep(2)
                else:
                    raise AssertionError('ONBOARDING_E2E_SERVER_START_TIMEOUT')
                bootstrap = http_json(origin, 'POST', '/api/v1/admin/bootstrap', body={
                    'email': 'recovery-' + suffix + '@example.com',
                    'password': secrets.token_urlsafe(32) + '-Aa7!', 'organization': 'Recovery E2E'},
                    code='ONBOARDING_E2E_BOOTSTRAP_FAILED')
                token = bootstrap.get('identity', {}).get('credentials', {}).get('token')
                identity = bootstrap.get('identity', {}).get('id')
                require(isinstance(token, str) and isinstance(identity, str), 'ONBOARDING_E2E_BOOTSTRAP_SHAPE')
                project = http_json(origin, 'POST', '/api/v1/projects', token=token,
                    body={'projectName': 'Recovery E2E ' + suffix, 'slug': 'recovery-e2e-' + suffix,
                          'shouldCreateDefaultEnvs': True}, code='ONBOARDING_E2E_PROJECT_CREATE_FAILED')['project']['id']
                universal = http_json(origin, 'POST', '/api/v1/auth/universal-auth/identities/' + identity,
                    token=token, body={'lockoutEnabled': False}, code='ONBOARDING_E2E_UA_ATTACH_FAILED')['identityUniversalAuth']
                client_id = universal.get('clientId')
                client_secret = http_json(origin, 'POST', '/api/v1/auth/universal-auth/identities/' + identity
                    + '/client-secrets', token=token, body={'description': 'Isolated recovery test'},
                    code='ONBOARDING_E2E_UA_CREDENTIAL_FAILED')['clientSecret']
                require(isinstance(client_id, str) and isinstance(client_secret, str), 'ONBOARDING_E2E_UA_SHAPE')
                invoke(['useradd', '--create-home', '--home-dir', home, '--shell', '/usr/sbin/nologin',
                        '--user-group', username], 'ONBOARDING_E2E_USER_CREATE_FAILED')
                user_created = True
                clear_fixture_acls(home)
                import pwd
                account = pwd.getpwnam(username)
                root = home / 'streams-aio'
                root.mkdir(mode=0o750)
                os.chown(root, account.pw_uid, account.pw_gid)
                (root / 'data').mkdir(mode=0o750)
                os.chown(root / 'data', account.pw_uid, account.pw_gid)
                (root / '.secrets').mkdir(mode=0o750)
                os.chown(root / '.secrets', 0, account.pw_gid)
                clear_fixture_acls(root / '.secrets')
                area = home / '.local/state/streams-aio-onboarding'
                area.mkdir(mode=0o700, parents=True)
                clear_fixture_acls(area)
                marker = dict(schema=1, kind='prepared_onboarding_lab', root=str(root), owner=username,
                    machine_id=Path('/etc/machine-id').read_text().strip(), publications_disabled=True)
                private_write(area / 'lab.json', json.dumps(marker).encode())
                cli_archive = base / 'cli.tar.gz'
                sys.path.insert(0, str(ROOT / 'remote'))
                import native_agent
                invoke(['curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
                        '--proto-redir', '=https', '--max-time', '180', '--output', cli_archive, native_agent.CLI_URL],
                       'ONBOARDING_E2E_CLI_DOWNLOAD_FAILED')
                binary = native_agent.install_cli(cli_archive, library=base / 'cli-library')
                agent_config = base / 'agent-config.yaml'
                private_write(base / 'client-id', client_id.encode())
                private_write(base / 'client-secret', client_secret.encode())
                initial_agent = {'infisical': {'address': origin, 'retry-strategy': {
                    'max-retries': 1, 'base-delay': '1s', 'max-delay': '1s'}},
                    'auth': {'type': 'universal-auth', 'config': {
                    'client-id': str(base / 'client-id'), 'client-secret': str(base / 'client-secret'),
                    'remove_client_secret_on_read': False}}, 'templates': [
                    {'template-content': "EXISTING='ready'\n", 'destination-path': str(root / '.secrets/existing.env')}]}
                private_write(agent_config, yaml.safe_dump(initial_agent).encode(), 0o640, 0, account.pw_gid)
                agent = AgentProcess(binary, agent_config, root, account.pw_gid, base / 'agent.log')
                agent.start()
                self.wait(lambda: (root / '.secrets/existing.env').is_file(), 'ONBOARDING_E2E_INITIAL_AGENT_FAILED')
                layout = remote.Layout(PurePosixPath(root), PurePosixPath(home), username,
                    account.pw_uid, account.pw_gid, PurePosixPath(agent_config))
                runner = ProcessRunner(layout, agent)
                ssh = LoopbackSSH(layout, runner)
                application_project = 'recovery-onboarding-' + suffix
                existing = {'name': application_project, 'services': {'existing': {'image': application_image,
                    'command': ['sh', '-c', 'while :; do sleep 3600; done'], 'network_mode': 'none'}}}
                private_write(root / 'docker-compose.yml', yaml.safe_dump(existing, sort_keys=False).encode(),
                              0o640, account.pw_uid, account.pw_gid)
                projects.append((root, application_project))
                self.compose(root, application_project, 'up', '-d', '--pull', 'never')
                existing_id = self.container(root, application_project, 'existing')
                opener = SSHInfisicalOpener(ssh, origin)
                private_value = 'synthetic-agent-$cash-${UNEXPANDED}-\u00e9-' + secrets.token_hex(8)
                # A real successful POST followed by response loss must be safe to retry.
                interrupted = DropAfterCreate(opener)
                interrupted_api = InfisicalClient(SSH_ORIGIN, project, 'prod', token, opener=interrupted)
                with self.assertRaisesRegex(InfisicalFailure, '^INFISICAL_CONNECTION_FAILED$'):
                    interrupted_api.ensure('retry-fixture', {'API_KEY': private_value})
                retry = interrupted_api.ensure('retry-fixture', {'API_KEY': private_value})
                require(retry['created_keys'] == [] and retry['verified_keys'] == ['API_KEY']
                        and sum(method == 'POST' and key == 'API_KEY' for method, key in interrupted.methods) == 1,
                        'ONBOARDING_E2E_SECRET_RETRY_FAILED')
                # Deliberately make the apparent reference resolvable: the raw
                # private value must still survive Agent/Compose literally, and
                # unrelated folder keys must not enter the generated env file.
                referenced_value = 'unselected-source-' + secrets.token_hex(8)
                InfisicalClient(SSH_ORIGIN, project, 'prod', token, opener=opener).ensure(
                    'fixture', {'UNEXPANDED': referenced_value})
                fixture = self.analysis(application_image, private_value)
                connection = dict(host='192.0.2.10', user=username, port=22, password='synthetic-ssh',
                    stack_root=str(root), ssh_key='', key_password='', sudo_password='', verification_scope='local_lab')
                scope = dict(endpoint=SSH_ORIGIN, project_id=project, environment='prod', access_token=token)
                events = []
                factory = lambda: ServiceController(lambda *_: False,
                    ssh_factory=lambda *_a, **_k: ssh, resource_dir=ROOT / 'remote', sleeper=lambda _: None)
                controller = factory()
                receipt = controller.inspect(fixture, connection, scope, events.append)
                compose_before = (root / 'docker-compose.yml').read_bytes()
                agent_before = agent_config.read_bytes()
                private_write(base / 'client-secret', secrets.token_urlsafe(48).encode())
                try:
                    # The writer token remains valid. Only the installed Agent's
                    # own authentication fails after the GUI's successful preview.
                    with self.assertRaisesRegex(OnboardingError, '^ONBOARDING_AGENT_RENDER_FAILED$'):
                        controller.apply(fixture, connection, scope, receipt, events.append)
                    require((root / 'docker-compose.yml').read_bytes() == compose_before
                            and agent_config.read_bytes() == agent_before,
                            'ONBOARDING_E2E_AGENT_FAILURE_CHANGED_LIVE_CONFIGURATION')
                    require(not any((root / path).exists() for path in (
                        'data/fixture/.env', 'data/fixture/public/index.html',
                        'config/service-resources.json', '.secrets/fixture.env')),
                        'ONBOARDING_E2E_AGENT_FAILURE_LEFT_APPLICATION_FILES')
                    require(self.container(root, application_project, 'existing') == existing_id,
                            'ONBOARDING_E2E_AGENT_FAILURE_CHANGED_EXISTING_CONTAINER')
                    running_services = self.compose(root, application_project, 'ps', '-a',
                                                    '--format', '{{.Service}}').decode().splitlines()
                    require('fixture' not in running_services, 'ONBOARDING_E2E_AGENT_FAILURE_STARTED_APPLICATION')
                finally:
                    private_write(base / 'client-secret', client_secret.encode())
                    existing_output = root / '.secrets/existing.env'
                    previous_render = existing_output.stat().st_mtime_ns
                    agent.start()
                    self.wait(lambda: agent.active() and existing_output.stat().st_mtime_ns != previous_render,
                              'ONBOARDING_E2E_AGENT_RECOVERY_FAILED')
                # Retrying after fixing the Agent must reuse the same real API
                # values, avoid duplicate secrets and create a clean operation.
                failed_job = receipt.job_id
                controller = factory()
                receipt = controller.inspect(fixture, connection, scope, events.append)
                require(not receipt.resume and receipt.job_id != failed_job,
                        'ONBOARDING_E2E_ROLLED_BACK_JOB_BLOCKED_RETRY')
                result = controller.apply(fixture, connection, scope, receipt, events.append)
                require(result.get('status') == 'PASS_LOCAL', 'ONBOARDING_E2E_ADD_FAILED')
                require(self.container(root, application_project, 'existing') == existing_id,
                        'ONBOARDING_E2E_EXISTING_SERVICE_CHANGED')
                fixture_id = self.container(root, application_project, 'fixture')
                observed = invoke(['docker', 'exec', fixture_id, 'sh', '-c', 'printf %s "$API_KEY"'])
                require(hmac.compare_digest(observed, private_value.encode()), 'ONBOARDING_E2E_PRIVATE_ENV_CHANGED')
                require((root / 'data/fixture/public/index.html').read_bytes() == b'public-fixture\n',
                        'ONBOARDING_E2E_PUBLIC_CONFIGURATION_CHANGED')
                require(self.compose(root, application_project, 'exec', '-T', 'fixture', 'cat', '/state/record.bin')
                        == b'created-by-application\n', 'ONBOARDING_E2E_APPLICATION_DATA_MISSING')
                # A new desktop controller must discover and reuse the durable job.
                restarts = agent.starts
                resumed_controller = factory()
                resumed = resumed_controller.inspect(fixture, connection, scope, events.append)
                require(resumed.resume is True and resumed.job_id == receipt.job_id,
                        'ONBOARDING_E2E_DURABLE_RESUME_REQUIRED')
                repeated = resumed_controller.apply(fixture, connection, scope, resumed, events.append)
                require(repeated.get('status') == 'PASS_LOCAL', 'ONBOARDING_E2E_RESUME_FAILED')
                require(self.container(root, application_project, 'fixture') == fixture_id
                        and agent.starts == restarts, 'ONBOARDING_E2E_RESUME_REINSTALLED_SERVICE')
                public_report = json.dumps([result, repeated, events]).encode() + b''.join(ssh.responses)
                require(not any(value.encode() in public_report for value in (private_value, referenced_value, token, client_secret)),
                        'ONBOARDING_E2E_PRIVATE_VALUE_IN_REPORT')
            finally:
                if agent is not None: agent.stop()
                cleanup_failed = False
                for root, project in reversed(projects):
                    try: self.compose(root, project, 'down', '--volumes', '--remove-orphans')
                    except Exception: cleanup_failed = True
                if user_created:
                    try:
                        import pwd
                        require(home.parent == Path('/home') and home.name == username
                                and username.startswith('recovery-e2e-')
                                and pwd.getpwnam(username).pw_dir == str(home), 'ONBOARDING_E2E_CLEANUP_SCOPE')
                        invoke(['userdel', '--remove', username], 'ONBOARDING_E2E_USER_CLEANUP_FAILED')
                    except Exception:
                        cleanup_failed = True
                require(not cleanup_failed, 'ONBOARDING_E2E_CLEANUP_FAILED')

    @staticmethod
    def compose(root, project, *arguments):
        require(project.startswith(('recovery-infisical-', 'recovery-onboarding-')),
                'ONBOARDING_E2E_PROJECT_SCOPE')
        return invoke(['docker', 'compose', '--project-directory', root, '-f', root / 'docker-compose.yml',
                       '-p', project, *arguments], 'ONBOARDING_E2E_COMPOSE_FAILED')

    @classmethod
    def container(cls, root, project, service):
        values = cls.compose(root, project, 'ps', '-a', '-q', '--', service).decode().split()
        require(len(values) == 1, 'ONBOARDING_E2E_CONTAINER_REQUIRED')
        return values[0]

    @staticmethod
    def wait(predicate, code, attempts=90):
        for _ in range(attempts):
            if predicate(): return
            time.sleep(1)
        raise AssertionError(code)

    @staticmethod
    def analysis(image, value):
        document = {'services': {'fixture': {'image': image, 'environment': {'API_KEY': '${API_KEY}'},
            'command': ['sh', '-ec', 'test -n "$$API_KEY"; printf "created-by-application\\n" > /state/record.bin; httpd -f -p 8080 -h /config'],
            'volumes': ['./data/fixture/public:/config:ro', 'fixture-data:/state'],
            'healthcheck': {'test': ['CMD-SHELL', 'test -n "$$API_KEY" && test -s /state/record.bin && wget -q -O - http://127.0.0.1:8080/ | grep -qx public-fixture'],
                            'interval': '1s', 'timeout': '3s', 'retries': 30}}},
            'volumes': {'fixture-data': {}}}
        return analyze_inputs(yaml.safe_dump(document, sort_keys=False), '', service_name='fixture',
            private_names=['API_KEY'], private_values={'API_KEY': value},
            configuration_files=[dict(path='data/fixture/public/index.html', content='public-fixture\n', mode=0o644)],
            storage_policies=[dict(service='fixture', target='/state', method='stopped_archive')])


if __name__ == '__main__':
    unittest.main()
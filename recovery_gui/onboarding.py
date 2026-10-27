"""Service onboarding orchestration. No desktop automation or implicit writes.

Analysis is offline; inspect is read-only. Apply requires the exact in-memory
inspection receipt, creates/verifies secrets, then invokes the bounded remote
transaction. Credentials and secret values never enter its request or journal.
"""
from dataclasses import dataclass, field
import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import uuid
import zlib

from .backend import Failure, Host, SSH, resources
from .onboarding_infisical import InfisicalClient, InfisicalFailure, validate_private_values
from .service_plan import ServiceAnalysis

ONBOARDING_FRAME = b'STREAMS_ONBOARDING_V1\n'
PRIVATE_PROOF_FRAME = b'STREAMS_PRIVATE_PROOF_V1\n'

# Both modules travel compressed so Linux never receives a source-sized argv
# entry. The worker expands bounded trusted sources after its own exec, while
# stdin remains reserved for the request and sudo framing.
MAX_REMOTE_SOURCE = 512 * 1024
MAX_REMOTE_ARGUMENT = 120 * 1024
REMOTE_WORKER = r'''
import base64, json, sys, types, zlib
try:
    import yaml
except Exception:
    print(json.dumps({'schema':1,'status':'REFUSED','code':'ONBOARDING_PYTHON_ENVIRONMENT_REQUIRED'}))
    sys.exit(0)
try:
    assert len(sys.argv) == 3
    def unpack(value):
        assert len(value) <= 120 * 1024
        compressed = base64.b64decode(value, validate=True)
        decoder = zlib.decompressobj()
        source = decoder.decompress(compressed, 512 * 1024 + 1)
        assert len(source) <= 512 * 1024 and decoder.eof
        assert not decoder.unused_data and not decoder.unconsumed_tail
        return source.decode('utf-8')
    source, helper = unpack(sys.argv[1]), unpack(sys.argv[2])
    module = types.ModuleType('service_tooling')
    module.__file__ = '<service-tooling>'
    sys.modules[module.__name__] = module
    exec(compile(helper, module.__file__, 'exec'), module.__dict__)
    exec(compile(source, '<service-onboarding>', 'exec'), globals())
except Exception:
    print(json.dumps({'schema':1,'status':'REFUSED','code':'ONBOARDING_PYTHON_ENVIRONMENT_REQUIRED'}))
'''

# Recovery installs PyYAML in its virtual environment, not Ubuntu's system
# Python. Select only an already installed recovery/worker interpreter.
REMOTE_LAUNCHER = r'''
import json, os, re, sys
try:
    interpreter = sys.argv[1]
    assert len(sys.argv) == 4
    assert all(len(value) <= 120 * 1024 for value in sys.argv[2:])
    assert re.fullmatch(r'/home/[A-Za-z_][A-Za-z0-9_-]*/\.local/share/streams-aio-(?:recovery|public-sync)/venv/bin/python', interpreter)
    if not os.path.isfile(interpreter) or not os.access(interpreter, os.X_OK):
        code = 'ONBOARDING_LAB_NOT_PREPARED' if '/streams-aio-recovery/' in interpreter else 'ONBOARDING_BACKUP_PIPELINE_NOT_READY'
        print(json.dumps({'schema': 1, 'status': 'REFUSED', 'code': code}))
    else:
        os.execv(interpreter, [interpreter, '-I', '-c', __WORKER__, sys.argv[2], sys.argv[3]])
except Exception:
    print('{"schema":1,"status":"REFUSED","code":"ONBOARDING_PYTHON_ENVIRONMENT_REQUIRED"}')
'''.replace('__WORKER__', repr(REMOTE_WORKER))


def packed_remote_source(path):
    raw = path.read_bytes()
    need(len(raw) <= MAX_REMOTE_SOURCE, 'SERVICE_TRANSPORT_FAILED')
    packed = base64.b64encode(zlib.compress(raw, level=9)).decode('ascii')
    need(len(packed) <= MAX_REMOTE_ARGUMENT, 'SERVICE_TRANSPORT_FAILED')
    return packed

# Independent, memory-only proof of the exact Agent output. The request carries
# a fresh challenge and keyed digests, never plaintext secret values. Neither
# the challenge nor the digests are written to a journal or a public report.
PRIVATE_PROOF = r'''
import hashlib, hmac, json, os, pathlib, re, stat, sys
try:
    raw_request = sys.stdin.buffer.read(131073)
    prefix, marker, payload = raw_request.rpartition(b'STREAMS_PRIVATE_PROOF_V1\n')
    assert len(raw_request) <= 131072 and marker
    assert not prefix or (len(prefix) <= 16385 and prefix.endswith(b'\n') and prefix.count(b'\n') == 1)
    request = json.loads(payload)
    path = pathlib.Path(request['path'])
    assert re.fullmatch(r'/home/[A-Za-z_][A-Za-z0-9_-]*/streams-aio/\.secrets/[a-z][a-z0-9_-]*\.env', str(path))
    assert not any(p.is_symlink() for p in (path, *path.parents))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        metadata = request['metadata']
        assert set(metadata) == {'uid', 'gid', 'mode'}
        assert all(type(metadata[key]) is int for key in metadata)
        assert metadata['gid'] > 0 and metadata['uid'] >= 0
        assert metadata['mode'] == (0o640 if metadata['uid'] == 0 else 0o600)
        assert stat.S_ISREG(info.st_mode) and info.st_uid == metadata['uid']
        assert info.st_gid == metadata['gid'] and stat.S_IMODE(info.st_mode) == metadata['mode']
        assert info.st_size < 1024 * 1024 and info.st_nlink == 1
        raw = os.read(fd, 1024 * 1024).decode('utf-8')
    finally:
        os.close(fd)
    key = bytes.fromhex(request['challenge'])
    expected = request['expected']
    found = {}
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        name, sep, value = line.partition('=')
        assert sep and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name) and name not in found
        assert len(value) >= 2 and value.startswith("'") and value.endswith("'")
        value = value[1:-1]
        assert "'" not in value and not value.endswith('\\')
        found[name] = hmac.digest(key, (name + '\0' + value).encode('utf-8'), 'sha256').hex()
    assert set(found) == set(expected)
    assert all(hmac.compare_digest(found[name], expected[name]) for name in found)
    print('{"status":"PASS"}')
except Exception:
    print('{"status":"REFUSED"}')
'''


class OnboardingError(ValueError):
    """Closed error code and reviewed metadata, never transport output."""
    def __init__(self, code, *, diagnostic=None):
        super().__init__(code)
        self.diagnostic = safe_service_diagnostic(diagnostic) if diagnostic is not None else None


def need(condition, code):
    if not condition:
        raise OnboardingError(code)


RESUME_PHASES = frozenset({'SERVICE_READY', 'PUBLIC_PUBLISHED', 'BACKUP_RUNNING', 'COMPLETE'})
SERVICE_DIAGNOSTIC_STAGES = frozenset({'HOST', 'INFISICAL', 'FILES', 'AGENT', 'SERVICE', 'GITHUB', 'BACKUP'})
SERVICE_DIAGNOSTIC_REASONS = frozenset({
    'PRIVATE_VALUE_IN_PUBLIC_FILE', 'PRIVATE_VARIABLE_DEFAULT_REFUSED', 'LITERAL_CREDENTIAL_REFUSED',
    'SERVICE_CONFIGURATION_MODE_MISMATCH', 'SERVICE_CONFIGURATION_HASH_MISMATCH',
    'SOURCE_FILE_MISSING_OR_OVERSIZED', 'COMMAND_FAILED', 'COMPOSE_CONFIG_FAILED',
    'COMPOSE_PULL_FAILED', 'COMPOSE_UP_FAILED', 'IMAGE_UNAVAILABLE', 'PORT_IN_USE',
    'PUBLIC_BASE_MOVED', 'SYNC_ALREADY_RUNNING', 'TOOLING_UPDATE_REQUIRED',
    'AGENT_SCOPE_UNAVAILABLE', 'COMPOSE_UNSUPPORTED', 'PUBLIC_DECLARATION_INVALID', 'PUBLIC_EXPORT_REFUSED',
    'RECOVERY_VOLUME_OVERRIDE_REVIEW_REQUIRED', 'MISSING_SERVICE_DEPENDENCY', 'SERVICE_DEPENDENCY_CYCLE',
    'CANDIDATE_PUBLIC_ENV_REQUIRES_PRIVATE_CLASSIFICATION',
})


def service_diagnostic_paths(plan):
    """Only paths explicitly reviewed as public can reach a service report."""
    result = {'docker-compose.yml', 'config/service-resources.json'}
    for child in plan.get('components') or (plan,):
        if isinstance(child, dict) and isinstance(child.get('public_env_path'), str):
            result.add(child['public_env_path'])
    for row in plan.get('configuration_files', ()):
        if isinstance(row, dict) and isinstance(row.get('path'), str): result.add(row['path'])
    return result


def safe_service_diagnostic(value, *, allowed_paths=None):
    """Copy a closed, bounded diagnostic; application output is never accepted."""
    need(isinstance(value, dict) and set(value) <= {
        'schema', 'stage', 'code', 'path', 'lines', 'references', 'retryable'}
        and {'schema', 'stage', 'code', 'retryable'} <= set(value), 'SERVICE_RESPONSE_INVALID')
    need(type(value['schema']) is int and value['schema'] == 1
         and isinstance(value['stage'], str) and value['stage'] in SERVICE_DIAGNOSTIC_STAGES
         and isinstance(value['code'], str) and re.fullmatch(r'[A-Z][A-Z0-9_]{1,100}', value['code'])
         and type(value['retryable']) is bool, 'SERVICE_RESPONSE_INVALID')
    result = dict(schema=1, stage=value['stage'],
                  code=value['code'] if value['code'] in SERVICE_DIAGNOSTIC_REASONS else 'PUBLIC_EXPORT_REFUSED',
                  retryable=value['retryable'])
    if 'path' in value:
        path = value['path']
        need(isinstance(path, str) and 0 < len(path) <= 4096 and not path.startswith('/')
             and '\\' not in path and '..' not in path.split('/') and not any(ord(c) < 32 or ord(c) == 127 for c in path)
             and (allowed_paths is None or path in allowed_paths), 'SERVICE_RESPONSE_INVALID')
        result['path'] = path
    if 'lines' in value:
        lines = value['lines']
        need('path' in result and isinstance(lines, list) and len(lines) <= 20
             and all(type(line) is int and 1 <= line <= 1000000 for line in lines)
             and len(set(lines)) == len(lines), 'SERVICE_RESPONSE_INVALID')
        result['lines'] = sorted(lines)
    if 'references' in value:
        references = value['references']
        need(isinstance(references, list) and len(references) <= 20
             and all(isinstance(ref, str) and re.fullmatch(r'/[A-Za-z0-9_-]{1,64}(?:/[A-Za-z0-9_-]{1,128}){1,8}', ref)
                     for ref in references) and len(set(references)) == len(references), 'SERVICE_RESPONSE_INVALID')
        result['references'] = sorted(references)
    return result


def verify_public_private_separation(plan, values):
    """Recheck new private inputs locally before any connection or transport."""
    if not values: return
    children = plan.get('components') or (plan,)
    rows = [('docker-compose.yml', plan.get('compose_fragment', ''))]
    rows += [(child['public_env_path'], child.get('public_env_text', '')) for child in children]
    rows += [(row['path'], row['content']) for row in plan.get('configuration_files', ())]
    names = set(values)
    for child in children: names.update(child.get('private_bindings', {}))
    escaped = '|'.join(re.escape(name) for name in sorted(names, key=len, reverse=True))
    key_pattern = re.compile(r'(?m)^(\s*(?:-\s*)?)(?:export\s+)?[\"\']?(?:' + escaped + r')[\"\']?\s*[:=]')
    reference = re.compile(r'\$\{[A-Za-z_][A-Za-z0-9_]*(?::?[-+?])?\}|\{\{\s*(?:[A-Za-z_][A-Za-z0-9_]*|\.[A-Za-z_][A-Za-z0-9_.]*)\s*\}\}')
    for path, text in rows:
        public = key_pattern.sub(r'\1', reference.sub('', text))
        lines = set()
        for private in values.values():
            if len(private) < 8: continue
            for match in re.finditer(re.escape(private), public):
                lines.add(public.count('\n', 0, match.start()) + 1)
        if lines:
            raise OnboardingError('ONBOARDING_PUBLIC_PREFLIGHT_FAILED', diagnostic=dict(
                schema=1, stage='FILES', code='PRIVATE_VALUE_IN_PUBLIC_FILE', path=path,
                lines=sorted(lines)[:20], retryable=True))


@dataclass(frozen=True, repr=False)
class InspectionReceipt:
    fingerprint: str
    job_id: str
    binding: bytes = field(repr=False)
    resume: bool = False
    agent_output: tuple = ()
    api_address: str = ''
    resume_phase: str = ''

    def __repr__(self):
        return '<InspectionReceipt values=redacted>'


class ServiceController:
    def __init__(self, confirm_key, *, confirm_changed_key=None, cancelled=None,
                 ssh_factory=SSH, api_factory=InfisicalClient, resource_dir=None,
                 sleeper=time.sleep, clock=time.monotonic, backup_timeout=1800):
        self.confirm_key, self.confirm_changed_key = confirm_key, confirm_changed_key
        self.cancelled = cancelled or threading.Event()
        self._ssh_factory, self._api_factory = ssh_factory, api_factory
        self._resources = resource_dir
        self._sleep, self._clock, self._backup_timeout = sleeper, clock, backup_timeout
        self.__binding_key = secrets.token_bytes(32)
        self.__jobs = {}  # Session cache; durable jobs are discovered and verified on the VM.

    def _check_cancel(self):
        need(not self.cancelled.is_set(), 'SERVICE_OPERATION_STOPPED')

    def _validate(self, analysis, connection, infisical):
        need(isinstance(analysis, ServiceAnalysis) and isinstance(connection, dict)
             and isinstance(infisical, dict), 'SERVICE_ANALYSIS_REQUIRED')
        values = analysis.sensitive.as_dict()
        need(set(values) == set(analysis.plan.private_bindings), 'SERVICE_PRIVATE_VALUES_INVALID')
        validate_private_values(values)
        verify_public_private_separation(analysis.plan.deployment_payload(), values)
        root = connection.get('stack_root', '')
        need(isinstance(root, str) and re.fullmatch(r'/home/[A-Za-z_][A-Za-z0-9_-]*/streams-aio', root),
             'SERVICE_STACK_ROOT_REQUIRED')
        need(root.split('/')[2] == connection.get('user'), 'SERVICE_STACK_OWNER_MISMATCH')
        need(connection.get('verification_scope', 'full') in ('full', 'local_lab'),
             'SERVICE_VERIFICATION_SCOPE_INVALID')
        # Bind all submitted inputs, including secrets, with an ephemeral HMAC.
        # This is never exported; public plans have no private-value fingerprints.
        try:
            raw = json.dumps([analysis.plan.deployment_payload(), connection, infisical, values],
                             sort_keys=True, ensure_ascii=False).encode('utf-8')
        except (ValueError, TypeError, UnicodeError):
            raise OnboardingError('SERVICE_INPUTS_INVALID') from None
        signature = hmac.digest(self.__binding_key, raw, 'sha256')
        key = hashlib.sha256(json.dumps([connection.get('host'), connection.get('port'),
            connection.get('user'), root, analysis.plan.fingerprint,
            infisical.get('project_id'), infisical.get('environment'),
            connection.get('verification_scope', 'full')], sort_keys=True).encode()).hexdigest()
        return values, signature, key

    def _connect(self, connection):
        self._check_cancel()
        try:
            host = Host(connection.get('host', ''), connection.get('user', ''), int(connection.get('port') or 22),
                        connection.get('password', ''), connection.get('ssh_key', ''),
                        connection.get('key_password', ''), connection.get('sudo_password', ''))
            return self._ssh_factory(host, self.confirm_key, self.cancelled,
                                     confirm_changed_key=self.confirm_changed_key)
        except Failure:
            raise
        except Exception:
            raise OnboardingError('SSH_CONNECTION_FAILED') from None

    def _api(self, infisical, ssh=None, receipt=None):
        if receipt and receipt.api_address:
            from .onboarding_ssh_api import SSHInfisicalOpener, SSH_ORIGIN
            return self._api_factory(SSH_ORIGIN, infisical.get('project_id', ''),
                infisical.get('environment', ''), infisical.get('access_token', ''),
                opener=SSHInfisicalOpener(ssh, receipt.api_address))
        return self._api_factory(infisical.get('endpoint', ''), infisical.get('project_id', ''),
                                 infisical.get('environment', ''), infisical.get('access_token', ''))

    def prepare_lab(self, snapshot, progress_callback=None):
        from .lab_prepare import prepare_lab
        return prepare_lab(snapshot, confirm_key=self.confirm_key,
            confirm_changed_key=self.confirm_changed_key, cancelled=self.cancelled,
            progress_callback=progress_callback, ssh_factory=self._ssh_factory)

    @staticmethod
    def _progress(callback, stage, status):
        if callback:
            callback({'stage': stage, 'status': status})

    def _request(self, action, analysis, connection, infisical, receipt=None):
        request = dict(action=action, root=connection['stack_root'], plan=analysis.plan.deployment_payload(),
                       project_id=infisical.get('project_id', ''), environment=infisical.get('environment', ''),
                       probe_url=connection.get('probe_url', ''),
                       verification_scope=connection.get('verification_scope', 'full'))
        if receipt:
            request.update(fingerprint=receipt.fingerprint, job_id=receipt.job_id)
        if action == 'apply' and analysis.plan.private_bindings:
            proof = {}
            for service, _, values in self._component_values(analysis, analysis.sensitive.as_dict()):
                challenge = secrets.token_bytes(32)
                proof[service] = dict(challenge=challenge.hex(), expected={name: hmac.digest(challenge,
                    (name + '\0' + value).encode('utf-8'), 'sha256').hex() for name, value in values.items()})
            request['private_proof'] = proof
        return request

    @staticmethod
    def _agent_output(result, private_required):
        if not private_required:
            return ()
        metadata = result.get('agent_output')
        need(isinstance(metadata, dict) and set(metadata) == {'uid', 'gid', 'mode'}
             and all(type(value) is int for value in metadata.values())
             and 0 <= metadata['uid'] < 2 ** 32 and 0 < metadata['gid'] < 2 ** 32
             and metadata['mode'] == (0o640 if metadata['uid'] == 0 else 0o600),
             'SERVICE_RESPONSE_INVALID')
        return metadata['uid'], metadata['gid'], metadata['mode']

    @staticmethod
    def _agent_api(result):
        address = result.get('api_address', '')
        need(isinstance(address, str), 'SERVICE_RESPONSE_INVALID')
        if address:
            need(re.fullmatch(r'http://127\.0\.0\.1:[0-9]{1,5}', address) is not None,
                 'SERVICE_RESPONSE_INVALID')
            need(1 <= int(address.rsplit(':', 1)[1]) <= 65535, 'SERVICE_RESPONSE_INVALID')
        return address

    @staticmethod
    def _component_values(analysis, values):
        """Route namespaced desktop values to each service's original env keys."""
        components = getattr(analysis.plan, 'components', ())
        if not components:
            return [(analysis.plan.service_name, analysis.plan.private_env_path, values)]
        groups = []
        for component in components:
            bindings = component.get('private_bindings', {})
            names = component.get('value_names', {})
            local = {name: values[names.get(name, name)] for name in bindings}
            if local:
                groups.append((component['service_name'], component['private_env_path'], local))
        return groups

    def _verify_private(self, ssh, analysis, connection, values, agent_output):
        for service, private_path, local_values in self._component_values(analysis, values):
            if not local_values:
                continue
            challenge = secrets.token_bytes(32)
            request = dict(path=connection['stack_root'] + '/' + private_path,
                           metadata=dict(zip(('uid', 'gid', 'mode'), agent_output)),
                           challenge=challenge.hex(), expected={name: hmac.digest(challenge,
                               (name + '\0' + value).encode('utf-8'), 'sha256').hex()
                               for name, value in local_values.items()})
            try:
                result = json.loads(ssh.run(['python3', '-B', '-c', PRIVATE_PROOF], sudo=True,
                                            input=PRIVATE_PROOF_FRAME + json.dumps(request).encode() + b'\n', timeout=30))
                need(result == {'status': 'PASS'}, 'ONBOARDING_AGENT_VALUE_READBACK_FAILED')
            except (OnboardingError, Failure):
                raise
            except Exception:
                raise OnboardingError('ONBOARDING_AGENT_VALUE_READBACK_FAILED') from None

    def _remote(self, ssh, request):
        self._check_cancel()
        folder = self._resources if self._resources is not None else resources()
        try:
            source = packed_remote_source(folder / 'service_onboarding.py')
            tooling = packed_remote_source(folder / 'service_tooling.py')
            area = 'streams-aio-recovery' if request.get('verification_scope') == 'local_lab' else 'streams-aio-public-sync'
            interpreter = request['root'].rsplit('/', 1)[0] + '/.local/share/' + area + '/venv/bin/python'
            raw = ssh.run(['python3', '-I', '-c', REMOTE_LAUNCHER, interpreter, source, tooling], sudo=True,
                          input=ONBOARDING_FRAME + json.dumps(request, ensure_ascii=False).encode('utf-8') + b'\n',
                          timeout=1200)
            need(len(raw) <= 256 * 1024, 'SERVICE_RESPONSE_INVALID')
            result = json.loads(raw)
            need(isinstance(result, dict) and type(result.get('schema')) is int and result['schema'] == 1,
                 'SERVICE_RESPONSE_INVALID')
            if result.get('status') == 'REFUSED':
                code = result.get('code', '')
                need(isinstance(code, str) and re.fullmatch(r'ONBOARDING_[A-Z0-9_]{1,100}', code),
                     'SERVICE_RESPONSE_INVALID')
                diagnostic = result.get('diagnostic')
                if diagnostic is not None:
                    diagnostic = safe_service_diagnostic(diagnostic,
                        allowed_paths=service_diagnostic_paths(request.get('plan', {})))
                raise OnboardingError(code, diagnostic=diagnostic)
            allowed = ({'NO_JOB'} | RESUME_PHASES if request['action'] == 'discover' else
                       {'TOOLS_READY'} if request['action'] == 'update_tools' else
                       {'PREVIEW', 'ROLLED_BACK', 'REVIEW_REQUIRED'} | RESUME_PHASES)
            need(result.get('status') in allowed, 'SERVICE_RESPONSE_INVALID')
            return result
        except (OnboardingError, Failure):
            raise
        except Exception:
            raise OnboardingError('SERVICE_TRANSPORT_FAILED') from None

    def _resumed_receipt(self, state, binding, private_required, plan, expected_scope, previous=None):
        need(state.get('status') in RESUME_PHASES and state.get('application_verified') is True,
             'SERVICE_RESPONSE_INVALID')
        job = state.get('job_id')
        fingerprint = state.get('fingerprint', previous.fingerprint if previous else None)
        need(isinstance(job, str) and re.fullmatch(r'[0-9a-f]{32}', job)
             and isinstance(fingerprint, str) and re.fullmatch(r'[0-9a-f]{64}', fingerprint),
             'SERVICE_RESPONSE_INVALID')
        names = plan.get('service_names') or [plan['service_name']]
        need(state.get('service') == plan['service_name'] and state.get('services') == list(names)
             and state.get('verification_scope') == expected_scope, 'SERVICE_RESPONSE_INVALID')
        output, address = self._agent_output(state, private_required), self._agent_api(state)
        if previous:
            need(job == previous.job_id and fingerprint == previous.fingerprint, 'ONBOARDING_RESUME_CHANGED')
            need(output == previous.agent_output and address == previous.api_address, 'ONBOARDING_AGENT_PROFILE_CHANGED')
        return InspectionReceipt(fingerprint, job, binding, resume=True, agent_output=output,
                                 api_address=address, resume_phase=state['status'])

    def inspect(self, analysis, connection, infisical, progress_callback=None):
        values, binding, key = self._validate(analysis, connection, infisical)
        self._progress(progress_callback, 'HOST', 'RUNNING')
        ssh = self._connect(connection)
        try:
            previous = self.__jobs.get(key)
            receipt = None
            if previous:
                state = self._remote(ssh, self._request('status', analysis, connection, infisical, previous))
                need(state.get('job_id') == previous.job_id, 'SERVICE_RESPONSE_INVALID')
                if state['status'] in RESUME_PHASES:
                    receipt = self._resumed_receipt(state, binding, bool(values), analysis.plan.deployment_payload(),
                        connection.get('verification_scope', 'full'), previous)
                elif state['status'] == 'ROLLED_BACK':
                    self.__jobs.pop(key, None)
                    previous = None
                else:
                    raise OnboardingError('ONBOARDING_INTERRUPTED_REVIEW_REQUIRED')
            if not previous:
                state = self._remote(ssh, self._request('discover', analysis, connection, infisical))
                if state['status'] != 'NO_JOB':
                    receipt = self._resumed_receipt(state, binding, bool(values), analysis.plan.deployment_payload(),
                        connection.get('verification_scope', 'full'))
            if receipt is None:
                result = self._remote(ssh, self._request('inspect', analysis, connection, infisical))
                fingerprint = result.get('fingerprint')
                need(result['status'] == 'PREVIEW' and isinstance(fingerprint, str)
                     and re.fullmatch(r'[0-9a-f]{64}', fingerprint), 'SERVICE_RESPONSE_INVALID')
                receipt = InspectionReceipt(fingerprint, uuid.uuid4().hex, binding,
                    agent_output=self._agent_output(result, bool(values)), api_address=self._agent_api(result))
            if receipt.resume:
                # A new desktop process must prove the current private output
                # before it may create anything missing in Infisical.
                self._verify_private(ssh, analysis, connection, values, receipt.agent_output)
                self.__jobs[key] = receipt
            self._progress(progress_callback, 'HOST', 'PASS')
            if values:
                self._progress(progress_callback, 'INFISICAL', 'RUNNING')
                api = self._api(infisical, ssh, receipt)
                for service, _, local_values in self._component_values(analysis, values):
                    api.inspect(service, local_values)
                self._progress(progress_callback, 'INFISICAL', 'PASS')
            return receipt
        finally:
            ssh.close()

    def prepare_tools(self, analysis, connection, infisical, progress_callback=None):
        self._validate(analysis, connection, infisical)
        self._progress(progress_callback, 'HOST', 'RUNNING')
        ssh = self._connect(connection)
        try:
            result = self._remote(ssh, self._request('update_tools', analysis, connection, infisical))
            need(result['status'] == 'TOOLS_READY', 'SERVICE_RESPONSE_INVALID')
            self._progress(progress_callback, 'HOST', 'PASS')
            return dict(status='TOOLS_READY')
        finally:
            ssh.close()

    def apply(self, analysis, connection, infisical, receipt, progress_callback=None):
        values, binding, key = self._validate(analysis, connection, infisical)
        need(isinstance(receipt, InspectionReceipt)
             and hmac.compare_digest(receipt.binding, binding), 'SERVICE_INPUTS_CHANGED')
        ssh = self._connect(connection)
        try:
            if not receipt.resume:
                fresh = self._remote(ssh, self._request('inspect', analysis, connection, infisical))
                need(fresh.get('fingerprint') == receipt.fingerprint, 'ONBOARDING_PREVIEW_STALE')
                need(self._agent_output(fresh, bool(values)) == receipt.agent_output
                     and self._agent_api(fresh) == receipt.api_address,
                     'ONBOARDING_AGENT_PROFILE_CHANGED')
            if values:
                self._progress(progress_callback, 'INFISICAL', 'RUNNING')
                api = self._api(infisical, ssh, receipt)
                for service, _, local_values in self._component_values(analysis, values):
                    api.ensure(service, local_values)
                self._progress(progress_callback, 'INFISICAL', 'PASS')
            self._check_cancel()
            self.__jobs[key] = receipt
            self._progress(progress_callback, 'FILES', 'RUNNING')
            result = self._remote(ssh, self._request('apply', analysis, connection, infisical, receipt))
            need(result.get('job_id') == receipt.job_id
                 and result['status'] in ('SERVICE_READY', 'PUBLIC_PUBLISHED', 'BACKUP_RUNNING', 'COMPLETE'),
                 'SERVICE_OPERATION_INCOMPLETE')
            need(result.get('application_verified') is True, 'SERVICE_OPERATION_INCOMPLETE')
            self._verify_private(ssh, analysis, connection, values, receipt.agent_output)
            for stage in ('FILES', 'AGENT', 'SERVICE'):
                self._progress(progress_callback, stage, 'PASS')
            if connection.get('verification_scope') == 'local_lab':
                self._progress(progress_callback, 'GITHUB', 'SKIPPED')
                self._progress(progress_callback, 'BACKUP', 'SKIPPED')
                return dict(status='PASS_LOCAL', checks=dict(service=True, agent=True, github=False, backup=False),
                            job_id=receipt.job_id)
            self._progress(progress_callback, 'GITHUB', 'RUNNING')
            deadline = self._clock() + self._backup_timeout
            if result['status'] == 'COMPLETE':
                # An old receipt is not a fresh proof of the running service.
                result = self._remote(ssh, self._request('finalize', analysis, connection, infisical, receipt))
                need(result.get('job_id') == receipt.job_id and result['status'] == 'COMPLETE',
                     'SERVICE_OPERATION_INCOMPLETE')
            while result['status'] != 'COMPLETE':
                self._check_cancel()
                need(self._clock() < deadline, 'ONBOARDING_BACKUP_PENDING')
                result = self._remote(ssh, self._request('finalize', analysis, connection, infisical, receipt))
                need(result.get('job_id') == receipt.job_id
                     and result['status'] in ('PUBLIC_PUBLISHED', 'BACKUP_RUNNING', 'COMPLETE'),
                     'SERVICE_OPERATION_INCOMPLETE')
                if result['status'] in ('BACKUP_RUNNING', 'COMPLETE'):
                    self._progress(progress_callback, 'GITHUB', 'PASS')
                    self._progress(progress_callback, 'BACKUP', 'RUNNING')
                if result['status'] != 'COMPLETE':
                    self._sleep(3)
            need(result.get('application_verified') is True
                 and result.get('backup_integrity_verified') is True
                 and isinstance(result.get('public_commit'), str)
                 and re.fullmatch(r'[0-9a-f]{40}', result['public_commit'])
                 and isinstance(result.get('backup_tag'), str)
                 and re.fullmatch(r'dr-[0-9]{8}T[0-9]{6}Z', result['backup_tag']),
                 'SERVICE_OPERATION_INCOMPLETE')
            self._verify_private(ssh, analysis, connection, values, receipt.agent_output)
            self._progress(progress_callback, 'BACKUP', 'PASS')
            return dict(status='PASS', checks=dict(service=True, agent=True, github=True, backup=True),
                        public_commit=result['public_commit'], backup_tag=result['backup_tag'])
        except (Failure, OnboardingError, InfisicalFailure):
            raise
        except Exception:
            raise OnboardingError('SERVICE_TOOL_FAILED') from None
        finally:
            ssh.close()

"""Service onboarding orchestration. No desktop automation or implicit writes.

Analysis is offline; inspect is read-only. Apply requires the exact in-memory
inspection receipt, creates/verifies secrets, then invokes the bounded remote
transaction. Credentials and secret values never enter its request or journal.
"""
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import uuid

from .backend import Failure, Host, SSH, resources
from .onboarding_infisical import InfisicalClient, InfisicalFailure, validate_private_values
from .service_plan import ServiceAnalysis

ONBOARDING_FRAME = b'STREAMS_ONBOARDING_V1\n'
PRIVATE_PROOF_FRAME = b'STREAMS_PRIVATE_PROOF_V1\n'

# Recovery installs PyYAML in its virtual environment, not in Ubuntu's system
# Python. Select only the already installed recovery/worker interpreter and keep
# stdin untouched, including the framing needed when sudo leaves its input line.
REMOTE_LAUNCHER = r'''
import json, os, re, sys
try:
    interpreter = sys.argv[1]
    assert re.fullmatch(r'/home/[A-Za-z_][A-Za-z0-9_-]*/\.local/share/streams-aio-(?:recovery|public-sync)/venv/bin/python', interpreter)
    if not os.path.isfile(interpreter) or not os.access(interpreter, os.X_OK):
        code = 'ONBOARDING_LAB_NOT_PREPARED' if '/streams-aio-recovery/' in interpreter else 'ONBOARDING_BACKUP_PIPELINE_NOT_READY'
        print(json.dumps({'schema': 1, 'status': 'REFUSED', 'code': code}))
    else:
        guard = "import json,sys\ntry:\n import yaml\nexcept Exception:\n print(json.dumps({'schema':1,'status':'REFUSED','code':'ONBOARDING_PYTHON_ENVIRONMENT_REQUIRED'}));sys.exit(0)\nexec(compile(sys.argv[1], '<service-onboarding>', 'exec'), globals())"
        os.execv(interpreter, [interpreter, '-I', '-c', guard, sys.argv[2]])
except Exception:
    print('{"schema":1,"status":"REFUSED","code":"ONBOARDING_PYTHON_ENVIRONMENT_REQUIRED"}')
'''

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
    """Closed error code for presentation, never arbitrary transport output."""


def need(condition, code):
    if not condition:
        raise OnboardingError(code)


@dataclass(frozen=True, repr=False)
class InspectionReceipt:
    fingerprint: str
    job_id: str
    binding: bytes = field(repr=False)
    resume: bool = False
    agent_output: tuple = ()
    api_address: str = ''

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
        self.__jobs = {}  # Safe job IDs only, scoped to this desktop session.

    def _check_cancel(self):
        need(not self.cancelled.is_set(), 'SERVICE_OPERATION_STOPPED')

    def _validate(self, analysis, connection, infisical):
        need(isinstance(analysis, ServiceAnalysis) and isinstance(connection, dict)
             and isinstance(infisical, dict), 'SERVICE_ANALYSIS_REQUIRED')
        values = analysis.sensitive.as_dict()
        need(set(values) == set(analysis.plan.private_bindings), 'SERVICE_PRIVATE_VALUES_INVALID')
        validate_private_values(values)
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

    def _verify_private(self, ssh, analysis, connection, values, agent_output):
        if not values:
            return
        challenge = secrets.token_bytes(32)
        request = dict(path=connection['stack_root'] + '/' + analysis.plan.private_env_path,
                       metadata=dict(zip(('uid', 'gid', 'mode'), agent_output)),
                       challenge=challenge.hex(), expected={name: hmac.digest(challenge,
                           (name + '\0' + value).encode('utf-8'), 'sha256').hex()
                           for name, value in values.items()})
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
            source = (folder / 'service_onboarding.py').read_text(encoding='utf-8')
            area = 'streams-aio-recovery' if request.get('verification_scope') == 'local_lab' else 'streams-aio-public-sync'
            interpreter = request['root'].rsplit('/', 1)[0] + '/.local/share/' + area + '/venv/bin/python'
            raw = ssh.run(['python3', '-I', '-c', REMOTE_LAUNCHER, interpreter, source], sudo=True,
                          input=ONBOARDING_FRAME + json.dumps(request, ensure_ascii=False).encode('utf-8') + b'\n',
                          timeout=1200)
            need(len(raw) <= 256 * 1024, 'SERVICE_RESPONSE_INVALID')
            result = json.loads(raw)
            need(isinstance(result, dict) and result.get('schema') == 1,
                 'SERVICE_RESPONSE_INVALID')
            if result.get('status') == 'REFUSED':
                code = result.get('code', '')
                need(isinstance(code, str) and re.fullmatch(r'ONBOARDING_[A-Z0-9_]{1,100}', code),
                     'SERVICE_RESPONSE_INVALID')
                raise OnboardingError(code)
            need(result.get('status') in ('PREVIEW', 'SERVICE_READY', 'PUBLIC_PUBLISHED',
                                          'BACKUP_RUNNING', 'COMPLETE', 'ROLLED_BACK', 'REVIEW_REQUIRED'),
                 'SERVICE_RESPONSE_INVALID')
            return result
        except (OnboardingError, Failure):
            raise
        except Exception:
            raise OnboardingError('SERVICE_TRANSPORT_FAILED') from None

    def inspect(self, analysis, connection, infisical, progress_callback=None):
        values, binding, key = self._validate(analysis, connection, infisical)
        self._progress(progress_callback, 'HOST', 'RUNNING')
        ssh = self._connect(connection)
        try:
            previous = self.__jobs.get(key)
            if previous:
                state = self._remote(ssh, self._request('status', analysis, connection, infisical, previous))
                need(state.get('job_id') == previous.job_id, 'SERVICE_RESPONSE_INVALID')
                if state['status'] in ('SERVICE_READY', 'PUBLIC_PUBLISHED', 'BACKUP_RUNNING', 'COMPLETE'):
                    output = self._agent_output(state, bool(values))
                    address = self._agent_api(state)
                    need(output == previous.agent_output and address == previous.api_address,
                         'ONBOARDING_AGENT_PROFILE_CHANGED')
                    receipt = InspectionReceipt(previous.fingerprint, previous.job_id, binding,
                                                resume=True, agent_output=output, api_address=address)
                elif state['status'] == 'ROLLED_BACK':
                    self.__jobs.pop(key, None)
                    previous = None
                else:
                    raise OnboardingError('ONBOARDING_INTERRUPTED_REVIEW_REQUIRED')
            if not previous:
                result = self._remote(ssh, self._request('inspect', analysis, connection, infisical))
                fingerprint = result.get('fingerprint')
                need(result['status'] == 'PREVIEW' and isinstance(fingerprint, str)
                     and re.fullmatch(r'[0-9a-f]{64}', fingerprint), 'SERVICE_RESPONSE_INVALID')
                receipt = InspectionReceipt(fingerprint, uuid.uuid4().hex, binding,
                    agent_output=self._agent_output(result, bool(values)), api_address=self._agent_api(result))
            self._progress(progress_callback, 'HOST', 'PASS')
            if values:
                self._progress(progress_callback, 'INFISICAL', 'RUNNING')
                self._api(infisical, ssh, receipt).inspect(analysis.plan.service_name, values)
                self._progress(progress_callback, 'INFISICAL', 'PASS')
            return receipt
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
                self._api(infisical, ssh, receipt).ensure(analysis.plan.service_name, values)
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

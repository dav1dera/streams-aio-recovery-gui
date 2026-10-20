"""Narrow, memory-only JSON API for the local webview.

Remote work runs only after an explicit method call. Public methods never return
exception excerpts, input values, credentials, executable paths or raw reports.
The host must expose only these methods to a trusted bundled local page.
"""
from collections import deque
from functools import wraps
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import re
import secrets
import threading
import uuid

from . import __version__, backend
from .onboarding import ServiceController
from .age_input import validate_identity_input
from .lab_prepare import LabFailure
from .service_plan import inspect_inputs, analyze_inputs
from .ui_onboarding import (ERROR_TEXT, PROGRESS_TEXT, STAGES as SERVICE_STAGES, connection_from_snapshot,
                           infisical_from_fields, verified_completion, verified_local_completion)
from .ui_state import FINISHED_STAGES, PHASE_STAGES, operational_request, machine_status


KEYS = frozenset(('host', 'user', 'port', 'password', 'ssh_key', 'key_password', 'sudo_password',
    'infisical_host', 'infisical_user', 'infisical_port', 'infisical_password', 'infisical_key',
    'infisical_key_password', 'infisical_sudo_password', 'github_token', 'dr_tag', 'public_commit',
    'age_identity', 'age_identity_mode', 'age_identity_text', 'supplemental_inputs', 'infisical_address', 'project_id', 'environment',
    'client_id_file', 'client_secret_file', 'domain_target_address', 'routing_mode'))
SENSITIVE = frozenset(('password', 'key_password', 'sudo_password', 'infisical_password',
    'infisical_key_password', 'infisical_sudo_password', 'github_token', 'client_secret_file', 'age_identity_text'))
DEFAULTS = dict.fromkeys(KEYS, '') | dict(user='test', port='22', infisical_user='test2',
                                       infisical_port='22', routing_mode='parallel_test', age_identity_mode='file')
WEB_ERRORS = {
    'WEB_INPUT_INVALID': 'Controlla i campi del modulo e riprova.',
    'WEB_CLOSED': 'La finestra è stata chiusa. Apri di nuovo il programma.',
    'WEB_HOST_KEY_INVALID': 'La richiesta di conferma SSH non è valida o è scaduta.',
    'SERVICE_OPERATION_BUSY': 'È già in corso un’operazione. Attendi il suo esito o interrompila.',
    'SERVICE_TOOL_FAILED': 'Il controllo non è stato completato. Le credenziali non vengono registrate.',
    'RECOVERY_OPERATION_INCOMPLETE': 'Il recupero non ha ancora superato tutti i controlli richiesti.',
    'AGE_IDENTITY_FILE_REQUIRED': 'In Accessi e backup scegli il file della chiave privata, oppure seleziona Incolla chiave e inserisci la riga AGE-SECRET-KEY-1….',
    'AGE_IDENTITY_FILE_INVALID': 'La chiave deve essere entro 64 KiB. Se scegli un file, deve essere un file normale e non un collegamento.',
    'AGE_IDENTITY_ENCODING_INVALID': 'La chiave privata deve essere testo valido. I file sono supportati in UTF-8 o UTF-16.',
    'AGE_PRIVATE_IDENTITY_REQUIRED': 'Serve la riga originale completa AGE-SECRET-KEY-1…. Inseriscila nel campo mascherato oppure scegli il file della chiave privata.',
    'AGE_PUBLIC_KEY_NOT_IDENTITY': 'age1… è una chiave pubblica. Per decifrare serve la chiave privata PRIMARY o RECOVERY che inizia con AGE-SECRET-KEY-1….',
}
# Closed codes emitted by the bundled planner, controller and remote helper.
DIAGNOSTIC_CODES = frozenset("""
INFISICAL_AGENT_RENDER
INFISICAL_API_FAILED
INFISICAL_API_PORT_REQUIRES_REVIEW
INFISICAL_API_VERSION_UNSUPPORTED
INFISICAL_AUTH_FAILED
INFISICAL_CONNECTION_FAILED
INFISICAL_FOLDER_CONFLICT
INFISICAL_HTTP_ERROR
INFISICAL_PERMISSION_DENIED
INFISICAL_RATE_LIMITED
INFISICAL_READBACK_FAILED
INFISICAL_REDIRECT_REFUSED
INFISICAL_RESPONSE_INVALID
INFISICAL_RESPONSE_TOO_LARGE
INFISICAL_SECRET_CONFLICT
INFISICAL_SSH_REQUEST_REFUSED
INFISICAL_SSH_TARGET_INVALID
LAB_EMPTY_VMS_REQUIRED
LAB_HOST_IDENTITY_INVALID
LAB_INPUTS_REQUIRED
LAB_MARKER_REFUSED
LAB_PREPARATION_FAILED
ONBOARDING_AGENT_API_ENDPOINT_UNSUPPORTED
ONBOARDING_AGENT_CONFIG_INVALID
ONBOARDING_AGENT_DESTINATION_EXISTS
ONBOARDING_AGENT_HOOK_REVIEW_REQUIRED
ONBOARDING_AGENT_MERGE_INVALID
ONBOARDING_AGENT_PERMISSIONS_INVALID
ONBOARDING_AGENT_PROFILE_CHANGED
ONBOARDING_AGENT_PROFILE_UNSUPPORTED
ONBOARDING_AGENT_RENDER_FAILED
ONBOARDING_AGENT_RESTART_FAILED
ONBOARDING_AGENT_SERVICE_REVIEW_REQUIRED
ONBOARDING_AGENT_STOP_FAILED
ONBOARDING_AGENT_VALUE_READBACK_FAILED
ONBOARDING_APPLICATION_HEALTH_TIMEOUT
ONBOARDING_APPLICATION_PROBE_INVALID
ONBOARDING_APPLICATION_PROBE_NOT_PUBLISHED_BY_SERVICE
ONBOARDING_APPLICATION_PROBE_REQUIRED
ONBOARDING_APPLY_FAILED
ONBOARDING_BACKUP_ASSETS_INVALID
ONBOARDING_BACKUP_ASSET_SIZE_INVALID
ONBOARDING_BACKUP_CHECKSUM_INVALID
ONBOARDING_BACKUP_CHECKSUM_MISMATCH
ONBOARDING_BACKUP_MANIFEST_INVALID
ONBOARDING_BACKUP_NOT_ENCRYPTED
ONBOARDING_BACKUP_PENDING
ONBOARDING_BACKUP_PIPELINE_NOT_READY
ONBOARDING_BACKUP_PUBLIC_COMMIT_MISMATCH
ONBOARDING_BACKUP_STACK_COMMIT_INVALID
ONBOARDING_BINDINGS_INVALID
ONBOARDING_COMPOSE_COMMAND_FAILED
ONBOARDING_COMPOSE_MERGE_INVALID
ONBOARDING_CONTAINER_FAILED
ONBOARDING_CONTAINER_ID_INVALID
ONBOARDING_CONTAINER_INSPECT_FAILED
ONBOARDING_DATA_DIRECTORY_MISSING
ONBOARDING_DEPENDENCY_MISSING
ONBOARDING_DIRECTORY_PERMISSIONS_INVALID
ONBOARDING_DR_BACKUP_FAILED
ONBOARDING_DR_MAPPING_READBACK_FAILED
ONBOARDING_DR_SERVICE_REVIEW_REQUIRED
ONBOARDING_DR_START_FAILED
ONBOARDING_DUPLICATE_JSON_KEY
ONBOARDING_DUPLICATE_YAML_KEY
ONBOARDING_ENV_FILE_INVALID
ONBOARDING_ENV_FILE_ORDER_INVALID
ONBOARDING_EXISTING_COMPOSE_UNSUPPORTED
ONBOARDING_FILE_INVALID
ONBOARDING_FRAGMENT_INVALID
ONBOARDING_GITHUB_READ_FAILED
ONBOARDING_IMAGE_METADATA_FAILED
ONBOARDING_INFISICAL_SCOPE_INVALID
ONBOARDING_INPUT_TOO_LARGE
ONBOARDING_INSTALLED_FILES_CHANGED
ONBOARDING_INTERRUPTED_REVIEW_REQUIRED
ONBOARDING_JOB_INVALID
ONBOARDING_JOB_PLAN_MISMATCH
ONBOARDING_JOB_SCOPE_MISMATCH
ONBOARDING_JOURNAL_PERMISSIONS_INVALID
ONBOARDING_LAB_NOT_PREPARED
ONBOARDING_LAB_PUBLICATION_REFUSED
ONBOARDING_LOCK_INVALID
ONBOARDING_NEW_BACKUP_NOT_FOUND
ONBOARDING_OPERATION_FAILED
ONBOARDING_OTHER_OPERATION_RUNNING
ONBOARDING_OUTPUT_CHANGED
ONBOARDING_OUTPUT_EXISTS
ONBOARDING_PERSISTENT_DATA_COVERAGE_REQUIRED
ONBOARDING_PLAN_INVALID
ONBOARDING_PLAN_PATH_INVALID
ONBOARDING_PREVIEW_STALE
ONBOARDING_PRIVATE_ACL_REVIEW_REQUIRED
ONBOARDING_PRIVATE_OUTPUT_PERMISSIONS_INVALID
ONBOARDING_PRIVATE_VARIABLE_IN_PUBLIC_ENV
ONBOARDING_PRIVATE_VARIABLE_OVERRIDE
ONBOARDING_PUBLIC_ENV_READBACK_FAILED
ONBOARDING_PUBLIC_IMAGE_INVALID
ONBOARDING_PUBLIC_IMAGE_LOCK_INVALID
ONBOARDING_PUBLIC_READBACK_FAILED
ONBOARDING_PUBLIC_RECEIPT_INVALID
ONBOARDING_PUBLIC_SERVICE_MISSING
ONBOARDING_PUBLIC_SERVICE_READBACK_FAILED
ONBOARDING_PUBLIC_SYNC_FAILED
ONBOARDING_RELEASE_LIST_INVALID
ONBOARDING_REQUEST_INVALID
ONBOARDING_REQUEST_TOO_LARGE
ONBOARDING_ROOT_REQUIRED
ONBOARDING_SERVICE_ALREADY_EXISTS
ONBOARDING_SERVICE_COMMAND_INVALID
ONBOARDING_SERVICE_NAME_INVALID
ONBOARDING_SERVICE_NOT_VERIFIED
ONBOARDING_SOURCE_CHANGED
ONBOARDING_STACK_NOT_FOUND
ONBOARDING_STACK_OWNER_INVALID
ONBOARDING_STACK_ROOT_INVALID
ONBOARDING_SYMLINK_PATH_REFUSED
ONBOARDING_SYSTEMD_QUERY_FAILED
ONBOARDING_VERIFICATION_SCOPE_INVALID
ONBOARDING_WRITE_VERIFICATION_FAILED
ONBOARDING_YAML_STRUCTURE_INVALID
SERVICE_ALREADY_EXISTS
SERVICE_ANALYSIS_REQUIRED
SERVICE_APPEND_INVALID
SERVICE_COMPOSE_ALIAS_UNSUPPORTED
SERVICE_COMPOSE_DUPLICATE_KEY
SERVICE_COMPOSE_FEATURE_UNSUPPORTED
SERVICE_COMPOSE_FLOW_UNSUPPORTED
SERVICE_COMPOSE_INVALID
SERVICE_COMPOSE_KEY_INVALID
SERVICE_COMPOSE_TOP_LEVEL_UNSUPPORTED
SERVICE_ENVIRONMENT_FLOW_UNSUPPORTED
SERVICE_ENVIRONMENT_INVALID
SERVICE_ENV_DUPLICATE_KEY
SERVICE_ENV_FILE_UNSUPPORTED
SERVICE_ENV_INTERPOLATION_UNSUPPORTED
SERVICE_ENV_INVALID
SERVICE_ENV_MULTILINE_UNSUPPORTED
SERVICE_ENV_QUOTING_UNSUPPORTED
SERVICE_EXACTLY_ONE_REQUIRED
SERVICE_EXISTING_COMPOSE_INVALID
SERVICE_EXISTING_COMPOSE_UNSUPPORTED
SERVICE_EXTERNAL_CONFIGURATION_UNSUPPORTED
SERVICE_IMAGE_INVALID
SERVICE_INFISICAL_ACCESS_REQUIRED
SERVICE_INFISICAL_ADDRESS_REQUIRED
SERVICE_INFISICAL_ENVIRONMENT_INVALID
SERVICE_INPUTS_CHANGED
SERVICE_INPUTS_INVALID
SERVICE_INTERPOLATION_INVALID
SERVICE_INTERPOLATION_UNSUPPORTED
SERVICE_LAB_CHECKING_INFISICAL
SERVICE_LAB_CHECKING_INPUTS
SERVICE_LAB_CHECKING_STACK
SERVICE_LAB_CONNECTING_INFISICAL
SERVICE_LAB_CONNECTING_STACK
SERVICE_LAB_READING_BACKUP
SERVICE_NAME_INVALID
SERVICE_NAME_REQUIRED
SERVICE_OPERATION_INCOMPLETE
SERVICE_OPERATION_STOPPED
SERVICE_PERSISTENT_DATA_COVERAGE_REQUIRED
SERVICE_PRIVATE_INTERPOLATION_OUTSIDE_ENV
SERVICE_PRIVATE_SELECTION_INVALID
SERVICE_PRIVATE_VALUES_INVALID
SERVICE_PRIVATE_VALUE_OUTSIDE_ENV
SERVICE_PRIVATE_VALUE_QUOTING_UNSUPPORTED
SERVICE_PRIVATE_VALUE_REQUIRED
SERVICE_READY
SERVICE_RESPONSE_INVALID
SERVICE_STACK_OWNER_MISMATCH
SERVICE_STACK_ROOT_REQUIRED
SERVICE_TOOL_FAILED
SERVICE_TRANSPORT_FAILED
SERVICE_VARIABLE_CONFLICT
SERVICE_VARIABLE_NAME_INVALID
SERVICE_VARIABLE_VALUE_REQUIRED
SERVICE_VERIFICATION_SCOPE_INVALID
SERVICE_VOLUME_INVALID
""".split())
CODE = re.compile(r'[A-Z][A-Z0-9_]{0,100}\Z')
ENV_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,127}\Z')
JOB = re.compile(r'[0-9a-f]{32}\Z')
FINGERPRINT = re.compile(r'SHA256:[A-Za-z0-9+/]{43}=?\Z')
MAX_INPUT = 1024 * 1024
MAX_EVENTS = 512


class BridgeFailure(ValueError):
    pass


def need(value, code='WEB_INPUT_INVALID'):
    if not value:
        raise BridgeFailure(code)


def public(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except Exception as error:
            return self._error(error)
    return wrapped


class WebBridge:
    def __init__(self, controller=None):
        self._lock = threading.RLock()
        self._cancelled = threading.Event()
        self._settings = DEFAULTS.copy()
        self._events = deque(maxlen=MAX_EVENTS)
        self._report_events = deque(maxlen=2048)
        self._busy, self._closed, self._job_id = False, False, None
        self._pending_keys = {}
        self._revision, self._analysis, self._receipt = 0, None, None
        self._service_signature = None
        self._binding_key = secrets.token_bytes(32)
        self._backup_has_aio = None
        self._errors = dict(ERROR_TEXT, **WEB_ERRORS)
        self._stages = dict.fromkeys(backend.STAGES, 'Passaggio del recupero') | SERVICE_STAGES
        self._controller = controller or ServiceController(self._confirm_key,
            confirm_changed_key=self._confirm_changed_key, cancelled=self._cancelled)

    def _error(self, error):
        code = str(error) if (isinstance(error, BridgeFailure) or
            type(error).__module__.startswith('recovery_gui.')) else 'SERVICE_TOOL_FAILED'
        if not CODE.fullmatch(code) or code not in backend.ERROR_CODES | set(self._errors) | DIAGNOSTIC_CODES:
            code = 'SERVICE_TOOL_FAILED'
        result = dict(ok=False, code=code, description=self._errors.get(code,
            'Il passaggio si è fermato. Controlla i dati indicati; lo stato remoto resta conservato.'))
        role = getattr(error, 'target_role', None)
        if isinstance(error, LabFailure) and role in ('stack', 'infisical'):
            result['target_role'] = role
        return result

    def _guard(self):
        need(not self._closed, 'WEB_CLOSED')
        need(not self._busy, 'SERVICE_OPERATION_BUSY')

    def _active(self):
        need(not self._closed and not self._cancelled.is_set(), 'SERVICE_OPERATION_STOPPED')

    def _invalidate(self, clear=True):
        self._revision += 1
        self._receipt, self._service_signature = None, None
        if clear:
            self._analysis = None

    def _update(self, settings):
        need(isinstance(settings, dict) and set(settings) <= KEYS)
        need(all(isinstance(value, str) and len(value) <= (65536 if key in SENSITIVE else 4096)
                 and '\x00' not in value for key, value in settings.items()))
        changes = {key: value if key in SENSITIVE else value.strip() for key, value in settings.items()}
        if changes.get('age_identity_mode') == 'file':
            changes['age_identity_text'] = ''
        if any(self._settings[key] != value for key, value in changes.items()):
            self._settings.update(changes)
            self._invalidate(clear=False)

    def _enqueue(self, kind, **values):
        with self._lock:
            if self._closed:
                return
            # Freeze validated nested diagnostics: the backend may reuse its
            # dictionary after a callback, and reports must retain that exact
            # approved snapshot rather than a mutable reference.
            event = json.loads(json.dumps(dict(kind=kind, job_id=self._job_id, **values), allow_nan=False))
            self._events.append(event)
            if kind in ('stage', 'error', 'completed', 'lab_prepared'):
                self._report_events.append(event)

    def _start(self, operation, worker):
        self._guard()
        self._busy, self._job_id = True, uuid.uuid4().hex
        job = self._job_id
        self._cancelled.clear()
        def run():
            succeeded = False
            try:
                worker()
                succeeded = True
            except Exception as error:
                if operation in ('inspect_service', 'apply_service'):
                    with self._lock:
                        self._receipt, self._service_signature = None, None
                self._enqueue('error', **{key: value for key, value in self._error(error).items() if key != 'ok'})
            finally:
                with self._lock:
                    self._busy = False
                    self._events.append(dict(kind='done', job_id=job, operation=operation, success=succeeded))
        try:
            threading.Thread(target=run, daemon=True).start()
        except Exception:
            self._busy = False
            raise
        return dict(ok=True, job_id=job)

    def _progress(self, value):
        if not isinstance(value, dict):
            return
        stage, status = value.get('stage'), value.get('status')
        if stage not in backend.STAGES | set(SERVICE_STAGES) or status not in (
                'RUNNING', 'PASS', 'REFUSED', 'WARNING', 'SKIPPED', 'VERIFIED', 'FAILED', 'ERROR'):
            return
        safe = dict(stage=stage, status=status)
        code = value.get('code')
        if isinstance(code, str) and CODE.fullmatch(code) and code in backend.ERROR_CODES | set(self._errors) | DIAGNOSTIC_CODES:
            safe['code'] = code
        if stage == 'REFUSED' and code == 'APPLICATION_HEALTH_WAIT_FAILED':
            try:
                safe['diagnostic'] = backend.safe_startup_diagnostic(value.get('diagnostic'))
            except Exception:
                pass
        if stage == 'EXTERNAL_UPSTREAMS':
            try:
                safe['diagnostic'] = backend.validate_external_dependencies(value.get('diagnostic'))
            except Exception:
                pass
        self._enqueue('stage', **safe)

    def _confirm(self, endpoint, fingerprint, previous=None):
        if self._closed or self._cancelled.is_set():
            return False
        need(isinstance(endpoint, str) and re.fullmatch(r'[A-Za-z0-9_.:\[\]-]{1,300}', endpoint),
             'WEB_HOST_KEY_INVALID')
        need(isinstance(fingerprint, str) and FINGERPRINT.fullmatch(fingerprint), 'WEB_HOST_KEY_INVALID')
        need(previous is None or isinstance(previous, str) and FINGERPRINT.fullmatch(previous), 'WEB_HOST_KEY_INVALID')
        identifier, event = uuid.uuid4().hex, threading.Event()
        answer = [False]
        with self._lock:
            self._pending_keys[identifier] = (event, answer)
            values = dict(id=identifier, endpoint=endpoint, fingerprint=fingerprint, changed=previous is not None)
            if previous is not None:
                values['previous'] = previous
            self._events.append(dict(kind='host_key', job_id=self._job_id, **values))
        try:
            while not event.wait(0.1):
                if self._cancelled.is_set() or self._closed:
                    return False
            return answer[0] is True and not self._cancelled.is_set() and not self._closed
        finally:
            with self._lock:
                self._pending_keys.pop(identifier, None)

    def _confirm_key(self, endpoint, fingerprint):
        return self._confirm(endpoint, fingerprint)

    def _confirm_changed_key(self, endpoint, previous, current):
        return self._confirm(endpoint, current, previous)

    def _point(self, value, kind='point'):
        need(isinstance(value, dict) and isinstance(value.get('tag'), str) and backend.TAG.fullmatch(value['tag'])
             and isinstance(value.get('public_commit'), str) and backend.SHA.fullmatch(value['public_commit'])
             and type(value.get('aio_snapshot')) is bool, 'DR_RELEASE_METADATA_UNAVAILABLE')
        safe = {key: value[key] for key in ('tag', 'public_commit', 'aio_snapshot')}
        with self._lock:
            self._settings.update(dr_tag=safe['tag'], public_commit=safe['public_commit'])
            self._backup_has_aio = safe['aio_snapshot']
            self._invalidate(clear=False)
        if kind == 'point':
            self._enqueue(kind, **safe)
        return safe

    @public
    def initialize(self):
        with self._lock:
            need(not self._closed, 'WEB_CLOSED')
            # These are static module literals, never transport/input text.
            from .app import ERRORS, TEXT
            self._errors = dict(ERRORS) | ERROR_TEXT | WEB_ERRORS
            self._stages.update(TEXT)
            return dict(ok=True, version=__version__, defaults={key: value for key, value in DEFAULTS.items()
                        if key not in SENSITIVE}, errors=self._errors.copy(), stages=self._stages.copy(),
                        progress_text=PROGRESS_TEXT.copy(),
                        phase_stages={name: sorted(stages) for name, stages in PHASE_STAGES.items()},
                        finished_stages=sorted(FINISHED_STAGES))

    @public
    def update_settings(self, settings):
        with self._lock:
            self._guard()
            self._update(settings)
            return dict(ok=True, revision=self._revision)

    @public
    def load_backups(self, settings):
        with self._lock:
            self._guard()
            self._update(settings)
            token, old = self._settings['github_token'], self._settings['dr_tag']
            def worker():
                github = backend.GitHub(token)
                tags, _ = github.choices()
                need(isinstance(tags, list) and 0 < len(tags) <= 100
                     and all(isinstance(tag, str) and backend.TAG.fullmatch(tag) for tag in tags), 'PUBLISHED_RELEASE_REQUIRED')
                chosen = old if old in tags else tags[0]
                point = github.point(chosen)
                self._active()
                self._enqueue('choices', tags=tags)
                self._point(point)
            return self._start('load_backups', worker)

    @public
    def load_backup(self, tag):
        with self._lock:
            self._guard()
            need(isinstance(tag, str) and backend.TAG.fullmatch(tag), 'SELECT_GITHUB_RECOVERY_POINT')
            token = self._settings['github_token']
            def worker():
                point = backend.GitHub(token).point(tag)
                self._active()
                self._point(point)
            return self._start('load_backup', worker)

    @public
    def prepare_lab(self, settings):
        with self._lock:
            self._guard()
            self._update(settings)
            snapshot = self._settings.copy()
            def worker():
                result = self._controller.prepare_lab(snapshot, self._progress)
                self._active()
                need(isinstance(result, dict) and result.get('status') == 'PREPARED_LAB'
                     and result.get('applications_started') is False and result.get('publications_enabled') is False
                     and result.get('backup_verified') is False
                     and isinstance(result.get('checks'), dict) and
                     all(result['checks'].get(key) is True for key in ('infisical_restored', 'stack_prepared',
                         'agent_installed', 'lab_scope_recorded')), 'SERVICE_LAB_PREPARATION_INCOMPLETE')
                with self._lock:
                    self._invalidate()
                user = snapshot['user']
                need(re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user), 'SSH_ADDRESS_REQUIRED')
                self._enqueue('lab_prepared', status='PREPARED_LAB', stack_root='/home/' + user + '/streams-aio',
                              verification_scope='local_lab', applications_started=False,
                              publications_enabled=False, backup_verified=False,
                              checks={key: True for key in ('infisical_restored', 'stack_prepared', 'agent_installed', 'lab_scope_recorded')})
            return self._start('prepare_lab', worker)

    @staticmethod
    def _host(data, prefix=''):
        return backend.Host(data[prefix + 'host'], data[prefix + 'user'], int(data[prefix + 'port'] or '22'),
            data[prefix + 'password'], data['infisical_key' if prefix else 'ssh_key'],
            data[prefix + 'key_password'], data[prefix + 'sudo_password'])

    @public
    def recover(self, settings, action):
        with self._lock:
            self._guard()
            self._update(settings)
            need(action in ('fresh', 'resume'), 'OPERATIONAL_DEPLOYMENT_REFUSED')
            data = operational_request(self._settings.copy(), action)
            if action == 'fresh':
                try:
                    address = ipaddress.ip_address(data.get('domain_target_address', ''))
                except ValueError:
                    raise BridgeFailure('PUBLIC_DOMAIN_CONFIGURATION_REQUIRED') from None
                need(str(address) == data['domain_target_address'] and not address.is_unspecified
                     and not address.is_multicast, 'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')
                need(data['routing_mode'] in ('parallel_test', 'production_recovery'), 'OPERATIONAL_DEPLOYMENT_REFUSED')
                need(backend.SHA.fullmatch(data['public_commit']) and backend.TAG.fullmatch(data['dr_tag']), 'SELECT_GITHUB_RECOVERY_POINT')
                need(self._backup_has_aio is not False, 'AIO_SNAPSHOT_REQUIRED')
            try:
                stack_host, server_host = self._host(data), self._host(data, 'infisical_')
                stack_host.validate(); server_host.validate()
            except backend.Failure:
                raise
            except Exception:
                raise BridgeFailure('SSH_ADDRESS_REQUIRED') from None
            need(data['host'] != data['infisical_host'], 'SEPARATE_RECOVERY_VMS_REQUIRED')
            validate_identity_input(data)
            if action == 'fresh':
                need(not data.get('supplemental_inputs') or Path(data['supplemental_inputs']).is_file(), 'RECOVERY_SUPPLEMENT_INVALID')
            def worker():
                stack = server = None
                infrastructure = [False]
                def progress(value):
                    if isinstance(value, dict) and value.get('stage') == 'OPERATIONAL_READY' and value.get('status') == 'PASS':
                        infrastructure[0] = True
                    self._progress(value)
                try:
                    stack = backend.SSH(stack_host, self._confirm_key, self._cancelled, confirm_changed_key=self._confirm_changed_key)
                    server = backend.SSH(server_host, self._confirm_key, self._cancelled, confirm_changed_key=self._confirm_changed_key)
                    request = data
                    if action == 'resume':
                        request = backend.resolve_resume_request(stack, server, data)
                        need(request.get('routing_mode') in ('parallel_test', 'production_recovery'),
                             'OPERATIONAL_DEPLOYMENT_REFUSED')
                        try:
                            address = ipaddress.ip_address(request.get('domain_target_address', ''))
                        except (TypeError, ValueError):
                            raise BridgeFailure('PUBLIC_DOMAIN_CONFIGURATION_REQUIRED') from None
                        need(isinstance(request.get('domain_target_address'), str)
                             and str(address) == request['domain_target_address']
                             and not address.is_unspecified and not address.is_multicast,
                             'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')
                        if (request['dr_tag'], request['public_commit']) != (data['dr_tag'], data['public_commit']):
                            request = dict(request, supplemental_inputs='')
                        point = backend.GitHub(data['github_token']).point(request['dr_tag'])
                        need(point.get('public_commit') == request['public_commit'], 'DR_STACK_COMMIT_MISMATCH')
                        need(point.get('aio_snapshot') is True, 'AIO_SNAPSHOT_BACKUP_REQUIRED')
                        safe = self._point(point, kind='resumed_selection')
                        with self._lock:
                            self._settings.update(routing_mode=request['routing_mode'], domain_target_address=request['domain_target_address'])
                        self._enqueue('resumed_selection', point=safe, routing_mode=request['routing_mode'],
                                      domain_target_address=request['domain_target_address'])
                    need(not request.get('supplemental_inputs') or Path(request['supplemental_inputs']).is_file(),
                         'RECOVERY_SUPPLEMENT_INVALID')
                    detected = backend.inspect_recovery(stack, server, request)
                    safe = {}
                    for role in ('stack', 'infisical'):
                        title, detail = machine_status(detected.get(role), role)
                        safe[role] = dict(title=title, detail=detail)
                    self._enqueue('detected', **safe)
                    backend.restore_all(stack, server, request, progress, tls=True)
                    self._active()
                    need(infrastructure[0], 'RECOVERY_OPERATION_INCOMPLETE')
                    self._enqueue('completed', operation='recovery', status='PASS',
                                  checks=dict(infrastructure=True, functional=False))
                finally:
                    for client in (server, stack):
                        if client is not None:
                            try:
                                client.close()
                            except Exception:
                                pass
            return self._start('recover', worker)

    @staticmethod
    def _sources(payload, prepare=False):
        allowed = {'compose', 'env', 'service_name'} | ({'private_names', 'private_values', 'reviewed'} if prepare else set())
        need(isinstance(payload, dict) and set(payload) <= allowed)
        values = tuple(payload.get(key, '') for key in ('compose', 'env', 'service_name'))
        need(all(isinstance(value, str) and len(value) <= MAX_INPUT and '\x00' not in value for value in values))
        return values

    @public
    def analyze_service(self, payload):
        with self._lock:
            self._guard()
            self._invalidate()
            rows = inspect_inputs(*self._sources(payload))
            return dict(ok=True, variables=[dict(name=row.name, source=row.source,
                suggested_private=row.suggested_private, selected_private=row.selected_private,
                has_value=row.has_value) for row in rows])

    @public
    def prepare_service(self, payload):
        with self._lock:
            self._guard()
            self._invalidate()
            sources = self._sources(payload, prepare=True)
            need(payload.get('reviewed') is True, 'SERVICE_REVIEW_REQUIRED')
            names, values = payload.get('private_names', []), payload.get('private_values', {})
            need(isinstance(names, list) and len(names) <= 200 and len(set(names)) == len(names)
                 and all(isinstance(name, str) and ENV_NAME.fullmatch(name) for name in names), 'SERVICE_PRIVATE_VALUES_INVALID')
            need(isinstance(values, dict) and len(values) <= 200 and set(values) <= set(names)
                 and all(isinstance(value, str) and len(value) <= 16384 for value in values.values()), 'SERVICE_PRIVATE_VALUES_INVALID')
            self._analysis = analyze_inputs(*sources, private_names=names, private_values=values)
            return dict(ok=True, plan=self._analysis.plan.to_public_dict())

    def _service_inputs(self, payload):
        need(self._analysis is not None, 'SERVICE_ANALYSIS_REQUIRED')
        need(isinstance(payload, dict) and set(payload) <= {'stack_root', 'probe_url', 'verification_scope', 'infisical'})
        need(all(isinstance(payload.get(key, ''), str) for key in ('stack_root', 'probe_url', 'verification_scope')))
        private = payload.get('infisical', {})
        need(isinstance(private, dict) and set(private) <= {'endpoint', 'project_id', 'environment', 'access_token'}
             and all(isinstance(value, str) and len(value) <= 16384 for value in private.values()))
        connection = connection_from_snapshot(self._settings, payload.get('stack_root', ''),
            probe_url=payload.get('probe_url', ''), verification_scope=payload.get('verification_scope', 'full'))
        infisical = infisical_from_fields(*(private.get(key, '') for key in ('endpoint', 'project_id', 'environment', 'access_token')),
            private_required=bool(self._analysis.plan.private_bindings))
        raw = json.dumps([connection, infisical], sort_keys=True).encode()
        signature = hmac.digest(self._binding_key, raw, 'sha256')
        return self._analysis, connection, infisical, signature

    @public
    def inspect_service(self, payload):
        with self._lock:
            self._guard()
            analysis, connection, infisical, signature = self._service_inputs(payload)
            self._receipt, self._service_signature = None, None
            revision = self._revision
            def worker():
                receipt = self._controller.inspect(analysis, connection, infisical, self._progress)
                self._active()
                with self._lock:
                    need(revision == self._revision, 'SERVICE_INPUTS_CHANGED')
                    self._receipt, self._service_signature = receipt, signature
                self._enqueue('inspected', verification_scope=connection['verification_scope'])
            return self._start('inspect_service', worker)

    @public
    def apply_service(self, payload):
        with self._lock:
            self._guard()
            analysis, connection, infisical, signature = self._service_inputs(payload)
            need(self._receipt is not None, 'SERVICE_INSPECTION_REQUIRED')
            if self._service_signature is None or not hmac.compare_digest(self._service_signature, signature):
                self._receipt = None
                raise BridgeFailure('SERVICE_INPUTS_CHANGED')
            receipt, revision = self._receipt, self._revision
            def worker():
                result = self._controller.apply(analysis, connection, infisical, receipt, self._progress)
                self._active()
                local = connection['verification_scope'] == 'local_lab'
                need(verified_local_completion(result) if local else verified_completion(result), 'SERVICE_OPERATION_INCOMPLETE')
                with self._lock:
                    need(revision == self._revision, 'SERVICE_INPUTS_CHANGED')
                    self._invalidate()
                safe = dict(operation='service', status='PASS_LOCAL' if local else 'PASS',
                            checks=dict(service=True, agent=True, github=not local, backup=not local))
                if not local:
                    safe.update(public_commit=result['public_commit'], backup_tag=result['backup_tag'])
                self._enqueue('completed', **safe)
            return self._start('apply_service', worker)

    @public
    def invalidate_service(self):
        with self._lock:
            self._guard()
            self._invalidate()
            return dict(ok=True)

    @public
    def poll(self):
        with self._lock:
            events, size = [], 0
            while self._events and len(events) < 64:
                next_size = len(json.dumps(self._events[0], ensure_ascii=True))
                if events and size + next_size > 128 * 1024:
                    break
                events.append(self._events.popleft())
                size += next_size
            return dict(ok=True, busy=self._busy, events=events)

    @public
    def answer_host_key(self, identifier, approved):
        with self._lock:
            need(isinstance(identifier, str) and JOB.fullmatch(identifier) and type(approved) is bool, 'WEB_HOST_KEY_INVALID')
            need(identifier in self._pending_keys, 'WEB_HOST_KEY_INVALID')
            event, answer = self._pending_keys[identifier]
            answer[0] = approved
            event.set()
            return dict(ok=True)

    @public
    def cancel(self):
        with self._lock:
            self._cancelled.set()
            for event, answer in self._pending_keys.values():
                answer[0] = False
                event.set()
            return dict(ok=True)

    def _close(self):
        with self._lock:
            self._closed = True
            self._cancelled.set()
            for event, answer in self._pending_keys.values():
                answer[0] = False
                event.set()
            self._settings = DEFAULTS.copy()
            self._invalidate()
            self._events.clear()

    def _is_busy(self):
        with self._lock:
            return self._busy

    def _report(self):
        with self._lock:
            return dict(schema=1, version=__version__, events=json.loads(json.dumps(list(self._report_events))))

    def _public_plan(self):
        with self._lock:
            return self._analysis.plan.to_public_dict() if self._analysis is not None else None

    def _set_window(self, window):
        # The narrow host façade owns file dialogs; no window object is exposed.
        pass

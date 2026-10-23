"""Explicit application startup, on the prepared replacement host only."""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

DEFERRED = {'watchtower', 'wud', 'cloudflare-ddns', 'deunhealth'}
TLS_CODES = frozenset('TLS_NPM_' + phase + '_FAILED' for phase in (
    'DNS01_ISSUANCE', 'CERTIFICATE', 'ACCESS_LISTS_REBUILD', 'NGINX_GENERATE',
    'NGINX_TEST', 'NGINX_RELOAD', 'TLS_LOOPBACK', 'HTTPS_UPSTREAM'))
PINNED_IMAGE = re.compile(r'[^@\s]+@sha256:[0-9a-f]{64}\Z')
STARTUP_CODES = {
    'LAB_APPLICATION_START_REFUSED', 'LAB_RUNTIME_SCOPE_REFUSED',
    'LOCAL_ENDPOINTS_RELOCATION_REFUSED', 'LOCAL_ENDPOINTS_SOURCE_DRIFT',
    'HEADPLANE_CONTROLLER_CONFIGURATION_REQUIRED', 'HEADPLANE_BOOTSTRAP_SCOPE_REFUSED',
    'HEADPLANE_BOOTSTRAP_STATE_CHANGED', 'HEADPLANE_CONTROLLER_API_PROBE_FAILED',
    'HEADPLANE_API_BOOTSTRAP_FAILED', 'HEADPLANE_RECREATE_FAILED',
    'APPLICATION_IMAGE_DOWNLOAD_FAILED', 'APPLICATION_PINNED_IMAGES_REQUIRED',
    'APPLICATION_IMAGE_PLATFORM_REFUSED', 'APPLICATION_HEALTH_WAIT_FAILED',
    'APPLICATION_FINAL_CHECK_FAILED',
    'SERVICE_HEALTHCHECK_REQUIRED', 'PGBOUNCER_NOT_READY', 'TLS_VERIFICATION_FAILED',
    'COMPOSE_PROJECT_REQUIRED', 'FOREIGN_CONTAINER_REFUSED', 'FOREIGN_VOLUME_REFUSED',
    'EXTERNAL_VOLUME_REFUSED', 'RESTORE_WAVES_REQUIRE_REVIEW',
    'SYMLINK_PATH_REFUSED', 'PRIVATE_CHECKPOINT_REQUIRED', 'PREPARED_REPLACEMENT_REQUIRED',
    'ROOT_START_INSTALLER_REQUIRED', 'RECOVERY_ALREADY_RUNNING',
    'RUNTIME_PROFILE_CHANGED', 'RUNTIME_PROFILE_SOURCE_CHANGED',
    'RUNTIME_PROFILE_SCOPE_REFUSED', 'RUNTIME_PROFILE_PATH_REFUSED',
    'RUNTIME_PROFILE_DEPENDENCY_REFUSED',
    'RUNTIME_PROFILE_ENV_REFUSED', 'FRESH_RENDERER_REFUSED',
    'RUNTIME_PROFILE_PRESTART_CHECKPOINT_REQUIRED',
    'RECOVERY_TREE_MODIFIED', 'RECOVERY_COMMIT_CHANGED',
    'COMETNET_TRIAL_SCOPE_REFUSED', 'COMETNET_TRIAL_TLS_REFUSED',
    'COMETNET_TRIAL_TRANSACTION_FAILED',
    'RUNTIME_PROFILE_TRANSACTION_FAILED', 'RUNTIME_PROFILE_CANDIDATE_REFUSED',
    'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED',
    'OPERATIONAL_DEPLOYMENT_REFUSED', 'OPERATIONAL_PROFILE_TRANSACTION_FAILED',
    'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED', 'PUBLIC_DOMAIN_TARGET_MISMATCH',
    'PUBLIC_DOMAIN_PROBE_FAILED', 'PUBLIC_DOMAIN_PROBE_CLEANUP_REQUIRED',
    'PUBLIC_CONTROLLER_CUTOVER_REQUIRED', 'OPERATIONAL_TLS_REQUIRED',
    'NPM_TOPOLOGY_BACKUP_REQUIRED', 'NPM_TOPOLOGY_ADDRESS_INVALID',
    'NPM_TOPOLOGY_ALREADY_MOUNTED', 'NPM_TOPOLOGY_APPLY_FAILED',
    'NPM_TOPOLOGY_DATABASE_INVALID', 'NPM_TOPOLOGY_DATABASE_IDENTITY_REQUIRED',
    'NPM_TOPOLOGY_ENDPOINT_UNPROVEN', 'NPM_TOPOLOGY_EVIDENCE_REQUIRED',
    'NPM_TOPOLOGY_INVALID', 'NPM_TOPOLOGY_JOURNAL_INVALID', 'NPM_TOPOLOGY_PATH_INVALID',
    'NPM_TOPOLOGY_PRIVATE_FILE_REQUIRED', 'NPM_TOPOLOGY_SCHEMA_UNSUPPORTED',
    'NPM_TOPOLOGY_SERVICE_UNPROVEN', 'NPM_TOPOLOGY_SOURCE_DRIFT',
    'NPM_TOPOLOGY_SOURCE_INVALID', 'NPM_TOPOLOGY_TARGET_INVALID',
    'NPM_TOPOLOGY_UNCLASSIFIED_REFERENCE',
    'TAILSCALE_CONTROLLER_CONFIGURATION_REQUIRED', 'TAILSCALE_CONTROLLER_DNS_MISMATCH',
    'TAILSCALE_CONTROLLER_UNREACHABLE', 'TAILSCALE_CONTROLLER_TARGET_MISMATCH',
    'TAILSCALE_CONTROLLER_PROBE_FAILED', 'TAILSCALE_CONTROLLER_PROBE_CLEANUP_REQUIRED',
    'TAILSCALE_CONTROLLER_OWNERSHIP_REFUSED', 'TAILSCALE_CONTROLLER_IMAGE_REFUSED',
    'TAILSCALE_CONTROLLER_NOT_HEALTHY', 'TAILSCALE_HEADSCALE_ENROLLMENT_REQUIRED',
    'TAILSCALE_PROFILE_SCOPE_REFUSED', 'TAILSCALE_PROFILE_KEY_REFUSED',
    'TAILSCALE_PROFILE_TRANSACTION_FAILED',
}
STARTUP_CODES.update(TLS_CODES)
DIAGNOSTIC_SERVICES = frozenset('aiomanager aiometadata aiostreams cloudflare-ddns comet cometnet '
    'deunhealth dnscrypt-proxy easyproxy gluetun gost headplane headscale honey jackett '
    'mediaflow-proxy-light microwarp npm oauth2-proxy pgbouncer portainer postgres redis '
    'seanime seanime-shared streamvix stremthru tailscale teamspeak tvvoo watchtower wud'.split())
DIAGNOSTIC_STATUSES = frozenset({'NOT_STARTED', 'RUNNING', 'HEALTHY', 'UNHEALTHY', 'STARTING',
    'RESTARTING', 'PAUSED', 'EXITED', 'CREATED', 'DEAD', 'UNKNOWN', 'DEFERRED'})
TAILSCALE_BACKEND_STATES = frozenset({'Running', 'NeedsLogin', 'NeedsMachineAuth',
    'Stopped', 'NoState', 'Starting', 'InUseOtherUser'})
TAILSCALE_SIGNALS = frozenset({'LOGIN_SERVER_KEY_FAILED', 'TS_UP_FAILED',
    'AUTH_KEY_REJECTED', 'TUN_CREATE_FAILED'})


class StartupFailure(ValueError):
    def __init__(self, diagnostic):
        super().__init__('APPLICATION_HEALTH_WAIT_FAILED')
        self.diagnostic = diagnostic


class EarlyUnhealthy(ValueError):
    """Compose stopped on an unhealthy check before its wait deadline."""


def emit(stage, status='PASS'):
    print('RECOVERY_EVENT ' + json.dumps(dict(stage=stage, status=status)), flush=True)


def external_dependency_report(raw):
    records = [line[len('NPM_EXTERNAL_REPORT '):] for line in raw.decode('utf-8').splitlines()
               if line.startswith('NPM_EXTERNAL_REPORT ')]
    if len(records) != 1:
        raise ValueError('TLS_VERIFICATION_FAILED')
    value = json.loads(records[0])
    if (not isinstance(value,dict) or set(value) != {'schema','total','unavailable'}
            or type(value['schema']) is not int or value['schema'] != 1
            or type(value['total']) is not int or not 0 <= value['total'] <= 4096
            or not isinstance(value['unavailable'],list)
            or any(type(v) is not int or not 1 <= v <= 2**31-1 for v in value['unavailable'])
            or value['unavailable'] != sorted(set(value['unavailable']))
            or len(value['unavailable']) > value['total']):
        raise ValueError('TLS_VERIFICATION_FAILED')
    return value


def call(args, root):
    env = {k: v for k, v in os.environ.items() if not k.startswith(('COMPOSE_', 'INFISICAL_', 'PYTHON'))}
    p = subprocess.run([str(x) for x in args], cwd=root, env=env, capture_output=True, timeout=1800)
    if p.returncode:
        if (len(args) in (6, 8) and args[:2] == [sys.executable, '-B']
                and Path(args[2]) == Path(__file__).with_name('npm_runtime.py')
                and args[3] in ('reissue', 'verify') and args[4] == '--target'
                and Path(args[5]) == Path(root)
                and (len(args) == 6 or args[3] == 'verify' and args[6] == '--state-home'
                     and Path(args[7]).is_absolute())):
            raw = p.stdout.decode('ascii', 'replace').strip()
            if raw.startswith('NPM DR_REFUSED ') and raw[len('NPM DR_REFUSED '):] in TLS_CODES:
                raise ValueError(raw[len('NPM DR_REFUSED '):])
        if (args[:5] == ['docker', 'compose', '--profile', 'all', 'up']
                and re.search(rb'(?:^|\n)container [A-Za-z0-9][A-Za-z0-9_.-]{0,250} is unhealthy\r?(?:\n|$)',
                              p.stderr[-4096:])):
            raise EarlyUnhealthy('SERVICE_START_OR_CHECK_FAILED')
        raise ValueError('SERVICE_START_OR_CHECK_FAILED')
    return p.stdout


def wait_wave_ready(compose, root, selected, deadline, reader=None,
                    clock=None, sleeper=None):
    """Use the remaining original budget without restarting or weakening health."""
    clock, sleeper = clock or time.monotonic, sleeper or time.sleep
    if not selected or len(selected) != len(set(selected)) or not set(selected) <= set(compose['services']):
        raise ValueError('APPLICATION_HEALTH_WAIT_FAILED')
    if reader is None:
        def reader(args):
            remaining = deadline - clock()
            if remaining <= 0:
                raise ValueError('APPLICATION_HEALTH_WAIT_FAILED')
            env = {k:v for k,v in os.environ.items()
                   if not k.startswith(('COMPOSE_', 'INFISICAL_', 'PYTHON'))
                   and k not in {'GH_TOKEN', 'GITHUB_TOKEN'}}
            result = subprocess.run(args, cwd=root, env=env, capture_output=True,
                                    timeout=min(5, remaining))
            if result.returncode or len(result.stdout) > 16*1024**2:
                raise ValueError('APPLICATION_HEALTH_WAIT_FAILED')
            return result.stdout
    refs = [compose['services'][name]['image'] for name in selected]
    if any(not isinstance(ref, str) or not PINNED_IMAGE.fullmatch(ref) for ref in refs):
        raise ValueError('APPLICATION_PINNED_IMAGES_REQUIRED')
    image_ids = reader(['docker', 'image', 'inspect', '--format', '{{.Id}}', *refs]).decode('ascii').split()
    if len(image_ids) != len(selected) or any(not re.fullmatch(r'sha256:[0-9a-f]{64}', v) for v in image_ids):
        raise ValueError('APPLICATION_HEALTH_WAIT_FAILED')
    expected_images = dict(zip(selected, image_ids))
    original_ids, original_restarts = None, None
    while clock() < deadline:
        ids = reader(['docker', 'compose', '--profile', 'all', 'ps', '-aq', '--', *selected]).decode('ascii').split()
        if (len(ids) != len(selected) or len(ids) != len(set(ids))
                or any(not re.fullmatch(r'[0-9a-f]{12,64}', v) for v in ids)):
            raise ValueError('APPLICATION_HEALTH_WAIT_FAILED')
        containers = json.loads(reader(['docker', 'inspect', *ids]))
        if not isinstance(containers, list) or len(containers) != len(selected):
            raise ValueError('APPLICATION_HEALTH_WAIT_FAILED')
        validate_runtime(compose, root, containers, [])
        rows = {c['Config']['Labels']['com.docker.compose.service']:c for c in containers}
        if len(rows) != len(containers) or set(rows) != set(selected):
            raise ValueError('APPLICATION_HEALTH_WAIT_FAILED')
        current_ids, restarts, ready = {}, {}, True
        for name, container in rows.items():
            state, config = container['State'], container['Config']
            current_ids[name] = container['Id']
            restarts[name] = container['RestartCount']
            if (container['Id'] not in ids or config.get('Image') != compose['services'][name]['image']
                    or container['Image'] != expected_images[name]
                    or state.get('Running') is not True or state.get('Status') != 'running'
                    or any(state.get(k) is not False for k in ('Paused', 'Restarting', 'Dead', 'OOMKilled'))
                    or type(restarts[name]) is not int or restarts[name] < 0):
                raise ValueError('APPLICATION_HEALTH_WAIT_FAILED')
            healthcheck = config.get('Healthcheck') or {}
            enabled = bool(healthcheck.get('Test')) and healthcheck['Test'][0] != 'NONE'
            health = (state.get('Health') or {}).get('Status')
            if enabled:
                if health not in ('starting', 'unhealthy', 'healthy'):
                    raise ValueError('APPLICATION_HEALTH_WAIT_FAILED')
                ready = ready and health == 'healthy'
            elif health is not None:
                raise ValueError('APPLICATION_HEALTH_WAIT_FAILED')
        if original_ids is None:
            original_ids, original_restarts = current_ids, restarts
        if current_ids != original_ids or restarts != original_restarts:
            raise ValueError('APPLICATION_HEALTH_WAIT_FAILED')
        if ready and clock() < deadline:
            return
        remaining = deadline - clock()
        if remaining > 0:
            sleeper(min(5, remaining))
    raise ValueError('APPLICATION_HEALTH_WAIT_FAILED')


def start_wave(compose, root, selected):
    deadline = time.monotonic() + 300
    try:
        try:
            call(['docker', 'compose', '--profile', 'all', 'up', '-d', '--no-deps', '--wait',
                  '--wait-timeout', '300', *selected], root)
        except EarlyUnhealthy:
            wait_wave_ready(compose, root, selected, deadline)
    except Exception:
        raise StartupFailure(startup_diagnostic(compose, root, selected)) from None


def validate_runtime(compose, root, containers, volumes):
    """Only resume resources belonging to this exact replacement deployment."""
    project = compose.get('name')
    if not isinstance(project, str) or not project:
        raise ValueError('COMPOSE_PROJECT_REQUIRED')
    expected = compose.get('services', {})
    for container in containers:
        labels = container.get('Config', {}).get('Labels') or {}
        if (labels.get('com.docker.compose.project.working_dir') != str(root)
                or labels.get('com.docker.compose.project') != project
                or labels.get('com.docker.compose.service') not in expected):
            raise ValueError('FOREIGN_CONTAINER_REFUSED')
    declared = compose.get('volumes', {})
    if any(item.get('external') for item in declared.values()):
        raise ValueError('EXTERNAL_VOLUME_REFUSED')
    for volume in volumes:
        labels = volume.get('Labels') or {}
        key = labels.get('com.docker.compose.volume')
        if (labels.get('com.docker.compose.project') != project or key not in declared
                or volume.get('Name') != declared[key].get('name')):
            raise ValueError('FOREIGN_VOLUME_REFUSED')


def diagnostic_unavailable(status='UNAVAILABLE', wave=()):
    valid_wave = (isinstance(wave, (tuple, list)) and len(wave) <= len(DIAGNOSTIC_SERVICES)
                  and all(isinstance(name, str) and name in DIAGNOSTIC_SERVICES for name in wave)
                  and len(wave) == len(set(wave)))
    return dict(schema=1, status=status, wave=list(wave) if valid_wave else [], services={})


def diagnostic_safe(value):
    """Producer boundary also rejects unexpected fields and private canaries."""
    try:
        if (not isinstance(value, dict)
                or set(value) not in ({'schema', 'status', 'wave', 'services'},
                                      {'schema', 'status', 'wave', 'services', 'tailscale'})
                or type(value['schema']) is not int or value['schema'] != 1
                or value['status'] not in {'COMPLETE', 'UNAVAILABLE', 'OWNERSHIP_REFUSED'}):
            raise ValueError()
        wave, rows = value['wave'], value['services']
        if (not isinstance(wave, list) or len(wave) > len(DIAGNOSTIC_SERVICES)
                or any(not isinstance(name, str) or name not in DIAGNOSTIC_SERVICES for name in wave)
                or len(wave) != len(set(wave)) or not isinstance(rows, dict)
                or not set(rows) <= DIAGNOSTIC_SERVICES
                or value['status'] != 'COMPLETE' and rows
                or value['status'] == 'COMPLETE' and (not rows or not set(wave) <= set(rows))):
            raise ValueError()
        fields = {'status', 'exit_code', 'health_exit_code', 'restarts', 'oom_killed'}
        for row in rows.values():
            if (not isinstance(row, dict) or set(row) != fields
                    or row['status'] not in DIAGNOSTIC_STATUSES):
                raise ValueError()
            for key in ('exit_code', 'health_exit_code', 'restarts'):
                maximum = 10000 if key == 'restarts' else 255
                if row[key] is not None and (type(row[key]) is not int or not 0 <= row[key] <= maximum):
                    raise ValueError()
            if row['oom_killed'] is not None and type(row['oom_killed']) is not bool:
                raise ValueError()
        if 'tailscale' in value:
            detail = value['tailscale']
            if (value['status'] != 'COMPLETE' or 'tailscale' not in wave
                    or not isinstance(detail, dict) or set(detail) != {'backend_state', 'signals'}
                    or detail['backend_state'] is not None
                    and (not isinstance(detail['backend_state'], str)
                         or detail['backend_state'] not in TAILSCALE_BACKEND_STATES)):
                raise ValueError()
            signals = detail['signals']
            if (not isinstance(signals, list) or len(signals) > len(TAILSCALE_SIGNALS)
                    or any(not isinstance(signal, str) or signal not in TAILSCALE_SIGNALS
                           for signal in signals) or signals != sorted(set(signals))):
                raise ValueError()
        return value
    except (ValueError, TypeError, KeyError):
        return diagnostic_unavailable()


def diagnostic_status(state):
    if state.get('Restarting') is True:
        return 'RESTARTING'
    if state.get('Paused') is True:
        return 'PAUSED'
    if state.get('Running') is not True:
        return {'created':'CREATED', 'dead':'DEAD', 'exited':'EXITED'}.get(state.get('Status'), 'UNKNOWN')
    health = state.get('Health')
    if health is None:
        return 'RUNNING'
    if not isinstance(health, dict):
        return 'UNKNOWN'
    return {'healthy':'HEALTHY', 'unhealthy':'UNHEALTHY', 'starting':'STARTING'}.get(
        health.get('Status'), 'UNKNOWN')


def tailscale_diagnostic(compose, container, reader):
    """After ownership/uniqueness checks, classify private output into fixed codes."""
    try:
        reference = compose['services']['tailscale']['image']
        identity = container['Id']
        image = container['Image']
        if (not isinstance(reference, str) or not PINNED_IMAGE.fullmatch(reference)
                or container['Config'].get('Image') != reference
                or not isinstance(identity, str) or not re.fullmatch(r'[0-9a-f]{64}', identity)
                or not isinstance(image, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', image)):
            return None
        expected = reader(['docker', 'image', 'inspect', '--format', '{{.ID}}', reference]).decode('ascii').strip()
        if image != expected:
            return None
    except Exception:
        return None
    signals, backend, available = set(), None, False
    try:
        raw = reader(['docker', 'logs', '--tail', '80', identity])
        if len(raw) > 262144:
            raise ValueError()
        text = raw.decode('utf-8', 'replace')
        patterns = {
            'LOGIN_SERVER_KEY_FAILED': r'\b(?:fetch(?:ing)?|get(?:ting)?)\b[^\r\n]{0,60}\b(?:login server|server|control)\b[^\r\n]{0,50}\bkey\b[^\r\n]{0,120}\b(?:failed|error|dial|refused)\b',
            'TS_UP_FAILED': r'\bfailed to (?:bring|run)[^\r\n]{0,80}\btailscale\b|\btailscale\s+up\b[^\r\n]{0,100}\b(?:failed|exit status)\b|\btailscale\b[^\r\n]{0,50}\bup failed\b',
            'AUTH_KEY_REJECTED': r'\b(?:auth|preauth)[ -]?key\b[^\r\n]{0,80}\b(?:invalid|expired|already used|revoked)\b|\b(?:invalid|expired|already used|revoked)\b[^\r\n]{0,40}\b(?:auth|preauth)[ -]?key\b',
            'TUN_CREATE_FAILED': r'\b(?:CreateTUN|create TUN|tstun\.New)\b[^\r\n]{0,120}\b(?:failed|error|not permitted|permission denied|no such file)\b|\bfailed to create (?:a )?TUN\b',
        }
        signals.update(name for name, pattern in patterns.items() if re.search(pattern, text, re.I))
        available = True
    except Exception:
        pass
    try:
        raw = reader(['docker', 'exec', identity, 'tailscale', 'status', '--json'])
        if len(raw) > 262144:
            raise ValueError()
        status = json.loads(raw)
        candidate = status.get('BackendState') if isinstance(status, dict) else None
        if isinstance(candidate, str) and candidate in TAILSCALE_BACKEND_STATES:
            backend, available = candidate, True
    except Exception:
        pass
    return dict(backend_state=backend, signals=sorted(signals)) if available else None


def startup_diagnostic(compose, root, wave, reader=None):
    """Read once under the held recovery lock; never start or retry services.

    Full current ownership is rechecked after the failed wave, before any
    service metadata may be emitted. Unknown workloads produce no details.
    """
    unavailable = diagnostic_unavailable(wave=wave)
    try:
        services = compose.get('services')
        if (compose.get('name') != 'streams-aio' or not isinstance(services, dict)
                or not services or not set(services) <= DIAGNOSTIC_SERVICES
                or unavailable['wave'] != wave or not set(wave) <= set(services)):
            return unavailable
        deadline = time.monotonic() + 20
        if reader is None:
            def reader(args):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError()
                env = {key: value for key, value in os.environ.items()
                       if not key.startswith(('COMPOSE_', 'INFISICAL_', 'PYTHON'))
                       and key not in {'GH_TOKEN', 'GITHUB_TOKEN'}}
                result = subprocess.run(args, cwd=root, env=env, capture_output=True,
                                        timeout=min(5, remaining))
                output = (result.stdout + b'\n' + result.stderr
                          if args[:2] == ['docker', 'logs'] else result.stdout)
                limit = 262144 if args[:2] in (['docker', 'logs'], ['docker', 'exec']) else 4*1024**2
                if result.returncode or len(output) > limit:
                    raise ValueError()
                return output
        ids = reader(['docker', 'ps', '-aq']).decode('ascii').split()
        if len(ids) > len(DIAGNOSTIC_SERVICES) or any(not re.fullmatch(r'[0-9a-f]{12,64}', value) for value in ids):
            return unavailable
        containers = json.loads(reader(['docker', 'inspect', *ids])) if ids else []
        names = reader(['docker', 'volume', 'ls', '-q']).decode('ascii').split()
        if len(names) > 100 or any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', value) for value in names):
            return unavailable
        volumes = json.loads(reader(['docker', 'volume', 'inspect', *names])) if names else []
        if (not isinstance(containers, list) or len(containers) != len(ids)
                or not isinstance(volumes, list) or len(volumes) != len(names)):
            return unavailable
        try:
            validate_runtime(compose, root, containers, volumes)
        except ValueError:
            return diagnostic_unavailable('OWNERSHIP_REFUSED', wave)
        rows = {name: dict(status='DEFERRED' if name in DEFERRED else 'NOT_STARTED',
                    exit_code=None, health_exit_code=None, restarts=None, oom_killed=None)
                for name in sorted(services)}
        seen = set()
        def number(value, maximum):
            return value if type(value) is int and 0 <= value <= maximum else None
        for container in containers:
            name = container['Config']['Labels']['com.docker.compose.service']
            if name in seen:
                return unavailable
            seen.add(name)
            state = container.get('State')
            if not isinstance(state, dict):
                return unavailable
            health = state.get('Health') or {}
            logs = health.get('Log') if isinstance(health, dict) else None
            last = logs[-1] if isinstance(logs, list) and logs and isinstance(logs[-1], dict) else {}
            rows[name] = dict(status=diagnostic_status(state),
                exit_code=number(state.get('ExitCode'), 255),
                health_exit_code=number(last.get('ExitCode'), 255),
                restarts=number(container.get('RestartCount'), 10000),
                oom_killed=state.get('OOMKilled') if type(state.get('OOMKilled')) is bool else None)
        report = dict(schema=1, status='COMPLETE', wave=list(wave), services=rows)
        if 'tailscale' in wave and 'tailscale' in seen:
            tail = next(container for container in containers
                        if container['Config']['Labels']['com.docker.compose.service'] == 'tailscale')
            detail = tailscale_diagnostic(compose, tail, reader)
            if detail is not None:
                report['tailscale'] = detail
        return diagnostic_safe(report)
    except Exception:
        return unavailable


def emit_failure(error):
    code = failure_code(error)
    value = dict(stage='REFUSED', status='REFUSED', code=code)
    if code == 'APPLICATION_HEALTH_WAIT_FAILED' and isinstance(error, StartupFailure):
        value['diagnostic'] = diagnostic_safe(error.diagnostic)
    print('RECOVERY_EVENT ' + json.dumps(value), flush=True)


def prepare_images(compose, root, runner=None, deferred=DEFERRED):
    """Pull every active pinned image before checking inherited healthchecks."""
    runner = runner or call
    images = set()
    for name, service in compose['services'].items():
        if name in deferred:
            continue
        ref = service.get('image')
        if not isinstance(ref, str) or not PINNED_IMAGE.fullmatch(ref) or service.get('build'):
            raise ValueError('APPLICATION_PINNED_IMAGES_REQUIRED')
        images.add(ref)
    emit('IMAGES', 'RUNNING')
    for ref in sorted(images):
        args = ['docker', 'image', 'inspect', '--format',
                '{"id":{{json .Id}},"os":{{json .Os}},"arch":{{json .Architecture}}}', ref]
        try:
            raw = runner(args, root)
        except Exception:
            try:
                runner(['docker', 'pull', ref], root)
                raw = runner(args, root)
            except Exception:
                raise ValueError('APPLICATION_IMAGE_DOWNLOAD_FAILED') from None
        try:
            info = json.loads(raw)
            valid = (info.get('os') == 'linux' and info.get('arch') == 'amd64'
                     and re.fullmatch(r'sha256:[0-9a-f]{64}', info.get('id', '')))
        except Exception:
            valid = False
        if not valid:
            raise ValueError('APPLICATION_IMAGE_PLATFORM_REFUSED')
    emit('IMAGES')


def failure_code(error):
    """Do not forward arbitrary exceptions, subprocess output or private values."""
    if isinstance(error, BlockingIOError):
        return 'RECOVERY_ALREADY_RUNNING'
    code = str(error)
    return code if code in STARTUP_CODES else 'APPLICATION_START_REFUSED'


def final_service_check(compose, root, runner=None, deferred=DEFERRED):
    """Check the entire active set again after all dependency waves finish."""
    runner = runner or call
    emit('APPLICATION_CHECKS', 'RUNNING')
    expected = set(compose['services']) - deferred
    try:
        ids = runner(['docker', 'compose', '--profile', 'all', 'ps', '-aq'], root).split()
        if not ids:
            raise ValueError()
        fmt = ('{"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
               '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
               '"directory":{{json (index .Config.Labels "com.docker.compose.project.working_dir")}},'
               '"running":{{json .State.Running}},'
               '"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}}}')
        raw = runner(['docker', 'inspect', '--format', fmt, *[i.decode('ascii') for i in ids]], root)
        rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
        if (len(rows) != len(expected) or {row['service'] for row in rows} != expected
                or any(row['project'] != compose['name'] or row['directory'] != str(root)
                       or row['running'] is not True or row['health'] not in (None, 'healthy') for row in rows)):
            raise ValueError()
    except Exception:
        raise ValueError('APPLICATION_FINAL_CHECK_FAILED') from None
    emit('APPLICATION_CHECKS')


def relocate_local_endpoints(root, home, state, compose, containers, save):
    spec = importlib.util.spec_from_file_location('startup_local_endpoints',
                                                  Path(__file__).with_name('local_endpoints.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    emit('LOCAL_ENDPOINTS', 'RUNNING')
    evidence = module.apply(root, home, state, lambda args: call(args, root), save)
    if state.get('local_endpoints_runtime') != evidence['sha256']:
        affected = set(evidence['affected'])
        if 'headscale' in affected:
            # Headscale reads this file at boot; Headplane binds its inode.
            affected.add('headplane')
        owned = set()
        for row in containers:
            labels = row.get('Config', {}).get('Labels') or {}
            if (labels.get('com.docker.compose.project') == compose.get('name') == 'streams-aio'
                    and labels.get('com.docker.compose.project.working_dir') == str(root)):
                owned.add(labels.get('com.docker.compose.service'))
        selected = sorted(affected & owned & set(compose['services']))
        if selected:
            call(['docker', 'compose', '--profile', 'all', 'up', '-d', '--no-deps',
                  '--force-recreate', *selected], root)
        state['local_endpoints_runtime'] = evidence['sha256']
        save(home/'state.json', state)
    emit('LOCAL_ENDPOINTS')


def start(root, home, tls=False, operational=False, cutover=False,
          routing_mode=None, domain_target_address=None):
    state_path = home / 'state.json'
    if any(p.is_symlink() for path in (root, home, state_path) for p in (path, *path.parents)):
        raise ValueError('SYMLINK_PATH_REFUSED')
    if not state_path.is_file() or state_path.stat().st_mode & 0o077:
        raise ValueError('PRIVATE_CHECKPOINT_REQUIRED')
    state = json.loads(state_path.read_bytes())
    if state.get('lab_deployment') is not None:
        raise ValueError('LAB_APPLICATION_START_REFUSED')
    if state.get('target') != str(root) or state.get('machine_id') != Path('/etc/machine-id').read_text().strip() or state.get('preparation') != 'PASS':
        raise ValueError('PREPARED_REPLACEMENT_REQUIRED')
    # Do not let Compose adopt other workloads, same-name containers or old volumes.
    checks_spec = importlib.util.spec_from_file_location('startup_recovery_checks', Path(__file__).with_name('recover.py'))
    checks = importlib.util.module_from_spec(checks_spec)
    checks_spec.loader.exec_module(checks)
    checks.stack_preflight(root, state)
    profile_spec = importlib.util.spec_from_file_location('startup_runtime_profile', Path(__file__).with_name('runtime_profile.py'))
    profile = importlib.util.module_from_spec(profile_spec)
    profile_spec.loader.exec_module(profile)
    if profile.validate(root, home, state) is not True:
        raise ValueError('RUNTIME_PROFILE_PRESTART_CHECKPOINT_REQUIRED')
    compose = json.loads(call(['docker', 'compose', '--profile', 'all', 'config', '--format', 'json'], root))
    ids = call(['docker', 'ps', '-aq'], root).split()
    containers = json.loads(call(['docker', 'inspect', *[i.decode() for i in ids]], root)) if ids else []
    names = call(['docker', 'volume', 'ls', '-q'], root).split()
    volumes = json.loads(call(['docker', 'volume', 'inspect', *[n.decode() for n in names]], root)) if names else []
    validate_runtime(compose, root, containers, volumes)
    record = state.get('runtime_profile') or {}
    operational_policy = None
    deferred = DEFERRED
    if operational:
        if not tls:
            raise ValueError('OPERATIONAL_TLS_REQUIRED')
        operational_spec = importlib.util.spec_from_file_location('startup_operational_policy',
            Path(__file__).with_name('operational_profile.py'))
        operational_policy = importlib.util.module_from_spec(operational_spec)
        operational_spec.loader.exec_module(operational_policy)
        deployment = state.get('operational_deployment') or {}
        routing_mode = routing_mode or deployment.get('routing_mode')
        domain_target_address = domain_target_address or deployment.get('domain_target_address')
        # Refuse a missing explicit cutover before changing any checkpoint or
        # overlay. A parallel test never runs public controllers.
        operational_policy.deployment({'operational_deployment':dict(
            routing_mode=routing_mode, domain_target_address=domain_target_address)}, cutover)
        # Refuse a missing/drifted private relocation proof before changing
        # an overlay, pulling images or starting application containers.
        operational_policy.topology_targets(root,state)
        emit('OPERATIONAL_PROFILE', 'RUNNING')
        profile.promote_operational(root, home, state, compose, lambda args: call(args, root),
                                    routing_mode, domain_target_address)
        compose = json.loads(call(['docker', 'compose', '--profile', 'all', 'config', '--format', 'json'], root))
        validate_runtime(compose, root, containers, volumes)
        deferred = operational_policy.deployment(state, cutover)
        operational_policy.cometnet_endpoint(compose)
        emit('OPERATIONAL_PROFILE')
        relocate_local_endpoints(root, home, state, compose, containers, checks.save)
    elif record.get('id') is not None and record.get('id') == getattr(profile, 'OPERATIONAL_PROFILE', None):
        raise ValueError('OPERATIONAL_DEPLOYMENT_REFUSED')
    elif record.get('origin') == 'FIRST_BOOT':
        # This fixed first-boot profile is the .29 trial, where public DNS/TLS
        # and production P2P enrollment are outside the startup contract.
        if tls:
            raise ValueError('COMETNET_TRIAL_TLS_REFUSED')
        if record['id'] == profile.FIRST_BOOT_PROFILE:
            emit('COMETNET_TRIAL', 'RUNNING')
            profile.migrate_cometnet_trial(root, home, state, compose,
                lambda args: call(args, root), tls=False)
            # Resolve and validate again; never use the old Compose model to
            # adopt resources after committing an explicitly reviewed delta.
            compose = json.loads(call(['docker', 'compose', '--profile', 'all', 'config', '--format', 'json'], root))
            validate_runtime(compose, root, containers, volumes)
            emit('COMETNET_TRIAL')
    manifest = json.loads((root / 'config/dr-manifest.yaml').read_bytes())
    tailscale_policy = None
    headplane_policy = None
    plan = compose
    if operational and 'tailscale' in compose['services']:
        tailscale_spec = importlib.util.spec_from_file_location('startup_tailscale_policy',
            Path(__file__).with_name('tailscale_recovery.py'))
        tailscale_policy = importlib.util.module_from_spec(tailscale_spec)
        tailscale_spec.loader.exec_module(tailscale_policy)
        # This is a scheduling model, not a change to the effective deployment.
        # The private enrollment overlay is committed only after origin proof.
        plan = tailscale_policy.planned_model(root, compose)
        tailscale_policy.preflight_dns(root, compose, state, lambda args: call(args, root))
    if operational and 'headplane' in compose['services']:
        headplane_spec = importlib.util.spec_from_file_location('startup_headplane_policy',
            Path(__file__).with_name('headplane_recovery.py'))
        headplane_policy = importlib.util.module_from_spec(headplane_spec)
        headplane_spec.loader.exec_module(headplane_policy)
        # Headplane checks the public Headscale HTTPS endpoint at startup.
        # Prepare that route after NPM is healthy, before its health wait.
        plan = headplane_policy.planned_model(root, plan)
    waves = profile.derived_waves(plan, manifest['restore_waves'])
    declared = [s for wave in waves for s in wave]
    if len(declared) != len(set(declared)) or set(declared) != set(compose['services']):
        raise ValueError('RESTORE_WAVES_REQUIRE_REVIEW')
    if operational:
        positions = {name:index for index,wave in enumerate(waves) for name in wave}
        if ('cometnet' not in positions or any(name not in positions
                or positions[name] >= positions['cometnet'] for name in ('npm', 'comet'))):
            raise ValueError('RESTORE_WAVES_REQUIRE_REVIEW')
    if operational:
        prepare_images(compose, root, deferred=deferred)
    else:
        prepare_images(compose, root)
    health_issues, missing_images = profile.health_dependency_issues(
        compose, lambda args: call(args, root))
    if health_issues or missing_images:
        raise ValueError('SERVICE_HEALTHCHECK_REQUIRED')
    state['application_start_attempted'] = True
    checks.save(state_path, state)
    emit('STARTED', 'RUNNING')
    public_target_verified = False
    for wave in waves:
        # Public controllers are intentionally activated only after NPM,
        # CometNet and all application services pass their checks below.
        selected = [s for s in wave if s not in deferred
                    and not (operational and s in DEFERRED)]
        if selected:
            if headplane_policy is not None and 'headplane' in selected:
                headplane_policy.before_headplane(root, home, state, compose,
                    lambda args: call(args, root), operational_policy, emit, checks.save)
            if tailscale_policy is not None and 'tailscale' in selected:
                compose = tailscale_policy.before_tailscale(root, home, state, compose,
                    lambda args: call(args, root), profile, operational_policy, emit)
                validate_runtime(compose, root, containers, volumes)
            if operational and 'cometnet' in selected:
                operational_policy.before_cometnet(root, compose, lambda args: call(args, root),
                                                   emit, checks.save, state, state_path)
                public_target_verified = True
            # Dependency ordering is explicit. Check health before the next wave.
            state['application_wave'] = selected
            checks.save(state_path, state)
            start_wave(compose, root, selected)
            if 'pgbouncer' in selected:
                try:
                    call(['docker', 'compose', '--profile', 'all', 'exec', '-T', 'pgbouncer',
                          'pg_isready', '-h', '127.0.0.1', '-p', '6432'], root)
                except Exception:
                    raise ValueError('PGBOUNCER_NOT_READY') from None
    if operational and not public_target_verified:
        raise ValueError('PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')
    if tls:
        emit('TLS', 'RUNNING')
        try:
            if not operational:
                call([sys.executable, '-B', Path(__file__).with_name('npm_runtime.py'), 'reissue', '--target', root], root)
            args = [sys.executable, '-B', Path(__file__).with_name('npm_runtime.py'), 'verify', '--target', root]
            if operational:
                args += ['--state-home', home]
            raw = call(args, root)
            if operational:
                external = external_dependency_report(raw)
                state['external_upstreams'] = external
        except Exception as error:
            raise ValueError(str(error) if str(error) in TLS_CODES else 'TLS_VERIFICATION_FAILED') from None
        emit('TLS')
        if operational:
            print('RECOVERY_EVENT '+json.dumps(dict(stage='EXTERNAL_UPSTREAMS',
                status='WARNING' if external['unavailable'] else 'PASS',diagnostic=external)),flush=True)
    if operational and not deferred:
        emit('PUBLIC_CONTROLLERS', 'RUNNING')
        selected = sorted(DEFERRED & set(compose['services']))
        state['application_wave'] = selected
        checks.save(state_path, state)
        start_wave(compose, root, selected)
        emit('PUBLIC_CONTROLLERS')
    if operational:
        final_service_check(compose, root, deferred=deferred)
        state['public_domain_recovery'] = 'VERIFIED'
        state['operational_recovery'] = 'STARTED_NEEDS_FUNCTIONAL_TEST'
        state['public_controllers_enabled'] = not deferred
    else:
        final_service_check(compose, root)
    # Running/healthy does not certify enrollment/login/real upstream behavior.
    state['application_recovery'] = 'STARTED_NEEDS_FUNCTIONAL_TEST'
    state['deferred_controllers'] = sorted(deferred)
    state['tls_verified'] = bool(tls)
    state.pop('application_wave', None)
    checks.save(state_path, state)
    emit('STARTED')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--target', required=True)
    p.add_argument('--state-home', required=True)
    p.add_argument('--tls', action='store_true')
    p.add_argument('--operational', action='store_true')
    p.add_argument('--cutover', action='store_true')
    p.add_argument('--routing-mode', choices=('parallel_test', 'production_recovery'))
    p.add_argument('--domain-target-address')
    a = p.parse_args()
    try:
        home = Path(a.state_home).absolute()
        if os.geteuid() != 0:
            raise ValueError('ROOT_START_INSTALLER_REQUIRED')
        if any(p.is_symlink() for p in (home, *home.parents)):
            raise ValueError('SYMLINK_PATH_REFUSED')
        with (home / 'recovery.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            start(Path(a.target).absolute(), home, a.tls, operational=a.operational,
                  cutover=a.cutover, routing_mode=a.routing_mode,
                  domain_target_address=a.domain_target_address)
    except Exception as error:
        emit_failure(error)
        sys.exit(1)

"""Enroll only this replacement's Tailscale against its verified Headscale.

The startup caller holds recovery.lock and has validated the prepared stack.
Private configuration, CLI responses and probe data never become events. The
temporary NPM nonce uses ordinary DNS and certificate verification from the
host namespace used by the pinned Tailscale service.
"""
import copy
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import sys
from urllib.parse import urlsplit

ERROR_CODES = frozenset({
    'TAILSCALE_CONTROLLER_CONFIGURATION_REQUIRED',
    'TAILSCALE_CONTROLLER_DNS_MISMATCH', 'TAILSCALE_CONTROLLER_UNREACHABLE',
    'TAILSCALE_CONTROLLER_TARGET_MISMATCH', 'TAILSCALE_CONTROLLER_PROBE_FAILED',
    'TAILSCALE_CONTROLLER_PROBE_CLEANUP_REQUIRED',
    'TAILSCALE_CONTROLLER_OWNERSHIP_REFUSED', 'TAILSCALE_CONTROLLER_IMAGE_REFUSED',
    'TAILSCALE_CONTROLLER_NOT_HEALTHY', 'TAILSCALE_HEADSCALE_ENROLLMENT_REQUIRED',
})
PINS = {
    'tailscale': 'tailscale/tailscale@sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065',
    'headscale': 'headscale/headscale@sha256:8833f828b414c0907b7e5c71da76473216fe17cce0818a166b536ec552c0903f',
    'npm': 'jc21/nginx-proxy-manager@sha256:4393e642e233e5efd5adeb7f10918d4aaea71c9ed875b94190273fc8e87f9594',
}
USER = 'streams-aio-recovery'
KEY = re.compile(r'[A-Za-z0-9._:-]{16,512}\Z')
CONFIGURATION = 'TAILSCALE_CONTROLLER_CONFIGURATION_REQUIRED'
ENROLLMENT = 'TAILSCALE_HEADSCALE_ENROLLMENT_REQUIRED'


def require(ok, code):
    if not ok:
        raise ValueError(code)


def _origin(value):
    require(isinstance(value, str) and value and not re.search(r'\s', value), CONFIGURATION)
    try:
        parsed = urlsplit(value)
        hostname, port = parsed.hostname, parsed.port
    except (ValueError, TypeError):
        raise ValueError(CONFIGURATION) from None
    require(parsed.scheme == 'https' and hostname and port in (None, 443)
            and parsed.username is None and parsed.password is None
            and not parsed.query and not parsed.fragment and parsed.path in ('', '/')
            and len(hostname) <= 253 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                                           for label in hostname.split('.')), CONFIGURATION)
    return ('https', hostname, 443)


def controller_plan(root, model):
    """Return private local-controller context; external controllers are untouched."""
    try:
        services = model.get('services', {})
        require(isinstance(services, dict), CONFIGURATION)
        if 'tailscale' not in services:
            return None
        environment = services['tailscale'].get('environment', {})
        require(isinstance(environment, dict), CONFIGURATION)
        extra = environment.get('TS_EXTRA_ARGS', '')
        if extra in ('', None):
            return None
        require(isinstance(extra, str), CONFIGURATION)
        tokens = shlex.split(extra)
        servers = []
        for index, token in enumerate(tokens):
            if token == '--login-server':
                require(index + 1 < len(tokens) and not tokens[index + 1].startswith('--'), CONFIGURATION)
                servers.append(tokens[index + 1])
            elif token.startswith('--login-server='):
                servers.append(token.split('=', 1)[1])
        if not servers:
            return None
        require(len(servers) == 1, CONFIGURATION)
        origin = _origin(servers[0])
        if 'headscale' not in services:
            return None
        path = Path(root).absolute()/'data/headscale/data/config/config.yaml'
        require(not any(p.is_symlink() for p in (path, *path.parents)), CONFIGURATION)
        info = path.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 1024**2, CONFIGURATION)
        config = json.loads(path.read_bytes())
        require(isinstance(config, dict), CONFIGURATION)
        if _origin(config.get('server_url')) != origin:
            return None
        require('npm' in services, CONFIGURATION)
        return {'hostname': origin[1], 'scheme': origin[0], 'port': origin[2]}
    except Exception:
        # Parsing failures may carry a hostname, an argument or file contents.
        raise ValueError(CONFIGURATION) from None


def planned_model(root, model):
    """Derive startup ordering without modifying the actual Compose candidate."""
    desired = copy.deepcopy(model)
    if controller_plan(root, model) is None:
        return desired
    dependencies = desired['services']['tailscale'].setdefault('depends_on', {})
    if isinstance(dependencies, list):
        dependencies = {name: dict(condition='service_started', required=True) for name in dependencies}
        desired['services']['tailscale']['depends_on'] = dependencies
    require(isinstance(dependencies, dict), CONFIGURATION)
    dependencies.update({name: dict(condition='service_healthy', required=True)
                         for name in ('headscale', 'npm')})
    return desired


# A child resolver has a fixed deadline even when libc/DNS is unresponsive.
DNS_PROBE = (
    "import json,subprocess,sys; "
    "code='import json,socket,sys; print(json.dumps(sorted({r[4][0] for r in socket.getaddrinfo(sys.argv[1],443,socket.AF_INET,socket.SOCK_STREAM)})))'; "
    "p=subprocess.run([sys.executable,'-c',code,sys.argv[1]],capture_output=True,timeout=8); "
    "sys.stdout.buffer.write(p.stdout if p.returncode==0 else b''); "
    "raise SystemExit(p.returncode)"
)


def preflight_dns(root, model, state, run):
    """Catch a stale LAN A record before pulling or starting any workload."""
    context = controller_plan(root, model)
    if context is None:
        return
    try:
        expected = ipaddress.ip_address(state['operational_deployment']['domain_target_address'])
    except Exception:
        raise ValueError(CONFIGURATION) from None
    try:
        values = json.loads(run([sys.executable, '-c', DNS_PROBE, context['hostname']]))
        require(isinstance(values, list) and 0 < len(values) <= 256
                and all(isinstance(item, str) for item in values), 'TAILSCALE_CONTROLLER_UNREACHABLE')
        answers = {ipaddress.IPv4Address(value) for value in values}
    except Exception:
        raise ValueError('TAILSCALE_CONTROLLER_UNREACHABLE') from None
    # Public proxy addresses cannot be compared to a LAN replacement address;
    # the nonce proof below verifies that path after NPM becomes healthy.
    if isinstance(expected, ipaddress.IPv4Address) and expected.is_private and all(a.is_private for a in answers):
        require(expected in answers, 'TAILSCALE_CONTROLLER_DNS_MISMATCH')


def checked_container(root, model, service, run, *, optional=False, healthy=True):
    """Confirm labels, full ID, pinned reference, image ID and critical mounts."""
    ownership = 'TAILSCALE_CONTROLLER_OWNERSHIP_REFUSED'
    image_error = 'TAILSCALE_CONTROLLER_IMAGE_REFUSED'
    try:
        require(model.get('name') == 'streams-aio', ownership)
        require(service in PINS, image_error)
        reference, same_image = _image_selection(root, model, service)
        require(model['services'][service].get('image') == reference, image_error)
        ids = run(['docker', 'compose', '--profile', 'all', 'ps', '-aq', service]).decode().split()
        if optional and not ids:
            return None
        require(len(ids) == 1 and re.fullmatch(r'[0-9a-f]{12,64}', ids[0]), ownership)
        rows = json.loads(run(['docker', 'inspect', ids[0]]))
        require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict), ownership)
        row = rows[0]
        identifier = row.get('Id')
        labels = row.get('Config', {}).get('Labels') or {}
        require(isinstance(identifier, str) and re.fullmatch(r'[0-9a-f]{64}', identifier)
                and identifier.startswith(ids[0])
                and labels.get('com.docker.compose.project.working_dir') == str(root)
                and labels.get('com.docker.compose.project') == model['name']
                and labels.get('com.docker.compose.service') == service, ownership)
        require(same_image(row.get('Config', {}).get('Image')), image_error)
        # Inspect only the always-present JSON Id. The metadata formatter's
        # typed .ID workaround is needed when also reading omitted fields.
        actual_image = json.loads(run(['docker', 'image', 'inspect', '--format', '{{json .Id}}', reference]))
        require(isinstance(actual_image, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', actual_image)
                and row.get('Image') == actual_image, image_error)
        if healthy:
            require(row.get('State', {}).get('Running') is True
                    and row.get('State', {}).get('Health', {}).get('Status') == 'healthy',
                    'TAILSCALE_CONTROLLER_NOT_HEALTHY')
        if service == 'tailscale':
            require(model['services'][service].get('network_mode') == 'host'
                    and row.get('HostConfig', {}).get('NetworkMode') == 'host', ownership)
        else:
            expected = ({'/data': 'data/npm/data', '/etc/letsencrypt': 'data/npm/data/letsencrypt'}
                        if service == 'npm' else {'/etc/headscale': 'data/headscale/data/config',
                            '/var/lib/headscale': 'data/headscale/data/lib',
                            '/var/run/headscale': 'data/headscale/data/run'})
            mounts = row.get('Mounts', [])
            require(isinstance(mounts, list), ownership)
            for target, source in expected.items():
                matching = [mount for mount in mounts if mount.get('Destination') == target]
                require(len(matching) == 1 and matching[0].get('Type') == 'bind'
                        and matching[0].get('Source') == str(Path(root)/source), ownership)
        return identifier
    except Exception as error:
        code = str(error)
        raise ValueError(code if code in ERROR_CODES else ownership) from None


def _image_selection(root, model, service):
    """Use only the sibling runner's verified backup/image-lock policy."""
    code = 'TAILSCALE_CONTROLLER_IMAGE_REFUSED'
    try:
        spec = importlib.util.spec_from_file_location('tailscale_runtime_image_policy',
                    Path(__file__).with_name('runtime_profile.py'))
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        reference = policy.selected_runtime_images(root, model)[service]
        require(isinstance(reference, str) and re.fullmatch(
            r'[^@\s]+@sha256:[0-9a-f]{64}', reference), code)
        expected = policy.image_identity(reference)
        def same_image(value):
            try:
                return policy.image_identity(value) == expected
            except Exception:
                return False
        return reference, same_image
    except Exception:
        raise ValueError(code) from None


def private_run(args, root, payload):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('COMPOSE_', 'INFISICAL_', 'PYTHON'))
           and key not in {'GH_TOKEN', 'GITHUB_TOKEN'}}
    try:
        result = subprocess.run([str(arg) for arg in args], cwd=root, env=env,
                                input=payload, capture_output=True, timeout=90)
        require(result.returncode == 0, 'TAILSCALE_CONTROLLER_PROBE_FAILED')
        return result.stdout
    except Exception:
        raise ValueError('TAILSCALE_CONTROLLER_PROBE_FAILED') from None


def verify_controller_target(root, model, state, context, npm, run, policy, send=None):
    """Prove the topology-bound HTTPS hostname reaches this NPM, then clean up."""
    send = send or private_run
    try:
        module, deployment, saved, routes = policy.topology_targets(root, state)
        candidates = [row for row in routes if context['hostname'] in row['routing']['domain_names']]
        require(len(candidates) == 1, CONFIGURATION)
        route = candidates[0]
        bindings = [item for item in deployment['bindings'] if item['table'] == 'proxy_host'
                    and item['id'] == route['id'] and item['path'] == ['forward_host']]
        routing = route['routing']
        require(len(bindings) == 1 and bindings[0]['role'] in ('stack', 'compose')
                and bindings[0]['service'] == 'headscale' and routing['forward_port'] == 8080
                and routing['forward_scheme'] == 'http' and isinstance(routing['forward_host'], str)
                and bool(routing['forward_host']), CONFIGURATION)
        helper_path = Path(__file__).with_name('npm-domain-probe.mjs')
        require(not any(path.is_symlink() for path in (helper_path, *helper_path.parents))
                and helper_path.is_file(), 'TAILSCALE_CONTROLLER_PROBE_FAILED')
        helper = helper_path.read_text()
    except Exception as error:
        raise ValueError(str(error) if str(error) in ERROR_CODES else CONFIGURATION) from None
    nonce = secrets.token_hex(24)
    args = ['docker', 'exec', '-i', '--user', '0', '--workdir', '/app', npm,
            'node', '--input-type=module', '-e', helper]
    def marker(action):
        payload = dict(action=action, kind='headscale', hostname=context['hostname'], nonce=nonce,
                       forward_hosts=[routing['forward_host']], forward_port=8080)
        try:
            response = json.loads(send(args, root, json.dumps(payload).encode()))
            require(response == {'status': 'PASS'}, 'TAILSCALE_CONTROLLER_PROBE_FAILED')
        except Exception:
            raise ValueError('TAILSCALE_CONTROLLER_PROBE_FAILED') from None
    probe = policy.nonce_probe_code()
    try:
        # An install can write its journal before returning failure.
        marker('install')
        try:
            run([sys.executable, '-c', probe, context['hostname'], nonce])
        except Exception:
            raise ValueError('TAILSCALE_CONTROLLER_TARGET_MISMATCH') from None
    finally:
        try:
            marker('remove')
        except Exception:
            raise ValueError('TAILSCALE_CONTROLLER_PROBE_CLEANUP_REQUIRED') from None
    try:
        module.verify(root, state.get('npm_topology'), stack_commit=state.get('public_commit'))
    except Exception:
        raise ValueError(CONFIGURATION) from None


def _backend(identifier, run):
    if identifier is None:
        return None
    try:
        value = json.loads(run(['docker', 'exec', identifier, 'tailscale', 'status', '--json']))
        return value.get('BackendState') if isinstance(value, dict) else None
    except Exception:
        return None


def _user_id(value):
    if isinstance(value, str) and re.fullmatch(r'[1-9][0-9]{0,18}', value):
        value = int(value)
    require(type(value) is int and 1 <= value <= 2**63 - 1, ENROLLMENT)
    return str(value)


def _enrollment_key(identifier, run):
    prefix = ['docker', 'exec', identifier, '/ko-app/headscale']
    users = json.loads(run([*prefix, 'users', 'list', '-o', 'json']))
    require(users is None or isinstance(users, list), ENROLLMENT)
    if not users:
        user = json.loads(run([*prefix, 'users', 'create', USER, '-o', 'json']))
    else:
        require(len(users) == 1, ENROLLMENT)
        user = users[0]
    require(isinstance(user, dict) and user.get('name') == USER, ENROLLMENT)
    uid = _user_id(user.get('id'))
    response = json.loads(run([*prefix, 'preauthkeys', 'create', '--user', uid,
                              '--expiration', '15m', '-o', 'json']))
    require(isinstance(response, dict) and isinstance(response.get('key'), str)
            and KEY.fullmatch(response['key']), ENROLLMENT)
    return response['key']


def before_tailscale(root, home, state, model, run, profile, policy, emit):
    """Prepare local enrollment immediately before the normal Tailscale wave."""
    context = controller_plan(root, model)
    if context is None:
        return model
    emit('TAILSCALE', 'RUNNING')
    try:
        require(model['services']['tailscale'].get('network_mode') == 'host', CONFIGURATION)
        headscale = checked_container(root, model, 'headscale', run)
        npm = checked_container(root, model, 'npm', run)
        tailscale = checked_container(root, model, 'tailscale', run, optional=True, healthy=False)
        backend = _backend(tailscale, run)
        binding = (state.get('runtime_profile') or {}).get('tailscale_artifact')
        if backend == 'Running' and binding == '.generated/tailscale-recovery.env':
            emit('TAILSCALE')
            return model
        require(not binding or binding == '.generated/tailscale-recovery.env', CONFIGURATION)
        if backend == 'Running':
            key = model['services']['tailscale'].get('environment', {}).get('TS_AUTHKEY')
            require(isinstance(key, str) and KEY.fullmatch(key), ENROLLMENT)
        else:
            require(backend in (None, 'NeedsLogin', 'Starting'), ENROLLMENT)
            policy.npm_action(root, run, 'reissue')
            verify_controller_target(root, model, state, context, npm, run, policy)
            if tailscale is not None:
                run(['docker', 'stop', tailscale])
            key = _enrollment_key(headscale, run)
        raw = ('TS_AUTHKEY=' + key + '\nTS_AUTH_ONCE=true\n').encode('ascii')
        profile.migrate_tailscale(root, home, state, model, run, raw)
        updated = json.loads(run(['docker', 'compose', '--profile', 'all', 'config', '--format', 'json']))
        require(isinstance(updated, dict) and isinstance(updated.get('services'), dict), ENROLLMENT)
    except Exception as error:
        code = str(error)
        allowed = (ERROR_CODES | getattr(profile, 'ERROR_CODES', frozenset())
                   | getattr(policy, 'TLS_CODES', frozenset()) | {'TLS_VERIFICATION_FAILED'})
        raise ValueError(code if code in allowed else ENROLLMENT) from None
    emit('TAILSCALE')
    return updated

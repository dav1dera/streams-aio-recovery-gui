"""Bootstrap Headplane against this replacement's verified Headscale only.

The startup caller holds recovery.lock and has checked the prepared deployment.
HTTPS is restored before Headplane's healthcheck can depend on it. An API key
from the old, deliberately excluded Headscale database is replaced only after
an authenticated request is explicitly refused by the proven new controller.
All credential-bearing input/output is private and never included in events.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from urllib.parse import urlsplit


CONFIGURATION = 'HEADPLANE_CONTROLLER_CONFIGURATION_REQUIRED'
SCOPE = 'HEADPLANE_BOOTSTRAP_SCOPE_REFUSED'
DRIFT = 'HEADPLANE_BOOTSTRAP_STATE_CHANGED'
PROBE = 'HEADPLANE_CONTROLLER_API_PROBE_FAILED'
BOOTSTRAP = 'HEADPLANE_API_BOOTSTRAP_FAILED'
RECREATE = 'HEADPLANE_RECREATE_FAILED'
ERROR_CODES = frozenset({CONFIGURATION, SCOPE, DRIFT, PROBE, BOOTSTRAP, RECREATE})
HEADPLANE_IMAGE = 'ghcr.io/tale/headplane@sha256:394483fd2336ce6b15df360c3e118ddfd45eb8140fe21df9f2611077f5d79d22'
CONFIG = 'data/headplane/data/config.yaml'
HEADSCALE_CONFIG = 'data/headscale/data/config/config.yaml'
DATABASE = 'data/headscale/data/lib/db.sqlite'
JOURNAL = 'headplane-recovery.json'
NEW_KEY = re.compile(r'hskey-api-[A-Za-z0-9_-]{12}-[A-Za-z0-9_-]{64}\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
MAX_CONFIG = 1024 * 1024


def require(ok, code):
    if not ok:
        raise ValueError(code)


def _safe(path, code):
    path = Path(path).absolute()
    require(not any(item.is_symlink() for item in (path, *path.parents)), code)
    return path


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, CONFIGURATION)
        result[key] = value
    return result


def _metadata(info, code, *, private=False, public=False, posix=None):
    """Config/journal confidentiality differs from public manifests and SQLite."""
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and 0 < info.st_size <= 4 * MAX_CONFIG, code)
    is_posix = posix if posix is not None else os.name != 'nt'
    if is_posix:
        require(info.st_uid in (0, 1000) and info.st_gid in (0, 1000), code)
        if private:
            require(stat.S_IMODE(info.st_mode) == 0o600, code)
        elif public:
            require(not info.st_mode & 0o022, code)
        else:
            require(not info.st_mode & 0o007, code)


def _regular(path, code, *, private=False, public=False):
    path = _safe(path, code)
    info = path.stat()
    _metadata(info, code, private=private, public=public)
    return info


def _document(path, code=CONFIGURATION, *, private=False, public=False):
    _regular(path, code, private=private, public=public)
    try:
        raw = path.read_bytes()
        require(len(raw) <= (4 * MAX_CONFIG if private else MAX_CONFIG), code)
        value = json.loads(raw, object_pairs_hook=_pairs)
        require(isinstance(value, dict), code)
        return value, raw
    except Exception:
        raise ValueError(code) from None


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _origin(value):
    require(isinstance(value, str) and value and not re.search(r'\s', value), CONFIGURATION)
    try:
        parsed = urlsplit(value)
        hostname, port = parsed.hostname, parsed.port
    except Exception:
        raise ValueError(CONFIGURATION) from None
    require(parsed.scheme == 'https' and hostname and port in (None, 443)
            and parsed.username is None and parsed.password is None
            and not parsed.query and not parsed.fragment and parsed.path in ('', '/')
            and len(hostname) <= 253 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                                           for label in hostname.split('.')), CONFIGURATION)
    return {'hostname': hostname, 'scheme': 'https', 'port': 443}


def controller_plan(root, model):
    """An external Headscale is untouched; a local one requires a public route."""
    try:
        services = model.get('services', {})
        require(isinstance(services, dict), CONFIGURATION)
        if 'headplane' not in services or 'headscale' not in services:
            return None
        root = _safe(root, CONFIGURATION)
        config, _ = _document(root / CONFIG)
        server, _ = _document(root / HEADSCALE_CONFIG)
        require(isinstance(config.get('headscale'), dict), CONFIGURATION)
        context = _origin(config['headscale'].get('url'))
        if context != _origin(server.get('server_url')):
            return None
        require('npm' in services, CONFIGURATION)
        return context
    except Exception:
        raise ValueError(CONFIGURATION) from None


def _dependencies(service):
    dependencies = service.setdefault('depends_on', {})
    if isinstance(dependencies, list):
        require(all(isinstance(name, str) for name in dependencies), CONFIGURATION)
        dependencies = {name: dict(condition='service_started', required=True) for name in dependencies}
        service['depends_on'] = dependencies
    require(isinstance(dependencies, dict), CONFIGURATION)
    return dependencies


def _started_dependency(service, name):
    dependencies = _dependencies(service)
    edge = dependencies.get(name, {})
    require(isinstance(edge, dict) and edge.get('condition', 'service_started') == 'service_started',
            CONFIGURATION)
    dependencies[name] = dict(edge, condition='service_started', required=True)


def planned_model(root, model):
    """Schedule HTTPS prerequisites without Headplane's OAuth DNS cycle.

    NPM's restored auth locations can contain a static oauth2-proxy upstream.
    OAuth2 Proxy can listen before its HTTP backend; it connects on requests.
    Only this scheduling copy reverses the short-syntax started dependency.
    Explicit health/completion requirements are never silently weakened.
    """
    desired = copy.deepcopy(model)
    if controller_plan(root, model) is None:
        return desired
    dependencies = _dependencies(desired['services']['headplane'])
    dependencies.update({name: dict(condition='service_healthy', required=True)
                         for name in ('headscale', 'npm')})
    if 'oauth2-proxy' in desired['services']:
        oauth = desired['services']['oauth2-proxy']
        previous = oauth.get('depends_on', {})
        if isinstance(previous, list):
            require(all(isinstance(name, str) for name in previous), CONFIGURATION)
            oauth['depends_on'] = [name for name in previous if name != 'headplane']
        else:
            require(isinstance(previous, dict), CONFIGURATION)
            if 'headplane' in previous:
                edge = previous['headplane']
                require(isinstance(edge, dict) and edge.get('condition', 'service_started') == 'service_started',
                        CONFIGURATION)
            oauth['depends_on'] = {name: row for name, row in previous.items() if name != 'headplane'}
        # Every early TLS caller needs NPM's static auth upstream resolvable,
        # including Tailscale and CometNet, not just Headplane itself.
        _started_dependency(desired['services']['npm'], 'oauth2-proxy')
        _started_dependency(desired['services']['headplane'], 'oauth2-proxy')
    if 'cometnet' in desired['services']:
        comet = _dependencies(desired['services']['cometnet'])
        edge = comet.get('npm', {})
        require(isinstance(edge, dict) and edge.get('condition', 'service_started')
                in ('service_started', 'service_healthy'), CONFIGURATION)
        comet['npm'] = dict(edge, condition='service_healthy', required=True)
    return desired


def _controller():
    spec = importlib.util.spec_from_file_location('headplane_controller_policy',
                                                 Path(__file__).with_name('tailscale_recovery.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _scope(root, home, state, model):
    root, home = _safe(root, SCOPE), _safe(home, SCOPE)
    require(root.is_dir() and home.is_dir() and state.get('target') == str(root)
            and isinstance(state.get('machine_id'), str) and state['machine_id']
            and re.fullmatch(r'[0-9a-f]{40}', state.get('public_commit', ''))
            and state.get('preparation') == 'PASS'
            and 'EMPTY_STATE' in state.get('completed', [])
            and (state.get('runtime_profile') or {}).get('origin') == 'FIRST_BOOT'
            and model.get('name') == 'streams-aio'
            and model['services']['headplane'].get('image') == HEADPLANE_IMAGE, SCOPE)
    machine = Path('/etc/machine-id')
    if os.name != 'nt':
        require(state['machine_id'] == machine.read_text().strip(), SCOPE)
    stored, _ = _document(home / 'state.json', SCOPE, private=True)
    require(stored == state, SCOPE)
    manifest, _ = _document(root / 'config/dr-manifest.yaml', SCOPE, public=True)
    units = manifest.get('state_units')
    require(isinstance(units, list), SCOPE)
    matching = [item for item in units if isinstance(item, dict) and item.get('id') == 'headscale-enrollments']
    require(len(matching) == 1 and matching[0].get('services') == ['headscale']
            and matching[0].get('path_or_type') == DATABASE
            and matching[0].get('classification') == 'OPTIONAL_RUNTIME_STATE'
            and matching[0].get('backup_required') is False, SCOPE)
    _regular(root / DATABASE, SCOPE, public=True)
    with (root / DATABASE).open('rb') as stream:
        require(stream.read(16) == b'SQLite format 3\0', SCOPE)
    return root, home


def _headplane_container(root, model, run):
    """A previous failed Headplane may be recreated only with exact ownership."""
    try:
        ids = run(['docker', 'compose', '--profile', 'all', 'ps', '-aq', 'headplane']).decode().split()
        if not ids:
            return None
        require(len(ids) == 1 and re.fullmatch(r'[0-9a-f]{12,64}', ids[0]), SCOPE)
        rows = json.loads(run(['docker', 'inspect', ids[0]]))
        require(isinstance(rows, list) and len(rows) == 1, SCOPE)
        row = rows[0]
        labels = row.get('Config', {}).get('Labels') or {}
        identity = row.get('Id')
        require(isinstance(identity, str) and re.fullmatch(r'[0-9a-f]{64}', identity)
                and identity.startswith(ids[0])
                and labels.get('com.docker.compose.project') == 'streams-aio'
                and labels.get('com.docker.compose.project.working_dir') == str(root)
                and labels.get('com.docker.compose.service') == 'headplane'
                and row.get('Config', {}).get('Image') == HEADPLANE_IMAGE, SCOPE)
        image = json.loads(run(['docker', 'image', 'inspect', '--format', '{{json .Id}}', HEADPLANE_IMAGE]))
        require(isinstance(image, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', image)
                and row.get('Image') == image, SCOPE)
        mounts = row.get('Mounts', [])
        require(isinstance(mounts, list), SCOPE)
        for target, source in (('/etc/headplane/config.yaml', root / CONFIG),
                               ('/var/lib/headplane', root / 'data/headplane/data'),
                               ('/etc/headscale/config.yaml', root / HEADSCALE_CONFIG)):
            matching = [entry for entry in mounts if entry.get('Destination') == target]
            require(len(matching) == 1 and matching[0].get('Type') == 'bind'
                    and matching[0].get('Source') == str(source), SCOPE)
        return identity
    except Exception:
        raise ValueError(SCOPE) from None


# The key goes through stdin to the already-verified NPM, never Docker argv or
# an event. Normal DNS and certificate verification are mandatory. Redirects,
# custom DNS, TLS exceptions and unexpected response shapes are refused.
API_PROBE = r"""
import https from 'node:https';
let raw = '';
for await (const chunk of process.stdin) {
  raw += chunk;
  if (raw.length > 4096) process.exit(1);
}
try {
  const value = JSON.parse(raw);
  if (Object.keys(value).sort().join(',') !== 'hostname,key' ||
      typeof value.hostname !== 'string' || typeof value.key !== 'string' ||
      !/^[a-z0-9.-]{1,253}$/.test(value.hostname) ||
      !/^[A-Za-z0-9._:-]{1,512}$/.test(value.key)) process.exit(1);
  const request = https.request({hostname:value.hostname, port:443,
    path:'/api/v1/user', method:'GET', timeout:15000,
    rejectUnauthorized:true,
    headers:{Authorization:'Bearer '+value.key, Accept:'application/json'}}, response => {
      let body = '';
      response.on('data', chunk => {
        body += chunk;
        if (body.length > 1048576) request.destroy();
      });
      response.on('end', () => {
        const status = response.statusCode;
        if (status === 200) {
          try {
            const data = JSON.parse(body);
            if (!data || typeof data !== 'object' || Array.isArray(data) ||
                !(Array.isArray(data.users) ||
                  (data.users === undefined && Object.keys(data).length === 0))) process.exit(1);
          } catch { process.exit(1); }
        } else if (status !== 401 && status !== 403) process.exit(1);
        process.stdout.write(JSON.stringify({schema:1,status}));
      });
    });
  request.on('timeout', () => request.destroy());
  request.on('error', () => process.exit(1));
  request.end();
} catch { process.exit(1); }
"""


def private_run(args, root, payload):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('COMPOSE_', 'INFISICAL_', 'PYTHON'))
           and key not in {'GH_TOKEN', 'GITHUB_TOKEN', 'NODE_OPTIONS', 'NODE_TLS_REJECT_UNAUTHORIZED'}}
    try:
        result = subprocess.run([str(arg) for arg in args], cwd=root, env=env,
                                input=payload, capture_output=True, timeout=30)
        require(result.returncode == 0 and len(result.stdout) <= 256, PROBE)
        return result.stdout
    except Exception:
        raise ValueError(PROBE) from None


def _probe(npm, context, key, root, send):
    require(isinstance(key, str) and re.fullmatch(r'[A-Za-z0-9._:-]{1,512}', key), BOOTSTRAP)
    args = ['docker', 'exec', '-i', '--user', '0', '--workdir', '/app', npm,
            'node', '--input-type=module', '-e', API_PROBE]
    try:
        value = json.loads(send(args, root, json.dumps(dict(hostname=context['hostname'], key=key)).encode()))
        require(isinstance(value, dict) and set(value) == {'schema', 'status'}
                and type(value['schema']) is int and value['schema'] == 1
                and type(value['status']) is int and value['status'] in (200, 401, 403), PROBE)
        return value['status']
    except Exception:
        raise ValueError(PROBE) from None


def _atomic(path, raw, *, expected=None, info=None):
    """Private journal creation is no-clobber; config replacement checks drift."""
    path = _safe(path, DRIFT)
    if expected is None:
        require(not path.exists(), DRIFT)
    else:
        current = _regular(path, DRIFT)
        require(_sha(path.read_bytes()) == expected and info is not None
                and (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), DRIFT)
    descriptor, name = tempfile.mkstemp(prefix='.headplane-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            if info is not None:
                if os.name != 'nt':
                    os.fchown(stream.fileno(), info.st_uid, info.st_gid)
                os.chmod(name, stat.S_IMODE(info.st_mode))
            else:
                os.chmod(name, 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if expected is None:
            # Windows' rename is no-clobber; POSIX rename would overwrite.
            # Remote execution is Linux, while the GUI tests run on Windows.
            if os.name == 'nt':
                os.rename(name, path)
            else:
                os.link(name, path)
        else:
            require(_sha(path.read_bytes()) == expected, DRIFT)
            os.replace(name, path)
        if os.name != 'nt':
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
    except Exception as error:
        raise ValueError(str(error) if str(error) in ERROR_CODES else DRIFT) from None
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _key_from_cli(headscale, run):
    try:
        value = json.loads(run(['docker', 'exec', headscale, '/ko-app/headscale',
                                'apikeys', 'create', '--expiration', '90d', '-o', 'json']))
        require(isinstance(value, str) and NEW_KEY.fullmatch(value), BOOTSTRAP)
        return value
    except Exception:
        raise ValueError(BOOTSTRAP) from None


def _record(root, state, original, applied):
    return dict(schema=1, target=str(root), machine_id=state['machine_id'],
                public_commit=state['public_commit'], config_path=CONFIG,
                original_sha256=_sha(original), applied_sha256=_sha(applied))


def _journal(home, root, state, raw, config):
    """Recover a key saved before a crash, without adopting unrelated drift."""
    path = home / JOURNAL
    record = state.get('headplane_recovery')
    if not path.exists():
        require(record is None, DRIFT)
        return None
    value, _ = _document(path, DRIFT, private=True)
    fields = {'schema', 'target', 'machine_id', 'public_commit', 'config_path',
              'original_sha256', 'applied_sha256', 'original_config', 'api_key'}
    require(set(value) == fields and type(value['schema']) is int and value['schema'] == 1
            and value['target'] == str(root) and value['machine_id'] == state['machine_id']
            and value['public_commit'] == state['public_commit'] and value['config_path'] == CONFIG
            and isinstance(value['original_config'], dict)
            and isinstance(value['api_key'], str) and NEW_KEY.fullmatch(value['api_key'])
            and isinstance(value['original_sha256'], str) and SHA256.fullmatch(value['original_sha256'])
            and isinstance(value['applied_sha256'], str) and SHA256.fullmatch(value['applied_sha256']), DRIFT)
    expected = copy.deepcopy(value['original_config'])
    require(isinstance(expected.get('headscale'), dict), DRIFT)
    expected['headscale']['api_key'] = value['api_key']
    require(_sha(_config_bytes(expected)) == value['applied_sha256'], DRIFT)
    current_hash = _sha(raw)
    require(current_hash in (value['original_sha256'], value['applied_sha256']), DRIFT)
    require((current_hash == value['original_sha256'] and config == value['original_config'])
            or (current_hash == value['applied_sha256'] and config == expected), DRIFT)
    base = {key: value[key] for key in _record(root, state, b'', b'')}
    if record is not None:
        require(isinstance(record, dict) and set(record) == set(base) | {'phase'}
                and record['phase'] in ('pending', 'complete', 'recreate_required')
                and all(record[key] == val for key, val in base.items()), DRIFT)
        require(record['phase'] != 'complete' or current_hash == value['applied_sha256'], DRIFT)
    return value


def _config_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode('utf-8')


def before_headplane(root, home, state, model, run, policy, emit, save, *, controller=None, send=None):
    """Restore TLS, authenticate Headplane and retain the normal startup check."""
    context = controller_plan(root, model)
    if context is None:
        return model
    emit('HEADPLANE', 'RUNNING')
    controller = controller or _controller()
    send = send or private_run
    allowed = (ERROR_CODES | getattr(controller, 'ERROR_CODES', frozenset())
               | getattr(policy, 'TLS_CODES', frozenset()) | {'TLS_VERIFICATION_FAILED'})
    try:
        root, home = _scope(root, home, state, model)
        config, raw = _document(root / CONFIG)
        require(isinstance(config.get('headscale'), dict)
                and 'api_key_path' not in config['headscale'], CONFIGURATION)
        info = _regular(root / CONFIG, SCOPE)
        journal = _journal(home, root, state, raw, config)
        previous = _headplane_container(root, model, run)
        headscale = controller.checked_container(root, model, 'headscale', run)
        npm = controller.checked_container(root, model, 'npm', run)
        policy.npm_action(root, run, 'reissue')
        controller.verify_controller_target(root, model, state, context, npm, run, policy)
        key = journal['api_key'] if journal is not None else config['headscale'].get('api_key')
        status = _probe(npm, context, key, root, send)
        if journal is not None:
            require(status == 200, BOOTSTRAP)
        elif status == 200:
            require(_sha((root / CONFIG).read_bytes()) == _sha(raw), DRIFT)
            emit('HEADPLANE')
            return model
        else:
            # Only a proven 401/403 on this verified replacement permits a key.
            key = _key_from_cli(headscale, run)
            original_config = copy.deepcopy(config)
            updated = copy.deepcopy(config)
            updated['headscale']['api_key'] = key
            applied = _config_bytes(updated)
            journal = dict(_record(root, state, raw, applied), original_config=original_config, api_key=key)
            # Persist the one-time CLI output immediately, before another API
            # request can time out. Resumption never issues a second unknown key.
            _atomic(home / JOURNAL, _config_bytes(journal))
            require(_probe(npm, context, key, root, send) == 200, BOOTSTRAP)
        base = {field: journal[field] for field in _record(root, state, b'', b'')}
        previous_phase = (state.get('headplane_recovery') or {}).get('phase')
        if previous_phase != 'complete':
            state['headplane_recovery'] = dict(base, phase='pending')
            save(home / 'state.json', state)
        updated = copy.deepcopy(journal['original_config'])
        updated['headscale']['api_key'] = journal['api_key']
        applied = _config_bytes(updated)
        changed = _sha(raw) == journal['original_sha256']
        if changed:
            _atomic(root / CONFIG, applied, expected=journal['original_sha256'], info=info)
        # A single-file bind mount otherwise keeps the old inode after an
        # atomic update. Recreate this exact owned container, preserving data.
        needs_recreate = previous is not None and (
            changed or previous_phase != 'complete')
        if needs_recreate:
            state['headplane_recovery'] = dict(base, phase='recreate_required')
            save(home / 'state.json', state)
            try:
                run(['docker', 'compose', '--profile', 'all', 'up', '-d', '--no-deps',
                     '--force-recreate', 'headplane'])
            except Exception:
                raise ValueError(RECREATE) from None
        state['headplane_recovery'] = dict(base, phase='complete')
        save(home / 'state.json', state)
    except Exception as error:
        code = str(error)
        raise ValueError(code if code in allowed else BOOTSTRAP) from None
    emit('HEADPLANE')
    return model

"""Explicit application startup, on the prepared replacement host only."""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

DEFERRED = {'watchtower', 'cloudflare-ddns', 'deunhealth'}


def emit(stage, status='PASS'):
    print('RECOVERY_EVENT ' + json.dumps(dict(stage=stage, status=status)), flush=True)


def call(args, root):
    env = {k: v for k, v in os.environ.items() if not k.startswith(('COMPOSE_', 'INFISICAL_', 'PYTHON'))}
    p = subprocess.run([str(x) for x in args], cwd=root, env=env, capture_output=True, timeout=1800)
    if p.returncode:
        raise ValueError('SERVICE_START_OR_CHECK_FAILED')
    return p.stdout


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


def start(root, home, tls=False):
    state_path = home / 'state.json'
    if any(p.is_symlink() for path in (root, home, state_path) for p in (path, *path.parents)):
        raise ValueError('SYMLINK_PATH_REFUSED')
    if not state_path.is_file() or state_path.stat().st_mode & 0o077:
        raise ValueError('PRIVATE_CHECKPOINT_REQUIRED')
    state = json.loads(state_path.read_bytes())
    if state.get('target') != str(root) or state.get('machine_id') != Path('/etc/machine-id').read_text().strip() or state.get('preparation') != 'PASS':
        raise ValueError('PREPARED_REPLACEMENT_REQUIRED')
    # Do not let Compose adopt other workloads, same-name containers or old volumes.
    checks_spec = importlib.util.spec_from_file_location('startup_recovery_checks', Path(__file__).with_name('recover.py'))
    checks = importlib.util.module_from_spec(checks_spec)
    checks_spec.loader.exec_module(checks)
    checks.stack_preflight(root, state)
    compose = json.loads(call(['docker', 'compose', '--profile', 'all', 'config', '--format', 'json'], root))
    ids = call(['docker', 'ps', '-aq'], root).split()
    containers = json.loads(call(['docker', 'inspect', *[i.decode() for i in ids]], root)) if ids else []
    names = call(['docker', 'volume', 'ls', '-q'], root).split()
    volumes = json.loads(call(['docker', 'volume', 'inspect', *[n.decode() for n in names]], root)) if names else []
    validate_runtime(compose, root, containers, volumes)
    manifest = json.loads((root / 'config/dr-manifest.yaml').read_bytes())
    waves = manifest['restore_waves']
    declared = [s for wave in waves for s in wave]
    if len(declared) != len(set(declared)) or set(declared) != set(compose['services']):
        raise ValueError('RESTORE_WAVES_REQUIRE_REVIEW')
    emit('STARTED', 'RUNNING')
    for wave in waves:
        selected = [s for s in wave if s not in DEFERRED]
        if selected:
            # Dependency ordering is explicit. Check health before the next wave.
            call(['docker', 'compose', '--profile', 'all', 'up', '-d', '--no-deps', '--wait',
                  '--wait-timeout', '300', *selected], root)
    if tls:
        emit('TLS', 'RUNNING')
        call([sys.executable, '-B', root / 'scripts/npm-dr.py', 'reissue', '--target', root], root)
        call([sys.executable, '-B', root / 'scripts/npm-dr.py', 'verify', '--target', root], root)
        emit('TLS')
    # Running/healthy does not certify enrollment/login/real upstream behavior.
    state['application_recovery'] = 'STARTED_NEEDS_FUNCTIONAL_TEST'
    state['deferred_controllers'] = sorted(DEFERRED)
    state['tls_verified'] = bool(tls)
    raw = json.dumps(state).encode()
    temp = home / 'state-start.json'
    with temp.open('xb') as f:
        f.write(raw)
    temp.chmod(0o600)
    os.replace(temp, state_path)
    emit('STARTED')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--target', required=True)
    p.add_argument('--state-home', required=True)
    p.add_argument('--tls', action='store_true')
    a = p.parse_args()
    try:
        home = Path(a.state_home).absolute()
        if os.geteuid() != 0:
            raise ValueError('ROOT_START_INSTALLER_REQUIRED')
        if any(p.is_symlink() for p in (home, *home.parents)):
            raise ValueError('SYMLINK_PATH_REFUSED')
        with (home / 'recovery.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            start(Path(a.target).absolute(), home, a.tls)
    except Exception:
        print('RECOVERY_EVENT ' + json.dumps(dict(stage='REFUSED', status='REFUSED', code='APPLICATION_START_REFUSED')), flush=True)
        sys.exit(1)

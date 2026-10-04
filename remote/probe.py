"""Read-only host check. Output never includes env values or container settings."""
import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys


def probe(target, runner, fresh=False):
    for path in (target, runner):
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('SYMLINK_PATH_REFUSED')
    user = pwd.getpwuid(1000)
    if user.pw_gid != 1000:
        raise ValueError('DEPLOYMENT_UID_GID_REQUIRED')
    info = dict(x.split('=', 1) for x in Path('/etc/os-release').read_text().splitlines() if '=' in x)
    if info.get('ID', '').strip('"') != 'ubuntu' or info.get('VERSION_ID', '').strip('"') != '24.04':
        raise ValueError('UBUNTU_2404_REQUIRED')
    if os.uname().machine != 'x86_64':
        raise ValueError('UBUNTU_AMD64_REQUIRED')
    existing = target.exists()
    if existing:
        state = runner / 'state.json'
        if not state.is_file() or state.is_symlink() or state.stat().st_mode & 0o077:
            raise ValueError('EXISTING_STACK_REFUSED')
        data = json.loads(state.read_bytes())
        if data.get('machine_id') != Path('/etc/machine-id').read_text().strip() or data.get('target') != str(target):
            raise ValueError('FOREIGN_RECOVERY_STATE')
    containers = volumes = 0
    if shutil.which('docker'):
        for label, args in [('containers', ['docker', 'ps', '-aq']), ('volumes', ['docker', 'volume', 'ls', '-q'])]:
            p = subprocess.run(args, capture_output=True, timeout=15)
            if p.returncode:
                raise ValueError('DOCKER_CHECK_REQUIRES_SUDO_OR_RUNNING_DAEMON')
            count = len(p.stdout.split())
            if label == 'containers':
                containers = count
            else:
                volumes = count
    elif Path('/var/lib/docker').exists() and any(Path('/var/lib/docker').iterdir()):
        raise ValueError('EXISTING_DOCKER_DATA')
    if fresh and (containers or volumes):
        raise ValueError('FRESH_DOCKER_HOST_REQUIRED')
    return dict(os='Ubuntu 24.04', architecture='amd64', user=user.pw_name,
                home=user.pw_dir, existing_recovery=existing,
                containers=containers, volumes=volumes)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--target', required=True)
    p.add_argument('--runner', required=True)
    p.add_argument('--fresh', action='store_true')
    a = p.parse_args()
    try:
        print(json.dumps(probe(Path(a.target), Path(a.runner), a.fresh)))
    except Exception as error:
        allowed = {'SYMLINK_PATH_REFUSED', 'DEPLOYMENT_UID_GID_REQUIRED', 'UBUNTU_2404_REQUIRED',
                   'UBUNTU_AMD64_REQUIRED', 'EXISTING_STACK_REFUSED', 'FOREIGN_RECOVERY_STATE',
                   'DOCKER_CHECK_REQUIRES_SUDO_OR_RUNNING_DAEMON', 'EXISTING_DOCKER_DATA', 'FRESH_DOCKER_HOST_REQUIRED'}
        print(json.dumps({'error': str(error) if str(error) in allowed else 'HOST_CHECK_REFUSED'}))
        sys.exit(1)

"""Read-only host check. Output never includes env values or container settings."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys


def ubuntu_codename(info):
    """Explicit OS policy shared by the SSH probe and the Docker installer."""
    values = {key: value.strip('\"') for key, value in info.items()}
    supported = {'24.04': 'noble', '26.04': 'resolute'}
    version = values.get('VERSION_ID')
    if values.get('ID') != 'ubuntu' or version not in supported:
        raise ValueError('UBUNTU_LTS_VERSION_REQUIRED')
    codename = supported[version]
    declared = [values[key] for key in ('UBUNTU_CODENAME', 'VERSION_CODENAME') if key in values]
    if not declared or any(value != codename for value in declared):
        raise ValueError('UBUNTU_CODENAME_MISMATCH')
    return codename


def probe(target, runner, fresh=False, role='stack'):
    if role not in ('stack', 'infisical') or (role == 'infisical' and target != Path('/opt/infisical')):
        raise ValueError('INVALID_RECOVERY_ROLE')
    for path in (target, runner):
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('SYMLINK_PATH_REFUSED')
    user = pwd.getpwuid(1000)
    if user.pw_gid != 1000:
        raise ValueError('DEPLOYMENT_UID_GID_REQUIRED')
    info = dict(x.split('=', 1) for x in Path('/etc/os-release').read_text().splitlines() if '=' in x)
    ubuntu_codename(info)
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
        if role != 'infisical' or not existing or 'INFISICAL_CONFIG' not in data.get('completed', []):
            raise ValueError('FRESH_DOCKER_HOST_REQUIRED')
        config_names = {'.env','docker-compose.prod.yml','recovery-compose.json','recovery-bootstrap-compose.json'}
        hashes = data.get('installed_config_hashes', {})
        if set(hashes) != config_names:
            raise ValueError('INFISICAL_CONFIG_CHANGED')
        for name, expected in hashes.items():
            path = target / name
            if (not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o077
                    or hashlib.sha256(path.read_bytes()).hexdigest() != expected):
                raise ValueError('INFISICAL_CONFIG_CHANGED')
        model = json.loads((target/'recovery-compose.json').read_bytes())
        def docker_json(args):
            p = subprocess.run(['docker',*args], capture_output=True, timeout=20)
            if p.returncode:
                raise ValueError('DOCKER_CHECK_REQUIRES_SUDO_OR_RUNNING_DAEMON')
            return json.loads(p.stdout)
        def docker_names(args):
            p = subprocess.run(['docker',*args], capture_output=True, timeout=15)
            if p.returncode:
                raise ValueError('DOCKER_CHECK_REQUIRES_SUDO_OR_RUNNING_DAEMON')
            return p.stdout.decode().split()
        ids = docker_names(['ps','-aq'])
        for item in docker_json(['inspect',*ids]) if ids else []:
            labels = item.get('Config',{}).get('Labels') or {}
            if (labels.get('com.docker.compose.project') != 'infisical'
                    or labels.get('com.docker.compose.project.working_dir') != str(target)
                    or labels.get('com.docker.compose.service') not in model['services']):
                raise ValueError('FOREIGN_CONTAINER_REFUSED')
        names = docker_names(['volume','ls','-q'])
        for item in docker_json(['volume','inspect',*names]) if names else []:
            labels = item.get('Labels') or {}
            key = labels.get('com.docker.compose.volume')
            declared = model.get('volumes',{})
            if (labels.get('com.docker.compose.project') != 'infisical' or key not in declared
                    or item.get('Name') != declared[key].get('name')):
                raise ValueError('FOREIGN_VOLUME_REFUSED')
    return dict(os='Ubuntu ' + info['VERSION_ID'].strip('"'), architecture='amd64', user=user.pw_name,
                home=user.pw_dir, existing_recovery=existing,
                containers=containers, volumes=volumes,
                machine_id=Path('/etc/machine-id').read_text().strip())


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--target')
    p.add_argument('--runner')
    p.add_argument('--docker-suite', action='store_true')
    p.add_argument('--fresh', action='store_true')
    p.add_argument('--role', choices=('stack','infisical'), default='stack')
    a = p.parse_args()
    try:
        if a.docker_suite:
            info = dict(x.split('=', 1) for x in Path('/etc/os-release').read_text().splitlines() if '=' in x)
            print(ubuntu_codename(info))
        else:
            if not a.target or not a.runner:
                p.error('--target and --runner are required for a host check')
            print(json.dumps(probe(Path(a.target), Path(a.runner), a.fresh, a.role)))
    except Exception as error:
        allowed = {'SYMLINK_PATH_REFUSED', 'DEPLOYMENT_UID_GID_REQUIRED', 'UBUNTU_LTS_VERSION_REQUIRED', 'UBUNTU_CODENAME_MISMATCH',
                   'UBUNTU_AMD64_REQUIRED', 'EXISTING_STACK_REFUSED', 'FOREIGN_RECOVERY_STATE',
                   'DOCKER_CHECK_REQUIRES_SUDO_OR_RUNNING_DAEMON', 'EXISTING_DOCKER_DATA', 'FRESH_DOCKER_HOST_REQUIRED',
                   'INFISICAL_CONFIG_CHANGED','FOREIGN_CONTAINER_REFUSED','FOREIGN_VOLUME_REFUSED','INVALID_RECOVERY_ROLE'}
        print(json.dumps({'error': str(error) if str(error) in allowed else 'HOST_CHECK_REFUSED'}))
        sys.exit(1)

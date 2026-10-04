"""Read-only deployment inventory. Never request env, logs or Compose contents."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


class InventoryRefused(Exception):
    pass


FORMAT = ('{"name":{{json .Name}},"image":{{json .Config.Image}},'
          '"image_id":{{json .Image}},'
          '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
          '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
          '"directory":{{json (index .Config.Labels "com.docker.compose.project.working_dir")}},'
          '"compose_files":{{json (index .Config.Labels "com.docker.compose.project.config_files")}},'
          '"mounts":{{json .Mounts}},"ports":{{json .NetworkSettings.Ports}}}')
MOUNT_KEYS = ('Type', 'Source', 'Destination', 'Name', 'RW')
ROW_KEYS = ('name', 'image', 'image_id', 'service', 'project', 'directory', 'compose_files')


def require(ok, code):
    if not ok:
        raise InventoryRefused(code)


def read(args):
    try:
        result = subprocess.run(args, capture_output=True, timeout=30)
        require(result.returncode == 0 and len(result.stdout) <= 1024**2,
                'INVENTORY_DOCKER_ACCESS_REQUIRED')
        return result.stdout.decode('utf-8')
    except InventoryRefused:
        raise
    except Exception:
        raise InventoryRefused('INVENTORY_READ_FAILED') from None


def clean_row(raw):
    require(isinstance(raw, dict), 'INVENTORY_INVALID_METADATA')
    row = {key: raw.get(key) for key in ROW_KEYS}
    require(all(value is None or isinstance(value, str) and len(value) <= 4096
                and not any(c in value for c in ('\0', '\n', '\r'))
                for value in row.values()), 'INVENTORY_INVALID_METADATA')
    require(isinstance(raw.get('mounts'), list), 'INVENTORY_INVALID_METADATA')
    row['mounts'] = []
    for mount in raw['mounts']:
        require(isinstance(mount, dict), 'INVENTORY_INVALID_METADATA')
        selected = {key: mount.get(key) for key in MOUNT_KEYS}
        require(all(value is None or isinstance(value, (str, bool))
                    for value in selected.values()), 'INVENTORY_INVALID_METADATA')
        row['mounts'].append(selected)
    row['ports'] = {}
    ports = raw.get('ports') or {}
    require(isinstance(ports, dict), 'INVENTORY_INVALID_METADATA')
    for port, bindings in ports.items():
        require(isinstance(port, str) and re.fullmatch(r'[0-9]{1,5}/(?:tcp|udp)', port),
                'INVENTORY_INVALID_METADATA')
        require(bindings is None or isinstance(bindings, list), 'INVENTORY_INVALID_METADATA')
        row['ports'][port] = None if bindings is None else [
            {key: binding.get(key) for key in ('HostIp', 'HostPort')} for binding in bindings]
    return row


def deployment(rows):
    """Identify one existing Compose project; never infer a deployment to write."""
    candidates = [row for row in rows if 'infisical' in (row['image'] or '').lower()]
    require(bool(candidates), 'INFISICAL_CONTAINER_NOT_FOUND')
    projects = {row['project'] for row in candidates}
    require(len(projects) == 1 and None not in projects and '' not in projects,
            'INFISICAL_COMPOSE_PROJECT_NOT_UNIQUE')
    project = next(iter(projects))
    selected = [row for row in rows if row['project'] == project]
    require(all(row['service'] and row['directory'] and row['compose_files'] for row in selected),
            'INFISICAL_COMPOSE_LABELS_REQUIRED')
    require(len({row['directory'] for row in selected}) == 1
            and len({row['compose_files'] for row in selected}) == 1,
            'INFISICAL_COMPOSE_PATHS_NOT_UNIQUE')
    require(len({row['service'] for row in selected}) == len(selected),
            'INFISICAL_SERVICE_REPLICAS_REQUIRE_REVIEW')
    return dict(project=project, directory=selected[0]['directory'],
                compose_files=selected[0]['compose_files'].split(','),
                services=sorted(selected, key=lambda row: row['service']))


def inventory(run=read, os_file=Path('/etc/os-release')):
    ids = run(['docker', 'ps', '-aq']).split()
    require(len(ids) <= 1000 and all(re.fullmatch(r'[0-9a-f]{12,64}', item) for item in ids),
            'INVENTORY_INVALID_CONTAINER_IDS')
    rows = [clean_row(json.loads(run(['docker', 'inspect', '--format', FORMAT, cid]))) for cid in ids]
    result = deployment(rows)
    for row in result['services']:
        image = json.loads(run(['docker', 'image', 'inspect', '--format',
            '{"digests":{{json .RepoDigests}},"os":{{json .Os}},"architecture":{{json .Architecture}}}',
            row['image_id']]))
        require(isinstance(image, dict), 'INVENTORY_INVALID_METADATA')
        digests = image.get('digests') or []
        require(isinstance(digests, list) and all(isinstance(x, str)
                and re.fullmatch(r'[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}', x) for x in digests),
                'INVENTORY_INVALID_IMAGE_DIGESTS')
        row['repo_digests'] = digests
        row['platform'] = '/'.join(str(image.get(key, '')) for key in ('os', 'architecture'))
    osinfo = dict(line.split('=', 1) for line in os_file.read_text().splitlines() if '=' in line)
    return dict(schema=1, operation='READ_ONLY_DEPLOYMENT_INVENTORY',
                os={key: osinfo.get(key, '').strip('"') for key in ('ID', 'VERSION_ID')},
                deployment=result)


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    try:
        print(json.dumps(inventory(), indent=2))
    except Exception as error:
        code = str(error) if isinstance(error, InventoryRefused) else 'INVENTORY_READ_FAILED'
        print(json.dumps(dict(error=code)))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

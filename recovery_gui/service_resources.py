"""Pure Compose resource inventory for reviewed service additions.

No file, process, Docker, or network operations occur here. Runtime resources are
recreated on the destination; data resources explicitly require an archive.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import PurePosixPath
import re


RESOURCE_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
METHODS = frozenset({'recreate', 'stopped_archive', 'external'})
RUNTIME_ROOTS = ('/proc', '/sys', '/dev', '/run', '/var/run', '/var/lib/docker')
MAX_CONTENT = 256 * 1024
MAX_CONFIGURATION = 4 * 1024 * 1024


class ResourceFailure(ValueError):
    """Closed errors only: rejected paths and contents never enter diagnostics."""


def require(ok, code):
    if not ok:
        raise ResourceFailure(code)


def clean_path(value, *, absolute=None):
    require(isinstance(value, str) and bool(value) and len(value) <= 4096
            and not any(ord(c) < 32 or ord(c) == 127 for c in value)
            and '\\' not in value and ':' not in value and '$' not in value,
            'SERVICE_RESOURCE_PATH_INVALID')
    require('..' not in value.split('/'), 'SERVICE_RESOURCE_PATH_INVALID')
    path = PurePosixPath(value)
    require(absolute is None or path.is_absolute() == absolute, 'SERVICE_RESOURCE_PATH_INVALID')
    require(str(path) not in ('', '.'), 'SERVICE_RESOURCE_PATH_INVALID')
    return str(path)


def configuration_files(files, service_names):
    require(isinstance(files, (list, tuple)), 'SERVICE_CONFIGURATION_INVALID')
    allowed = set(service_names)
    result, seen, total = [], set(), 0
    for item in files:
        require(isinstance(item, dict) and set(item) <= {'path', 'content', 'mode'}
                and {'path', 'content'} <= set(item), 'SERVICE_CONFIGURATION_INVALID')
        path = clean_path(item['path'], absolute=False)
        parts = PurePosixPath(path).parts
        require(len(parts) >= 4 and parts[0] == 'data' and parts[1] in allowed and parts[2] == 'public'
                and path != 'data/' + parts[1] + '/.env' and '.git' not in parts
                and '.secrets' not in parts and path not in seen,
                'SERVICE_CONFIGURATION_PATH_INVALID')
        content = item['content']
        require(isinstance(content, str) and '\0' not in content
                and len(content.encode('utf-8')) <= MAX_CONTENT, 'SERVICE_CONFIGURATION_CONTENT_INVALID')
        total += len(content.encode('utf-8'))
        require(total <= MAX_CONFIGURATION, 'SERVICE_CONFIGURATION_CONTENT_INVALID')
        mode = item.get('mode', 0o640)
        if isinstance(mode, str):
            require(re.fullmatch(r'0?[0-7]{3}', mode) is not None, 'SERVICE_CONFIGURATION_MODE_INVALID')
            mode = int(mode, 8)
        require(type(mode) is int and 0 <= mode <= 0o777, 'SERVICE_CONFIGURATION_MODE_INVALID')
        seen.add(path)
        result.append(dict(path=path, content=content, mode=mode,
                           sha256=hashlib.sha256(content.encode('utf-8')).hexdigest()))
    return tuple(result)


def _short_mount(value, service):
    require(isinstance(value, str) and len(value) <= 8192, 'SERVICE_MOUNT_INVALID')
    parts = value.split(':')
    require(1 <= len(parts) <= 3, 'SERVICE_MOUNT_INVALID')
    if len(parts) == 1:
        target = clean_path(parts[0], absolute=True)
        name = service + '-data-' + hashlib.sha256(target.encode()).hexdigest()[:12]
        return dict(type='volume', source=name, target=target, read_only=False)
    source, target = parts[:2]
    target = clean_path(target, absolute=True)
    flags = parts[2].split(',') if len(parts) == 3 else []
    require(all(flag in {'ro', 'rw', 'z', 'Z', 'cached', 'delegated', 'consistent',
                        'rprivate', 'rshared', 'rslave', 'private', 'shared', 'slave', 'unbindable'}
                for flag in flags) and not ({'ro', 'rw'} <= set(flags)), 'SERVICE_MOUNT_OPTIONS_INVALID')
    kind = 'bind' if source.startswith(('/', '.')) else 'volume'
    source = clean_path(source) if kind == 'bind' else source
    require(kind != 'volume' or RESOURCE_NAME.fullmatch(source), 'SERVICE_VOLUME_NAME_INVALID')
    result = dict(type=kind, source=source, target=target, read_only='ro' in flags)
    if kind == 'bind':
        bind = {}
        if 'z' in flags or 'Z' in flags:
            bind['selinux'] = 'Z' if 'Z' in flags else 'z'
        propagation = [f for f in flags if f in {'rprivate', 'rshared', 'rslave', 'private', 'shared', 'slave', 'unbindable'}]
        require(len(propagation) <= 1, 'SERVICE_MOUNT_OPTIONS_INVALID')
        if propagation:
            bind['propagation'] = propagation[0]
        if bind:
            result['bind'] = bind
    consistency = [f for f in flags if f in {'cached', 'delegated', 'consistent'}]
    require(len(consistency) <= 1, 'SERVICE_MOUNT_OPTIONS_INVALID')
    if consistency:
        result['consistency'] = consistency[0]
    return result


def normalize_mount(value, service):
    if isinstance(value, str):
        return _short_mount(value, service)
    require(isinstance(value, dict) and set(value) <= {
        'type', 'source', 'target', 'read_only', 'bind', 'volume', 'tmpfs', 'consistency'},
        'SERVICE_MOUNT_INVALID')
    result = deepcopy(value)
    kind = result.get('type')
    require(isinstance(kind, str) and kind in {'bind', 'volume', 'tmpfs'}, 'SERVICE_MOUNT_TYPE_INVALID')
    result['target'] = clean_path(result.get('target'), absolute=True)
    require(type(result.get('read_only', False)) is bool, 'SERVICE_MOUNT_OPTIONS_INVALID')
    result['read_only'] = result.get('read_only', False)
    if kind == 'tmpfs':
        require('source' not in result and 'bind' not in result and 'volume' not in result,
                'SERVICE_MOUNT_INVALID')
    else:
        source = result.get('source')
        require(source is None or isinstance(source, str), 'SERVICE_MOUNT_INVALID')
        if kind == 'volume' and not source:
            source = service + '-data-' + hashlib.sha256(result['target'].encode()).hexdigest()[:12]
        if kind == 'bind':
            result['source'] = clean_path(source)
            require('volume' not in result and 'tmpfs' not in result, 'SERVICE_MOUNT_OPTIONS_INVALID')
        else:
            require(isinstance(source, str) and RESOURCE_NAME.fullmatch(source), 'SERVICE_VOLUME_NAME_INVALID')
            result['source'] = source
            require('bind' not in result and 'tmpfs' not in result, 'SERVICE_MOUNT_OPTIONS_INVALID')
    for key in ('bind', 'volume', 'tmpfs'):
        require(key not in result or isinstance(result[key], dict), 'SERVICE_MOUNT_OPTIONS_INVALID')
    bind = result.get('bind', {})
    require(set(bind) <= {'propagation', 'create_host_path', 'selinux'}
            and ('create_host_path' not in bind or type(bind['create_host_path']) is bool),
            'SERVICE_MOUNT_OPTIONS_INVALID')
    require('propagation' not in bind or isinstance(bind['propagation'], str) and bind['propagation'] in
            {'rprivate', 'rshared', 'rslave', 'private', 'shared', 'slave', 'unbindable'},
            'SERVICE_MOUNT_OPTIONS_INVALID')
    require('selinux' not in bind or isinstance(bind['selinux'], str) and bind['selinux'] in {'z', 'Z'}, 'SERVICE_MOUNT_OPTIONS_INVALID')
    require('consistency' not in result or isinstance(result['consistency'], str) and result['consistency'] in {'cached', 'delegated', 'consistent'},
            'SERVICE_MOUNT_OPTIONS_INVALID')
    tmpfs = result.get('tmpfs', {})
    require(set(tmpfs) <= {'size', 'mode'} and ('mode' not in tmpfs or
            type(tmpfs['mode']) is int and 0 <= tmpfs['mode'] <= 0o7777) and
            ('size' not in tmpfs or type(tmpfs['size']) is int and tmpfs['size'] > 0 or
             isinstance(tmpfs.get('size'), str) and re.fullmatch(r'[0-9]+[bkmgBKMG]?', tmpfs['size'])),
            'SERVICE_MOUNT_OPTIONS_INVALID')
    volume = result.get('volume', {})
    require(set(volume) <= {'nocopy', 'subpath'}
            and ('nocopy' not in volume or type(volume['nocopy']) is bool), 'SERVICE_MOUNT_OPTIONS_INVALID')
    if 'subpath' in volume:
        volume['subpath'] = clean_path(volume['subpath'], absolute=False)
    return result


def _runtime(source):
    return source == '/' or any(source == root or source.startswith(root + '/') for root in RUNTIME_ROOTS) or (
        source.startswith('/') and source.endswith('.sock')) or source in {'/etc/localtime', '/etc/timezone'}


def inventory(services, compose_resources=None, files=(), policies=()):
    """Return normalized new Compose services plus their recovery resource plan."""
    require(isinstance(services, dict) and bool(services), 'SERVICE_RESOURCES_INVALID')
    require(isinstance(compose_resources or {}, dict) and set(compose_resources or {}) <= {'volumes', 'networks', 'configs'},
            'SERVICE_COMPOSE_TOP_LEVEL_UNSUPPORTED')
    top = deepcopy(compose_resources or {})
    for key, definitions in top.items():
        require(isinstance(definitions, dict), 'SERVICE_COMPOSE_RESOURCE_INVALID')
        for name, definition in definitions.items():
            require(isinstance(name, str) and RESOURCE_NAME.fullmatch(name)
                    and (definition is None or isinstance(definition, dict)), 'SERVICE_COMPOSE_RESOURCE_INVALID')
            if definition is None:
                definitions[name] = {}
    public_files = configuration_files(files, services)
    file_paths = {row['path'] for row in public_files}
    require(isinstance(policies, (list, tuple)), 'SERVICE_STORAGE_POLICY_INVALID')
    policy_map = {}
    for policy in policies:
        require(isinstance(policy, dict) and set(policy) <= {'service', 'target', 'role', 'recovery', 'method'}
                and {'service', 'target'} <= set(policy)
                and (('method' in policy) != ('recovery' in policy))
                and isinstance(policy['service'], str) and policy['service'] in services, 'SERVICE_STORAGE_POLICY_INVALID')
        key = (policy['service'], clean_path(policy['target'], absolute=True))
        recovery = policy.get('recovery', {'method': policy.get('method')})
        require(key not in policy_map and isinstance(recovery, dict) and set(recovery) == {'method'}
                and isinstance(recovery['method'], str) and recovery['method'] in METHODS, 'SERVICE_STORAGE_POLICY_INVALID')
        require(isinstance(policy.get('role', 'data'), str) and policy.get('role', 'data') in {'runtime', 'config', 'data', 'external'}, 'SERVICE_STORAGE_POLICY_INVALID')
        policy_map[key] = dict(policy, recovery=recovery)
    resources, normalized, used_policies = [], deepcopy(services), set()
    for service_name, service in normalized.items():
        require(isinstance(service, dict), 'SERVICE_RESOURCES_INVALID')
        require(not ({'secrets', 'volumes_from'} & set(service)), 'SERVICE_EXTERNAL_CONFIGURATION_UNSUPPORTED')
        mounts = service.get('volumes', [])
        require(isinstance(mounts, list), 'SERVICE_VOLUME_INVALID')
        targets, new_mounts = set(), []
        for raw in mounts:
            mount = normalize_mount(raw, service_name)
            target, kind = mount['target'], mount['type']
            require(target not in targets, 'SERVICE_MOUNT_TARGET_DUPLICATE')
            targets.add(target)
            source = mount.get('source', '')
            role, method = 'data', 'stopped_archive'
            if kind == 'tmpfs' or (kind == 'bind' and _runtime(source)):
                role, method = 'runtime', 'recreate'
            elif kind == 'bind' and source in file_paths:
                role, method = 'config', 'recreate'
            elif mount['read_only']:
                role, method = 'external', 'recreate'
            if kind == 'volume':
                definition = top.setdefault('volumes', {}).setdefault(source, {})
                if definition.get('external'):
                    role, method = 'external', 'external'
            key = (service_name, target)
            if key in policy_map:
                policy = policy_map[key]
                method = policy['recovery']['method']
                role = policy.get('role', 'external' if method == 'external' else role)
                used_policies.add(key)
                require(not (kind == 'tmpfs' or (kind == 'bind' and _runtime(source))) or
                        (role == 'runtime' and method == 'recreate'), 'SERVICE_RUNTIME_ARCHIVE_REFUSED')
                require(role != 'runtime' or kind == 'tmpfs' or (kind == 'bind' and _runtime(source)),
                        'SERVICE_RUNTIME_SOURCE_INVALID')
                require(role != 'config' or (kind == 'bind' and (source in file_paths or
                        mount['read_only'] and any(path.startswith(source + '/') for path in file_paths))),
                        'SERVICE_CONFIGURATION_SOURCE_INVALID')
                require(method != 'recreate' or mount['read_only'] or role in {'runtime', 'config'},
                        'SERVICE_DATA_RECOVERY_REQUIRED')
            if kind == 'bind' and method == 'stopped_archive':
                require(not source.startswith('/') and source.startswith('data/'),
                        'SERVICE_DATA_RESOURCE_OUTSIDE_STACK')
            if kind == 'volume' and method == 'stopped_archive':
                require(definition.get('driver', 'local') == 'local' and not definition.get('driver_opts')
                        and not definition.get('external'), 'SERVICE_VOLUME_DRIVER_UNSUPPORTED')
            rid = hashlib.sha256(json.dumps([service_name, kind, source, target], separators=(',', ':')).encode()).hexdigest()[:20]
            resources.append(dict(id=rid, service=service_name, type=kind, source=source, target=target,
                                  read_only=mount['read_only'], role=role, recovery={'method': method}))
            new_mounts.append(mount)
        if mounts:
            service['volumes'] = new_mounts
        tmpfs = service.get('tmpfs', [])
        if isinstance(tmpfs, str):
            tmpfs = [tmpfs]
        require(isinstance(tmpfs, list), 'SERVICE_TMPFS_INVALID')
        for entry in tmpfs:
            require(isinstance(entry, str), 'SERVICE_TMPFS_INVALID')
            target = clean_path(entry.split(':', 1)[0], absolute=True)
            require(target not in targets, 'SERVICE_MOUNT_TARGET_DUPLICATE')
            targets.add(target)
            rid = hashlib.sha256((service_name + ':tmpfs:' + target).encode()).hexdigest()[:20]
            resources.append(dict(id=rid, service=service_name, type='tmpfs', source='', target=target,
                                  read_only=False, role='runtime', recovery={'method': 'recreate'}))
        configs = service.get('configs', [])
        require(isinstance(configs, list), 'SERVICE_CONFIGURATION_INVALID')
        for ref in configs:
            require(isinstance(ref, (str, dict)), 'SERVICE_CONFIGURATION_INVALID')
            name = ref if isinstance(ref, str) else ref.get('source')
            require(isinstance(name, str) and name in top.get('configs', {}), 'SERVICE_CONFIGURATION_MISSING')
            definition = top['configs'][name]
            require(set(definition) <= {'name', 'file', 'content', 'environment', 'external'}, 'SERVICE_CONFIGURATION_INVALID')
            require(sum(k in definition for k in ('file', 'content', 'environment', 'external')) == 1,
                    'SERVICE_CONFIGURATION_INVALID')
            target = '/' + name if isinstance(ref, str) else ref.get('target', '/' + name)
            target = clean_path(target, absolute=True)
            require(target not in targets, 'SERVICE_MOUNT_TARGET_DUPLICATE')
            targets.add(target)
            source = definition.get('file', 'config:' + name)
            if 'file' in definition:
                source = clean_path(source, absolute=False)
                definition['file'] = './' + source
                require(source in file_paths, 'SERVICE_CONFIGURATION_FILE_REQUIRED')
            rid = hashlib.sha256((service_name + ':config:' + name + ':' + target).encode()).hexdigest()[:20]
            resources.append(dict(id=rid, service=service_name, type='config', source=source, target=target,
                                  read_only=True, role='config' if not definition.get('external') else 'external',
                                  recovery={'method': 'recreate' if not definition.get('external') else 'external'}))
    require(set(policy_map) == used_policies, 'SERVICE_STORAGE_POLICY_TARGET_MISSING')
    seeded_paths = file_paths | {'data/' + service + '/.env' for service in services}
    require(not any(row['type'] == 'bind' and row['recovery']['method'] == 'stopped_archive'
                    and any(path == row['source'] or path.startswith(row['source'] + '/') for path in seeded_paths)
                    for row in resources), 'SERVICE_CONFIGURATION_DATA_OVERLAP')
    for item in public_files:
        path = item['path']
        require(any(row['read_only'] and (row['type'] == 'bind' and (path == row['source'] or path.startswith(row['source'] + '/'))
                    or row['type'] == 'config' and row['source'] == path) for row in resources),
                'SERVICE_CONFIGURATION_NOT_MOUNTED')
    return dict(services=normalized, compose_resources=top, resources=tuple(resources), configuration_files=public_files)

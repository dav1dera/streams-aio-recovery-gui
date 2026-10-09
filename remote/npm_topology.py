"""Private, exact NPM upstream bindings for a replacement host only.

No DNS/router change and no text substitution in nginx snippets. Capture runs
against the source SQLite DB read-only. Prepare runs before any container mounts
the restored DB and journals the closed before/after routing images. External
hosts, ports, schemes, certificates and access lists are never rewritten.
"""
import contextlib
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from urllib.parse import quote

FORMAT = 'streams-aio-npm-topology'
JOURNAL = '.generated/npm-topology-recovery.json'
DATABASE = 'data/npm/data/database.sqlite'
TABLES = ('proxy_host', 'stream')
FIELDS = {
    'proxy_host': ('domain_names', 'forward_host', 'forward_port', 'forward_scheme', 'locations', 'advanced_config'),
    'stream': ('forwarding_host', 'forwarding_port'),
}
ROLES = frozenset({'stack', 'infisical', 'compose', 'external'})
HEX = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
SERVICE = re.compile(r'[a-z0-9][a-z0-9_-]*\Z')


class Refused(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Refused(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def fingerprint(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def address(value):
    try:
        result = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        raise Refused('NPM_TOPOLOGY_ADDRESS_INVALID') from None
    require(isinstance(value, str) and str(result) == value and not result.is_unspecified
            and not result.is_multicast and not result.is_loopback, 'NPM_TOPOLOGY_ADDRESS_INVALID')
    return value


def checked(path, private=False, exists=True):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'NPM_TOPOLOGY_PATH_INVALID')
    if exists:
        info = path.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'NPM_TOPOLOGY_PATH_INVALID')
        if private and os.name != 'nt':
            require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
                    'NPM_TOPOLOGY_PRIVATE_FILE_REQUIRED')
    return path


def rows(database):
    """Routing fields only; quarantine may legitimately change enabled/cert IDs."""
    database = checked(database)
    output = []
    try:
        with contextlib.closing(sqlite3.connect('file:' + quote(str(database), safe='/:')
                + '?mode=ro', uri=True, timeout=5)) as db:
            db.execute('PRAGMA query_only=ON')
            db.row_factory = sqlite3.Row
            for table in TABLES:
                columns = {r[1] for r in db.execute('PRAGMA table_info("' + table + '")')}
                require({'id', 'is_deleted', *FIELDS[table]} <= columns, 'NPM_TOPOLOGY_SCHEMA_UNSUPPORTED')
                selected = ','.join(('id', *FIELDS[table]))
                for record in db.execute('SELECT ' + selected + ' FROM ' + table
                                         + ' WHERE is_deleted=0 ORDER BY id'):
                    row = dict(record)
                    identity = row.pop('id')
                    require(type(identity) is int and identity > 0, 'NPM_TOPOLOGY_SCHEMA_UNSUPPORTED')
                    if table == 'proxy_host':
                        for field, empty in (('domain_names', []), ('locations', [])):
                            value = row[field]
                            row[field] = json.loads(value) if isinstance(value, str) else empty if value is None else value
                        row['advanced_config'] = row['advanced_config'] or ''
                    output.append({'table': table, 'id': identity, 'routing': row})
        validate_rows(output)
        return output
    except Refused:
        raise
    except (OSError, sqlite3.Error, ValueError, TypeError, UnicodeError):
        raise Refused('NPM_TOPOLOGY_DATABASE_INVALID') from None


def validate_rows(values):
    require(isinstance(values, list) and 0 < len(values) <= 4096, 'NPM_TOPOLOGY_SCHEMA_UNSUPPORTED')
    identities = set()
    for row in values:
        require(isinstance(row, dict) and set(row) == {'table', 'id', 'routing'}
                and row['table'] in TABLES and type(row['id']) is int and row['id'] > 0
                and (row['table'], row['id']) not in identities, 'NPM_TOPOLOGY_SCHEMA_UNSUPPORTED')
        identities.add((row['table'], row['id']))
        data = row['routing']
        require(isinstance(data, dict) and set(data) == set(FIELDS[row['table']]), 'NPM_TOPOLOGY_SCHEMA_UNSUPPORTED')
        host, port = ('forward_host', 'forward_port') if row['table'] == 'proxy_host' else ('forwarding_host', 'forwarding_port')
        require(isinstance(data[host], str) and 0 < len(data[host]) <= 253
                and not re.search(r'\s|[\x00/]', data[host]) and type(data[port]) is int
                and 1 <= data[port] <= 65535, 'NPM_TOPOLOGY_SCHEMA_UNSUPPORTED')
        if row['table'] == 'proxy_host':
            require(data['forward_scheme'] in ('http', 'https') and isinstance(data['advanced_config'], str)
                    and len(data['advanced_config']) <= 1024 * 1024
                    and isinstance(data['domain_names'], list) and data['domain_names']
                    and all(isinstance(v, str) and 0 < len(v) <= 253 for v in data['domain_names'])
                    and isinstance(data['locations'], list) and len(data['locations']) <= 256,
                    'NPM_TOPOLOGY_SCHEMA_UNSUPPORTED')
            for location in data['locations']:
                require(isinstance(location, dict) and isinstance(location.get('forward_host'), str)
                        and location.get('forward_scheme') in ('http', 'https')
                        and type(location.get('forward_port')) is int
                        and 1 <= location['forward_port'] <= 65535,
                        'NPM_TOPOLOGY_SCHEMA_UNSUPPORTED')


def endpoints(row):
    data = row['routing']
    if row['table'] == 'stream':
        yield ['forwarding_host'], data['forwarding_host'], data['forwarding_port']
    else:
        yield ['forward_host'], data['forward_host'], data['forward_port']
        for index, location in enumerate(data['locations']):
            yield ['locations', index, 'forward_host'], location['forward_host'], location['forward_port']


def inventory(model, stack_addresses, infisical_address, infisical_port):
    require(isinstance(stack_addresses, list) and stack_addresses and len(stack_addresses) <= 128
            and len(set(stack_addresses)) == len(stack_addresses), 'NPM_TOPOLOGY_SOURCE_INVALID')
    stack_addresses = sorted(address(v) for v in stack_addresses)
    infisical_address = address(infisical_address)
    require(infisical_address not in stack_addresses and type(infisical_port) is int
            and 1 <= infisical_port <= 65535, 'NPM_TOPOLOGY_SOURCE_INVALID')
    require(isinstance(model, dict) and isinstance(model.get('services'), dict), 'NPM_TOPOLOGY_SOURCE_INVALID')
    names, ips, ports = {}, {}, {}
    for service, item in model['services'].items():
        require(SERVICE.fullmatch(service) and isinstance(item, dict), 'NPM_TOPOLOGY_SOURCE_INVALID')
        for name in (service, item.get('container_name')):
            if isinstance(name, str):
                names.setdefault(name, set()).add(service)
        for network in (item.get('networks') or {}).values():
            if isinstance(network, dict):
                for key in ('ipv4_address', 'ipv6_address'):
                    if network.get(key):
                        ips.setdefault(address(network[key]), set()).add(service)
                for name in network.get('aliases', []):
                    if isinstance(name, str):
                        names.setdefault(name, set()).add(service)
        for entry in item.get('ports') or []:
            require(isinstance(entry, dict), 'NPM_TOPOLOGY_SOURCE_INVALID')
            if entry.get('protocol', 'tcp') != 'tcp':
                continue
            published = entry.get('published')
            require(isinstance(published, (str, int)) and str(published).isdigit()
                    and 1 <= int(published) <= 65535, 'NPM_TOPOLOGY_SOURCE_INVALID')
            bind = entry.get('host_ip', '0.0.0.0')
            for source in stack_addresses:
                if bind in ('0.0.0.0', '::', '', source):
                    ports.setdefault((source, int(published)), set()).add(service)
    return {'stack_addresses': stack_addresses, 'infisical_address': infisical_address,
            'infisical_port': infisical_port}, names, ips, ports


def capture(database, model, *, stack_commit, stack_addresses, infisical_address, infisical_port):
    require(isinstance(stack_commit, str) and COMMIT.fullmatch(stack_commit), 'NPM_TOPOLOGY_SOURCE_INVALID')
    source, names, ips, ports = inventory(model, stack_addresses, infisical_address, infisical_port)
    values = rows(database)
    bindings = []
    for row in values:
        data = row['routing']
        snippets = [data.get('advanced_config', '')]
        snippets += [loc.get('advanced_config', '') for loc in data.get('locations', [])]
        require(all(isinstance(value, str) and not any(ip in value for ip in
                    [*source['stack_addresses'], source['infisical_address']]) for value in snippets),
                'NPM_TOPOLOGY_UNCLASSIFIED_REFERENCE')
        for path, host, port in endpoints(row):
            role, service = 'external', None
            if host in source['stack_addresses']:
                candidates = ports.get((host, port), set())
                require(len(candidates) == 1, 'NPM_TOPOLOGY_ENDPOINT_UNPROVEN')
                role, service = 'stack', next(iter(candidates))
            elif host == source['infisical_address']:
                require(port == source['infisical_port'], 'NPM_TOPOLOGY_ENDPOINT_UNPROVEN')
                role, service = 'infisical', 'backend'
            elif host in names or host in ips:
                candidates = names.get(host, ips.get(host, set()))
                require(len(candidates) == 1, 'NPM_TOPOLOGY_ENDPOINT_UNPROVEN')
                role, service = 'compose', next(iter(candidates))
            else:
                require(not SERVICE.fullmatch(host), 'NPM_TOPOLOGY_SERVICE_UNPROVEN')
            bindings.append({'table': row['table'], 'id': row['id'], 'path': path,
                             'role': role, 'service': service})
    result = {'schema': 1, 'format': FORMAT, 'stack_commit': stack_commit,
              'source': source, 'routes': values, 'bindings': bindings,
              'routes_sha256': fingerprint(values)}
    validate(result, stack_commit=stack_commit)
    return result


def validate(value, *, stack_commit):
    require(isinstance(value, dict) and set(value) == {'schema', 'format', 'stack_commit',
            'source', 'routes', 'bindings', 'routes_sha256'} and type(value['schema']) is int
            and value['schema'] == 1 and value['format'] == FORMAT and value['stack_commit'] == stack_commit
            and isinstance(stack_commit, str) and COMMIT.fullmatch(stack_commit), 'NPM_TOPOLOGY_INVALID')
    source = value['source']
    require(isinstance(source, dict) and set(source) == {'stack_addresses', 'infisical_address', 'infisical_port'}
            and isinstance(source['stack_addresses'], list) and source['stack_addresses']
            and len(set(source['stack_addresses'])) == len(source['stack_addresses']), 'NPM_TOPOLOGY_INVALID')
    for item in source['stack_addresses']:
        address(item)
    address(source['infisical_address'])
    require(source['infisical_address'] not in source['stack_addresses'] and type(source['infisical_port']) is int
            and 1 <= source['infisical_port'] <= 65535, 'NPM_TOPOLOGY_INVALID')
    validate_rows(value['routes'])
    require(value['routes_sha256'] == fingerprint(value['routes']) and isinstance(value['bindings'], list),
            'NPM_TOPOLOGY_INVALID')
    expected = {(row['table'], row['id'], tuple(path)): (host, port)
                for row in value['routes'] for path, host, port in endpoints(row)}
    seen = set()
    for item in value['bindings']:
        require(isinstance(item, dict) and set(item) == {'table', 'id', 'path', 'role', 'service'}
                and item['role'] in ROLES and isinstance(item['path'], list), 'NPM_TOPOLOGY_INVALID')
        identity = (item['table'], item['id'], tuple(item['path']))
        require(identity in expected and identity not in seen, 'NPM_TOPOLOGY_INVALID')
        seen.add(identity)
        host, port = expected[identity]
        if item['role'] == 'stack':
            require(host in source['stack_addresses'] and isinstance(item['service'], str)
                    and SERVICE.fullmatch(item['service']), 'NPM_TOPOLOGY_INVALID')
        elif item['role'] == 'infisical':
            require(host == source['infisical_address'] and port == source['infisical_port']
                    and item['service'] == 'backend', 'NPM_TOPOLOGY_INVALID')
        else:
            require(host not in {*source['stack_addresses'], source['infisical_address']}, 'NPM_TOPOLOGY_INVALID')
            require(item['service'] is None if item['role'] == 'external' else
                    isinstance(item['service'], str) and bool(SERVICE.fullmatch(item['service'])), 'NPM_TOPOLOGY_INVALID')
    require(seen == set(expected), 'NPM_TOPOLOGY_INVALID')
    return value


def planned(value, targets):
    validate(value, stack_commit=value.get('stack_commit'))
    require(isinstance(targets, dict) and set(targets) == {'stack', 'infisical'}, 'NPM_TOPOLOGY_TARGET_INVALID')
    for target in targets.values():
        address(target)
    require(targets['stack'] != targets['infisical'], 'NPM_TOPOLOGY_TARGET_INVALID')
    after = copy.deepcopy(value['routes'])
    selected = {(row['table'], row['id']): row['routing'] for row in after}
    for binding in value['bindings']:
        if binding['role'] not in targets:
            continue
        parent = selected[(binding['table'], binding['id'])]
        for part in binding['path'][:-1]:
            parent = parent[part]
        parent[binding['path'][-1]] = targets[binding['role']]
    return {'schema': 1, 'format': FORMAT, 'stack_commit': value['stack_commit'],
            'topology_sha256': fingerprint(value), 'targets': dict(targets),
            'before': value['routes'], 'after': after,
            'before_sha256': fingerprint(value['routes']), 'after_sha256': fingerprint(after)}


def save(path, value, *, exclusive=False):
    path = checked(path, exists=False)
    temporary = path.with_name(path.name + '.new')
    require(not temporary.exists(), 'NPM_TOPOLOGY_JOURNAL_INVALID')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
        require(not exclusive or not path.exists(), 'NPM_TOPOLOGY_JOURNAL_INVALID')
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def prepare(root, value, targets, run):
    """Caller proves deployment/checkpoint ownership; this gate proves unmounted."""
    root = Path(root).absolute()
    database = checked(root / DATABASE)
    if os.name != 'nt':
        info = database.stat()
        require(info.st_uid == 1000 and info.st_gid == 1000
                and stat.S_IMODE(info.st_mode) == 0o600, 'NPM_TOPOLOGY_DATABASE_IDENTITY_REQUIRED')
    expected = planned(value, targets)
    raw = run(['docker', 'ps', '-aq'])
    ids = raw.decode().split()
    containers = json.loads(run(['docker', 'inspect', *ids])) if ids else []
    data = str((root / 'data/npm/data').absolute())
    require(isinstance(containers, list) and not any(m.get('Source') == data for row in containers
            for m in row.get('Mounts', [])), 'NPM_TOPOLOGY_ALREADY_MOUNTED')
    journal = checked(root / JOURNAL, exists=False)
    require(journal.parent.is_dir() and not journal.parent.is_symlink(), 'NPM_TOPOLOGY_JOURNAL_INVALID')
    if journal.exists():
        saved = json.loads(checked(journal, private=True).read_bytes())
        require(saved in [dict(expected, phase='planned'), dict(expected, phase='complete')],
                'NPM_TOPOLOGY_JOURNAL_INVALID')
    else:
        require(rows(database) == expected['before'], 'NPM_TOPOLOGY_SOURCE_DRIFT')
        save(journal, dict(expected, phase='planned'), exclusive=True)
    current = rows(database)
    require(current in (expected['before'], expected['after']), 'NPM_TOPOLOGY_SOURCE_DRIFT')
    if current != expected['after']:
        with contextlib.closing(sqlite3.connect(database, timeout=5)) as db:
            db.execute('BEGIN IMMEDIATE')
            # Re-read under the writer transaction; no source rows may drift.
            require(rows(database) == expected['before'], 'NPM_TOPOLOGY_SOURCE_DRIFT')
            for before, after in zip(expected['before'], expected['after']):
                require(before['table'] == after['table'] and before['id'] == after['id'], 'NPM_TOPOLOGY_INVALID')
                changed = {k: v for k, v in after['routing'].items() if v != before['routing'][k]}
                require(set(changed) <= {'forward_host', 'forwarding_host', 'locations'}, 'NPM_TOPOLOGY_INVALID')
                if changed:
                    fields = sorted(changed)
                    values = [json.dumps(changed[k], separators=(',', ':')) if k == 'locations' else changed[k] for k in fields]
                    cursor = db.execute('UPDATE ' + before['table'] + ' SET ' + ','.join(k + '=?' for k in fields)
                                        + ' WHERE id=? AND is_deleted=0', [*values, before['id']])
                    require(cursor.rowcount == 1, 'NPM_TOPOLOGY_SOURCE_DRIFT')
            db.commit()
    require(rows(database) == expected['after'], 'NPM_TOPOLOGY_APPLY_FAILED')
    complete = dict(expected, phase='complete')
    save(journal, complete)
    return {'schema': 1, 'sha256': fingerprint(complete), 'topology_sha256': fingerprint(value),
            'changed_rows': sum(a != b for a, b in zip(expected['before'], expected['after']))}


def verify(root, evidence, *, stack_commit):
    root = Path(root).absolute()
    require(isinstance(evidence, dict) and set(evidence) == {'schema', 'sha256', 'topology_sha256', 'changed_rows'}
            and evidence['schema'] == 1 and type(evidence['changed_rows']) is int
            and evidence['changed_rows'] >= 0 and HEX.fullmatch(evidence['sha256'])
            and HEX.fullmatch(evidence['topology_sha256']), 'NPM_TOPOLOGY_EVIDENCE_REQUIRED')
    saved = json.loads(checked(root / JOURNAL, private=True).read_bytes())
    require(isinstance(saved, dict) and set(saved) == {'schema', 'format', 'stack_commit', 'topology_sha256',
            'targets', 'before', 'after', 'before_sha256', 'after_sha256', 'phase'}
            and saved['schema'] == 1 and saved['format'] == FORMAT and saved['phase'] == 'complete'
            and saved['stack_commit'] == stack_commit and fingerprint(saved) == evidence['sha256']
            and saved['topology_sha256'] == evidence['topology_sha256'], 'NPM_TOPOLOGY_EVIDENCE_REQUIRED')
    validate_rows(saved['before']); validate_rows(saved['after'])
    require(saved['before_sha256'] == fingerprint(saved['before'])
            and saved['after_sha256'] == fingerprint(saved['after'])
            and rows(root / DATABASE) == saved['after'], 'NPM_TOPOLOGY_SOURCE_DRIFT')
    return saved


def report(value):
    """Only structural data suitable for the fixed live-audit output schema."""
    validate(value, stack_commit=value.get('stack_commit'))
    counts = {role: 0 for role in sorted(ROLES)}
    route_ids = []
    selected = {(row['table'], row['id'], tuple(path)): port
                for row in value['routes'] for path, host, port in endpoints(row)}
    for item in value['bindings']:
        counts[item['role']] += 1
        route_ids.append({'table': item['table'], 'id': item['id'], 'role': item['role'],
                          'service': item['service'], 'port': selected[(item['table'], item['id'], tuple(item['path']))]})
    return {'schema': 1, 'routes': len(value['routes']), 'bindings': counts, 'rows': route_ids}

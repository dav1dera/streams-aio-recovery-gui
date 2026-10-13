"""Relocate exact local application endpoints using verified backup topology.

Only Headscale extra A/AAAA values and Honey service href hosts are edited.
The private journal stores hashes and metadata, never configuration contents.
The startup caller holds recovery.lock and has validated replacement ownership.
No resolver, network, Docker or public DNS operation is performed here.
"""
import copy
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from urllib.parse import urlsplit


ERROR = 'LOCAL_ENDPOINTS_RELOCATION_REFUSED'
DRIFT = 'LOCAL_ENDPOINTS_SOURCE_DRIFT'
JOURNAL = 'local-endpoints-recovery.json'
FILES = {
    'headscale': 'data/headscale/data/config/config.yaml',
    'honey': 'data/honey/data/config/config.json',
}
HEX = re.compile(r'[0-9a-f]{64}\Z')


def require(ok, code=ERROR):
    if not ok:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def checked(path, *, exists=True, private=False):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)))
    if exists:
        info = path.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
        if os.name != 'nt':
            mode = stat.S_IMODE(info.st_mode)
            require(info.st_uid in (0, 1000) and mode & 0o400 and not mode & ~0o664)
            if private:
                require(info.st_uid == 0 and mode == 0o600)
    return path


def decode(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value)
            value[key] = item
        return value
    require(len(raw) <= 8 * 1024 * 1024)
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: require(False))


def topology(root, state):
    spec = importlib.util.spec_from_file_location('local_endpoint_operational_policy',
                Path(__file__).with_name('operational_profile.py'))
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    module, value, saved, _ = policy.topology_targets(root, state)
    targets = state['npm_upstream_targets']
    require(saved['targets'] == targets and set(targets) == {'stack', 'infisical'})
    mapping = {address: module.address(targets['stack']) for address in value['source']['stack_addresses']}
    mapping[value['source']['infisical_address']] = module.address(targets['infisical'])
    return {'schema': 1, 'topology_sha256': module.fingerprint(value), 'mapping': mapping}


def href(value, mapping):
    if not isinstance(value, str) or not re.match(r'[A-Za-z][A-Za-z0-9+.-]*://', value):
        return value
    try:
        parsed = urlsplit(value)
        source = str(ipaddress.ip_address(parsed.hostname))
    except (ValueError, TypeError):
        return value
    target = mapping.get(source)
    if target is None or target == source:
        return value
    # Preserve the original scheme, credentials, port spelling, query and
    # fragment verbatim; replace only the parsed authority's IP host.
    try:
        parsed.port
    except ValueError:
        raise ValueError(ERROR) from None
    authority_start = value.index('://') + 3
    authority = parsed.netloc
    require(value[authority_start:authority_start + len(authority)] == authority)
    host_start = authority.rfind('@') + 1
    host_end = (authority.index(']', host_start) + 1 if authority[host_start:host_start + 1] == '['
                else authority.find(':', host_start))
    if host_end == -1:
        host_end = len(authority)
    replacement = '[' + target + ']' if ipaddress.ip_address(target).version == 6 else target
    return (value[:authority_start] + authority[:host_start] + replacement + authority[host_end:]
            + value[authority_start + len(authority):])


def transform(service, raw, mapping):
    value = decode(raw)
    require(isinstance(value, dict))
    changed = 0
    if service == 'headscale':
        dns = value.get('dns', {})
        require(isinstance(dns, dict))
        records = dns.get('extra_records', [])
        require(isinstance(records, list))
        for record in records:
            require(isinstance(record, dict))
            source = record.get('value')
            if record.get('type') not in ('A', 'AAAA') or not isinstance(source, str) or source not in mapping:
                continue
            target = mapping[source]
            if target != source:
                family = 4 if record['type'] == 'A' else 6
                require(ipaddress.ip_address(source).version == family
                        and ipaddress.ip_address(target).version == family)
                record['value'] = target
                changed += 1
    else:
        require(service == 'honey')
        services = value.get('services', [])
        require(isinstance(services, list))
        for entry in services:
            require(isinstance(entry, dict))
            if 'href' in entry:
                replacement = href(entry['href'], mapping)
                if replacement != entry['href']:
                    entry['href'] = replacement
                    changed += 1
    after = (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode() if changed else raw
    return after, changed


def metadata(path):
    info = checked(path).stat()
    return {'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode)}


def atomic(path, raw, identity):
    """Replace atomically, preserving application ownership and permissions."""
    path = checked(path, exists=False)
    fd, name = tempfile.mkstemp(prefix='.local-endpoints-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(raw)
            output.flush()
            if os.name != 'nt':
                os.fchown(output.fileno(), identity['uid'], identity['gid'])
                os.fchmod(output.fileno(), identity['mode'])
            os.fsync(output.fileno())
        if os.name == 'nt':
            os.chmod(name, identity['mode'])
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def journal_write(path, value):
    atomic(path, encoded(value), {'uid': 0, 'gid': 0, 'mode': 0o600})


def apply(root, home, state, run, save):
    """Apply or resume a closed hash plan; run is deliberately never invoked.

    Return private checkpoint evidence plus services rewritten on this call.
    Existing containers with a single-file bind need caller reconciliation;
    this module never recreates or restarts a container.
    """
    try:
        return _apply(Path(root).absolute(), Path(home).absolute(), state, save)
    except Exception as error:
        raise ValueError(DRIFT if str(error) == DRIFT else ERROR) from None


def _apply(root, home, state, save):
    journal = checked(home / JOURNAL, exists=False)
    checkpoint = checked(home / 'state.json', private=True)
    require(home.is_dir() and not home.is_symlink())
    context = topology(root, state)
    present = {name: checked(root / relative) for name, relative in FILES.items()
               if checked(root / relative, exists=False).exists()}
    if journal.exists():
        plan = decode(checked(journal, private=True).read_bytes())
        require(isinstance(plan, dict) and set(plan) == {*context, 'files', 'phase'}
                and all(plan.get(key) == value for key, value in context.items())
                and plan['phase'] in ('planned', 'complete') and isinstance(plan['files'], dict)
                and set(plan['files']) == set(present))
    else:
        require(state.get('local_endpoints') is None)
        rows = {}
        for name, path in present.items():
            before = path.read_bytes()
            after, changed = transform(name, before, context['mapping'])
            rows[name] = dict(metadata(path), before_sha256=digest(before),
                              after_sha256=digest(after), changed=changed)
        plan = dict(context, files=rows, phase='planned')
        journal_write(journal, plan)
    completed = dict(plan, phase='complete')
    evidence = {'schema': 1, 'sha256': digest(encoded(completed)),
                'changed_files': sum(row['before_sha256'] != row['after_sha256'] for row in plan['files'].values())}
    existing = state.get('local_endpoints')
    require(existing is None or plan['phase'] == 'complete' and existing == evidence)
    pending = []
    # Validate every file before editing any file, including unchanged fields.
    for name, path in present.items():
        row = plan['files'][name]
        require(isinstance(row, dict) and set(row) == {'uid', 'gid', 'mode', 'before_sha256', 'after_sha256', 'changed'}
                and all(type(row[key]) is int and row[key] >= 0 for key in ('uid', 'gid', 'mode', 'changed'))
                and all(isinstance(row[key], str) and HEX.fullmatch(row[key]) for key in ('before_sha256', 'after_sha256')))
        require(metadata(path) == {key: row[key] for key in ('uid', 'gid', 'mode')}, DRIFT)
        before = path.read_bytes()
        current = digest(before)
        if current == row['after_sha256']:
            continue
        require(plan['phase'] == 'planned' and current == row['before_sha256'], DRIFT)
        after, changed = transform(name, before, context['mapping'])
        require(digest(after) == row['after_sha256'] and changed == row['changed'], DRIFT)
        pending.append((name, path, before, after, row))
    rewritten = []
    for name, path, before, after, row in pending:
        require(checked(path).read_bytes() == before and metadata(path) == {key: row[key] for key in ('uid', 'gid', 'mode')}, DRIFT)
        atomic(path, after, row)
        require(checked(path).read_bytes() == after and metadata(path) == {key: row[key] for key in ('uid', 'gid', 'mode')}, DRIFT)
        rewritten.append(name)
    if plan['phase'] != 'complete':
        journal_write(journal, completed)
    if existing is None:
        updated = copy.deepcopy(state)
        updated['local_endpoints'] = evidence
        save(checkpoint, updated)
        state.update(updated)
    return dict(evidence, rewritten=rewritten, affected=sorted(name for name, row in plan['files'].items()
                    if row['before_sha256'] != row['after_sha256']))

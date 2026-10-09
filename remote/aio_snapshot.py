"""Native, image-bound snapshots of the two AIO SQLite databases only.

This does not serialize exports or change application versions. SQLite's online
backup API preserves identities, encrypted profiles and linked OAuth records.
PostgreSQL, Comet, StremThru, Redis and external cache directories are outside
this closed scope. Private manifests are inside the age-encrypted capsule.
"""
import contextlib
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import tarfile
import tempfile
import time
from urllib.parse import quote

SERVICES = ('aiostreams', 'aiometadata')
PATHS = {service: f'data/{service}/data/db.sqlite' for service in SERVICES}
TARGETS = {'aiostreams': '/app/data', 'aiometadata': '/app/addon/data'}
URIS = {'aiostreams': {'sqlite://./data/db.sqlite', 'sqlite:///app/data/db.sqlite'},
        'aiometadata': {'sqlite://addon/data/db.sqlite', 'sqlite:///app/addon/data/db.sqlite'}}
REQUIRED_TABLES = {'aiostreams': {'users'}, 'aiometadata': {'user_configs'}}
MARKER = '.generated/aio-snapshot-complete.json'
PENDING = '.generated/aio-snapshot-pending.json'
MAX_DATABASE = 2 * 1024 ** 3
MAX_DEPLOYMENT = 8 * 1024 ** 2
DEPLOYMENT = '.generated/npm-deployment.json'
PIN = re.compile(r'[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')
STAMP = re.compile(r'[0-9]{8}T[0-9]{6}Z\Z')
SENSITIVE = re.compile(r'(?:^|_)(?:SECRET|KEY|PASSWORD|TOKEN)(?:_|$)')


class Refused(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


def canonical(data):
    return (json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def checked(path, *, private=False, exists=True):
    path = Path(path).absolute()
    require(not any(item.is_symlink() for item in (path, *path.parents)), 'AIO_SNAPSHOT_SYMLINK_REFUSED')
    if exists:
        info = path.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'AIO_SNAPSHOT_FILE_INVALID')
        if private and os.name != 'nt':
            require(info.st_mode & 0o077 == 0, 'AIO_SNAPSHOT_REQUIRES_MODE_600')
    return path


def scope(run_id, source_commit):
    require(isinstance(run_id, str) and STAMP.fullmatch(run_id), 'AIO_SNAPSHOT_SCOPE_INVALID')
    try:
        dt.datetime.strptime(run_id, '%Y%m%dT%H%M%SZ')
    except ValueError:
        raise Refused('AIO_SNAPSHOT_SCOPE_INVALID') from None
    require(isinstance(source_commit, str) and re.fullmatch(r'[0-9a-f]{40}', source_commit),
            'AIO_SNAPSHOT_SCOPE_INVALID')


def encryption_bindings(environment):
    require(isinstance(environment, dict) and all(isinstance(k, str) and isinstance(v, str)
            for k, v in environment.items()), 'AIO_SNAPSHOT_ENVIRONMENT_INVALID')
    selected = {key: value for key, value in environment.items() if SENSITIVE.search(key)}
    # Only the fingerprint is persisted, and only inside the encrypted capsule.
    return {'keys': sorted(selected), 'sha256': hashlib.sha256(canonical(selected)).hexdigest()}


def validate_model(root, model):
    root = Path(root).absolute()
    require(isinstance(model, dict) and isinstance(model.get('services'), dict),
            'AIO_SNAPSHOT_COMPOSE_INVALID')
    result = {}
    for service in SERVICES:
        item = model['services'].get(service)
        require(isinstance(item, dict) and isinstance(item.get('image'), str) and PIN.fullmatch(item['image']),
                'AIO_SNAPSHOT_PINNED_IMAGE_REQUIRED')
        env = item.get('environment')
        binding = encryption_bindings(env)
        require(env.get('DATABASE_URI') in URIS[service], 'AIO_SNAPSHOT_SQLITE_LAYOUT_REQUIRED')
        if service == 'aiostreams':
            require(bool(env.get('SECRET_KEY')), 'AIO_SNAPSHOT_SECRET_KEY_REQUIRED')
        volumes = [v for v in item.get('volumes', []) if isinstance(v, dict)
                   and v.get('target') == TARGETS[service]]
        require(len(volumes) == 1 and volumes[0].get('type') == 'bind'
                and Path(volumes[0].get('source', '')).absolute() == (root / PATHS[service]).parent,
                'AIO_SNAPSHOT_BIND_LAYOUT_REQUIRED')
        checked(root / PATHS[service], exists=False)
        result[service] = {'image': item['image'], 'bindings': binding}
    return result


def docker_containers(run):
    raw = run(['docker', 'ps', '-aq'], 'AIO_SNAPSHOT_DOCKER_CHECK_FAILED')
    ids = raw.decode().split()
    if not ids:
        return []
    try:
        data = json.loads(run(['docker', 'inspect', *ids], 'AIO_SNAPSHOT_DOCKER_CHECK_FAILED'))
    except (TypeError, ValueError, UnicodeError):
        raise Refused('AIO_SNAPSHOT_DOCKER_CHECK_FAILED') from None
    require(isinstance(data, list) and len(data) == len(ids), 'AIO_SNAPSHOT_DOCKER_CHECK_FAILED')
    return data


def guard_live(root, model, run):
    """Verify active image/config and actual mounts, without pausing services."""
    root = Path(root).absolute()
    binding = validate_model(root, model)
    containers = docker_containers(run)
    result = {}
    for service in SERVICES:
        matches = [c for c in containers if c.get('Config', {}).get('Labels', {}).get(
            'com.docker.compose.service') == service and c.get('Config', {}).get('Labels', {}).get(
            'com.docker.compose.project.working_dir') == str(root)]
        require(len(matches) == 1, 'AIO_SNAPSHOT_SOURCE_CONTAINER_REQUIRED')
        container = matches[0]
        require(container.get('State', {}).get('Running') is True
                and container.get('State', {}).get('Paused') is False,
                'AIO_SNAPSHOT_SOURCE_NOT_RUNNING')
        mounts = [m for m in container.get('Mounts', []) if m.get('Destination') == TARGETS[service]]
        require(len(mounts) == 1 and mounts[0].get('Type') == 'bind'
                and mounts[0].get('Source') == str((root / PATHS[service]).parent),
                'AIO_SNAPSHOT_SOURCE_MOUNT_CHANGED')
        actual = {}
        for entry in container.get('Config', {}).get('Env', []):
            key, sep, value = entry.partition('=')
            require(sep and key not in actual, 'AIO_SNAPSHOT_SOURCE_ENV_CHANGED')
            actual[key] = value
        wanted = model['services'][service]['environment']
        require(all(actual.get(k) == v for k, v in wanted.items()), 'AIO_SNAPSHOT_SOURCE_ENV_CHANGED')
        try:
            image = json.loads(run(['docker', 'image', 'inspect', '--format',
                '{"Id":{{json .Id}},"RepoDigests":{{json .RepoDigests}}}', container['Image']],
                'AIO_SNAPSHOT_IMAGE_CHECK_FAILED'))
        except (KeyError, TypeError, ValueError, UnicodeError):
            raise Refused('AIO_SNAPSHOT_IMAGE_CHECK_FAILED') from None
        require(image.get('Id') == container.get('Image') and binding[service]['image'] in image.get('RepoDigests', []),
                'AIO_SNAPSHOT_SOURCE_IMAGE_CHANGED')
        result[service] = {'container': container.get('Id'), 'image': container.get('Image'),
                           'started': container.get('State', {}).get('StartedAt'),
                           'bindings': binding[service]}
    return result


def guard_unmounted(root, run):
    root = Path(root).absolute()
    directories = [(root / rel).parent for rel in PATHS.values()]
    for container in docker_containers(run):
        for mount in container.get('Mounts', []):
            if mount.get('Type') != 'bind' or not mount.get('Source'):
                continue
            source = Path(mount['Source']).absolute()
            require(not any(source == d or source in d.parents or d in source.parents for d in directories),
                    'AIO_SNAPSHOT_TARGET_MOUNTED')


def sqlite_read(path):
    path = checked(path)
    for suffix in ('-wal', '-shm', '-journal'):
        sidecar = Path(str(path) + suffix)
        checked(sidecar, exists=sidecar.exists())
    connection = sqlite3.connect('file:' + quote(str(Path(path).absolute()), safe='/:') + '?mode=ro',
                                uri=True, timeout=10)
    connection.execute('PRAGMA query_only=ON')
    deadline = time.monotonic() + 120
    connection.set_progress_handler(lambda: time.monotonic() > deadline, 10000)
    return connection


def database_metadata(path, service):
    try:
        with contextlib.closing(sqlite_read(path)) as db:
            require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)],
                    'AIO_SNAPSHOT_DATABASE_CORRUPT')
            require(not db.execute('PRAGMA foreign_key_check').fetchall(), 'AIO_SNAPSHOT_FOREIGN_KEY_INVALID')
            rows = db.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE sql IS NOT NULL "
                              "ORDER BY type,name,tbl_name").fetchall()
            # SQLite identifiers are ASCII case-insensitive. AIOStreams uses
            # USERS in the current source, while earlier images used users.
            # Keep the actual schema bytes in the fingerprint and normalize
            # only the closed required-table lookup/count keys.
            tables = [row[1] for row in rows if row[0] == 'table']
            matched = {name: [table for table in tables if table.lower() == name]
                       for name in REQUIRED_TABLES[service]}
            require(all(len(names) == 1 for names in matched.values()), 'AIO_SNAPSHOT_SCHEMA_UNSUPPORTED')
            counts = {}
            for table in sorted(REQUIRED_TABLES[service]):
                actual = matched[table][0].replace('"', '""')
                counts[table] = db.execute('SELECT count(*) FROM "' + actual + '"').fetchone()[0]
            require(all(count > 0 for count in counts.values()), 'AIO_SNAPSHOT_CONFIGURATION_MISSING')
            return {'schema_sha256': hashlib.sha256(canonical(rows)).hexdigest(),
                    'user_version': db.execute('PRAGMA user_version').fetchone()[0],
                    'application_id': db.execute('PRAGMA application_id').fetchone()[0],
                    'required_counts': counts}
    except sqlite3.Error:
        raise Refused('AIO_SNAPSHOT_DATABASE_INVALID') from None


def exclusive(path, data, mode=0o600):
    path = checked(path, exists=False)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    identity = os.fstat(fd)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        if path.exists() and not path.is_symlink() and (path.stat().st_dev, path.stat().st_ino) == (identity.st_dev, identity.st_ino):
            path.unlink()
        raise


def deployment_bytes(value, source_commit):
    path = Path(__file__).resolve().with_name('npm_topology.py')
    require(path.is_file() and not path.is_symlink(), 'AIO_SNAPSHOT_DEPLOYMENT_INVALID')
    spec = importlib.util.spec_from_file_location('native_aio_npm_topology', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        module.validate(value, stack_commit=source_commit)
    except module.Refused:
        raise Refused('AIO_SNAPSHOT_DEPLOYMENT_INVALID') from None
    data = canonical(value)
    require(0 < len(data) <= MAX_DEPLOYMENT, 'AIO_SNAPSHOT_DEPLOYMENT_INVALID')
    return data


def deployment_descriptor(data):
    return {'schema': 1, 'format': 'streams-aio-npm-topology', 'size': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


def _capture_capsule(root, output, *, run_id, source_commit, model, run, deployment=None):
    """Read online SQLite snapshots into a private archive outside the checkout.

    Caller holds the coordinator lock. Both read transactions are established
    before either backup. Their capture window is recorded; this makes no claim
    of a distributed transaction between the independent applications.
    """
    scope(run_id, source_commit)
    root, output = Path(root).absolute(), checked(output, exists=False)
    require(not output.is_relative_to(root) and not output.exists(), 'AIO_SNAPSHOT_PRIVATE_OUTPUT_REQUIRED')
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(os.name == 'nt' or output.parent.stat().st_mode & 0o077 == 0,
            'AIO_SNAPSHOT_PRIVATE_OUTPUT_REQUIRED')
    bindings = validate_model(root, model)
    before = guard_live(root, model, run)
    manifest = {'schema': 1, 'format': 'streams-aio-native-sqlite', 'run': run_id,
                'source_commit': source_commit, 'method': 'sqlite-online-backup',
                'scope': list(SERVICES), 'capture_started': dt.datetime.now(dt.timezone.utc).isoformat(),
                'applications': {}}
    topology = deployment_bytes(deployment, source_commit) if deployment is not None else None
    if topology is not None:
        manifest['deployment'] = deployment_descriptor(topology)
    with tempfile.TemporaryDirectory(prefix='aio-capture-', dir=output.parent) as temporary:
        temporary = Path(temporary)
        temporary.chmod(0o700)
        with contextlib.ExitStack() as stack:
            sources = {}
            for service in SERVICES:
                path = checked(root / PATHS[service])
                require(0 < path.stat().st_size <= MAX_DATABASE, 'AIO_SNAPSHOT_DATABASE_SIZE_INVALID')
                sources[service] = stack.enter_context(contextlib.closing(sqlite_read(path)))
                sources[service].execute('BEGIN')
                sources[service].execute('SELECT count(*) FROM sqlite_schema').fetchone()
            for service, source in sources.items():
                target = temporary / (service + '.sqlite')
                exclusive(target, b'')
                deadline = time.monotonic() + 180
                def progress(status, remaining, total):
                    require(time.monotonic() <= deadline, 'AIO_SNAPSHOT_CAPTURE_TIMEOUT')
                with contextlib.closing(sqlite3.connect(target)) as destination:
                    source.backup(destination, pages=1024, progress=progress, sleep=0.05)
                metadata = database_metadata(target, service)
                manifest['applications'][service] = {'file': target.name, 'path': PATHS[service],
                    'size': target.stat().st_size, 'sha256': digest(target),
                    **bindings[service], **metadata}
        require(guard_live(root, model, run) == before, 'AIO_SNAPSHOT_SOURCE_CHANGED')
        manifest['capture_finished'] = dt.datetime.now(dt.timezone.utc).isoformat()
        staged = temporary / 'capsule.tar.gz'
        with tarfile.open(staged, 'w:gz', format=tarfile.USTAR_FORMAT) as archive:
            data = canonical(manifest)
            item = tarfile.TarInfo('manifest.json')
            item.size, item.mode = len(data), 0o600
            archive.addfile(item, io.BytesIO(data))
            if topology is not None:
                item = tarfile.TarInfo('deployment.json')
                item.size, item.mode = len(topology), 0o600
                archive.addfile(item, io.BytesIO(topology))
            for service in SERVICES:
                archive.add(temporary / (service + '.sqlite'), arcname=service + '.sqlite', recursive=False)
        staged.chmod(0o600)
        # Atomic no-replace publication; an existing archive is never overwritten.
        os.link(staged, output)
    return manifest


def capture_capsule(root, output, *, run_id, source_commit, model, run, deployment=None):
    try:
        return _capture_capsule(root, output, run_id=run_id, source_commit=source_commit, model=model, run=run,
                                deployment=deployment)
    except sqlite3.Error:
        raise Refused('AIO_SNAPSHOT_DATABASE_INVALID') from None


def validate_manifest(manifest, *, run_id, source_commit, bindings):
    scope(run_id, source_commit)
    fields = {'schema', 'format', 'run', 'source_commit', 'method', 'scope', 'capture_started',
              'capture_finished', 'applications'}
    require(isinstance(manifest, dict) and set(manifest) in (fields, fields | {'deployment'})
            and type(manifest['schema']) is int and manifest['schema'] == 1
            and manifest['format'] == 'streams-aio-native-sqlite'
            and manifest['method'] == 'sqlite-online-backup' and manifest['scope'] == list(SERVICES),
            'AIO_SNAPSHOT_MANIFEST_INVALID')
    if 'deployment' in manifest:
        item = manifest['deployment']
        require(isinstance(item, dict) and set(item) == {'schema','format','size','sha256'}
                and type(item['schema']) is int and item['schema'] == 1
                and item['format'] == 'streams-aio-npm-topology'
                and type(item['size']) is int and 0 < item['size'] <= MAX_DEPLOYMENT
                and isinstance(item['sha256'], str) and HEX.fullmatch(item['sha256']),
                'AIO_SNAPSHOT_DEPLOYMENT_INVALID')
    require(manifest['run'] == run_id and manifest['source_commit'] == source_commit,
            'AIO_SNAPSHOT_SCOPE_CHANGED')
    try:
        times = [dt.datetime.fromisoformat(manifest[k]) for k in ('capture_started', 'capture_finished')]
        require(all(t.utcoffset() == dt.timedelta(0) for t in times)
                and dt.timedelta(0) <= times[1] - times[0] <= dt.timedelta(minutes=10),
                'AIO_SNAPSHOT_CAPTURE_WINDOW_INVALID')
    except (ValueError, TypeError):
        raise Refused('AIO_SNAPSHOT_CAPTURE_WINDOW_INVALID') from None
    require(isinstance(manifest['applications'], dict) and set(manifest['applications']) == set(SERVICES),
            'AIO_SNAPSHOT_MANIFEST_INVALID')
    for service, item in manifest['applications'].items():
        require(isinstance(item, dict) and set(item) == {'file', 'path', 'size', 'sha256', 'image', 'bindings',
                'schema_sha256', 'user_version', 'application_id', 'required_counts'}
                and item['file'] == service + '.sqlite' and item['path'] == PATHS[service]
                and type(item['size']) is int and 0 < item['size'] <= MAX_DATABASE
                and isinstance(item['sha256'], str) and HEX.fullmatch(item['sha256'])
                and isinstance(item['schema_sha256'], str) and HEX.fullmatch(item['schema_sha256'])
                and type(item['user_version']) is int and type(item['application_id']) is int
                and isinstance(item['required_counts'], dict)
                and set(item['required_counts']) == REQUIRED_TABLES[service]
                and all(type(v) is int and v > 0 for v in item['required_counts'].values()),
                'AIO_SNAPSHOT_MANIFEST_INVALID')
        require(item['image'] == bindings[service]['image'], 'AIO_SNAPSHOT_IMAGE_MISMATCH')
        require(item['bindings'] == bindings[service]['bindings'], 'AIO_SNAPSHOT_ENCRYPTION_KEY_MISMATCH')


def unpack_capsule(archive, staging, *, run_id, source_commit, bindings):
    try:
        with tarfile.open(checked(archive, private=True), 'r:gz') as capsule:
            members = []
            for member in capsule:
                members.append(member)
                require(len(members) <= 4, 'AIO_SNAPSHOT_ARCHIVE_UNSAFE')
            require(sum(m.name == 'manifest.json' for m in members) == 1, 'AIO_SNAPSHOT_ARCHIVE_UNSAFE')
            require(capsule.getmember('manifest.json').isfile()
                    and 0 < capsule.getmember('manifest.json').size <= 65536, 'AIO_SNAPSHOT_ARCHIVE_UNSAFE')
            manifest = json.loads(capsule.extractfile('manifest.json').read(65537))
            validate_manifest(manifest, run_id=run_id, source_commit=source_commit, bindings=bindings)
            expected = {'manifest.json', *(service + '.sqlite' for service in SERVICES)}
            if 'deployment' in manifest:
                expected.add('deployment.json')
            require(len(members) == len(expected) and {m.name for m in members} == expected
                    and all(m.isfile() and not m.issym() and not m.islnk() and not m.pax_headers
                            and 0 < m.size <= (65536 if m.name == 'manifest.json' else
                                MAX_DEPLOYMENT if m.name == 'deployment.json' else MAX_DATABASE)
                            for m in members), 'AIO_SNAPSHOT_ARCHIVE_UNSAFE')
            if 'deployment' in manifest:
                item = manifest['deployment']
                require(capsule.getmember('deployment.json').size == item['size'], 'AIO_SNAPSHOT_DIGEST_MISMATCH')
                data = capsule.extractfile('deployment.json').read(MAX_DEPLOYMENT + 1)
                require(deployment_descriptor(data) == item, 'AIO_SNAPSHOT_DIGEST_MISMATCH')
                require(deployment_bytes(json.loads(data), source_commit) == data, 'AIO_SNAPSHOT_DEPLOYMENT_INVALID')
                exclusive(staging / 'deployment.json', data)
            for service in SERVICES:
                item, target = manifest['applications'][service], staging / (service + '.sqlite')
                require(capsule.getmember(item['file']).size == item['size'], 'AIO_SNAPSHOT_DIGEST_MISMATCH')
                with capsule.extractfile(item['file']) as source:
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, 'wb') as destination:
                        shutil.copyfileobj(source, destination, 1024 * 1024)
                require(digest(target) == item['sha256'], 'AIO_SNAPSHOT_DIGEST_MISMATCH')
                require(database_metadata(target, service) == {key: item[key] for key in
                    ('schema_sha256', 'user_version', 'application_id', 'required_counts')},
                    'AIO_SNAPSHOT_DATABASE_MISMATCH')
            return manifest
    except Refused:
        raise
    except (OSError, tarfile.TarError, ValueError, TypeError, UnicodeError, KeyError):
        raise Refused('AIO_SNAPSHOT_ARCHIVE_INVALID') from None


def capsule_evidence(root, manifest, archive_sha256):
    result = {'schema': 1, 'format': manifest['format'], 'root': str(Path(root).absolute()),
            'run': manifest['run'], 'source_commit': manifest['source_commit'],
            'archive_sha256': archive_sha256, 'applications': manifest['applications'],
            'stable_ids': 'PRESERVED', 'linked_credentials': 'NATIVE_DATABASE_PRESERVED'}
    if 'deployment' in manifest:
        result['deployment'] = manifest['deployment']
    return result


def capsule_outputs(root, staging, manifest, uid, gid):
    outputs = [(root / relative, staging / (service + '.sqlite'),
                manifest['applications'][service]['sha256'], (uid, gid))
               for service, relative in PATHS.items()]
    if 'deployment' in manifest:
        owner = (os.geteuid(), os.getegid()) if os.name != 'nt' else (0, 0)
        outputs.append((root / DEPLOYMENT, staging / 'deployment.json', manifest['deployment']['sha256'], owner))
    return outputs


def validate_pending_capsule(archive, root, *, run_id, source_commit, model, run, uid=1000, gid=1000):
    """Read-only proof of a resumable, unstarted native import.

    Temporary validation is outside the target. This never retires journals,
    staging files, markers or installed database links. The recovery caller
    continues to own its lock and must call restore_capsule to resume.
    """
    root = Path(root).absolute()
    bindings = validate_model(root, model)
    archive = checked(archive, private=True)
    require(not archive.is_relative_to(root), 'AIO_SNAPSHOT_PRIVATE_OUTPUT_REQUIRED')
    marker = checked(root / MARKER, exists=False)
    require(not checked(root / '.generated/aio-import-complete.json', exists=False).exists(),
            'AIO_SNAPSHOT_JOURNAL_INVALID')
    pending = checked(root / PENDING, private=True)
    require(os.name == 'nt' or pending.stat().st_uid == os.geteuid(), 'AIO_SNAPSHOT_JOURNAL_INVALID')
    require(pending.stat().st_size <= 65536, 'AIO_SNAPSHOT_JOURNAL_INVALID')
    try:
        journal = json.loads(pending.read_bytes())
    except (OSError, ValueError, UnicodeError):
        raise Refused('AIO_SNAPSHOT_JOURNAL_INVALID') from None
    guard_unmounted(root, run)
    before = digest(archive)
    with tempfile.TemporaryDirectory(prefix='aio-check-', dir=archive.parent) as temporary:
        staging = Path(temporary)
        staging.chmod(0o700)
        manifest = unpack_capsule(archive, staging, run_id=run_id, source_commit=source_commit, bindings=bindings)
        evidence = capsule_evidence(root, manifest, before)
        require(digest(archive) == before, 'AIO_SNAPSHOT_SOURCE_CHANGED')
        require(isinstance(journal, dict) and set(journal) == {'schema', 'evidence', 'staging'}
                and type(journal['schema']) is int and journal['schema'] == 1
                and journal['evidence'] == evidence and isinstance(journal['staging'], str),
                'AIO_SNAPSHOT_JOURNAL_INVALID')
        if marker.exists():
            try:
                checked(marker, private=True)
                require((os.name == 'nt' or marker.stat().st_uid == os.geteuid())
                        and marker.stat().st_size <= 65536 and json.loads(marker.read_bytes()) == evidence,
                        'AIO_SNAPSHOT_JOURNAL_INVALID')
            except (OSError, ValueError, UnicodeError):
                raise Refused('AIO_SNAPSHOT_JOURNAL_INVALID') from None
        previous = checked(journal['staging'], exists=False)
        require(previous.parent == pending.parent and re.fullmatch(r'aio-restore-[A-Za-z0-9_-]+', previous.name),
                'AIO_SNAPSHOT_JOURNAL_INVALID')
        if previous.exists():
            info = previous.stat()
            require(stat.S_ISDIR(info.st_mode) and (os.name == 'nt'
                    or info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0)
                    and {p.name for p in previous.iterdir()} <= {s + '.sqlite' for s in SERVICES}
                        | ({'deployment.json'} if 'deployment' in manifest else set()),
                    'AIO_SNAPSHOT_JOURNAL_INVALID')
        require('deployment' in manifest or not checked(root / DEPLOYMENT, exists=False).exists(),
                'AIO_SNAPSHOT_JOURNAL_INVALID')
        for target, old, expected, owner in capsule_outputs(root, previous, manifest, uid, gid):
            target = checked(target, exists=False)
            require(not marker.exists() or target.exists(), 'AIO_SNAPSHOT_JOURNAL_INVALID')
            for suffix in ('-wal', '-shm', '-journal'):
                sidecar = Path(str(target) + suffix)
                require(not sidecar.exists() and not sidecar.is_symlink(), 'AIO_SNAPSHOT_EXISTING_DATABASE_REFUSED')
            for candidate in (old, target):
                checked(candidate, exists=False)
                if not candidate.exists():
                    continue
                info = candidate.stat()
                require(stat.S_ISREG(info.st_mode) and info.st_nlink in (1, 2)
                        and (os.name == 'nt' or info.st_mode & 0o077 == 0
                             and ((info.st_uid, info.st_gid) == owner
                                  or candidate == old and info.st_uid == os.geteuid()))
                        and digest(candidate) == expected, 'AIO_SNAPSHOT_JOURNAL_INVALID')
                if info.st_nlink == 2:
                    other = target if candidate == old else old
                    require(other.exists() and not other.is_symlink()
                            and (other.stat().st_dev, other.stat().st_ino) == (info.st_dev, info.st_ino),
                            'AIO_SNAPSHOT_JOURNAL_INVALID')
        guard_unmounted(root, run)
        require(pending.read_bytes() == canonical(journal), 'AIO_SNAPSHOT_JOURNAL_INVALID')
        return evidence


def restore_capsule(archive, root, *, run_id, source_commit, model, run, uid=1000, gid=1000):
    """Fresh-only transaction; caller holds the existing recovery lock."""
    root = Path(root).absolute()
    bindings = validate_model(root, model)
    archive = checked(archive, private=True)
    require(not archive.is_relative_to(root), 'AIO_SNAPSHOT_PRIVATE_OUTPUT_REQUIRED')
    marker = checked(root / MARKER, exists=False)
    pending = checked(root / PENDING, exists=False)
    legacy = checked(root / '.generated/aio-import-complete.json', exists=False)
    targets = {service: checked(root / rel, exists=False) for service, rel in PATHS.items()}
    deployment_target = checked(root / DEPLOYMENT, exists=False)
    def fresh():
        require(not legacy.exists() and not any(path.exists() or path.is_symlink()
            for target in targets.values() for path in (Path(str(target) + '-wal'),
                Path(str(target) + '-shm'), Path(str(target) + '-journal'))),
            'AIO_SNAPSHOT_EXISTING_DATABASE_REFUSED')
        if not (pending.exists() or marker.exists()):
            require(not any(path.exists() or path.is_symlink() for path in (*targets.values(), deployment_target)),
                    'AIO_SNAPSHOT_EXISTING_DATABASE_REFUSED')
    def private_json(path):
        try:
            path = checked(path, private=True)
            require(os.name == 'nt' or path.stat().st_uid == os.geteuid(), 'AIO_SNAPSHOT_JOURNAL_INVALID')
            require(path.stat().st_size <= 65536, 'AIO_SNAPSHOT_JOURNAL_INVALID')
            return json.loads(path.read_bytes())
        except (OSError, ValueError, UnicodeError):
            raise Refused('AIO_SNAPSHOT_JOURNAL_INVALID') from None
    fresh()
    guard_unmounted(root, run)
    marker.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    before_archive = digest(archive)
    installed = {}
    with tempfile.TemporaryDirectory(prefix='aio-restore-', dir=marker.parent) as temporary:
        staging = Path(temporary)
        staging.chmod(0o700)
        manifest = unpack_capsule(archive, staging, run_id=run_id, source_commit=source_commit, bindings=bindings)
        require(digest(archive) == before_archive, 'AIO_SNAPSHOT_SOURCE_CHANGED')
        guard_unmounted(root, run)
        fresh()
        evidence = capsule_evidence(root, manifest, before_archive)
        outputs = capsule_outputs(root, staging, manifest, uid, gid)
        require('deployment' in manifest or not deployment_target.exists(), 'AIO_SNAPSHOT_EXISTING_DATABASE_REFUSED')
        if pending.exists():
            journal = private_json(pending)
            require(isinstance(journal, dict) and set(journal) == {'schema', 'evidence', 'staging'}
                    and type(journal['schema']) is int and journal['schema'] == 1
                    and journal['evidence'] == evidence and isinstance(journal['staging'], str),
                    'AIO_SNAPSHOT_JOURNAL_INVALID')
            previous = checked(journal['staging'], exists=False)
            require(previous.parent == marker.parent and previous.name.startswith('aio-restore-')
                    and previous != staging, 'AIO_SNAPSHOT_JOURNAL_INVALID')
            # A power loss may leave the staging half of an installed hard link.
            # Retire only these exact recorded private database copies. Unknown
            # files or links remain preserved and refuse automatic recovery.
            if previous.exists():
                require(previous.is_dir() and not previous.is_symlink()
                        and (os.name == 'nt' or previous.stat().st_uid == os.geteuid()
                             and previous.stat().st_mode & 0o077 == 0)
                        and {p.name for p in previous.iterdir()} <= {s + '.sqlite' for s in SERVICES}
                            | ({'deployment.json'} if 'deployment' in manifest else set()),
                        'AIO_SNAPSHOT_JOURNAL_INVALID')
                for _, old, expected, _ in capsule_outputs(root, previous, manifest, uid, gid):
                    if old.exists():
                        checked(old, exists=False)
                        info = old.stat()
                        require(stat.S_ISREG(info.st_mode) and (os.name == 'nt' or info.st_mode & 0o077 == 0)
                                and digest(old) == expected,
                                'AIO_SNAPSHOT_JOURNAL_INVALID')
                        old.unlink()
                previous.rmdir()
        for target, _, expected, owner in outputs:
            if target.exists():
                checked(target, private=True)
                require((os.name == 'nt' or (target.stat().st_uid, target.stat().st_gid) == owner)
                        and digest(target) == expected,
                        'AIO_SNAPSHOT_EXISTING_DATABASE_REFUSED')
        if marker.exists():
            require(private_json(marker) == evidence and all(target.exists() for target,_,_,_ in outputs),
                    'AIO_SNAPSHOT_MARKER_INVALID')
            if pending.exists():
                pending.unlink()
            return evidence
        journal = {'schema': 1, 'evidence': evidence, 'staging': str(staging)}
        if pending.exists():
            temporary_journal = staging / 'pending.json'
            exclusive(temporary_journal, canonical(journal))
            os.replace(temporary_journal, pending)
        else:
            exclusive(pending, canonical(journal))
        try:
            for target, staged, expected, owner in outputs:
                if target.exists():
                    continue
                target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
                if os.name != 'nt':
                    os.chown(staged, *owner)
                os.link(staged, target)
                installed[target] = (target.stat().st_dev, target.stat().st_ino, expected)
                # Retain our staging hard link until commit/rollback. Otherwise
                # a concurrent unlink can free and reuse this inode for an
                # unrelated replacement before rollback compares identities.
            exclusive(marker, canonical(evidence))
        except Exception:
            # Remove only the links this transaction created, never foreign data.
            for target, identity in installed.items():
                if (target.exists() and not target.is_symlink()
                        and (target.stat().st_dev, target.stat().st_ino) == identity[:2]
                        and digest(target) == identity[2]):
                    target.unlink()
            raise Refused('AIO_SNAPSHOT_INSTALL_FAILED') from None
        # Marker commits the transaction. A leftover journal after a power loss
        # is safe and is validated/retired on the next idempotent call.
        try:
            pending.unlink()
        except OSError:
            pass
    return evidence


def verify_restored(root, evidence, model, *, before_start=False, uid=1000, gid=1000):
    """Validate native import evidence; DB hashes can change after application use.

    Use before_start=True during prepare/resume before any AIO container starts.
    A completed/started deployment instead proves file ownership, schema and
    required user tables without comparing mutable database bytes.
    """
    root = Path(root).absolute()
    bindings = validate_model(root, model)
    try:
        marker = json.loads(checked(root / MARKER, private=True).read_bytes())
    except (OSError, ValueError, UnicodeError):
        raise Refused('AIO_SNAPSHOT_MARKER_INVALID') from None
    fields = {
        'schema', 'format', 'root', 'run', 'source_commit', 'archive_sha256', 'applications',
        'stable_ids', 'linked_credentials'}
    require(isinstance(evidence, dict) and marker == evidence and set(evidence) in (fields, fields | {'deployment'})
        and evidence['schema'] == 1 and evidence['root'] == str(root)
        and evidence['format'] == 'streams-aio-native-sqlite' and evidence['stable_ids'] == 'PRESERVED'
        and evidence['linked_credentials'] == 'NATIVE_DATABASE_PRESERVED'
        and isinstance(evidence['archive_sha256'], str) and HEX.fullmatch(evidence['archive_sha256']),
        'AIO_SNAPSHOT_MARKER_INVALID')
    manifest = {'schema': 1, 'format': evidence['format'], 'run': evidence['run'],
                'source_commit': evidence['source_commit'], 'method': 'sqlite-online-backup',
                'scope': list(SERVICES), 'capture_started': '2026-01-01T00:00:00+00:00',
                'capture_finished': '2026-01-01T00:00:00+00:00', 'applications': evidence['applications']}
    if 'deployment' in evidence:
        manifest['deployment'] = evidence['deployment']
    validate_manifest(manifest, run_id=evidence['run'], source_commit=evidence['source_commit'], bindings=bindings)
    if 'deployment' in evidence:
        path = checked(root / DEPLOYMENT, private=True)
        require(os.name == 'nt' or path.stat().st_uid == os.geteuid(), 'AIO_SNAPSHOT_DEPLOYMENT_INVALID')
        data = path.read_bytes()
        require(deployment_descriptor(data) == evidence['deployment']
                and deployment_bytes(json.loads(data), evidence['source_commit']) == data,
                'AIO_SNAPSHOT_DEPLOYMENT_INVALID')
    for service, rel in PATHS.items():
        path = checked(root / rel, private=True)
        require(os.name == 'nt' or (path.stat().st_uid, path.stat().st_gid) == (uid, gid),
                'AIO_SNAPSHOT_DATABASE_OWNER_CHANGED')
        metadata = database_metadata(path, service)
        expected = evidence['applications'][service]
        require(metadata['required_counts'].keys() == expected['required_counts'].keys()
                and all(metadata['required_counts'][k] >= expected['required_counts'][k]
                        for k in metadata['required_counts']), 'AIO_SNAPSHOT_CONFIGURATION_MISSING')
        if before_start:
            require(digest(path) == expected['sha256'], 'AIO_SNAPSHOT_RESTORED_DATABASE_CHANGED')
    return True

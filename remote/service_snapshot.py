#!/usr/bin/env python3
"""Stopped, declared container data snapshots. Runtime mounts never enter archives."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile

INVENTORY = 'config/service-resources.json'
FORMAT = 'streams-aio-services-state'
MAX_MANIFEST = 2 * 1024 * 1024

class Refused(ValueError):
    pass

def require(ok, code):
    if not ok:
        raise Refused(code)

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()

def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def checked(path, missing=False):
    path = Path(path).absolute()
    require(not any(item.is_symlink() for item in (path, *path.parents)), 'SERVICES_STATE_SYMLINK_REFUSED')
    require(missing or path.exists(), 'SERVICES_STATE_SOURCE_MISSING')
    return path

def inventory(root):
    path = checked(Path(root) / INVENTORY)
    require(path.is_file() and path.stat().st_size <= MAX_MANIFEST, 'SERVICES_STATE_INVENTORY_INVALID')
    try:
        value = json.loads(path.read_bytes())
    except (ValueError, UnicodeError):
        raise Refused('SERVICES_STATE_INVENTORY_INVALID') from None
    validate_inventory(value)
    return value

def validate_inventory(value):
    require(isinstance(value, dict) and value.get('schema') == 1
            and set(value) <= {'schema', 'resources', 'configuration_files'}
            and isinstance(value.get('resources'), list) and len(value['resources']) <= 500,
            'SERVICES_STATE_INVENTORY_INVALID')
    ids, targets = set(), set()
    for item in value['resources']:
        require(isinstance(item, dict) and isinstance(item.get('id'), str)
                and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', item['id'])
                and re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}', item.get('service', ''))
                and item.get('type') in ('bind', 'volume', 'tmpfs', 'config')
                and item.get('role') in ('runtime', 'config', 'data', 'external')
                and isinstance(item.get('source', ''), str)
                and isinstance(item.get('target'), str) and item['target'].startswith('/')
                and '..' not in PurePosixPath(item['target']).parts
                and type(item.get('read_only')) is bool
                and isinstance(item.get('recovery'), dict)
                and item['recovery'].get('method') in ('recreate', 'stopped_archive', 'external'),
                'SERVICES_STATE_INVENTORY_INVALID')
        require(item['id'] not in ids and (item['service'], item['target']) not in targets,
                'SERVICES_STATE_INVENTORY_INVALID')
        ids.add(item['id']); targets.add((item['service'], item['target']))
        if item['recovery']['method'] == 'stopped_archive':
            require(item['role'] == 'data' and not item['read_only'] and item['type'] in ('bind', 'volume'),
                    'SERVICES_STATE_RUNTIME_ARCHIVE_REFUSED')
    return value

def selected(value):
    return [item for item in value['resources'] if item['recovery']['method'] == 'stopped_archive']

def run(args, code):
    try:
        result = subprocess.run([str(x) for x in args], capture_output=True, timeout=1800,
                                env={k:v for k,v in os.environ.items() if not k.startswith(('COMPOSE_', 'PYTHON', 'GH_', 'GITHUB_'))})
    except (OSError, subprocess.TimeoutExpired):
        raise Refused(code) from None
    require(result.returncode == 0, code)
    return result.stdout

def parse(raw, code):
    try:
        return json.loads(raw)
    except (ValueError, TypeError, UnicodeError):
        raise Refused(code) from None

def volume_name(source, model):
    declaration = model.get('volumes', {}).get(source)
    require(isinstance(declaration, dict) and declaration.get('driver', 'local') == 'local'
            and not declaration.get('driver_opts') and not declaration.get('external'),
            'SERVICES_STATE_VOLUME_DRIVER_UNSUPPORTED')
    name = declaration.get('name', source)
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,254}', name),
            'SERVICES_STATE_VOLUME_INVALID')
    return name

def paths(root, value, model, runner=run, create=False):
    root = checked(root)
    result = {}
    for item in selected(value):
        service = model.get('services', {}).get(item['service'], {})
        mounts = [mount for mount in service.get('volumes', []) if isinstance(mount, dict)
                  and mount.get('target') == item['target']]
        require(len(mounts) == 1 and mounts[0].get('type') == item['type']
                and not mounts[0].get('read_only', False), 'SERVICES_STATE_COMPOSE_MISMATCH')
        mount = mounts[0]
        if item['type'] == 'bind':
            source = item['source']
            path = Path(source) if source.startswith('/') else root / source.removeprefix('./')
            require(Path(mount.get('source', '')).absolute() == path.absolute(), 'SERVICES_STATE_COMPOSE_MISMATCH')
            require(path.is_relative_to(root / 'data') and path != root / 'data'
                    and '..' not in path.parts, 'SERVICES_STATE_HOST_PATH_REFUSED')
        else:
            require(mount.get('source') == item['source'], 'SERVICES_STATE_COMPOSE_MISMATCH')
            name = volume_name(item['source'], model)
            if create:
                existing = runner(['docker', 'volume', 'ls', '--format', '{{.Name}}'], 'SERVICES_STATE_VOLUME_INVALID').decode().splitlines()
                if name not in existing:
                    runner(['docker', 'volume', 'create', '--driver', 'local', name], 'SERVICES_STATE_VOLUME_CREATE_FAILED')
            info = parse(runner(['docker', 'volume', 'inspect', name], 'SERVICES_STATE_VOLUME_INVALID'), 'SERVICES_STATE_VOLUME_INVALID')
            require(isinstance(info, list) and len(info) == 1 and info[0].get('Driver') == 'local'
                    and not info[0].get('Options') and isinstance(info[0].get('Mountpoint'), str), 'SERVICES_STATE_VOLUME_INVALID')
            path = Path(info[0]['Mountpoint'])
        result[item['id']] = checked(path, missing=create)
    destinations = list(result.values())
    require(all(a != b and not a.is_relative_to(b) and not b.is_relative_to(a)
                for index, a in enumerate(destinations) for b in destinations[index+1:]),
            'SERVICES_STATE_OVERLAPPING_DATA_REFUSED')
    return result

def containers(runner):
    ids = runner(['docker', 'ps', '-aq'], 'SERVICES_STATE_DOCKER_FAILED').decode().split()
    if not ids:
        return []
    return parse(runner(['docker', 'inspect', *ids], 'SERVICES_STATE_DOCKER_FAILED'), 'SERVICES_STATE_DOCKER_FAILED')

def writers(root, destinations, rows):
    found = []
    for row in rows:
        overlaps = any(mount.get('RW') is True and isinstance(mount.get('Source'), str)
                       and any(Path(mount['Source']) == target or Path(mount['Source']).is_relative_to(target)
                               or target.is_relative_to(Path(mount['Source'])) for target in destinations)
                       for mount in row.get('Mounts', []))
        if overlaps and row.get('State', {}).get('Running') is True:
            labels = row.get('Config', {}).get('Labels') or {}
            require(labels.get('com.docker.compose.project.working_dir') == str(root),
                    'SERVICES_STATE_EXTERNAL_WRITER_REFUSED')
            found.append(row['Id'])
    return sorted(found)

def safe_member(name, prefix):
    path = PurePosixPath(name)
    require(name == str(path) and path.parts and path.parts[0] == prefix
            and not path.is_absolute() and '..' not in path.parts and '\\' not in name,
            'SERVICES_STATE_UNSAFE_ARCHIVE')
    return path

def capture(root, archive, *, run_id, source_commit, model, images, runner=run):
    require(re.fullmatch(r'[0-9]{8}T[0-9]{6}Z', run_id) and re.fullmatch(r'[0-9a-f]{40}', source_commit),
            'SERVICES_STATE_BINDING_INVALID')
    root = checked(root); archive = checked(archive, missing=True)
    require(not archive.exists() and not archive.is_relative_to(root), 'SERVICES_STATE_PRIVATE_OUTPUT_REQUIRED')
    value = inventory(root); destinations = paths(root, value, model, runner)
    require(destinations, 'SERVICES_STATE_NO_DATA')
    require(not any(archive == target or archive.is_relative_to(target) for target in destinations.values()),
            'SERVICES_STATE_PRIVATE_OUTPUT_REQUIRED')
    inventory_hash = digest(root / INVENTORY)
    services = {item['service'] for item in selected(value)}
    require(set(images) == services and all(re.fullmatch(r'.+@sha256:[0-9a-f]{64}', image) for image in images.values()),
            'SERVICES_STATE_IMAGES_INVALID')
    before_rows = containers(runner)
    for service in services:
        matches = [row for row in before_rows if (row.get('Config', {}).get('Labels') or {}).get('com.docker.compose.service') == service
                   and (row.get('Config', {}).get('Labels') or {}).get('com.docker.compose.project.working_dir') == str(root)]
        require(len(matches) == 1, 'SERVICES_STATE_CONTAINER_REQUIRED')
        metadata = parse(runner(['docker','image','inspect',matches[0]['Image']], 'SERVICES_STATE_IMAGES_INVALID'), 'SERVICES_STATE_IMAGES_INVALID')
        require(len(metadata) == 1 and images[service] in metadata[0].get('RepoDigests', []), 'SERVICES_STATE_IMAGES_CHANGED')
    stopped = writers(root, destinations.values(), before_rows)
    entries = []
    try:
        if stopped:
            runner(['docker','stop','--time','60',*stopped], 'SERVICES_STATE_STOP_FAILED')
        require(not writers(root, destinations.values(), containers(runner)), 'SERVICES_STATE_WRITER_RUNNING')
        with tarfile.open(archive, 'x:gz', dereference=False) as bundle:
            for ident, path in destinations.items():
                prefix = 'data/' + ident
                kind = 'directory' if path.is_dir() else 'file'
                require(path.is_dir() or path.is_file(), 'SERVICES_STATE_DATA_TYPE_UNSUPPORTED')
                # Enumerate without following links. Links outside the saved root are rejected.
                for folder, dirs, files in os.walk(path if path.is_dir() else path.parent, followlinks=False):
                    if not path.is_dir():
                        break
                    for name in dirs + files:
                        child = Path(folder) / name
                        require(not child.is_symlink() and (not child.is_file() or child.stat().st_nlink == 1),
                                'SERVICES_STATE_DATA_LINK_UNSUPPORTED')
                require(not path.is_file() or path.stat().st_nlink == 1, 'SERVICES_STATE_DATA_LINK_UNSUPPORTED')
                def clean(info):
                    require(info.isdir() or info.isfile(), 'SERVICES_STATE_DATA_TYPE_UNSUPPORTED')
                    require(info.name == prefix or info.name.startswith(prefix + '/'), 'SERVICES_STATE_UNSAFE_ARCHIVE')
                    info.mode &= 0o777
                    info.uname = info.gname = ''
                    return info
                bundle.add(path, arcname=prefix, recursive=True, filter=clean)
                entries.append(dict(id=ident,kind=kind))
            require(not writers(root, destinations.values(), containers(runner)), 'SERVICES_STATE_WRITER_RUNNING')
            require(inventory(root) == value and digest(root / INVENTORY) == inventory_hash,
                    'SERVICES_STATE_INVENTORY_CHANGED')
            manifest = dict(schema=1,format=FORMAT,run=run_id,stack_commit=source_commit,
                            inventory_sha256=inventory_hash,images=images,entries=entries)
            raw = canonical(manifest); info = tarfile.TarInfo('manifest.json'); info.size=len(raw);info.mode=0o600
            bundle.addfile(info,io.BytesIO(raw))
    finally:
        if stopped:
            runner(['docker','start',*stopped], 'SERVICES_STATE_RESTART_FAILED')
    return manifest


def checkpoint_write(path, value):
    path = checked(path, missing=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.restore-checkpoint-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(canonical(value)); stream.flush()
            if os.name != 'nt': os.fchmod(stream.fileno(), 0o600)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def empty_destination(target):
    checked(target, missing=True)
    require(not target.exists() or target.is_dir() and not any(target.iterdir()),
            'SERVICES_STATE_EXISTING_DATA_REFUSED')
    if target.exists():
        info = target.stat()
        return [info.st_dev, info.st_ino, info.st_mtime_ns, stat.S_IMODE(info.st_mode)]
    return None


def restore(archive, root, *, run_id, source_commit, model, runner=run, checkpoint=None):
    """Stage every resource before atomic installs; reverse all installs on failure.

    A private checkpoint retains staging/backup locations on an interrupted or
    failed rollback. Unknown checkpoints require review instead of overwriting
    possibly recovered application data.
    """
    archive = checked(archive); root = checked(root)
    archive_hash = digest(archive)
    checkpoint = checked(checkpoint or archive.parent / ('.services-restore-' + archive_hash[:16] + '.json'), missing=True)
    if checkpoint.exists():
        previous = parse(checkpoint.read_bytes(), 'SERVICES_STATE_CHECKPOINT_INVALID')
        require(isinstance(previous, dict) and previous.get('archive_sha256') == archive_hash
                and previous.get('phase') == 'ROLLED_BACK', 'SERVICES_STATE_INTERRUPTED_REVIEW_REQUIRED')
        require(not any(Path(row.get('temporary', '')).exists() for row in previous.get('targets', [])),
                'SERVICES_STATE_INTERRUPTED_REVIEW_REQUIRED')
    value = inventory(root); inventory_hash = digest(root / INVENTORY)
    targets = paths(root, value, model, runner, create=True)
    require(not any(archive == target or archive.is_relative_to(target) or checkpoint == target
                    or checkpoint.is_relative_to(target) for target in targets.values()),
            'SERVICES_STATE_PRIVATE_OUTPUT_REQUIRED')
    require(not writers(root,targets.values(),containers(runner)), 'SERVICES_STATE_WRITER_RUNNING')
    records, installed = [], []
    journal = dict(schema=1, phase='VALIDATING', archive_sha256=archive_hash,
                   inventory_sha256=inventory_hash, run=run_id, stack_commit=source_commit, targets=records)
    committed = False
    try:
        with tarfile.open(archive,'r:gz') as bundle:
            members = bundle.getmembers()
            require(len(members) <= 1000000 and len({item.name for item in members}) == len(members), 'SERVICES_STATE_UNSAFE_ARCHIVE')
            manifests=[item for item in members if item.name=='manifest.json']
            require(len(manifests)==1 and manifests[0].isfile() and manifests[0].size<=MAX_MANIFEST, 'SERVICES_STATE_MANIFEST_INVALID')
            manifest=parse(bundle.extractfile(manifests[0]).read(),'SERVICES_STATE_MANIFEST_INVALID')
            require(isinstance(manifest,dict) and set(manifest)=={'schema','format','run','stack_commit','inventory_sha256','images','entries'}
                    and manifest['schema']==1 and manifest['format']==FORMAT and manifest['run']==run_id
                    and manifest['stack_commit']==source_commit
                    and manifest['inventory_sha256']==inventory_hash, 'SERVICES_STATE_BINDING_MISMATCH')
            require(isinstance(manifest['entries'],list) and all(isinstance(item,dict) and set(item)=={'id','kind'}
                    and item['kind'] in ('directory','file') for item in manifest['entries'])
                    and len(manifest['entries'])==len(targets) and {item['id'] for item in manifest['entries']}==set(targets),
                    'SERVICES_STATE_MANIFEST_INVALID')
            expected={item['service']:model.get('services',{}).get(item['service'],{}).get('image') for item in selected(value)}
            require(manifest['images']==expected,'SERVICES_STATE_IMAGES_CHANGED')
            for target in targets.values(): empty_destination(target)
            groups = {identifier: [] for identifier in targets}
            # Validate every member, its ancestor types and its declared root.
            for item in members:
                if item.name=='manifest.json': continue
                name=safe_member(item.name,'data')
                require(len(name.parts)>=2 and name.parts[1] in targets and (item.isdir() or item.isfile())
                        and item.size>=0 and item.mode & ~0o777 == 0 and item.uid >= 0 and item.gid >= 0,
                        'SERVICES_STATE_UNSAFE_ARCHIVE')
                groups[name.parts[1]].append(item)
            for entry in manifest['entries']:
                identifier = entry['id']; prefix='data/'+identifier; rows=groups[identifier]
                roots = [item for item in rows if item.name == prefix]
                require(len(roots)==1 and roots[0].isdir() == (entry['kind']=='directory'),
                        'SERVICES_STATE_MANIFEST_INVALID')
                require(entry['kind']=='directory' or len(rows)==1, 'SERVICES_STATE_UNSAFE_ARCHIVE')
                file_names={item.name for item in rows if item.isfile()}
                require(not any(str(parent) in file_names for item in rows
                    for parent in PurePosixPath(item.name).parents), 'SERVICES_STATE_UNSAFE_ARCHIVE')
            # Nothing has been installed yet. Every target is extracted in a
            # separate sibling staging directory on its own filesystem.
            for entry in manifest['entries']:
                target=targets[entry['id']]
                checked(target.parent, missing=True).mkdir(mode=0o700,parents=True,exist_ok=True)
                temporary=Path(tempfile.mkdtemp(prefix='.service-restore-',dir=target.parent))
                if os.name != 'nt': temporary.chmod(0o700)
                record=dict(id=entry['id'],path=str(target),temporary=str(temporary),stage=str(temporary/'content'),
                            backup=str(temporary/'original'),before=empty_destination(target),state='STAGING')
                records.append(record)
                stage=Path(record['stage']); prefix='data/'+entry['id']; rows=groups[entry['id']]
                for item in sorted(rows,key=lambda row:(len(PurePosixPath(row.name).parts),row.name)):
                    relative=PurePosixPath(item.name).relative_to(prefix)
                    destination=stage.joinpath(*relative.parts)
                    if item.isdir(): destination.mkdir(mode=0o700,parents=True,exist_ok=True)
                    else:
                        destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                        with destination.open('xb') as stream:
                            shutil.copyfileobj(bundle.extractfile(item),stream,1024*1024)
                            stream.flush(); os.fsync(stream.fileno())
                    if os.name != 'nt': os.chown(destination,item.uid,item.gid)
                for item in sorted(rows,key=lambda row:len(PurePosixPath(row.name).parts),reverse=True):
                    destination=stage.joinpath(*PurePosixPath(item.name).relative_to(prefix).parts)
                    destination.chmod(item.mode); os.utime(destination,(item.mtime,item.mtime))
                record['state']='STAGED'
            journal['phase']='STAGED'; checkpoint_write(checkpoint,journal)
            require(digest(root / INVENTORY)==inventory_hash and not writers(root,targets.values(),containers(runner)),
                    'SERVICES_STATE_SOURCE_CHANGED')
            for record in records:
                target=Path(record['path']); before=empty_destination(target)
                require(before==record['before'],'SERVICES_STATE_TARGET_CHANGED')
            journal['phase']='INSTALLING'; checkpoint_write(checkpoint,journal)
            for record in records:
                target=Path(record['path'])
                if record['before'] is not None:
                    os.replace(target,record['backup']); record['state']='BACKED_UP'
                    checkpoint_write(checkpoint,journal)
                os.replace(record['stage'],target); record['state']='INSTALLED'; installed.append(record)
                checkpoint_write(checkpoint,journal)
            require(not writers(root,targets.values(),containers(runner)), 'SERVICES_STATE_WRITER_RUNNING')
            journal['phase']='COMPLETE'; checkpoint_write(checkpoint,journal); committed=True
    except BaseException:
        # A concurrently started container may already have written recovered
        # data. Retain all targets/staging for review instead of deleting writes.
        try:
            rollback_safe = not writers(root,targets.values(),containers(runner))
        except BaseException:
            rollback_safe = False
        if records and not rollback_safe:
            journal['phase']='REVIEW_REQUIRED'
            checkpoint_write(checkpoint,journal)
            raise Refused('SERVICES_STATE_RESTORE_REVIEW_REQUIRED') from None
        rollback_ok=True
        for record in reversed(records):
            try:
                if record['state']=='INSTALLED':
                    os.replace(record['path'],record['stage']); record['state']='BACKED_UP' if record['before'] is not None else 'STAGED'
                if record['state']=='BACKED_UP':
                    require(not Path(record['path']).exists(),'SERVICES_STATE_TARGET_CHANGED')
                    os.replace(record['backup'],record['path']); record['state']='STAGED'
            except BaseException:
                rollback_ok=False
        journal['phase']='ROLLED_BACK' if rollback_ok else 'REVIEW_REQUIRED'
        if records:
            try: checkpoint_write(checkpoint,journal)
            except BaseException: rollback_ok=False
        if rollback_ok:
            for record in records:
                shutil.rmtree(record['temporary'])
        else:
            raise Refused('SERVICES_STATE_RESTORE_REVIEW_REQUIRED') from None
        raise
    if committed:
        for record in records:
            backup=Path(record['backup'])
            if backup.exists(): backup.rmdir()  # The original destination was empty.
            Path(record['temporary']).rmdir()
    return dict(schema=1,run=run_id,stack_commit=source_commit,inventory_sha256=manifest['inventory_sha256'],
                archive_sha256=archive_hash,resources=sorted(targets),checkpoint=str(checkpoint))


def verify_restored(root, archive, evidence, model, *, before_start=True, runner=run):
    """Recheck saved data before first start and immutable bindings afterwards."""
    root=checked(root);archive=checked(archive)
    value=inventory(root);targets=paths(root,value,model,runner)
    require(isinstance(evidence,dict) and set(evidence)=={'schema','run','stack_commit','inventory_sha256','archive_sha256','resources'}
            and evidence['schema']==1 and isinstance(evidence['run'],str)
            and re.fullmatch(r'[0-9]{8}T[0-9]{6}Z',evidence['run'])
            and isinstance(evidence['stack_commit'],str) and re.fullmatch(r'[0-9a-f]{40}',evidence['stack_commit'])
            and evidence['inventory_sha256']==digest(root/INVENTORY)
            and evidence['archive_sha256']==digest(archive) and evidence['resources']==sorted(targets),
            'SERVICES_STATE_CHECKPOINT_CHANGED')
    if before_start:
        require(not writers(root,targets.values(),containers(runner)),'SERVICES_STATE_WRITER_RUNNING')
    with tarfile.open(archive,'r:gz') as bundle:
        members=bundle.getmembers()
        require(len(members)<=1000000 and len({item.name for item in members})==len(members),
                'SERVICES_STATE_UNSAFE_ARCHIVE')
        manifests=[item for item in members if item.name=='manifest.json']
        require(len(manifests)==1 and manifests[0].isfile() and manifests[0].size<=MAX_MANIFEST,
                'SERVICES_STATE_MANIFEST_INVALID')
        manifest=parse(bundle.extractfile(manifests[0]).read(),'SERVICES_STATE_MANIFEST_INVALID')
        require(isinstance(manifest,dict) and set(manifest)=={'schema','format','run','stack_commit','inventory_sha256','images','entries'}
                and manifest['schema']==1 and manifest['format']==FORMAT
                and all(manifest[key]==evidence[key] for key in ('run','stack_commit','inventory_sha256')),
                'SERVICES_STATE_BINDING_MISMATCH')
        expected={item['service']:model.get('services',{}).get(item['service'],{}).get('image') for item in selected(value)}
        require(manifest['images']==expected,'SERVICES_STATE_IMAGES_CHANGED')
        entries=manifest['entries']
        require(isinstance(entries,list) and len(entries)==len(targets)
                and all(isinstance(entry,dict) and set(entry)=={'id','kind'} and entry['kind'] in ('file','directory') for entry in entries)
                and {entry['id'] for entry in entries}==set(targets),'SERVICES_STATE_MANIFEST_INVALID')
        groups={identifier:[] for identifier in targets}
        for item in members:
            if item.name=='manifest.json':continue
            name=safe_member(item.name,'data')
            require(len(name.parts)>=2 and name.parts[1] in targets and (item.isdir() or item.isfile())
                    and item.size>=0 and item.mode & ~0o777 == 0,'SERVICES_STATE_UNSAFE_ARCHIVE')
            groups[name.parts[1]].append(item)
        for entry in entries:
            target=targets[entry['id']];prefix='data/'+entry['id'];rows=groups[entry['id']]
            roots=[item for item in rows if item.name==prefix]
            require(len(roots)==1 and roots[0].isdir()==(entry['kind']=='directory')
                    and target.is_dir()==(entry['kind']=='directory')
                    and (target.is_file() or target.is_dir()),'SERVICES_STATE_RESTORED_DATA_CHANGED')
            if not before_start:continue
            actual={'.':target}
            if target.is_dir():
                for folder,directories,files in os.walk(target,followlinks=False):
                    for name in directories+files:
                        child=checked(Path(folder)/name)
                        require(child.is_file() or child.is_dir(),'SERVICES_STATE_RESTORED_DATA_CHANGED')
                        actual[child.relative_to(target).as_posix()]=child
            expected_paths={str(PurePosixPath(item.name).relative_to(prefix)):item for item in rows}
            require(set(actual)==set(expected_paths),'SERVICES_STATE_RESTORED_DATA_CHANGED')
            for relative,item in expected_paths.items():
                path=actual[relative];metadata=path.stat()
                require(path.is_file()==item.isfile(),'SERVICES_STATE_RESTORED_DATA_CHANGED')
                if os.name!='nt':
                    require((metadata.st_uid,metadata.st_gid,stat.S_IMODE(metadata.st_mode))==(item.uid,item.gid,item.mode),
                            'SERVICES_STATE_RESTORED_DATA_CHANGED')
                if item.isfile():
                    require(metadata.st_nlink==1,'SERVICES_STATE_RESTORED_DATA_CHANGED')
                    expected_hash=hashlib.sha256()
                    stream=bundle.extractfile(item)
                    for block in iter(lambda:stream.read(1024*1024),b''):expected_hash.update(block)
                    require(metadata.st_size==item.size and digest(path)==expected_hash.hexdigest(),
                            'SERVICES_STATE_RESTORED_DATA_CHANGED')
    if before_start:
        require(not writers(root,targets.values(),containers(runner)),'SERVICES_STATE_WRITER_RUNNING')
    return dict(evidence)

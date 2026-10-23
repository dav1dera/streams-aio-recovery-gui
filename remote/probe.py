"""Read-only host check. Output never includes env values or container settings."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tarfile


FIRST_BOOT_TARGET = Path('/home/test/streams-aio')
FIRST_BOOT_TAG = 'dr-20261006T210601Z'
FIRST_BOOT_COMMIT = '28f6ca7cc6f5fd10418fc0af2926815927ef98c8'
FIRST_BOOT_STAGES = frozenset({'CLONES', 'DOWNLOAD', 'DECRYPT', 'INITIALIZE',
                              'INPUTS', 'RENDER', 'EMPTY_STATE'})
DOCKER_VOLUME_ROOT = Path('/var/lib/docker/volumes')


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


def checkpoint_summary(data):
    """Expose fixed phase flags, never arbitrary checkpoint fields or values."""
    attempted = data.get('application_start_attempted', False)
    completed = data.get('completed')
    result = dict(prepared=data.get('preparation') == 'PASS',
                application_start_attempted=attempted if type(attempted) is bool else None,
                runtime_profile_recorded=isinstance(data.get('runtime_profile'), dict),
                npm_completed=isinstance(completed, list) and 'NPM' in completed,
                aio_completed=isinstance(completed, list) and 'AIO' in completed,
                infisical_completed=isinstance(completed, list) and 'INFISICAL_SERVER' in completed)
    if data.get('operational_deployment') is not None:
        result.update(operational_profile_recorded=(data.get('runtime_profile') or {}).get('id')
                      == 'PG18_DNS_UID_AIO_OAUTH_PGBOUNCER_GROUP_PUBLIC_DOMAINS_V3',
                      application_started=data.get('application_recovery') == 'STARTED_NEEDS_FUNCTIONAL_TEST',
                      public_domains_verified=data.get('public_domain_recovery') == 'VERIFIED',
                      controllers_enabled=data.get('public_controllers_enabled') is True,
                      aio_snapshot_completed=data.get('aio_mode') == 'snapshot'
                          and isinstance(completed, list) and 'AIO' in completed)
    return result


def pending_aio_checkpoint(target, runner, data, lab=False):
    """Admit only a closed native-SQLite journal before the first app start.

    This standalone read-only guard verifies the exact capsule bytes and the
    journal's installed/staged copies. The trusted runner additionally checks
    SQLite schemas and current image/encryption bindings before resuming it.
    """
    code = 'RECOVERY_OPERATION_INCOMPLETE'
    def need(ok):
        if not ok:
            raise ValueError(code)
    def checked(path, *, directory=False, owner=0, links=(1,)):
        path = Path(path)
        need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)))
        info = path.stat()
        need((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
             and info.st_uid == owner and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600)
             and (directory or info.st_nlink in links))
        return info
    def digest(path):
        with Path(path).open('rb') as stream:
            return hashlib.file_digest(stream, 'sha256').hexdigest()
    def private_json(path):
        info = checked(path)
        need(info.st_size <= 65536)
        return json.loads(Path(path).read_bytes())
    completed = data.get('completed')
    need(data.get('in_progress') == 'AIO' and data.get('input_aio_mode') == 'snapshot'
         and isinstance(completed, list) and len(completed) == len(set(completed))
         and set(completed) == FIRST_BOOT_STAGES | {'NPM'}
         and data.get('application_start_attempted', False) is False
         and data.get('preparation') is None
         and data.get('application_recovery') in (None, 'NOT_VERIFIED')
         and all(data.get(key) is None for key in ('native_agent','public_domain_recovery','operational_recovery'))
         and isinstance(data.get('runtime_profile'), dict)
         and data['runtime_profile'].get('origin') == 'FIRST_BOOT'
         and data['runtime_profile'].get('id') in (
             'PG18_DNS_UID_AIO_OAUTH_PGBOUNCER_GROUP_V1',
             'PG18_DNS_UID_AIO_OAUTH_PGBOUNCER_GROUP_PUBLIC_DOMAINS_V3') + (
             ('PG18_DNS_UID_AIO_OAUTH_PGBOUNCER_GROUP_COMETNET_TRIAL_V2',)
             if lab and isinstance(data.get('lab_deployment'), dict) else ()))
    archive = runner/'private/aio-state.tar.gz'
    checked(archive)
    expected_hash = (data.get('private_hashes') or {}).get('aio-state.tar.gz')
    need(isinstance(expected_hash, str) and re.fullmatch(r'[0-9a-f]{64}', expected_hash))
    need(digest(archive) == expected_hash)
    services = ('aiostreams','aiometadata')
    paths = {name: 'data/' + name + '/data/db.sqlite' for name in services}
    generated = target/'.generated'
    journal_path = generated/'aio-snapshot-pending.json'
    need(not journal_path.is_symlink())
    journal_present = journal_path.exists()
    journal = private_json(journal_path) if journal_present else None
    if journal_present:
        need(isinstance(journal, dict) and set(journal) == {'schema','evidence','staging'}
             and type(journal['schema']) is int and journal['schema'] == 1)
    with tarfile.open(archive, 'r:gz') as capsule:
        members = []
        for member in capsule:
            members.append(member)
            need(len(members) <= 4)
        names = {'manifest.json', *(name + '.sqlite' for name in services)}
        need(len(members) in (3,4) and len({m.name for m in members}) == len(members)
             and {m.name for m in members} in (names,names | {'deployment.json'})
             and all(m.isfile() and not m.pax_headers and 0 < m.size <= (
                 65536 if m.name == 'manifest.json' else 8 * 1024**2
                 if m.name == 'deployment.json' else 2 * 1024**3) for m in members))
        manifest = json.loads(capsule.extractfile('manifest.json').read(65537))
        fields = {'schema','format','run','source_commit','method','scope',
                  'capture_started','capture_finished','applications'}
        need(isinstance(manifest, dict) and set(manifest) in (fields,fields | {'deployment'})
             and type(manifest['schema']) is int and manifest['schema'] == 1
             and manifest['format'] == 'streams-aio-native-sqlite'
             and manifest['method'] == 'sqlite-online-backup' and manifest['scope'] == list(services)
             and manifest['run'] == data['tag'][3:] and manifest['source_commit'] == data['public_commit']
             and isinstance(manifest['applications'], dict) and set(manifest['applications']) == set(services))
        need({m.name for m in members} == names | ({'deployment.json'} if 'deployment' in manifest else set()))
        if 'deployment' in manifest:
            item = manifest['deployment']
            need(isinstance(item,dict) and set(item) == {'schema','format','size','sha256'}
                 and type(item['schema']) is int and item['schema'] == 1
                 and item['format'] == 'streams-aio-npm-topology'
                 and type(item['size']) is int and 0 < item['size'] <= 8 * 1024**2
                 and item['size'] == capsule.getmember('deployment.json').size
                 and isinstance(item['sha256'],str) and re.fullmatch(r'[0-9a-f]{64}',item['sha256']))
            with capsule.extractfile('deployment.json') as stream:
                raw = stream.read(8 * 1024**2 + 1)
            topology = json.loads(raw)
            need(len(raw) == item['size'] and hashlib.sha256(raw).hexdigest() == item['sha256']
                 and isinstance(topology,dict) and set(topology) == {'schema','format','stack_commit',
                     'source','routes','bindings','routes_sha256'}
                 and type(topology['schema']) is int and topology['schema'] == 1
                 and topology['format'] == 'streams-aio-npm-topology'
                 and topology['stack_commit'] == manifest['source_commit']
                 and isinstance(topology['source'],dict) and isinstance(topology['routes'],list)
                 and isinstance(topology['bindings'],list)
                 and (json.dumps(topology,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode() == raw)
        for service, item in manifest['applications'].items():
            need(isinstance(item, dict) and set(item) == {'file','path','size','sha256','image','bindings',
                 'schema_sha256','user_version','application_id','required_counts'}
                 and item['file'] == service + '.sqlite' and item['path'] == paths[service]
                 and type(item['size']) is int and item['size'] == capsule.getmember(item['file']).size
                 and isinstance(item['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}',item['sha256']))
            with capsule.extractfile(item['file']) as stream:
                need(hashlib.file_digest(stream,'sha256').hexdigest() == item['sha256'])
    need(digest(archive) == expected_hash)
    evidence = dict(schema=1,format=manifest['format'],root=str(target),run=manifest['run'],
        source_commit=manifest['source_commit'],archive_sha256=expected_hash,
        applications=manifest['applications'],stable_ids='PRESERVED',
        linked_credentials='NATIVE_DATABASE_PRESERVED')
    if 'deployment' in manifest:
        evidence['deployment'] = manifest['deployment']
    if not journal_present:
        # Failed validation has not created the link journal. Prove absence
        # of every output and staging artifact before permitting a retry.
        outputs = [generated/'aio-snapshot-complete.json', generated/'aio-import-complete.json',
                   generated/'npm-deployment.json']
        for relative in paths.values():
            destination = target/relative
            outputs.extend(Path(str(destination)+suffix) for suffix in ('','-wal','-shm','-journal'))
        for path in outputs:
            need(not any(p.is_symlink() for p in (path,*path.parents)) and not path.exists())
        need(not list(generated.glob('aio-restore-*')))
        return
    need(journal['evidence'] == evidence and isinstance(journal['staging'],str))
    staging = Path(journal['staging'])
    need(staging.parent == generated and staging.name.startswith('aio-restore-')
         and not any(p.is_symlink() for p in (staging,*staging.parents)))
    if staging.exists():
        checked(staging,directory=True)
        need({p.name for p in staging.iterdir()} <= {name + '.sqlite' for name in services}
             | ({'deployment.json'} if 'deployment' in manifest else set()))
    outputs = [(target/rel,staging/(service + '.sqlite'),manifest['applications'][service]['sha256'],1000)
               for service,rel in paths.items()]
    deployment_target = generated/'npm-deployment.json'
    need(not deployment_target.is_symlink())
    if 'deployment' in manifest:
        outputs.append((deployment_target,staging/'deployment.json',manifest['deployment']['sha256'],0))
    else:
        need(not deployment_target.exists())
    for destination,staged,expected,owner in outputs:
        need(not any(p.is_symlink() for p in (destination,*destination.parents)) and not staged.is_symlink())
        for sidecar in ('-wal','-shm','-journal'):
            need(not Path(str(destination) + sidecar).exists() and not Path(str(destination) + sidecar).is_symlink())
        if staged.exists():
            # A killed link transaction may leave the exact paired hard link.
            info = staged.stat()
            checked(staged,owner=info.st_uid,links=(1,2))
            need(info.st_uid in (0,owner) and digest(staged) == expected)
            if info.st_nlink == 2:
                need(destination.exists() and os.path.samefile(staged,destination))
        if destination.exists():
            info = checked(destination,owner=owner,links=(1,2))
            need(info.st_gid == owner and digest(destination) == expected)
            if info.st_nlink == 2:
                need(staged.exists() and os.path.samefile(staged,destination))
    marker = generated/'aio-snapshot-complete.json'
    need(not marker.is_symlink() and not (generated/'aio-import-complete.json').is_symlink())
    if marker.exists():
        need(private_json(marker) == evidence and all(path.exists() for path,_,_,_ in outputs))
    need(not (generated/'aio-import-complete.json').exists())


def operational_checkpoint(target, runner, data):
    """Standalone probe never imports executable code from the remote host."""
    user = pwd.getpwuid(1000)
    record = data.get('operational_deployment')
    keys = {'schema','routing_mode','domain_target_address','uid','gid','user','home','target',
            'machine_id','tag','public_commit','tooling_commit'}
    if not isinstance(record, dict) or set(record) != keys:
        raise ValueError('OPERATIONAL_DEPLOYMENT_REFUSED')
    try:
        address = str(ipaddress.ip_address(record['domain_target_address']))
    except (TypeError, ValueError):
        raise ValueError('OPERATIONAL_DEPLOYMENT_REFUSED') from None
    expected = dict(schema=1,routing_mode=record['routing_mode'],domain_target_address=address,
        uid=1000,gid=1000,user=user.pw_name,home=user.pw_dir,target=str(target),
        machine_id=data.get('machine_id'),tag=data.get('tag'),
        public_commit=data.get('public_commit'),tooling_commit=data.get('tooling_commit'))
    checkpoint = runner/'state.json'
    info = checkpoint.stat()
    disk = json.loads(checkpoint.read_bytes())
    reconciled = dict(disk, in_progress=None) if isinstance(disk,dict) and disk.get('in_progress') == 'AIO' else disk
    if (record != expected or type(record['schema']) is not int or record['schema'] != 1
            or record['routing_mode'] not in ('parallel_test','production_recovery')
            or user.pw_gid != 1000 or target != Path(user.pw_dir)/'streams-aio'
            or runner != Path(user.pw_dir)/'.local/share/streams-aio-recovery'
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or not (disk == data or data.get('in_progress') is None and reconciled == data)
            or data.get('target') != str(target) or data.get('runner_version') != '0.2.0'
            or data.get('schema') != 1 or type(data.get('schema')) is not int
            or data.get('machine_id') != Path('/etc/machine-id').read_text().strip()
            or not isinstance(data.get('tag'),str) or not re.fullmatch(r'dr-[0-9]{8}T[0-9]{6}Z',data['tag'])
            or not isinstance(data.get('public_commit'),str) or not re.fullmatch(r'[0-9a-f]{40}',data['public_commit'])
            or data.get('tooling_commit') != data['public_commit']):
        raise ValueError('OPERATIONAL_DEPLOYMENT_REFUSED')
    if disk.get('in_progress') == 'AIO':
        pending_aio_checkpoint(target,runner,disk)
    elif data.get('in_progress') is not None:
        raise ValueError('RECOVERY_OPERATION_INCOMPLETE')



def validated_lab_point(point):
    if (not isinstance(point, (tuple, list)) or len(point) != 2
            or not isinstance(point[0], str) or not re.fullmatch(r'dr-[0-9]{8}T[0-9]{6}Z', point[0])
            or not isinstance(point[1], str) or not re.fullmatch(r'[0-9a-f]{40}', point[1])):
        raise ValueError('LAB_RUNTIME_SCOPE_REFUSED')
    return tuple(point)


def lab_checkpoint(target, runner, data, role, point):
    """Prove this selected preparation without importing restored host code."""
    code = 'LAB_RUNTIME_SCOPE_REFUSED'
    def need(ok):
        if not ok:
            raise ValueError(code)
    tag, commit = validated_lab_point(point)
    user = pwd.getpwuid(1000)
    need(os.geteuid() == 0 and getattr(user, 'pw_uid', None) == 1000 and user.pw_gid == 1000
         and isinstance(user.pw_name, str) and re.fullmatch(r'[a-z_][a-z0-9_-]*', user.pw_name))
    need(target == (Path(user.pw_dir)/'streams-aio' if role == 'stack' else Path('/opt/infisical'))
         and runner == Path(user.pw_dir)/'.local/share'/(
             'streams-aio-recovery' if role == 'stack' else 'streams-aio-infisical-recovery'))
    checkpoint = runner/'state.json'
    need(not any(path.is_symlink() for path in (checkpoint, *checkpoint.parents)))
    info = checkpoint.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
         and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 1024**2)
    disk = json.loads(checkpoint.read_bytes())
    reconciled = (dict(disk, in_progress=None) if isinstance(disk, dict)
                  and disk.get('in_progress') == 'AIO' and isinstance(disk.get('lab_deployment'), dict)
                  else disk)
    need(isinstance(data, dict) and isinstance(disk, dict)
         and (disk == data or data.get('in_progress') is None and reconciled == data)
         and type(data.get('schema')) is int and data['schema'] == 1
         and data.get('runner_version') == '0.2.0' and data.get('target') == str(target)
         and data.get('machine_id') == Path('/etc/machine-id').read_text().strip()
         and data.get('tag') == tag and data.get('tooling_commit') == commit
         and (data.get('public_commit') == commit if role == 'stack'
              else data.get('public_commit') in (None, commit))
         and data.get('operational_deployment') is None
         and data.get('application_start_attempted', False) is False
         and data.get('application_recovery') in (None, 'NOT_VERIFIED')
         and data.get('timers_installed', False) is False
         and all(data.get(key) is None for key in (
             'public_domain_recovery', 'operational_recovery', 'public_controllers_enabled')))
    completed = data.get('completed')
    need(isinstance(completed, list) and all(isinstance(name, str) for name in completed)
         and len(completed) == len(set(completed)))
    if role == 'infisical':
        need(set(completed) == {'CLONES', 'DOWNLOAD', 'DECRYPT', 'INFISICAL_CONFIG',
                               'INFISICAL_DATABASE', 'INFISICAL_SERVER'}
             and data.get('in_progress') is None and data.get('lab_deployment') is None
             and data.get('runtime_profile') is None
             and data.get('server_restore') == 'PASS_NEEDS_SECRET_READ_TEST')
        return
    need(data.get('preparation') in (None, 'PASS'))
    record = data.get('lab_deployment')
    if record is None:
        # The sole old attempt admitted here stopped exactly before its first
        # compatibility profile. Broader partial recoveries remain refused.
        need(set(completed) == FIRST_BOOT_STAGES and data.get('in_progress') is None
             and data.get('runtime_profile') is None and data.get('preparation') is None
             and data.get('native_agent') is None)
    else:
        expected = dict(schema=1, kind='onboarding_lab', uid=1000, gid=1000,
            user=user.pw_name, home=user.pw_dir, target=str(target),
            machine_id=data['machine_id'], tag=tag, public_commit=commit,
            tooling_commit=commit, publications_disabled=True)
        need(isinstance(record, dict) and record == expected
             and type(record.get('schema')) is int and record['schema'] == 1
             and record.get('publications_disabled') is True
             and FIRST_BOOT_STAGES <= set(completed)
             <= FIRST_BOOT_STAGES | {'RUNTIME_PROFILE', 'NPM', 'AIO', 'AIO_SNAPSHOT', 'PREFLIGHT', 'PREPARED'}
             and data.get('in_progress') in (None, 'AIO'))
        if disk.get('in_progress') == 'AIO':
            pending_aio_checkpoint(target, runner, disk, lab=True)
        if data.get('runtime_profile') is None:
            need(set(completed) == FIRST_BOOT_STAGES and data.get('preparation') is None
                 and data.get('native_agent') is None)
    if data.get('runtime_profile') is None:
        for name in ('.generated/recovery-runtime.compose.yaml', '.generated/cometnet-trial.password',
                     '.generated/tailscale-recovery.env'):
            path = target/name
            need(not path.is_symlink() and not path.exists())


def checked_stack_runtime(target, runner, data, lab_point=None):
    """Resume owned startup, or the scoped prestart checkpoint with empty volumes."""
    attempted = data.get('application_start_attempted', False)
    lab = lab_point is not None
    if lab:
        lab_checkpoint(target, runner, data, 'stack', lab_point)
    operational = not lab and data.get('operational_deployment') is not None
    if operational:
        operational_checkpoint(target, runner, data)
    partial = (operational or lab) and attempted is False and data.get('preparation') is None
    if (data.get('preparation') != 'PASS' and not partial) or type(attempted) is not bool:
        raise ValueError('FRESH_DOCKER_HOST_REQUIRED')
    prestart = attempted is False
    if prestart:
        completed = data.get('completed')
        if lab:
            pass  # The stricter selected-point checkpoint guard ran above.
        elif operational:
            if (not isinstance(completed,list) or not all(isinstance(name,str) for name in completed)
                    or len(completed) != len(set(completed))
                    or not FIRST_BOOT_STAGES <= set(completed)
                    <= FIRST_BOOT_STAGES | {'RUNTIME_PROFILE','NPM','AIO','AIO_SNAPSHOT','PREFLIGHT','PREPARED'}):
                raise ValueError('FRESH_DOCKER_HOST_REQUIRED')
        elif (target != FIRST_BOOT_TARGET
                or type(data.get('schema')) is not int or data['schema'] != 1
                or data.get('runner_version') != '0.2.0'
                or data.get('tag') != FIRST_BOOT_TAG
                or data.get('public_commit') != FIRST_BOOT_COMMIT
                or data.get('tooling_commit') != FIRST_BOOT_COMMIT
                or data.get('target') != str(target)
                or data.get('machine_id') != Path('/etc/machine-id').read_text().strip()
                or data.get('in_progress', False) is not None
                or not isinstance(completed, list)
                or not all(isinstance(name, str) for name in completed)
                or len(completed) != len(set(completed))
                or not FIRST_BOOT_STAGES <= set(completed) <= FIRST_BOOT_STAGES | {'NPM', 'AIO'}):
            raise ValueError('FRESH_DOCKER_HOST_REQUIRED')
    def run(args):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(('COMPOSE_', 'INFISICAL_', 'PYTHON'))
               and k not in ('GH_TOKEN', 'GITHUB_TOKEN')}
        p = subprocess.run(['docker', *args], cwd=target, env=env,
                           capture_output=True, timeout=40)
        if p.returncode:
            raise ValueError('DOCKER_CHECK_REQUIRES_SUDO_OR_RUNNING_DAEMON')
        return p.stdout
    model = json.loads(run(['compose', '--profile', 'all', 'config', '--format', 'json']))
    project, services = model.get('name'), model.get('services', {})
    if not isinstance(project, str) or not project or not services:
        raise ValueError('COMPOSE_PROJECT_REQUIRED')
    if prestart and (project != 'streams-aio' or not isinstance(services, dict)):
        raise ValueError('COMPOSE_PROJECT_REQUIRED')
    ids = run(['ps', '-aq']).decode().split()
    if prestart and ids:
        raise ValueError('FRESH_DOCKER_HOST_REQUIRED')
    for item in json.loads(run(['inspect', *ids])) if ids else []:
        labels = item.get('Config', {}).get('Labels') or {}
        if (labels.get('com.docker.compose.project') != project
                or labels.get('com.docker.compose.project.working_dir') != str(target)
                or labels.get('com.docker.compose.service') not in services):
            raise ValueError('FOREIGN_CONTAINER_REFUSED')
    declared = model.get('volumes', {})
    if any(v.get('external') for v in declared.values()):
        raise ValueError('EXTERNAL_VOLUME_REFUSED')
    names = run(['volume', 'ls', '-q']).decode().split()
    for item in json.loads(run(['volume', 'inspect', *names])) if names else []:
        labels = item.get('Labels') or {}
        key = labels.get('com.docker.compose.volume')
        if (labels.get('com.docker.compose.project') != project or key not in declared
                or item.get('Name') != declared[key].get('name')):
            raise ValueError('FOREIGN_VOLUME_REFUSED')
        if prestart:
            name, location = item.get('Name'), item.get('Mountpoint')
            if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name)
                    or not isinstance(location, str) or item.get('Driver') != 'local'
                    or item.get('Options')):
                raise ValueError('FOREIGN_VOLUME_REFUSED')
            path = Path(location)
            if not path.is_absolute() or path != DOCKER_VOLUME_ROOT / name / '_data':
                raise ValueError('FOREIGN_VOLUME_REFUSED')
            try:
                if any(parent.is_symlink() for parent in (path, *path.parents)):
                    raise ValueError('SYMLINK_PATH_REFUSED')
                if not stat.S_ISDIR(path.lstat().st_mode) or any(path.iterdir()):
                    raise ValueError('FRESH_DOCKER_HOST_REQUIRED')
            except OSError:
                raise ValueError('FRESH_DOCKER_HOST_REQUIRED') from None


def checked_infisical_runtime(target, data):
    """Retain the installed-configuration hashes and Docker ownership checks."""
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


def probe(target, runner, fresh=False, role='stack', lab_point=None):
    if role not in ('stack', 'infisical') or (role == 'infisical' and target != Path('/opt/infisical')):
        raise ValueError('INVALID_RECOVERY_ROLE')
    if lab_point is not None:
        lab_point = validated_lab_point(lab_point)
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
    data = {}
    if existing:
        state = runner / 'state.json'
        if not state.is_file() or state.is_symlink() or state.stat().st_mode & 0o077:
            raise ValueError('EXISTING_STACK_REFUSED')
        if lab_point is not None:
            metadata = state.stat()
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != 0o600 or not 0 < metadata.st_size <= 1024**2):
                raise ValueError('LAB_RUNTIME_SCOPE_REFUSED')
        data = json.loads(state.read_bytes())
        if lab_point is not None:
            lab_checkpoint(target, runner, data, role, lab_point)
        if data.get('machine_id') != Path('/etc/machine-id').read_text().strip() or data.get('target') != str(target):
            raise ValueError('FOREIGN_RECOVERY_STATE')
        if lab_point is None and role == 'stack' and data.get('operational_deployment') is not None:
            operational_checkpoint(target, runner, data)
    elif lab_point is not None and ((runner/'state.json').exists() or (runner/'state.json').is_symlink()):
        raise ValueError('LAB_RUNTIME_SCOPE_REFUSED')
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
    if lab_point is not None and existing:
        if role == 'stack':
            checked_stack_runtime(target, runner, data, lab_point=lab_point)
        else:
            if not shutil.which('docker'):
                raise ValueError('DOCKER_CHECK_REQUIRES_SUDO_OR_RUNNING_DAEMON')
            checked_infisical_runtime(target, data)
        return dict(os='Ubuntu ' + info['VERSION_ID'].strip('"'), architecture='amd64',
                    user=user.pw_name, home=user.pw_dir, existing_recovery=True,
                    containers=containers, volumes=volumes, machine_id=data['machine_id'],
                    recovery=checkpoint_summary(data), lab_preparation_resume=True)
    if role == 'stack' and data.get('in_progress') == 'AIO':
        # Detection itself proves ownership; counts are never enough to adopt
        # resources while a native database transaction is interrupted.
        checked_stack_runtime(target,runner,data)
    if fresh and (containers or volumes):
        if role == 'stack' and existing:
            checked_stack_runtime(target, runner, data)
            return dict(os='Ubuntu ' + info['VERSION_ID'].strip('"'), architecture='amd64',
                        user=user.pw_name, home=user.pw_dir, existing_recovery=True,
                        containers=containers, volumes=volumes, machine_id=data['machine_id'],
                        recovery=checkpoint_summary(data))
        if role != 'infisical' or not existing or 'INFISICAL_CONFIG' not in data.get('completed', []):
            raise ValueError('FRESH_DOCKER_HOST_REQUIRED')
        checked_infisical_runtime(target, data)
    return dict(os='Ubuntu ' + info['VERSION_ID'].strip('"'), architecture='amd64', user=user.pw_name,
                home=user.pw_dir, existing_recovery=existing,
                containers=containers, volumes=volumes,
                machine_id=Path('/etc/machine-id').read_text().strip(),
                recovery=checkpoint_summary(data) if existing else None)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--target')
    p.add_argument('--runner')
    p.add_argument('--docker-suite', action='store_true')
    p.add_argument('--fresh', action='store_true')
    p.add_argument('--role', choices=('stack','infisical'), default='stack')
    p.add_argument('--lab-tag')
    p.add_argument('--lab-commit')
    a = p.parse_args()
    try:
        if a.docker_suite:
            info = dict(x.split('=', 1) for x in Path('/etc/os-release').read_text().splitlines() if '=' in x)
            print(ubuntu_codename(info))
        else:
            if not a.target or not a.runner:
                p.error('--target and --runner are required for a host check')
            point = validated_lab_point((a.lab_tag, a.lab_commit)) if (
                a.lab_tag is not None or a.lab_commit is not None) else None
            print(json.dumps(probe(Path(a.target), Path(a.runner), a.fresh, a.role, lab_point=point)))
    except Exception as error:
        allowed = {'SYMLINK_PATH_REFUSED', 'DEPLOYMENT_UID_GID_REQUIRED', 'UBUNTU_LTS_VERSION_REQUIRED', 'UBUNTU_CODENAME_MISMATCH',
                   'UBUNTU_AMD64_REQUIRED', 'EXISTING_STACK_REFUSED', 'FOREIGN_RECOVERY_STATE',
                   'DOCKER_CHECK_REQUIRES_SUDO_OR_RUNNING_DAEMON', 'EXISTING_DOCKER_DATA', 'FRESH_DOCKER_HOST_REQUIRED',
                   'INFISICAL_CONFIG_CHANGED','FOREIGN_CONTAINER_REFUSED','FOREIGN_VOLUME_REFUSED','INVALID_RECOVERY_ROLE',
                   'COMPOSE_PROJECT_REQUIRED', 'EXTERNAL_VOLUME_REFUSED'}
        allowed |= {'OPERATIONAL_DEPLOYMENT_REFUSED','RECOVERY_OPERATION_INCOMPLETE','LAB_RUNTIME_SCOPE_REFUSED'}
        print(json.dumps({'error': str(error) if str(error) in allowed else 'HOST_CHECK_REFUSED'}))
        sys.exit(1)

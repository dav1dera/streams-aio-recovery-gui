"""A scoped, registered startup correction for this replacement deployment.

This module never starts/stops containers or deletes volume contents.  The
caller holds the recovery lock and stops only the verified failing services
before apply().  Only COMPOSE_FILE changes in the generated root env; the
selected public checkout, generated SQL and application configuration remain.
"""
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import subprocess
import tarfile
import tempfile
import tomllib
from urllib.parse import urlsplit

PROFILE = 'PG18_DNS_UID_AIO_DEPENDENCY_V1'
FIRST_BOOT_PROFILE = 'PG18_DNS_UID_AIO_OAUTH_PGBOUNCER_GROUP_V1'
COMETNET_TRIAL_PROFILE = 'PG18_DNS_UID_AIO_OAUTH_PGBOUNCER_GROUP_COMETNET_TRIAL_V2'
OPERATIONAL_PROFILE = 'PG18_DNS_UID_AIO_OAUTH_PGBOUNCER_GROUP_PUBLIC_DOMAINS_V3'
# Closed public trial delta reviewed against vendor commit f56677f. The
# generated network password is added separately and never placed in source.
COMETNET_TRIAL_ENV = {
    'COMETNET_ADVERTISE_URL': 'ws://127.0.0.1:8765',
    'COMETNET_PRIVATE_NETWORK': 'true',
    'COMETNET_NETWORK_ID': 'streams-aio-dr-local',
    'COMETNET_BOOTSTRAP_NODES': '[]',
    'COMETNET_MANUAL_PEERS': '[]',
    'COMETNET_INGEST_POOLS': '[]',
    'COMETNET_UPNP_ENABLED': 'false',
    'COMETNET_SKIP_REACHABILITY_CHECK': 'false',
    'COMETNET_SKIP_TIME_CHECK': 'false',
    'COMETNET_KEYS_DIR': '/tmp/streams-aio-cometnet-trial/keys',
    'COMETNET_POOLS_DIR': '/tmp/streams-aio-cometnet-trial/pools',
    'COMETNET_RELAY_URL': '',
    'COMETNET_ALLOW_PRIVATE_PEX': 'false',
}
TRIAL_PASSWORD = '.generated/cometnet-trial.password'
COMETNET_IMAGE = 'g0ldyy/comet@sha256:dca62133336e02784d02aaad861381820674d1c8e3e98a03797610b81ee4defe'
COMETNET_MIGRATION_BACKUP = 'runtime-profile/cometnet-trial-v1'
TAG = 'dr-20261006T210601Z'
COMMIT = '28f6ca7cc6f5fd10418fc0af2926815927ef98c8'
TARGET = Path('/home/test/streams-aio')
ARTIFACT = '.generated/recovery-runtime.compose.yaml'
BACKUP = 'runtime-profile/base.env'
BASE_COMPOSE = 'docker-compose.yml:config/compose.dr.yaml'
EFFECTIVE_COMPOSE = BASE_COMPOSE + ':' + ARTIFACT
PG_IMAGE = 'postgres@sha256:650d7a867dc5336eff67802a1417fcc801821d73d824c608e80afbde792fe6e1'
DNS_IMAGE = 'klutchell/dnscrypt-proxy@sha256:a98e8d13314fa8b75620026441b1d6581e2b55189509a794500c5c86064df810'
OAUTH_IMAGE = 'quay.io/oauth2-proxy/oauth2-proxy@sha256:8498b0d0ef0a7b29686414000a08aee467f02d0299c9ed1e006a8f33fc017916'
PGBOUNCER_IMAGE = 'edoburu/pgbouncer@sha256:9c78945868a6a142c7fc40ccd843bbe5a606df163c7ffce4de70e0d628d696a2'
FIRST_BOOT_IMAGES = (PG_IMAGE, DNS_IMAGE, OAUTH_IMAGE, PGBOUNCER_IMAGE)
# Docker's typed InspectResponse field is ID, while its JSON name is Id.  Using
# .Id forces the CLI's raw-JSON fallback, where an omitted empty Config.User
# fails under missingkey=error.  .ID keeps the typed empty string available.
IMAGE_METADATA_FORMAT = (
    '{"Id":{{json .ID}},"Os":{{json .Os}},"Architecture":{{json .Architecture}},'
    '"Env":{{json .Config.Env}},"User":{{json .Config.User}}}')
FIRST_BOOT_STAGES = frozenset({'CLONES', 'DOWNLOAD', 'DECRYPT', 'INITIALIZE',
                               'INPUTS', 'RENDER', 'EMPTY_STATE'})
DOCKER_VOLUME_ROOT = Path('/var/lib/docker/volumes')
ERROR_CODES = frozenset({
    'RUNTIME_PROFILE_SCOPE_REFUSED', 'RUNTIME_PROFILE_CHANGED',
    'RUNTIME_PROFILE_SOURCE_CHANGED', 'RUNTIME_PROFILE_EVIDENCE_REQUIRED',
    'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED', 'RUNTIME_PROFILE_IMAGE_CHANGED',
    'RUNTIME_PROFILE_COMPOSE_VERSION_REQUIRED', 'RUNTIME_PROFILE_POSTGRES_LAYOUT_REFUSED',
    'RUNTIME_PROFILE_DATABASE_PRESENT', 'RUNTIME_PROFILE_POSTGRES_MUST_BE_STOPPED',
    'RUNTIME_PROFILE_DNS_IDENTITY_REFUSED', 'RUNTIME_PROFILE_DNS_PERMISSIONS_REFUSED',
    'RUNTIME_PROFILE_SQL_CHANGED', 'RUNTIME_PROFILE_ENV_REFUSED',
    'RUNTIME_PROFILE_CANDIDATE_REFUSED', 'RUNTIME_PROFILE_TRANSACTION_FAILED',
    'RUNTIME_PROFILE_DEPENDENCY_REFUSED', 'RUNTIME_PROFILE_PATH_REFUSED',
    'RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED', 'RUNTIME_PROFILE_FRESH_HOST_REQUIRED',
    'RUNTIME_PROFILE_PRESTART_CHECKPOINT_REQUIRED',
    'COMETNET_TRIAL_SCOPE_REFUSED', 'COMETNET_TRIAL_TLS_REFUSED', 'COMETNET_TRIAL_TRANSACTION_FAILED',
    'OPERATIONAL_DEPLOYMENT_REFUSED', 'OPERATIONAL_PROFILE_TRANSACTION_FAILED',
})


class Refused(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Refused(code)


def safe(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)),
            'RUNTIME_PROFILE_PATH_REFUSED')
    return path


def regular(path):
    path = safe(path)
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            'RUNTIME_PROFILE_PATH_REFUSED')
    return info


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(path):
    regular(path)
    return sha(Path(path).read_bytes())


def env_metadata(path):
    info = regular(path)
    require(info.st_uid in (0, 1000) and info.st_gid == 1000
            and stat.S_IMODE(info.st_mode) in (0o600, 0o640),
            'RUNTIME_PROFILE_ENV_REFUSED')
    return info


def identity_scope(root, home, state):
    if state.get('operational_deployment') is not None:
        return deployment_scope(root, home, state)
    import pwd
    root, home = safe(root), safe(home)
    require(os.geteuid() == 0 and root == TARGET
            and not home.is_relative_to(root) and not root.is_relative_to(home),
            'RUNTIME_PROFILE_SCOPE_REFUSED')
    user = pwd.getpwuid(1000)
    require(user.pw_name == 'test' and user.pw_gid == 1000
            and user.pw_dir == '/home/test', 'RUNTIME_PROFILE_SCOPE_REFUSED')
    checkpoint = home / 'state.json'
    info = regular(checkpoint)
    require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == 0
            and json.loads(checkpoint.read_bytes()) == state,
            'RUNTIME_PROFILE_SCOPE_REFUSED')
    require(type(state.get('schema')) is int and state['schema'] == 1
            and state.get('runner_version') == '0.2.0'
            and state.get('tag') == TAG and state.get('public_commit') == COMMIT
            and state.get('tooling_commit') == COMMIT
            and state.get('machine_id') == Path('/etc/machine-id').read_text().strip()
            and state.get('target') == str(root) and state.get('in_progress') is None,
            'RUNTIME_PROFILE_SCOPE_REFUSED')
    return root, home


def deployment_record(root, state, routing_mode, domain_target_address):
    """Record explicit replacement intent; never infer a DNS cutover from IPs."""
    import ipaddress
    import pwd
    user = pwd.getpwuid(1000)
    require(routing_mode in ('parallel_test', 'production_recovery'), 'OPERATIONAL_DEPLOYMENT_REFUSED')
    try:
        address = str(ipaddress.ip_address(domain_target_address))
    except (ValueError, TypeError):
        raise Refused('OPERATIONAL_DEPLOYMENT_REFUSED') from None
    require(address == domain_target_address, 'OPERATIONAL_DEPLOYMENT_REFUSED')
    return dict(schema=1, routing_mode=routing_mode, domain_target_address=address,
                uid=1000, gid=1000, user=user.pw_name, home=user.pw_dir, target=str(root),
                machine_id=state.get('machine_id'), tag=state.get('tag'),
                public_commit=state.get('public_commit'), tooling_commit=state.get('tooling_commit'))


def validate_pending_native_aio(root, home, state):
    """Read-only reconciliation evidence for this one interrupted transaction.

    The runner clears a retryable pending phase in memory before revisiting
    the runtime policy. A closed native AIO journal may justify that sole
    difference; generic interrupted phases must still refuse.
    """
    code = 'OPERATIONAL_DEPLOYMENT_REFUSED'
    completed = state.get('completed')
    require(state.get('in_progress') == 'AIO' and state.get('input_aio_mode') == 'snapshot'
            and isinstance(completed,list) and all(isinstance(name,str) for name in completed)
            and len(completed) == len(set(completed))
            and set(completed) == FIRST_BOOT_STAGES | {'NPM'}
            and state.get('application_start_attempted',False) is False
            and state.get('preparation') is None
            and state.get('application_recovery') in (None,'NOT_VERIFIED')
            and all(state.get(key) is None for key in ('native_agent','public_domain_recovery','operational_recovery'))
            and isinstance(state.get('runtime_profile'),dict)
            and state['runtime_profile'].get('origin') == 'FIRST_BOOT'
            and state['runtime_profile'].get('id') in (FIRST_BOOT_PROFILE,OPERATIONAL_PROFILE), code)
    archive = safe(home/'private/aio-state.tar.gz')
    info = regular(archive)
    expected = (state.get('private_hashes') or {}).get('aio-state.tar.gz')
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
            and isinstance(expected,str) and re.fullmatch(r'[0-9a-f]{64}',expected)
            and digest(archive) == expected, code)
    def run(args, ignored=None):
        env = {k:v for k,v in os.environ.items()
               if not k.startswith(('COMPOSE_','INFISICAL_','PYTHON'))
               and k not in ('GH_TOKEN','GITHUB_TOKEN')}
        result = subprocess.run([str(value) for value in args],cwd=root,env=env,
                                capture_output=True,timeout=40)
        require(result.returncode == 0,code)
        return result.stdout
    try:
        model = json.loads(run(['docker','compose','--profile','all','config','--format','json']))
        require(not run(['docker','ps','-aq']).strip(),code)
        resources = cometnet_runtime_snapshot(root,model,run)
        require(not resources['containers'],code)
        for name in resources['volumes'].values():
            location = safe(DOCKER_VOLUME_ROOT/name/'_data')
            require(location.is_dir() and not any(location.iterdir()),code)
        # This sibling is the trusted program uploaded by the desktop, never
        # a module from the restored checkout or an archive-provided path.
        import importlib.util
        spec = importlib.util.spec_from_file_location('runtime_pending_native_aio',
                    Path(__file__).with_name('aio_snapshot.py'))
        snapshot = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(snapshot)
        try:
            snapshot.validate_pending_capsule(archive,root,run_id=state['tag'][3:],
                source_commit=state['public_commit'],model=model,run=run,uid=1000,gid=1000)
        except snapshot.Refused:
            raise Refused(code) from None
        require(digest(archive) == expected,code)
    except (ValueError,TypeError,KeyError,OSError):
        raise Refused(code) from None


def deployment_scope(root, home, state):
    """New deployments bind actual SSH identity and selected verified pins.

    Legacy checkpoints without this explicit record keep the original exact
    .29/tag/commit guard. A root-owned checkpoint is required in either path.
    """
    import pwd
    root, home = safe(root), safe(home)
    user = pwd.getpwuid(1000)
    record = state.get('operational_deployment')
    require(isinstance(record, dict), 'OPERATIONAL_DEPLOYMENT_REFUSED')
    expected = deployment_record(root, state, record.get('routing_mode'), record.get('domain_target_address'))
    require(record == expected and type(record['schema']) is int and record['schema'] == 1
            and user.pw_gid == 1000
            and re.fullmatch(r'[a-z_][a-z0-9_-]*', user.pw_name)
            and root == Path(user.pw_dir)/'streams-aio'
            and home == Path(user.pw_dir)/'.local/share/streams-aio-recovery'
            and os.geteuid() == 0 and not home.is_relative_to(root)
            and not root.is_relative_to(home), 'OPERATIONAL_DEPLOYMENT_REFUSED')
    checkpoint = home/'state.json'
    info = regular(checkpoint)
    disk = json.loads(checkpoint.read_bytes())
    reconciled = dict(disk,in_progress=None) if isinstance(disk,dict) and disk.get('in_progress') == 'AIO' else disk
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
            and (disk == state or state.get('in_progress') is None and reconciled == state)
            and type(state.get('schema')) is int and state['schema'] == 1
            and state.get('runner_version') == '0.2.0'
            and isinstance(state.get('tag'), str) and re.fullmatch(r'dr-[0-9]{8}T[0-9]{6}Z', state['tag'])
            and isinstance(state.get('public_commit'), str) and re.fullmatch(r'[0-9a-f]{40}', state['public_commit'])
            and state.get('tooling_commit') == state['public_commit']
            and state.get('machine_id') == Path('/etc/machine-id').read_text().strip()
            and state.get('target') == str(root)
            and state.get('in_progress') in (None,'AIO'),
            'OPERATIONAL_DEPLOYMENT_REFUSED')
    if disk.get('in_progress') == 'AIO':
        validate_pending_native_aio(root,home,disk)
    else:
        require(state.get('in_progress') is None,'OPERATIONAL_DEPLOYMENT_REFUSED')
    return root, home


def state_commit(root):
    home = Path(root).parent/'.local/share/streams-aio-recovery'
    checkpoint = safe(home/'state.json')
    if not checkpoint.is_file():
        return None
    state = json.loads(checkpoint.read_bytes())
    if state.get('operational_deployment') is None:
        return None
    deployment_scope(root, home, state)
    return state['public_commit']


def source_identity(root):
    selected = state_commit(root)
    if selected is None:
        return 'test', COMMIT
    import pwd
    return pwd.getpwuid(1000).pw_name, selected


def scope(root, home, state):
    root, home = identity_scope(root, home, state)
    require(state.get('preparation') == 'PASS'
            and state.get('application_start_attempted') is True,
            'RUNTIME_PROFILE_SCOPE_REFUSED')
    return root, home


def first_boot_scope(root, home, state, installing=False):
    root, home = identity_scope(root, home, state)
    completed = state.get('completed')
    require(isinstance(completed, list) and all(isinstance(name, str) for name in completed)
            and len(completed) == len(set(completed))
            and FIRST_BOOT_STAGES <= set(completed), 'RUNTIME_PROFILE_SCOPE_REFUSED')
    if installing:
        # Earlier runners prepared NPM/AIO before this profile existed. Those
        # files may be preserved while registering the compatibility overlay;
        # physical Docker/volume checks still run twice before committing it.
        attempted = state.get('application_start_attempted', False)
        require(type(attempted) is bool and attempted is False
                and state.get('preparation') in (None, 'PASS')
                and set(completed) <= FIRST_BOOT_STAGES | {'NPM', 'AIO'},
                'RUNTIME_PROFILE_PRESTART_CHECKPOINT_REQUIRED')
    return root, home


def compose_line(raw, expected, replacement=None):
    """Replace exactly the renderer's COMPOSE_FILE line, without parsing secrets."""
    pattern = re.compile(rb'^COMPOSE_FILE=(?:\"([^\"\r\n]*)\"|\x27([^\x27\r\n]*)\x27|([^\r\n]*))(?=\r?$)', re.M)
    matches = list(pattern.finditer(raw))
    require(len(matches) == 1 and next(x for x in matches[0].groups() if x is not None)
            == expected.encode(), 'RUNTIME_PROFILE_ENV_REFUSED')
    if replacement is None:
        return raw
    row = matches[0]
    return raw[:row.start()] + b"COMPOSE_FILE='" + replacement.encode() + b"'" + raw[row.end():]


def overlay(root, first_boot=False, cometnet_trial=False, password=None):
    """A reviewed local overlay; V2 includes only its generated trial password.

    Agent-managed env_file contents are never copied. The local overlay and
    separate generated password file are private 0600 artifacts.
    """
    root = Path(root)
    # !override is required: ordinary Compose merging retains the legacy mounts.
    raw = ('services:\n'
            '  postgres:\n'
            '    environment:\n'
            '      PGDATA: /var/lib/postgresql/18/docker\n'
            '    volumes: !override\n'
            '      - type: bind\n'
            '        source: ' + json.dumps(str(root/'data/postgres/init')) + '\n'
            '        target: /docker-entrypoint-initdb.d\n'
            '        read_only: true\n'
            '        bind:\n'
            '          create_host_path: false\n'
            '      - type: volume\n'
            '        source: postgres-cluster\n'
            '        target: /var/lib/postgresql\n'
            '      - type: volume\n'
            '        source: pgdata\n'
            '        target: /legacy-postgresql-data\n'
            '        read_only: true\n'
            '      - type: bind\n'
            '        source: ' + json.dumps(str(root/'data/postgres/postgresql.conf')) + '\n'
            '        target: /etc/postgresql/streams-aio.conf\n'
            '        read_only: true\n'
            '        bind:\n'
            '          create_host_path: false\n'
            '  dnscrypt-proxy:\n'
            '    user: "1000:1000"\n'
            '  aiomanager:\n'
            '    depends_on:\n'
            '      pgbouncer:\n'
            '        condition: service_healthy\n')
    if first_boot:
        raw += ('  oauth2-proxy:\n'
                '    group_add:\n'
                '      - "1000"\n'
                '  pgbouncer:\n'
                '    group_add:\n'
                '      - "1000"\n')
    if cometnet_trial:
        require(first_boot and bool(COMETNET_TRIAL_ENV) and isinstance(password, str)
                and re.fullmatch(r'[0-9a-f]{64}', password), 'COMETNET_TRIAL_SCOPE_REFUSED')
        raw += '  cometnet:\n    environment:\n'
        for name, value in COMETNET_TRIAL_ENV.items():
            raw += '      ' + name + ': ' + json.dumps(value) + '\n'
        raw += '      COMETNET_NETWORK_PASSWORD: ' + json.dumps(password) + '\n'
    return raw.encode()


def source_hashes(root, first_boot=False):
    names = ('docker-compose.yml', 'config/compose.dr.yaml', 'config/dr-manifest.yaml',
             'data/postgres/.env', 'data/postgres/postgresql.conf',
             'data/postgres/init/init.sql', 'data/dnscrypt-proxy/data/dnscrypt-proxy.toml')
    if first_boot:
        names += ('data/oauth2-proxy/allowed-emails.txt', 'data/pgbouncer/data/pgbouncer.ini',
                  '.generated/pgbouncer/userlist.txt', 'scripts/dr.py')
    return {name: digest(root/name) for name in names}


def validate(root, home, state):
    """False means no profile; an orphan or changed profile always refuses."""
    root, home = Path(root), Path(home)
    record = state.get('runtime_profile')
    artifact = safe(root/ARTIFACT)
    backup = safe(home/BACKUP)
    if record is None:
        require(not artifact.exists() and not safe(root/TRIAL_PASSWORD).exists(), 'RUNTIME_PROFILE_CHANGED')
        return False
    fields = {
        'schema', 'id', 'artifact', 'artifact_sha256', 'base_env_sha256',
        'effective_env_sha256', 'env_backup', 'source_hashes', 'preserved_volumes'}
    trial_fields = {'password_artifact', 'password_sha256'}
    require(isinstance(record, dict) and set(record) in (
        fields, fields | {'origin'}, fields | {'origin'} | trial_fields),
        'RUNTIME_PROFILE_CHANGED')
    if 'origin' in record:
        require(record['origin'] == 'FIRST_BOOT', 'RUNTIME_PROFILE_CHANGED')
        root, home = first_boot_scope(root, home, state)
    else:
        root, home = scope(root, home, state)
    first_boot = record.get('origin') == 'FIRST_BOOT'
    expected_profiles = {FIRST_BOOT_PROFILE, COMETNET_TRIAL_PROFILE, OPERATIONAL_PROFILE} if first_boot else {PROFILE}
    cometnet_trial = record.get('id') == COMETNET_TRIAL_PROFILE
    if record.get('id') == OPERATIONAL_PROFILE:
        deployment_scope(root, home, state)
    require(record['schema'] == 1 and record['id'] in expected_profiles
            and record['artifact'] == ARTIFACT and record['env_backup'] == BACKUP,
            'RUNTIME_PROFILE_CHANGED')
    require(set(record) == (fields | {'origin'} | trial_fields if cometnet_trial else
                           fields | {'origin'} if first_boot else fields), 'RUNTIME_PROFILE_CHANGED')
    password = None
    if cometnet_trial:
        require(record.get('password_artifact') == TRIAL_PASSWORD, 'RUNTIME_PROFILE_CHANGED')
        password = trial_password(root, record.get('password_sha256'))
    else:
        require(not safe(root/TRIAL_PASSWORD).exists(), 'RUNTIME_PROFILE_CHANGED')
    info = regular(artifact)
    before_info = regular(backup)
    require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == 1000 and info.st_gid == 1000
            and stat.S_IMODE(before_info.st_mode) == 0o600 and before_info.st_uid == 0
            and digest(artifact) == record['artifact_sha256'] == sha(overlay(root, first_boot, cometnet_trial, password))
            and digest(backup) == record['base_env_sha256'], 'RUNTIME_PROFILE_CHANGED')
    require(source_hashes(root, first_boot) == record['source_hashes'], 'RUNTIME_PROFILE_SOURCE_CHANGED')
    env_metadata(root/'.env')
    raw = (root/'.env').read_bytes()
    require(sha(raw) == record['effective_env_sha256']
            and compose_line(backup.read_bytes(), BASE_COMPOSE, EFFECTIVE_COMPOSE) == raw,
            'RUNTIME_PROFILE_CHANGED')
    require(isinstance(record['preserved_volumes'], dict)
            and set(record['preserved_volumes']) == {'pgdata', 'postgres-cluster'}
            and all(isinstance(value, str) and value == 'streams-aio_' + key
                    for key, value in record['preserved_volumes'].items()),
            'RUNTIME_PROFILE_CHANGED')
    return True


def evidence(facts):
    positive = ('pgdata_nonempty', 'pgdata_legacy', 'sql_readable', 'dnscrypt_permission_denied')
    negative = ('legacy_pg_version', 'versioned_pg_version')
    require(isinstance(facts, dict) and all(facts.get(key) is True for key in positive)
            and all(facts.get(key) is False for key in negative)
            and type(facts.get('pg_major')) is int and facts['pg_major'] == 18
            and type(facts.get('dnscrypt_uid')) is int and facts['dnscrypt_uid'] == 65532
            and type(facts.get('dnscrypt_gid')) is int and facts['dnscrypt_gid'] == 65532
            and facts.get('aiomanager_endpoint') == 'PGBOUNCER',
            'RUNTIME_PROFILE_EVIDENCE_REQUIRED')


def base_model(root, model):
    require(model.get('name') == 'streams-aio' and isinstance(model.get('services'), dict),
            'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED')
    services = model['services']
    require(services.get('postgres', {}).get('image') == PG_IMAGE
            and services.get('dnscrypt-proxy', {}).get('image') == DNS_IMAGE,
            'RUNTIME_PROFILE_IMAGE_CHANGED')
    pg = services['postgres']
    require(pg.get('environment', {}).get('PGDATA') == '/var/lib/postgresql/data'
            and not pg.get('command') and not services['dnscrypt-proxy'].get('user'),
            'RUNTIME_PROFILE_POSTGRES_LAYOUT_REFUSED')
    dns = services['dnscrypt-proxy']
    require(not dns.get('userns_mode') and not dns.get('group_add')
            and len(dns.get('volumes', [])) == 1
            and dns['volumes'][0].get('type') == 'bind'
            and dns['volumes'][0].get('source') == str(root/'data/dnscrypt-proxy/data')
            and dns['volumes'][0].get('target') == '/config'
            and not dns['volumes'][0].get('read_only'),
            'RUNTIME_PROFILE_DNS_PERMISSIONS_REFUSED')
    expected = {
        '/docker-entrypoint-initdb.d': ('bind', str(root/'data/postgres/init')),
        '/var/lib/postgresql/data': ('volume', 'pgdata'),
        '/var/lib/postgresql/data/postgresql.conf': ('bind', str(root/'data/postgres/postgresql.conf')),
        '/var/lib/postgresql': ('volume', 'postgres-cluster'),
    }
    mounts = pg.get('volumes', [])
    require(len(mounts) == len(expected) and {row.get('target') for row in mounts} == set(expected)
            and all((row.get('type'), row.get('source')) == expected[row['target']] for row in mounts),
            'RUNTIME_PROFILE_POSTGRES_LAYOUT_REFUSED')
    declared = model.get('volumes', {})
    require(all(key in declared and not declared[key].get('external')
                and declared[key].get('name') == 'streams-aio_' + key
                for key in ('pgdata', 'postgres-cluster')),
            'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED')
    require('pgbouncer' in services and bool(services['pgbouncer'].get('healthcheck')),
            'RUNTIME_PROFILE_DEPENDENCY_REFUSED')


def candidate_model(root, base, effective, first_boot=False, cometnet_trial=False, password=None):
    """Only the three reviewed service fields may change in resolved Compose."""
    desired = copy.deepcopy(base)
    pg = desired['services']['postgres']
    pg['environment']['PGDATA'] = '/var/lib/postgresql/18/docker'
    pg['volumes'] = [
        dict(type='bind', source=str(root/'data/postgres/init'), target='/docker-entrypoint-initdb.d',
             read_only=True, bind={'create_host_path': False}),
        dict(type='volume', source='postgres-cluster', target='/var/lib/postgresql', volume={}),
        dict(type='volume', source='pgdata', target='/legacy-postgresql-data', read_only=True, volume={}),
        dict(type='bind', source=str(root/'data/postgres/postgresql.conf'), target='/etc/postgresql/streams-aio.conf',
             read_only=True, bind={'create_host_path': False}),
    ]
    desired['services']['dnscrypt-proxy']['user'] = '1000:1000'
    dependencies = desired['services']['aiomanager'].setdefault('depends_on', {})
    require(isinstance(dependencies, dict), 'RUNTIME_PROFILE_DEPENDENCY_REFUSED')
    dependencies['pgbouncer'] = dict(condition='service_healthy', required=True)
    if first_boot:
        desired['services']['oauth2-proxy']['group_add'] = ['1000']
        desired['services']['pgbouncer']['group_add'] = ['1000']
    if cometnet_trial:
        cometnet_trial_model(base)
        desired['services']['cometnet'].setdefault('environment', {}).update(COMETNET_TRIAL_ENV)
        require(isinstance(password, str) and re.fullmatch(r'[0-9a-f]{64}', password),
                'COMETNET_TRIAL_SCOPE_REFUSED')
        desired['services']['cometnet']['environment']['COMETNET_NETWORK_PASSWORD'] = password
    # Compose may serialize an absent empty volume/bind/options object differently.
    def normalized(obj):
        obj = copy.deepcopy(obj)
        for service in obj['services'].values():
            for row in service.get('volumes', []):
                for key in ('volume', 'bind'):
                    if row.get(key) == {}:
                        row.pop(key, None)
                if row.get('read_only') is False:
                    row.pop('read_only', None)
            if 'volumes' in service:
                service['volumes'].sort(key=lambda row: row['target'])
            if isinstance(service.get('depends_on'), dict):
                for row in service['depends_on'].values():
                    if row.get('restart') is False:
                        row.pop('restart', None)
                    row.setdefault('required', True)
        return obj
    require(normalized(effective) == normalized(desired), 'RUNTIME_PROFILE_CANDIDATE_REFUSED')


def cometnet_trial_model(model):
    """The trial may change only reviewed public environment fields."""
    require(bool(COMETNET_TRIAL_ENV), 'COMETNET_TRIAL_SCOPE_REFUSED')
    services = model.get('services', {})
    cometnet = services.get('cometnet', {})
    require(model.get('name') == 'streams-aio'
            and cometnet.get('image') == COMETNET_IMAGE
            and services.get('comet', {}).get('image') == COMETNET_IMAGE
            and cometnet.get('entrypoint') == ['python', '-m', 'comet.cometnet.standalone']
            and cometnet.get('network_mode') == 'service:gluetun'
            and cometnet.get('user') == '1000:1000'
            and isinstance(cometnet.get('environment', {}), dict)
            and cometnet.get('environment', {}).get('COMETNET_LISTEN_PORT') == '8765'
            and cometnet.get('environment', {}).get('COMETNET_HTTP_PORT') == '8766'
            and isinstance(cometnet.get('healthcheck'), dict)
            and not cometnet['healthcheck'].get('disable')
            and cometnet['healthcheck'].get('test') not in (None, 'NONE', ['NONE']),
            'COMETNET_TRIAL_SCOPE_REFUSED')


def trial_password(root, expected_sha):
    path = safe(Path(root)/TRIAL_PASSWORD)
    require(path.is_file(), 'RUNTIME_PROFILE_CHANGED')
    info = regular(path)
    raw = path.read_bytes()
    require(info.st_uid == 1000 and info.st_gid == 1000 and stat.S_IMODE(info.st_mode) == 0o600
            and isinstance(expected_sha, str) and re.fullmatch(r'[0-9a-f]{64}', expected_sha)
            and sha(raw) == expected_sha and re.fullmatch(rb'[0-9a-f]{64}\n', raw),
            'RUNTIME_PROFILE_CHANGED')
    return raw[:-1].decode('ascii')


def derived_waves(model, original):
    """Keep declared ordering, delaying services whose dependency is later."""
    services = model.get('services', {})
    require(isinstance(services, dict) and services and isinstance(original, list)
            and all(isinstance(wave, list) for wave in original),
            'RUNTIME_PROFILE_DEPENDENCY_REFUSED')
    listed = [name for wave in original for name in wave]
    require(all(isinstance(name, str) for name in listed)
            and len(listed) == len(set(listed)) and set(listed) == set(services),
            'RUNTIME_PROFILE_DEPENDENCY_REFUSED')
    original_index = {name: index for index, wave in enumerate(original) for name in wave}
    result, visiting = {}, set()
    def position(name):
        if name in result:
            return result[name]
        require(name not in visiting, 'RUNTIME_PROFILE_DEPENDENCY_REFUSED')
        visiting.add(name)
        row = services[name]
        dependencies = row.get('depends_on', {})
        require(isinstance(dependencies, (dict, list)), 'RUNTIME_PROFILE_DEPENDENCY_REFUSED')
        required = set(dependencies)
        mode = row.get('network_mode', '')
        if isinstance(mode, str) and mode.startswith('service:'):
            required.add(mode.split(':', 1)[1])
        require(required <= set(services) and name not in required,
                'RUNTIME_PROFILE_DEPENDENCY_REFUSED')
        earliest = original_index[name]
        for dependency in sorted(required):
            if isinstance(dependencies, dict):
                config = dependencies.get(dependency, {})
                require(isinstance(config, dict), 'RUNTIME_PROFILE_DEPENDENCY_REFUSED')
                if config.get('condition') == 'service_healthy':
                    # The effective healthcheck may come from the pinned image.
                    # Graph ordering must not mistake an omitted Compose override
                    # for an absent image HEALTHCHECK. Actual image evidence is
                    # collected separately by health_dependency_issues().
                    health = services[dependency].get('healthcheck') or {}
                    require(isinstance(health, dict) and health.get('disable') is not True
                            and health.get('test') not in ('NONE', ['NONE']),
                            'RUNTIME_PROFILE_DEPENDENCY_REFUSED')
            earliest = max(earliest, position(dependency) + 1)
        visiting.remove(name)
        result[name] = earliest
        return earliest
    for name in listed:
        position(name)
    return [[name for name in listed if result[name] == index]
            for index in range(max(result.values()) + 1)
            if any(value == index for value in result.values())]


def health_dependency_issues(model, run):
    """Validate actual healthy-dependency tests; never start or pull an image.

    Missing local images are a separate pending count so the existing download
    step can supply them. An inspected image without a usable test is a failure.
    Query only the public Healthcheck field and cache by pinned image reference.
    """
    services = model.get('services', {})
    require(isinstance(services, dict), 'RUNTIME_PROFILE_DEPENDENCY_REFUSED')
    providers = set()
    issues = 0
    for service in services.values():
        dependencies = service.get('depends_on') or {}
        if isinstance(dependencies, list):
            continue  # Short syntax requires startup, not a healthy result.
        if not isinstance(dependencies, dict):
            issues += 1
            continue
        for name, row in dependencies.items():
            if not isinstance(row, dict):
                issues += 1
            elif row.get('condition') == 'service_healthy':
                providers.add(name)
    cache = {}
    missing = set()
    def usable(test, compose=False):
        if compose and isinstance(test, str):
            return bool(test.strip()) and test != 'NONE'
        return (isinstance(test, list) and len(test) > 1 and test[0] in ('CMD', 'CMD-SHELL')
                and all(isinstance(value, str) for value in test)
                and bool(test[1].strip()))
    for name in sorted(providers):
        if name not in services:
            issues += 1
            continue
        service = services[name]
        health = service.get('healthcheck')
        if health is None:
            health = {}
        if (not isinstance(health, dict)
                or 'disable' in health and type(health['disable']) is not bool
                or health.get('disable') is True):
            issues += 1
            continue
        test = health.get('test')
        if test is not None and test != []:
            issues += int(not usable(test, compose=True))
            continue
        image = service.get('image')
        if not isinstance(image, str) or not re.fullmatch(
                r'[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}', image):
            issues += 1
            continue
        if image not in cache:
            try:
                raw = run(['docker', 'image', 'inspect', '--format',
                           '{{json .Config.Healthcheck}}', image])
            except Exception:
                cache[image] = 'MISSING'
            else:
                try:
                    inherited = json.loads(raw)
                    ok = (isinstance(inherited, dict) and inherited.get('Disable') is not True
                          and usable(inherited.get('Test')))
                except (TypeError, ValueError, UnicodeError):
                    ok = False
                cache[image] = 'VALID' if ok else 'INVALID'
        if cache[image] == 'MISSING':
            missing.add(image)
        else:
            issues += int(cache[image] != 'VALID')
    return issues, len(missing)


def json_run(run, args):
    return json.loads(run([str(value) for value in args]))


def owned_runtime(root, model, run):
    ids = run(['docker', 'ps', '-aq']).decode().split()
    containers = json_run(run, ['docker', 'inspect', *ids]) if ids else []
    names = run(['docker', 'volume', 'ls', '-q']).decode().split()
    volumes = json_run(run, ['docker', 'volume', 'inspect', *names]) if names else []
    for row in containers:
        labels = row.get('Config', {}).get('Labels') or {}
        require(labels.get('com.docker.compose.project') == model['name']
                and labels.get('com.docker.compose.project.working_dir') == str(root)
                and labels.get('com.docker.compose.service') in model['services'],
                'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED')
    declared = model.get('volumes', {})
    require(not any(row.get('external') for row in declared.values()),
            'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED')
    for row in volumes:
        labels = row.get('Labels') or {}
        key = labels.get('com.docker.compose.volume')
        require(labels.get('com.docker.compose.project') == model['name']
                and key in declared and row.get('Name') == declared[key].get('name'),
                'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED')
    by_service = {}
    for row in containers:
        name = row['Config']['Labels']['com.docker.compose.service']
        require(name not in by_service, 'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED')
        by_service[name] = row
    by_volume = {row['Labels']['com.docker.compose.volume']: row for row in volumes}
    require({'postgres', 'dnscrypt-proxy', 'aiomanager'} <= set(by_service)
            and {'pgdata', 'postgres-cluster'} <= set(by_volume),
            'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED')
    return by_service, by_volume


def empty_clusters(volumes, root):
    """Read Docker's owned volume directories, never recursively mutate them."""
    paths = {}
    for key in ('pgdata', 'postgres-cluster'):
        row = volumes[key]
        path = safe(row['Mountpoint'])
        require(path == DOCKER_VOLUME_ROOT/row['Name']/'_data' and path.is_dir(),
                'RUNTIME_PROFILE_POSTGRES_LAYOUT_REFUSED')
        paths[key] = path
    legacy, parent = paths['pgdata'], paths['postgres-cluster']
    for path in (legacy/'PG_VERSION', parent/'18/docker/PG_VERSION', parent/'PG_VERSION', parent/'data/PG_VERSION'):
        require(not path.exists() and not path.is_symlink(), 'RUNTIME_PROFILE_DATABASE_PRESENT')
    entries = list(legacy.iterdir())
    require(len(entries) == 1 and entries[0].name == 'postgresql.conf',
            'RUNTIME_PROFILE_POSTGRES_LAYOUT_REFUSED')
    regular(entries[0])
    require(entries[0].read_bytes() in (b'', (root/'data/postgres/postgresql.conf').read_bytes()),
            'RUNTIME_PROFILE_POSTGRES_LAYOUT_REFUSED')
    # Docker creates the mountpoint in the parent before attaching the companion.
    require({p.name for p in parent.iterdir()} <= {'data'},
            'RUNTIME_PROFILE_POSTGRES_LAYOUT_REFUSED')
    if (parent/'data').exists():
        data = safe(parent/'data')
        require(data.is_dir() and not any(data.iterdir()),
                'RUNTIME_PROFILE_POSTGRES_LAYOUT_REFUSED')
    return {key: row['Name'] for key, row in volumes.items() if key in paths}


def resolve_account(identity, account_file):
    require(isinstance(identity, str) and identity, 'RUNTIME_PROFILE_DNS_IDENTITY_REFUSED')
    user, separator, group = identity.partition(':')
    if user.isdecimal() and group.isdecimal():
        return int(user), int(group)
    rows = [row.split(':') for row in account_file('passwd')]
    matches = [row for row in rows if len(row) == 7 and
               (row[0] == user or user.isdecimal() and row[2] == user)]
    require(len(matches) == 1 and matches[0][2].isdecimal() and matches[0][3].isdecimal(),
            'RUNTIME_PROFILE_DNS_IDENTITY_REFUSED')
    uid, gid = int(matches[0][2]), int(matches[0][3])
    if separator:
        if group.isdecimal():
            gid = int(group)
        else:
            matches = [row.split(':') for row in account_file('group') if row.split(':')[0] == group]
            require(len(matches) == 1 and len(matches[0]) == 4 and matches[0][2].isdecimal(),
                    'RUNTIME_PROFILE_DNS_IDENTITY_REFUSED')
            gid = int(matches[0][2])
    return uid, gid


def container_account(run, container):
    def account_file(name):
        raw = run(['docker', 'cp', container['Id'] + ':/etc/' + name, '-'])
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:*') as archive:
            members = archive.getmembers()
            require(len(members) == 1 and members[0].isfile()
                    and Path(members[0].name).name == name and members[0].size < 1024**2,
                    'RUNTIME_PROFILE_DNS_IDENTITY_REFUSED')
            return archive.extractfile(members[0]).read().decode().splitlines()
    return resolve_account(container.get('Config', {}).get('User'), account_file)


def verified_oci_layers(read, image_id, config_name, config_raw, layer_names, limit):
    """Bind containerd's manifest/index ID to the selected Docker-save row.

    The export's synthetic index.json locates the original inspected target.
    Only hash- and size-verified descriptors below that target may supply the
    linux/amd64 config and layers. Other platforms need not be exported.
    """
    code = 'RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED'
    indices = {'application/vnd.oci.image.index.v1+json',
               'application/vnd.docker.distribution.manifest.list.v2+json'}
    manifests = {'application/vnd.oci.image.manifest.v1+json',
                 'application/vnd.docker.distribution.manifest.v2+json'}
    configs = {'application/vnd.oci.image.config.v1+json',
               'application/vnd.docker.container.image.v1+json'}
    layers = {'application/vnd.oci.image.layer.v1.tar',
              'application/vnd.oci.image.layer.v1.tar+gzip',
              'application/vnd.docker.image.rootfs.diff.tar',
              'application/vnd.docker.image.rootfs.diff.tar.gzip'}

    def descriptor(item, types, maximum):
        require(isinstance(item, dict) and item.get('mediaType') in types
                and isinstance(item.get('digest'), str)
                and re.fullmatch(r'sha256:[0-9a-f]{64}', item['digest'])
                and type(item.get('size')) is int and 0 < item['size'] <= maximum, code)
        return 'blobs/sha256/' + item['digest'][7:]

    def blob(item, types, maximum):
        name = descriptor(item, types, maximum)
        raw = read(name, maximum)
        require(len(raw) == item['size'] and 'sha256:' + sha(raw) == item['digest'], code)
        return raw

    def document(item):
        value = json.loads(blob(item, indices | manifests, 1024**2))
        require(isinstance(value, dict) and value.get('schemaVersion') == 2
                and value.get('mediaType', item['mediaType']) == item['mediaType'], code)
        return value

    def platform(item):
        value = item.get('platform')
        if value is None:
            return None
        require(isinstance(value, dict) and isinstance(value.get('os'), str)
                and isinstance(value.get('architecture'), str), code)
        return value['os'] == 'linux' and value['architecture'] == 'amd64'

    layout = json.loads(read('oci-layout', 1024))
    require(isinstance(layout, dict) and layout.get('imageLayoutVersion') == '1.0.0', code)
    wrapper = json.loads(read('index.json', 1024**2))
    require(isinstance(wrapper, dict) and wrapper.get('schemaVersion') == 2
            and wrapper.get('mediaType') == 'application/vnd.oci.image.index.v1+json'
            and isinstance(wrapper.get('manifests'), list) and 0 < len(wrapper['manifests']) <= 128, code)
    targets = [item for item in wrapper['manifests']
               if isinstance(item, dict) and item.get('digest') == image_id]
    require(len(targets) == 1 and platform(targets[0]) is not False, code)
    visited, candidates = set(), []

    def walk(item, depth):
        require(depth <= 4 and len(visited) < 256, code)
        descriptor(item, indices | manifests, 1024**2)
        require(item['digest'] not in visited, code)
        visited.add(item['digest'])
        value = document(item)
        if item['mediaType'] in indices:
            children = value.get('manifests')
            require(isinstance(children, list) and 0 < len(children) <= 128, code)
            for child in children:
                require(isinstance(child, dict), code)
                # The authenticated index may name absent foreign platforms.
                # Every potentially selected child must be present and verified.
                if platform(child) is not False:
                    walk(child, depth + 1)
            return
        config_descriptor = value.get('config')
        selected_config = blob(config_descriptor, configs, 1024**2)
        selected = json.loads(selected_config)
        require(isinstance(selected, dict) and isinstance(selected.get('os'), str)
                and isinstance(selected.get('architecture'), str), code)
        is_amd64 = selected['os'] == 'linux' and selected['architecture'] == 'amd64'
        declared = platform(item)
        require(declared is None or declared == is_amd64, code)
        if is_amd64:
            require(isinstance(selected.get('rootfs'), dict)
                    and selected['rootfs'].get('type') == 'layers', code)
            candidates.append((value, selected_config))

    walk(targets[0], 0)
    require(len(candidates) == 1, code)
    selected, selected_config = candidates[0]
    require(selected_config == config_raw
            and descriptor(selected['config'], configs, 1024**2)
                == config_name, code)
    selected_layers = selected.get('layers')
    require(isinstance(selected_layers, list) and 0 < len(selected_layers) <= 200
            and [descriptor(item, layers, limit) for item in selected_layers] == layer_names, code)
    return selected_layers


def image_account(raw, image_id, identity, lookup=None):
    """Read two public account files from verified layers, without extraction.

    Legacy Docker config IDs, or containerd's verified OCI descriptor chain,
    and layer diff IDs bind account evidence to the inspected image. Overlay
    whiteouts apply before each layer's files. No container is created.
    """
    limit = 512 * 1024**2
    require(isinstance(raw, bytes) and len(raw) <= limit,
            'RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED')
    require(isinstance(image_id, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', image_id),
            'RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED')
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:*') as outer:
            members = outer.getmembers()
            require(len(members) <= 10000 and len({row.name for row in members}) == len(members),
                    'RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED')
            def read(name, maximum):
                path = PurePosixPath(name)
                require(isinstance(name, str) and not path.is_absolute()
                        and '..' not in path.parts, 'RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED')
                member = outer.getmember(name)
                require(member.isfile() and 0 <= member.size <= maximum,
                        'RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED')
                return outer.extractfile(member).read(maximum + 1)
            manifest = json.loads(read('manifest.json', 1024**2))
            require(isinstance(manifest, list) and len(manifest) == 1
                    and isinstance(manifest[0], dict), 'RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED')
            config_raw = read(manifest[0]['Config'], 1024**2)
            config = json.loads(config_raw)
            require(isinstance(config, dict) and isinstance(config.get('config', {}), dict)
                    and isinstance(config.get('rootfs'), dict)
                    and config.get('config', {}).get('User', '') == identity,
                    'RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED')
            layers = manifest[0]['Layers']
            diffs = config.get('rootfs', {}).get('diff_ids')
            require(isinstance(layers, list) and isinstance(diffs, list)
                    and 0 < len(layers) <= 200 and len(layers) == len(diffs)
                    and all(isinstance(name, str) for name in layers)
                    and len(set(layers)) == len(layers), 'RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED')
            oci_layers = None
            if 'sha256:' + sha(config_raw) != image_id:
                oci_layers = verified_oci_layers(read, image_id, manifest[0]['Config'], config_raw, layers, limit)
            accounts = {}
            for index, (name, expected) in enumerate(zip(layers, diffs)):
                layer_raw = read(name, limit)
                if oci_layers is not None:
                    item = oci_layers[index]
                    require(len(layer_raw) == item['size'] and 'sha256:' + sha(layer_raw) == item['digest']
                            and layer_raw.startswith(b'\x1f\x8b') == (item['mediaType'] in {
                                'application/vnd.oci.image.layer.v1.tar+gzip',
                                'application/vnd.docker.image.rootfs.diff.tar.gzip'}),
                            'RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED')
                if layer_raw.startswith(b'\x1f\x8b'):
                    with gzip.GzipFile(fileobj=io.BytesIO(layer_raw)) as stream:
                        layer_raw = stream.read(limit + 1)
                require(len(layer_raw) <= limit and expected == 'sha256:' + sha(layer_raw),
                        'RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED')
                with tarfile.open(fileobj=io.BytesIO(layer_raw), mode='r:') as layer:
                    rows = layer.getmembers()
                    require(len(rows) <= 200000, 'RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED')
                    require(all(not PurePosixPath(row.name).is_absolute()
                                and '..' not in PurePosixPath(row.name).parts for row in rows)
                            and all(row.isdir() for row in rows if str(PurePosixPath(row.name)) == 'etc'),
                            'RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED')
                    names = {str(PurePosixPath(row.name)) for row in rows}
                    if {'.wh..wh..opq', '.wh.etc', 'etc/.wh..wh..opq'} & names:
                        accounts.clear()
                    for key in ('passwd', 'group'):
                        if 'etc/.wh.' + key in names:
                            accounts.pop(key, None)
                        matches = [row for row in rows if str(PurePosixPath(row.name)) == 'etc/' + key]
                        require(len(matches) <= 1, 'RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED')
                        if matches:
                            row = matches[0]
                            require(row.isfile() and row.size <= 1024**2,
                                    'RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED')
                            accounts[key] = layer.extractfile(row).read().decode().splitlines()
            return resolve_account(identity if lookup is None else lookup, lambda name: accounts[name])
    except Refused:
        raise
    except (KeyError, TypeError, ValueError, UnicodeError, tarfile.TarError, OSError, EOFError, RecursionError):
        raise Refused('RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED') from None


def dns_permissions(root):
    parent = safe(root/'data/dnscrypt-proxy/data')
    info = parent.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 1000 and info.st_gid == 1000
            and stat.S_IMODE(info.st_mode) & 0o700 == 0o700
            and not stat.S_IMODE(info.st_mode) & 0o002,
            'RUNTIME_PROFILE_DNS_PERMISSIONS_REFUSED')
    config = parent/'dnscrypt-proxy.toml'
    info = regular(config)
    require(info.st_uid == 1000 and info.st_gid == 1000 and stat.S_IMODE(info.st_mode) == 0o640,
            'RUNTIME_PROFILE_DNS_PERMISSIONS_REFUSED')
    parsed = tomllib.loads(config.read_text())
    require(parsed.get('user_name') in (None, ''), 'RUNTIME_PROFILE_DNS_IDENTITY_REFUSED')


def readonly_checks(root, model, run):
    version = run(['docker', 'compose', 'version', '--short']).decode().strip()
    match = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?', version)
    require(match is not None and tuple(map(int, match.groups())) >= (2, 24, 4),
            'RUNTIME_PROFILE_COMPOSE_VERSION_REQUIRED')
    user, commit = source_identity(root)
    head = run(['sudo', '-H', '-u', user, '--', 'git', '-C', str(root), 'rev-parse', 'HEAD']).decode().strip()
    require(head == commit, 'RUNTIME_PROFILE_SOURCE_CHANGED')
    containers, volumes = owned_runtime(root, model, run)
    pg, dns = containers['postgres'], containers['dnscrypt-proxy']
    require(pg['Config'].get('Image') == PG_IMAGE and dns['Config'].get('Image') == DNS_IMAGE,
            'RUNTIME_PROFILE_IMAGE_CHANGED')
    require(pg.get('State', {}).get('Running') is False,
            'RUNTIME_PROFILE_POSTGRES_MUST_BE_STOPPED')
    image = json_run(run, ['docker', 'image', 'inspect', pg['Image']])
    require(isinstance(image, list) and len(image) == 1, 'RUNTIME_PROFILE_IMAGE_CHANGED')
    public_env = image[0].get('Config', {}).get('Env') or []
    require('PG_MAJOR=18' in public_env and image[0].get('Id') == pg['Image'],
            'RUNTIME_PROFILE_IMAGE_CHANGED')
    actual_env = pg['Config'].get('Env') or []
    require([value for value in actual_env if value.startswith('PGDATA=')]
            == ['PGDATA=/var/lib/postgresql/data'], 'RUNTIME_PROFILE_POSTGRES_LAYOUT_REFUSED')
    expected_mounts = {
        '/var/lib/postgresql/data': ('volume', volumes['pgdata']['Name']),
        '/var/lib/postgresql': ('volume', volumes['postgres-cluster']['Name']),
        '/var/lib/postgresql/data/postgresql.conf': ('bind', str(root/'data/postgres/postgresql.conf')),
        '/docker-entrypoint-initdb.d': ('bind', str(root/'data/postgres/init')),
    }
    mounts = pg.get('Mounts', [])
    require(len(mounts) == 4 and {row.get('Destination') for row in mounts} == set(expected_mounts)
            and all((row.get('Type'), row.get('Name') if row.get('Type') == 'volume' else row.get('Source'))
                    == expected_mounts[row['Destination']] for row in mounts),
            'RUNTIME_PROFILE_POSTGRES_LAYOUT_REFUSED')
    require(container_account(run, dns) == (65532, 65532), 'RUNTIME_PROFILE_DNS_IDENTITY_REFUSED')
    require(not dns.get('HostConfig', {}).get('UsernsMode')
            and not dns.get('HostConfig', {}).get('GroupAdd')
            and len(dns.get('Mounts', [])) == 1
            and dns['Mounts'][0].get('Type') == 'bind'
            and dns['Mounts'][0].get('Source') == str(root/'data/dnscrypt-proxy/data')
            and dns['Mounts'][0].get('Destination') == '/config'
            and dns['Mounts'][0].get('RW') is True,
            'RUNTIME_PROFILE_DNS_PERMISSIONS_REFUSED')
    dns_permissions(root)
    sql = regular(root/'data/postgres/init/init.sql')
    require(sql.st_uid == 70 and sql.st_gid == 70 and stat.S_IMODE(sql.st_mode) == 0o640,
            'RUNTIME_PROFILE_SQL_CHANGED')
    return empty_clusters(volumes, root)


def readonly_first_boot_checks(root, model, run):
    """Inspect the clean host and pinned images without creating resources."""
    first_boot_model(root, model)
    version = run(['docker', 'compose', 'version', '--short']).decode().strip()
    match = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?', version)
    require(match is not None and tuple(map(int, match.groups())) >= (2, 24, 4),
            'RUNTIME_PROFILE_COMPOSE_VERSION_REQUIRED')
    user, commit = source_identity(root)
    head = run(['sudo', '-H', '-u', user, '--', 'git', '-C', str(root), 'rev-parse', 'HEAD']).decode().strip()
    require(head == commit, 'RUNTIME_PROFILE_SOURCE_CHANGED')
    require(not run(['docker', 'ps', '-aq']).strip(), 'RUNTIME_PROFILE_FRESH_HOST_REQUIRED')
    declared = model.get('volumes', {})
    require(isinstance(declared, dict) and not any(row.get('external') for row in declared.values()),
            'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED')
    names = run(['docker', 'volume', 'ls', '-q']).decode().split()
    volumes = json_run(run, ['docker', 'volume', 'inspect', *names]) if names else []
    for row in volumes:
        labels = row.get('Labels') or {}
        key = labels.get('com.docker.compose.volume')
        require(labels.get('com.docker.compose.project') == model['name']
                and key in declared and row.get('Name') == declared[key].get('name'),
                'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED')
        path = safe(row['Mountpoint'])
        require(path == DOCKER_VOLUME_ROOT/row['Name']/'_data' and path.is_dir(),
                'RUNTIME_PROFILE_POSTGRES_LAYOUT_REFUSED')
        if key in ('pgdata', 'postgres-cluster'):
            for relative in ('PG_VERSION', '18/docker/PG_VERSION', 'data/PG_VERSION'):
                marker = safe(path/relative)
                require(not marker.exists(), 'RUNTIME_PROFILE_DATABASE_PRESENT')
        require(not any(path.iterdir()), 'RUNTIME_PROFILE_FRESH_HOST_REQUIRED')
    images = {}
    for reference in FIRST_BOOT_IMAGES:
        item = json_run(run, ['docker', 'image', 'inspect', '--format', IMAGE_METADATA_FORMAT, reference])
        require(isinstance(item, dict) and item.get('Os') == 'linux'
                and item.get('Architecture') == 'amd64'
                and isinstance(item.get('User'), str)
                and isinstance(item.get('Id'), str)
                and re.fullmatch(r'sha256:[0-9a-f]{64}', item['Id']),
                'RUNTIME_PROFILE_IMAGE_CHANGED')
        images[reference] = item
    pg = images[PG_IMAGE]
    require(isinstance(pg.get('Env'), list) and 'PG_MAJOR=18' in pg['Env']
            and 'PGDATA=/var/lib/postgresql/18/docker' in pg['Env'],
            'RUNTIME_PROFILE_IMAGE_CHANGED')
    dns = images[DNS_IMAGE]
    identity = dns.get('User')
    if isinstance(identity, str) and re.fullmatch(r'\d+:\d+', identity):
        account = tuple(map(int, identity.split(':')))
    else:
        account = image_account(run(['docker', 'image', 'save', DNS_IMAGE]), dns['Id'], identity)
    require(account == (65532, 65532), 'RUNTIME_PROFILE_DNS_IDENTITY_REFUSED')
    dns_permissions(root)
    sql = regular(root/'data/postgres/init/init.sql')
    require(sql.st_uid == 70 and sql.st_gid == 70 and stat.S_IMODE(sql.st_mode) == 0o640,
            'RUNTIME_PROFILE_SQL_CHANGED')
    pg_account = image_account(run(['docker', 'image', 'save', PG_IMAGE]), pg['Id'], pg['User'], lookup='postgres')
    require(pg_account[0] > 0 and bind_readable(root/'data/postgres/init', 'init.sql', *pg_account),
            'RUNTIME_PROFILE_SQL_CHANGED')
    try:
        environment = model['services']['aiomanager'].get('environment') or {}
        endpoint = urlsplit(environment.get('DATABASE_URL', '')).hostname
    except (TypeError, ValueError):
        endpoint = None
    require(endpoint == 'pgbouncer', 'RUNTIME_PROFILE_DEPENDENCY_REFUSED')
    init = safe(root/'data/postgres/init')
    require(init.is_dir() and {row.name for row in init.iterdir()} == {'init.sql'},
            'RUNTIME_PROFILE_SQL_CHANGED')
    for service, reference, expected_account, specs in (
            ('oauth2-proxy', OAUTH_IMAGE, (65532, 65532),
             (('data/oauth2-proxy/allowed-emails.txt', 1000),)),
            ('pgbouncer', PGBOUNCER_IMAGE, None,
             (('data/pgbouncer/data/pgbouncer.ini', 1000), ('.generated/pgbouncer/userlist.txt', 0)))):
        item = images[reference]
        account = image_account(run(['docker', 'image', 'save', reference]), item['Id'], item['User'])
        require(account[0] > 0 and (expected_account is None or account == expected_account),
                'RUNTIME_PROFILE_DNS_IDENTITY_REFUSED')
        for relative, owner in specs:
            path = root/relative
            private_bind_metadata(path, owner)
            require(bind_readable(path.parent, path.name, *account, groups=(1000,)),
                    'RUNTIME_PROFILE_DNS_PERMISSIONS_REFUSED')
    verify_pgbouncer_userlist(root, model, run)
    # Names are retained even when Compose will first create the empty volumes.
    return {key: declared[key]['name'] for key in ('pgdata', 'postgres-cluster')}


def verify_pgbouncer_userlist(root, model, run):
    """Use the immutable renderer's parser; never append or log credentials."""
    path = root/'scripts/dr.py'
    regular(path)
    user, commit = source_identity(root)
    source = run(['sudo', '-H', '-u', user, '--', 'git', '-C', str(root),
                  'show', commit + ':scripts/dr.py'])
    require(path.read_bytes() == source, 'RUNTIME_PROFILE_SOURCE_CHANGED')
    environment = model['services']['pgbouncer'].get('environment') or {}
    require(environment.get('DB_USER') == 'postgres'
            and isinstance(environment.get('DB_PASSWORD'), str) and environment['DB_PASSWORD'],
            'RUNTIME_PROFILE_SQL_CHANGED')
    content = (root/'.generated/pgbouncer/userlist.txt').read_text()
    # The image entrypoint's grep anchors at column zero; a leading-space row
    # accepted by PgBouncer itself would otherwise trigger an attempted append.
    require(any(re.match(r'^"postgres"\s+"', line) for line in content.splitlines()),
            'RUNTIME_PROFILE_SQL_CHANGED')
    try:
        namespace = {'__name__': 'runtime_profile_pinned_renderer', '__file__': str(path)}
        exec(compile(source, str(path), 'exec'), namespace)
        entries = namespace['userlist_entries'](content)
        namespace['verified_role_password']('postgres', environment['DB_PASSWORD'], entries.get('postgres'))
    except Exception:
        raise Refused('RUNTIME_PROFILE_SQL_CHANGED') from None


def first_boot_model(root, model):
    for service, reference, expected in (
            ('oauth2-proxy', OAUTH_IMAGE,
             {'/etc/oauth2-proxy/allowed-emails.txt': ('data/oauth2-proxy/allowed-emails.txt', True)}),
            ('pgbouncer', PGBOUNCER_IMAGE,
             {'/etc/pgbouncer/pgbouncer.ini': ('data/pgbouncer/data/pgbouncer.ini', True),
              '/etc/pgbouncer/userlist.txt': ('.generated/pgbouncer/userlist.txt', False)})):
        row = model['services'].get(service, {})
        require(row.get('image') == reference and not row.get('user')
                and not row.get('group_add') and not row.get('userns_mode'),
                'RUNTIME_PROFILE_IMAGE_CHANGED')
        binds = row.get('volumes', [])
        require(len(binds) == len(expected) and {item.get('target') for item in binds} == set(expected)
                and all(item.get('type') == 'bind'
                        and item.get('source') == str(root/expected[item['target']][0])
                        and bool(item.get('read_only')) == expected[item['target']][1] for item in binds),
                'RUNTIME_PROFILE_DNS_PERMISSIONS_REFUSED')


def private_bind_metadata(path, owner):
    info = regular(path)
    parent = safe(path.parent).stat()
    require(info.st_uid == owner and info.st_gid == 1000 and stat.S_IMODE(info.st_mode) == 0o640
            and stat.S_ISDIR(parent.st_mode) and parent.st_uid in (0, 1000)
            and parent.st_gid == 1000 and stat.S_IMODE(parent.st_mode) & 0o700 == 0o700
            and not stat.S_IMODE(parent.st_mode) & 0o002,
            'RUNTIME_PROFILE_DNS_PERMISSIONS_REFUSED')


def bind_readable(directory, filename, uid, gid, groups=()):
    """Check kernel ACL access after dropping privileges in the bound root."""
    require(os.geteuid() == 0 and hasattr(os, 'fork')
            and isinstance(filename, str) and Path(filename).name == filename,
            'RUNTIME_PROFILE_DNS_PERMISSIONS_REFUSED')
    directory = safe(directory)
    child = os.fork()
    if child == 0:
        try:
            os.chdir(directory)
            os.setgroups(list(groups))
            os.setgid(gid)
            os.setuid(uid)
            ok = os.access('.', os.X_OK) and os.access(filename, os.R_OK)
            os._exit(0 if ok else 1)
        except Exception:
            os._exit(2)
    _, status = os.waitpid(child, 0)
    return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


def atomic(path, raw, mode, uid, gid):
    path = safe(path)
    fd, name = tempfile.mkstemp(prefix='.runtime-profile-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), mode)
            os.fchown(output.fileno(), uid, gid)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def private_directory(path):
    info = safe(path).stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) == 0o700,
            'RUNTIME_PROFILE_PATH_REFUSED')


def apply(root, home, state, model, facts, run):
    """Commit a verified override and pointer; roll back an uncommitted change."""
    root, home = scope(root, home, state)
    if validate(root, home, state):
        return dict(applied=False, profile=state['runtime_profile']['id'])
    evidence(facts)
    base_model(root, model)
    return commit_profile(root, home, state, model, run,
                          lambda: readonly_checks(root, model, run))


def apply_fresh(root, home, state, model, run):
    """Register the reviewed profile before the first application startup.

    Call after completed EMPTY_STATE, normally before NPM, while holding
    recovery.lock. An older same-scope prepared checkpoint may register this
    profile without replaying NPM/AIO if application startup was never attempted
    and all physical first-boot checks still pass.
    FIRST_BOOT_IMAGES must already be pulled; this module only inspects them.
    An existing verified FIRST_BOOT record is safe to revisit after preparation.
    """
    root, home = Path(root), Path(home)
    if validate(root, home, state):
        return dict(applied=False, profile=state['runtime_profile']['id'])
    root, home = first_boot_scope(root, home, state, installing=True)
    base_model(root, model)
    first_boot_model(root, model)
    cometnet_trial_model(model)
    return commit_profile(root, home, state, model, run,
                          lambda: readonly_first_boot_checks(root, model, run), origin='FIRST_BOOT',
                          cometnet_trial=state.get('operational_deployment') is None)


def commit_profile(root, home, state, model, run, inspect, origin=None, cometnet_trial=False):
    first_boot = origin == 'FIRST_BOOT'
    identifier = (COMETNET_TRIAL_PROFILE if cometnet_trial else FIRST_BOOT_PROFILE) if first_boot else PROFILE
    if first_boot and state.get('operational_deployment') is not None:
        require(not cometnet_trial, 'OPERATIONAL_DEPLOYMENT_REFUSED')
        identifier = OPERATIONAL_PROFILE
    preserved = inspect()
    before_sources = source_hashes(root, first_boot)
    env_path = root/'.env'
    env_info = env_metadata(env_path)
    original_env = env_path.read_bytes()
    updated_env = compose_line(original_env, BASE_COMPOSE, EFFECTIVE_COMPOSE)
    artifact, backup = safe(root/ARTIFACT), safe(home/BACKUP)
    require(not artifact.exists(), 'RUNTIME_PROFILE_CHANGED')
    password_path = safe(root/TRIAL_PASSWORD)
    require(not password_path.exists(), 'RUNTIME_PROFILE_CHANGED')
    password = secrets.token_hex(32) if cometnet_trial else None
    password_raw = (password + '\n').encode() if cometnet_trial else None
    backup.parent.mkdir(mode=0o700, exist_ok=True)
    private_directory(backup.parent)
    if backup.exists():
        info = regular(backup)
        require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
                and backup.read_bytes() == original_env, 'RUNTIME_PROFILE_CHANGED')
    else:
        atomic(backup, original_env, 0o600, 0, 0)
    candidate = overlay(root, first_boot, cometnet_trial, password)
    committed = False
    env_changed = False
    password_created = False
    try:
        atomic(artifact, candidate, 0o600, 1000, 1000)
        effective = json_run(run, ['docker', 'compose', '--env-file', str(env_path),
            '-f', str(root/'docker-compose.yml'), '-f', str(root/'config/compose.dr.yaml'),
            '-f', str(artifact), '--profile', 'all', 'config', '--format', 'json'])
        candidate_model(root, model, effective, first_boot, cometnet_trial, password)
        require(source_hashes(root, first_boot) == before_sources and env_path.read_bytes() == original_env,
                'RUNTIME_PROFILE_SOURCE_CHANGED')
        require(inspect() == preserved,
                'RUNTIME_PROFILE_POSTGRES_LAYOUT_REFUSED')
        updated_state = copy.deepcopy(state)
        updated_state['runtime_profile'] = dict(
            schema=1, id=identifier, artifact=ARTIFACT, artifact_sha256=sha(candidate),
            base_env_sha256=sha(original_env), effective_env_sha256=sha(updated_env),
            env_backup=BACKUP, source_hashes=before_sources, preserved_volumes=preserved)
        if origin is not None:
            updated_state['runtime_profile']['origin'] = origin
        if cometnet_trial:
            password_created = True
            atomic(password_path, password_raw, 0o600, 1000, 1000)
            updated_state['runtime_profile'].update(password_artifact=TRIAL_PASSWORD,
                                                     password_sha256=sha(password_raw))
        atomic(env_path, updated_env, stat.S_IMODE(env_info.st_mode), env_info.st_uid, env_info.st_gid)
        env_changed = True
        require(source_hashes(root, first_boot) == before_sources, 'RUNTIME_PROFILE_SOURCE_CHANGED')
        raw_state = (json.dumps(updated_state, indent=2) + '\n').encode()
        atomic(home/'state.json', raw_state, 0o600, 0, 0)
        committed = True
        state.clear()
        state.update(updated_state)
        return dict(applied=True, profile=identifier)
    except Exception as error:
        if not committed:
            if env_changed:
                atomic(env_path, original_env, stat.S_IMODE(env_info.st_mode), env_info.st_uid, env_info.st_gid)
            if artifact.exists():
                artifact.unlink()
            if password_created and password_path.exists():
                password_path.unlink()
        if isinstance(error, Refused):
            raise
        raise Refused('RUNTIME_PROFILE_TRANSACTION_FAILED') from None


def cometnet_runtime_snapshot(root, model, run):
    """Check every workload before changing the registered public overlay.

    Only identity metadata is retained: restart counters and health may change
    while Docker's restart policy runs. The same resource IDs must still be
    present at commit. No container or volume operation is performed here.
    """
    require(model.get('name') == 'streams-aio' and isinstance(model.get('services'), dict)
            and isinstance(model.get('volumes', {}), dict),
            'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED')
    ids = run(['docker', 'ps', '-aq']).decode().split()
    require(len(ids) == len(set(ids)) and len(ids) <= len(model['services'])
            and all(re.fullmatch(r'[0-9a-f]{12,64}', value) for value in ids),
            'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED')
    rows = json_run(run, ['docker', 'inspect', *ids]) if ids else []
    names = run(['docker', 'volume', 'ls', '-q']).decode().split()
    require(len(names) == len(set(names)) and len(names) <= len(model.get('volumes', {}))
            and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', value) for value in names),
            'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED')
    volumes = json_run(run, ['docker', 'volume', 'inspect', *names]) if names else []
    require(isinstance(rows, list) and len(rows) == len(ids)
            and isinstance(volumes, list) and len(volumes) == len(names),
            'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED')
    services = {}
    for row in rows:
        labels = row.get('Config', {}).get('Labels') or {}
        service = labels.get('com.docker.compose.service')
        identifier = row.get('Id')
        require(labels.get('com.docker.compose.project') == 'streams-aio'
                and labels.get('com.docker.compose.project.working_dir') == str(root)
                and service in model['services'] and service not in services
                and isinstance(identifier, str) and re.fullmatch(r'[0-9a-f]{64}', identifier),
                'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED')
        if service in ('comet', 'cometnet'):
            require(row.get('Config', {}).get('Image') == COMETNET_IMAGE,
                    'RUNTIME_PROFILE_IMAGE_CHANGED')
        services[service] = identifier
    declared = model.get('volumes', {})
    require(not any(row.get('external') for row in declared.values()),
            'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED')
    owned_volumes = {}
    for row in volumes:
        labels = row.get('Labels') or {}
        key = labels.get('com.docker.compose.volume')
        name = row.get('Name')
        require(labels.get('com.docker.compose.project') == 'streams-aio'
                and key in declared and key not in owned_volumes
                and isinstance(name, str) and name in names
                and name == declared[key].get('name') and row.get('Driver') == 'local'
                and not row.get('Options') and row.get('Mountpoint') == str(DOCKER_VOLUME_ROOT/name/'_data'),
                'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED')
        owned_volumes[key] = name
    return dict(containers=services, volumes=owned_volumes)


def migrate_cometnet_trial(root, home, state, model, run, tls=False):
    """Replace a validated V1 overlay while preserving prepared private state.

    The caller must hold the exclusive recovery lock. It also chooses whether
    to resume the failing Compose wave after commit; this function never
    starts, stops, recreates or deletes any workload.
    """
    require(type(tls) is bool and tls is False, 'COMETNET_TRIAL_TLS_REFUSED')
    root, home = identity_scope(root, home, state)
    require(validate(root, home, state) is True, 'COMETNET_TRIAL_SCOPE_REFUSED')
    old_record = state['runtime_profile']
    if old_record['id'] == COMETNET_TRIAL_PROFILE:
        return dict(applied=False, profile=COMETNET_TRIAL_PROFILE)
    attempted = state.get('application_start_attempted', False)
    require(old_record.get('origin') == 'FIRST_BOOT' and old_record['id'] == FIRST_BOOT_PROFILE
            and state.get('preparation') == 'PASS' and type(attempted) is bool
            and state.get('application_recovery') in (None, 'NOT_VERIFIED')
            and (state.get('tls_verified') is None or state.get('tls_verified') is False)
            and (state.get('application_wave') == ['cometnet'] if attempted
                 else state.get('application_wave') is None),
            'COMETNET_TRIAL_SCOPE_REFUSED')
    cometnet_trial_model(model)
    require(json_run(run, ['docker', 'compose', '--profile', 'all', 'config', '--format', 'json']) == model,
            'RUNTIME_PROFILE_CANDIDATE_REFUSED')
    preserved = cometnet_runtime_snapshot(root, model, run)
    if attempted:
        require({'comet', 'cometnet', 'postgres', 'pgbouncer', 'gluetun'} <= set(preserved['containers']),
                'COMETNET_TRIAL_SCOPE_REFUSED')
    else:
        require(not preserved['containers'] and not preserved['volumes'],
                'COMETNET_TRIAL_SCOPE_REFUSED')
    artifact, state_path, env_path = safe(root/ARTIFACT), safe(home/'state.json'), safe(root/'.env')
    old_artifact, old_state, old_env = artifact.read_bytes(), state_path.read_bytes(), env_path.read_bytes()
    old_sources = source_hashes(root, first_boot=True)
    archive_parent = safe(home/COMETNET_MIGRATION_BACKUP)
    archive_parent.mkdir(mode=0o700, exist_ok=True)
    private_directory(archive_parent)
    archive = safe(archive_parent/(sha(old_state)[:16] + '-' + sha(old_artifact)[:16]))
    archive.mkdir(mode=0o700, exist_ok=True)
    private_directory(archive)
    for filename, raw in (('state.json', old_state), ('runtime.compose.yaml', old_artifact)):
        path = archive/filename
        if path.exists():
            info = regular(path)
            require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and path.read_bytes() == raw,
                    'RUNTIME_PROFILE_CHANGED')
        else:
            atomic(path, raw, 0o600, 0, 0)
    password_path = safe(root/TRIAL_PASSWORD)
    require(not password_path.exists(), 'RUNTIME_PROFILE_CHANGED')
    password = secrets.token_hex(32)
    password_raw = (password + '\n').encode()
    candidate = overlay(root, first_boot=True, cometnet_trial=True, password=password)
    updated = copy.deepcopy(state)
    updated['runtime_profile']['id'] = COMETNET_TRIAL_PROFILE
    updated['runtime_profile']['artifact_sha256'] = sha(candidate)
    updated['runtime_profile'].update(password_artifact=TRIAL_PASSWORD, password_sha256=sha(password_raw))
    updated_raw = (json.dumps(updated, indent=2) + '\n').encode()
    fd, staging_name = tempfile.mkstemp(prefix='.cometnet-trial-', dir=artifact.parent)
    os.close(fd)
    staging = safe(staging_name)
    artifact_changed = state_changed = password_created = committed = False
    try:
        atomic(staging, candidate, 0o600, 1000, 1000)
        effective = json_run(run, ['docker', 'compose', '--env-file', str(env_path),
            '-f', str(root/'docker-compose.yml'), '-f', str(root/'config/compose.dr.yaml'),
            '-f', str(staging), '--profile', 'all', 'config', '--format', 'json'])
        candidate_model(root, model, effective, first_boot=True, cometnet_trial=True, password=password)
        require(validate(root, home, state) is True and state_path.read_bytes() == old_state
                and artifact.read_bytes() == old_artifact and env_path.read_bytes() == old_env
                and source_hashes(root, first_boot=True) == old_sources
                and json_run(run, ['docker', 'compose', '--profile', 'all', 'config', '--format', 'json']) == model
                and cometnet_runtime_snapshot(root, model, run) == preserved,
                'RUNTIME_PROFILE_CHANGED')
        artifact_changed = True
        password_created = True
        atomic(password_path, password_raw, 0o600, 1000, 1000)
        atomic(artifact, candidate, 0o600, 1000, 1000)
        # The pointer and all source hashes are deliberately unchanged.
        require(env_path.read_bytes() == old_env and source_hashes(root, first_boot=True) == old_sources,
                'RUNTIME_PROFILE_SOURCE_CHANGED')
        state_changed = True
        atomic(state_path, updated_raw, 0o600, 0, 0)
        require(state_path.read_bytes() == updated_raw and artifact.read_bytes() == candidate,
                'COMETNET_TRIAL_TRANSACTION_FAILED')
        committed = True
        state.clear()
        state.update(updated)
        return dict(applied=True, profile=COMETNET_TRIAL_PROFILE)
    except Exception as error:
        if not committed:
            if artifact_changed:
                atomic(artifact, old_artifact, 0o600, 1000, 1000)
            if state_changed:
                atomic(state_path, old_state, 0o600, 0, 0)
            if password_created and password_path.exists():
                password_path.unlink()
        if isinstance(error, Refused):
            raise
        raise Refused('COMETNET_TRIAL_TRANSACTION_FAILED') from None
    finally:
        if staging.exists():
            staging.unlink()


def promote_operational(root, home, state, model, run, routing_mode, domain_target_address):
    """Restore CometNet's actual Infisical environment without resetting data.

    V1/V2 archives remain root-private and rollback is atomic under the
    caller's recovery lock. This only changes the registered overlay; DNS,
    containers and NPM are handled by the subsequent checked startup phases.
    """
    root, home = identity_scope(root, home, state)
    require(validate(root, home, state) is True and state.get('preparation') == 'PASS'
            and state['runtime_profile'].get('origin') == 'FIRST_BOOT',
            'OPERATIONAL_DEPLOYMENT_REFUSED')
    record = deployment_record(root, state, routing_mode, domain_target_address)
    if state['runtime_profile']['id'] == OPERATIONAL_PROFILE:
        require(state.get('operational_deployment') == record, 'OPERATIONAL_DEPLOYMENT_REFUSED')
        return dict(applied=False, profile=OPERATIONAL_PROFILE)
    require(state['runtime_profile']['id'] in (FIRST_BOOT_PROFILE, COMETNET_TRIAL_PROFILE),
            'OPERATIONAL_DEPLOYMENT_REFUSED')
    preserved = cometnet_runtime_snapshot(root, model, run)
    artifact, checkpoint = safe(root/ARTIFACT), safe(home/'state.json')
    old_artifact, old_state, old_env = artifact.read_bytes(), checkpoint.read_bytes(), (root/'.env').read_bytes()
    old_sources = source_hashes(root, first_boot=True)
    password_path = safe(root/TRIAL_PASSWORD)
    old_password = password_path.read_bytes() if password_path.exists() else None
    # Resolve the original env files, not the V2 Compose environment overrides.
    args = ['docker', 'compose', '--env-file', str(root/'.env'), '-f', str(root/'docker-compose.yml'),
            '-f', str(root/'config/compose.dr.yaml'), '--profile', 'all', 'config', '--format', 'json']
    base = json_run(run, args)
    candidate_model(root, base, model, first_boot=True,
                    cometnet_trial=state['runtime_profile']['id'] == COMETNET_TRIAL_PROFILE,
                    password=old_password[:-1].decode('ascii') if old_password else None)
    candidate = overlay(root, first_boot=True)
    parent = safe(home/'runtime-profile/operational-v3')
    parent.mkdir(mode=0o700, exist_ok=True); private_directory(parent)
    archive = safe(parent/(sha(old_state)[:16] + '-' + sha(old_artifact)[:16]))
    archive.mkdir(mode=0o700, exist_ok=True); private_directory(archive)
    for name, raw in (('state.json', old_state), ('runtime.compose.yaml', old_artifact),
                      ('trial.password', old_password)):
        if raw is None:
            continue
        path = archive/name
        if path.exists():
            info = regular(path)
            require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and path.read_bytes() == raw,
                    'RUNTIME_PROFILE_CHANGED')
        else:
            atomic(path, raw, 0o600, 0, 0)
    updated = copy.deepcopy(state)
    updated['operational_deployment'] = record
    updated['public_domain_recovery'] = 'PENDING'
    updated['runtime_profile'].update(id=OPERATIONAL_PROFILE, artifact_sha256=sha(candidate))
    updated['runtime_profile'].pop('password_artifact', None)
    updated['runtime_profile'].pop('password_sha256', None)
    raw_state = (json.dumps(updated, indent=2) + '\n').encode()
    fd, name = tempfile.mkstemp(prefix='.operational-', dir=artifact.parent)
    os.close(fd); staging = safe(name)
    changed = password_removed = committed = False
    try:
        atomic(staging, candidate, 0o600, 1000, 1000)
        effective = json_run(run, args[:args.index('--profile')] + ['-f', str(staging)]
                             + args[args.index('--profile'):])
        candidate_model(root, base, effective, first_boot=True)
        require(validate(root, home, state) is True and checkpoint.read_bytes() == old_state
                and artifact.read_bytes() == old_artifact and (root/'.env').read_bytes() == old_env
                and source_hashes(root, first_boot=True) == old_sources
                and json_run(run, args) == base
                and cometnet_runtime_snapshot(root, model, run) == preserved,
                'RUNTIME_PROFILE_CHANGED')
        changed = True
        atomic(artifact, candidate, 0o600, 1000, 1000)
        if old_password is not None:
            password_path.unlink(); password_removed = True
        atomic(checkpoint, raw_state, 0o600, 0, 0)
        require(checkpoint.read_bytes() == raw_state and artifact.read_bytes() == candidate
                and (root/'.env').read_bytes() == old_env
                and source_hashes(root, first_boot=True) == old_sources,
                'OPERATIONAL_PROFILE_TRANSACTION_FAILED')
        committed = True
        state.clear(); state.update(updated)
        return dict(applied=True, profile=OPERATIONAL_PROFILE)
    except Exception as error:
        if not committed and changed:
            atomic(artifact, old_artifact, 0o600, 1000, 1000)
            if password_removed:
                atomic(password_path, old_password, 0o600, 1000, 1000)
            atomic(checkpoint, old_state, 0o600, 0, 0)
        if isinstance(error, Refused):
            raise
        raise Refused('OPERATIONAL_PROFILE_TRANSACTION_FAILED') from None
    finally:
        if staging.exists():
            staging.unlink()

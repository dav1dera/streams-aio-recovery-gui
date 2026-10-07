"""Restore the reviewed Infisical Docker deployment on a fresh replacement VM.

All subprocess output and private configuration stay on the replacement host.
The desktop forwards the restored API over two authenticated SSH connections.
"""
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import tarfile
import tempfile
import time

from recover import (Recovery, Refused, command, digest, event, private_file,
                     require, safe_path, save, validate_bundle)
from start import validate_runtime


SERVICES = {'backend', 'db', 'redis'}
PROFILE_PATH = Path(__file__).with_name('infisical-deployment.json')
CONFIG_NAMES = {'docker-compose.prod.yml', '.env'}
DIGEST = re.compile(r'[a-zA-Z0-9._:/-]+@sha256:[0-9a-f]{64}\Z')
IDENTIFIER = re.compile(r'[a-zA-Z_][a-zA-Z0-9_]{0,62}\Z')
# These are the two shipped byte representations of the same reviewed profile
# (LF in the source archive/local build, CRLF in the Windows CI checkout).
# A legacy checkpoint can migrate only to that exact semantic profile.
LEGACY_PROFILE_HASHES = {
    '91a2952ba4c2b974fffe63c4aff1e265df70302909f7ed1522d9ac2bc46c44ed',
    '410fd23eeaf793240713472a7430c68b57302ee0668de9efd0ed47d86173af88',
}
LEGACY_PROFILE_CANONICAL_SHA256 = '1b3e2e99aecc38f4a49d6ccb30ce39305950d6816d32026191a4bb0a9f1ffb71'


def deployment_fingerprint(deployment):
    """Bind the actual database/image settings, independent of JSON layout."""
    normalized = copy.deepcopy(deployment)
    normalized['services'] = sorted(normalized['services'])
    raw = json.dumps(normalized, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def validate_profile_checkpoint(state, state_path, deployment):
    current = deployment_fingerprint(deployment)
    if 'deployment_profile_canonical_sha256' in state:
        require(state['deployment_profile_canonical_sha256'] == current,
                'INFISICAL_DEPLOYMENT_PROFILE_CHANGED')
        return
    legacy = state.get('deployment_profile_sha256')
    require(isinstance(legacy, str) and legacy in LEGACY_PROFILE_HASHES
            and current == LEGACY_PROFILE_CANONICAL_SHA256,
            'INFISICAL_DEPLOYMENT_PROFILE_CHANGED')
    # Keep the original raw fingerprint and all completed phases for audit.
    # Atomic save happens only after proving compatibility, without touching
    # installed configuration, database, containers or restore materials.
    updated = dict(state, deployment_profile_canonical_sha256=current)
    save(state_path, updated)
    state.update(updated)


def profile(path=PROFILE_PATH):
    data = json.loads(path.read_bytes())
    require(set(data) == {'schema', 'source_directory', 'services', 'database',
                         'database_user', 'postgres_major', 'images'},
            'INFISICAL_DEPLOYMENT_PROFILE_INVALID')
    require(data['schema'] == 1 and data['source_directory'] == '/opt/infisical'
            and set(data['services']) == SERVICES and set(data['images']) == SERVICES,
            'INFISICAL_DEPLOYMENT_PROFILE_INVALID')
    require(data['postgres_major'] == 14 and all(isinstance(data[key], str)
            and IDENTIFIER.fullmatch(data[key]) for key in ('database', 'database_user')),
            'INFISICAL_DEPLOYMENT_PROFILE_INVALID')
    require(data['database'] not in ('postgres', 'template0', 'template1'),
            'INFISICAL_APPLICATION_DATABASE_REQUIRED')
    require(all(isinstance(image, str) and DIGEST.fullmatch(image)
            for image in data['images'].values()), 'INFISICAL_PINNED_IMAGES_REQUIRED')
    return data


def unpack_config(archive, destination):
    """Accept the two reviewed tar layouts, never extract archives towards /."""
    require(not destination.exists(), 'EXISTING_INFISICAL_CONFIG_REFUSED')
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        require(len(members) <= 2000 and sum(item.size for item in members) <= 64*1024**2,
                'INFISICAL_CONFIG_ARCHIVE_TOO_LARGE')
        files, normalized = {}, set()
        for item in members:
            path = PurePosixPath(item.name)
            require(not path.is_absolute() and '..' not in path.parts
                    and '\\' not in item.name and ':' not in item.name
                    and (item.isdir() or item.isfile()), 'UNSAFE_INFISICAL_CONFIG_ARCHIVE')
            name = path.as_posix()
            require(name not in normalized, 'DUPLICATE_INFISICAL_CONFIG_ENTRY')
            normalized.add(name)
            if item.isfile():
                files[name] = item
        layouts = [dict((name, name) for name in CONFIG_NAMES),
                   dict((name, 'opt/infisical/'+name) for name in CONFIG_NAMES)]
        accepted = [layout for layout in layouts if set(layout.values()) == set(files)]
        require(len(accepted) == 1, 'INFISICAL_CONFIG_ARCHIVE_LAYOUT_REQUIRES_REVIEW')
        destination.mkdir(mode=0o700)
        for name, original in accepted[0].items():
            target = destination / name
            with tar.extractfile(files[original]) as source, target.open('xb') as output:
                for block in iter(lambda: source.read(1024*1024), b''):
                    output.write(block)
            target.chmod(0o600)


def validate_raw_compose(raw):
    import yaml
    try:
        doc = yaml.safe_load(raw)
    except Exception:
        raise Refused('INFISICAL_COMPOSE_INVALID') from None
    require(isinstance(doc, dict) and set(doc.get('services', {})) == SERVICES,
            'INFISICAL_SERVICE_SET_REQUIRES_REVIEW')
    require(not any(key in doc for key in ('include', 'configs', 'secrets')),
            'INFISICAL_EXTERNAL_CONFIG_REFUSED')
    for name, service in doc['services'].items():
        require(isinstance(service, dict) and not any(key in service for key in
                ('build', 'extends', 'configs', 'secrets', 'volumes_from', 'devices',
                 'network_mode', 'pid', 'ipc')) and not service.get('privileged'),
                'INFISICAL_EXTERNAL_CONFIG_REFUSED')
        env_files = service.get('env_file', [])
        if isinstance(env_files, str):
            env_files = [env_files]
        require(isinstance(env_files, list) and all(item in ('.env', './.env') for item in env_files),
                'INFISICAL_EXTRA_ENV_FILE_REFUSED')
        # Compose evaluates env files before the resolved model is checked.
        # Reject host bind sources here so no private host file is consulted.
        mounts = service.get('volumes', [])
        require(isinstance(mounts, list), 'INFISICAL_BIND_MOUNT_REQUIRES_REVIEW')
        for mount in mounts:
            source = mount.split(':')[0] if isinstance(mount, str) else mount.get('source', '')
            require(isinstance(source, str) and IDENTIFIER.fullmatch(source)
                    and (isinstance(mount, str) or mount.get('type') == 'volume'),
                    'INFISICAL_BIND_MOUNT_REQUIRES_REVIEW')
    return doc


def checked_model(model, deployment):
    """A private resolved Compose model may contain secrets; never return it to UI."""
    require(isinstance(model, dict) and set(model.get('services', {})) == SERVICES,
            'INFISICAL_SERVICE_SET_REQUIRES_REVIEW')
    require(not model.get('configs') and not model.get('secrets'), 'INFISICAL_EXTERNAL_CONFIG_REFUSED')
    for network in model.get('networks', {}).values():
        require(not network.get('external') and network.get('driver', 'bridge') == 'bridge'
                and not network.get('driver_opts'), 'INFISICAL_EXTERNAL_NETWORK_REFUSED')
    volumes = model.get('volumes', {})
    require(all(not volume.get('external') and volume.get('driver', 'local') == 'local'
                and not volume.get('driver_opts') for volume in volumes.values()),
            'INFISICAL_EXTERNAL_VOLUME_REFUSED')
    for name, service in model['services'].items():
        require(not any(key in service for key in ('build', 'extends', 'configs', 'secrets',
                'devices', 'volumes_from', 'network_mode', 'pid', 'ipc'))
                and not service.get('privileged'), 'INFISICAL_EXTERNAL_CONFIG_REFUSED')
        mounts = service.get('volumes', [])
        require(all(isinstance(mount, dict) and mount.get('type') == 'volume'
                    and mount.get('source') in volumes for mount in mounts),
                'INFISICAL_BIND_MOUNT_REQUIRES_REVIEW')
        require(not any(mount.get('target') == '/var/run/docker.sock' for mount in mounts),
                'INFISICAL_EXTERNAL_CONFIG_REFUSED')
        require(name not in ('db','redis') or not service.get('ports'),
                'INFISICAL_DATABASE_PORT_EXPOSURE_REFUSED')
    db = model['services']['db']
    require(len(db.get('volumes', [])) == 1
            and db['volumes'][0].get('target') == '/var/lib/postgresql/data',
            'INFISICAL_POSTGRES_VOLUME_REQUIRES_REVIEW')
    original_user = db.get('environment', {}).get('POSTGRES_USER')
    require(original_user == deployment['database_user'], 'INFISICAL_DATABASE_USER_MISMATCH')
    backend_env = model['services']['backend'].get('environment', {})
    require(all(isinstance(backend_env.get(key), str) and backend_env[key]
                for key in ('ENCRYPTION_KEY', 'AUTH_SECRET', 'DB_CONNECTION_URI', 'REDIS_URL')),
            'INFISICAL_APPLICATION_KEYS_MISSING')
    from urllib.parse import unquote, urlsplit
    try:
        db_uri = urlsplit(backend_env['DB_CONNECTION_URI'])
        uri_valid = db_uri.scheme in ('postgres', 'postgresql') and db_uri.hostname in (
            'db', db.get('container_name')) and unquote(db_uri.username or '') == deployment['database_user']
        uri_valid = uri_valid and unquote(db_uri.path.lstrip('/')) == deployment['database']
    except Exception:
        uri_valid = False
    require(uri_valid, 'INFISICAL_DATABASE_URI_MISMATCH')
    result = copy.deepcopy(model)
    result['name'] = 'infisical'
    for name, service in result['services'].items():
        service['image'] = deployment['images'][name]
        service['platform'] = 'linux/amd64'
    return result


def api_port(model):
    ports = model['services']['backend'].get('ports', [])
    candidates = [item for item in ports if item.get('target') == 8080
                  and item.get('protocol', 'tcp') == 'tcp'
                  and item.get('host_ip', '0.0.0.0') in ('0.0.0.0', '127.0.0.1')]
    require(len(candidates) == 1 and str(candidates[0].get('published', '')).isdigit(),
            'INFISICAL_API_PORT_REQUIRES_REVIEW')
    port = int(candidates[0]['published'])
    require(1 <= port <= 65535, 'INFISICAL_API_PORT_REQUIRES_REVIEW')
    return port


class InfisicalRecovery(Recovery):
    def __init__(self, args):
        self.deployment = profile()
        require(Path(args.target).absolute() == Path('/opt/infisical'),
                'INFISICAL_RESTORE_TARGET_REQUIRED')
        super().__init__(args)
        self.compose_path = self.root / 'recovery-compose.json'
        self.initial_path = self.root / 'recovery-bootstrap-compose.json'
        if not self.state.get('postgres_bootstrap_user'):
            self.state['postgres_bootstrap_user'] = 'recovery_' + secrets.token_hex(12)
            self.state['deployment_profile_sha256'] = digest(PROFILE_PATH)
            self.state['deployment_profile_canonical_sha256'] = deployment_fingerprint(self.deployment)
            save(self.state_path, self.state)
        validate_profile_checkpoint(self.state, self.state_path, self.deployment)

    def clones(self):
        from recover import PRIVATE, SHA
        command(['git', 'clone', '--quiet', f'https://github.com/{PRIVATE}.git', self.manager],
                'PRIVATE_CLONE_FAILED')
        self.state['manager_commit'] = command(['git', '-C', self.manager, 'rev-parse', 'HEAD'],
                                               'MANAGER_COMMIT_REQUIRED').decode().strip()
        require(bool(SHA.fullmatch(self.state['manager_commit'])), 'INVALID_MANAGER_COMMIT')

    def configuration(self):
        extracted = Path(tempfile.mkdtemp(prefix='infisical-config-', dir=self.home)) / 'files'
        unpack_config(private_file(self.private / 'infisical-config.tar.gz'), extracted)
        validate_raw_compose((extracted / 'docker-compose.prod.yml').read_bytes())
        resolved = command(['docker', 'compose', '--project-directory', extracted, '--env-file',
                            extracted / '.env', '-f', extracted / 'docker-compose.prod.yml',
                            'config', '--format', 'json'], 'INFISICAL_COMPOSE_INVALID')
        model = checked_model(json.loads(resolved), self.deployment)
        port = api_port(model)
        bootstrap = copy.deepcopy(model)
        bootstrap['services']['db']['environment'].update(
            POSTGRES_USER=self.state['postgres_bootstrap_user'], POSTGRES_DB='postgres')
        # Never restore files outside a brand new reviewed target directory.
        require(not self.root.exists(), 'EXISTING_INFISICAL_CONFIG_REFUSED')
        self.root.mkdir(mode=0o700)
        for name in CONFIG_NAMES:
            with (self.root / name).open('xb') as output:
                output.write((extracted / name).read_bytes())
            (self.root / name).chmod(0o600)
        save(self.compose_path, model)
        save(self.initial_path, bootstrap)
        self.state['api_port'] = port
        self.state['installed_config_hashes'] = {
            name: digest(self.root / name) for name in (*CONFIG_NAMES, self.compose_path.name, self.initial_path.name)}

    def compose(self, args, *, bootstrap=False, input=None):
        path = self.initial_path if bootstrap else self.compose_path
        return command(['docker', 'compose', '--project-directory', self.root,
                        '-f', path, *args], 'INFISICAL_RESTORE_COMMAND_FAILED',
                       cwd=self.root, input=input, timeout=1800)

    def runtime(self):
        model = json.loads(private_file(self.compose_path).read_bytes())
        ids = command(['docker','ps','-aq'], 'DOCKER_ACCESS_REQUIRED').split()
        containers = json.loads(command(['docker','inspect', *[i.decode() for i in ids]],
                                        'DOCKER_ACCESS_REQUIRED')) if ids else []
        names = command(['docker','volume','ls','-q'], 'DOCKER_ACCESS_REQUIRED').split()
        volumes = json.loads(command(['docker','volume','inspect', *[n.decode() for n in names]],
                                    'DOCKER_ACCESS_REQUIRED')) if names else []
        try:
            validate_runtime(model, self.root, containers, volumes)
        except ValueError:
            raise Refused('INFISICAL_FOREIGN_RUNTIME_REFUSED') from None

    def database(self):
        self.runtime()
        self.compose(['pull'])
        # Validate the custom dump before creating any persistent cluster.
        image = self.deployment['images']['db']
        listing = command(['docker', 'run', '--rm', '--network', 'none', '-i',
                           '--entrypoint', 'pg_restore', image, '--list'],
                          'INFISICAL_DUMP_NOT_COMPATIBLE',
                          input=private_file(self.private / 'infisical-postgres.dump').read_bytes())
        header = listing.decode('utf-8', 'replace').splitlines()[:30]
        require(any(re.fullmatch(r';\s+dbname:\s*'+re.escape(self.deployment['database'])+r'\s*', line)
                    for line in header), 'INFISICAL_DUMP_DATABASE_MISMATCH')
        require(any(re.match(r';\s+Dumped from database version: 14(?:\.|\s)', line)
                    for line in header), 'INFISICAL_POSTGRES_MAJOR_MISMATCH')
        self.compose(['up','-d','--no-deps','db'], bootstrap=True)
        bootstrap = self.state['postgres_bootstrap_user']
        for attempt in range(60):
            try:
                # The official image briefly runs a socket-only server while
                # initializing, then stops it. Wait for the final server before
                # writing roles/database; SELECT 1 also succeeds on that first
                # temporary server. Query locally, without publishing a port.
                ready = self.compose(['exec','-T','db','psql','-X','-U',bootstrap,
                                      '-d','postgres','-At','-c',
                                      "SELECT current_setting('listen_addresses') <> ''"], bootstrap=True)
                if ready.strip() == b't':
                    break
            except Refused:
                pass
            time.sleep(1)
        else:
            raise Refused('INFISICAL_POSTGRES_NOT_READY')
        globals_sql = private_file(self.private / 'infisical-postgres-globals.sql').read_bytes()
        require(not re.search(rb'\bCREATE\s+TABLESPACE\b', globals_sql, re.I),
                'INFISICAL_TABLESPACE_REQUIRES_REVIEW')
        # Fresh cluster uses a distinct bootstrap superuser, so the source roles
        # can be restored with ON_ERROR_STOP instead of ignoring existing roles.
        self.compose(['exec','-T','db','psql','-X','-v','ON_ERROR_STOP=1','--single-transaction',
                      '-U',bootstrap,'-d','postgres'], bootstrap=True, input=globals_sql)
        db, user = self.deployment['database'], self.deployment['database_user']
        self.compose(['exec','-T','db','createdb','-U',bootstrap,'-O',user,db], bootstrap=True)
        self.compose(['exec','-T','db','pg_restore','--exit-on-error','--single-transaction',
                      '-U',bootstrap,'--dbname',db], bootstrap=True,
                     input=private_file(self.private / 'infisical-postgres.dump').read_bytes())
        # Check role/database access without exposing user or secret data.
        check = self.compose(['exec','-T','db','psql','-X','-U',user,'-d',db,'-At','-c',
                              'SELECT count(*) > 0 FROM information_schema.tables WHERE table_schema=\'public\''],
                             bootstrap=True)
        require(check.strip() == b't', 'INFISICAL_RESTORED_SCHEMA_EMPTY')
        self.compose(['exec','-T','db','psql','-X','-v','ON_ERROR_STOP=1','-U',user,
                      '-d',db,'-c','ALTER ROLE "'+bootstrap+'" NOLOGIN'], bootstrap=True)

    def start_server(self):
        self.runtime()
        self.compose(['up','-d','--no-deps','--wait','--wait-timeout','300','db','redis'])
        self.compose(['up','-d','--no-deps','backend'])
        # The API is checked locally. Secrets later travel to the replacement
        # stack through desktop-managed SSH forwarding, never a plaintext LAN hop.
        import urllib.request
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        port = self.state['api_port']
        for attempt in range(90):
            try:
                with opener.open('http://127.0.0.1:'+str(port)+'/api/status', timeout=5) as response:
                    body = response.read(65537)
                    if response.status == 200 and len(body) <= 65536:
                        break
            except Exception:
                pass
            time.sleep(2)
        else:
            raise Refused('INFISICAL_RESTORED_API_NOT_READY')
        self.state['server_restore'] = 'PASS_NEEDS_SECRET_READ_TEST'
        save(self.state_path, self.state)

    def validate_server_resume(self):
        if 'CLONES' in self.state['completed']:
            require(command(['git','-C',self.manager,'rev-parse','HEAD'], 'RECOVERY_COMMIT_CHECK_FAILED')
                    .decode().strip() == self.state['manager_commit'], 'RECOVERY_COMMIT_CHANGED')
            require(not command(['git','-C',self.manager,'status','--porcelain'], 'RECOVERY_DIFF_FAILED'),
                    'RECOVERY_TREE_MODIFIED')
        if 'DOWNLOAD' in self.state['completed']:
            require(self.config['dr_tag'] == self.state['tag'], 'RECOVERY_TAG_CHANGED')
            validate_bundle(self.manager, self.bundle, self.state['tag'])
        if 'DECRYPT' in self.state['completed']:
            require(all(digest(private_file(self.private / name)) == sha
                        for name, sha in self.state['private_hashes'].items()), 'PRIVATE_MATERIAL_CHANGED')
        if 'INFISICAL_CONFIG' in self.state['completed']:
            require(all(digest(private_file(self.root / name)) == sha
                    for name, sha in self.state['installed_config_hashes'].items()),
                    'INFISICAL_CONFIG_CHANGED')
            self.runtime()

    def prepare(self):
        # All database/config phases are write-ahead checkpointed. Partial SQL
        # or interrupted writes are preserved and never retried blindly.
        self.auth()
        self.validate_server_resume()
        self.step('CLONES', self.clones)
        self.step('DOWNLOAD', self.download)
        self.step('DECRYPT', self.decrypt)
        self.step('INFISICAL_CONFIG', self.configuration)
        self.step('INFISICAL_DATABASE', self.database)
        if 'INFISICAL_SERVER' in self.state['completed']:
            self.start_server()
            event('INFISICAL_SERVER')
        else:
            self.step('INFISICAL_SERVER', self.start_server)


def main():
    import argparse
    import fcntl
    import pwd
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--state-home', required=True)
    parser.add_argument('--config-stdin', required=True, action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    require(os.geteuid() == 0, 'ROOT_RECOVERY_INSTALLER_REQUIRED')
    user = os.environ.get('STREAMS_RECOVERY_USER','')
    require(pwd.getpwnam(user).pw_uid == 1000 and pwd.getpwnam(user).pw_gid == 1000,
            'DEPLOYMENT_UID_GID_REQUIRED')
    raw = sys.stdin.buffer.read(1024**2+1)
    require(len(raw) <= 1024**2, 'RECOVERY_REQUEST_TOO_LARGE')
    args.config_data = json.loads(raw)
    home = safe_path(Path(args.state_home))
    with (home/'recovery.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        InfisicalRecovery(args).prepare()


if __name__ == '__main__':
    import sys
    try:
        main()
    except Exception as error:
        code = str(error) if isinstance(error,Refused) else 'INFISICAL_RESTORE_FAILED'
        event('REFUSED','REFUSED',code)
        sys.exit(1)

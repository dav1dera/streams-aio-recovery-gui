#!/usr/bin/env python3
"""Desktop-driven preparation on a fresh Ubuntu VM.

Completion means PREPARED, not verified application recovery. Infisical must
already be reachable. See README.md for the remaining recovery steps.
"""
import argparse
import contextlib
import datetime
import hashlib
import importlib.util
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import tarfile
from urllib.parse import urlsplit

PUBLIC = 'dav1dera/streams-aio-sanitized'
PRIVATE = 'dav1dera/streams-aio-dr'
ASSETS = {
    'npm-database.sqlite.age': 'database.sqlite',
    'infisical-agent-infisical-agent.tar.gz.age': 'infisical-agent.tar.gz',
    'infisical-config.tar.gz.age': 'infisical-config.tar.gz',
    'infisical-postgres.dump.age': 'infisical-postgres.dump',
    'infisical-postgres-globals.sql.age': 'infisical-postgres-globals.sql',
}
BUNDLE_FILES = set(ASSETS) | {'manifest.json', 'SHA256SUMS'}
CODE = re.compile(r'[A-Z][A-Z0-9_]*\Z')
SHA = re.compile(r'[0-9a-f]{40}\Z')
KEY = re.compile(r'[A-Z][A-Z0-9_]*\Z')
RUNNER_VERSION = '0.2.0'
GITHUB_TOKEN = None
EVENTS = {'CLONES', 'DOWNLOAD', 'DECRYPT', 'INITIALIZE', 'INPUTS', 'RENDER',
          'EMPTY_STATE', 'NPM', 'AIO', 'PREFLIGHT', 'PREPARED', 'STARTED', 'REFUSED',
          'INFISICAL_CONFIG', 'INFISICAL_DATABASE', 'INFISICAL_SERVER', 'NATIVE_AGENT'}


def event(stage, status='PASS', code=None):
    require(stage in EVENTS and status in ('RUNNING', 'PASS', 'REFUSED'), 'INVALID_EVENT')
    data = dict(stage=stage, status=status)
    if code:
        require(CODE.fullmatch(code), 'INVALID_ERROR_CODE')
        data['code'] = code
    print('RECOVERY_EVENT ' + json.dumps(data), flush=True)


class Refused(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Refused(code)


def safe_path(path):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'SYMLINK_PATH_REFUSED')
    return path


def private_file(path, outside=()):
    path = safe_path(Path(path).expanduser())
    require(path.is_file() and stat.S_ISREG(path.stat().st_mode), 'PRIVATE_INPUT_FILE_REQUIRED')
    require(path.stat().st_mode & 0o077 == 0, 'PRIVATE_INPUT_REQUIRES_MODE_600')
    require(all(not path.is_relative_to(p) for p in outside), 'PRIVATE_INPUT_MUST_BE_OUTSIDE_CLONES')
    return path


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def save(path, obj):
    safe_path(path)
    fd, name = tempfile.mkstemp(prefix='.checkpoint-', dir=path.parent)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(name, path)


def command(args, code, cwd=None, interactive=False, timeout=1800, input=None):
    # Capture all child output except the required sudo/browser login exchange.
    # No decrypted data, SDK exceptions, Docker configuration or stderr is echoed.
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(('COMPOSE_', 'INFISICAL_', 'PYTHON'))
           and k not in ('GH_TOKEN', 'GITHUB_TOKEN')}
    env.update(PYTHONDONTWRITEBYTECODE='1', GIT_TERMINAL_PROMPT='0', GH_PROMPT_DISABLED='1')
    if GITHUB_TOKEN and str(args[0]) in ('git', 'gh'):
        env['GH_TOKEN'] = GITHUB_TOKEN
    if str(args[0]) in ('git', 'gh') and os.geteuid() == 0:
        args = ['sudo', '-H', '-u', os.environ['STREAMS_RECOVERY_USER'],
                '--preserve-env=GH_TOKEN,GIT_TERMINAL_PROMPT,GH_PROMPT_DISABLED,PYTHONDONTWRITEBYTECODE', '--', *args]
    try:
        result = subprocess.run([str(x) for x in args], cwd=cwd, env=env,
                                capture_output=not interactive, timeout=timeout, input=input)
    except (OSError, subprocess.TimeoutExpired):
        raise Refused(code) from None
    require(result.returncode == 0, code)
    return b'' if interactive else result.stdout


def valid_tag(tag):
    require(bool(re.fullmatch(r'dr-[0-9]{8}T[0-9]{6}Z', tag)), 'INVALID_DR_TAG')
    try:
        datetime.datetime.strptime(tag[3:], '%Y%m%dT%H%M%SZ')
    except ValueError:
        raise Refused('INVALID_DR_TAG') from None
    return tag


def validate_release(meta, tag):
    require(meta.get('tag_name') == tag and meta.get('draft') is False, 'PUBLISHED_RELEASE_REQUIRED')
    assets = meta.get('assets')
    require(isinstance(assets, list) and len(assets) == len(BUNDLE_FILES)
            and {a.get('name') for a in assets} == BUNDLE_FILES, 'UNEXPECTED_RELEASE_ASSETS')
    require(all(a.get('state') == 'uploaded' and isinstance(a.get('size'), int)
                and 0 < a['size'] < 10 * 1024**3 for a in assets), 'INCOMPLETE_RELEASE_ASSET')


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_bundle(manager, directory, tag):
    module = load_module(manager / 'scripts/dr-releases.py', 'recovery_release_manager')
    # This is the same fail-closed SHA256/envelope/inventory check as publication.
    try:
        module.bundle_check(directory)
    except Exception:
        raise Refused('DR_BUNDLE_VERIFICATION_FAILED') from None
    data = json.loads((directory / 'manifest.json').read_bytes())
    require('dr-' + data['run'] == tag, 'DR_TAG_MANIFEST_MISMATCH')
    return data


def validate_address(address, ssh_bridge=False):
    u = urlsplit(address)
    loopback = (ssh_bridge is True and u.scheme == 'http' and u.hostname == '127.0.0.1'
                and u.port is not None and 1 <= u.port <= 65535)
    require(((u.scheme == 'https' and bool(u.hostname)) or loopback) and u.username is None
            and u.password is None and not u.query and not u.fragment
            and u.path in ('', '/'), 'HTTPS_INFISICAL_ORIGIN_REQUIRED')
    return address.rstrip('/')


def response_values(response):
    # Imported values are not guessed/merged: SDK import precedence can differ
    # from the recovered Agent. Refuse ambiguous imports before writing anything.
    require(not response.imports, 'INFISICAL_IMPORTS_REQUIRE_MAPPING_REVIEW')
    result = {}
    for secret in response.secrets:
        key, value = secret.secretKey, secret.secretValue
        require(isinstance(key, str) and bool(KEY.fullmatch(key)), 'INVALID_INFISICAL_KEY')
        require(isinstance(value, str) and not secret.secretValueHidden
                and value != '<hidden-by-infisical>', 'INFISICAL_VALUE_UNAVAILABLE')
        require(key not in result, 'DUPLICATE_INFISICAL_KEY')
        require('\0' not in value, 'INFISICAL_NUL_REFUSED')
        result[key] = value
    return result


def collect_inputs(plan, dr, client, project, environment):
    snapshots, values = {}, {}
    for folder in dr.all_paths(plan):
        response = client.secrets.list_secrets(
            project_id=project, environment_slug=environment, secret_path=folder,
            recursive=False, expand_secret_references=True,
            view_secret_value=True, include_imports=True)
        entries = response_values(response)
        snapshots[dr.folder_file(folder)] = ''.join(k + '=' + repr(v) + '\n'
                                                  for k, v in sorted(entries.items())).encode()
        values.update({folder + '/' + k: v for k, v in entries.items()})
    require(all(ref in values for ref in plan['required_values']), 'REQUIRED_INFISICAL_KEY_MISSING')
    return snapshots


def write_inputs(destination, snapshots):
    require(not destination.exists(), 'EXISTING_INPUT_SNAPSHOTS_REFUSED')
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='inputs-', dir=destination.parent))
    for name, data in snapshots.items():
        require(re.fullmatch(r'[a-zA-Z0-9_-]+\.goenv', name), 'UNSAFE_INPUT_FILENAME')
        path = stage / name
        with path.open('xb') as f:
            f.write(data)
        path.chmod(0o600)
    os.rename(stage, destination)


def decrypt_all(identity, bundle, destination, run=command):
    require(not destination.exists(), 'EXISTING_DECRYPTED_MATERIAL_REFUSED')
    stage = Path(tempfile.mkdtemp(prefix='decryption-', dir=destination.parent))
    for asset, name in ASSETS.items():
        run(['age', '--decrypt', '--identity', identity, '--output', stage / name,
             bundle / asset], 'AGE_DECRYPTION_FAILED')
        private_file(stage / name)
    # A failure leaves staging untouched and never installs a partially decrypted set.
    os.rename(stage, destination)


def unpack_agent(archive, destination):
    require(not destination.exists(), 'EXISTING_AGENT_ARCHIVE_REFUSED')
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        require(len(members) <= 2000 and sum(m.size for m in members) <= 64 * 1024**2,
                'AGENT_ARCHIVE_TOO_LARGE')
        names = set()
        for member in members:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts
                    and '\\' not in member.name and ':' not in member.name
                    and (member.isdir() or member.isfile()), 'UNSAFE_AGENT_ARCHIVE')
            require(path.as_posix() not in names, 'DUPLICATE_AGENT_ARCHIVE_ENTRY')
            names.add(path.as_posix())
        destination.mkdir(mode=0o700)
        # Manual regular-file extraction; never restore ownership, links or hooks.
        for member in members:
            path = destination / member.name
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with tar.extractfile(member) as source, path.open('xb') as target:
                    for block in iter(lambda: source.read(1024 * 1024), b''):
                        target.write(block)
                path.chmod(0o600)


def agent_bootstrap(directory):
    import yaml
    candidates = []
    for path in directory.rglob('*'):
        if path.is_file() and path.name in ('agent-config.yaml', 'agent-config.yml', 'agent-config.json'):
            obj = yaml.safe_load(path.read_bytes())
            if isinstance(obj, dict) and obj.get('auth', {}).get('type') == 'universal-auth':
                candidates.append(obj)
    require(len(candidates) == 1, 'AGENT_BOOTSTRAP_CONFIG_NOT_UNIQUE')
    obj = candidates[0]
    credentials = []
    for key in ('client-id', 'client-secret'):
        original = obj['auth']['config'].get(key)
        require(isinstance(original, str) and original.startswith('/')
                and '..' not in PurePosixPath(original).parts, 'AGENT_CREDENTIAL_PATH_UNSUPPORTED')
        # Exact recovered path only; do not search by basename or copy from /etc.
        credentials.append(private_file(directory / original.lstrip('/')))
    scopes = set()
    for row in obj.get('templates', []):
        content = row.get('template-content')
        if content is None and row.get('source-path'):
            original = PurePosixPath(row['source-path'])
            require(original.is_absolute() and '..' not in original.parts, 'AGENT_TEMPLATE_PATH_UNSUPPORTED')
            content = private_file(directory / str(original).lstrip('/')).read_text()
        for match in re.finditer(r'\b(?:secret|listSecrets)\s+"([A-Za-z0-9_-]+)"\s+"([A-Za-z0-9_-]+)"', content or ''):
            scopes.add(match.groups())
    require(len(scopes) == 1, 'AGENT_PROJECT_SCOPE_NOT_UNIQUE')
    project, environment = scopes.pop()
    address = obj.get('infisical', {}).get('address')
    require(isinstance(address, str), 'AGENT_ENDPOINT_MISSING')
    return dict(address=address, project=project, environment=environment,
                client_id=credentials[0], client_secret=credentials[1])


def logical_payload(registry, streams, metadata):
    result = dict(schema=1, aiostreams=[], aiometadata=[])
    for service, paths in (('aiostreams', streams), ('aiometadata', metadata)):
        profiles = registry.get(service)
        require(isinstance(profiles, dict) and bool(profiles), 'AIO_PROFILE_REGISTRY_REQUIRED')
        used = set()
        for path in paths:
            export = json.loads(private_file(path).read_bytes())
            require(isinstance(export, dict), 'AIO_EXPORT_OBJECT_REQUIRED')
            if service == 'aiostreams':
                export = export.get('UserData', export)
                require(isinstance(export, dict) and bool(export), 'AIO_USERDATA_REQUIRED')
                config = export
            else:
                require(export.get('version') == '3.3.0' and isinstance(export.get('metadata'), dict)
                        and isinstance(export.get('config'), dict), 'AIO_METADATA_VERSION_UNSUPPORTED')
                config = export['config']
            uid = config.get('uuid')
            matches = [name for name, identity in profiles.items() if uid and identity.get('uuid') == uid]
            if not uid and len(profiles) == 1:
                matches = list(profiles)
            require(len(matches) == 1 and matches[0] not in used, 'AIO_EXPORT_PROFILE_AMBIGUOUS')
            profile = matches[0]
            used.add(profile)
            entry = dict(profile=profile, version={'aiostreams': '2.35.3', 'aiometadata': '3.3.0'}[service],
                         export=export, bindings=[], dependencies=[], reauthorize=[])
            if service == 'aiostreams':
                entry['linked_accounts'] = 'reauthorize'
            result[service].append(entry)
        require(used == set(profiles), 'AIO_EXPORT_PROFILE_SET_INCOMPLETE')
    return result


class Recovery:
    def __init__(self, args):
        self.args = args
        self.config = args.config_data
        self.root = safe_path(Path(args.target).expanduser())
        self.home = safe_path(Path(args.state_home).expanduser())
        self.tooling = Path(__file__).resolve().parent
        require(not self.home.is_relative_to(self.root) and not self.root.is_relative_to(self.home),
                'RECOVERY_STORAGE_MUST_BE_SEPARATE')
        self.home.mkdir(parents=True, mode=0o700, exist_ok=True)
        require(self.home.stat().st_uid == 1000 and self.home.stat().st_mode & 0o077 == 0,
                'PRIVATE_RECOVERY_DIRECTORY_REQUIRED')
        self.state_path = self.home / 'state.json'
        machine = Path('/etc/machine-id').read_text().strip()
        tooling_sha = self.config['public_commit']
        require(bool(SHA.fullmatch(tooling_sha)), 'INVALID_TOOLING_COMMIT')
        if self.state_path.exists():
            private_file(self.state_path)
            self.state = json.loads(self.state_path.read_text())
            require(self.state.get('machine_id') == machine and self.state.get('target') == str(self.root)
                    and self.state.get('tooling_commit') == tooling_sha
                    and self.state.get('runner_version') == RUNNER_VERSION, 'FOREIGN_RECOVERY_STATE')
            pending = self.state.get('in_progress')
            # These stages have no installed outputs until they succeed. Keep
            # failed staging directories, but allow corrected credentials/files.
            retryable = {'DOWNLOAD': not (self.home / 'ciphertext').exists(),
                         'DECRYPT': not (self.home / 'private').exists(),
                         'INPUTS': not (self.root / '.secrets/dr-inputs').exists(),
                         'AIO': not any((self.root / f'data/{s}/data/db.sqlite').exists()
                                        for s in ('aiostreams', 'aiometadata'))
                                and not (self.root / '.generated/aio-import-complete.json').exists(),
                         'INFISICAL_SERVER': self.config.get('role') == 'infisical'
                                and 'INFISICAL_DATABASE' in self.state['completed']}
            require(not pending or retryable.get(pending, False), 'INCOMPLETE_STEP_REQUIRES_REVIEW')
            self.state['in_progress'] = None
        else:
            require(not self.root.exists(), 'EXISTING_STACK_REFUSED')
            self.state = dict(schema=1, machine_id=machine, target=str(self.root),
                              tooling_commit=tooling_sha, runner_version=RUNNER_VERSION,
                              completed=[], in_progress=None)
            save(self.state_path, self.state)
        self.manager = self.home / 'manager'
        self.bundle = self.home / 'ciphertext'
        self.private = self.home / 'private'

    def step(self, name, action):
        if name in self.state['completed']:
            event(name)
            return
        event(name, 'RUNNING')
        self.state['in_progress'] = name
        save(self.state_path, self.state)
        action()
        self.state['completed'].append(name)
        self.state['in_progress'] = None
        save(self.state_path, self.state)
        event(name)

    def auth(self):
        global GITHUB_TOKEN
        token = self.config.get('github_token')
        require(isinstance(token, str) and bool(token.strip()) and '\n' not in token and '\r' not in token,
                'GITHUB_TOKEN_REQUIRED')
        GITHUB_TOKEN = token.strip()
        command(['gh', 'auth', 'setup-git', '--hostname', 'github.com'], 'GITHUB_GIT_AUTH_FAILED')
        info = json.loads(command(['gh', 'api', '--hostname', 'github.com', f'repos/{PRIVATE}'],
                                  'PRIVATE_REPOSITORY_ACCESS_REQUIRED'))
        require(info.get('private') is True, 'PRIVATE_REPOSITORY_REQUIRED')

    def clones(self):
        commit = self.state['tooling_commit']
        require(bool(SHA.fullmatch(commit)), 'FULL_PUBLIC_COMMIT_REQUIRED')
        command(['git', 'clone', '--quiet', '--no-checkout', f'https://github.com/{PUBLIC}.git', self.root],
                'PUBLIC_CLONE_FAILED')
        command(['git', '-C', self.root, 'checkout', '--quiet', '--detach', commit], 'PUBLIC_COMMIT_UNAVAILABLE')
        command(['git', 'clone', '--quiet', f'https://github.com/{PRIVATE}.git', self.manager], 'PRIVATE_CLONE_FAILED')
        self.state['public_commit'] = commit
        self.state['manager_commit'] = command(['git', '-C', self.manager, 'rev-parse', 'HEAD'],
                                                'MANAGER_COMMIT_REQUIRED').decode().strip()
        require(bool(SHA.fullmatch(self.state['manager_commit'])), 'INVALID_MANAGER_COMMIT')

    def download(self):
        # User chooses a published point in time. Do not silently pick a draft/latest.
        tag = valid_tag(self.config['dr_tag'])
        meta = json.loads(command(['gh', 'api', '--hostname', 'github.com', f'repos/{PRIVATE}/releases/tags/{tag}'],
                                  'DR_RELEASE_METADATA_UNAVAILABLE'))
        validate_release(meta, tag)
        require(not self.bundle.exists(), 'EXISTING_BUNDLE_REFUSED')
        stage = Path(tempfile.mkdtemp(prefix='download-', dir=self.home))
        command(['gh', 'release', 'download', tag, '--repo', PRIVATE, '--dir', stage], 'DR_DOWNLOAD_FAILED')
        validate_bundle(self.manager, stage, tag)
        require(all((stage / a['name']).stat().st_size == a['size'] for a in meta['assets']),
                'DOWNLOADED_ASSET_SIZE_MISMATCH')
        os.rename(stage, self.bundle)
        self.state['tag'] = tag

    def decrypt(self):
        identity = private_file(self.config['age_identity'],
                                (self.root, self.manager, self.tooling))
        decrypt_all(identity, self.bundle, self.private)
        self.state['private_hashes'] = {name: digest(self.private / name) for name in ASSETS.values()}

    def initialize(self):
        self.run_script('dr.py', 'init')

    def inputs(self):
        from infisical_sdk import InfisicalSDKClient
        if self.config.get('client_id_file') and self.config.get('client_secret_file'):
            recovered = dict(address=self.config.get('infisical_address'), project=self.config.get('project_id'),
                             environment=self.config.get('environment', 'prod'),
                             client_id=self.config['client_id_file'], client_secret=self.config['client_secret_file'])
        else:
            directory = Path(tempfile.mkdtemp(prefix='agent-backup-', dir=self.home)) / 'files'
            unpack_agent(self.private / 'infisical-agent.tar.gz', directory)
            recovered = agent_bootstrap(directory)
        address = validate_address(self.config.get('infisical_address') or recovered['address'],
                                   ssh_bridge=self.config.get('ssh_bridge') is True)
        project = self.config.get('project_id') or recovered['project']
        environment = self.config.get('environment') or recovered['environment']
        require(re.fullmatch(r'[A-Za-z0-9_-]+', project) and re.fullmatch(r'[A-Za-z0-9_-]+', environment),
                'INVALID_INFISICAL_SCOPE')
        excluded = (self.root, self.manager, self.tooling)
        client_id = private_file(recovered['client_id'], excluded)
        client_secret = private_file(recovered['client_secret'], excluded)
        # Nothing is logged, including API errors. Authentication posts only to the
        # explicit HTTPS origin; subsequent SDK operations read existing secrets.
        logging.disable(logging.CRITICAL)
        client = InfisicalSDKClient(host=address, cache_ttl=None)
        if self.config.get('ssh_bridge') is True:
            client.api.session.trust_env = False
        original_request = client.api.session.request
        def bounded_request(method, url, **kwargs):
            expected, actual = urlsplit(address), urlsplit(url)
            require((actual.scheme, actual.hostname, actual.port) ==
                    (expected.scheme, expected.hostname, expected.port), 'INFISICAL_API_ORIGIN_CHANGED')
            kwargs.update(timeout=(10, 30), allow_redirects=False)
            return original_request(method, url, **kwargs)
        client.api.session.request = bounded_request
        dr = load_module(self.root / 'scripts/dr.py', 'fresh_renderer')
        plan = json.loads((self.root / 'config/dr-render-plan.json').read_bytes())
        try:
            client.auth.universal_auth.login(client_id=client_id.read_text().strip(),
                                            client_secret=client_secret.read_text().strip())
            snapshots = collect_inputs(plan, dr, client, project, environment)
        except Refused:
            raise
        except Exception:
            raise Refused('INFISICAL_SNAPSHOT_FAILED') from None
        finally:
            client.close()
        write_inputs(self.root / '.secrets/dr-inputs', snapshots)

    def run_script(self, name, action, *extra, root=False):
        args = [sys.executable, '-B', self.root / 'scripts' / name, action, '--target', self.root, *extra]
        if root and os.geteuid() != 0:
            args = ['sudo', '--', *args]
        command(args, {'dr.py': 'FRESH_RENDERER_REFUSED', 'npm-dr.py': 'NPM_RECOVERY_REFUSED',
                       'aio-dr.py': 'AIO_IMPORT_REFUSED'}[name], cwd=self.root)

    def npm(self):
        target = self.root / 'data/npm/data/database.sqlite'
        require(not target.exists() and not target.is_symlink(), 'EXISTING_NPM_DATABASE_REFUSED')
        command(['sudo', 'install', '-m', '600', '-o', '1000', '-g', '1000',
                 self.private / 'database.sqlite', target], 'NPM_DATABASE_INSTALL_FAILED')
        self.run_script('npm-dr.py', 'prepare', root=True)

    def aio(self):
        if self.config.get('aio_payload'):
            path = private_file(self.config['aio_payload'], (self.root, self.manager, self.tooling))
        else:
            dr = load_module(self.root / 'scripts/dr.py', 'aio_input_renderer')
            plan = json.loads((self.root / 'config/dr-render-plan.json').read_bytes())
            values = dr.read_values(self.root, plan, None)
            registry = json.loads(values['/dr/AIO_PROFILE_BINDINGS'])
            # Resolve the same {ref} nodes as the existing importer, without guessing IDs.
            sys.path.insert(0, str(self.root / 'scripts'))
            importer = load_module(self.root / 'scripts/aio-dr.py', 'aio_payload_adapter')
            registry = importer.resolve(registry, values)
            payload = logical_payload(registry, self.config.get('aiostreams_exports', []),
                                      self.config.get('aiometadata_exports', []))
            path = self.home / 'logical-aio-payload.json'
            if path.exists():
                require(json.loads(private_file(path).read_bytes()) == payload, 'EXISTING_AIO_PAYLOAD_REFUSED')
            save(path, payload)
        self.run_script('aio-dr.py', 'validate', '--payload', path)
        self.run_script('aio-dr.py', 'import', '--payload', path, root=True)

    def validate_resume(self):
        if 'CLONES' in self.state['completed']:
            for folder, field in ((self.root, 'public_commit'), (self.manager, 'manager_commit')):
                require(command(['git', '-C', folder, 'rev-parse', 'HEAD'], 'RECOVERY_COMMIT_CHECK_FAILED')
                        .decode().strip() == self.state[field], 'RECOVERY_COMMIT_CHANGED')
                changed = set(command(['git', '-C', folder, 'diff', '--name-only', 'HEAD'],
                                      'RECOVERY_DIFF_FAILED').decode().splitlines())
                allowed = set()
                if folder == self.root and 'RENDER' in self.state['completed']:
                    marker = json.loads((self.root / '.generated/dr-render-complete.json').read_bytes())
                    require(marker.get('root') == str(self.root), 'INVALID_RENDER_MARKER')
                    allowed = set(marker['outputs'])
                require(changed <= allowed and not command(['git', '-C', folder, 'ls-files', '--others', '--exclude-standard'],
                                                          'RECOVERY_UNTRACKED_CHECK_FAILED'), 'RECOVERY_TREE_MODIFIED')
        if 'DOWNLOAD' in self.state['completed']:
            require(self.config['dr_tag'] == self.state['tag'], 'RECOVERY_TAG_CHANGED')
            validate_bundle(self.manager, self.bundle, self.state['tag'])
        if 'DECRYPT' in self.state['completed']:
            require(all(digest(private_file(self.private / name)) == sha
                        for name, sha in self.state['private_hashes'].items()), 'PRIVATE_MATERIAL_CHANGED')

    def prepare(self):
        require(not command(['docker', 'ps', '-aq'], 'DOCKER_ACCESS_REQUIRED').strip()
                and not command(['docker', 'volume', 'ls', '-q'], 'DOCKER_ACCESS_REQUIRED').strip(),
                'FRESH_DOCKER_HOST_REQUIRED')
        self.auth()
        self.validate_resume()
        self.step('CLONES', self.clones)
        self.step('DOWNLOAD', self.download)
        self.step('DECRYPT', self.decrypt)
        self.step('INITIALIZE', self.initialize)
        self.step('INPUTS', self.inputs)
        self.step('RENDER', lambda: self.run_script('dr.py', 'render', '--mode', 'fresh', root=True))
        self.step('EMPTY_STATE', lambda: self.run_script('dr.py', 'prepare-state', root=True))
        self.step('NPM', self.npm)
        self.step('AIO', self.aio)
        # Always repeat real checks. A checkpoint alone never means ready.
        self.run_script('dr.py', 'preflight', '--mode', 'fresh', root=True)
        command(['docker', 'compose', '--profile', 'all', 'config', '--quiet'], 'COMPOSE_VALIDATION_FAILED', cwd=self.root)
        self.state['preparation'] = 'PASS'
        self.state['application_recovery'] = 'NOT_VERIFIED'
        self.state['timers_installed'] = False
        save(self.state_path, self.state)
        event('PREPARED')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', default=str(Path.home() / 'streams-aio'))
    p.add_argument('--state-home', default=str(Path.home() / '.local/share/streams-aio-recovery'))
    p.add_argument('--config-stdin', action='store_true', required=True)
    args = p.parse_args()
    os.umask(0o077)
    require(sys.platform == 'linux' and os.getuid() == 0, 'ROOT_RECOVERY_INSTALLER_REQUIRED')
    import pwd
    user = os.environ.get('STREAMS_RECOVERY_USER', '')
    require(bool(re.fullmatch(r'[a-z_][a-z0-9_-]*', user)) and pwd.getpwnam(user).pw_uid == 1000
            and pwd.getpwnam(user).pw_gid == 1000, 'DEPLOYMENT_UID_GID_REQUIRED')
    request = sys.stdin.buffer.read(1024**2 + 1)
    require(len(request) <= 1024**2, 'RECOVERY_REQUEST_TOO_LARGE')
    args.config_data = json.loads(request)
    require(isinstance(args.config_data, dict), 'RECOVERY_REQUEST_REQUIRED')
    # Token stays in memory, including during dependency installation. Uploaded
    # identities/backups remain private for recovery; no request file is created.
    import fcntl
    home = safe_path(Path(args.state_home).expanduser())
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = safe_path(home / 'recovery.lock')
    with lock.open('a') as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused('RECOVERY_ALREADY_RUNNING') from None
        command(['sudo', '-n', 'true'], 'SUDO_REQUIRED')
        Recovery(args).prepare()


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        event('REFUSED', 'REFUSED', 'INTERRUPTED')
        sys.exit(1)
    except Exception as error:
        # Never echo paths/values, API response bodies, subprocess output or tracebacks.
        code = str(error) if isinstance(error, Refused) and CODE.fullmatch(str(error)) else 'OPERATION_STOPPED'
        event('REFUSED', 'REFUSED', code)
        sys.exit(1)

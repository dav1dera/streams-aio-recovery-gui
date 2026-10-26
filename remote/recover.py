#!/usr/bin/env python3
"""Desktop-driven preparation on a fresh Ubuntu VM.

Completion means PREPARED, not verified application recovery. Infisical must
already be reachable. See README.md for the remaining recovery steps.
"""
import argparse
import contextlib
import copy
import datetime
import hashlib
import importlib.util
import io
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
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
AIO_ASSET = 'aio-state.tar.gz.age'
AIO_PLAINTEXT = 'aio-state.tar.gz'
SERVICES_ASSET = 'services-state.tar.gz.age'
SERVICES_PLAINTEXT = 'services-state.tar.gz'


def bundle_files(names):
    """Only the original bundle or its native AIO extension are accepted."""
    names = set(names)
    require(names in (BUNDLE_FILES, BUNDLE_FILES | {AIO_ASSET}, BUNDLE_FILES | {AIO_ASSET, SERVICES_ASSET}), 'UNEXPECTED_RELEASE_ASSETS')
    return names


def encrypted_assets(bundle):
    names = bundle_files(path.name for path in Path(bundle).iterdir())
    return dict(ASSETS, **({AIO_ASSET: AIO_PLAINTEXT} if AIO_ASSET in names else {}),
                **({SERVICES_ASSET: SERVICES_PLAINTEXT} if SERVICES_ASSET in names else {}))
CODE = re.compile(r'[A-Z][A-Z0-9_]*\Z')
SHA = re.compile(r'[0-9a-f]{40}\Z')
KEY = re.compile(r'[A-Z][A-Z0-9_]*\Z')
RUNNER_VERSION = '0.2.0'
GITHUB_TOKEN = None
FIRST_BOOT_PULL_CODES = (
    'RUNTIME_PROFILE_POSTGRES_PULL_FAILED', 'RUNTIME_PROFILE_DNS_PULL_FAILED',
    'RUNTIME_PROFILE_OAUTH_PULL_FAILED', 'RUNTIME_PROFILE_PGBOUNCER_PULL_FAILED',
)
FIRST_BOOT_COMMAND_CODES = frozenset(FIRST_BOOT_PULL_CODES) | {
    'RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED', 'RUNTIME_PROFILE_IMAGE_CACHE_INVALID',
    'RUNTIME_PROFILE_IMAGE_INSPECT_FAILED', 'RUNTIME_PROFILE_IMAGE_SAVE_FAILED',
    'RUNTIME_PROFILE_COMPOSE_CONFIG_FAILED', 'RUNTIME_PROFILE_COMPOSE_CONFIG_INVALID',
    'RUNTIME_PROFILE_COMPOSE_VERSION_FAILED', 'RUNTIME_PROFILE_GIT_READ_FAILED',
    'RUNTIME_PROFILE_DOCKER_RESOURCE_CHECK_FAILED', 'RUNTIME_PROFILE_COMMAND_FAILED',
}
FIRST_BOOT_CACHE_FORMAT = ('{"Id":{{json .Id}},"Os":{{json .Os}},'
                           '"Architecture":{{json .Architecture}},"RepoDigests":{{json .RepoDigests}}}')
PINNED_IMAGE = re.compile(r'[a-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}\Z')
AIO_BINDINGS_REF = '/dr/AIO_PROFILE_BINDINGS'
OAUTH_ALLOWLIST_REF = '/oauth2-proxy/ALLOWED_EMAILS'
EVENTS = {'CLONES', 'DOWNLOAD', 'DECRYPT', 'INITIALIZE', 'INPUTS', 'RENDER',
          'EMPTY_STATE', 'NPM', 'AIO', 'PREFLIGHT', 'PREPARED', 'STARTED', 'REFUSED',
          'INFISICAL_CONFIG', 'INFISICAL_DATABASE', 'INFISICAL_SERVER', 'NATIVE_AGENT', 'RUNTIME_PROFILE',
          'NPM_TOPOLOGY', 'SERVICES'}


def event(stage, status='PASS', code=None):
    require(stage in EVENTS and (status in ('RUNNING', 'PASS', 'REFUSED')
            or stage == 'AIO' and status == 'SKIPPED'), 'INVALID_EVENT')
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
    if (result.returncode != 0 and not interactive
            and code == 'RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED'
            and [str(x) for x in args[:3]] == ['docker', 'image', 'inspect']
            and len(args) == 6 and args[3:5] == ['--format', FIRST_BOOT_CACHE_FORMAT]
            and PINNED_IMAGE.fullmatch(str(args[-1]))):
        # A cache miss is different from an inaccessible daemon. Accept only
        # Docker's exact missing-object diagnostic for the requested public pin;
        # all other stderr stays private and refuses before any pull.
        reference = str(args[-1]).encode('ascii')
        missing = (b'Error response from daemon: No such image: ' + reference,
                   b'Error: No such image: ' + reference)
        if (result.stderr or b'').strip() in missing and not (result.stdout or b'').strip():
            return None
    if result.returncode != 0 and str(args[0]) == 'age' and code == 'AGE_DECRYPTION_FAILED':
        # Map only known age diagnostics to a fixed code. Never expose stderr,
        # which may contain paths, private inputs or arbitrary child output.
        if any(marker in (result.stderr or b'') for marker in
               (b'no identity matched any of the recipients',
                b'identity did not match any of the recipients')):
            raise Refused('AGE_NO_MATCHING_RECIPIENT') from None
    require(result.returncode == 0, code)
    return b'' if interactive else result.stdout


def first_boot_command_code(args):
    """Classify the policy's fixed command shapes without exposing arguments."""
    args = [str(x) for x in args]
    if args[:2] == ['docker', 'compose']:
        if args[2:3] == ['version']:
            return 'RUNTIME_PROFILE_COMPOSE_VERSION_FAILED'
        if 'config' in args[2:]:
            return 'RUNTIME_PROFILE_COMPOSE_CONFIG_FAILED'
    if args[:3] == ['docker', 'image', 'inspect']:
        return 'RUNTIME_PROFILE_IMAGE_INSPECT_FAILED'
    if args[:3] == ['docker', 'image', 'save']:
        return 'RUNTIME_PROFILE_IMAGE_SAVE_FAILED'
    if (args[:2] in (['docker', 'ps'], ['docker', 'inspect'])
            or args[:3] in (['docker', 'volume', 'ls'], ['docker', 'volume', 'inspect'])):
        return 'RUNTIME_PROFILE_DOCKER_RESOURCE_CHECK_FAILED'
    if args[:1] == ['git'] or args[:7] == ['sudo', '-H', '-u', 'test', '--', 'git', '-C']:
        return 'RUNTIME_PROFILE_GIT_READ_FAILED'
    return 'RUNTIME_PROFILE_COMMAND_FAILED'


def first_boot_repository(reference):
    """Normalize only Docker Hub spelling aliases, preserving the exact digest."""
    repository, digest_value = reference.split('@', 1)
    if repository.rfind(':') > repository.rfind('/'):
        repository = repository.rsplit(':', 1)[0]
    for prefix in ('docker.io/', 'index.docker.io/', 'registry-1.docker.io/'):
        if repository.startswith(prefix):
            repository = repository[len(prefix):]
            break
    if '/' not in repository:
        repository = 'library/' + repository
    return repository + '@' + digest_value


def first_boot_cached_image(reference, root):
    raw = command(['docker', 'image', 'inspect', '--format', FIRST_BOOT_CACHE_FORMAT, reference],
                  'RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED', cwd=root, timeout=60)
    if raw is None:
        return False
    try:
        info = json.loads(raw)
        require(isinstance(info, dict) and set(info) == {'Id', 'Os', 'Architecture', 'RepoDigests'}
                and isinstance(info['Id'], str) and re.fullmatch(r'sha256:[0-9a-f]{64}', info['Id'])
                and info['Os'] == 'linux' and info['Architecture'] == 'amd64'
                and isinstance(info['RepoDigests'], list) and 0 < len(info['RepoDigests']) <= 32
                and all(isinstance(item, str) and PINNED_IMAGE.fullmatch(item)
                        for item in info['RepoDigests'])
                and first_boot_repository(reference) in {
                    first_boot_repository(item) for item in info['RepoDigests']},
                'RUNTIME_PROFILE_IMAGE_CACHE_INVALID')
    except (ValueError, TypeError, UnicodeError):
        raise Refused('RUNTIME_PROFILE_IMAGE_CACHE_INVALID') from None
    return True


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
    require(isinstance(assets, list) and all(isinstance(a, dict) for a in assets), 'UNEXPECTED_RELEASE_ASSETS')
    names = bundle_files(a.get('name') for a in assets)
    require(len(assets) == len(names), 'UNEXPECTED_RELEASE_ASSETS')
    require(all(a.get('state') == 'uploaded' and isinstance(a.get('size'), int)
                and 0 < a['size'] < 10 * 1024**3 for a in assets), 'INCOMPLETE_RELEASE_ASSET')


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise
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


def input_plan(plan, aio_mode='import'):
    """Manual AIO defers its identity registry, never a stack security input.

    This is an in-memory view of the pinned public plan. The checked-out plan,
    its templates and the renderer's ownership/integrity checks stay intact.
    """
    require(aio_mode in ('import', 'manual', 'snapshot'), 'INVALID_AIO_RECOVERY_MODE')
    if aio_mode == 'import':
        return plan
    effective = copy.deepcopy(plan)
    required = effective['required_values']
    require(isinstance(required, list) and all(isinstance(ref, str) for ref in required),
            'MANUAL_AIO_INPUT_CONTRACT_INVALID')
    # A future plan that uses the registry as an actual configuration binding
    # cannot be made optional merely because the application import is manual.
    def references(value):
        if isinstance(value, dict):
            return (value.get('path') == '/dr' and value.get('key') == 'AIO_PROFILE_BINDINGS'
                    or any(references(v) for v in value.values()))
        if isinstance(value, list):
            return any(references(v) for v in value)
        return isinstance(value, str) and (value == AIO_BINDINGS_REF
                or '@@INFISICAL:' + AIO_BINDINGS_REF + '@@' in value)
    require(not references({key: value for key, value in effective.items()
            if key not in ('required_values', 'additional_input_folders', 'private_dr_bindings_ref')}),
            'MANUAL_AIO_INPUT_CONTRACT_INVALID')
    effective['required_values'] = [ref for ref in required if ref != AIO_BINDINGS_REF]
    effective['additional_input_folders'] = [folder for folder in effective.get('additional_input_folders', [])
                                           if folder != '/dr']
    return effective


def configure_renderer(dr, aio_mode):
    """Use the same private-input contract at collection and fresh rendering."""
    context = dr.context
    def checked_context(args, marked=True):
        root, plan = context(args, marked)
        return root, input_plan(plan, aio_mode)
    dr.context = checked_context
    return dr


def validate_allowlist(value):
    # Match the pinned renderer's explicit-email contract. Never widen access
    # to an email domain or use identities from another application as a list.
    require(isinstance(value, str) and len(value.encode('utf-8')) <= 65536
            and '\0' not in value and '\r' not in value, 'OAUTH_ALLOWLIST_INVALID')
    entries = [line.strip() for line in value.splitlines()
               if line.strip() and not line.lstrip().startswith('#')]
    require(entries and len(entries) == len(set(entries)) and all(
            re.fullmatch(r"[A-Za-z0-9.!#$%&'+/=?^_`{|}~-]+@[A-Za-z0-9.-]+", line)
            and '*' not in line for line in entries), 'OAUTH_ALLOWLIST_INVALID')
    return value


def read_supplemental_inputs(identity, ciphertext, home, tag, commit, outside=(), run=command):
    """Read the reviewed encrypted companion made by complete-missing-dr-inputs.

    Its age envelope authenticates the supplied data. Bind the tag/commit
    inside that envelope before accepting only request.allowed_emails. The AIO
    payload and every other field are retained in the original encrypted file
    and never imported by this fallback.
    """
    ciphertext = private_file(ciphertext, outside)
    identity = private_file(identity, outside)
    require(ciphertext.stat().st_size <= 64 * 1024**2, 'RECOVERY_SUPPLEMENT_INVALID')
    source_sha256 = digest(ciphertext)
    with identity.open('rb') as source:
        canonical = canonical_age_identity(source.read(65537))
    with tempfile.TemporaryDirectory(prefix='supplement-', dir=home) as directory:
        directory = Path(directory)
        key_path, output = directory / 'identity.txt', directory / 'inputs.json'
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as target:
            target.write(canonical)
        run(['age-keygen', '-y', key_path], 'AGE_IDENTITY_INVALID')
        run(['age', '--decrypt', '--identity', key_path, '--output', output, ciphertext],
            'AGE_DECRYPTION_FAILED')
        output = private_file(output)
        require(output.stat().st_size <= 64 * 1024**2, 'RECOVERY_SUPPLEMENT_INVALID')
        try:
            data = json.loads(output.read_bytes())
        except (ValueError, UnicodeError):
            raise Refused('RECOVERY_SUPPLEMENT_INVALID') from None
    require(isinstance(data, dict) and set(data) == {'schema', 'tag', 'commit', 'request', 'payload'}
            and type(data['schema']) is int and data['schema'] == 1
            and isinstance(data['request'], dict) and isinstance(data['payload'], dict),
            'RECOVERY_SUPPLEMENT_INVALID')
    require(data['tag'] == valid_tag(tag) and data['commit'] == commit
            and isinstance(commit, str) and bool(SHA.fullmatch(commit)),
            'RECOVERY_SUPPLEMENT_SCOPE_CHANGED')
    require(digest(private_file(ciphertext, outside)) == source_sha256,
            'RECOVERY_SUPPLEMENT_INVALID')
    value = validate_allowlist(data['request'].get('allowed_emails'))
    return {OAUTH_ALLOWLIST_REF: value}, dict(schema=1, tag=tag, commit=commit,
            ciphertext_sha256=source_sha256)


def archived_local_inputs(directory, plan):
    """Optional ordinary configuration from the encrypted Agent archive."""
    module = load_module(Path(__file__).with_name('local_config.py'), 'recovery_local_inputs')
    try:
        return module.load_local_config(directory, plan['required_values'])
    except module.ConfigRefused as error:
        raise Refused(str(error)) from None


def collect_inputs(plan, dr, client, project, environment, *, aio_mode='import', supplemental=None,
                   applied=None, local_values=None):
    plan = input_plan(plan, aio_mode)
    supplemental = {} if supplemental is None else supplemental
    require(isinstance(supplemental, dict) and set(supplemental) <= {OAUTH_ALLOWLIST_REF},
            'RECOVERY_SUPPLEMENT_INVALID')
    for value in supplemental.values():
        validate_allowlist(value)
    local_values = {} if local_values is None else local_values
    local_module, local_folders = None, set()
    if local_values:
        local_module = load_module(Path(__file__).with_name('local_config.py'), 'recovery_local_merge')
        try:
            local_values = local_module.validate_document(
                {'schema': 1, 'values': local_values}, plan['required_values'])
            local_folders = local_module.local_only_folders(plan, local_values, plan['required_values'])
        except local_module.ConfigRefused as error:
            raise Refused(str(error)) from None
    else:
        require(isinstance(local_values, dict), 'LOCAL_CONFIG_INVALID')
    snapshots, values = {}, {}
    for folder in dr.all_paths(plan):
        # Entirely local folders may have been removed from Infisical. Dynamic
        # AIO folders always retain the normal API read, including new secrets.
        if folder in local_folders:
            entries = {}
        else:
            response = client.secrets.list_secrets(
                project_id=project, environment_slug=environment, secret_path=folder,
                recursive=False, expand_secret_references=True,
                view_secret_value=True, include_imports=True)
            entries = response_values(response)
        if local_module is not None:
            try:
                entries = local_module.merge_folder_values(
                    folder, entries, local_values, plan['required_values'])
            except local_module.ConfigRefused as error:
                raise Refused(str(error)) from None
        if folder == '/oauth2-proxy' and 'ALLOWED_EMAILS' not in entries and OAUTH_ALLOWLIST_REF in supplemental:
            entries['ALLOWED_EMAILS'] = supplemental[OAUTH_ALLOWLIST_REF]
            if applied is not None:
                applied.add(OAUTH_ALLOWLIST_REF)
        snapshots[dr.folder_file(folder)] = ''.join(k + '=' + repr(v) + '\n'
                                                  for k, v in sorted(entries.items())).encode()
        values.update({folder + '/' + k: v for k, v in entries.items()})
    if OAUTH_ALLOWLIST_REF in plan['required_values'] and OAUTH_ALLOWLIST_REF not in values:
        raise Refused('OAUTH_ALLOWLIST_SUPPLEMENT_REQUIRED')
    require(all(ref in values for ref in plan['required_values']), 'REQUIRED_INFISICAL_KEY_MISSING')
    validate_database_mappings(plan, dr, values)
    return snapshots


def validate_database_mappings(plan, dr, values):
    """CometNet must use a database/role actually provisioned by the SQL plan.

    Compare decoded role, password and database privately, allowing a pooler
    host instead of the database host. Never invent another database mapping or
    replace the recovered application's connection string.
    """
    binding = plan.get('env_files', {}).get('.secrets/cometnet.env', {}).get('DATABASE_URL')
    if binding is None:
        return
    try:
        ref = binding['path'] + '/' + binding['key']
        target = dr.postgres_connection(values[ref], 'comet')
        provisioned = {dr.postgres_connection(values[row['ref']], row['service'])
                       for row in plan['postgres_bootstrap']['connections']}
    except Exception:
        raise Refused('COMETNET_DATABASE_NOT_PROVISIONED') from None
    require(target in provisioned, 'COMETNET_DATABASE_NOT_PROVISIONED')


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


def canonical_age_identity(raw):
    """Decode a Windows text file without guessing or generating key material."""
    require(isinstance(raw, bytes) and len(raw) <= 65536, 'AGE_IDENTITY_FILE_INVALID')
    try:
        if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
            text = raw.decode('utf-16')
        else:
            text = raw.decode('utf-8-sig')
    except UnicodeError:
        raise Refused('AGE_IDENTITY_ENCODING_INVALID') from None
    lines = [line.strip() for line in text.splitlines()
             if line.strip() and not line.lstrip().startswith('#')]
    require(bool(lines) and len(lines) <= 16, 'AGE_PRIVATE_IDENTITY_REQUIRED')
    require(not any(line.startswith('age1') for line in lines), 'AGE_PUBLIC_KEY_NOT_IDENTITY')
    # Only native X25519 identities match the existing backup contract. Reject
    # plugins, SSH keys and passphrase files before invoking an external tool.
    require(all(re.fullmatch(r'AGE-SECRET-KEY-1[A-Z0-9]+', line) for line in lines),
            'AGE_PRIVATE_IDENTITY_REQUIRED')
    return ('\n'.join(lines) + '\n').encode('ascii')


def decrypt_all(identity, bundle, destination, run=command):
    require(not destination.exists(), 'EXISTING_DECRYPTED_MATERIAL_REFUSED')
    with Path(identity).open('rb') as source:
        canonical = canonical_age_identity(source.read(65537))
    # The original transferred file is preserved. The canonical copy exists
    # only inside a fresh 0700 directory, is 0600, and never joins the bundle.
    with tempfile.TemporaryDirectory(prefix='age-identity-', dir=destination.parent) as key_dir:
        key_path = Path(key_dir) / 'identity.txt'
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as target:
            target.write(canonical)
        run(['age-keygen', '-y', key_path], 'AGE_IDENTITY_INVALID')
        stage = Path(tempfile.mkdtemp(prefix='decryption-', dir=destination.parent))
        for asset, name in encrypted_assets(bundle).items():
            run(['age', '--decrypt', '--identity', key_path, '--output', stage / name,
                 bundle / asset], 'AGE_DECRYPTION_FAILED')
            private_file(stage / name)
        # A failure leaves staging untouched and never installs a partial set.
        os.rename(stage, destination)


def unpack_agent(archive, destination):
    destination = safe_path(destination)
    require(not destination.exists(), 'EXISTING_AGENT_ARCHIVE_REFUSED')
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        require(len(members) <= 2000 and sum(m.size for m in members) <= 64 * 1024**2,
                'AGENT_ARCHIVE_TOO_LARGE')
        names = {}
        entries = []
        for member in members:
            path = PurePosixPath(member.name)
            require('..' not in path.parts
                    and '\\' not in member.name and ':' not in member.name
                    and (member.isdir() or member.isfile()), 'UNSAFE_AGENT_ARCHIVE')
            if path.is_absolute():
                # The producer archives these Linux paths with tar -P. Rebase
                # the known Agent layout into private staging, never onto /etc.
                require(path.anchor == '/', 'UNSAFE_AGENT_ARCHIVE')
                path = path.relative_to('/')
                roots = (PurePosixPath('etc/infisical'), PurePosixPath('etc/infisical-agent'))
                require(any(path.is_relative_to(root) for root in roots)
                        or path == PurePosixPath('etc/systemd/system/infisical-agent.service')
                        or path.is_relative_to(PurePosixPath('etc/systemd/system/infisical-agent.service.d'))
                        or (member.isdir() and path.as_posix() in ('etc', 'etc/systemd', 'etc/systemd/system')),
                        'UNSAFE_AGENT_ARCHIVE')
            require(bool(path.parts) and path.as_posix() != '.', 'UNSAFE_AGENT_ARCHIVE')
            require(path.as_posix() not in names, 'DUPLICATE_AGENT_ARCHIVE_ENTRY')
            names[path.as_posix()] = member.isdir()
            entries.append((member, path))
        # Validate the complete tree before creating any private output.
        require(all(names.get(parent.as_posix(), True) for _, path in entries for parent in path.parents),
                'UNSAFE_AGENT_ARCHIVE')
        destination.mkdir(mode=0o700)
        # Manual regular-file extraction; never restore ownership, links or hooks.
        for member, relative in entries:
            path = destination / relative.as_posix()
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


def public_configuration_mode_matches(target, declared_mode):
    """Allow only a widened POSIX ACL mask on an explicit public config file.

    With an extended ACL, stat's group bits represent ACL_MASK, not GROUP_OBJ.
    The local public-file access watcher may widen that mask after installation;
    the reviewed portable mode and the file's content hash remain unchanged.
    """
    if type(declared_mode) is not int or not 0 <= declared_mode <= 0o777:
        return False
    observed = target.stat()
    current = stat.S_IMODE(observed.st_mode)
    if not stat.S_ISREG(observed.st_mode):
        return False
    if current == declared_mode:
        return True
    if current & ~0o070 != declared_mode & ~0o070:
        return False
    group, declared_group = (current >> 3) & 7, (declared_mode >> 3) & 7
    if group & declared_group != declared_group:
        return False
    try:
        raw = os.getxattr(target, 'system.posix_acl_access', follow_symlinks=False)
    except (AttributeError, OSError, TypeError):
        return False
    if (not isinstance(raw, bytes) or len(raw) < 4 or len(raw) > 65536
            or (len(raw) - 4) % 8 or struct.unpack_from('<I', raw)[0] != 2):
        return False
    basic, named = {}, set()
    for tag, permissions, qualifier in struct.iter_unpack('<HHI', raw[4:]):
        if permissions & ~7 or tag not in {1, 2, 4, 8, 16, 32}:
            return False
        if tag in {2, 8}:
            identity = tag, qualifier
            if qualifier == 0xffffffff or identity in named:
                return False
            named.add(identity)
        else:
            if qualifier != 0xffffffff or tag in basic:
                return False
            basic[tag] = permissions
    return (bool(named) and set(basic) == {1, 4, 16, 32}
            and basic[1] == (current >> 6) & 7
            and basic[4] & group & declared_group == declared_group
            and basic[16] == group and basic[32] == current & 7)



def verify_service_snapshot(root, state):
    """Return verified resource IDs and owners; a checkpoint never proves data."""
    root = safe_path(root)
    inventory_path = safe_path(root / 'config/service-resources.json')
    archive = safe_path(root.parent / '.local/share/streams-aio-recovery/private' / SERVICES_PLAINTEXT)
    evidence = state.get('services_snapshot')
    if not inventory_path.exists():
        require(evidence is None and not archive.exists(), 'SERVICES_STATE_INVENTORY_REQUIRED')
        return {}
    module = load_module(Path(__file__).with_name('service_snapshot.py'), 'generic_services_verifier')
    try:
        value = module.inventory(root)
        files = value.get('configuration_files', [])
        require(isinstance(files, list), 'SERVICES_STATE_CONFIGURATION_INVALID')
        for item in files:
            require(isinstance(item, dict) and set(item) == {'path', 'mode', 'sha256'}
                    and isinstance(item['path'], str)
                    and re.fullmatch(r'data/[a-z0-9][a-z0-9_-]*/public/.+', item['path'])
                    and '..' not in PurePosixPath(item['path']).parts and '\\' not in item['path']
                    and not any(ord(char) < 32 or ord(char) == 127 for char in item['path'])
                    and type(item['mode']) is int and 0 <= item['mode'] <= 0o777
                    and isinstance(item['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', item['sha256']),
                    'SERVICES_STATE_CONFIGURATION_INVALID')
            target = safe_path(root / item['path'])
            require(target.is_file() and digest(target) == item['sha256']
                    and (os.name == 'nt' or public_configuration_mode_matches(target, item['mode'])),
                    'SERVICES_STATE_CONFIGURATION_CHANGED')
        selected = module.selected(value)
        if not selected:
            require(evidence is None and not archive.exists(), 'SERVICES_STATE_UNEXPECTED_ARCHIVE')
            return {}
        require(isinstance(evidence, dict) and set(evidence) == {
                    'schema', 'run', 'stack_commit', 'inventory_sha256', 'archive_sha256', 'resources'},
                'SERVICES_STATE_CHECKPOINT_REQUIRED')
        require(state.get('target') == str(root) and isinstance(state.get('tag'), str)
                and re.fullmatch(r'dr-[0-9]{8}T[0-9]{6}Z', state['tag'])
                and isinstance(state.get('public_commit'), str) and SHA.fullmatch(state['public_commit'])
                and evidence.get('run') == state['tag'][3:]
                and evidence.get('stack_commit') == state['public_commit'], 'SERVICES_STATE_SCOPE_MISMATCH')
        require(type(evidence.get('schema')) is int and evidence['schema'] == 1
                and evidence.get('inventory_sha256') == digest(inventory_path)
                and evidence.get('resources') == sorted(item['id'] for item in selected),
                'SERVICES_STATE_CHECKPOINT_CHANGED')
        require(archive.is_file(), 'SERVICES_STATE_BACKUP_REQUIRED')
        if os.name != 'nt':
            private_file(archive, (root,))
        require(evidence.get('archive_sha256') == digest(archive), 'SERVICES_STATE_CHECKPOINT_CHANGED')
        model = json.loads(command(['docker', 'compose', '--profile', 'all', 'config', '--format', 'json'],
                                   'COMPOSE_VALIDATION_FAILED', cwd=root))
        require(type(state.get('application_start_attempted', False)) is bool, 'SERVICES_STATE_CHECKPOINT_CHANGED')
        module.verify_restored(root, archive, evidence, model,
            before_start=not state.get('application_start_attempted', False),
            runner=lambda args, code: command(args, code, cwd=root))
    except module.Refused as error:
        raise Refused(str(error)) from None
    return {item['id']: item['service'] for item in selected}


def stack_preflight(root, state):
    """Run the pinned renderer, accepting only independently verified state."""
    if state.get('runtime_profile') is not None:
        policy = load_module(Path(__file__).with_name('runtime_profile.py'), 'recovery_runtime_policy')
        policy.validate(root, root.parent/'.local/share/streams-aio-recovery', state)
    service_resources = verify_service_snapshot(root, state)
    snapshot = state.get('aio_mode') == 'snapshot'
    manual = state.get('aio_recovery') == 'MANUAL_PENDING'
    if snapshot:
        verify_aio_snapshot(root, state)
    if not manual and not snapshot and not service_resources:
        command([sys.executable, '-B', root / 'scripts/dr.py', 'preflight',
                 '--target', root, '--mode', 'fresh'], 'FRESH_RENDERER_REFUSED', cwd=root)
        return
    if manual or snapshot:
        require(state.get('aio_mode') in ('manual', 'snapshot') and state.get('target') == str(root)
                and state.get('machine_id') == Path('/etc/machine-id').read_text().strip()
                and 'NPM' in state.get('completed', []) and 'AIO' in state.get('completed', []),
                'MANUAL_AIO_CHECKPOINT_REQUIRED')
        require(not safe_path(root / '.generated/aio-import-complete.json').exists(),
                'MANUAL_AIO_IMPORT_CONFLICT')
    dr = load_module(root / 'scripts/dr.py', 'verified_state_preflight')
    manifest = json.loads(safe_path(root / 'config/dr-manifest.yaml').read_bytes())
    units = manifest.get('state_units')
    require(isinstance(units, list) and all(isinstance(unit, dict) and isinstance(unit.get('id'), str)
            for unit in units) and len({unit['id'] for unit in units}) == len(units), 'FRESH_RENDERER_REFUSED')
    allowed = {'aio PRIVATE_DR_PAYLOAD_IMPORT_REQUIRED'} if manual or snapshot else set()
    for unit in units:
        services = unit.get('services', [])
        identifier = unit.get('resource_id')
        if (identifier in service_resources and unit.get('id') == 'service-' + identifier
                and unit.get('recovery_asset') == SERVICES_ASSET
                and unit.get('classification') == 'REQUIRED_USER_STATE'
                and services == [service_resources[identifier]]):
            allowed.add(','.join(services) + ' ' + unit['id']
                        + ':REQUIRED_USER_CONFIGURATION_NOT_RECONSTRUCTED')
        # A mixed AIO/legacy unit must still pass its ordinary check.
        if (manual and not snapshot and not unit.get('resource_id') and not unit['id'].startswith('service-')
                and unit.get('recovery_asset') != SERVICES_ASSET
                and services and set(services) <= {'aiostreams', 'aiometadata'} and unit.get('classification') in (
                'REQUIRED_IDENTITY_STATE', 'REQUIRED_USER_STATE')):
            allowed.add(','.join(services) + ' ' + unit['id']
                        + ':REQUIRED_USER_CONFIGURATION_NOT_RECONSTRUCTED')
    captured = io.StringIO()
    args = argparse.Namespace(target=str(root), mode='fresh', synthetic=False)
    try:
        with contextlib.redirect_stdout(captured):
            dr.preflight(args)
    except dr.Refused as error:
        failures = captured.getvalue().splitlines()
        require(str(error) == 'DR_PREFLIGHT_BLOCKED' and bool(failures)
                and all(line in allowed for line in failures), 'FRESH_RENDERER_REFUSED')
    else:
        if manual or snapshot:
            # Native/manual AIO still requires the pinned missing-import check.
            raise Refused('MANUAL_AIO_IMPORT_CONFLICT')


def verify_aio_snapshot(root, state):
    """Native evidence replaces only the obsolete logical-import marker."""
    require(state.get('aio_recovery') == 'NATIVE_SNAPSHOT_RESTORED'
            and isinstance(state.get('aio_snapshot'), dict), 'AIO_SNAPSHOT_MARKER_INVALID')
    evidence = state['aio_snapshot']
    require(evidence.get('run') == state.get('tag', '')[3:]
            and evidence.get('source_commit') == state.get('public_commit'), 'AIO_SNAPSHOT_SCOPE_MISMATCH')
    model = json.loads(command(['docker', 'compose', '--profile', 'all', 'config', '--format', 'json'],
                               'COMPOSE_VALIDATION_FAILED', cwd=root))
    snapshot = load_module(Path(__file__).with_name('aio_snapshot.py'), 'native_aio_verifier')
    try:
        snapshot.verify_restored(root, evidence, model,
                                 before_start=not state.get('application_start_attempted', False))
    except snapshot.Refused as error:
        raise Refused(str(error)) from None


def upstream_targets(value):
    import ipaddress
    require(isinstance(value,dict) and set(value) == {'stack','infisical'}, 'NPM_TOPOLOGY_TARGET_INVALID')
    for address in value.values():
        try:
            parsed = ipaddress.ip_address(address)
        except (ValueError,TypeError):
            raise Refused('NPM_TOPOLOGY_TARGET_INVALID') from None
        require(isinstance(address,str) and str(parsed) == address and not parsed.is_unspecified
                and not parsed.is_loopback and not parsed.is_multicast, 'NPM_TOPOLOGY_TARGET_INVALID')
    require(value['stack'] != value['infisical'], 'NPM_TOPOLOGY_TARGET_INVALID')
    return dict(value)


def render_base_snapshot(root):
    """Private evidence of the completed pinned renderer, never marker-only."""
    root = safe_path(root)
    try:
        plan_path, compose_path = root/'config/dr-render-plan.json',root/'docker-compose.yml'
        plan = json.loads(safe_path(plan_path).read_bytes())
        marker_path = private_file(root/'.generated/dr-render-complete.json')
        marker = json.loads(marker_path.read_bytes())
        expected = (set(plan['env_files']) | set(plan.get('service_folder_exports',{})) | {'.env'}
                    | {row['destination'] for row in plan['files']} | {plan['postgres_bootstrap']['destination']})
        require(isinstance(marker,dict) and marker.get('root') == str(root)
                and isinstance(marker.get('outputs'),list)
                and all(isinstance(name,str) for name in marker['outputs'])
                and len(marker['outputs']) == len(set(marker['outputs']))
                and set(marker['outputs']) == expected, 'AGENT_RENDER_BASE_INVALID')
        outputs = {}
        for name in sorted(expected):
            relative = PurePosixPath(name)
            require(relative.as_posix() == name and not relative.is_absolute() and '..' not in relative.parts
                    and re.fullmatch(r'[A-Za-z0-9_./-]+',name), 'AGENT_RENDER_BASE_INVALID')
            path = safe_path(root/name)
            info = path.stat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'AGENT_RENDER_BASE_INVALID')
            outputs[name] = dict(sha256=digest(path),uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode))
        return dict(schema=1,root=str(root),plan_sha256=digest(safe_path(plan_path)),
                    compose_sha256=digest(safe_path(compose_path)),marker_sha256=digest(marker_path),outputs=outputs)
    except (ValueError,TypeError,KeyError,OSError):
        raise Refused('AGENT_RENDER_BASE_INVALID') from None


class Recovery:
    def __init__(self, args):
        self.args = args
        self.config = args.config_data
        if 'onboarding_lab' in self.config:
            require(type(self.config['onboarding_lab']) is bool, 'LAB_RUNTIME_SCOPE_REFUSED')
        if self.config.get('onboarding_lab') is True:
            require(self.config.get('role', 'stack') == 'stack'
                    and self.config.get('aio_mode') == 'snapshot'
                    and self.config.get('native_agent', True) is True
                    and self.config.get('operational_profile') is not True,
                    'LAB_RUNTIME_SCOPE_REFUSED')
        if self.config.get('operational_profile') is True:
            import ipaddress
            require(self.config.get('aio_mode') == 'snapshot'
                    and self.config.get('routing_mode') in ('parallel_test', 'production_recovery'),
                    'OPERATIONAL_DEPLOYMENT_REFUSED')
            try:
                address = ipaddress.ip_address(self.config.get('domain_target_address'))
            except (ValueError, TypeError):
                raise Refused('PUBLIC_DOMAIN_CONFIGURATION_REQUIRED') from None
            require(str(address) == self.config['domain_target_address'] and not address.is_unspecified
                    and not address.is_multicast, 'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')
            upstream_targets(self.config.get('npm_upstream_targets'))
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
        pending = None
        if self.state_path.exists():
            private_file(self.state_path)
            self.state = json.loads(self.state_path.read_text())
            require(self.state.get('machine_id') == machine and self.state.get('target') == str(self.root)
                    and self.state.get('tooling_commit') == tooling_sha
                    and self.state.get('runner_version') == RUNNER_VERSION, 'FOREIGN_RECOVERY_STATE')
            if self.state.get('lab_deployment') is not None:
                require(self.config.get('onboarding_lab') is True
                        and self.config.get('operational_profile') is not True,
                        'LAB_RUNTIME_SCOPE_REFUSED')
            pending = self.state.get('in_progress')
            # These stages have no installed outputs until they succeed. Keep
            # failed staging directories, but allow corrected credentials/files.
            retryable = {'DOWNLOAD': not (self.home / 'ciphertext').exists(),
                         'DECRYPT': not (self.home / 'private').exists(),
                         'INPUTS': not (self.root / '.secrets/dr-inputs').exists(),
                         'AIO': self.config.get('aio_mode') == 'snapshot' or not any((self.root / f'data/{s}/data/db.sqlite').exists()
                                        for s in ('aiostreams', 'aiometadata'))
                                and not (self.root / '.generated/aio-import-complete.json').exists(),
                         'INFISICAL_SERVER': self.config.get('role') == 'infisical'
                                and 'INFISICAL_DATABASE' in self.state['completed']}
            if pending == 'RENDER' and self.state.get('render_base') is not None:
                state_info = self.state_path.stat()
                require(state_info.st_uid == os.geteuid() and stat.S_IMODE(state_info.st_mode) == 0o600
                        and state_info.st_nlink == 1,
                        'AGENT_RENDER_BASE_INVALID')
                self.verify_render_base()
                retryable['RENDER'] = True
            require(not pending or retryable.get(pending, False), 'INCOMPLETE_STEP_REQUIRES_REVIEW')
            self.state['in_progress'] = None
        else:
            require(not self.root.exists(), 'EXISTING_STACK_REFUSED')
            self.state = dict(schema=1, machine_id=machine, target=str(self.root),
                              tooling_commit=tooling_sha, runner_version=RUNNER_VERSION,
                              completed=[], in_progress=None)
            save(self.state_path, self.state)
        if self.config.get('operational_profile') is True:
            targets = upstream_targets(self.config.get('npm_upstream_targets'))
            if self.state.get('npm_upstream_targets') is not None:
                require(self.state['npm_upstream_targets'] == targets, 'NPM_TOPOLOGY_TARGET_INVALID')
            else:
                require(not self.state.get('application_start_attempted',False) and pending is None,
                        'NPM_TOPOLOGY_EVIDENCE_REQUIRED')
                self.state['npm_upstream_targets'] = targets
                save(self.state_path,self.state)
        self.manager = self.home / 'manager'
        self.bundle = self.home / 'ciphertext'
        self.private = self.home / 'private'

    def step(self, name, action):
        if name in self.state['completed']:
            event(name, 'SKIPPED' if name == 'AIO' and self.state.get('aio_recovery') == 'MANUAL_PENDING' else 'PASS')
            return
        event(name, 'RUNNING')
        self.state['in_progress'] = name
        save(self.state_path, self.state)
        action()
        self.state['completed'].append(name)
        self.state['in_progress'] = None
        save(self.state_path, self.state)
        event(name, 'SKIPPED' if name == 'AIO' and self.state.get('aio_recovery') == 'MANUAL_PENDING' else 'PASS')

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
        try:
            stage = Path(tempfile.mkdtemp(prefix='download-', dir=self.home))
            # gh runs as the validated deployment user (UID/GID 1000), while
            # this installer runs as root. Keep mode 0700; transfer ownership
            # only on the newly created staging directory, never recursively.
            if os.geteuid() == 0:
                os.chown(stage, 1000, 1000)
        except OSError:
            raise Refused('DR_DOWNLOAD_DIRECTORY_FAILED') from None
        command(['gh', 'release', 'download', tag, '--repo', PRIVATE, '--dir', stage], 'DR_DOWNLOAD_FAILED')
        manifest = validate_bundle(self.manager, stage, tag)
        if manifest.get('schema') == 2:
            # Infisical downloads the same bundle before cloning the stack.
            # The request pin is validated in __init__ for both roles.
            require(manifest.get('stack_commit') == self.config['public_commit'], 'DR_STACK_COMMIT_MISMATCH')
        if self.config.get('aio_mode') == 'snapshot':
            require(manifest.get('schema') == 2 and AIO_ASSET in encrypted_assets(stage),
                    'AIO_SNAPSHOT_BACKUP_REQUIRED')
        require(all((stage / a['name']).stat().st_size == a['size'] for a in meta['assets']),
                'DOWNLOADED_ASSET_SIZE_MISMATCH')
        os.rename(stage, self.bundle)
        self.state['tag'] = tag

    def decrypt(self):
        identity = private_file(self.config['age_identity'],
                                (self.root, self.manager, self.tooling))
        decrypt_all(identity, self.bundle, self.private)
        self.state['private_hashes'] = {name: digest(self.private / name)
                                       for name in encrypted_assets(self.bundle).values()}

    def initialize(self):
        self.run_script('dr.py', 'init')

    def inputs(self):
        from infisical_sdk import InfisicalSDKClient
        mode = self.config.get('aio_mode', 'import')
        require(mode in ('import', 'manual', 'snapshot'), 'INVALID_AIO_RECOVERY_MODE')
        supplemental, provenance, applied = {}, None, set()
        if self.config.get('supplemental_inputs'):
            supplemental, provenance = read_supplemental_inputs(
                self.config['age_identity'], self.config['supplemental_inputs'], self.home,
                self.state['tag'], self.state['public_commit'],
                (self.root, self.manager, self.tooling))
        directory, local_values = None, {}
        agent_archive = self.private / 'infisical-agent.tar.gz'
        if agent_archive.is_file():
            directory = Path(tempfile.mkdtemp(prefix='agent-backup-', dir=self.home)) / 'files'
            unpack_agent(agent_archive, directory)
            local_values = archived_local_inputs(
                directory, json.loads((self.root / 'config/dr-render-plan.json').read_bytes()))
        if self.config.get('client_id_file') and self.config.get('client_secret_file'):
            recovered = dict(address=self.config.get('infisical_address'), project=self.config.get('project_id'),
                             environment=self.config.get('environment', 'prod'),
                             client_id=self.config['client_id_file'], client_secret=self.config['client_secret_file'])
        else:
            require(directory is not None, 'AGENT_BOOTSTRAP_CONFIG_NOT_UNIQUE')
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
            snapshots = collect_inputs(plan, dr, client, project, environment,
                                       aio_mode=mode, supplemental=supplemental, applied=applied,
                                       local_values=local_values)
        except Refused:
            raise
        except Exception:
            raise Refused('INFISICAL_SNAPSHOT_FAILED') from None
        finally:
            client.close()
        write_inputs(self.root / '.secrets/dr-inputs', snapshots)
        self.state['input_aio_mode'] = mode
        if provenance is not None:
            self.state['supplemental_inputs'] = dict(provenance, applied=sorted(applied))

    def run_script(self, name, action, *extra, root=False):
        if name == 'dr.py' and action == 'render' and self.state.get('render_base') is not None:
            require(root and extra == ('--mode','fresh'), 'AGENT_RENDER_BASE_INVALID')
            self.verify_render_base()
            self.seed_private_envs()
            return
        if name == 'dr.py' and action == 'render' and self.config.get('aio_mode', 'import') in ('manual', 'snapshot'):
            # Run the pinned renderer with the same in-memory input plan as
            # INPUTS. Its files, permissions, marker and SQL checks are intact.
            require(root and extra == ('--mode', 'fresh') and os.geteuid() == 0,
                    'MANUAL_AIO_INPUT_CONTRACT_INVALID')
            dr = configure_renderer(load_module(self.root / 'scripts/dr.py', 'manual_aio_renderer'), self.config['aio_mode'])
            args = argparse.Namespace(target=str(self.root), input_dir=None, mode='fresh',
                                      synthetic=False, deployment_gid=1000)
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    dr.render(args)
            except Exception:
                raise Refused('FRESH_RENDERER_REFUSED') from None
            self.record_render_base()
            self.seed_private_envs()
            return
        args = [sys.executable, '-B', self.root / 'scripts' / name, action, '--target', self.root, *extra]
        if root and os.geteuid() != 0:
            args = ['sudo', '--', *args]
        command(args, {'dr.py': 'FRESH_RENDERER_REFUSED', 'npm-dr.py': 'NPM_RECOVERY_REFUSED',
                       'aio-dr.py': 'AIO_IMPORT_REFUSED'}[name], cwd=self.root)
        if name == 'dr.py' and action == 'render':
            self.record_render_base()
            self.seed_private_envs()

    def record_render_base(self):
        # Persist this boundary before any new private output can be promoted.
        self.state['render_base'] = render_base_snapshot(self.root)
        save(self.state_path,self.state)

    def verify_render_base(self):
        prefix = {'CLONES','DOWNLOAD','DECRYPT','INITIALIZE','INPUTS'}
        completed = self.state.get('completed')
        require(isinstance(completed,list) and len(completed) == len(prefix) and set(completed) == prefix
                and self.state.get('in_progress') in (None,'RENDER')
                and self.state.get('preparation') is None and self.state.get('runtime_profile') is None
                and self.state.get('native_agent') is None
                and not self.state.get('application_start_attempted',False), 'AGENT_RENDER_BASE_INVALID')
        require(self.state.get('render_base') == render_base_snapshot(self.root), 'AGENT_RENDER_BASE_CHANGED')

    def seed_private_envs(self):
        """Complete RENDER from exact encrypted Agent templates, before Compose."""
        native = load_module(self.tooling/'native_agent.py','recovery_early_agent')
        plan = json.loads(safe_path(self.root/'config/dr-render-plan.json').read_bytes())
        try:
            targets = native.required_private_envs(self.root,plan)
            outputs = {}
            if targets:
                # Only the recovered scope is authoritative for private mappings.
                require(not any(self.config.get(key) for key in
                        ('project_id','environment','client_id_file','client_secret_file')),
                        'NATIVE_AGENT_REQUIRES_RECOVERED_SCOPE')
                require(self.config.get('native_agent',True) is True, 'AGENT_SEED_CONTINUOUS_AGENT_REQUIRED')
                address = validate_address(self.config.get('infisical_address'),
                                           ssh_bridge=self.config.get('ssh_bridge') is True)
                outputs = native.seed_required_envs(self.root,self.home,
                    self.private/'infisical-agent.tar.gz',plan,address)
            self.state['agent_seed'] = {'schema':1,'outputs':outputs}
        except native.Refused as error:
            # native_agent may import recover under another module name when
            # this runner is __main__; translate its finite errors explicitly.
            raise Refused(str(error)) from None

    def verify_seeded_envs(self):
        evidence = self.state.get('agent_seed')
        native = load_module(self.tooling/'native_agent.py','recovery_seed_verifier')
        plan = json.loads(safe_path(self.root/'config/dr-render-plan.json').read_bytes())
        # After permanent installation, the Agent intentionally owns secret
        # rotation. Preparation resumes before then must match the seed bytes.
        rotating = (self.state.get('preparation') == 'PASS'
                    and self.state.get('native_agent') == 'ACTIVE_NO_RESTART_HOOKS')
        try:
            if evidence is None:
                # Legacy checkpoints are compatible only when the original
                # public plan already covers every required private env file.
                require(not native.required_private_envs(self.root,plan), 'AGENT_SEED_CHECKPOINT_REQUIRED')
                return
            require(isinstance(evidence,dict) and set(evidence) == {'schema','outputs'}
                    and type(evidence['schema']) is int and evidence['schema'] == 1,
                    'AGENT_SEED_CHECKPOINT_INVALID')
            native.verify_seeded_envs(self.root,plan,evidence['outputs'],check_hash=not rotating)
        except native.Refused as error:
            raise Refused(str(error)) from None

    def npm(self):
        target = self.root / 'data/npm/data/database.sqlite'
        require(not target.exists() and not target.is_symlink(), 'EXISTING_NPM_DATABASE_REFUSED')
        command(['sudo', 'install', '-m', '600', '-o', '1000', '-g', '1000',
                 self.private / 'database.sqlite', target], 'NPM_DATABASE_INSTALL_FAILED')
        self.run_script('npm-dr.py', 'prepare', root=True)

    def aio(self):
        mode = self.config.get('aio_mode', 'import')
        require(mode in ('import', 'manual', 'snapshot'), 'INVALID_AIO_RECOVERY_MODE')
        if mode == 'snapshot':
            archive = private_file(self.private / AIO_PLAINTEXT, (self.root, self.manager, self.tooling))
            model = json.loads(command(['docker', 'compose', '--profile', 'all', 'config', '--format', 'json'],
                                       'COMPOSE_VALIDATION_FAILED', cwd=self.root))
            module = load_module(self.tooling / 'aio_snapshot.py', 'native_aio_restorer')
            try:
                evidence = module.restore_capsule(archive, self.root, run_id=self.state['tag'][3:],
                    source_commit=self.state['public_commit'], model=model,
                    run=lambda args, code: command(args, code, cwd=self.root))
            except module.Refused as error:
                raise Refused(str(error)) from None
            self.state.update(aio_mode='snapshot', aio_recovery='NATIVE_SNAPSHOT_RESTORED', aio_snapshot=evidence)
            return
        if mode == 'manual':
            require(not any(safe_path(self.root / f'data/{service}/data/db.sqlite').exists()
                            for service in ('aiostreams', 'aiometadata'))
                    and not safe_path(self.root / '.generated/aio-import-complete.json').exists(),
                    'MANUAL_AIO_IMPORT_CONFLICT')
            self.state['aio_mode'] = 'manual'
            self.state['aio_recovery'] = 'MANUAL_PENDING'
            return
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

    def services(self):
        path = self.root / 'config/service-resources.json'
        archive = self.private / SERVICES_PLAINTEXT
        if not path.exists():
            require(not archive.exists(), 'SERVICES_STATE_INVENTORY_REQUIRED')
            return
        module = load_module(self.tooling / 'service_snapshot.py', 'generic_services_restorer')
        try:
            value = module.inventory(self.root)
            for item in value.get('configuration_files', []):
                require(isinstance(item,dict) and set(item) == {'path','mode','sha256'}
                        and isinstance(item['path'],str) and re.fullmatch(r'data/[a-z][a-z0-9_-]*/public/.+',item['path'])
                        and '..' not in PurePosixPath(item['path']).parts and type(item['mode']) is int
                        and 0 <= item['mode'] <= 0o777 and isinstance(item['sha256'],str),
                        'SERVICES_STATE_CONFIGURATION_INVALID')
                target = safe_path(self.root / item['path'])
                require(target.is_file() and digest(target) == item['sha256'], 'SERVICES_STATE_CONFIGURATION_CHANGED')
                os.chmod(target,item['mode'])
            if not module.selected(value):
                require(not archive.exists(), 'SERVICES_STATE_UNEXPECTED_ARCHIVE')
                return
            require(archive.exists(), 'SERVICES_STATE_BACKUP_REQUIRED')
            model = json.loads(command(['docker', 'compose', '--profile', 'all', 'config', '--format', 'json'],
                                       'COMPOSE_VALIDATION_FAILED', cwd=self.root))
            previous = self.state.get('services_snapshot')
            expected = dict(schema=1,run=self.state['tag'][3:],stack_commit=self.state['public_commit'],
                            inventory_sha256=module.digest(path),
                            archive_sha256=module.digest(archive),resources=sorted(item['id'] for item in module.selected(value)))
            if previous:
                require(previous == expected, 'SERVICES_STATE_CHECKPOINT_CHANGED')
                return
            evidence = module.restore(private_file(archive, (self.root,self.manager,self.tooling)),self.root,
                run_id=self.state['tag'][3:],source_commit=self.state['public_commit'],model=model,
                runner=lambda args,code: command(args,code,cwd=self.root))
            require(isinstance(evidence,dict) and {key:value for key,value in evidence.items() if key != 'checkpoint'} == expected,
                    'SERVICES_STATE_CHECKPOINT_CHANGED')
            evidence.pop('checkpoint',None)
            self.state['services_snapshot'] = evidence
            save(self.state_path,self.state)
        except module.Refused as error:
            raise Refused(str(error)) from None

    def validate_resume(self):
        if self.state.get('lab_deployment') is not None:
            require(self.config.get('onboarding_lab') is True
                    and self.config.get('operational_profile') is not True,
                    'LAB_RUNTIME_SCOPE_REFUSED')
            policy = load_module(self.tooling / 'runtime_profile.py', 'resume_lab_scope')
            try:
                policy.lab_scope(self.root, self.home, self.state)
            except policy.Refused as error:
                raise Refused(str(error)) from None
        elif self.config.get('onboarding_lab') is True:
            # An interrupted pre-profile preparation may be adopted only after
            # the normal source/private/render checks below. Operational or
            # already-profiled deployments are never reclassified as a lab.
            require(self.state.get('operational_deployment') is None
                    and self.state.get('runtime_profile') is None
                    and self.state.get('application_start_attempted', False) is False
                    and self.state.get('preparation') is None
                    and self.state.get('application_recovery') in (None, 'NOT_VERIFIED')
                    and self.state.get('native_agent') is None
                    and self.state.get('timers_installed', False) is False
                    and all(self.state.get(key) is None for key in
                            ('public_domain_recovery', 'operational_recovery', 'public_controllers_enabled')),
                    'LAB_RUNTIME_SCOPE_REFUSED')
        if 'RENDER' in self.state.get('completed',[]):
            self.verify_seeded_envs()
        elif self.state.get('render_base') is not None:
            self.verify_render_base()
        if self.state.get('operational_deployment') is not None:
            require(self.config.get('operational_profile') is True, 'OPERATIONAL_DEPLOYMENT_REFUSED')
        if self.config.get('operational_profile') is True:
            require(self.state.get('npm_upstream_targets') == upstream_targets(self.config.get('npm_upstream_targets')),
                    'NPM_TOPOLOGY_TARGET_INVALID')
        if 'INPUTS' in self.state['completed'] and 'input_aio_mode' in self.state:
            require(self.state['input_aio_mode'] == self.config.get('aio_mode', 'import'),
                    'RECOVERY_AIO_MODE_CHANGED')
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
                elif folder == self.root and self.state.get('render_base') is not None:
                    allowed = set(self.state['render_base']['outputs'])
                require(changed <= allowed and not command(['git', '-C', folder, 'ls-files', '--others', '--exclude-standard'],
                                                          'RECOVERY_UNTRACKED_CHECK_FAILED'), 'RECOVERY_TREE_MODIFIED')
        if 'DOWNLOAD' in self.state['completed']:
            require(self.config['dr_tag'] == self.state['tag'], 'RECOVERY_TAG_CHANGED')
            manifest = validate_bundle(self.manager, self.bundle, self.state['tag'])
            if manifest.get('schema') == 2:
                require(manifest.get('stack_commit') == self.state['public_commit'], 'DR_STACK_COMMIT_MISMATCH')
            if self.config.get('aio_mode') == 'snapshot':
                require(manifest.get('schema') == 2 and AIO_ASSET in encrypted_assets(self.bundle),
                        'AIO_SNAPSHOT_BACKUP_REQUIRED')
        if 'DECRYPT' in self.state['completed']:
            hashes = self.state.get('private_hashes')
            expected = set(encrypted_assets(self.bundle).values())
            # Every decrypted artifact must remain covered, including the native
            # AIO capsule. An empty/partial checkpoint cannot weaken this check.
            require(isinstance(hashes, dict) and set(hashes) == expected
                    and all(isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{64}', sha)
                            for sha in hashes.values()), 'PRIVATE_MATERIAL_CHANGED')
            require(all(digest(private_file(self.private / name)) == sha
                        for name, sha in hashes.items()), 'PRIVATE_MATERIAL_CHANGED')

    def prepare_first_boot(self):
        """Register the reviewed compatibility fixes before any app container.

        The scoped policy verifies this exact fresh checkpoint and pinned
        images. It never starts containers or removes volumes; repeated calls
        verify its registered artifact before reusing it.
        """
        policy = load_module(self.tooling / 'runtime_profile.py', 'fresh_runtime_policy')
        def run(args):
            code = first_boot_command_code(args)
            try:
                raw = command(args, code, cwd=self.root)
                json_shape = None
                invalid_code = code
                if code == 'RUNTIME_PROFILE_COMPOSE_CONFIG_FAILED':
                    json_shape, invalid_code = dict, 'RUNTIME_PROFILE_COMPOSE_CONFIG_INVALID'
                elif code == 'RUNTIME_PROFILE_IMAGE_INSPECT_FAILED':
                    # Docker's default/json inspectors return a list. A Go
                    # template returns one selected value; an image without a
                    # healthcheck legitimately returns null for that field.
                    arguments = [str(value) for value in args]
                    selected_format = (arguments[arguments.index('--format') + 1]
                                       if '--format' in arguments else None)
                    if selected_format in (None, 'json'):
                        json_shape = list
                    elif selected_format == '{{json .Config.Healthcheck}}':
                        json_shape = (dict, type(None))
                    else:
                        json_shape = dict
                elif code == 'RUNTIME_PROFILE_DOCKER_RESOURCE_CHECK_FAILED' and (
                        [str(x) for x in args[:2]] == ['docker', 'inspect']
                        or [str(x) for x in args[:3]] == ['docker', 'volume', 'inspect']):
                    json_shape = list
                if json_shape is not None:
                    try:
                        model = json.loads(raw)
                    except (ValueError, TypeError, UnicodeError):
                        raise Refused(invalid_code) from None
                    require(isinstance(model, json_shape), invalid_code)
                return raw
            except Refused as error:
                # The policy rolls back a partially written profile and retains
                # this finite code only when its own Refused type is raised.
                fixed = str(error) if str(error) in FIRST_BOOT_COMMAND_CODES else 'RUNTIME_PROFILE_COMMAND_FAILED'
                raise policy.Refused(fixed) from None
        try:
            if policy.validate(self.root, self.home, self.state):
                return
            policy.first_boot_scope(self.root, self.home, self.state, installing=True)
            model = json.loads(run(['docker', 'compose', '--profile', 'all', 'config', '--format', 'json']))
            images = policy.first_boot_images(self.root, model)
            require(isinstance(images, tuple) and len(images) == 4
                    and len(set(images)) == 4 and all(PINNED_IMAGE.fullmatch(image) for image in images),
                    'RUNTIME_PROFILE_COMMAND_FAILED')
            # An exact cached digest is immutable. The policy still performs
            # its platform, content, user and layer checks before committing.
            for image, code in zip(images, FIRST_BOOT_PULL_CODES):
                if not first_boot_cached_image(image, self.root):
                    command(['docker', 'pull', image], code, cwd=self.root, timeout=300)
            policy.apply_fresh(self.root, self.home, self.state, model, run)
        except policy.Refused as error:
            raise Refused(str(error)) from None

    def prepare_topology(self):
        """Relocate proven NPM upstreams before any NPM container can start."""
        if self.config.get('operational_profile') is not True:
            return
        require(self.state.get('aio_recovery') == 'NATIVE_SNAPSHOT_RESTORED'
                and isinstance((self.state.get('aio_snapshot') or {}).get('deployment'),dict),
                'NPM_TOPOLOGY_BACKUP_REQUIRED')
        deployment = safe_path(self.root/'.generated/npm-deployment.json')
        require(deployment.is_file(), 'NPM_TOPOLOGY_BACKUP_REQUIRED')
        verify_aio_snapshot(self.root,self.state)
        module = load_module(self.tooling/'npm_topology.py','recovery_npm_topology')
        targets = upstream_targets(self.state.get('npm_upstream_targets'))
        require(targets == upstream_targets(self.config.get('npm_upstream_targets')), 'NPM_TOPOLOGY_TARGET_INVALID')
        try:
            value = json.loads(module.checked(deployment,private=True).read_bytes())
            module.validate(value,stack_commit=self.state['public_commit'])
            evidence = self.state.get('npm_topology')
            if evidence is not None:
                saved = module.verify(self.root,evidence,stack_commit=self.state['public_commit'])
                require(saved == dict(module.planned(value,targets),phase='complete'), 'NPM_TOPOLOGY_EVIDENCE_REQUIRED')
            else:
                require(not self.state.get('application_start_attempted',False), 'NPM_TOPOLOGY_EVIDENCE_REQUIRED')
                evidence = module.prepare(self.root,value,targets,
                    lambda args: command(args,'NPM_TOPOLOGY_APPLY_FAILED',cwd=self.root))
                self.state['npm_topology'] = evidence
                save(self.state_path,self.state)
        except module.Refused as error:
            raise Refused(str(error)) from None

    def prepare(self):
        existing = (command(['docker', 'ps', '-aq'], 'DOCKER_ACCESS_REQUIRED').strip()
                    or command(['docker', 'volume', 'ls', '-q'], 'DOCKER_ACCESS_REQUIRED').strip())
        if existing:
            probe = load_module(self.tooling / 'probe.py', 'resume_runtime_guard')
            try:
                if self.config.get('onboarding_lab') is True:
                    probe.checked_stack_runtime(self.root, self.home, self.state,
                        lab_point=(self.config['dr_tag'], self.config['public_commit']))
                else:
                    probe.checked_stack_runtime(self.root, self.home, self.state)
            except ValueError as error:
                raise Refused(str(error)) from None
        self.auth()
        self.validate_resume()
        self.step('CLONES', self.clones)
        self.step('DOWNLOAD', self.download)
        self.step('DECRYPT', self.decrypt)
        self.step('INITIALIZE', self.initialize)
        self.step('INPUTS', self.inputs)
        self.step('RENDER', lambda: self.run_script('dr.py', 'render', '--mode', 'fresh', root=True))
        self.step('EMPTY_STATE', lambda: self.run_script('dr.py', 'prepare-state', root=True))
        if self.config.get('onboarding_lab') is True:
            policy = load_module(self.tooling / 'runtime_profile.py', 'onboarding_lab_scope')
            record = policy.lab_record(self.root, self.state)
            if self.state.get('lab_deployment') is not None:
                require(self.state['lab_deployment'] == record, 'LAB_RUNTIME_SCOPE_REFUSED')
            else:
                # validate_resume has already checked the selected source,
                # encrypted bundle, private hashes and exact renderer outputs.
                require(not self.state.get('runtime_profile')
                        and self.state.get('application_start_attempted', False) is False
                        and self.state.get('in_progress') is None, 'LAB_RUNTIME_SCOPE_REFUSED')
                self.state['lab_deployment'] = record
                save(self.state_path, self.state)
        if self.config.get('operational_profile') is True:
            policy = load_module(self.tooling / 'runtime_profile.py', 'operational_deployment_scope')
            record = policy.deployment_record(self.root, self.state, self.config.get('routing_mode'),
                                              self.config.get('domain_target_address'))
            if self.state.get('operational_deployment') is not None:
                require(self.state['operational_deployment'] == record, 'OPERATIONAL_DEPLOYMENT_REFUSED')
            elif not self.state.get('runtime_profile'):
                # Legacy profile promotion remains a separate transactional start operation.
                self.state['operational_deployment'] = record
                save(self.state_path, self.state)
        event('RUNTIME_PROFILE', 'RUNNING')
        self.prepare_first_boot()
        event('RUNTIME_PROFILE')
        self.step('NPM', self.npm)
        self.step('AIO', self.aio)
        self.step('SERVICES', self.services)
        if self.config.get('operational_profile') is True:
            event('NPM_TOPOLOGY','RUNNING')
        self.prepare_topology()
        if self.config.get('operational_profile') is True:
            event('NPM_TOPOLOGY')
        # Always repeat real checks. A checkpoint alone never means ready.
        stack_preflight(self.root, self.state)
        event('PREFLIGHT')
        command(['docker', 'compose', '--profile', 'all', 'config', '--quiet'], 'COMPOSE_VALIDATION_FAILED', cwd=self.root)
        self.state['preparation'] = 'PASS'
        self.state.setdefault('application_recovery', 'NOT_VERIFIED')
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

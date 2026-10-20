"""Add one reviewed service to an existing stack. JSON stdin, safe JSON stdout.

The desktop creates or verifies Infisical secrets before ``apply``. This helper
never receives secret values. Existing files retain their bytes and metadata;
only a new service, its public env, and an Agent template are added. Completion
requires an application probe and a new coherent, read-back-verified DR release.
"""
from contextlib import contextmanager
from dataclasses import dataclass, field
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import uuid

import yaml


PUBLIC = 'dav1dera/streams-aio-sanitized'
PRIVATE = 'dav1dera/streams-aio-dr'
AGENT_UNIT = 'infisical-agent.service'
DR_UNIT = 'streams-aio-dr.service'
ASSETS = frozenset({'aio-state.tar.gz.age', 'infisical-agent-infisical-agent.tar.gz.age',
                    'infisical-config.tar.gz.age', 'infisical-postgres.dump.age',
                    'infisical-postgres-globals.sql.age', 'npm-database.sqlite.age'})
FILES = ASSETS | {'manifest.json', 'SHA256SUMS'}
NAME = re.compile(r'[a-z0-9][a-z0-9_-]{0,62}\Z')
KEY = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,127}\Z')
ACL_ATTRIBUTES = frozenset({'system.posix_acl_access', 'system.posix_acl_default'})
IDENTIFIER = re.compile(r'[A-Za-z0-9_-]{1,128}\Z')
SHA = re.compile(r'[0-9a-f]{40}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
JOB = re.compile(r'[0-9a-f]{32}\Z')
MAX_FILE = 4 * 1024**2


class Refused(Exception):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'ONBOARDING_DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def load_json(raw):
    return json.loads(raw, object_pairs_hook=pairs)


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    # Existing Compose anchors/merges remain supported; explicit duplicate keys
    # are rejected before YAML merge expansion resolves intentional overrides.
    explicit = set()
    for key_node, _ in node.value:
        if key_node.tag == 'tag:yaml.org,2002:merge':
            continue
        key = loader.construct_object(key_node, deep=True)
        need(isinstance(key, str) and key not in explicit, 'ONBOARDING_DUPLICATE_YAML_KEY')
        explicit.add(key)
    loader.flatten_mapping(node)
    return dict((loader.construct_object(key, deep=deep), loader.construct_object(value, deep=deep))
                for key, value in node.value)


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def yaml_document(raw):
    need(isinstance(raw, (bytes, str)) and len(raw) <= MAX_FILE, 'ONBOARDING_INPUT_TOO_LARGE')
    return yaml.load(raw, Loader=UniqueLoader)


def mapping_value(node, name):
    need(isinstance(node, yaml.MappingNode), 'ONBOARDING_YAML_STRUCTURE_INVALID')
    matches = [value for key, value in node.value if key.value == name]
    need(len(matches) == 1, 'ONBOARDING_YAML_STRUCTURE_INVALID')
    return matches[0]


def plan_document(plan):
    need(isinstance(plan, dict), 'ONBOARDING_PLAN_INVALID')
    allowed = {'schema', 'service_name', 'image', 'compose_fragment', 'public_env_path',
               'public_env_content', 'public_env_text', 'private_env_path', 'bindings',
               'private_bindings', 'fingerprint', 'variables'}
    need(set(plan) <= allowed and plan.get('schema', 1) == 1, 'ONBOARDING_PLAN_INVALID')
    name = plan.get('service_name')
    need(isinstance(name, str) and NAME.fullmatch(name), 'ONBOARDING_SERVICE_NAME_INVALID')
    public_path, private_path = 'data/' + name + '/.env', '.secrets/' + name + '.env'
    need(plan.get('public_env_path') == public_path and plan.get('private_env_path') == private_path,
         'ONBOARDING_PLAN_PATH_INVALID')
    text = plan.get('public_env_text', plan.get('public_env_content', ''))
    fragment = plan.get('compose_fragment')
    need(isinstance(text, str) and isinstance(fragment, str) and len(text.encode()) <= MAX_FILE
         and len(fragment.encode()) <= MAX_FILE and '\x00' not in text and '\x00' not in fragment,
         'ONBOARDING_PLAN_INVALID')
    # The transport carries only this explicit public deployment shape. In
    # particular there is no private_values field to accidentally persist.
    bindings = plan.get('private_bindings', plan.get('bindings', {}))
    need(isinstance(bindings, dict) and len(bindings) <= 200, 'ONBOARDING_BINDINGS_INVALID')
    normalized = {}
    for key, source in bindings.items():
        need(isinstance(key, str) and KEY.fullmatch(key) and isinstance(source, dict)
             and set(source) in ({'folder', 'key'}, {'path', 'key'}), 'ONBOARDING_BINDINGS_INVALID')
        folder, secret_key = source.get('folder', source.get('path')), source.get('key')
        need(isinstance(folder, str) and re.fullmatch(r'/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*', folder)
             and isinstance(secret_key, str) and KEY.fullmatch(secret_key), 'ONBOARDING_BINDINGS_INVALID')
        normalized[key] = {'folder': folder, 'key': secret_key}
    need(fragment.startswith('  ') and not fragment.startswith('services:'), 'ONBOARDING_FRAGMENT_INVALID')
    document = yaml_document('services:\n' + fragment)
    need(isinstance(document, dict) and set(document) == {'services'}
         and isinstance(document['services'], dict) and set(document['services']) == {name},
         'ONBOARDING_FRAGMENT_INVALID')
    service = document['services'][name]
    need(isinstance(service, dict) and isinstance(service.get('image'), str)
         and service['image'] == plan.get('image') and 0 < len(service['image']) < 512
         and not any(c.isspace() for c in service['image']) and not service['image'].startswith('-')
         and 'build' not in service and 'extends' not in service, 'ONBOARDING_FRAGMENT_INVALID')
    need(not service.get('volumes'), 'ONBOARDING_PERSISTENT_DATA_COVERAGE_REQUIRED')
    env_files = service.get('env_file') or []
    need(isinstance(env_files, list) and all(isinstance(p, str) for p in env_files),
         'ONBOARDING_ENV_FILE_INVALID')
    env_files = [p[2:] if p.startswith('./') else p for p in env_files]
    expected = [public_path] + ([private_path] if normalized else [])
    need(env_files == expected, 'ONBOARDING_ENV_FILE_ORDER_INVALID')
    environment = service.get('environment') or {}
    if isinstance(environment, list):
        environment = dict((row.split('=', 1) + [''])[:2] for row in environment if isinstance(row, str))
    need(isinstance(environment, dict) and not (set(environment) & normalized.keys()),
         'ONBOARDING_PRIVATE_VARIABLE_OVERRIDE')
    public_names = re.findall(r'(?m)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=', text)
    need(not (set(public_names) & normalized.keys()), 'ONBOARDING_PRIVATE_VARIABLE_IN_PUBLIC_ENV')
    return dict(schema=1, service_name=name, image=service['image'], compose_fragment=fragment,
                public_env_path=public_path, public_env_text=text, private_env_path=private_path,
                private_bindings=normalized), service


def merge_compose(raw, plan):
    """Insert a service inside the existing block without rewriting any byte."""
    plan, service = plan_document(plan)
    text = raw.decode('utf-8') if isinstance(raw, bytes) else raw
    document = yaml_document(text)
    need(isinstance(document, dict) and isinstance(document.get('services'), dict)
         and 'include' not in document, 'ONBOARDING_EXISTING_COMPOSE_UNSUPPORTED')
    need(plan['service_name'] not in document['services'], 'ONBOARDING_SERVICE_ALREADY_EXISTS')
    dependencies = service.get('depends_on') or {}
    need(isinstance(dependencies, (dict, list)) and set(dependencies) <= document['services'].keys(),
         'ONBOARDING_DEPENDENCY_MISSING')
    mode = service.get('network_mode', '')
    if isinstance(mode, str) and mode.startswith('service:'):
        need(mode[8:] in document['services'], 'ONBOARDING_DEPENDENCY_MISSING')
    node = mapping_value(yaml.compose(text), 'services')
    need(isinstance(node, yaml.MappingNode) and not node.flow_style, 'ONBOARDING_EXISTING_COMPOSE_UNSUPPORTED')
    position = node.end_mark.index
    # A block mapping's end points at the next root key (or EOF). Its line
    # indentation belongs to that following key and remains in the suffix.
    beginning = text.rfind('\n', 0, position) + 1
    if not text[beginning:position].strip():
        position = beginning
    newline = '\r\n' if '\r\n' in text else '\n'
    body = plan['compose_fragment'].replace('\r\n', '\n').rstrip('\n').replace('\n', newline)
    prefix, suffix = text[:position], text[position:]
    inserted = ('' if prefix.endswith(('\n', '\r')) else newline) + newline + body + newline
    result = prefix + inserted + suffix
    expected = dict(document)
    expected['services'] = dict(document['services'], **{plan['service_name']: service})
    need(yaml_document(result) == expected, 'ONBOARDING_COMPOSE_MERGE_INVALID')
    return result.encode('utf-8')


def agent_template(root, plan, project, environment):
    need(isinstance(project, str) and IDENTIFIER.fullmatch(project)
         and isinstance(environment, str) and IDENTIFIER.fullmatch(environment),
         'ONBOARDING_INFISICAL_SCOPE_INVALID')
    lines = []
    for key, source in sorted(plan['private_bindings'].items()):
        # Legacy .Value emission is understood by the installed DR verifier.
        # The desktop must reject apostrophes, line breaks and final backslash
        # in NEW values before writing them to Infisical; values never arrive here.
        getter = ' '.join(json.dumps(x) for x in (project, environment, source['folder'], source['key']))
        lines.append(key + "='{{ with getSecretByName " + getter + ' }}{{ .Value }}{{ end }}\'')
    return '\n'.join(lines) + '\n'


def extend_agent(raw, root, plan, project, environment):
    text = raw.decode('utf-8')
    document = yaml_document(text)
    need(isinstance(document, dict) and isinstance(document.get('templates'), list),
         'ONBOARDING_AGENT_CONFIG_INVALID')
    target = str(root / plan['private_env_path'])
    need(all(isinstance(row, dict) and row.get('destination-path') != target for row in document['templates']),
         'ONBOARDING_AGENT_DESTINATION_EXISTS')
    def hooks(value):
        if isinstance(value, dict):
            return any((key in {'execute', 'exec', 'command'} and bool(item)) or hooks(item)
                       for key, item in value.items())
        return isinstance(value, list) and any(hooks(item) for item in value)
    need(not hooks(document), 'ONBOARDING_AGENT_HOOK_REVIEW_REQUIRED')
    row = {'template-content': agent_template(root, plan, project, environment),
           'destination-path': target, 'config': {'polling-interval': '60s'}}
    node = mapping_value(yaml.compose(text), 'templates')
    need(isinstance(node, yaml.SequenceNode) and not node.flow_style, 'ONBOARDING_AGENT_CONFIG_INVALID')
    position = node.end_mark.index
    beginning = text.rfind('\n', 0, position) + 1
    if not text[beginning:position].strip():
        position = beginning
    indentation = node.start_mark.column
    addition = yaml.safe_dump([row], sort_keys=False, allow_unicode=True, width=4096)
    addition = '\n'.join((' ' * indentation + line) if line else '' for line in addition.splitlines()) + '\n'
    newline = '\r\n' if '\r\n' in text else '\n'
    addition = addition.replace('\n', newline)
    prefix = text[:position]
    result = prefix + ('' if prefix.endswith('\n') else newline) + addition + text[position:]
    expected = dict(document, templates=document['templates'] + [row])
    need(yaml_document(result) == expected, 'ONBOARDING_AGENT_MERGE_INVALID')
    return result.encode('utf-8')


@dataclass(frozen=True)
class Layout:
    root: PurePosixPath
    home: PurePosixPath
    user: str
    uid: int
    gid: int
    agent: PurePosixPath = PurePosixPath('/etc/infisical/agent-config.yaml')

    @property
    def state(self):
        return self.home / '.local/state/streams-aio-onboarding'

    @classmethod
    def production(cls, value):
        need(sys.platform == 'linux' and os.geteuid() == 0, 'ONBOARDING_ROOT_REQUIRED')
        need(isinstance(value, str) and re.fullmatch(r'/home/[a-z_][a-z0-9_-]{0,31}/streams-aio', value),
             'ONBOARDING_STACK_ROOT_INVALID')
        import pwd
        root = PurePosixPath(value)
        user = root.parent.name
        account = pwd.getpwnam(user)
        need(account.pw_uid != 0 and account.pw_dir == str(root.parent), 'ONBOARDING_STACK_OWNER_INVALID')
        return cls(root, root.parent, user, account.pw_uid, account.pw_gid)


@dataclass
class Snapshot:
    path: str
    raw: bytes = field(repr=False)
    uid: int = 0
    gid: int = 0
    mode: int = 0o600
    device: int = 0
    inode: int = 0
    mtime: int = 0
    attributes: dict = field(default_factory=dict, repr=False)

    def identity(self):
        return dict(path=self.path, sha256=digest(self.raw), uid=self.uid, gid=self.gid,
                    mode=self.mode, device=self.device, inode=self.inode, mtime=self.mtime,
                    attributes={key: digest(value) for key, value in self.attributes.items()})

    def saved(self):
        return dict(self.identity(), data=base64.b64encode(self.raw).decode(),
                    attributes={key: base64.b64encode(value).decode() for key, value in self.attributes.items()})

    @classmethod
    def restore(cls, value):
        return cls(value['path'], base64.b64decode(value['data']), value['uid'], value['gid'], value['mode'],
                   value['device'], value['inode'], value['mtime'],
                   {key: base64.b64decode(raw) for key, raw in value['attributes'].items()})


def metadata_matches(item, mode, attributes, public=False):
    if public:
        # The installed public-file ACL watcher can recalculate only the group
        # mask. Owner/other bits and non-ACL attributes must remain unchanged.
        return (item.mode & ~0o070 == mode & ~0o070 and
                {key: value for key, value in item.attributes.items() if key not in ACL_ATTRIBUTES} ==
                {key: value for key, value in attributes.items() if key not in ACL_ATTRIBUTES})
    return item.mode == mode and item.attributes == attributes


class Store:
    def safe(self, path):
        path = Path(str(path))
        need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)),
             'ONBOARDING_SYMLINK_PATH_REFUSED')
        return path

    def exists(self, path):
        return self.safe(path).exists()

    def read(self, path, limit=MAX_FILE):
        return self.snapshot(path, limit).raw

    def snapshot(self, path, limit=MAX_FILE):
        path = self.safe(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
                 'ONBOARDING_FILE_INVALID')
            with os.fdopen(os.dup(fd), 'rb') as reader:
                raw = reader.read(limit + 1)
            after = os.fstat(fd)
            need(len(raw) <= limit and (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size) ==
                 (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_size), 'ONBOARDING_SOURCE_CHANGED')
            return Snapshot(str(path), raw, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode),
                            info.st_dev, info.st_ino, info.st_mtime_ns,
                            {key: os.getxattr(fd, key) for key in os.listxattr(fd)})
        finally:
            os.close(fd)

    def directory(self, path, uid, gid, mode, create=False, public=False):
        path = self.safe(path)
        if create and not path.exists():
            path.mkdir(mode=mode)
            os.chown(path, uid, gid)
            os.chmod(path, mode)
        info = path.stat()
        current = stat.S_IMODE(info.st_mode)
        if public:
            # Public application folders can legitimately inherit the existing
            # ACL watcher's defaults. Never alter an existing folder's ACLs.
            need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, uid) and info.st_gid == gid
                 and not current & 0o7002, 'ONBOARDING_DIRECTORY_PERMISSIONS_INVALID')
        else:
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and info.st_gid == gid
                 and current == mode, 'ONBOARDING_DIRECTORY_PERMISSIONS_INVALID')
        if not public and mode in (0o700, 0o750):
            need(not ACL_ATTRIBUTES & set(os.listxattr(path)),
                 'ONBOARDING_PRIVATE_ACL_REVIEW_REQUIRED')

    def write(self, path, raw, uid, gid, mode, previous=None, public=False):
        path = self.safe(path)
        if previous is None:
            need(not path.exists(), 'ONBOARDING_OUTPUT_EXISTS')
        else:
            need(self.snapshot(path).identity() == previous.identity(), 'ONBOARDING_SOURCE_CHANGED')
        fd, name = tempfile.mkstemp(prefix='.onboarding-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as writer:
                writer.write(raw)
                writer.flush()
                os.fchown(writer.fileno(), uid, gid)
                if previous is not None:
                    for key in os.listxattr(writer.fileno()):
                        if key not in previous.attributes:
                            os.removexattr(writer.fileno(), key)
                    for key, value in previous.attributes.items():
                        os.setxattr(writer.fileno(), key, value)
                os.fchmod(writer.fileno(), mode)
                os.fsync(writer.fileno())
            if previous is None:
                os.link(name, path)
                os.unlink(name)
            else:
                os.replace(name, path)
        finally:
            if os.path.exists(name):
                os.unlink(name)
        current = self.snapshot(path)
        attributes = previous.attributes if previous else {}
        need(current.raw == raw and (current.uid, current.gid) == (uid, gid)
             and metadata_matches(current, mode, attributes, public),
             'ONBOARDING_WRITE_VERIFICATION_FAILED')
        return current

    def unlink(self, path, expected_hash):
        need(digest(self.read(path)) == expected_hash, 'ONBOARDING_OUTPUT_CHANGED')
        self.safe(path).unlink()

    def json(self, path):
        snap = self.snapshot(path, 16 * MAX_FILE)
        need(snap.uid == 0 and snap.mode == 0o600, 'ONBOARDING_JOURNAL_PERMISSIONS_INVALID')
        return load_json(snap.raw)

    def save(self, path, value):
        previous = self.snapshot(path, 16 * MAX_FILE) if self.exists(path) else None
        return self.write(path, canonical_json(value) + b'\n', 0, 0, 0o600, previous)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Runner:
    def __init__(self, layout):
        self.layout = layout

    def command(self, args, user=False):
        env = dict(os.environ)
        for key in ('GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN'):
            env.pop(key, None)
        env.update(GH_PROMPT_DISABLED='1', GIT_TERMINAL_PROMPT='0')
        if user:
            args = ['runuser', '-u', self.layout.user, '--', 'env', 'HOME=' + str(self.layout.home),
                    'GH_CONFIG_DIR=' + str(self.layout.home / '.config/gh'), *map(str, args)]
        return list(map(str, args)), env

    def run(self, args, code, timeout=120, user=False):
        args, env = self.command(args, user)
        result = subprocess.run(args, cwd=str(self.layout.root), env=env,
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        need(result.returncode == 0, code)
        return result.stdout

    def props(self, unit):
        raw = self.run(['systemctl', 'show', unit, '--property=ActiveState,Result,ExecMainStatus,InvocationID,User,Group,UMask,ExecStart,KillMode,ExecStartPre,ExecStartPost,ExecStop,ExecStopPost'],
                       'ONBOARDING_SYSTEMD_QUERY_FAILED').decode()
        return dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)

    def api(self, suffix, binary=False):
        args = ['gh', 'api', '--hostname', 'github.com', '--method', 'GET', '-H',
                'Accept: application/octet-stream' if binary else 'Accept: application/vnd.github+json', suffix]
        raw = self.run(args, 'ONBOARDING_GITHUB_READ_FAILED', timeout=300, user=True)
        return raw if binary else load_json(raw)

    def asset_digest(self, suffix, expected_size):
        """Hash encrypted release assets in bounded memory, without local copies."""
        args, env = self.command(['gh', 'api', '--hostname', 'github.com', '--method', 'GET',
                                  '-H', 'Accept: application/octet-stream', suffix], user=True)
        process = subprocess.Popen(args, cwd=str(self.layout.root), env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        def stop_group():
            # runuser may exit while its gh child still holds our output pipe.
            # Killing the whole isolated group also bounds that case.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        timer = threading.Timer(300, stop_group)
        timer.daemon = True
        timer.start()
        checksum, size, prefix = hashlib.sha256(), 0, b''
        try:
            while True:
                chunk = process.stdout.read(1024**2)
                if not chunk:
                    break
                size += len(chunk)
                need(size <= expected_size, 'ONBOARDING_BACKUP_ASSET_SIZE_INVALID')
                checksum.update(chunk)
                if len(prefix) < 32:
                    prefix = (prefix + chunk)[:32]
            need(process.wait() == 0, 'ONBOARDING_GITHUB_READ_FAILED')
            need(size == expected_size, 'ONBOARDING_BACKUP_ASSET_SIZE_INVALID')
            return dict(sha256=checksum.hexdigest(), size=size, prefix=prefix)
        finally:
            timer.cancel()
            if process.poll() is None:
                stop_group()
            process.wait()
            process.stdout.close()

    def probe(self, url):
        request = Request(url, headers={'User-Agent': 'StreamsAIO-Onboarding/1'})
        try:
            with build_opener(NoRedirect()).open(request, timeout=10) as response:
                response.read(1)
                return 200 <= response.status < 400
        except Exception:
            return False

    def now(self):
        return dt.datetime.now(dt.timezone.utc)

    def sleep(self, seconds):
        time.sleep(seconds)


def probe_url(value, service):
    if not value:
        return ''
    parts = urlsplit(value)
    need(parts.scheme == 'http' and parts.hostname == '127.0.0.1' and parts.port
         and not parts.username and not parts.password and not parts.fragment and not parts.query
         and re.fullmatch(r'/[A-Za-z0-9_./-]*', parts.path or '/')
         and '\\' not in value and not any(ord(c) < 32 for c in value),
         'ONBOARDING_APPLICATION_PROBE_INVALID')
    published = set()
    need(service.get('network_mode') not in ('host', 'none'), 'ONBOARDING_APPLICATION_PROBE_NOT_PUBLISHED_BY_SERVICE')
    for row in service.get('ports', []):
        if isinstance(row, str):
            address, separator, protocol = row.partition('/')
            selected = address.split(':')
            if ((not separator or protocol == 'tcp') and len(selected) in (2, 3)
                    and (len(selected) == 2 or selected[0] in ('', '0.0.0.0', '127.0.0.1'))
                    and selected[-2].isdigit()):
                published.add(int(selected[-2]))
        elif (isinstance(row, dict) and str(row.get('published', '')).isdigit()
              and row.get('protocol', 'tcp') == 'tcp'
              and row.get('host_ip', '') in ('', '0.0.0.0', '127.0.0.1')):
            published.add(int(row['published']))
    need(parts.port in published, 'ONBOARDING_APPLICATION_PROBE_NOT_PUBLISHED_BY_SERVICE')
    return value


def image_identity(value):
    need(isinstance(value, str) and value and not any(c.isspace() for c in value),
         'ONBOARDING_PUBLIC_IMAGE_INVALID')
    repository, separator, suffix = value.partition('@')
    if separator and ':' in repository.rsplit('/', 1)[-1]:
        repository = repository.rsplit(':', 1)[0]
    if not separator:
        last = repository.rsplit('/', 1)[-1]
        repository, _, suffix = repository.rpartition(':') if ':' in last else (repository, '', 'latest')
        separator = ':'
    first, slash, rest = repository.partition('/')
    if not slash:
        repository = 'docker.io/library/' + repository
    elif first == 'index.docker.io':
        repository = 'docker.io/' + rest
    elif first != 'localhost' and '.' not in first and ':' not in first:
        repository = 'docker.io/' + repository
    if repository.startswith('docker.io/') and '/' not in repository[len('docker.io/'):]:
        repository = 'docker.io/library/' + repository[len('docker.io/'):]
    return repository + separator + suffix


def image_repository_identity(value):
    normalized = image_identity(value)
    return normalized.rsplit('@', 1)[0] if '@' in normalized else normalized.rsplit(':', 1)[0]


class Engine:
    def __init__(self, layout, runner=None, store=None):
        self.layout, self.store = layout, store or Store()
        self.runner = runner or Runner(layout)

    @contextmanager
    def operation(self):
        """Serialize onboarding jobs without holding either worker's run.lock."""
        import fcntl
        self.store.directory(self.layout.state, 0, 0, 0o700, create=True)
        path = self.store.safe(self.layout.state / '.operation.lock')
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
                 and stat.S_IMODE(info.st_mode) == 0o600, 'ONBOARDING_LOCK_INVALID')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refused('ONBOARDING_OTHER_OPERATION_RUNNING') from None
            yield
        finally:
            os.close(fd)

    @contextmanager
    def locks(self):
        import fcntl
        opened = []
        try:
            for name in ('streams-aio-public-sync', 'streams-aio-dr'):
                path = self.layout.home / '.local/state' / name / 'run.lock'
                fd = os.open(self.store.safe(path), os.O_RDWR | os.O_NOFOLLOW)
                opened.append(fd)
                info = os.fstat(fd)
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'ONBOARDING_LOCK_INVALID')
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise Refused('ONBOARDING_OTHER_OPERATION_RUNNING') from None
            yield
        finally:
            for fd in reversed(opened):
                os.close(fd)

    def compose(self, *args):
        return self.runner.run(['docker', 'compose', '--project-directory', self.layout.root,
                               '-f', self.layout.root / 'docker-compose.yml', *args],
                              'ONBOARDING_COMPOSE_COMMAND_FAILED', timeout=300)

    def inspect(self, request):
        plan, service = plan_document(request.get('plan'))
        root = self.layout.root
        need(self.store.exists(root), 'ONBOARDING_STACK_NOT_FOUND')
        compose = self.store.snapshot(root / 'docker-compose.yml')
        result = merge_compose(compose.raw, plan)
        env_path = root / plan['public_env_path']
        private = root / plan['private_env_path']
        need(not self.store.exists(env_path) and not self.store.exists(private), 'ONBOARDING_OUTPUT_EXISTS')
        project, environment = request.get('project_id', ''), request.get('environment', '')
        agent, agent_result = None, None
        if plan['private_bindings']:
            agent = self.store.snapshot(self.layout.agent)
            need(agent.uid == 0 and agent.mode in (0o600, 0o640)
                 and not ACL_ATTRIBUTES & set(agent.attributes), 'ONBOARDING_AGENT_PERMISSIONS_INVALID')
            self.store.directory(root / '.secrets', 0, self.layout.gid, 0o750)
            agent_result = extend_agent(agent.raw, root, plan, project, environment)
            props = self.runner.props(AGENT_UNIT)
            need(props.get('ActiveState') == 'active' and props.get('User') in ('', 'root')
                 and props.get('Group') in (str(self.layout.gid), self.layout.user)
                 and props.get('UMask') == '0027' and props.get('KillMode') == 'control-group',
                 'ONBOARDING_AGENT_SERVICE_REVIEW_REQUIRED')
            need(str(self.layout.agent) in props.get('ExecStart', '') and
                 not any(props.get(key, '').strip() for key in ('ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost')),
                 'ONBOARDING_AGENT_SERVICE_REVIEW_REQUIRED')
        health_probe = probe_url(request.get('probe_url', ''), service)
        source = dict(root=str(root), owner=self.layout.user, plan=plan, project=project,
                      environment=environment, probe_url=health_probe, compose=compose.identity(),
                      agent=agent.identity() if agent else None,
                      machine=digest(self.store.read(PurePosixPath('/etc/machine-id'), 256)))
        return dict(schema=1, status='PREVIEW', fingerprint=digest(canonical_json(source)),
                    service=plan['service_name'], image=plan['image'], stack_root=str(root),
                    public_files=[plan['public_env_path'], 'docker-compose.yml'],
                    private_env=plan['private_env_path'] if plan['private_bindings'] else None,
                    private_keys=sorted(plan['private_bindings']), project_id=project, environment=environment,
                    application_probe=health_probe or 'Docker HEALTHCHECK required',
                    _plan=plan, _service=service, _compose=compose, _compose_result=result,
                    _agent=agent, _agent_result=agent_result)

    def journal_path(self, job):
        need(isinstance(job, str) and JOB.fullmatch(job), 'ONBOARDING_JOB_INVALID')
        self.store.directory(self.layout.state, 0, 0, 0o700, create=True)
        return self.layout.state / (job + '.json')

    def safe_result(self, journal, status=None):
        return dict(schema=1, status=status or journal['phase'], job_id=journal['job_id'],
                    service=journal['plan']['service_name'], phase=journal['phase'],
                    public_commit=journal.get('public_commit'), backup_tag=journal.get('backup_tag'),
                    application_verified=journal.get('application_verified', False),
                    backup_integrity_verified=journal.get('backup_integrity_verified', False),
                    agent_archive_contents_verified=False)

    def save(self, journal):
        self.store.save(self.journal_path(journal['job_id']), journal)

    def generated_env(self, plan, timeout=150):
        target = self.layout.root / plan['private_env_path']
        for _ in range(max(1, timeout // 2)):
            if self.store.exists(target):
                item = self.store.snapshot(target)
                need(item.uid == 0 and item.gid == self.layout.gid and item.mode == 0o640
                     and 'system.posix_acl_access' not in item.attributes,
                     'ONBOARDING_PRIVATE_OUTPUT_PERMISSIONS_INVALID')
                # Only the precise, single-quoted legacy template format is
                # accepted. Missing-source Agent renders often produce KEY='';
                # a healthy application must never make that a valid linkage.
                rows = item.raw.decode('utf-8').splitlines()
                matches = [re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)='([^'\r\n]*)'", row) for row in rows]
                valid = rows and all(matches)
                names = [match[1] for match in matches] if valid else []
                if (valid and len(names) == len(set(names)) and set(names) == set(plan['private_bindings'])
                        and all(match[2] and not match[2].endswith('\\')
                                and not any(ord(c) < 32 for c in match[2]) for match in matches)):
                    return item
            self.runner.sleep(2)
        raise Refused('ONBOARDING_AGENT_RENDER_FAILED')

    def health(self, journal):
        service = journal['plan']['service_name']
        stable = 0
        for _ in range(90):
            ids = self.compose('ps', '-a', '-q', '--', service).decode().split()
            need(len(ids) <= 1 and all(re.fullmatch(r'[0-9a-f]{12,64}', value) for value in ids),
                 'ONBOARDING_CONTAINER_ID_INVALID')
            if ids:
                state = load_json(self.runner.run(['docker', 'inspect', '--format', '{{json .State}}', ids[0]],
                                                 'ONBOARDING_CONTAINER_INSPECT_FAILED'))
                need(isinstance(state, dict) and not state.get('OOMKilled'), 'ONBOARDING_CONTAINER_FAILED')
                if state.get('Status') in ('exited', 'dead'):
                    raise Refused('ONBOARDING_CONTAINER_FAILED')
                health = state.get('Health')
                if isinstance(health, dict):
                    if health.get('Status') == 'healthy' and state.get('Status') == 'running':
                        return
                elif journal.get('probe_url'):
                    stable = stable + 1 if state.get('Status') == 'running' and self.runner.probe(journal['probe_url']) else 0
                    if stable >= 3:
                        return
                elif state.get('Status') == 'running':
                    raise Refused('ONBOARDING_APPLICATION_PROBE_REQUIRED')
            self.runner.sleep(2)
        raise Refused('ONBOARDING_APPLICATION_HEALTH_TIMEOUT')

    def rollback(self, journal):
        complete = True
        try:
            if journal.get('agent_changed'):
                self.runner.run(['systemctl', 'stop', AGENT_UNIT], 'ONBOARDING_AGENT_STOP_FAILED')
            for name in reversed(journal['outputs']):
                output = journal['outputs'][name]
                target = PurePosixPath(output['path'])
                if not self.store.exists(target):
                    if output.get('before'):
                        complete = False
                    continue
                current = self.store.snapshot(target)
                if digest(current.raw) == output['expected']:
                    if output.get('before'):
                        old = Snapshot.restore(output['before'])
                        self.store.write(target, old.raw, old.uid, old.gid, old.mode, current,
                                         public=name in ('compose', 'public_env'))
                    else:
                        self.store.unlink(target, output['expected'])
                elif not output.get('before') or digest(current.raw) != output['before']['sha256']:
                    complete = False
            if journal.get('private_output'):
                value = journal['private_output']
                if self.store.exists(PurePosixPath(value['path'])):
                    self.store.unlink(PurePosixPath(value['path']), value['sha256'])
            elif journal['plan']['private_bindings'] and self.store.exists(self.layout.root / journal['plan']['private_env_path']):
                complete = False  # Unknown partial output is retained for review.
        except Exception:
            complete = False
        finally:
            if journal.get('agent_changed'):
                try:
                    self.runner.run(['systemctl', 'start', AGENT_UNIT], 'ONBOARDING_AGENT_RESTART_FAILED')
                except Exception:
                    complete = False
        return complete

    def apply(self, request):
        with self.operation():
            return self._apply(request)

    def request_identity(self, request):
        plan, _ = plan_document(request.get('plan'))
        return digest(canonical_json(dict(plan=plan, fingerprint=request.get('fingerprint'),
                                         project_id=request.get('project_id', ''),
                                         environment=request.get('environment', ''),
                                         probe_url=request.get('probe_url', ''))))

    def _apply(self, request):
        job = request.get('job_id') or uuid.uuid4().hex
        path = self.journal_path(job)
        if self.store.exists(path):
            journal = self.store.json(path)
            need(journal.get('root') == str(self.layout.root) and journal.get('owner') == self.layout.user,
                 'ONBOARDING_JOB_SCOPE_MISMATCH')
            need(journal.get('request_identity') == self.request_identity(request),
                 'ONBOARDING_JOB_PLAN_MISMATCH')
            need(journal['phase'] in ('SERVICE_READY', 'PUBLIC_PUBLISHED', 'BACKUP_RUNNING', 'COMPLETE'),
                 'ONBOARDING_INTERRUPTED_REVIEW_REQUIRED')
            self.unchanged(journal)
            if journal['phase'] == 'COMPLETE':
                self.health(journal)
            return self.safe_result(journal)
        with self.locks():
            preview = self.inspect(request)
            need(request.get('fingerprint') == preview['fingerprint'], 'ONBOARDING_PREVIEW_STALE')
            plan = preview['_plan']
            journal = dict(schema=1, job_id=job, root=str(self.layout.root), owner=self.layout.user,
                           plan=plan, fingerprint=preview['fingerprint'], phase='PREPARED',
                           request_identity=self.request_identity(request),
                           probe_url=request.get('probe_url', ''), outputs={}, agent_changed=False)
            for name, target, raw, before in (
                ('compose', self.layout.root / 'docker-compose.yml', preview['_compose_result'], preview['_compose']),
                ('public_env', self.layout.root / plan['public_env_path'], plan['public_env_text'].encode(), None),
                ('agent', self.layout.agent, preview['_agent_result'], preview['_agent'])):
                if raw is not None:
                    journal['outputs'][name] = dict(path=str(target), expected=digest(raw), before=before.saved() if before else None)
            self.save(journal)
            try:
                data = self.layout.root / 'data'
                # Never change permissions of existing application data directories.
                need(self.store.exists(data), 'ONBOARDING_DATA_DIRECTORY_MISSING')
                self.store.directory(data / plan['service_name'], self.layout.uid, self.layout.gid, 0o750,
                                     create=not self.store.exists(data / plan['service_name']), public=True)
                item = self.store.write(self.layout.root / plan['public_env_path'], plan['public_env_text'].encode(),
                                        self.layout.uid, self.layout.gid, 0o640, public=True)
                journal['outputs']['public_env']['after'] = item.identity()
                old = preview['_compose']
                item = self.store.write(self.layout.root / 'docker-compose.yml', preview['_compose_result'],
                                        old.uid, old.gid, old.mode, old, public=True)
                journal['outputs']['compose']['after'] = item.identity()
                if preview['_agent_result'] is not None:
                    journal['agent_changed'] = True
                    self.save(journal)
                    old = preview['_agent']
                    item = self.store.write(self.layout.agent, preview['_agent_result'], old.uid, old.gid, old.mode, old)
                    journal['outputs']['agent']['after'] = item.identity()
                    self.runner.run(['systemctl', 'restart', AGENT_UNIT], 'ONBOARDING_AGENT_RESTART_FAILED')
                    item = self.generated_env(plan)
                    journal['private_output'] = dict(path=item.path, sha256=digest(item.raw))
                journal['phase'] = 'FILES_WRITTEN'
                self.save(journal)
                self.compose('config', '--quiet')
                self.compose('pull', '--', plan['service_name'])
                volumes = load_json(self.runner.run(['docker', 'image', 'inspect', '--format',
                                                      '{{json .Config.Volumes}}', plan['image']],
                                                     'ONBOARDING_IMAGE_METADATA_FAILED'))
                need(volumes in (None, {}), 'ONBOARDING_PERSISTENT_DATA_COVERAGE_REQUIRED')
                journal['phase'] = 'START_ATTEMPTED'
                self.save(journal)
                self.compose('up', '-d', '--no-deps', '--pull', 'missing', '--', plan['service_name'])
                self.health(journal)
                journal['phase'], journal['application_verified'] = 'SERVICE_READY', True
                self.save(journal)
                return self.safe_result(journal)
            except Exception as error:
                code = str(error) if isinstance(error, Refused) else 'ONBOARDING_APPLY_FAILED'
                if journal['phase'] != 'START_ATTEMPTED':
                    journal['phase'] = 'ROLLED_BACK' if self.rollback(journal) else 'REVIEW_REQUIRED'
                else:
                    journal['phase'] = 'REVIEW_REQUIRED'
                journal['failure_code'] = code
                self.save(journal)
                return dict(self.safe_result(journal, 'REFUSED'), code=code)

    def unchanged(self, journal):
        for name, output in journal['outputs'].items():
            item = self.store.snapshot(PurePosixPath(output['path']))
            expected = output.get('after')
            need(digest(item.raw) == output['expected'] and isinstance(expected, dict)
                 and (item.uid, item.gid) == (expected['uid'], expected['gid'])
                 and (item.mode & ~0o070 == expected['mode'] & ~0o070
                      if name in ('compose', 'public_env') else item.mode == expected['mode'])
                 and {key: digest(value) for key, value in item.attributes.items()
                      if name == 'agent' or key not in ACL_ATTRIBUTES} ==
                     {key: value for key, value in expected['attributes'].items()
                      if name == 'agent' or key not in ACL_ATTRIBUTES},
                 'ONBOARDING_INSTALLED_FILES_CHANGED')
        if journal.get('private_output'):
            item = self.generated_env(journal['plan'], 2)
            # A legitimate secret rotation may change the generated bytes. Its
            # expected names and private permissions remain the invariant.
            need(item.mode == 0o640, 'ONBOARDING_PRIVATE_OUTPUT_PERMISSIONS_INVALID')

    def github_file(self, repository, path, commit):
        value = self.runner.api('repos/' + repository + '/contents/' + path + '?ref=' + commit)
        need(value.get('encoding') == 'base64' and isinstance(value.get('content'), str),
             'ONBOARDING_PUBLIC_READBACK_FAILED')
        return base64.b64decode(value['content'], validate=False)

    def public_readback(self, journal, commit):
        need(isinstance(commit, str) and SHA.fullmatch(commit), 'ONBOARDING_PUBLIC_RECEIPT_INVALID')
        plan = journal['plan']
        compose = yaml_document(self.github_file(PUBLIC, 'docker-compose.yml', commit))
        service = compose.get('services', {}).get(plan['service_name'])
        need(isinstance(service, dict), 'ONBOARDING_PUBLIC_SERVICE_MISSING')
        expected = yaml_document('services:\n' + plan['compose_fragment'])['services'][plan['service_name']]
        observed = dict(service)
        expected = dict(expected)
        observed['image'], expected['image'] = image_identity(observed.get('image')), image_identity(expected['image'])
        for selected in (observed, expected):
            rows = selected.get('env_file') or []
            need(isinstance(rows, list) and all(isinstance(row, str) for row in rows),
                 'ONBOARDING_PUBLIC_READBACK_FAILED')
            selected['env_file'] = [row.removeprefix('./') for row in rows]
        need(observed == expected, 'ONBOARDING_PUBLIC_SERVICE_READBACK_FAILED')
        env_files = service.get('env_file') or []
        need(isinstance(env_files, list) and all(isinstance(p, str) for p in env_files),
             'ONBOARDING_PUBLIC_READBACK_FAILED')
        need([p.removeprefix('./') for p in env_files] == [plan['public_env_path']] +
             ([plan['private_env_path']] if plan['private_bindings'] else []), 'ONBOARDING_PUBLIC_READBACK_FAILED')
        need(self.github_file(PUBLIC, plan['public_env_path'], commit).decode() == plan['public_env_text'],
             'ONBOARDING_PUBLIC_ENV_READBACK_FAILED')
        image_lock = load_json(self.github_file(PUBLIC, 'config/image-lock.json', commit))
        selected_image = image_lock.get(plan['service_name'], {})
        pinned = selected_image.get('image', '')
        identity = image_identity(pinned)
        need('@sha256:' in identity and re.fullmatch(r'[0-9a-f]{64}', identity.rsplit('@sha256:', 1)[1])
             and identity.rsplit('@', 1)[0] == image_repository_identity(plan['image'])
             and image_identity(selected_image.get('configured_image')) == image_identity(plan['image']),
             'ONBOARDING_PUBLIC_IMAGE_LOCK_INVALID')
        override = yaml_document(self.github_file(PUBLIC, 'config/compose.dr.yaml', commit))
        need(override.get('services', {}).get(plan['service_name'], {}).get('image') == pinned,
             'ONBOARDING_PUBLIC_IMAGE_LOCK_INVALID')
        if plan['private_bindings']:
            mapping = load_json(self.github_file(PUBLIC, 'config/dr-render-plan.json', commit))
            selected = mapping.get('env_files', {}).get(plan['private_env_path'])
            expected = {key: {'path': value['folder'], 'key': value['key']}
                        for key, value in plan['private_bindings'].items()}
            if selected is not None:
                need(selected == expected, 'ONBOARDING_DR_MAPPING_READBACK_FAILED')
            else:
                # Seamless export intentionally does not invent Infisical
                # mappings. GUI 0.4.19 restores the encrypted Agent first and
                # waits for these explicitly inventoried targets before Compose.
                layout = load_json(self.github_file(PUBLIC, 'config/public-stack-layout.json', commit))
                manifest = yaml_document(self.github_file(PUBLIC, 'config/dr-manifest.yaml', commit))
                component = manifest.get('components', {}).get(plan['service_name'], {})
                target = plan['private_env_path']
                references = [row for row in manifest.get('references', [])
                              if row.get('SERVICE') == plan['service_name'] and row.get('SOURCE') == target]
                need(layout.get('schema') == 1 and plan['service_name'] in layout.get('services', [])
                     and target in layout.get('private_env_targets', [])
                     and target in layout.get('private_env_targets_from_restored_agent', [])
                     and target in component.get('GENERATED_FILES', [])
                     and target in component.get('REQUIRED_BEFORE_COMPOSE_UP', [])
                     and plan['public_env_path'] in component.get('PUBLIC_REPO_FILES', [])
                     and len(references) == 1 and references[0].get('TYPE') == 'ENV_FILE'
                     and references[0].get('RESTORE_METHOD') == 'INFISICAL_AGENT_RENDER'
                     and references[0].get('RESOLVED') is True,
                     'ONBOARDING_DR_MAPPING_READBACK_FAILED')

    def finalize(self, request):
        with self.operation():
            return self._finalize(request)

    def _finalize(self, request):
        path = self.journal_path(request.get('job_id'))
        journal = self.store.json(path)
        need(journal.get('root') == str(self.layout.root) and journal.get('owner') == self.layout.user,
             'ONBOARDING_JOB_SCOPE_MISMATCH')
        if journal['phase'] == 'COMPLETE':
            self.unchanged(journal)
            self.health(journal)
            return self.safe_result(journal)
        need(journal['phase'] in ('SERVICE_READY', 'PUBLIC_PUBLISHED', 'BACKUP_RUNNING'),
             'ONBOARDING_SERVICE_NOT_VERIFIED')
        self.unchanged(journal)
        if journal['phase'] == 'SERVICE_READY':
            home = self.layout.home
            worker = home / '.local/share/streams-aio-public-sync'
            self.runner.run([worker / 'venv/bin/python', '-B', worker / 'tooling/scripts/sync-public-stack.py',
                             '--source', self.layout.root, '--state', home / '.local/state/streams-aio-public-sync',
                             '--seamless', '--publish'], 'ONBOARDING_PUBLIC_SYNC_FAILED', timeout=900, user=True)
            receipt = load_json(self.store.read(home / '.local/state/streams-aio-public-sync/current.json'))
            need(receipt.get('repository') == PUBLIC and receipt.get('verified') is True,
                 'ONBOARDING_PUBLIC_RECEIPT_INVALID')
            self.public_readback(journal, receipt.get('commit'))
            journal['public_commit'], journal['phase'] = receipt['commit'], 'PUBLIC_PUBLISHED'
            self.save(journal)
        if journal['phase'] == 'PUBLIC_PUBLISHED':
            props = self.runner.props(DR_UNIT)
            expected = str(self.layout.home / 'streams-aio-dr/scripts/update-dr.sh')
            need(props.get('ActiveState') in ('inactive', 'failed') and props.get('User') == self.layout.user
                 and expected in props.get('ExecStart', ''), 'ONBOARDING_DR_SERVICE_REVIEW_REQUIRED')
            releases = self.runner.api('repos/' + PRIVATE + '/releases?per_page=100')
            need(isinstance(releases, list), 'ONBOARDING_RELEASE_LIST_INVALID')
            journal.update(phase='BACKUP_RUNNING', backup_before_invocation=props.get('InvocationID', ''),
                           backup_before_tags=[row.get('tag_name') for row in releases],
                           backup_requested_at=self.runner.now().isoformat().replace('+00:00', 'Z'))
            self.save(journal)
            self.runner.run(['systemctl', 'start', '--no-block', DR_UNIT], 'ONBOARDING_DR_START_FAILED')
            return self.safe_result(journal)
        props = self.runner.props(DR_UNIT)
        if props.get('ActiveState') in ('activating', 'active'):
            return self.safe_result(journal)
        need(props.get('ActiveState') == 'inactive' and props.get('Result') == 'success'
             and props.get('ExecMainStatus') == '0' and props.get('InvocationID')
             and props['InvocationID'] != journal['backup_before_invocation'], 'ONBOARDING_DR_BACKUP_FAILED')
        releases = self.runner.api('repos/' + PRIVATE + '/releases?per_page=100')
        boundary = dt.datetime.fromisoformat(journal['backup_requested_at'].replace('Z', '+00:00'))
        selected = []
        for row in releases:
            tag = row.get('tag_name', '')
            if (isinstance(tag, str) and re.fullmatch(r'dr-[0-9]{8}T[0-9]{6}Z', tag)
                    and tag not in journal['backup_before_tags'] and not row.get('draft') and not row.get('prerelease')
                    and row.get('body', '').splitlines()[:1] == ['streams-aio-dr-managed:v1']
                    and dt.datetime.fromisoformat(row['published_at'].replace('Z', '+00:00')) > boundary):
                selected.append(row)
        need(bool(selected), 'ONBOARDING_NEW_BACKUP_NOT_FOUND')
        release = sorted(selected, key=lambda row: row['tag_name'], reverse=True)[0]
        assets = release.get('assets', [])
        need(len(assets) == 8 and {row.get('name') for row in assets} == FILES
             and all(row.get('state') == 'uploaded' for row in assets), 'ONBOARDING_BACKUP_ASSETS_INVALID')
        # Download and hash every encrypted asset. Plaintext identities are never
        # present on this VM; archive content decryption is a separate offline test.
        downloads = {}
        for row in assets:
            need(type(row.get('size')) is int and 0 < row['size'] <= 1024**3 and type(row.get('id')) is int,
                 'ONBOARDING_BACKUP_ASSETS_INVALID')
            endpoint = 'repos/' + PRIVATE + '/releases/assets/' + str(row['id'])
            if row['name'] in ASSETS:
                item = self.runner.asset_digest(endpoint, row['size'])
                need(item['prefix'].startswith(b'age-encryption.org/v1\n'), 'ONBOARDING_BACKUP_NOT_ENCRYPTED')
                downloads[row['name']] = {key: item[key] for key in ('sha256', 'size')}
                continue
            need(row['size'] <= MAX_FILE, 'ONBOARDING_BACKUP_ASSETS_INVALID')
            raw = self.runner.api(endpoint, binary=True)
            need(len(raw) == row['size'], 'ONBOARDING_BACKUP_ASSET_SIZE_INVALID')
            downloads[row['name']] = {'sha256': digest(raw), 'size': len(raw)}
            if row['name'] == 'manifest.json':
                manifest = load_json(raw)
            elif row['name'] == 'SHA256SUMS':
                sums_raw = raw
        need(manifest.get('schema') == 2 and manifest.get('repository') == PRIVATE
             and manifest.get('encryption') == 'age' and release['tag_name'] == 'dr-' + manifest.get('run', '')
             and set(manifest.get('artifacts', {})) == ASSETS, 'ONBOARDING_BACKUP_MANIFEST_INVALID')
        need(all(manifest['artifacts'][name] == downloads[name] for name in ASSETS),
             'ONBOARDING_BACKUP_CHECKSUM_MISMATCH')
        sums = {}
        for line in sums_raw.decode('ascii').splitlines():
            match = re.fullmatch(r'([0-9a-f]{64}) [ *]([A-Za-z0-9_.-]+)', line)
            need(match is not None and match[2] not in sums, 'ONBOARDING_BACKUP_CHECKSUM_INVALID')
            sums[match[2]] = match[1]
        need(set(sums) == ASSETS | {'manifest.json'} and
             all(downloads[name]['sha256'] == value for name, value in sums.items()),
             'ONBOARDING_BACKUP_CHECKSUM_MISMATCH')
        commit = manifest.get('stack_commit')
        need(isinstance(commit, str) and SHA.fullmatch(commit), 'ONBOARDING_BACKUP_STACK_COMMIT_INVALID')
        comparison = self.runner.api('repos/' + PUBLIC + '/compare/' + journal['public_commit'] + '...' + commit)
        need(comparison.get('status') in ('ahead', 'identical') and comparison.get('behind_by') == 0,
             'ONBOARDING_BACKUP_PUBLIC_COMMIT_MISMATCH')
        self.public_readback(journal, commit)
        self.unchanged(journal)
        self.health(journal)
        journal.update(phase='COMPLETE', backup_tag=release['tag_name'], backup_stack_commit=commit,
                       backup_integrity_verified=True, backup_assets=downloads)
        self.save(journal)
        return self.safe_result(journal)


def handle(request, runner=None, store=None, layout=None):
    job = request.get('job_id') if isinstance(request, dict) else None
    try:
        need(isinstance(request, dict) and request.get('action') in ('inspect', 'apply', 'finalize', 'status'),
             'ONBOARDING_REQUEST_INVALID')
        layout = layout or Layout.production(request.get('root'))
        engine = Engine(layout, runner, store)
        action = request['action']
        if action == 'inspect':
            with engine.locks():
                result = engine.inspect(request)
            return {key: value for key, value in result.items() if not key.startswith('_')}
        if action == 'apply':
            return engine.apply(request)
        if action == 'status':
            journal = engine.store.json(engine.journal_path(job))
            need(journal.get('root') == str(layout.root), 'ONBOARDING_JOB_SCOPE_MISMATCH')
            return engine.safe_result(journal)
        return engine.finalize(request)
    except Exception as error:
        code = str(error) if isinstance(error, Refused) else 'ONBOARDING_OPERATION_FAILED'
        return dict(schema=1, status='REFUSED', code=code, **({'job_id': job} if isinstance(job, str) and JOB.fullmatch(job) else {}))


def main():
    try:
        raw = sys.stdin.buffer.read(2 * MAX_FILE + 1)
        need(len(raw) <= 2 * MAX_FILE, 'ONBOARDING_REQUEST_TOO_LARGE')
        result = handle(load_json(raw))
    except Exception:
        result = dict(schema=1, status='REFUSED', code='ONBOARDING_REQUEST_INVALID')
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())

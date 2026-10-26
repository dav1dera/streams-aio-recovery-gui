"""Prepare existing VM tooling through bounded fast-forward updates only.

No package installation, application lifecycle command or source-stack mutation
is part of this operation. Authentication is inherited from the reviewed runner.
"""
from contextlib import contextmanager
import ast
import hashlib
import os
from pathlib import PurePosixPath
import re
import stat
import tempfile

PUBLIC_REPOSITORY = 'dav1dera/streams-aio-sanitized'
DR_REPOSITORY = 'dav1dera/streams-aio-dr'
PUBLIC_MINIMUM_COMMIT = '7d1e89c230618136cdb46d581f143ba52e226ed7'
DR_MINIMUM_COMMIT = 'd6addeda5ec936cf007d3bec020343330eb7b8cb'
PUBLIC_API_VERSION = 1
PRODUCER_SOURCES = ('install-service-resources.sh', 'service_snapshot.py',
                    'snapshot-services.py', 'streams-aio-services-dr-backup')
PRODUCER = PurePosixPath('/usr/local/sbin/streams-aio-services-dr-backup')
PRODUCER_MODULES = (PurePosixPath('/usr/local/lib/streams-aio-dr/service_snapshot.py'),
                    PurePosixPath('/usr/local/lib/streams-aio-dr/snapshot-services.py'))
MAX_SOURCE = 4 * 1024 * 1024
SHA = re.compile(r'[0-9a-f]{40}\Z')


class ToolingFailure(ValueError):
    """Only a closed code may leave the tooling updater."""


def need(value, code):
    if not value:
        raise ToolingFailure(code)


def _run(runner, args, code, *, user=True, timeout=300):
    try:
        raw = runner.run(args, code, user=user, timeout=timeout)
    except Exception:
        raise ToolingFailure(code) from None
    need(isinstance(raw, bytes) and len(raw) <= MAX_SOURCE, code)
    return raw


def _git(runner, repository, *args, code='ONBOARDING_TOOLING_GIT_FAILED'):
    # Repository hooks and fsmonitor are not part of an update of these tools.
    return _run(runner, ['git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
        '-c', 'submodule.recurse=false', '-C', repository, *args], code)


def _text(raw, code):
    try:
        return raw.decode('utf-8').strip()
    except UnicodeError:
        raise ToolingFailure(code) from None


@contextmanager
def _tooling_locks(layout, store):
    import fcntl
    opened = []
    try:
        for worker in ('streams-aio-dr', 'streams-aio-public-sync'):
            path = layout.home / '.local/state' / worker / 'run.lock'
            try:
                target = store.safe(path)
                fd = os.open(target, os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0))
            except Exception:
                raise ToolingFailure('ONBOARDING_TOOLING_LOCK_INVALID') from None
            opened.append(fd)
            try:
                info = os.fstat(fd)
            except OSError:
                raise ToolingFailure('ONBOARDING_TOOLING_LOCK_INVALID') from None
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                 and info.st_uid in (0, layout.uid) and not info.st_mode & 0o002,
                 'ONBOARDING_TOOLING_LOCK_INVALID')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ToolingFailure('ONBOARDING_OTHER_OPERATION_RUNNING') from None
            except OSError:
                raise ToolingFailure('ONBOARDING_TOOLING_LOCK_INVALID') from None
        yield
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _repository(layout, runner, store, path, repository, *, main_required=False):
    try:
        store.directory(path, layout.uid, layout.gid, 0o750, public=True)
        store.directory(path / '.git', layout.uid, layout.gid, 0o750, public=True)
    except Exception:
        raise ToolingFailure('ONBOARDING_TOOLING_REPOSITORY_INVALID') from None
    need(_text(_git(runner, path, 'rev-parse', '--show-toplevel'),
               'ONBOARDING_TOOLING_REPOSITORY_INVALID') == str(path), 'ONBOARDING_TOOLING_REPOSITORY_INVALID')
    origins = _text(_git(runner, path, 'remote', 'get-url', '--all', 'origin'),
                    'ONBOARDING_TOOLING_ORIGIN_INVALID').splitlines()
    allowed = {'https://github.com/' + repository, 'https://github.com/' + repository + '.git',
               'git@github.com:' + repository, 'git@github.com:' + repository + '.git'}
    need(len(origins) == 1 and origins[0] in allowed, 'ONBOARDING_TOOLING_ORIGIN_INVALID')
    need(not _git(runner, path, 'status', '--porcelain'), 'ONBOARDING_TOOLING_LOCAL_CHANGES')
    if main_required:
        need(_text(_git(runner, path, 'rev-parse', '--abbrev-ref', 'HEAD'),
                   'ONBOARDING_TOOLING_BRANCH_INVALID') == 'main', 'ONBOARDING_TOOLING_BRANCH_INVALID')
    head = _text(_git(runner, path, 'rev-parse', 'HEAD'), 'ONBOARDING_TOOLING_GIT_FAILED')
    need(SHA.fullmatch(head), 'ONBOARDING_TOOLING_GIT_FAILED')
    return head


def _fetch(runner, path, before, *, minimum=None):
    _git(runner, path, 'fetch', '--no-tags', '--no-recurse-submodules', 'origin',
         'refs/heads/main:refs/remotes/origin/main', code='ONBOARDING_TOOLING_FETCH_FAILED')
    target = _text(_git(runner, path, 'rev-parse', 'refs/remotes/origin/main'), 'ONBOARDING_TOOLING_GIT_FAILED')
    need(SHA.fullmatch(target), 'ONBOARDING_TOOLING_GIT_FAILED')
    _git(runner, path, 'merge-base', '--is-ancestor', before, target, code='ONBOARDING_TOOLING_DIVERGED')
    if minimum is not None:
        need(isinstance(minimum, str) and SHA.fullmatch(minimum), 'ONBOARDING_TOOLING_SOURCE_TOO_OLD')
        _git(runner, path, 'merge-base', '--is-ancestor', minimum, target, code='ONBOARDING_TOOLING_SOURCE_TOO_OLD')
    return target


def _api_source(raw):
    try:
        tree = ast.parse(raw.decode('utf-8'))
    except (UnicodeError, SyntaxError, ValueError):
        raise ToolingFailure('ONBOARDING_TOOLING_SOURCE_TOO_OLD') from None
    marker = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                and target.id == 'PUBLIC_ONBOARDING_PREFLIGHT' for target in node.targets):
            marker.append(node.value.value if isinstance(node.value, ast.Constant) else None)
        elif (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
                and node.target.id == 'PUBLIC_ONBOARDING_PREFLIGHT'):
            marker.append(node.value.value if isinstance(node.value, ast.Constant) else None)
    need(len(marker) == 1 and type(marker[0]) is int and marker[0] == PUBLIC_API_VERSION,
         'ONBOARDING_TOOLING_SOURCE_TOO_OLD')
    need(any(isinstance(node, ast.FunctionDef) and node.name == 'preflight' for node in tree.body),
         'ONBOARDING_TOOLING_SOURCE_TOO_OLD')


def _merge(runner, path, before, target):
    need(_text(_git(runner, path, 'rev-parse', 'HEAD'), 'ONBOARDING_TOOLING_GIT_FAILED') == before,
         'ONBOARDING_TOOLING_SOURCE_CHANGED')
    need(not _git(runner, path, 'status', '--porcelain'), 'ONBOARDING_TOOLING_LOCAL_CHANGES')
    _git(runner, path, 'merge', '--ff-only', target, code='ONBOARDING_TOOLING_MERGE_FAILED')
    need(_text(_git(runner, path, 'rev-parse', 'HEAD'), 'ONBOARDING_TOOLING_GIT_FAILED') == target,
         'ONBOARDING_TOOLING_SOURCE_CHANGED')
    need(not _git(runner, path, 'status', '--porcelain'), 'ONBOARDING_TOOLING_LOCAL_CHANGES')


def _producer_ready(store):
    files = (PRODUCER, *PRODUCER_MODULES)
    if not all(store.exists(path) for path in files): return False
    try:
        for path in files:
            item = store.snapshot(path)
            need(item.uid == 0 and not item.mode & 0o022, 'ONBOARDING_TOOLING_PRODUCER_INVALID')
            if path == PRODUCER:
                need(bool(item.mode & 0o111), 'ONBOARDING_TOOLING_PRODUCER_INVALID')
    except ToolingFailure:
        raise
    except Exception:
        raise ToolingFailure('ONBOARDING_TOOLING_PRODUCER_INVALID') from None
    return True


@contextmanager
def _root_staging(store, sources):
    """Execute only captured Git bytes from a private root-owned directory."""
    need(set(sources) == set(PRODUCER_SOURCES), 'ONBOARDING_TOOLING_SOURCE_CHANGED')
    with tempfile.TemporaryDirectory(prefix='streams-aio-tools-', dir='/run') as temporary:
        folder = PurePosixPath(temporary)
        store.directory(folder, 0, 0, 0o700)
        for name in PRODUCER_SOURCES:
            store.write(folder / name, sources[name], 0, 0, 0o600)
        yield folder


def _prepare_tooling(layout, runner, store, request):
    """Update existing trusted tooling and the optional root backup producer."""
    need(isinstance(request, dict) and request.get('verification_scope', 'full') == 'full',
         'ONBOARDING_TOOLING_SCOPE_REFUSED')
    need(re.fullmatch(r'/home/[a-z_][a-z0-9_-]{0,31}', str(layout.home))
         and layout.home.name == layout.user and layout.root == layout.home / 'streams-aio'
         and type(layout.uid) is int and layout.uid > 0 and type(layout.gid) is int and layout.gid > 0,
         'ONBOARDING_TOOLING_REPOSITORY_INVALID')
    worker = layout.home / '.local/share/streams-aio-public-sync'
    public = worker / 'tooling'
    dr = layout.home / 'streams-aio-dr'
    with _tooling_locks(layout, store):
        needs_producer = not _producer_ready(store)
        if needs_producer:
            # The current reviewed installer manages pi's production pipeline.
            need(layout.user == 'pi', 'ONBOARDING_TOOLING_OWNER_UNSUPPORTED')
        public_before = _repository(layout, runner, store, public, PUBLIC_REPOSITORY)
        dr_before = _repository(layout, runner, store, dr, DR_REPOSITORY, main_required=True) if needs_producer else None
        public_target = _fetch(runner, public, public_before, minimum=PUBLIC_MINIMUM_COMMIT)
        api = _git(runner, public, 'show', public_target + ':scripts/public_export.py',
                   code='ONBOARDING_TOOLING_SOURCE_TOO_OLD')
        _api_source(api)
        dr_target = _fetch(runner, dr, dr_before, minimum=DR_MINIMUM_COMMIT) if needs_producer else None
        producer_sources = ({name: _git(runner, dr, 'show', dr_target + ':scripts/' + name,
                             code='ONBOARDING_TOOLING_SOURCE_TOO_OLD') for name in PRODUCER_SOURCES}
                            if needs_producer else None)
        _merge(runner, public, public_before, public_target)
        installed = store.snapshot(public / 'scripts/public_export.py')
        need(installed.uid in (0, layout.uid) and not installed.mode & 0o002
             and hashlib.sha256(installed.raw).digest() == hashlib.sha256(api).digest(),
             'ONBOARDING_TOOLING_SOURCE_CHANGED')
        program = ('import sys;sys.path.insert(0,sys.argv[1]);import yaml,public_export as p;'
                   'assert type(p.PUBLIC_ONBOARDING_PREFLIGHT) is int and p.PUBLIC_ONBOARDING_PREFLIGHT==1;'
                   'assert callable(p.preflight)')
        _run(runner, [worker / 'venv/bin/python', '-I', '-B', '-c', program, public / 'scripts'],
             'ONBOARDING_TOOLING_VERIFY_FAILED')
        if needs_producer:
            _merge(runner, dr, dr_before, dr_target)
            # The user-owned checkout is updated for future maintenance, but
            # root never executes its files. The staged bytes are the four
            # exact blobs captured from the verified Git revision above.
            with _root_staging(store, producer_sources) as staged:
                _run(runner, ['bash', staged / 'install-service-resources.sh'],
                     'ONBOARDING_TOOLING_INSTALL_FAILED', user=False)
            need(_producer_ready(store), 'ONBOARDING_TOOLING_PRODUCER_INVALID')
    return dict(schema=1, status='TOOLS_READY')

def prepare_tooling(layout, runner, store, request):
    """Return a safe result or a closed failure without filesystem excerpts."""
    try:
        return _prepare_tooling(layout, runner, store, request)
    except ToolingFailure:
        raise
    except Exception:
        raise ToolingFailure('ONBOARDING_TOOLING_VERIFY_FAILED') from None

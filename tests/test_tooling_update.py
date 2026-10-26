"""Bounded VM tool updates: no live host, repository or application access."""
from contextlib import contextmanager, nullcontext
from pathlib import PurePosixPath
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from remote import service_tooling as tooling


OLD = '1' * 40
NEW = '2' * 40
DR_OLD = '3' * 40
DR_NEW = '4' * 40
API = b'PUBLIC_ONBOARDING_PREFLIGHT = 1\ndef preflight(*args, **kwargs):\n    return {}\n'
INSTALLER = b'#!/bin/bash\n# fixed reviewed producer installer\n'
STAGE = PurePosixPath('/run/streams-aio-tools-test')
PRODUCER_SOURCES = {
    'install-service-resources.sh': INSTALLER,
    'service_snapshot.py': b'# trusted service snapshot implementation\n',
    'snapshot-services.py': b'# trusted snapshot command\n',
    'streams-aio-services-dr-backup': b'#!/bin/bash\n# trusted backup entry point\n',
}


def layout(user='pi'):
    home = PurePosixPath('/home') / user
    return SimpleNamespace(home=home, root=home / 'streams-aio', user=user, uid=1000, gid=1000)


class ToolStore:
    def __init__(self, scope, *, producer=True):
        self.scope = scope
        self.files = {}
        self.directories = set()
        self.refused = set()
        self.directory_calls = []
        self.public = scope.home / '.local/share/streams-aio-public-sync/tooling'
        self.dr = scope.home / 'streams-aio-dr'
        self.directories.update((self.public, self.public / '.git', self.dr, self.dr / '.git'))
        self.put(self.public / 'scripts/public_export.py', API, uid=scope.uid)
        self.put(self.dr / 'scripts/install-service-resources.sh', INSTALLER, uid=scope.uid, mode=0o755)
        if producer:
            self.install_producer()

    def put(self, path, raw=b'# existing trusted tooling\n', *, uid=0, gid=0, mode=0o644):
        self.files[PurePosixPath(path)] = SimpleNamespace(raw=raw, uid=uid, gid=gid, mode=mode)

    def install_producer(self):
        self.put(tooling.PRODUCER, mode=0o755)
        for path in tooling.PRODUCER_MODULES:
            self.put(path)

    def safe(self, path):
        path = PurePosixPath(path)
        if path in self.refused or not path.is_absolute() or '..' in path.parts:
            raise ValueError('synthetic symlink must never be followed')
        return path

    def exists(self, path):
        path = self.safe(path)
        return path in self.files or path in self.directories

    def snapshot(self, path):
        return self.files[self.safe(path)]

    def directory(self, path, uid, gid, mode, *, create=False, public=False):
        path = self.safe(path)
        self.directory_calls.append((path, uid, gid, mode, create, public))
        if create or path not in self.directories:
            raise ValueError('existing canonical directory required')


class ToolRunner:
    def __init__(self, store):
        self.store = store
        self.calls = []
        self.api = API
        self.installer = INSTALLER
        self.sources = dict(PRODUCER_SOURCES)
        self.diverged = set()
        self.fail_codes = set()
        self.import_programs = []
        self.repositories = {
            store.public: dict(head=OLD, target=NEW, branch='HEAD', dirty=b'',
                origin='https://github.com/' + tooling.PUBLIC_REPOSITORY),
            store.dr: dict(head=DR_OLD, target=DR_NEW, branch='main', dirty=b'',
                origin='git@github.com:' + tooling.DR_REPOSITORY + '.git'),
        }

    def run(self, args, code, *, user=True, timeout=300):
        argv = [str(arg) for arg in args]
        self.calls.append((argv, code, user, timeout))
        if code in self.fail_codes:
            raise RuntimeError('synthetic-private-error-value')
        if argv[0] == 'git':
            index = argv.index('-C')
            path = PurePosixPath(argv[index + 1])
            command = argv[index + 2:]
            repository = self.repositories[path]
            if command == ['rev-parse', '--show-toplevel']:
                return (str(path) + '\n').encode()
            if command == ['remote', 'get-url', '--all', 'origin']:
                return (repository['origin'] + '\n').encode()
            if command == ['status', '--porcelain']:
                return repository['dirty']
            if command == ['rev-parse', '--abbrev-ref', 'HEAD']:
                return (repository['branch'] + '\n').encode()
            if command == ['rev-parse', 'HEAD']:
                return (repository['head'] + '\n').encode()
            if command == ['rev-parse', 'refs/remotes/origin/main']:
                return (repository['target'] + '\n').encode()
            if command[0] == 'fetch':
                return b''
            if command[:2] == ['merge-base', '--is-ancestor']:
                if path in self.diverged:
                    raise RuntimeError('synthetic divergent repository')
                return b''
            if command[0] == 'show':
                if command[1] == repository['target'] + ':scripts/public_export.py':
                    return self.api
                prefix = repository['target'] + ':scripts/'
                if path == self.store.dr and command[1].startswith(prefix):
                    return self.sources[command[1][len(prefix):]]
            if command[:2] == ['merge', '--ff-only']:
                if command[2] != repository['target']:
                    raise AssertionError('only the captured remote commit may be merged')
                repository['head'] = command[2]
                if path == self.store.public:
                    self.store.put(path / 'scripts/public_export.py', self.api, uid=self.store.scope.uid)
                else:
                    self.store.put(path / 'scripts/install-service-resources.sh', self.installer,
                                   uid=self.store.scope.uid, mode=0o755)
                return b''
        elif argv[0] == str(self.store.public.parent / 'venv/bin/python'):
            self.import_programs.append(argv)
            return b''
        elif argv == ['bash', str(STAGE / 'install-service-resources.sh')]:
            if user:
                raise AssertionError('only the fixed producer installer needs root')
            self.store.install_producer()
            return b''
        raise AssertionError('unexpected command: ' + repr(argv))

    def commands(self, name):
        return [call for call in self.calls if name in call[0]]


class ToolingUpdateTests(unittest.TestCase):
    def setUp(self):
        self.scope = layout()
        self.store = ToolStore(self.scope)
        self.runner = ToolRunner(self.store)
        self.staged_sources = None

    @contextmanager
    def root_staging(self, store, sources):
        self.assertIs(store, self.store)
        self.staged_sources = dict(sources)
        yield STAGE

    def prepare(self, request=None):
        with patch.object(tooling, '_tooling_locks', return_value=nullcontext()), \
                patch.object(tooling, '_root_staging', side_effect=self.root_staging, create=True):
            return tooling.prepare_tooling(self.scope, self.runner, self.store,
                                          request if request is not None else {'verification_scope': 'full'})

    def assert_refused_without_merge(self, code):
        with self.assertRaisesRegex(tooling.ToolingFailure, '^' + code + '$'):
            self.prepare()
        self.assertEqual(self.runner.commands('merge'), [])
        self.assertEqual(self.runner.commands('bash'), [])

    def test_clean_detached_public_checkout_is_fast_forwarded_and_import_verified(self):
        self.assertEqual(self.prepare(), {'schema': 1, 'status': 'TOOLS_READY'})
        self.assertEqual(self.runner.repositories[self.store.public]['head'], NEW)
        self.assertEqual(self.runner.repositories[self.store.public]['branch'], 'HEAD')
        merges = self.runner.commands('merge')
        self.assertEqual(len(merges), 1)
        self.assertEqual(merges[0][0][-3:], ['merge', '--ff-only', NEW])
        self.assertEqual(len(self.runner.import_programs), 1)
        self.assertEqual(self.runner.import_programs[0][1:4], ['-I', '-B', '-c'])
        self.assertIn('PUBLIC_ONBOARDING_PREFLIGHT', self.runner.import_programs[0][4])
        self.assertTrue(all(call[2] for call in self.runner.calls))
        self.assertFalse(any(str(self.store.dr) in call[0] for call in self.runner.calls))

    def test_commands_disable_git_hooks_and_do_not_touch_application_lifecycle(self):
        self.prepare()
        for args, _, _, _ in self.runner.calls:
            if args[0] == 'git':
                self.assertEqual(args[1:7], ['-c', 'core.hooksPath=/dev/null', '-c',
                    'core.fsmonitor=false', '-c', 'submodule.recurse=false'])
            self.assertFalse(set(args) & {'docker', 'compose', 'systemctl', 'apt', 'apt-get',
                                          'pip', 'reset', 'clean', 'checkout', 'clone'})
        self.assertTrue(all(not call[4] for call in self.store.directory_calls))

    def test_missing_producer_updates_only_existing_dr_and_invokes_fixed_installer(self):
        self.store.files.pop(tooling.PRODUCER)
        self.assertEqual(self.prepare()['status'], 'TOOLS_READY')
        self.assertTrue(tooling._producer_ready(self.store))
        self.assertEqual(self.runner.repositories[self.store.dr]['head'], DR_NEW)
        self.assertEqual(len(self.runner.commands('merge')), 2)
        installer = self.runner.commands('bash')
        self.assertEqual(len(installer), 1)
        self.assertEqual(installer[0][0], ['bash', str(STAGE / 'install-service-resources.sh')])
        self.assertNotIn(str(self.store.dr / 'scripts/install-service-resources.sh'), installer[0][0])
        self.assertEqual(self.staged_sources, PRODUCER_SOURCES)
        self.assertFalse(installer[0][2])
        self.assertTrue(any(call[0][-4:] == ['merge-base', '--is-ancestor', tooling.DR_MINIMUM_COMMIT, DR_NEW]
                            for call in self.runner.calls))

    def test_root_stage_uses_four_exact_fetched_blobs_instead_of_mutable_checkout(self):
        self.store.files.pop(tooling.PRODUCER)
        for name in PRODUCER_SOURCES:
            self.store.put(self.store.dr / 'scripts' / name, b'synthetic mutable checkout content',
                           uid=self.scope.uid, mode=0o664)
        self.assertEqual(self.prepare()['status'], 'TOOLS_READY')
        self.assertEqual(self.staged_sources, PRODUCER_SOURCES)
        fetched = [call[0][-1] for call in self.runner.calls
                   if 'show' in call[0] and call[0][-1].startswith(DR_NEW + ':scripts/')]
        self.assertEqual(set(fetched), {DR_NEW + ':scripts/' + name for name in PRODUCER_SOURCES})
        self.assertEqual(len(fetched), 4)
        self.assertEqual(self.runner.commands('bash')[0][0],
                         ['bash', str(STAGE / 'install-service-resources.sh')])

    def test_wrong_dr_branch_refuses_before_either_repository_is_merged(self):
        self.store.files.pop(tooling.PRODUCER)
        self.runner.repositories[self.store.dr]['branch'] = 'HEAD'
        self.assert_refused_without_merge('ONBOARDING_TOOLING_BRANCH_INVALID')

    def test_invalid_dr_origin_refuses_before_public_repository_is_merged(self):
        self.store.files.pop(tooling.PRODUCER)
        self.runner.repositories[self.store.dr]['origin'] = 'https://github.com/other/streams-aio-dr'
        self.assert_refused_without_merge('ONBOARDING_TOOLING_ORIGIN_INVALID')

    def test_missing_producer_for_other_owner_refuses_without_running_installer(self):
        self.scope = layout('operator')
        self.store = ToolStore(self.scope, producer=False)
        self.runner = ToolRunner(self.store)
        self.assert_refused_without_merge('ONBOARDING_TOOLING_OWNER_UNSUPPORTED')
        self.assertEqual(self.runner.calls, [])

    def test_existing_producer_allows_other_normal_owner(self):
        self.scope = layout('operator')
        self.store = ToolStore(self.scope)
        self.runner = ToolRunner(self.store)
        self.assertEqual(self.prepare()['status'], 'TOOLS_READY')

    def test_dirty_checkout_is_preserved(self):
        self.runner.repositories[self.store.public]['dirty'] = b' M scripts/public_export.py\n'
        self.assert_refused_without_merge('ONBOARDING_TOOLING_LOCAL_CHANGES')
        self.assertEqual(self.runner.repositories[self.store.public]['head'], OLD)

    def test_public_origin_is_exactly_allowlisted(self):
        for value in ('https://github.com/other/streams-aio-sanitized',
                      'https://private-token@github.com/' + tooling.PUBLIC_REPOSITORY,
                      'https://github.example.test/' + tooling.PUBLIC_REPOSITORY,
                      'https://github.com/' + tooling.PUBLIC_REPOSITORY + '\nhttps://other.test/a'):
            with self.subTest(origin=value):
                self.runner.repositories[self.store.public]['origin'] = value
                self.assert_refused_without_merge('ONBOARDING_TOOLING_ORIGIN_INVALID')

    def test_diverged_history_is_not_reset_or_merged(self):
        self.runner.diverged.add(self.store.public)
        self.assert_refused_without_merge('ONBOARDING_TOOLING_DIVERGED')
        self.assertEqual(self.runner.repositories[self.store.public]['head'], OLD)

    def test_canonical_existing_repository_and_git_directory_are_required(self):
        for path in (self.store.public, self.store.public / '.git'):
            with self.subTest(path=str(path)):
                self.store.refused = {path}
                self.assert_refused_without_merge('ONBOARDING_TOOLING_REPOSITORY_INVALID')

    def test_preflight_api_marker_and_function_are_checked_before_merge(self):
        for value in (b'PUBLIC_ONBOARDING_PREFLIGHT = True\ndef preflight(): pass\n',
                      b'PUBLIC_ONBOARDING_PREFLIGHT = 0\ndef preflight(): pass\n',
                      b'PUBLIC_ONBOARDING_PREFLIGHT = 1\n',
                      b'PUBLIC_ONBOARDING_PREFLIGHT = 1\nPUBLIC_ONBOARDING_PREFLIGHT = 1\ndef preflight(): pass\n',
                      b'PUBLIC_ONBOARDING_PREFLIGHT = 1\ndef invalid(\n',
                      b'\xffprivate-synthetic-noise'):
            with self.subTest(source=value):
                self.runner.api = value
                self.assert_refused_without_merge('ONBOARDING_TOOLING_SOURCE_TOO_OLD')

    def test_pinned_public_ancestor_is_checked_before_merge_when_configured(self):
        minimum = '9' * 40
        with patch.object(tooling, 'PUBLIC_MINIMUM_COMMIT', minimum):
            self.assertEqual(self.prepare()['status'], 'TOOLS_READY')
        self.assertTrue(any(call[0][-4:] == ['merge-base', '--is-ancestor', minimum, NEW]
                            for call in self.runner.calls))

    def test_bad_public_pin_fails_before_merge(self):
        with patch.object(tooling, 'PUBLIC_MINIMUM_COMMIT', 'not-a-commit'):
            self.assert_refused_without_merge('ONBOARDING_TOOLING_SOURCE_TOO_OLD')

    def test_invalid_existing_producer_is_preserved_instead_of_overwritten(self):
        self.store.files[tooling.PRODUCER].uid = self.scope.uid
        self.assert_refused_without_merge('ONBOARDING_TOOLING_PRODUCER_INVALID')
        self.assertEqual(self.runner.calls, [])

    def test_local_lab_scope_is_not_upgraded_to_production(self):
        with self.assertRaisesRegex(tooling.ToolingFailure, '^ONBOARDING_TOOLING_SCOPE_REFUSED$'):
            self.prepare({'verification_scope': 'local_lab'})
        self.assertEqual(self.runner.calls, [])

    def test_runner_failures_expose_only_closed_code(self):
        self.runner.fail_codes.add('ONBOARDING_TOOLING_FETCH_FAILED')
        try:
            self.prepare()
        except tooling.ToolingFailure as error:
            self.assertEqual(str(error), 'ONBOARDING_TOOLING_FETCH_FAILED')
            self.assertNotIn('synthetic-private-error-value', str(error))
        else:
            self.fail('expected a safe tooling refusal')

    def test_unexpected_store_failure_is_sanitized_by_public_entry_point(self):
        original = self.store.snapshot
        def snapshot(path):
            if PurePosixPath(path) == self.store.public / 'scripts/public_export.py':
                raise OSError('synthetic-private-filesystem-detail')
            return original(path)
        with patch.object(self.store, 'snapshot', side_effect=snapshot):
            with self.assertRaisesRegex(tooling.ToolingFailure, '^ONBOARDING_TOOLING_VERIFY_FAILED$') as refused:
                self.prepare()
        self.assertNotIn('synthetic-private-filesystem-detail', str(refused.exception))
        self.assertEqual(self.runner.commands('bash'), [])

    def test_import_failure_never_invokes_root_installer_or_reports_ready(self):
        self.store.files.pop(tooling.PRODUCER)
        self.runner.fail_codes.add('ONBOARDING_TOOLING_VERIFY_FAILED')
        with self.assertRaisesRegex(tooling.ToolingFailure, '^ONBOARDING_TOOLING_VERIFY_FAILED$'):
            self.prepare()
        self.assertEqual(self.runner.commands('bash'), [])
        self.assertEqual(self.runner.repositories[self.store.dr]['head'], DR_OLD)


class RootStagingTests(unittest.TestCase):
    def setUp(self):
        self.directories = []
        self.writes = []
        self.store = SimpleNamespace(
            directory=lambda *args, **kwargs: self.directories.append((args, kwargs)),
            write=lambda *args, **kwargs: self.writes.append((args, kwargs)))

    def test_only_exact_git_bytes_are_written_to_root_private_temporary_directory(self):
        with patch.object(tooling.tempfile, 'TemporaryDirectory') as temporary:
            temporary.return_value.__enter__.return_value = str(STAGE)
            with tooling._root_staging(self.store, PRODUCER_SOURCES) as folder:
                self.assertEqual(folder, STAGE)
                temporary.return_value.__exit__.assert_not_called()
            temporary.assert_called_once_with(prefix='streams-aio-tools-', dir='/run')
            temporary.return_value.__exit__.assert_called_once_with(None, None, None)
        self.assertEqual(self.directories, [((STAGE, 0, 0, 0o700), {})])
        self.assertEqual(self.writes,
            [((STAGE / name, PRODUCER_SOURCES[name], 0, 0, 0o600), {})
             for name in tooling.PRODUCER_SOURCES])
        self.assertTrue(all(str(call[0][0]).startswith('/run/streams-aio-tools-test/')
                            for call in self.writes))

    def test_body_exception_still_exits_only_the_temporary_directory_context(self):
        with patch.object(tooling.tempfile, 'TemporaryDirectory') as temporary:
            temporary.return_value.__enter__.return_value = str(STAGE)
            with self.assertRaisesRegex(ValueError, '^synthetic installer failure$'):
                with tooling._root_staging(self.store, PRODUCER_SOURCES):
                    raise ValueError('synthetic installer failure')
            temporary.assert_called_once_with(prefix='streams-aio-tools-', dir='/run')
            cleanup = temporary.return_value.__exit__
            cleanup.assert_called_once()
            self.assertIs(cleanup.call_args.args[0], ValueError)
            self.assertEqual(str(cleanup.call_args.args[1]), 'synthetic installer failure')
        self.assertEqual(len(self.writes), 4)

    def test_unknown_or_missing_source_name_is_refused_before_creating_any_directory(self):
        for sources in ({'../unexpected': b'unsafe'},
                        {name: raw for name, raw in PRODUCER_SOURCES.items() if name != 'service_snapshot.py'}):
            with self.subTest(names=list(sources)), patch.object(tooling.tempfile, 'TemporaryDirectory') as temporary:
                with self.assertRaisesRegex(tooling.ToolingFailure, '^ONBOARDING_TOOLING_SOURCE_CHANGED$'):
                    with tooling._root_staging(self.store, sources):
                        self.fail('unreviewed source names must not reach staging')
                temporary.assert_not_called()
        self.assertEqual(self.directories, [])
        self.assertEqual(self.writes, [])


class ToolingLocksTests(unittest.TestCase):
    def setUp(self):
        self.scope = layout()
        self.store = ToolStore(self.scope)
        self.fcntl = SimpleNamespace(LOCK_EX=2, LOCK_NB=4)
        self.lock_calls = []
        self.fcntl.flock = lambda fd, flags: self.lock_calls.append((fd, flags))
        self.info = SimpleNamespace(st_mode=stat.S_IFREG | 0o640, st_nlink=1, st_uid=self.scope.uid)

    def lock_context(self, *, fstat=None):
        return (
            patch.dict(sys.modules, {'fcntl': self.fcntl}),
            patch.object(tooling.os, 'open', side_effect=[41, 42]),
            patch.object(tooling.os, 'fstat', side_effect=fstat) if fstat else
                patch.object(tooling.os, 'fstat', return_value=self.info),
            patch.object(tooling.os, 'close'),
        )

    def test_fixed_order_nonblocking_flags_and_reverse_release(self):
        modules, opened, infos, closed = self.lock_context()
        with modules, opened as opens, infos, closed as closes:
            with tooling._tooling_locks(self.scope, self.store):
                self.assertEqual(self.lock_calls, [(41, 6), (42, 6)])
                closes.assert_not_called()
        expected = [self.scope.home / '.local/state' / name / 'run.lock'
                    for name in ('streams-aio-dr', 'streams-aio-public-sync')]
        self.assertEqual([item.args[0] for item in opens.call_args_list], expected)
        self.assertTrue(all(item.args[1] & tooling.os.O_RDWR for item in opens.call_args_list))
        self.assertEqual([item.args[0] for item in closes.call_args_list], [42, 41])

    def test_open_explicitly_refuses_symbolic_link_replacement(self):
        modules, opened, infos, closed = self.lock_context()
        with modules, opened as opens, infos, closed, patch.object(tooling.os, 'O_NOFOLLOW', 0x20000, create=True):
            with tooling._tooling_locks(self.scope, self.store):
                pass
        self.assertTrue(all(item.args[1] & 0x20000 for item in opens.call_args_list))

    def test_busy_lock_refuses_without_wait_and_releases_opened_descriptors(self):
        def busy(fd, flags):
            self.lock_calls.append((fd, flags))
            raise BlockingIOError('synthetic busy lock')
        self.fcntl.flock = busy
        modules, opened, infos, closed = self.lock_context()
        with modules, opened as opens, infos, closed as closes:
            with self.assertRaisesRegex(tooling.ToolingFailure, '^ONBOARDING_OTHER_OPERATION_RUNNING$'):
                with tooling._tooling_locks(self.scope, self.store):
                    self.fail('a busy operation must not enter its body')
        self.assertEqual(opens.call_count, 1)
        closes.assert_called_once_with(41)

    def test_lock_files_must_be_regular_single_link_owned_and_not_other_writable(self):
        cases = [dict(st_mode=stat.S_IFDIR | 0o640), dict(st_nlink=2), dict(st_uid=2000),
                 dict(st_mode=stat.S_IFREG | 0o642)]
        for changes in cases:
            with self.subTest(changes=changes):
                info = SimpleNamespace(**(vars(self.info) | changes))
                modules, opened, infos, closed = self.lock_context(fstat=lambda _: info)
                with modules, opened, infos, closed as closes:
                    with self.assertRaisesRegex(tooling.ToolingFailure, '^ONBOARDING_TOOLING_LOCK_INVALID$'):
                        with tooling._tooling_locks(self.scope, self.store):
                            self.fail('invalid lock must not enter its body')
                closes.assert_called_once_with(41)

    def test_failed_lock_metadata_read_is_closed_and_releases_descriptor(self):
        modules, opened, infos, closed = self.lock_context(fstat=OSError('synthetic-private-metadata-detail'))
        with modules, opened, infos, closed as closes:
            with self.assertRaisesRegex(tooling.ToolingFailure, '^ONBOARDING_TOOLING_LOCK_INVALID$') as refused:
                with tooling._tooling_locks(self.scope, self.store):
                    self.fail('unreadable lock metadata must not enter its body')
        self.assertNotIn('synthetic-private-metadata-detail', str(refused.exception))
        closes.assert_called_once_with(41)

    def test_failed_flock_is_closed_and_releases_descriptor(self):
        def fail(fd, flags):
            raise OSError('synthetic-private-flock-detail')
        self.fcntl.flock = fail
        modules, opened, infos, closed = self.lock_context()
        with modules, opened, infos, closed as closes:
            with self.assertRaisesRegex(tooling.ToolingFailure, '^ONBOARDING_TOOLING_LOCK_INVALID$') as refused:
                with tooling._tooling_locks(self.scope, self.store):
                    self.fail('failed locking must not enter its body')
        self.assertNotIn('synthetic-private-flock-detail', str(refused.exception))
        closes.assert_called_once_with(41)

    def test_root_owned_existing_lock_is_supported(self):
        self.info.st_uid = 0
        modules, opened, infos, closed = self.lock_context()
        with modules, opened, infos, closed:
            with tooling._tooling_locks(self.scope, self.store):
                pass
        self.assertEqual(self.lock_calls, [(41, 6), (42, 6)])

    def test_symlink_lock_is_refused_before_open(self):
        self.store.refused.add(self.scope.home / '.local/state/streams-aio-dr/run.lock')
        modules, opened, infos, closed = self.lock_context()
        with modules, opened as opens, infos, closed:
            with self.assertRaisesRegex(tooling.ToolingFailure, '^ONBOARDING_TOOLING_LOCK_INVALID$'):
                with tooling._tooling_locks(self.scope, self.store):
                    self.fail('symlink lock must not enter its body')
        opens.assert_not_called()

    def test_exception_inside_operation_releases_both_locks(self):
        modules, opened, infos, closed = self.lock_context()
        with modules, opened, infos, closed as closes:
            with self.assertRaisesRegex(ValueError, 'synthetic operation failure'):
                with tooling._tooling_locks(self.scope, self.store):
                    raise ValueError('synthetic operation failure')
        self.assertEqual([item.args[0] for item in closes.call_args_list], [42, 41])


if __name__ == '__main__':
    unittest.main()
"""Synthetic resolver transactions; no VM, network or system service is used."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('host_dns_tests', ROOT / 'remote/host_dns.py')
dns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dns)
SERVER = '192.168.50.12'
OLD_SERVER = '192.168.50.13'
CANARY = 'private-input-must-not-be-disclosed'


class HostDNS(unittest.TestCase):
    def setUp(self):
        self.area = tempfile.TemporaryDirectory(dir=ROOT / 'tests')
        self.addCleanup(self.area.cleanup)
        self.root = Path(self.area.name)
        self.home = self.root / 'home' / 'recovery'
        self.home.mkdir(parents=True)
        self.path = self.root / 'etc' / 'systemd' / 'resolved.conf.d' / dns.DROP_IN.name
        self.path.parent.parent.mkdir(parents=True)
        self.account = types.SimpleNamespace(pw_name='recovery', pw_uid=1000,
                                            pw_gid=1000, pw_dir=str(self.home))
        self.overrides = {}
        self.commands = []
        self.fail_host = None
        self.fail_restart = False
        self.active_server = SERVER
        self.active_domain = '~.'
        real_lstat, real_fstat = Path.lstat, os.fstat

        def metadata(info, path=None):
            # Model Ubuntu ownership/modes while keeping file I/O inside a
            # disposable test directory on both Windows and Unix hosts.
            values = {key: getattr(info, key) for key in (
                'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                'st_size', 'st_mtime_ns')}
            values.update(st_uid=1000 if path == self.home else 0,
                          st_gid=1000 if path == self.home else 0,
                          st_mode=stat.S_IFMT(info.st_mode) |
                          (0o755 if stat.S_ISDIR(info.st_mode) else 0o644))
            values.update(self.overrides.get(path, {}))
            return types.SimpleNamespace(**values)

        def lstat(path, *args, **kwargs):
            return metadata(real_lstat(path, *args, **kwargs), path)

        def publish(source, destination, **kwargs):
            # The Windows sandbox disallows hard links. Model the single
            # no-clobber publication operation without using the real OS link.
            with Path(destination).open('xb') as target:
                target.write(Path(source).read_bytes())

        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        for item in (
                patch.object(dns, 'DROP_IN', self.path),
                patch.object(dns.sys, 'platform', 'linux'),
                patch.dict(os.environ, {'SUDO_USER': 'recovery'}),
                patch.dict(sys.modules, {'pwd': types.SimpleNamespace(getpwnam=lambda user: self.account)}),
                patch.object(os, 'getuid', return_value=0, create=True),
                patch.object(os, 'geteuid', return_value=0, create=True),
                patch.object(os, 'chown', create=True),
                patch.object(os, 'fchown', create=True),
                patch.object(os, 'fchmod', create=True),
                patch.object(os, 'link', side_effect=publish),
                patch.object(Path, 'lstat', lstat),
                patch.object(os, 'fstat', side_effect=lambda fd: metadata(real_fstat(fd))),
                patch.object(subprocess, 'run', side_effect=self.command)):
            self.patches.enter_context(item)

    def command(self, args, **kwargs):
        self.commands.append((args, kwargs))
        self.assertNotIn('shell', kwargs)
        self.assertIs(kwargs['stderr'], subprocess.DEVNULL)
        self.assertIs(kwargs['stdin'], subprocess.DEVNULL)
        self.assertTrue(kwargs['check'])
        self.assertLessEqual(kwargs['timeout'], 20)
        if args[:2] == ['/usr/bin/systemctl', 'restart']:
            if self.fail_restart:
                raise subprocess.CalledProcessError(1, args, output=CANARY, stderr=CANARY)
            return types.SimpleNamespace(stdout=None)
        if args == ['/usr/bin/resolvectl', 'dns']:
            return types.SimpleNamespace(stdout=('Global: ' + self.active_server +
                '\nLink 2 (eth0): 192.168.50.1\n').encode())
        if args == ['/usr/bin/resolvectl', 'domain']:
            return types.SimpleNamespace(stdout=('Global: ' + self.active_domain +
                '\nLink 2 (eth0): local\n').encode())
        self.assertEqual(args[:2], ['/usr/bin/getent', 'ahostsv4'])
        self.assertIn(args[2], dns.PUBLIC_HOSTS)
        if args[2] == self.fail_host:
            raise subprocess.TimeoutExpired(args, kwargs['timeout'], output=CANARY)
        return types.SimpleNamespace(stdout=None)

    def write(self, raw):
        self.path.parent.mkdir(exist_ok=True)
        self.path.write_bytes(raw)

    def restarts(self):
        return [args for args, kwargs in self.commands if args[0] == '/usr/bin/systemctl']

    def refused(self, server=SERVER):
        with self.assertRaisesRegex(dns.HostDNSError, '^' + dns.REFUSED + '$'):
            dns.run(server)
        self.assertFalse(self.commands)

    def test_explicit_canonical_unicast_ipv4_ipv6(self):
        for value in (SERVER, '8.8.8.8', 'fdab:1234::12', '2606:4700:4700::1111'):
            with self.subTest(value=value):
                self.assertEqual(dns.validate_server(value), value)

    def test_unsafe_and_noncanonical_addresses_refused(self):
        for value in ('', None, 12, 'localhost', 'https://8.8.8.8', '8.8.8.8\n',
                      ' 8.8.8.8', '192.168.050.12', '8.8.8.8:53', '127.0.0.1',
                      '0.0.0.0', '224.0.0.1', '255.255.255.255', '169.254.1.2',
                      '::', '::1', 'ff02::1', 'fe80::1', 'fe80::1%eth0',
                      '[fdab::12]', 'FDAB::12', 'fdab:0:0:0:0:0:0:12', '::ffff:192.168.1.1'):
            with self.subTest(value=value), self.assertRaisesRegex(dns.HostDNSError, '^' + dns.REFUSED + '$'):
                dns.validate_server(value)

    def test_requires_root_and_sudo_uid_gid_1000(self):
        with patch.object(os, 'getuid', return_value=1000):
            self.refused()
        with patch.dict(os.environ, {'SUDO_USER': 'root'}):
            self.refused()
        self.account.pw_uid = 1001
        self.refused()
        self.account.pw_uid, self.account.pw_gid = 1000, 1001
        self.refused()

    def test_home_must_be_owned_directory_without_symlink_or_writable_ancestors(self):
        for path, change in ((self.home, {'st_uid': 0}),
                             (self.home, {'st_mode': stat.S_IFLNK | 0o777}),
                             (self.home.parent, {'st_mode': stat.S_IFDIR | 0o777})):
            with self.subTest(path=path, change=change):
                self.overrides[path] = change
                self.refused()
                self.overrides.clear()

    def test_new_configuration_is_scoped_and_probed_after_restart(self):
        result = dns.run(SERVER)
        self.assertEqual(result, {'schema': 1, 'status': 'PASS', 'server': SERVER, 'action': 'CHANGED'})
        self.assertEqual(self.path.read_bytes(), dns.configuration(SERVER))
        self.assertEqual(self.path.read_text().splitlines(), [dns.MARKER.strip(), '[Resolve]',
                                                            'DNS=' + SERVER, 'Domains=~.'])
        self.assertEqual(len(self.restarts()), 1)
        self.assertEqual([args[0] for args, _ in self.commands],
                         ['/usr/bin/systemctl', '/usr/bin/resolvectl', '/usr/bin/resolvectl',
                          '/usr/bin/getent', '/usr/bin/getent'])
        os.fchown.assert_called_once()
        self.assertEqual(os.fchown.call_args.args[1:], (0, 0))
        self.assertEqual(os.fchmod.call_args.args[1:], (0o644,))
        self.assertEqual(list(self.path.parent.glob('.streams-aio-dns-*')), [])

    def test_identical_managed_configuration_is_unchanged_without_restart(self):
        self.write(dns.configuration(SERVER))
        before = self.path.read_bytes()
        result = dns.run(SERVER)
        self.assertEqual(result['action'], 'UNCHANGED')
        self.assertEqual(self.path.read_bytes(), before)
        self.assertFalse(self.restarts())
        self.assertEqual(len(self.commands), 4)
        os.fchmod.assert_not_called()

    def test_unmanaged_or_edited_file_never_overwritten(self):
        for raw in (b'[Resolve]\nDNS=8.8.8.8\n',
                    dns.configuration(SERVER) + b'# local addition\n',
                    dns.configuration(SERVER).replace(b'Domains=~.', b'Domains=example.invalid'),
                    b'\xff' * 20):
            with self.subTest(raw=raw):
                self.write(raw)
                self.refused()
                self.assertEqual(self.path.read_bytes(), raw)

    def test_symlink_special_unowned_or_hardlinked_target_never_overwritten(self):
        self.write(dns.configuration(OLD_SERVER))
        for change in ({'st_mode': stat.S_IFLNK | 0o777}, {'st_mode': stat.S_IFIFO | 0o644},
                       {'st_uid': 1000}, {'st_gid': 1000}, {'st_nlink': 2},
                       {'st_mode': stat.S_IFREG | 0o666}, {'st_size': dns.MAX_BYTES + 1}):
            with self.subTest(change=change):
                self.overrides[self.path] = change
                self.refused()
                self.assertEqual(self.path.read_bytes(), dns.configuration(OLD_SERVER))
                self.overrides.clear()

    def test_config_parent_symlink_unowned_or_writable_is_refused(self):
        self.path.parent.mkdir()
        for change in ({'st_mode': stat.S_IFLNK | 0o777}, {'st_uid': 1000},
                       {'st_gid': 1000}, {'st_mode': stat.S_IFDIR | 0o777}):
            with self.subTest(change=change):
                self.overrides[self.path.parent] = change
                self.refused()
                self.assertFalse(self.path.exists())
                self.overrides.clear()

    def test_public_lookup_failure_restores_previous_managed_file(self):
        old = dns.configuration(OLD_SERVER)
        self.write(old)
        self.fail_host = 'download.docker.com'
        with self.assertRaisesRegex(dns.HostDNSError, '^' + dns.FAILED + '$'):
            dns.run(SERVER)
        self.assertEqual(self.path.read_bytes(), old)
        self.assertEqual(len(self.restarts()), 2)

    def test_public_lookup_failure_removes_only_new_file(self):
        self.fail_host = 'github.com'
        with self.assertRaisesRegex(dns.HostDNSError, '^' + dns.FAILED + '$'):
            dns.run(SERVER)
        self.assertFalse(self.path.exists())
        self.assertEqual(len(self.restarts()), 2)
        self.assertTrue(self.home.is_dir())

    def test_wrong_running_global_dns_or_domain_rolls_back_before_getent(self):
        for field, value in (('active_server', OLD_SERVER), ('active_domain', 'example.invalid')):
            with self.subTest(field=field):
                self.commands.clear()
                setattr(self, field, value)
                with self.assertRaisesRegex(dns.HostDNSError, '^' + dns.FAILED + '$'):
                    dns.run(SERVER)
                self.assertFalse(self.path.exists())
                self.assertEqual(len(self.restarts()), 2)
                self.assertFalse(any(args[0] == '/usr/bin/getent' for args, _ in self.commands))
                setattr(self, field, SERVER if field == 'active_server' else '~.')

    def test_restart_failure_rolls_back_and_attempts_restart_once_more(self):
        old = dns.configuration(OLD_SERVER)
        self.write(old)
        self.fail_restart = True
        with self.assertRaisesRegex(dns.HostDNSError, '^' + dns.FAILED + '$'):
            dns.run(SERVER)
        self.assertEqual(self.path.read_bytes(), old)
        self.assertEqual(len(self.restarts()), 2)

    def test_existing_unchanged_file_lookup_failure_keeps_original_without_restart(self):
        old = dns.configuration(SERVER)
        self.write(old)
        self.fail_host = 'github.com'
        with self.assertRaisesRegex(dns.HostDNSError, '^' + dns.FAILED + '$'):
            dns.run(SERVER)
        self.assertEqual(self.path.read_bytes(), old)
        self.assertFalse(self.restarts())

    def test_atomic_creation_never_overwrites_file_that_appears_late(self):
        self.path.parent.mkdir()
        real_link = os.link

        def competing_file(source, destination, **kwargs):
            self.path.write_bytes(b'competing owner\n')
            return real_link(source, destination, **kwargs)

        with patch.object(os, 'link', side_effect=competing_file):
            with self.assertRaisesRegex(dns.HostDNSError, '^' + dns.FAILED + '$'):
                dns.run(SERVER)
        self.assertEqual(self.path.read_bytes(), b'competing owner\n')
        self.assertFalse(self.restarts())

    def test_cli_success_and_failures_have_closed_public_output(self):
        for args, code in ((['--server', SERVER], 0),
                           (['--server', CANARY], 1), ([], 1),
                           (['--server', SERVER, '--unknown', CANARY], 1)):
            out, err = io.StringIO(), io.StringIO()
            with self.subTest(args=args), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(dns.main(args), code)
            payload = json.loads(out.getvalue())
            if code == 0:
                self.assertEqual(payload['server'], SERVER)
                self.assertEqual(err.getvalue(), '')
            else:
                self.assertEqual(payload, {'error': dns.REFUSED})
                self.assertEqual(err.getvalue(), dns.REFUSED + '\n')
            self.assertNotIn(CANARY, out.getvalue() + err.getvalue())

    def test_command_failure_does_not_expose_output_or_traceback(self):
        self.fail_host = 'github.com'
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(dns.main(['--server', SERVER]), 1)
        self.assertEqual(json.loads(out.getvalue())['error'], dns.FAILED)
        self.assertEqual(err.getvalue(), dns.FAILED + '\n')
        self.assertNotIn(CANARY, out.getvalue() + err.getvalue())


if __name__ == '__main__':
    unittest.main()

"""Exercise the root umask and a real deployment UID, plus incomplete renders."""
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'remote'))
import native_agent as agent


@unittest.skipUnless(os.name == 'posix', 'Requires actual POSIX modes and ownership')
class Installation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.uid, self.gid = os.getuid(), os.getgid()
        self.library = self.base / 'library'
        self.archive = self.base / 'cli.tar.gz'
        with tarfile.open(self.archive, 'w:gz') as tar:
            member = tarfile.TarInfo('infisical')
            raw = b'#!/bin/sh\nprintf "synthetic-public-cli\\n"\n'
            member.size = len(raw)
            tar.addfile(member, io.BytesIO(raw))
        self.hash = agent.digest(self.archive)

    def install(self):
        old = os.umask(0o077)
        try:
            with patch.object(agent, 'CLI_SHA256', self.hash):
                return agent.install_cli(self.archive, self.library, self.uid, self.gid)
        finally:
            os.umask(old)

    def test_actual_root_umask_does_not_hide_the_public_executable(self):
        private = self.base / 'private'
        private.mkdir(mode=0o700)
        binary = self.install()
        self.assertEqual(stat.S_IMODE(binary.parent.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
        # Ubuntu compatibility jobs run as root. Drop to the actual VM UID/GID;
        # there need not be a passwd entry for numeric UID 1000 in the container.
        self.base.chmod(0o755)
        kwargs = {}
        if os.geteuid() == 0:
            kwargs = dict(user=1000, group=1000, extra_groups=[])
        result = subprocess.run([binary], capture_output=True, **kwargs)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'synthetic-public-cli\n')

    def test_repeat_repairs_only_the_verified_library_and_refuses_private_siblings(self):
        binary = self.install()
        binary.parent.chmod(0o700)
        self.install()
        self.assertEqual(stat.S_IMODE(binary.parent.stat().st_mode), 0o755)
        binary.parent.chmod(0o700)
        (binary.parent / 'credential').write_bytes(b'synthetic-private-canary')
        with self.assertRaisesRegex(agent.Refused, 'AGENT_CLI_LIBRARY_REFUSED'):
            self.install()
        self.assertEqual(stat.S_IMODE(binary.parent.stat().st_mode), 0o700)

    def test_changed_executable_checksum_and_hardlink_are_refused_before_chmod(self):
        binary = self.install()
        for kind in ('changed', 'hardlink'):
            with self.subTest(kind=kind):
                binary.parent.chmod(0o700)
                if kind == 'changed':
                    original = binary.read_bytes()
                    binary.write_bytes(b'foreign-canary')
                else:
                    os.link(binary, self.base / 'alias')
                with self.assertRaisesRegex(agent.Refused, 'AGENT_EXISTING_INSTALLATION_CHANGED'):
                    self.install()
                self.assertEqual(stat.S_IMODE(binary.parent.stat().st_mode), 0o700)
                if kind == 'changed':
                    binary.write_bytes(original)

    def render_fixture(self):
        area = self.base / 'private'
        area.mkdir(mode=0o700)
        outputs = [area / 'first.env', area / 'second.env']
        for output in outputs:
            output.write_bytes(b'previous-private-canary')
            output.chmod(0o600)
        config = dict(infisical={'address': 'http://127.0.0.1:18180'}, auth={},
                      templates=[{'destination-path': str(p), 'template-content': 'synthetic',
                                  'config': {'polling-interval': '60s'}} for p in outputs])
        return area, outputs, config

    def test_exit_zero_with_an_unwritten_template_preserves_all_prepared_files(self):
        area, outputs, config = self.render_fixture()
        def partial(args, *a, **kw):
            isolated = json.loads(Path(args[-1]).read_bytes())
            path = Path(isolated['templates'][0]['destination-path'])
            path.write_bytes(b'new-private-canary')
            path.chmod(0o600)
            return b''  # Mirrors the pinned CLI's swallowed write error.
        with patch.object(agent, 'command', partial), self.assertRaisesRegex(
                agent.Refused, 'AGENT_FIRST_RENDER_FAILED'):
            agent.first_render(config, area, Path('/synthetic-cli'), 'synthetic', self.uid, self.gid)
        self.assertTrue(all(p.read_bytes() == b'previous-private-canary' for p in outputs))
        self.assertEqual(len(list(area.iterdir())), 2)

    def test_complete_render_promotes_only_valid_owner_only_files(self):
        area, outputs, config = self.render_fixture()
        def complete(args, *a, **kw):
            isolated = json.loads(Path(args[-1]).read_bytes())
            for row in isolated['templates']:
                path = Path(row['destination-path'])
                path.write_bytes(b'new-private-canary')
                path.chmod(0o600)
            return b''
        with patch.object(agent, 'command', complete):
            agent.first_render(config, area, Path('/synthetic-cli'), 'synthetic', self.uid, self.gid)
        self.assertTrue(all(p.read_bytes() == b'new-private-canary' for p in outputs))
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in outputs))
        self.assertEqual(len(list(area.iterdir())), 2)

    def test_real_child_umask_is_private_after_privilege_transition_and_dry_run(self):
        area, outputs, config = self.render_fixture()
        target_uid, target_gid = self.uid, self.gid
        child_options = {}
        if os.geteuid() == 0:
            target_uid = target_gid = 1000
            child_options = dict(user=1000, group=1000, extra_groups=[])
        self.base.chmod(0o755)
        for path in (area, *outputs):
            os.chown(path, target_uid, target_gid)
        # The pinned Go CLI uses os.Create, whose requested mode is 0666.
        # Emulate a sudo policy setting 0022 before the actual installer command
        # runs as the deployment UID. Do not repair the output with chmod here:
        # only the installer's child umask may keep newly created files private.
        creator = '''import json,os,sys
config=json.load(open(sys.argv[-1]))
for row in config['templates']:
    fd=os.open(row['destination-path'],os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o666)
    with os.fdopen(fd,'wb') as file:
        file.write(b'new-private-canary')
'''
        def run_real_creator(args, *unused, **options):
            self.assertEqual(args[:5], ['sudo', '-H', '-u', 'synthetic', '--'])
            child = [str(value) for value in args[5:]]
            cli_index = child.index('/synthetic-cli')
            child[cli_index:cli_index + 1] = ['/usr/bin/python3', '-B', '-c', creator]
            result = subprocess.run(
                ['/bin/sh', '-c', 'umask 022; exec "$@"', 'sudo-policy', *child],
                capture_output=True, timeout=15, **child_options)
            self.assertEqual(result.returncode, 0)
            isolated = json.loads(Path(args[-1]).read_bytes())
            for row in isolated['templates']:
                info = Path(row['destination-path']).stat()
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                self.assertEqual((info.st_uid, info.st_gid), (target_uid, target_gid))
            return result.stdout
        for dry_run in (True, False):
            with self.subTest(dry_run=dry_run), patch.object(agent, 'command', run_real_creator):
                agent.first_render(config, area, Path('/synthetic-cli'), 'synthetic',
                                   target_uid, target_gid, dry_run=dry_run)
            expected = b'previous-private-canary' if dry_run else b'new-private-canary'
            self.assertTrue(all(path.read_bytes() == expected for path in outputs))
            self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in outputs))
            self.assertEqual(len(list(area.iterdir())), 2)


if __name__ == '__main__':
    unittest.main()

"""Compatibility with the producer's absolute tar paths, confined to staging."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('agent_archive_recover', ROOT / 'remote/recover.py')
remote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remote)


class AgentArchiveTests(unittest.TestCase):
    def setUp(self):
        fixture_root = ROOT.parent / 'gui-test-tmp' if sys.platform == 'win32' else None
        if fixture_root is not None:
            fixture_root.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=fixture_root)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.archive = self.base / 'agent.tar.gz'
        self.destination = self.base / 'output'
        if sys.platform == 'win32':
            # Windows cannot test POSIX mode bits. Paths, tar contents and
            # extraction are real; all inputs below are synthetic canaries.
            def fixture_private(path, outside=()):
                path = remote.safe_path(Path(path))
                remote.require(path.is_file(), 'PRIVATE_INPUT_FILE_REQUIRED')
                remote.require(all(not path.is_relative_to(root) for root in outside), 'PRIVATE_INPUT_MUST_BE_OUTSIDE_CLONES')
                return path
            private = patch.object(remote, 'private_file', fixture_private)
            private.start()
            self.addCleanup(private.stop)

    def write_archive(self, entries):
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, value, kind in entries:
                member = tarfile.TarInfo(name)
                if kind == 'file':
                    member.size = len(value)
                    archive.addfile(member, io.BytesIO(value))
                elif kind == 'directory':
                    member.type = tarfile.DIRTYPE
                    archive.addfile(member)
                else:
                    member.type = kind
                    member.linkname = '/etc/infisical/agent/client-secret'
                    archive.addfile(member)

    def absolute_fixture(self):
        config = dict(infisical={'address': 'https://infisical.example.invalid'},
                      auth={'type': 'universal-auth', 'config': {
                          'client-id': '/etc/infisical/agent/client-id',
                          'client-secret': '/etc/infisical/agent/client-secret'}},
                      templates=[{'source-path': '/etc/infisical/streams-aio.env'}])
        return [('/etc/infisical/agent/client-id', b'id-canary', 'file'),
                ('/etc/infisical/agent/client-secret', b'secret-canary', 'file'),
                ('/etc/infisical/agent-config.yaml', json.dumps(config).encode(), 'file'),
                ('/etc/infisical/streams-aio.env', b'{{ range secret "project" "prod" "/comet" }}{{ end }}', 'file'),
                ('/etc/systemd/system/infisical-agent.service', b'[Service]\nExecStart=/bin/false\n', 'file'),
                ('/etc/systemd/system/infisical-agent.service.d/permissions.conf', b'[Service]\nGroup=pi\n', 'file')]

    def test_all_six_producer_paths_are_rebased_and_bootstrap_is_recovered(self):
        entries = self.absolute_fixture()
        self.write_archive(entries)
        remote.unpack_agent(self.archive, self.destination)
        actual = {p.relative_to(self.destination).as_posix(): p.read_bytes()
                  for p in self.destination.rglob('*') if p.is_file()}
        self.assertEqual(actual, {name.lstrip('/'): value for name, value, _ in entries})
        result = remote.agent_bootstrap(self.destination)
        self.assertEqual(result['project'], 'project')
        self.assertEqual(result['environment'], 'prod')
        self.assertEqual(result['client_secret'].read_bytes(), b'secret-canary')
        self.assertTrue(result['client_id'].is_relative_to(self.destination))
        if os.name == 'posix':
            self.assertEqual(self.destination.stat().st_mode & 0o777, 0o700)
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600
                                for p in self.destination.rglob('*') if p.is_file()))

    def test_absolute_and_relative_aliases_are_rejected_before_any_extraction(self):
        self.write_archive([('/etc/infisical/agent/client-id', b'first', 'file'),
                            ('etc/infisical/agent/client-id', b'second', 'file')])
        with self.assertRaisesRegex(remote.Refused, 'DUPLICATE_AGENT_ARCHIVE_ENTRY'):
            remote.unpack_agent(self.archive, self.destination)
        self.assertFalse(self.destination.exists())

    def test_traversal_unrelated_roots_and_links_are_rejected_before_writes(self):
        cases = [(name, b'canary', 'file') for name in (
            '/etc/shadow', '/etc/escape', '/tmp/secret', '/etc/systemd/system/other.service',
            '/etc/systemd/system/infisical-agent.service.evil', '/etc/infisical/../../escape',
            '//etc/infisical/agent/client-id', '/etc/infisical/agent\\escape',
            '/etc/infisical/agent/C:escape', '../escape', '.')]
        cases += [('/etc/infisical/agent/link', b'', kind)
                  for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE)]
        for case in cases:
            with self.subTest(name=case[0], kind=case[2]):
                self.write_archive([self.absolute_fixture()[0], case])
                with self.assertRaisesRegex(remote.Refused, 'UNSAFE_AGENT_ARCHIVE'):
                    remote.unpack_agent(self.archive, self.destination)
                self.assertFalse(self.destination.exists())

    def test_parent_file_collision_is_rejected_before_extraction(self):
        self.write_archive([('/etc/infisical/agent', b'file', 'file'),
                            ('/etc/infisical/agent/client-id', b'child', 'file')])
        with self.assertRaisesRegex(remote.Refused, 'UNSAFE_AGENT_ARCHIVE'):
            remote.unpack_agent(self.archive, self.destination)
        self.assertFalse(self.destination.exists())

    def test_existing_destination_is_not_overwritten(self):
        self.destination.mkdir()
        marker = self.destination / 'preserved'
        marker.write_bytes(b'preserved-canary')
        self.write_archive(self.absolute_fixture())
        with self.assertRaisesRegex(remote.Refused, 'EXISTING_AGENT_ARCHIVE_REFUSED'):
            remote.unpack_agent(self.archive, self.destination)
        self.assertEqual(marker.read_bytes(), b'preserved-canary')
        self.assertEqual(list(self.destination.iterdir()), [marker])

    def test_known_absolute_directories_and_alternative_agent_root_are_supported(self):
        self.write_archive([('/etc', b'', 'directory'), ('/etc/infisical-agent', b'', 'directory'),
                            ('/etc/infisical-agent/templates/a.env', b'canary', 'file')])
        remote.unpack_agent(self.archive, self.destination)
        self.assertEqual((self.destination / 'etc/infisical-agent/templates/a.env').read_bytes(), b'canary')


if __name__ == '__main__':
    unittest.main()

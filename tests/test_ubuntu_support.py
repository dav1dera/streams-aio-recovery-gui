import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ubuntu_probe', ROOT / 'remote/probe.py')
probe = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {'pwd': N()} if sys.platform == 'win32' else {}):
    spec.loader.exec_module(probe)


class UbuntuSupport(unittest.TestCase):
    def test_supported_versions_select_their_own_repository(self):
        for version, codename in [('24.04', 'noble'), ('26.04', 'resolute')]:
            with self.subTest(version=version):
                info = dict(ID='ubuntu', VERSION_ID='"' + version + '"',
                            VERSION_CODENAME=codename, UBUNTU_CODENAME=codename)
                self.assertEqual(probe.ubuntu_codename(info), codename)

    def test_other_versions_and_derivatives_are_refused(self):
        for distribution, version in [('debian', '26.04'), ('linuxmint', '26.04'),
                                      ('ubuntu', '22.04'), ('ubuntu', '26.10'), ('ubuntu', '28.04')]:
            with self.subTest(distribution=distribution, version=version):
                with self.assertRaisesRegex(ValueError, '^UBUNTU_LTS_VERSION_REQUIRED$'):
                    probe.ubuntu_codename(dict(ID=distribution, VERSION_ID=version,
                                              VERSION_CODENAME='resolute'))

    def test_missing_or_conflicting_codenames_are_refused(self):
        for fields in [{}, {'VERSION_CODENAME': 'noble'},
                       {'VERSION_CODENAME': 'resolute', 'UBUNTU_CODENAME': 'noble'},
                       {'VERSION_CODENAME': 'resolute\nprivate-canary'}]:
            with self.subTest(fields=fields):
                with self.assertRaisesRegex(ValueError, '^UBUNTU_CODENAME_MISMATCH$') as error:
                    probe.ubuntu_codename(dict(ID='ubuntu', VERSION_ID='26.04', **fields))
                self.assertNotIn('canary', str(error.exception))

    def run_probe(self, version, docker=False, machine='x86_64', legacy_data=False):
        codename = {'24.04': 'noble', '26.04': 'resolute'}[version]
        original_read = Path.read_text
        original_exists, original_iterdir = Path.exists, Path.iterdir
        def exists(path):
            return legacy_data if path.as_posix() == '/var/lib/docker' else original_exists(path)
        def iterdir(path):
            return iter([Path('fixture-old-data')]) if path.as_posix() == '/var/lib/docker' else original_iterdir(path)
        def read(path, *args, **kwargs):
            if path.as_posix() == '/etc/os-release':
                return f'ID=ubuntu\nVERSION_ID="{version}"\nVERSION_CODENAME={codename}\n'
            if path.as_posix() == '/etc/machine-id':
                return 'fixture-machine\n'
            return original_read(path, *args, **kwargs)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with patch.object(Path, 'read_text', read), \
                 patch.object(Path, 'exists', exists), patch.object(Path, 'iterdir', iterdir), \
                 patch.object(probe.pwd, 'getpwuid', return_value=N(pw_gid=1000, pw_name='pi', pw_dir='/home/pi'), create=True), \
                 patch.object(os, 'uname', return_value=N(machine=machine), create=True), \
                 patch.object(probe.shutil, 'which', return_value='/usr/bin/docker' if docker else None), \
                 patch.object(probe.subprocess, 'run', return_value=N(returncode=0, stdout=b'existing-container\n')):
                return probe.probe(root/'stack', root/'runner', fresh=True)

    @unittest.skipIf(sys.platform == 'win32', 'The host probe uses Linux absolute paths')
    def test_host_probe_reports_the_actual_version(self):
        for version in ('24.04', '26.04'):
            result = self.run_probe(version)
            self.assertEqual(result['os'], 'Ubuntu ' + version)
            self.assertEqual(result['architecture'], 'amd64')

    @unittest.skipIf(sys.platform == 'win32', 'The host probe uses Linux absolute paths')
    def test_new_os_does_not_bypass_existing_runtime_or_architecture_guards(self):
        with self.assertRaisesRegex(ValueError, '^FRESH_DOCKER_HOST_REQUIRED$'):
            self.run_probe('26.04', docker=True)
        with self.assertRaisesRegex(ValueError, '^UBUNTU_AMD64_REQUIRED$'):
            self.run_probe('26.04', machine='aarch64')
        with self.assertRaisesRegex(ValueError, '^EXISTING_DOCKER_DATA$'):
            self.run_probe('26.04', legacy_data=True)


if __name__ == '__main__':
    unittest.main()

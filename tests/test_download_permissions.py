"""Download promotion guards and real root -> UID 1000 Linux permissions.

Only synthetic files are written; no network or credentials are used.
"""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('download_recovery', ROOT / 'remote/recover.py')
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
TAG = 'dr-20261004T023903Z'
META = dict(tag_name=TAG, draft=False, assets=[
    dict(name=name, state='uploaded', size=7) for name in sorted(recovery.BUNDLE_FILES)])
ROOT_POSIX = os.name == 'posix' and os.geteuid() == 0


def verified_manifest(manager, stage, tag):
    """Return the same schema-1 contract as a successful real verifier."""
    assert tag == TAG
    return dict(schema=1, managed_by='streams-aio-dr-managed:v1',
                repository='dav1dera/streams-aio-dr', run=TAG[3:],
                local_snapshot=TAG[3:], infisical_snapshot=TAG[3:],
                source_commit='a' * 40, encryption='age', artifacts={
                    name: dict(sha256=hashlib.sha256((stage / name).read_bytes()).hexdigest(),
                               size=(stage / name).stat().st_size)
                    for name in recovery.ASSETS})


def fixture(home):
    job = recovery.Recovery.__new__(recovery.Recovery)
    job.home = home
    job.manager = home / 'manager'
    job.bundle = home / 'ciphertext'
    job.config = dict(dr_tag=TAG)
    job.state = {}
    return job


class DownloadGuards(unittest.TestCase):
    def test_ownership_failure_stops_before_download_without_logging_details(self):
        with tempfile.TemporaryDirectory() as folder:
            job = fixture(Path(folder))
            with patch.object(recovery, 'command', return_value=json.dumps(META).encode()) as command, \
                 patch.object(recovery.os, 'geteuid', return_value=0, create=True), \
                 patch.object(recovery.os, 'chown', side_effect=PermissionError('private-canary'), create=True):
                with self.assertRaisesRegex(recovery.Refused, '^DR_DOWNLOAD_DIRECTORY_FAILED$'):
                    job.download()
            self.assertEqual(command.call_count, 1)
            self.assertFalse(job.bundle.exists())
            self.assertNotIn('tag', job.state)
            self.assertEqual(len(list(job.home.glob('download-*'))), 1)

    def fake_command(self, args, code):
        if args[1] == 'api':
            return json.dumps(META).encode()
        self.assertEqual(args[:3], ['gh', 'release', 'download'])
        stage = Path(args[-1])
        for asset in META['assets']:
            (stage / asset['name']).write_bytes(b'fixture')
        return b''

    def test_failed_verification_preserves_stage_and_retry_uses_a_new_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            job = fixture(Path(folder))
            with patch.object(recovery.os, 'geteuid', return_value=1000, create=True), \
                 patch.object(recovery, 'command', side_effect=self.fake_command), \
                 patch.object(recovery, 'validate_bundle', side_effect=recovery.Refused('DR_BUNDLE_VERIFICATION_FAILED')):
                with self.assertRaisesRegex(recovery.Refused, '^DR_BUNDLE_VERIFICATION_FAILED$'):
                    job.download()
            old_stage, = job.home.glob('download-*')
            self.assertFalse(job.bundle.exists())
            self.assertNotIn('tag', job.state)
            with patch.object(recovery.os, 'geteuid', return_value=1000, create=True), \
                 patch.object(recovery, 'command', side_effect=self.fake_command), \
                 patch.object(recovery, 'validate_bundle', side_effect=verified_manifest) as verify:
                job.download()
            self.assertTrue(old_stage.is_dir())
            self.assertNotEqual(verify.call_args.args[1], old_stage)
            self.assertEqual({p.name for p in job.bundle.iterdir()}, recovery.BUNDLE_FILES)
            self.assertEqual(job.state['tag'], TAG)

    def test_size_mismatch_is_not_promoted_even_after_bundle_verification(self):
        def wrong_size(args, code):
            result = self.fake_command(args, code)
            if args[1] == 'release':
                (Path(args[-1]) / 'SHA256SUMS').write_bytes(b'truncated')
            return result
        with tempfile.TemporaryDirectory() as folder:
            job = fixture(Path(folder))
            with patch.object(recovery.os, 'geteuid', return_value=1000, create=True), \
                 patch.object(recovery, 'command', side_effect=wrong_size), \
                 patch.object(recovery, 'validate_bundle', side_effect=verified_manifest) as verify:
                with self.assertRaisesRegex(recovery.Refused, '^DOWNLOADED_ASSET_SIZE_MISMATCH$'):
                    job.download()
            verify.assert_called_once()
            self.assertFalse(job.bundle.exists())
            self.assertNotIn('tag', job.state)

    def test_existing_bundle_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            job = fixture(Path(folder))
            job.bundle.mkdir()
            marker = job.bundle / 'preserved'
            marker.write_bytes(b'fixture')
            with patch.object(recovery, 'command', return_value=json.dumps(META).encode()) as command:
                with self.assertRaisesRegex(recovery.Refused, '^EXISTING_BUNDLE_REFUSED$'):
                    job.download()
            self.assertEqual(command.call_count, 1)
            self.assertEqual(marker.read_bytes(), b'fixture')

    def test_ci_permission_integration_cannot_silently_skip(self):
        if os.environ.get('RECOVERY_PERMISSION_INTEGRATION') == '1':
            self.assertTrue(ROOT_POSIX, 'Run permission integration as root in the Ubuntu container')


@unittest.skipUnless(ROOT_POSIX, 'Requires a Linux root process and a real UID 1000 child')
class RealDownloadPermissions(unittest.TestCase):
    def test_root_installer_allows_unprivileged_download_and_keeps_files_private(self):
        # /tmp is traversable by UID 1000; a root-owned workspace may not be.
        with tempfile.TemporaryDirectory(dir='/tmp') as folder:
            home = Path(folder)
            os.chown(home, 1000, 1000)
            os.chmod(home, 0o700)
            job = fixture(home)
            def as_user():
                os.setgroups([])
                os.setgid(1000)
                os.setuid(1000)
                os.umask(0o077)
            def command(args, code):
                if args[1] == 'api':
                    return json.dumps(META).encode()
                stage = Path(args[-1])
                writer = ('import json,sys; from pathlib import Path; '
                          'p=Path(sys.argv[1]); '
                          '[ (p/name).write_bytes(b"fixture") for name in json.loads(sys.argv[2]) ]')
                result = subprocess.run([sys.executable, '-c', writer, str(stage),
                                         json.dumps(sorted(recovery.BUNDLE_FILES))],
                                        preexec_fn=as_user, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, 'UID 1000 must be able to write the private stage')
                return b''
            def verified(manager, stage, tag):
                self.assertFalse(job.bundle.exists())
                self.assertEqual(tag, TAG)
                self.assertEqual(stage.stat().st_uid, 1000)
                self.assertEqual(stage.stat().st_gid, 1000)
                self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)
                for asset in recovery.BUNDLE_FILES:
                    info = (stage / asset).stat()
                    self.assertEqual(info.st_uid, 1000)
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                return verified_manifest(manager, stage, tag)
            with patch.object(recovery, 'command', side_effect=command), \
                 patch.object(recovery, 'validate_bundle', side_effect=verified) as verify:
                job.download()
            verify.assert_called_once()
            self.assertTrue(job.bundle.is_dir())
            self.assertEqual(job.state['tag'], TAG)


if __name__ == '__main__':
    unittest.main()

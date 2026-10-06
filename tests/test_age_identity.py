"""Identity text handling and real age round trips with disposable keys only."""
import codecs
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('age_identity_recovery', ROOT / 'remote/recover.py')
remote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remote)


class IdentityText(unittest.TestCase):
    def test_windows_encodings_preserve_original_key_material(self):
        key = 'AGE-SECRET-KEY-1SYNTHETICCANARY'
        text = '# synthetic fixture\r\n\r\n  ' + key + '  \r\n'
        for raw in (text.encode(), codecs.BOM_UTF8 + text.encode(),
                    codecs.BOM_UTF16_LE + text.encode('utf-16-le'),
                    codecs.BOM_UTF16_BE + text.encode('utf-16-be')):
            self.assertEqual(remote.canonical_age_identity(raw), (key + '\n').encode())

    def test_unsupported_or_public_inputs_refuse_without_values(self):
        cases = [(b'age1publiccanary\n', 'AGE_PUBLIC_KEY_NOT_IDENTITY'),
                 (b'canary-only-an-alphanumeric-code', 'AGE_PRIVATE_IDENTITY_REQUIRED'),
                 (b'# no identity\n', 'AGE_PRIVATE_IDENTITY_REQUIRED'),
                 (b'AGE-PLUGIN-CANARY-1\n', 'AGE_PRIVATE_IDENTITY_REQUIRED'),
                 (b'\xffcanary', 'AGE_IDENTITY_ENCODING_INVALID'),
                 (b'A' * 65537, 'AGE_IDENTITY_FILE_INVALID')]
        for raw, code in cases:
            with self.assertRaises(remote.Refused) as error:
                remote.canonical_age_identity(raw)
            self.assertEqual(str(error.exception), code)
            self.assertNotIn('canary', str(error.exception).lower())

    def test_invalid_checksum_stops_before_decrypt_and_removes_canonical_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            identity = root / 'original.txt'
            original = b'AGE-SECRET-KEY-1SYNTHETICCANARY\n'
            identity.write_bytes(original)
            calls = []
            def run(args, code):
                calls.append(args)
                self.assertEqual(args[0], 'age-keygen')
                if os.name != 'nt':
                    self.assertEqual(Path(args[-1]).stat().st_mode & 0o777, 0o600)
                    self.assertEqual(Path(args[-1]).parent.stat().st_mode & 0o777, 0o700)
                raise remote.Refused(code)
            with self.assertRaisesRegex(remote.Refused, '^AGE_IDENTITY_INVALID$'):
                remote.decrypt_all(identity, root / 'bundle', root / 'private', run=run)
            self.assertEqual(len(calls), 1)
            self.assertEqual(identity.read_bytes(), original)
            self.assertFalse((root / 'private').exists())
            self.assertFalse(list(root.glob('age-identity-*')))
            self.assertFalse(list(root.glob('decryption-*')))

    def test_only_fixed_age_errors_are_reported(self):
        for stderr, expected in [
            (b'age: error: no identity matched any of the recipients\nprivate-canary', 'AGE_NO_MATCHING_RECIPIENT'),
            (b'age: error: identity did not match any of the recipients: private-canary', 'AGE_NO_MATCHING_RECIPIENT'),
            (b'error: private-canary', 'AGE_DECRYPTION_FAILED')]:
            result = SimpleNamespace(returncode=1, stdout=b'', stderr=stderr)
            with patch.object(remote.subprocess, 'run', return_value=result):
                with self.assertRaises(remote.Refused) as error:
                    remote.command(['age', '--decrypt'], 'AGE_DECRYPTION_FAILED')
            self.assertEqual(str(error.exception), expected)
            self.assertNotIn('canary', str(error.exception))


class NativeAge(unittest.TestCase):
    def setUp(self):
        if os.environ.get('RECOVERY_AGE_INTEGRATION') != '1':
            self.skipTest('Enable RECOVERY_AGE_INTEGRATION for native age tests')
        self.assertTrue(shutil.which('age') and shutil.which('age-keygen'),
                        'Native age integration requires both bootstrap tools')
        if os.name != 'nt':
            # Match recover.main's private file creation policy for these
            # in-process fixtures; keep the mode assertions below active.
            previous_umask = os.umask(0o077)
            self.addCleanup(os.umask, previous_umask)
        # Production runs on Linux; Windows fixtures do not emulate POSIX modes.
        if os.name == 'nt':
            def fixture_private(path, outside=()):
                path = remote.safe_path(path)
                remote.require(path.is_file(), 'PRIVATE_INPUT_FILE_REQUIRED')
                return path
            mocked = patch.object(remote, 'private_file', fixture_private)
            mocked.start()
            self.addCleanup(mocked.stop)
        self.tmp = tempfile.TemporaryDirectory(prefix='synthetic-age-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.identities, recipients = [], []
        for index in range(3):
            identity = self.root / ('key-' + str(index) + '.txt')
            made = subprocess.run(['age-keygen', '-o', str(identity)], capture_output=True)
            self.assertEqual(made.returncode, 0, 'Synthetic key generation failed')
            public = subprocess.run(['age-keygen', '-y', str(identity)], capture_output=True)
            self.assertEqual(public.returncode, 0, 'Synthetic recipient derivation failed')
            recipients.append(public.stdout.decode('ascii').strip())
            self.identities.append(identity)
        self.bundle = self.root / 'bundle'
        self.bundle.mkdir()
        for asset in remote.ASSETS:
            encrypted = subprocess.run(['age', '--encrypt', '--recipient', recipients[0],
                                        '--recipient', recipients[1], '--output', str(self.bundle / asset)],
                                       input=b'synthetic-disposable-payload', capture_output=True)
            self.assertEqual(encrypted.returncode, 0, 'Synthetic encryption failed')

    def test_primary_and_recovery_with_windows_encodings_decrypt_complete_set(self):
        for index in (0, 1):
            text = self.identities[index].read_text()
            variants = [text.encode(), codecs.BOM_UTF8 + text.encode(),
                        codecs.BOM_UTF16_LE + text.encode('utf-16-le'),
                        codecs.BOM_UTF16_BE + text.encode('utf-16-be'),
                        text.replace('\n', '\r\n').encode()]
            for number, raw in enumerate(variants):
                identity = self.root / ('input-' + str(index) + '-' + str(number) + '.txt')
                identity.write_bytes(raw)
                destination = self.root / ('private-' + str(index) + '-' + str(number))
                remote.decrypt_all(identity, self.bundle, destination)
                self.assertEqual(set(p.name for p in destination.iterdir()), set(remote.ASSETS.values()))
                for file in destination.iterdir():
                    self.assertEqual(file.read_bytes(), b'synthetic-disposable-payload')
                    if os.name != 'nt':
                        self.assertEqual(file.stat().st_mode & 0o777, 0o600)
                self.assertEqual(identity.read_bytes(), raw)
                self.assertFalse(list(self.root.glob('age-identity-*')))

    def test_valid_unrelated_identity_refuses_without_installing_private_set(self):
        with self.assertRaisesRegex(remote.Refused, '^AGE_NO_MATCHING_RECIPIENT$'):
            remote.decrypt_all(self.identities[2], self.bundle, self.root / 'private')
        self.assertFalse((self.root / 'private').exists())
        self.assertTrue(list(self.root.glob('decryption-*')))
        self.assertFalse(list(self.root.glob('age-identity-*')))


if __name__ == '__main__':
    unittest.main()

"""Pasted identities are normalized in RAM and never echoed by validation."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from recovery_gui.age_input import (AgeInputFailure, MAX_IDENTITY_BYTES,
                                    validate_identity_input, validate_pasted_identity)


IDENTITY = 'AGE-SECRET-KEY-1SYNTHETICCANARY'


class AgeInputTests(unittest.TestCase):
    def refused(self, text, code):
        with self.assertRaises(AgeInputFailure) as caught:
            validate_pasted_identity(text)
        self.assertEqual(str(caught.exception), code)
        self.assertNotIn('CANARY', repr(caught.exception))

    def test_comments_bom_and_line_endings_have_one_canonical_line(self):
        for text in (IDENTITY, '\ufeff# created: synthetic\r\n\r\n' + IDENTITY + '\r\n',
                     ' \n# public key: age1synthetic\n  ' + IDENTITY + ' \r',
                     '# comment\r' + IDENTITY + '\r# another comment'):
            with self.subTest(text_kind=len(text)):
                self.assertEqual(validate_pasted_identity(text), (IDENTITY + '\n').encode())

    def test_pasted_mode_uses_no_files_and_ignores_inactive_file_selection(self):
        with patch.object(Path, 'open', side_effect=AssertionError('local file opened')), \
             patch.object(Path, 'write_bytes', side_effect=AssertionError('local file written')), \
             patch.object(Path, 'is_file', side_effect=AssertionError('local file inspected')):
            self.assertIsNone(validate_identity_input(dict(age_identity_mode='paste',
                age_identity_text=IDENTITY, age_identity='C:/does-not-exist/private.age')))

    def test_unsupported_and_multiple_identities_have_fixed_errors(self):
        for value in ('', '# comment only\n', IDENTITY + '\n' + IDENTITY,
                      'ssh-ed25519 SYNTHETICCANARY', 'passphrase:SYNTHETICCANARY',
                      'age-secret-key-1SYNTHETICCANARY', IDENTITY + '!'):
            with self.subTest(value_kind=len(value)):
                self.refused(value, 'AGE_PRIVATE_IDENTITY_REQUIRED')

    def test_public_identity_never_becomes_a_private_input(self):
        for value in ('age1syntheticcanary', IDENTITY + '\nage1syntheticcanary'):
            self.refused(value, 'AGE_PUBLIC_KEY_NOT_IDENTITY')

    def test_controls_and_interior_bom_are_rejected_without_echo(self):
        for control in ('\x00', '\t', '\x7f', '\u202e', '\ufeff'):
            self.refused('# comment' + control + '\n' + IDENTITY,
                         'AGE_PRIVATE_IDENTITY_REQUIRED')

    def test_encoding_failure_and_wrong_type_are_fixed(self):
        self.refused(IDENTITY + '\ud800', 'AGE_IDENTITY_ENCODING_INVALID')
        for value in (None, 123, b'AGE-SECRET-KEY-1SYNTHETICCANARY'):
            self.refused(value, 'AGE_PRIVATE_IDENTITY_REQUIRED')

    def test_limit_counts_utf8_bytes_including_comments(self):
        overhead = len(('#\n' + IDENTITY).encode())
        text = '#' + 'a' * (MAX_IDENTITY_BYTES - overhead) + '\n' + IDENTITY
        self.assertEqual(len(text.encode()), MAX_IDENTITY_BYTES)
        self.assertEqual(validate_pasted_identity(text), (IDENTITY + '\n').encode())
        self.refused(text + ' ', 'AGE_IDENTITY_FILE_INVALID')
        # Unicode comments cost their encoded byte length, not character count.
        self.refused('#' + '\u00e9' * (MAX_IDENTITY_BYTES // 2) + '\n' + IDENTITY,
                     'AGE_IDENTITY_FILE_INVALID')

    def test_existing_file_mode_defaults_and_ignores_pasted_text(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as folder:
            path = Path(folder) / 'identity.txt'
            path.write_bytes((IDENTITY + '\n').encode())
            for mode in ({}, dict(age_identity_mode='file')):
                self.assertIsNone(validate_identity_input(dict(mode, age_identity=str(path),
                    age_identity_text='invalid stale clipboard')))

    def test_file_mode_errors_are_fixed_and_do_not_read_file_contents(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as folder:
            path = Path(folder) / 'too-large.txt'
            path.write_bytes(b'a' * (MAX_IDENTITY_BYTES + 1))
            with self.assertRaisesRegex(AgeInputFailure, '^AGE_IDENTITY_FILE_INVALID$'):
                validate_identity_input(dict(age_identity=str(path)))
            with self.assertRaisesRegex(AgeInputFailure, '^AGE_IDENTITY_FILE_REQUIRED$'):
                validate_identity_input(dict(age_identity=str(path) + '.missing'))
            with patch.object(Path, 'read_bytes', side_effect=AssertionError('file read')), \
                 patch.object(Path, 'is_file', return_value=True), \
                 patch.object(Path, 'is_symlink', return_value=True):
                with self.assertRaisesRegex(AgeInputFailure, '^AGE_IDENTITY_FILE_INVALID$'):
                    validate_identity_input(dict(age_identity=str(path)))

    def test_invalid_mode_and_snapshot_do_not_fall_back(self):
        for value in (None, [], dict(age_identity_mode='unknown'),
                      dict(age_identity_mode='file', age_identity='')):
            with self.assertRaises(AgeInputFailure) as caught:
                validate_identity_input(value)
            self.assertIn(str(caught.exception), ('AGE_IDENTITY_FILE_INVALID',
                                                  'AGE_IDENTITY_FILE_REQUIRED'))


if __name__ == '__main__':
    unittest.main()

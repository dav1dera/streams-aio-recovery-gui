"""Only authenticated SFTP receives pasted identity bytes; no local staging."""
import json
from pathlib import Path
import stat
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

from recovery_gui import backend


IDENTITY = 'AGE-SECRET-KEY-1SYNTHETICCANARY'
CANONICAL = (IDENTITY + '\n').encode()


class Handle:
    def __init__(self, sftp, path, mode):
        self.sftp, self.path, self.mode = sftp, path, mode
        self.offset = 0

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.sftp.events.append(('close_handle', self.mode))

    def chmod(self, mode):
        self.sftp.events.append(('fchmod', mode))
        if self.sftp.bad_chmod:
            raise OSError('secret error: ' + IDENTITY)
        self.sftp.files[self.path]['mode'] = mode

    def stat(self):
        self.sftp.events.append(('fstat', self.mode))
        file = self.sftp.files[self.path]
        mode = file['mode']
        if self.sftp.bad_prewrite_mode and 'w' in self.mode:
            mode = 0o644
        if self.sftp.bad_readback_mode and self.mode == 'rb':
            mode = 0o644
        return N(st_mode=stat.S_IFREG | mode, st_size=len(file['bytes']))

    def write(self, raw):
        file = self.sftp.files[self.path]
        # This assertion is the meaningful boundary: no bytes before hardening.
        if file['mode'] != 0o600 or ('fstat', 'wx') not in self.sftp.events:
            raise AssertionError('identity written before permissions were verified')
        self.sftp.events.append(('write', len(raw)))
        file['bytes'] += raw

    def flush(self):
        self.sftp.events.append(('flush', self.mode))

    def read(self, count):
        self.sftp.events.append(('read', count))
        raw = self.sftp.files[self.path]['bytes']
        if self.sftp.corrupt_readback:
            raw = b'X' * len(raw)
        if self.sftp.truncate_readback:
            raw = raw[:-1]
        if self.sftp.extend_readback:
            raw += b'X'
        result = raw[self.offset:self.offset + count]
        self.offset += len(result)
        return result


class SFTP:
    def __init__(self):
        self.files, self.events = {}, []
        self.closed = False
        self.bad_chmod = self.bad_prewrite_mode = self.bad_readback_mode = False
        self.corrupt_readback = self.truncate_readback = self.extend_readback = False

    def chmod(self, *args):
        self.events.append(('chmod_directory', args))

    def mkdir(self, *args, **kwargs):
        self.events.append(('mkdir', args))

    def close(self):
        self.closed = True

    def open(self, path, mode):
        self.events.append(('open', mode))
        if mode == 'wx':
            if path in self.files:
                raise FileExistsError('do not echo: ' + IDENTITY)
            self.files[path] = dict(mode=0o644, bytes=b'')
        return Handle(self, path, mode)


class AgeUploadTests(unittest.TestCase):
    def setUp(self):
        self.sftp = SFTP()
        self.connection = backend.SSH.__new__(backend.SSH)
        self.connection.host = N(user='replacement')
        self.connection.check = Mock(return_value={'home': '/home/replacement'})
        self.connection.run = Mock(return_value=b'')
        self.connection.client = N(open_sftp=Mock(return_value=self.sftp))
        self.transferred = []
        self.connection._put = lambda sftp, source, destination: self.transferred.append((source, destination))
        self.request = dict(github_token='synthetic-token', public_commit='b' * 40,
            dr_tag='dr-20261020T120000Z', infisical_address='', project_id='',
            environment='', aio_mode='snapshot', native_agent=True,
            age_identity_mode='paste', age_identity_text='# created\r\n' + IDENTITY + '\r\n',
            age_identity='C:/stale/inactive-identity.txt')
        mock = patch.object(backend, 'validate_remote_shell_scripts')
        mock.start()
        self.addCleanup(mock.stop)

    def test_paste_upload_is_exclusive_0600_verified_and_config_is_path_only(self):
        with patch('tempfile.NamedTemporaryFile', side_effect=AssertionError('local temp file')), \
             patch.object(Path, 'write_bytes', side_effect=AssertionError('local write')), \
             patch.object(Path, 'write_text', side_effect=AssertionError('local write')):
            stage, raw = self.connection.upload(self.request)
        destination = stage + '/age_identity'
        self.assertEqual(self.sftp.files[destination], dict(mode=0o600, bytes=CANONICAL))
        self.assertEqual(json.loads(raw)['age_identity'], destination)
        self.assertNotIn('age_identity_mode', json.loads(raw))
        self.assertNotIn('age_identity_text', json.loads(raw))
        self.assertNotIn(IDENTITY.encode(), raw)
        self.assertNotIn(IDENTITY, repr(self.connection.run.call_args_list))
        self.assertNotIn(Path(self.request['age_identity']), [p for p, _ in self.transferred])
        self.assertIn(('open', 'wx'), self.sftp.events)
        self.assertLess(self.sftp.events.index(('fchmod', 0o600)),
                        self.sftp.events.index(('write', len(CANONICAL))))
        self.assertIn(('read', len(CANONICAL) + 1), self.sftp.events)
        self.assertTrue(self.sftp.closed)

    def test_infisical_role_gets_its_own_protected_upload(self):
        stage, raw = self.connection.upload(dict(self.request, role='infisical'))
        self.assertIn('/streams-aio-infisical-recovery/', stage)
        self.assertEqual(json.loads(raw)['age_identity'], stage + '/age_identity')
        self.connection.check.assert_called_once_with(role='infisical')

    def test_file_mode_retains_old_upload_and_ignores_stale_paste(self):
        for mode in ({'age_identity_mode': 'file'}, {}):
            request = dict(self.request, **mode)
            if not mode:
                del request['age_identity_mode']
            request['age_identity_text'] = 'invalid stale clipboard'
            with patch.object(self.connection, '_put_private_bytes',
                              side_effect=AssertionError('paste mode used')):
                stage, raw = self.connection.upload(request)
            self.assertIn((Path(request['age_identity']), stage + '/age_identity'), self.transferred)
            self.assertEqual(json.loads(raw)['age_identity'], stage + '/age_identity')
        self.assertFalse(self.sftp.files)

    def test_invalid_paste_or_mode_fails_before_ssh_and_does_not_echo(self):
        for change, code in ((dict(age_identity_text=IDENTITY + '\n' + IDENTITY), 'AGE_PRIVATE_IDENTITY_REQUIRED'),
                             (dict(age_identity_text='age1synthetic'), 'AGE_PUBLIC_KEY_NOT_IDENTITY'),
                             (dict(age_identity_mode='unknown'), 'AGE_IDENTITY_FILE_INVALID')):
            with self.assertRaises(backend.Failure) as caught:
                self.connection.upload(dict(self.request, **change))
            self.assertEqual(str(caught.exception), code)
            self.assertNotIn(IDENTITY, repr(caught.exception))
        self.connection.check.assert_not_called()
        self.connection.run.assert_not_called()
        self.connection.client.open_sftp.assert_not_called()

    def test_existing_remote_file_is_not_overwritten(self):
        destination = '/protected/age_identity'
        before = dict(mode=0o600, bytes=b'previous-private-key')
        self.sftp.files[destination] = dict(before)
        with self.assertRaisesRegex(backend.Failure, '^SSH_UPLOAD_FAILED$'):
            backend.SSH._put_private_bytes(self.sftp, CANONICAL, destination)
        self.assertEqual(self.sftp.files[destination], before)
        self.assertFalse(any(event[0] == 'write' for event in self.sftp.events))

    def test_permissions_failure_prevents_all_private_writes(self):
        for flag in ('bad_chmod', 'bad_prewrite_mode'):
            sftp = SFTP()
            setattr(sftp, flag, True)
            with self.assertRaises(backend.Failure) as caught:
                backend.SSH._put_private_bytes(sftp, CANONICAL, '/protected/key')
            self.assertEqual(str(caught.exception), 'SSH_UPLOAD_FAILED')
            self.assertNotIn(IDENTITY, repr(caught.exception))
            self.assertFalse(any(event[0] == 'write' for event in sftp.events))

    def test_readback_hash_length_and_permissions_must_all_match(self):
        for flag, code in (('corrupt_readback', 'SSH_UPLOAD_SHA256_MISMATCH'),
                           ('truncate_readback', 'SSH_UPLOAD_SHA256_MISMATCH'),
                           ('extend_readback', 'SSH_UPLOAD_SHA256_MISMATCH'),
                           ('bad_readback_mode', 'SSH_UPLOAD_FAILED')):
            with self.subTest(flag=flag):
                sftp = SFTP()
                setattr(sftp, flag, True)
                with self.assertRaisesRegex(backend.Failure, '^' + code + '$'):
                    backend.SSH._put_private_bytes(sftp, CANONICAL, '/protected/key')

    def test_failed_upload_closes_sftp_and_never_starts_bootstrap(self):
        self.sftp.corrupt_readback = True
        with self.assertRaisesRegex(backend.Failure, '^SSH_UPLOAD_SHA256_MISMATCH$'):
            self.connection.prepare(self.request, lambda event: None)
        self.assertTrue(self.sftp.closed)
        self.assertEqual(len(self.connection.run.call_args_list), 1)
        self.assertNotIn('bootstrap.sh', repr(self.connection.run.call_args_list))


if __name__ == '__main__':
    unittest.main()

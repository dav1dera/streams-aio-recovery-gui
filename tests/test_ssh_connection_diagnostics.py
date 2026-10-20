"""Actual Paramiko exception classes produce finite diagnostics without text."""
import errno
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import paramiko

from recovery_gui import backend, ssh_identity
from tests import test_ssh_identity as fixtures


SECRET = 'synthetic-private-exception-must-not-be-rendered'


class NoTextSSHError(paramiko.SSHException):
    def __str__(self):
        raise AssertionError('raw exception text was read')


class SSHConnectionDiagnostics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.new = paramiko.ECDSAKey.generate()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.host = backend.Host('192.0.2.33', user='replacement', password=SECRET)
        self.cancelled = threading.Event()
        self.connection_attempts = 0
        self.client = fixtures.CheckedClient(self, remote_key=self.new)
        self.client.transport.is_active.return_value = True
        self.client.transport.is_authenticated.return_value = True
        self.confirm = Mock(return_value=True)
        self.changed = Mock(return_value=True)
        self.store = self.root/'StreamsAIORecovery/known_hosts'
        self.patches = [patch.dict(os.environ, {'LOCALAPPDATA': str(self.root)}),
            patch('recovery_gui.ssh_identity.Path.home', return_value=self.root),
            patch('paramiko.SSHClient', return_value=self.client)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def connect(self):
        return backend.SSH(self.host, self.confirm, self.cancelled, confirm_changed_key=self.changed)

    def fail_connect(self, error, code, *, before_trust=False):
        self.client.closed = False
        if before_trust:
            self.client.connect = Mock(side_effect=error)
        else:
            def fail(_):
                raise error
            self.client.before_auth = fail
        with self.assertRaises(backend.Failure) as caught:
            self.connect()
        self.assertEqual(str(caught.exception), code)
        self.assertNotIn(SECRET, repr(caught.exception))
        self.assertTrue(self.client.closed)
        self.assertFalse(self.store.exists())
        self.changed.assert_not_called()

    def test_socket_causes_have_closed_codes_and_never_save_an_approved_key(self):
        cases = [(socket.timeout(SECRET), 'SSH_CONNECT_TIMEOUT'),
                 (ConnectionRefusedError(errno.ECONNREFUSED, SECRET), 'SSH_CONNECTION_REFUSED'),
                 (socket.gaierror(socket.EAI_NONAME, SECRET), 'SSH_NAME_RESOLUTION_FAILED'),
                 (OSError(errno.ENETUNREACH, SECRET), 'SSH_NETWORK_UNREACHABLE'),
                 (OSError(errno.EHOSTUNREACH, SECRET), 'SSH_NETWORK_UNREACHABLE'),
                 (PermissionError(errno.EACCES, SECRET), 'SSH_LOCAL_NETWORK_DENIED'),
                 (PermissionError(10013, SECRET), 'SSH_LOCAL_NETWORK_DENIED'),
                 (OSError(10061, SECRET), 'SSH_CONNECTION_REFUSED'),
                 (OSError(10060, SECRET), 'SSH_CONNECT_TIMEOUT'),
                 (ConnectionResetError(errno.ECONNRESET, SECRET), 'SSH_TRANSPORT_CLOSED'),
                 (EOFError(SECRET), 'SSH_TRANSPORT_CLOSED')]
        for error, code in cases:
            with self.subTest(code=code, error_type=type(error).__name__):
                self.fail_connect(error, code, before_trust=True)

    def test_no_valid_connections_uses_only_nested_types_and_numbers(self):
        for inner, code in ((ConnectionRefusedError(errno.ECONNREFUSED, SECRET), 'SSH_CONNECTION_REFUSED'),
                            (PermissionError(10013, SECRET), 'SSH_LOCAL_NETWORK_DENIED')):
            error = paramiko.ssh_exception.NoValidConnectionsError({('192.0.2.33', 22): inner})
            with self.subTest(code=code):
                self.fail_connect(error, code, before_trust=True)
        mixed = paramiko.ssh_exception.NoValidConnectionsError({
            ('192.0.2.33', 22): ConnectionRefusedError(errno.ECONNREFUSED, SECRET),
            ('192.0.2.34', 22): OSError(errno.ENETUNREACH, SECRET)})
        self.fail_connect(mixed, 'SSH_CONNECTION_FAILED', before_trust=True)

    def test_ssh_protocol_error_never_reads_or_copies_its_message(self):
        self.fail_connect(NoTextSSHError(SECRET), 'SSH_PROTOCOL_FAILED')
        self.confirm.assert_called_once()

    def test_passphrase_and_unsupported_key_type_are_proven_by_exception_class(self):
        self.fail_connect(paramiko.PasswordRequiredException(SECRET), 'SSH_KEY_PASSPHRASE_REQUIRED')
        self.fail_connect(paramiko.pkey.UnknownKeyType(key_type='unsupported', key_bytes=SECRET.encode()),
                          'SSH_KEY_FORMAT_INVALID')

    def test_authentication_error_keeps_its_existing_diagnostic(self):
        self.fail_connect(paramiko.AuthenticationException(SECRET), 'SSH_AUTH_FAILED')
        self.assertFalse(self.store.exists())

    def test_unrelated_exception_remains_generic_without_exposing_text(self):
        self.fail_connect(RuntimeError(SECRET), 'SSH_CONNECTION_FAILED')

    def test_selected_key_read_failure_is_distinguished_from_local_network_denial(self):
        key = self.root/'selected-ssh-key'
        key.write_text('synthetic placeholder; parsing is mocked')
        self.host.key_file = str(key)
        self.fail_connect(PermissionError(errno.EACCES, SECRET, str(key)), 'SSH_KEY_FILE_UNAVAILABLE')
        self.fail_connect(FileNotFoundError(errno.ENOENT, SECRET, str(key)), 'SSH_KEY_FILE_UNAVAILABLE')
        self.fail_connect(PermissionError(10013, SECRET), 'SSH_LOCAL_NETWORK_DENIED')

    def test_authenticated_but_absent_or_inactive_transport_does_not_persist_trust(self):
        for transport in (None, Mock(is_active=Mock(return_value=False))):
            self.client.before_auth = None
            self.client.transport = transport
            self.client.closed = False
            with self.assertRaisesRegex(backend.Failure, '^SSH_TRANSPORT_CLOSED$'):
                self.connect()
            self.assertTrue(self.client.closed)
            self.assertFalse(self.store.exists())

    def test_failed_keepalive_is_closed_and_never_saves_new_identity(self):
        self.client.transport.set_keepalive.side_effect = paramiko.SSHException(SECRET)
        with self.assertRaisesRegex(backend.Failure, '^SSH_TRANSPORT_CLOSED$'):
            self.connect()
        self.assertTrue(self.client.closed)
        self.assertFalse(self.store.exists())

    def test_active_but_partially_authenticated_transport_never_persists_trust(self):
        self.client.transport.is_authenticated.return_value = False
        with patch.object(ssh_identity, 'remember') as remember:
            with self.assertRaisesRegex(backend.Failure, '^SSH_AUTH_FAILED$'):
                self.connect()
            remember.assert_not_called()
        self.client.transport.set_keepalive.assert_not_called()
        self.assertTrue(self.client.closed)
        self.assertFalse(self.store.exists())

    def test_known_host_load_errors_have_store_code_before_any_connection(self):
        for error in (OSError(SECRET), ValueError(SECRET)):
            self.client.closed = False
            with patch.object(ssh_identity, 'trusted_keys', side_effect=error), \
                 patch.object(self.client, 'connect') as connect:
                with self.assertRaisesRegex(backend.Failure, '^SSH_HOST_KEY_STORE_FAILED$'):
                    self.connect()
                connect.assert_not_called()
            self.assertFalse(self.store.exists())

    def test_local_store_directory_failure_has_closed_code(self):
        with patch.object(Path, 'mkdir', side_effect=PermissionError(SECRET)), \
             patch.object(self.client, 'connect') as connect:
            with self.assertRaisesRegex(backend.Failure, '^SSH_HOST_KEY_STORE_FAILED$'):
                self.connect()
            connect.assert_not_called()

    def test_cleanup_error_does_not_replace_the_original_diagnostic(self):
        self.client.connect = Mock(side_effect=ConnectionRefusedError(errno.ECONNREFUSED, SECRET))
        self.client.close = Mock(side_effect=OSError(SECRET))
        with self.assertRaisesRegex(backend.Failure, '^SSH_CONNECTION_REFUSED$'):
            self.connect()
        self.assertFalse(self.store.exists())


if __name__ == '__main__':
    unittest.main()

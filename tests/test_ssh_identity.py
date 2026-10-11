"""SSH trust changes are verified before auth and scoped to one endpoint.

Keys are generated in memory. The transport double checks real Paramiko
HostKeys before recording authentication; no network or real credentials.
"""
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import paramiko
from recovery_gui import ssh_identity
from recovery_gui.backend import Failure, Host, SSH


class PublicKeys(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old = paramiko.RSAKey.generate(1024)
        cls.new = paramiko.ECDSAKey.generate()
        cls.third = paramiko.RSAKey.generate(1024)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.store = self.root / 'known_hosts'

    def write_keys(self, path, rows):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(''.join(
            f'{label} {key.get_name()} {key.get_base64()}\n'
            for label, key in rows), encoding='ascii')

    def read_keys(self, path=None):
        result = paramiko.HostKeys()
        result.load(str(path or self.store))
        return result

    def assert_identity(self, keys, label, expected):
        self.assertTrue(keys.check(label, expected), label)
        self.assertEqual(set(keys.lookup(label)), {expected.get_name()})


class HostKeyStore(PublicKeys):
    def test_endpoint_is_scoped_to_custom_port_and_ipv6(self):
        self.assertEqual(ssh_identity.endpoint('192.0.2.10', 22), '192.0.2.10')
        self.assertEqual(ssh_identity.endpoint('192.0.2.10', 2222), '[192.0.2.10]:2222')
        self.assertEqual(ssh_identity.endpoint('2001:db8::1', 2222), '[2001:db8::1]:2222')

    def test_replacing_one_alias_preserves_alias_other_host_and_other_port(self):
        self.write_keys(self.store, [
            ('192.0.2.10,vm-alias', self.old),
            ('[192.0.2.10]:2222', self.old),
            ('192.0.2.20', self.third),
        ])
        # Add a second algorithm only for the selected endpoint.
        original = self.read_keys()
        original.add('192.0.2.10', self.new.get_name(), self.new)
        original.save(str(self.store))
        ssh_identity.remember(self.store, '192.0.2.10', self.third)
        result = self.read_keys()
        self.assert_identity(result, '192.0.2.10', self.third)
        self.assert_identity(result, 'vm-alias', self.old)
        self.assert_identity(result, '[192.0.2.10]:2222', self.old)
        self.assert_identity(result, '192.0.2.20', self.third)

    def test_hashed_selected_host_is_replaced_without_removing_other_hash(self):
        selected = paramiko.HostKeys.hash_host('192.0.2.10')
        other = paramiko.HostKeys.hash_host('192.0.2.20')
        self.write_keys(self.store, [(selected, self.old), (other, self.third)])
        ssh_identity.remember(self.store, '192.0.2.10', self.new)
        result = self.read_keys()
        self.assertNotIn(selected, result.keys())
        self.assertIn(other, result.keys())
        self.assert_identity(result, '192.0.2.10', self.new)
        self.assert_identity(result, '192.0.2.20', self.third)

    def test_custom_port_replacement_preserves_default_port(self):
        self.write_keys(self.store, [('192.0.2.10', self.old), ('[192.0.2.10]:2222', self.old)])
        ssh_identity.remember(self.store, '[192.0.2.10]:2222', self.new)
        result = self.read_keys()
        self.assert_identity(result, '192.0.2.10', self.old)
        self.assert_identity(result, '[192.0.2.10]:2222', self.new)

    def test_without_peer_does_not_mutate_original_alias_table(self):
        self.write_keys(self.store, [('192.0.2.10,vm-alias', self.old)])
        original = self.read_keys()
        result = ssh_identity.without_peer(original, '192.0.2.10')
        self.assertIsNone(result.lookup('192.0.2.10'))
        self.assert_identity(result, 'vm-alias', self.old)
        self.assert_identity(original, '192.0.2.10', self.old)
        self.assert_identity(original, 'vm-alias', self.old)

    def test_app_override_preserves_system_file_and_other_system_identities(self):
        system = self.root / '.ssh' / 'known_hosts'
        self.write_keys(system, [('192.0.2.10,vm-alias', self.old), ('192.0.2.20', self.third)])
        original = system.read_bytes()
        self.write_keys(self.store, [('192.0.2.10', self.new)])
        with patch('recovery_gui.ssh_identity.Path.home', return_value=self.root):
            result = ssh_identity.trusted_keys(self.store, '192.0.2.10')
        self.assert_identity(result, '192.0.2.10', self.new)
        self.assert_identity(result, 'vm-alias', self.old)
        self.assert_identity(result, '192.0.2.20', self.third)
        self.assertEqual(system.read_bytes(), original)

    def test_system_key_is_used_when_app_has_no_entry(self):
        system = self.root / '.ssh' / 'known_hosts'
        self.write_keys(system, [('192.0.2.10', self.old)])
        with patch('recovery_gui.ssh_identity.Path.home', return_value=self.root):
            result = ssh_identity.trusted_keys(self.store, '192.0.2.10')
        self.assert_identity(result, '192.0.2.10', self.old)
        self.assertFalse(self.store.exists())

    def test_atomic_replace_failure_keeps_old_store_and_removes_temporary_file(self):
        self.write_keys(self.store, [('192.0.2.10', self.old)])
        original = self.store.read_bytes()
        with patch('recovery_gui.ssh_identity.os.replace', side_effect=OSError('synthetic')) as replace:
            with self.assertRaises(OSError):
                ssh_identity.remember(self.store, '192.0.2.10', self.new)
        replace.assert_called_once()
        self.assertEqual(self.store.read_bytes(), original)
        self.assertEqual(list(self.root.iterdir()), [self.store])


class CheckedClient:
    """Check the host's public key before simulating SSH authentication."""
    def __init__(self, owner, remote_key, auth_error=False, before_auth=None):
        self.owner = owner
        self.remote_key = remote_key
        self.auth_error = auth_error
        self.before_auth = before_auth
        self.keys = paramiko.HostKeys()
        self.closed = False
        self.transport = Mock()
        self.authentication_attempts = 0

    def get_host_keys(self):
        return self.keys

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def connect(self, hostname, *, port, **kwargs):
        self.owner.connection_attempts += 1
        peer = hostname if port == 22 else f'[{hostname}]:{port}'
        known = self.keys.lookup(peer)
        if known is None:
            self.policy.missing_host_key(self, peer, self.remote_key)
        elif not self.keys.check(peer, self.remote_key):
            expected = known.get(self.remote_key.get_name()) or next(iter(known.values()))
            raise paramiko.BadHostKeyException(hostname, self.remote_key, expected)
        if self.before_auth:
            self.before_auth(self)
        self.authentication_attempts += 1
        if self.auth_error:
            raise paramiko.AuthenticationException('synthetic')

    def get_transport(self):
        return self.transport

    def close(self):
        self.closed = True


class SSHIdentityFlow(PublicKeys):
    def setUp(self):
        super().setUp()
        self.store = self.root / 'StreamsAIORecovery' / 'known_hosts'
        self.host = Host('192.0.2.10', user='tester', password='synthetic-test-only')
        self.cancelled = threading.Event()
        self.clients = []
        self.connection_attempts = 0
        self.scenarios = []
        self.first_confirmation = Mock(return_value=True)
        self.changed_confirmation = Mock(return_value=True)
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {'LOCALAPPDATA': str(self.root)}).start()
        patch('recovery_gui.ssh_identity.Path.home', return_value=self.root).start()
        patch('paramiko.SSHClient', side_effect=self.client).start()

    def client(self):
        options = self.scenarios.pop(0)
        result = CheckedClient(self, **options)
        self.clients.append(result)
        return result

    def connect(self, *, changed=True):
        options = {'confirm_changed_key': self.changed_confirmation} if changed else {}
        return SSH(self.host, self.first_confirmation, self.cancelled, **options)

    def expect_failure(self, code, **options):
        with self.assertRaisesRegex(Failure, '^' + code + '$'):
            self.connect(**options)
        self.assertTrue(all(client.closed for client in self.clients))

    def existing(self):
        self.write_keys(self.store, [(ssh_identity.endpoint(self.host.address, self.host.port), self.old)])
        return self.store.read_bytes()

    def test_unchanged_host_does_not_prompt_or_rewrite_store(self):
        original = self.existing()
        self.scenarios = [dict(remote_key=self.old)]
        job = self.connect()
        self.first_confirmation.assert_not_called()
        self.changed_confirmation.assert_not_called()
        self.assertEqual(self.store.read_bytes(), original)
        self.assertEqual(self.connection_attempts, 1)
        self.assertEqual(self.clients[0].authentication_attempts, 1)
        self.clients[0].transport.set_keepalive.assert_called_once_with(15)
        job.close()

    def test_new_ip_saves_only_after_auth_and_uses_entered_endpoint(self):
        self.host.address = '192.0.2.99'
        self.host.port = 2222
        self.scenarios = [dict(remote_key=self.new, before_auth=lambda _: self.assertFalse(self.store.exists()))]
        job = self.connect()
        self.first_confirmation.assert_called_once_with('[192.0.2.99]:2222', ssh_identity.fingerprint(self.new))
        self.changed_confirmation.assert_not_called()
        self.assert_identity(self.read_keys(), '[192.0.2.99]:2222', self.new)
        job.close()

    def test_initial_authentication_failure_does_not_save_approved_key(self):
        self.scenarios = [dict(remote_key=self.new, auth_error=True)]
        self.expect_failure('SSH_AUTH_FAILED')
        self.assertFalse(self.store.exists())

    def test_initial_key_denial_happens_before_authentication(self):
        self.first_confirmation.return_value = False
        self.scenarios = [dict(remote_key=self.new)]
        self.expect_failure('SSH_HOST_KEY_NOT_APPROVED')
        self.assertEqual(self.clients[0].authentication_attempts, 0)
        self.assertFalse(self.store.exists())

    def test_recreated_host_is_pinned_for_one_retry_and_persisted_after_auth(self):
        original = self.existing()
        def approve(peer, old, new):
            self.assertTrue(self.clients[0].closed)
            self.assertEqual(self.clients[0].authentication_attempts, 0)
            self.assertEqual(self.store.read_bytes(), original)
            return True
        self.changed_confirmation.side_effect = approve
        self.scenarios = [dict(remote_key=self.new), dict(
            remote_key=self.new, before_auth=lambda _: self.assertEqual(self.store.read_bytes(), original))]
        job = self.connect()
        self.first_confirmation.assert_not_called()
        self.changed_confirmation.assert_called_once_with(
            self.host.address, ssh_identity.fingerprint(self.old), ssh_identity.fingerprint(self.new))
        self.assertEqual(self.connection_attempts, 2)
        self.assertEqual([client.authentication_attempts for client in self.clients], [0, 1])
        self.assert_identity(self.read_keys(), self.host.address, self.new)
        job.close()
        # Future visits reuse the explicitly verified identity without a prompt.
        self.scenarios = [dict(remote_key=self.new)]
        job = self.connect()
        self.assertEqual(self.changed_confirmation.call_count, 1)
        self.first_confirmation.assert_not_called()
        job.close()

    def test_denied_changed_key_preserves_store_without_authenticating(self):
        original = self.existing()
        self.changed_confirmation.return_value = False
        self.scenarios = [dict(remote_key=self.new)]
        self.expect_failure('SSH_HOST_KEY_NOT_APPROVED')
        self.assertEqual(self.store.read_bytes(), original)
        self.assertEqual(self.connection_attempts, 1)
        self.assertEqual(self.clients[0].authentication_attempts, 0)

    def test_legacy_caller_without_changed_key_callback_fails_closed(self):
        original = self.existing()
        self.scenarios = [dict(remote_key=self.new)]
        self.expect_failure('SSH_HOST_KEY_CHANGED', changed=False)
        self.changed_confirmation.assert_not_called()
        self.assertEqual(self.store.read_bytes(), original)
        self.assertEqual(self.clients[0].authentication_attempts, 0)

    def test_authentication_failure_after_changed_key_preserves_old_store(self):
        original = self.existing()
        self.scenarios = [dict(remote_key=self.new), dict(remote_key=self.new, auth_error=True)]
        self.expect_failure('SSH_AUTH_FAILED')
        self.assertEqual(self.store.read_bytes(), original)
        self.assertEqual([client.authentication_attempts for client in self.clients], [0, 1])

    def test_second_rotation_is_refused_before_auth_without_third_attempt(self):
        original = self.existing()
        self.scenarios = [dict(remote_key=self.new), dict(remote_key=self.third)]
        self.expect_failure('SSH_HOST_KEY_CHANGED')
        self.assertEqual(self.store.read_bytes(), original)
        self.assertEqual(self.changed_confirmation.call_count, 1)
        self.assertEqual(self.connection_attempts, 2)
        self.assertEqual([client.authentication_attempts for client in self.clients], [0, 0])

    def test_cancellation_before_connection_does_not_contact_vm(self):
        original = self.existing()
        self.cancelled.set()
        self.scenarios = [dict(remote_key=self.new)]
        self.expect_failure('INTERRUPTED')
        self.assertEqual(self.connection_attempts, 0)
        self.assertEqual(self.store.read_bytes(), original)

    def test_cancellation_during_changed_key_prompt_prevents_retry_and_save(self):
        original = self.existing()
        def approve(*_):
            self.cancelled.set()
            return True
        self.changed_confirmation.side_effect = approve
        self.scenarios = [dict(remote_key=self.new)]
        self.expect_failure('INTERRUPTED')
        self.assertEqual(self.connection_attempts, 1)
        self.assertEqual(self.store.read_bytes(), original)
        self.assertEqual(self.clients[0].authentication_attempts, 0)

    def test_cancellation_during_initial_key_prompt_prevents_authentication(self):
        def approve(*_):
            self.cancelled.set()
            return True
        self.first_confirmation.side_effect = approve
        self.scenarios = [dict(remote_key=self.new)]
        self.expect_failure('INTERRUPTED')
        self.assertEqual(self.clients[0].authentication_attempts, 0)
        self.assertFalse(self.store.exists())

    def test_failed_store_write_has_fixed_code_and_preserves_previous_identity(self):
        original = self.existing()
        self.scenarios = [dict(remote_key=self.new), dict(remote_key=self.new)]
        with patch('recovery_gui.ssh_identity.os.replace', side_effect=OSError('synthetic')) as replace:
            self.expect_failure('SSH_HOST_KEY_STORE_FAILED')
        replace.assert_called_once()
        self.assertEqual(self.store.read_bytes(), original)
        self.assertEqual(list(self.store.parent.iterdir()), [self.store])

    def test_changed_system_key_is_overridden_only_in_app_store(self):
        system = self.root / '.ssh' / 'known_hosts'
        self.write_keys(system, [(self.host.address, self.old)])
        original = system.read_bytes()
        self.scenarios = [dict(remote_key=self.new), dict(remote_key=self.new)]
        job = self.connect()
        self.assertEqual(system.read_bytes(), original)
        self.assert_identity(self.read_keys(), self.host.address, self.new)
        job.close()
        self.scenarios = [dict(remote_key=self.new)]
        job = self.connect()
        self.assertEqual(self.changed_confirmation.call_count, 1)
        self.assertEqual(system.read_bytes(), original)
        job.close()


if __name__ == '__main__':
    unittest.main()

"""A fresh stack may replace only the dedicated recovery tunnel's old key."""
import base64
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'remote'))
import native_agent as agent

PREFIX = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'
OLD = 'ssh-ed25519 ' + base64.b64encode(PREFIX + bytes(range(32))).decode()
NEW = 'ssh-ed25519 ' + base64.b64encode(PREFIX + bytes(reversed(range(32)))).decode()


def row(public, port=8080):
    return ('restrict,port-forwarding,permitopen="127.0.0.1:'+str(port)+
            '",command="/bin/false" '+public+'\n').encode()


class Authorization(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / 'authorized_keys'
        self.path.write_bytes(row(OLD))
        self.metadata = {self.path: dict(st_uid=123, st_gid=456,
                                        st_mode=stat.S_IFREG | 0o600)}
        real_stat = Path.stat

        def posix_metadata(path, *args, **kwargs):
            info = real_stat(path, *args, **kwargs)
            if path not in self.metadata:
                return info
            values = {field: getattr(info, field) for field in dir(info)
                      if field.startswith('st_')}
            values.update(self.metadata[path])
            return N(**values)

        # Windows does not implement POSIX ownership/modes. Keep real file I/O
        # and replacement, and supply the metadata reported on the Linux VMs.
        self.addCleanup(patch.stopall)
        patch.object(Path, 'stat', posix_metadata).start()
        patch.object(agent.os, 'fchmod', create=True).start()
        patch.object(agent.os, 'fchown', create=True).start()
        patch.object(agent.os, 'chown', create=True).start()

    def authorize(self, public=NEW):
        agent.authorize_owned_key(self.path, public, 8080, 123, 456)

    def test_new_stack_key_replaces_only_the_canonical_recovery_row(self):
        self.authorize()
        self.assertEqual(self.path.read_bytes(), row(NEW))
        self.assertEqual(set(self.root.iterdir()), {self.path})

    def test_same_key_resume_does_not_write(self):
        with patch.object(agent.os, 'replace') as replace, \
                patch.object(agent.tempfile, 'mkstemp') as create:
            self.authorize(OLD)
        replace.assert_not_called()
        create.assert_not_called()
        self.assertEqual(self.path.read_bytes(), row(OLD))

    def test_unmanaged_authorizations_are_preserved(self):
        for content in (row(OLD)+row(NEW), OLD.encode()+b'\n',
                        row(OLD).replace(b'restrict,', b''),
                        row(OLD, 8081), row(OLD).rstrip(b'\n')+b' comment\n',
                        b'# handwritten configuration\n'+row(OLD),
                        b'invalid\xff\n'):
            with self.subTest(content=content):
                self.path.write_bytes(content)
                with patch.object(agent.tempfile, 'mkstemp') as create, \
                        self.assertRaisesRegex(agent.Refused, 'AGENT_EXISTING_INSTALLATION_CHANGED'):
                    self.authorize()
                create.assert_not_called()
                self.assertEqual(self.path.read_bytes(), content)

    def test_foreign_metadata_and_hardlinks_are_preserved(self):
        original = dict(self.metadata[self.path])
        for change in ({'st_uid': 124}, {'st_gid': 457}, {'st_nlink': 2},
                       {'st_mode': stat.S_IFREG | 0o644}, {'st_mode': stat.S_IFDIR | 0o600}):
            with self.subTest(change=change):
                self.metadata[self.path] = original | change
                with patch.object(agent.tempfile, 'mkstemp') as create, \
                        self.assertRaisesRegex(agent.Refused, 'AGENT_EXISTING_INSTALLATION_CHANGED'):
                    self.authorize()
                create.assert_not_called()
                self.assertEqual(self.path.read_bytes(), row(OLD))

    def test_concurrent_change_refuses_rotation_and_removes_temporary_file(self):
        real_fsync = agent.os.fsync

        def changed(fd):
            real_fsync(fd)
            self.path.write_bytes(b'concurrent-private-canary')

        with patch.object(agent.os, 'fsync', changed), \
                self.assertRaisesRegex(agent.Refused, 'AGENT_EXISTING_INSTALLATION_CHANGED'):
            self.authorize()
        self.assertEqual(self.path.read_bytes(), b'concurrent-private-canary')
        self.assertEqual(set(self.root.iterdir()), {self.path})

    def test_invalid_new_key_cannot_replace_existing_key(self):
        with self.assertRaisesRegex(agent.Refused, 'AGENT_TUNNEL_PUBLIC_KEY_INVALID'):
            self.authorize('ssh-ed25519 YWJjZA==')
        self.assertEqual(self.path.read_bytes(), row(OLD))

    def server_fixture(self):
        account_home = self.root / 'tunnel'
        directory = account_home / '.ssh'
        directory.mkdir(parents=True)
        self.path.rename(directory / 'authorized_keys')
        info = self.metadata.pop(self.path)
        self.path = directory / 'authorized_keys'
        self.metadata[self.path] = info
        owner = account_home / 'recovery-owner'
        owner.write_text('a'*32)
        self.metadata[owner] = dict(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o600)
        account = N(pw_dir=str(account_home), pw_shell='/bin/false', pw_uid=123, pw_gid=456)
        real_safe_path = agent.safe_path

        def local_path(path):
            if Path(path) == Path('/var/lib/streams-aio-tunnel'):
                path = account_home
            elif Path(path) == Path('/etc/ssh/sshd_config.d/70-streams-aio-tunnel.conf'):
                path = self.root / 'sshd_config'
            return real_safe_path(path)

        patch.object(agent, 'safe_path', local_path).start()
        patch.dict(sys.modules, {'pwd': N(getpwnam=lambda name: account)}).start()
        patch.object(agent, 'checkpoint', return_value=dict(api_port=8080, machine_id='a'*32)).start()
        patch.object(agent, 'write_owned').start()
        patch.object(agent, 'command').start()
        return owner

    def test_authorize_rotates_after_matching_server_checkpoint_and_root_marker(self):
        self.server_fixture()
        agent.authorize(self.root, Path('/opt/infisical'), {'public_key': NEW})
        self.assertEqual(self.path.read_bytes(), row(NEW))
        agent.checkpoint.assert_called_once_with(self.root, Path('/opt/infisical'), True)
        self.assertEqual(agent.command.call_args_list[0].args[0], ['/usr/sbin/sshd', '-t'])
        self.assertEqual(agent.command.call_args_list[1].args[0], ['systemctl', 'reload', 'ssh.service'])

    def test_foreign_machine_marker_refuses_before_authorized_key_change(self):
        owner = self.server_fixture()
        owner.write_text('b'*32)
        with self.assertRaisesRegex(agent.Refused, 'AGENT_TUNNEL_ACCOUNT_CONFLICT'):
            agent.authorize(self.root, Path('/opt/infisical'), {'public_key': NEW})
        self.assertEqual(self.path.read_bytes(), row(OLD))
        agent.command.assert_not_called()

    def test_unowned_marker_refuses_before_authorized_key_change(self):
        owner = self.server_fixture()
        self.metadata[owner]['st_uid'] = 123
        with self.assertRaisesRegex(agent.Refused, 'AGENT_TUNNEL_ACCOUNT_CONFLICT'):
            agent.authorize(self.root, Path('/opt/infisical'), {'public_key': NEW})
        self.assertEqual(self.path.read_bytes(), row(OLD))
        agent.command.assert_not_called()

    def test_foreign_checkpoint_refuses_before_account_and_key_changes(self):
        self.server_fixture()
        agent.checkpoint.side_effect = agent.Refused('FOREIGN_RECOVERY_STATE')
        with self.assertRaisesRegex(agent.Refused, 'FOREIGN_RECOVERY_STATE'):
            agent.authorize(self.root, Path('/opt/infisical'), {'public_key': NEW})
        self.assertEqual(self.path.read_bytes(), row(OLD))
        agent.command.assert_not_called()


if __name__ == '__main__':
    unittest.main()

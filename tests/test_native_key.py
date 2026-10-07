"""Regressions for the Agent key handshake after a completed stack preparation."""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace as N
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'remote'))
import native_agent as agent
from recovery_gui.backend import Failure, SSH, remote_failure_code

PREFIX = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'
PUBLIC = 'ssh-ed25519 ' + base64.b64encode(PREFIX + bytes(range(32))).decode()


class NativeKey(unittest.TestCase):
    def test_openssh_comment_is_not_part_of_authorized_key(self):
        for suffix in ('', ' streams-aio-recovery-tunnel', ' comment with spaces', '\n'):
            self.assertEqual(agent.public_key_text(PUBLIC + suffix), PUBLIC)

    def test_key_type_blob_and_single_line_remain_required(self):
        wrong_blob = base64.b64encode(PREFIX[:-1] + b'x' + bytes(range(32))).decode()
        for raw in ('ssh-rsa ' + PUBLIC.split()[1], 'ssh-ed25519 !!!',
                    'ssh-ed25519 YWJjZA==', 'ssh-ed25519 ' + wrong_blob,
                    PUBLIC + '\n' + PUBLIC, PUBLIC + '\rcomment', ''):
            with self.subTest(raw=raw), self.assertRaisesRegex(agent.Refused, 'AGENT_TUNNEL_PUBLIC_KEY_INVALID'):
                agent.public_key_text(raw)

    def test_existing_key_is_reused_without_rotation(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp).resolve()
            private = home / 'agent-tunnel-key'
            private.write_bytes(b'synthetic-key-unchanged')
            output = io.StringIO()
            with patch.object(agent, 'checkpoint'), patch.object(agent, 'private_file'), \
                    patch.object(agent.os, 'chown', create=True), \
                    patch.object(agent, 'command', return_value=(PUBLIC + ' streams-aio-recovery-tunnel\n').encode()) as run, \
                    contextlib.redirect_stdout(output):
                agent.key(home, home / 'stack')
            self.assertEqual(private.read_bytes(), b'synthetic-key-unchanged')
            self.assertEqual(json.loads(output.getvalue()), {'public_key': PUBLIC})
            self.assertEqual(run.call_args.args[0], ['ssh-keygen', '-y', '-f', private])

    @unittest.skipUnless(os.name == 'posix' and shutil.which('ssh-keygen'), 'Linux OpenSSH integration')
    def test_real_commented_openssh_key_handshake_and_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp).resolve()
            output = io.StringIO()
            # This test isolates the SSH-key handshake; checkpoint/ownership are
            # covered separately and require a real replacement VM's UID/GID.
            with patch.object(agent, 'checkpoint'), patch.object(agent.os, 'chown'), \
                    contextlib.redirect_stdout(output):
                agent.key(home, home / 'stack')
                before = hashlib.sha256((home / 'agent-tunnel-key').read_bytes()).digest()
                raw = subprocess.run(['ssh-keygen', '-y', '-f', str(home / 'agent-tunnel-key')],
                                     check=True, capture_output=True, text=True).stdout
                self.assertTrue(raw.strip().endswith(' streams-aio-recovery-tunnel'))
                agent.key(home, home / 'stack')
                after = hashlib.sha256((home / 'agent-tunnel-key').read_bytes()).digest()
            results = [json.loads(row) for row in output.getvalue().splitlines()]
            self.assertEqual(results, [{'public_key': agent.public_key_text(raw)}] * 2)
            self.assertEqual(before, after)


class RemoteFailure(unittest.TestCase):
    def test_native_refusal_survives_metadata_transport(self):
        raw = b'RECOVERY_EVENT {"stage":"REFUSED","status":"REFUSED","code":"AGENT_TUNNEL_PUBLIC_KEY_INVALID"}\n'
        self.assertEqual(remote_failure_code(raw), 'AGENT_TUNNEL_PUBLIC_KEY_INVALID')
        self.assertEqual(remote_failure_code(b'{"error":"SUDO_REQUIRED"}'), 'SUDO_REQUIRED')

    def test_untrusted_output_cannot_become_a_report_code(self):
        for raw in (b'private-canary', b'{"error":"private-canary"}', b'{"error":[]}',
                    b'RECOVERY_EVENT {"stage":"REFUSED","status":"REFUSED","code":"private-canary"}',
                    b'RECOVERY_EVENT {"stage":"REFUSED","status":"REFUSED","code":"AGENT_INSTALL_FAILED","secret":"private-canary"}'):
            self.assertEqual(remote_failure_code(raw), 'REMOTE_OPERATION_FAILED')

    def run_refusal(self, callback):
        raw = (b'private-canary\nRECOVERY_EVENT {"stage":"REFUSED","status":"REFUSED",'
               b'"code":"AGENT_TUNNEL_PUBLIC_KEY_INVALID"}\n'
               b'RECOVERY_EVENT {"stage":"REFUSED","status":"REFUSED","code":"BOOTSTRAP_FAILED"}\n')
        channel = MagicMock()
        chunks = [raw[:53], raw[53:]]
        channel.recv_ready.side_effect = lambda: bool(chunks)
        channel.recv.side_effect = lambda _: chunks.pop(0)
        channel.recv_stderr_ready.return_value = False
        channel.exit_status_ready.return_value = True
        channel.recv_exit_status.return_value = 1
        job = SSH.__new__(SSH)
        job.cancelled = threading.Event()
        job.client = MagicMock()
        job.client.exec_command.return_value = (MagicMock(), N(channel=channel), MagicMock())
        with self.assertRaisesRegex(Failure, '^AGENT_TUNNEL_PUBLIC_KEY_INVALID$'):
            job.run(['native-key'], callback=callback)

    def test_ssh_run_reports_native_refusal_without_callback(self):
        self.run_refusal(None)

    def test_ssh_run_retains_first_specific_refusal_and_drops_raw_output(self):
        events = []
        self.run_refusal(events.append)
        self.assertEqual([item['code'] for item in events],
                         ['AGENT_TUNNEL_PUBLIC_KEY_INVALID', 'BOOTSTRAP_FAILED'])
        self.assertNotIn('private-canary', json.dumps(events))

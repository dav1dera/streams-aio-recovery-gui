"""SSH completion keeps fixed events and distinguishes missing exit status.

All output buffers are synthetic; no SSH server or credentials are used.
"""
import json
from pathlib import Path
import sys
import threading
from types import SimpleNamespace as N
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from recovery_gui.backend import Failure, SSH


class SSHCompletion(unittest.TestCase):
    def invoke(self, chunks, status, callback):
        chunks = list(chunks)
        channel = MagicMock()
        channel.recv_ready.side_effect = lambda: bool(chunks)
        channel.recv.side_effect = lambda _: chunks.pop(0)
        channel.recv_stderr_ready.return_value = False
        channel.exit_status_ready.return_value = True
        channel.recv_exit_status.return_value = status
        channel.eof_received = True
        channel.closed = False
        job = SSH.__new__(SSH)
        job.cancelled = threading.Event()
        job.client = MagicMock()
        job.client.exec_command.return_value = (MagicMock(), N(channel=channel), MagicMock())
        return job.run(['synthetic-read-only-command'], callback=callback)

    def test_complete_final_refusal_without_newline_is_not_lost(self):
        raw = b'RECOVERY_EVENT {"stage":"REFUSED","status":"REFUSED","code":"APPLICATION_HEALTH_WAIT_FAILED"}'
        events = []
        with self.assertRaisesRegex(Failure, '^APPLICATION_HEALTH_WAIT_FAILED$'):
            self.invoke([raw[:27], raw[27:]], 1, events.append)
        self.assertEqual(events, [dict(stage='REFUSED', status='REFUSED', code='APPLICATION_HEALTH_WAIT_FAILED')])

    def test_final_event_does_not_override_an_earlier_specific_refusal(self):
        raw = (b'RECOVERY_EVENT {"stage":"REFUSED","status":"REFUSED","code":"PGBOUNCER_NOT_READY"}\n'
               b'RECOVERY_EVENT {"stage":"REFUSED","status":"REFUSED","code":"BOOTSTRAP_FAILED"}')
        events = []
        with self.assertRaisesRegex(Failure, '^PGBOUNCER_NOT_READY$'):
            self.invoke([raw], 137, events.append)
        self.assertEqual([row['code'] for row in events], ['PGBOUNCER_NOT_READY', 'BOOTSTRAP_FAILED'])

    def test_signal_or_closed_channel_has_finite_code_without_guessing_oom(self):
        cases = ((-1, 'SSH_CHANNEL_CLOSED'), (137, 'REMOTE_EXIT_137'),
                 (143, 'REMOTE_EXIT_143'), (1, 'REMOTE_OPERATION_FAILED'))
        for status, expected in cases:
            for callback in (None, [].append):
                with self.subTest(status=status, streaming=callback is not None), self.assertRaisesRegex(
                        Failure, '^'+expected+'$'):
                    self.invoke([b'private-canary\n'], status, callback)

    def test_arbitrary_or_incomplete_final_output_cannot_become_an_event(self):
        for raw in (b'private-canary', b'RECOVERY_EVENT {"stage":"REFUSED"',
                    b'RECOVERY_EVENT {"stage":"REFUSED","status":"REFUSED","code":"private-canary"}',
                    b'RECOVERY_EVENT {"stage":"REFUSED","status":"REFUSED","code":"PGBOUNCER_NOT_READY","secret":"private-canary"}'):
            events = []
            with self.subTest(raw=raw), self.assertRaisesRegex(Failure, '^REMOTE_OPERATION_FAILED$'):
                self.invoke([raw], 1, events.append)
            self.assertEqual(events, [])

    def test_successful_final_event_without_newline_is_delivered(self):
        events = []
        self.assertEqual(self.invoke([b'RECOVERY_EVENT {"stage":"STARTED","status":"PASS"}'], 0, events.append), b'')
        self.assertEqual(events, [dict(stage='STARTED', status='PASS')])

    def test_exit_status_before_pipe_eof_does_not_drop_delayed_refusal(self):
        raw = b'RECOVERY_EVENT {"stage":"REFUSED","status":"REFUSED","code":"APPLICATION_HEALTH_WAIT_FAILED"}\n'
        channel = MagicMock()
        chunks = []
        channel.recv_ready.side_effect = lambda: bool(chunks)
        channel.recv.side_effect = lambda _: chunks.pop(0)
        channel.recv_stderr_ready.return_value = False
        channel.exit_status_ready.return_value = True
        channel.recv_exit_status.return_value = 1
        channel.eof_received = False
        channel.closed = False
        def deliver(_):
            chunks.append(raw)
            channel.eof_received = True
        job = SSH.__new__(SSH)
        job.cancelled = threading.Event()
        job.client = MagicMock()
        job.client.exec_command.return_value = (MagicMock(), N(channel=channel), MagicMock())
        events = []
        with patch('recovery_gui.backend.time.sleep', side_effect=deliver) as pause, \
                self.assertRaisesRegex(Failure, '^APPLICATION_HEALTH_WAIT_FAILED$'):
            job.run(['synthetic-read-only-command'], callback=events.append)
        pause.assert_called_once()
        self.assertEqual(events, [dict(stage='REFUSED', status='REFUSED', code='APPLICATION_HEALTH_WAIT_FAILED')])


if __name__ == '__main__':
    unittest.main()

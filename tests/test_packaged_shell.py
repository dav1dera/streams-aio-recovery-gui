"""Catch Windows checkout line endings in the actual packaged resource path."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from recovery_gui import backend


class PackagedShellTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.bundle = Path(self.temporary.name)
        self.remote = self.bundle / 'remote'
        self.remote.mkdir()
        self.script = self.remote / 'bootstrap.sh'
        self.patch = patch.object(backend.sys, '_MEIPASS', str(self.bundle), create=True)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_lf_bootstrap_in_frozen_bundle_is_accepted(self):
        self.script.write_bytes(b'#!/usr/bin/env bash\nset -euo pipefail\n')
        backend.validate_remote_shell_scripts()

    def test_windows_bootstrap_is_refused_before_any_remote_operation(self):
        self.script.write_bytes(b'#!/usr/bin/env bash\r\nset -euo pipefail\r\n')
        stack, server, callback = Mock(), Mock(), Mock()
        with self.assertRaisesRegex(backend.Failure, '^REMOTE_SCRIPT_FORMAT_INVALID$'):
            backend.restore_all(stack, server, {'restart_test': True}, callback)
        self.assertEqual(stack.mock_calls, [])
        self.assertEqual(server.mock_calls, [])
        callback.assert_not_called()

    def test_upload_also_refuses_before_staging_or_sftp(self):
        self.script.write_bytes(b'#!/usr/bin/env bash\r\nset -euo pipefail\r\n')
        connection = backend.SSH.__new__(backend.SSH)
        connection.check = Mock()
        connection.run = Mock()
        connection.client = Mock()
        with self.assertRaisesRegex(backend.Failure, '^REMOTE_SCRIPT_FORMAT_INVALID$'):
            connection.upload({})
        connection.check.assert_not_called()
        connection.run.assert_not_called()
        self.assertEqual(connection.client.mock_calls, [])

    def test_missing_bootstrap_is_refused(self):
        with self.assertRaisesRegex(backend.Failure, '^REMOTE_SCRIPT_FORMAT_INVALID$'):
            backend.validate_remote_shell_scripts()

    def test_other_bundled_shell_scripts_must_also_use_lf(self):
        self.script.write_bytes(b'#!/usr/bin/env bash\nset -euo pipefail\n')
        (self.remote / 'future-helper.sh').write_bytes(b'#!/usr/bin/env bash\r\nexit 0\r\n')
        with self.assertRaisesRegex(backend.Failure, '^REMOTE_SCRIPT_FORMAT_INVALID$'):
            backend.validate_remote_shell_scripts()


if __name__ == '__main__':
    unittest.main()

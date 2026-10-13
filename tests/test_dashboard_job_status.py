"""Backup selection completion must not leave the operation-running message."""
import queue
import unittest
from unittest.mock import Mock

from recovery_gui.ui_dashboard import App


class DashboardJobStatusTests(unittest.TestCase):
    def completed_view(self, *, snapshot=True, return_page=1, error=None):
        view = Mock()
        view.events = queue.Queue()
        view.events.put(('done', None))
        view.return_page = return_page
        view.backup_has_aio = snapshot
        view.last_error = error
        view.buttons = [Mock()]
        view.controls = [Mock()]
        return view

    def test_complete_backup_becomes_ready_without_certifying_recovery(self):
        view = self.completed_view()
        App.poll(view)
        self.assertFalse(view.busy)
        view.status.set.assert_called_once_with(
            'Backup selezionato. Puoi avviare o riprendere il recupero.')
        view.buttons[0].configure.assert_called_once_with(state='normal')
        view.controls[0].configure.assert_called_once_with(state='normal')
        view.phase_event.assert_not_called()
        view.hero_status.set.assert_not_called()
        self.assertIsNone(view.return_page)

    def test_legacy_backup_requires_complete_backup_and_does_not_become_ready(self):
        view = self.completed_view(snapshot=False)
        App.poll(view)
        view.status.set.assert_called_once_with(
            'Seleziona un backup completo con le configurazioni AIO.')
        view.phase_event.assert_not_called()

    def test_backup_loading_error_message_is_preserved(self):
        view = self.completed_view(error='GITHUB_TOKEN_REQUIRED')
        App.poll(view)
        view.status.set.assert_not_called()
        self.assertEqual(view.last_error, 'GITHUB_TOKEN_REQUIRED')

    def test_recovery_completion_preserves_its_last_result(self):
        for error in (None, 'APPLICATION_HEALTH_WAIT_FAILED'):
            with self.subTest(error=error):
                view = self.completed_view(return_page=None, error=error)
                App.poll(view)
                view.status.set.assert_not_called()
                view.phase_event.assert_not_called()


if __name__ == '__main__':
    unittest.main()

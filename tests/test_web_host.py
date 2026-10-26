"""Presentation host contracts. No native window or live bridge is created."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from recovery_gui import web_host


class WebHostTests(unittest.TestCase):
    def setUp(self):
        self.bridge = Mock()
        self.bridge._is_busy.return_value = False
        self.api = web_host.DesktopAPI(self.bridge)
        self.window = Mock()
        self.api._bind(self.window)
        self.webview = SimpleNamespace(FileDialog=SimpleNamespace(OPEN=1, SAVE=2))

    def test_document_inlines_only_bundled_assets_and_blocks_network(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'index.html').write_text('<html><head><link rel="stylesheet" href="app.css"><script src="app.js" defer></script></head><body><main>Workspace</main></body></html>')
            (root / 'app.css').write_text('body { color: white; }')
            (root / 'app.js').write_text('window.example = "</script>";')
            with patch.object(web_host, 'asset_directory', return_value=root):
                html = web_host.document()
            self.assertIn("connect-src 'none'", html)
            self.assertIn("form-action 'none'", html)
            self.assertIn('<style>body { color: white; }</style>', html)
            self.assertNotIn('src="app.js"', html)
            self.assertIn('<\\/script>', html)
            self.assertGreater(html.index('<script>'), html.index('</main>'))
            (root / 'index.html').write_text('<html><head></head><body><script src="https://example.invalid/app.js"></script></body></html>')
            with patch.object(web_host, 'asset_directory', return_value=root):
                with self.assertRaisesRegex(ValueError, 'WEB_ASSETS_INVALID'):
                    web_host.document()

    def test_file_picker_never_reads_selected_private_file(self):
        self.window.create_file_dialog.return_value = ('C:/fixtures/private.agekey',)
        with patch.dict('sys.modules', {'webview': self.webview}), patch.object(Path, 'read_bytes', side_effect=AssertionError('must not read')):
            result = self.api.choose_file('age_identity')
        self.assertEqual(result, {'ok': True, 'path': 'C:/fixtures/private.agekey'})

    def test_picker_is_refused_for_arbitrary_kinds_and_while_busy(self):
        for kind in ('arbitrary', '../private', {}, None):
            self.assertEqual(self.api.choose_file(kind)['code'], 'WEB_FILE_KIND_INVALID')
        self.bridge._is_busy.return_value = True
        self.assertEqual(self.api.choose_file('age_identity')['code'], 'SERVICE_OPERATION_BUSY')
        self.window.create_file_dialog.assert_not_called()

    def test_picker_failures_never_echo_private_exception(self):
        self.window.create_file_dialog.side_effect = RuntimeError('credential-marker')
        with patch.dict('sys.modules', {'webview': self.webview}):
            result = self.api.choose_file('ssh_key')
        self.assertEqual(result['code'], 'WEB_FILE_DIALOG_FAILED')
        self.assertNotIn('credential-marker', repr(result))
        self.assertFalse(self.api._dialog_lock.locked())

    def test_export_uses_only_bridge_safe_report_and_cancel_does_not_write(self):
        self.bridge._report.return_value = {'events': [{'code': 'SSH_AUTH_FAILED'}]}
        self.window.create_file_dialog.return_value = None
        with patch.dict('sys.modules', {'webview': self.webview}), patch.object(Path, 'write_text', side_effect=AssertionError('must not write')):
            self.assertEqual(self.api.save_report(), {'ok': True, 'path': ''})
        self.bridge._report.assert_called_once()
        self.bridge._public_plan.assert_not_called()

    def test_busy_export_never_calls_report_or_file_dialog(self):
        self.bridge._is_busy.return_value = True
        self.assertEqual(self.api.save_report()['code'], 'SERVICE_OPERATION_BUSY')
        self.bridge._report.assert_not_called()
        self.window.create_file_dialog.assert_not_called()

    def test_public_facade_has_no_arbitrary_url_file_or_code_execution_method(self):
        expected = {'initialize', 'update_settings', 'load_backups', 'load_backup', 'prepare_lab', 'recover',
                    'analyze_service', 'prepare_service', 'inspect_service', 'apply_service', 'invalidate_service',
                    'poll', 'answer_host_key', 'cancel', 'choose_file', 'save_report', 'save_plan', 'open_guide', 'import_service_bundle'}
        actual = {name for name, value in vars(web_host.DesktopAPI).items() if not name.startswith('_') and callable(value)}
        self.assertEqual(actual, expected)

    def test_import_bundle_reads_only_explicit_choice_and_invalidates_old_receipt(self):
        import json
        from recovery_gui.web_bridge import WebBridge
        bridge = WebBridge()
        api = web_host.DesktopAPI(bridge)
        api._bind(self.window)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'service.json'
            path.write_text(json.dumps(dict(compose='demo:\n  image: example/demo:latest\n',env='',service_name='')))
            self.window.create_file_dialog.return_value = (str(path),)
            with patch.dict('sys.modules', {'webview': self.webview}):
                result = api.import_service_bundle()
            self.assertTrue(result['ok'])
            self.assertIn('demo:',result['bundle']['compose'])
            path.write_text(json.dumps(dict(compose='demo:\n  image: example/demo:latest\n',private_values={'PASSWORD':'canary'})))
            with patch.dict('sys.modules', {'webview': self.webview}):
                rejected = api.import_service_bundle()
            self.assertEqual(rejected['code'],'WEB_SERVICE_BUNDLE_INVALID')
            self.assertNotIn('canary',repr(rejected))
        self.window.create_file_dialog.return_value = None
        with patch.dict('sys.modules', {'webview': self.webview}):
            self.assertEqual(api.import_service_bundle(),dict(ok=True,bundle=None))

    def test_explicit_user_help_opens_only_fixed_repository_guide(self):
        with patch.object(web_host.webbrowser, 'open') as open_browser:
            self.assertTrue(self.api.open_guide()['ok'])
        open_browser.assert_called_once_with(web_host.GUIDE)


if __name__ == '__main__':
    unittest.main()

"""Offline Windows presentation host. No window or connection is opened on import.

Only the bundled document is loaded in WebView2. The Python bridge has no HTTP
endpoint; its explicit facade exposes operations rather than an interpreter or
general file access. Application credentials remain in the bridge's RAM.
"""
import json
from pathlib import Path
import re
import sys
import threading
import time
import webbrowser

from . import __version__


GUIDE = 'https://github.com/dav1dera/streams-aio-recovery-gui/blob/main/README.md'
CSP = ("default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval'; "
       "style-src 'unsafe-inline'; img-src data:; font-src 'none'; "
       "connect-src 'none'; object-src 'none'; frame-src 'none'; "
       "form-action 'none'; base-uri 'none'")
FILE_KINDS = {'age_identity', 'ssh_key', 'infisical_key', 'supplemental_inputs'}


def asset_directory():
    return Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parents[1])) / 'recovery_gui' / 'web'


def document():
    """Inline the three public assets; never serve the workspace over HTTP."""
    folder = asset_directory()
    values = {}
    for name in ('index.html', 'app.css', 'app.js'):
        path = folder / name
        raw = path.read_bytes()
        if not 0 < len(raw) <= 2_000_000:
            raise ValueError('WEB_ASSETS_INVALID')
        values[name] = raw.decode('utf-8')
    html = values['index.html']
    html, css_count = re.subn(r'<link\b[^>]*href=[\"\'](?:\./)?app\.css[\"\'][^>]*>',
        lambda _: '<style>' + values['app.css'] + '</style>', html, flags=re.I)
    html, js_count = re.subn(r'<script\b[^>]*src=[\"\'](?:\./)?app\.js[\"\'][^>]*>\s*</script>',
        '', html, flags=re.I)
    if css_count != 1 or js_count != 1 or '<head>' not in html or '</body>' not in html:
        raise ValueError('WEB_ASSETS_INVALID')
    if re.search(r'<(?:script|link|iframe)\b[^>]*(?:src|href)=[\"\']https?://', html, re.I):
        raise ValueError('WEB_REMOTE_ASSET_REFUSED')
    # An external deferred script can live in <head>; inline `defer` would be
    # ignored. Execute it after the body so both host and file previews see the
    # same fully constructed document.
    html = html.replace('</body>', '<script>' + values['app.js'].replace('</script', '<\\/script') + '</script>\n</body>', 1)
    return html.replace('<head>', '<head>\n<meta http-equiv="Content-Security-Policy" content="' + CSP + '">', 1)


def _refused(code, description):
    return {'ok': False, 'code': code, 'description': description}


class DesktopAPI:
    """An explicit allowlist. Underscored methods are not exposed by pywebview."""
    def __init__(self, bridge):
        self._bridge = bridge
        self._window = None
        self._dialog_lock = threading.Lock()

    def _bind(self, window):
        self._window = window

    def initialize(self):
        return self._bridge.initialize()

    def update_settings(self, settings):
        return self._bridge.update_settings(settings)

    def load_backups(self, settings):
        return self._bridge.load_backups(settings)

    def load_backup(self, tag):
        return self._bridge.load_backup(tag)

    def prepare_lab(self, settings):
        return self._bridge.prepare_lab(settings)

    def recover(self, settings, action):
        return self._bridge.recover(settings, action)

    def analyze_service(self, payload):
        return self._bridge.analyze_service(payload)

    def prepare_service(self, payload):
        return self._bridge.prepare_service(payload)

    def inspect_service(self, payload):
        return self._bridge.inspect_service(payload)

    def update_service_tools(self, payload):
        return self._bridge.update_service_tools(payload)

    def apply_service(self, payload):
        return self._bridge.apply_service(payload)

    def invalidate_service(self):
        return self._bridge.invalidate_service()

    def poll(self):
        return self._bridge.poll()

    def answer_host_key(self, request_id, approved):
        return self._bridge.answer_host_key(request_id, approved)

    def cancel(self):
        return self._bridge.cancel()

    def choose_file(self, kind):
        if not isinstance(kind, str) or kind not in FILE_KINDS:
            return _refused('WEB_FILE_KIND_INVALID', 'Scegli un file tramite il pulsante del relativo campo.')
        if self._window is None or self._bridge._is_busy() or not self._dialog_lock.acquire(blocking=False):
            return _refused('SERVICE_OPERATION_BUSY', 'Attendi il termine dell’operazione in corso.')
        try:
            import webview
            types = ('Backup cifrato age (*.age)', 'Tutti i file (*.*)') if kind == 'supplemental_inputs' else ('Tutti i file (*.*)',)
            paths = self._window.create_file_dialog(webview.FileDialog.OPEN, allow_multiple=False, file_types=types)
            return {'ok': True, 'path': str(paths[0]) if paths else ''}
        except Exception:
            return _refused('WEB_FILE_DIALOG_FAILED', 'La scelta del file non è stata completata. Puoi inserirne il percorso nel campo.')
        finally:
            self._dialog_lock.release()

    def import_service_bundle(self):
        """Read only the JSON the user explicitly selects, without deploying it."""
        if self._window is None or self._bridge._is_busy() or not self._dialog_lock.acquire(blocking=False):
            return _refused('SERVICE_OPERATION_BUSY', 'Attendi il termine dell’operazione in corso.')
        try:
            import webview
            from .service_plan import inspect_inputs, inspect_resources
            paths = self._window.create_file_dialog(webview.FileDialog.OPEN, allow_multiple=False,
                                                    file_types=('Pacchetto servizio JSON (*.json)',))
            if not paths:
                return {'ok': True, 'bundle': None}
            path = Path(paths[0])
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
                raise ValueError('invalid bundle')
            raw = path.read_bytes()
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError('invalid bundle')
            value = json.loads(raw)
            sources = self._bridge._sources(value)
            options = self._bridge._resource_inputs(value)
            inspect_inputs(*sources, **options)
            inspect_resources(*sources, **options)
            # No receipt, saved plan, private classification or credentials may be imported.
            self._bridge.invalidate_service()
            return {'ok': True, 'bundle': dict(compose=sources[0],env=sources[1],service_name=sources[2],**options)}
        except Exception:
            return _refused('WEB_SERVICE_BUNDLE_INVALID', 'Il pacchetto non è valido. Usa un file JSON con Compose, variabili e configurazioni pubbliche del servizio.')
        finally:
            self._dialog_lock.release()

    def _save(self, kind):
        if self._window is None or self._bridge._is_busy() or not self._dialog_lock.acquire(blocking=False):
            return _refused('SERVICE_OPERATION_BUSY', 'Attendi il termine dell’operazione in corso.')
        try:
            import webview
            value = self._bridge._report() if kind == 'report' else self._bridge._public_plan()
            if not isinstance(value, dict):
                return _refused('SERVICE_ANALYSIS_REQUIRED', 'Prepara prima il piano del servizio.')
            paths = self._window.create_file_dialog(webview.FileDialog.SAVE,
                save_filename='streams-aio-esiti.json' if kind == 'report' else 'streams-aio-piano.json',
                file_types=('File JSON (*.json)',))
            if not paths:
                return {'ok': True, 'path': ''}
            Path(paths[0]).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            return {'ok': True, 'path': str(paths[0])}
        except Exception:
            return _refused('WEB_EXPORT_FAILED', 'Il salvataggio non è stato completato. Scegli una cartella scrivibile.')
        finally:
            self._dialog_lock.release()

    def save_report(self):
        return self._save('report')

    def save_plan(self):
        return self._save('plan')

    def open_guide(self):
        try:
            webbrowser.open(GUIDE)
            return {'ok': True}
        except Exception:
            return _refused('WEB_GUIDE_UNAVAILABLE', 'La guida è nel README del repository Streams AIO Recovery.')


def run(*, self_test=False):
    """Called only when the user launches the EXE (or on the Windows CI runner)."""
    import webview
    from .web_bridge import WebBridge

    if self_test:
        class OfflineBridge(WebBridge):
            # Even an accidental click in the CI script cannot open a network
            # connection. Planner analysis and the real local bridge still run.
            def _refuse_remote(self, *args, **kwargs):
                return _refused('SERVICE_LAB_PREPARATION_INCOMPLETE',
                    'Controllo grafico automatico: nessuna connessione alle VM.')
            load_backups = load_backup = prepare_lab = recover = _refuse_remote
            inspect_service = apply_service = update_service_tools = _refuse_remote
        bridge = OfflineBridge()
    else:
        bridge = WebBridge()
    api = DesktopAPI(bridge)
    window = webview.create_window('Streams AIO Recovery · ' + __version__, html=document(), js_api=api,
        width=1320, height=900, min_size=(960, 700), background_color='#070707',
        text_select=True, hidden=self_test, focus=not self_test, confirm_close=False)
    api._bind(window)
    webview.settings['ALLOW_DOWNLOADS'] = False
    webview.settings['OPEN_EXTERNAL_LINKS_IN_BROWSER'] = False

    def closing():
        if bridge._is_busy() and not self_test:
            if not window.create_confirmation_dialog('Operazione in corso',
                    'Chiudere interrompe il collegamento. I dati già preparati sulle VM restano conservati. Chiudere?'):
                return False
        bridge._close()
        return True
    window.events.closing += closing
    window.events.closed += bridge._close
    outcome = {'ok': not self_test}

    def check():
        # A real WebView is exercised only in CI. No SSH or API job is run.
        try:
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                ready = window.evaluate_js("Boolean(window.recoveryUI && window.recoveryUI.ready && document.body.dataset.bridgeState === 'connected')")
                if ready:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError('WEB_UI_NOT_READY')
            completed, results = threading.Event(), []
            def collect(value):
                results.append(value)
                completed.set()
            window.evaluate_js('Promise.resolve(window.__uiSelfTest())', callback=collect)
            if not completed.wait(10):
                raise RuntimeError('WEB_UI_SELF_TEST_TIMEOUT')
            checks = results[0]
            if not isinstance(checks, dict) or checks.get('ok') is not True:
                raise RuntimeError('WEB_UI_SELF_TEST_FAILED')
            outcome['ok'] = True
        except Exception:
            outcome['ok'] = False
        finally:
            window.destroy()
    webview.start(check if self_test else None, gui='edgechromium', debug=False, private_mode=True)
    bridge._close()
    if not outcome['ok']:
        raise SystemExit(1)


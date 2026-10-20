"""Offline checks for the original, locally packaged desktop web frontend.

These are deliberately security and packaging checks, not pixel snapshots or a
substitute for executing the bridge and application flows in their own tests.
"""
from html.parser import HTMLParser
from pathlib import Path
import re
import unittest
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / 'recovery_gui' / 'web'


class AssetDocument(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.elements = []
        self.inline_scripts = []
        self._script = None
        self.feed(text)
        self.close()

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        self.elements.append((tag, attributes))
        if tag == 'script':
            self._script = {'attributes': attributes, 'text': ''}

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag == 'script':
            self.handle_endtag(tag)

    def handle_data(self, data):
        if self._script is not None:
            self._script['text'] += data

    def handle_endtag(self, tag):
        if tag == 'script' and self._script is not None:
            self.inline_scripts.append(self._script)
            self._script = None


def local_asset_path(reference):
    """Require an asset inside the bundle, regardless of URL spelling."""
    parsed = urlsplit(reference)
    if parsed.scheme or parsed.netloc or reference.startswith(('\\', '/')):
        raise ValueError('Remote or absolute asset reference')
    if parsed.query or parsed.fragment:
        raise ValueError('Runtime asset reference must name a plain file')
    candidate = (WEB / unquote(parsed.path)).resolve()
    if not candidate.is_relative_to(WEB.resolve()) or candidate == WEB.resolve():
        raise ValueError('Asset reference leaves the bundle')
    return candidate


class WebAssetsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (WEB / 'index.html').read_text(encoding='utf-8')
        cls.css = (WEB / 'app.css').read_text(encoding='utf-8')
        cls.js = (WEB / 'app.js').read_text(encoding='utf-8')
        cls.document = AssetDocument(cls.html)

    def test_local_scripts_and_stylesheets_are_present_in_the_bundle(self):
        scripts, styles = [], []
        for tag, attrs in self.document.elements:
            if tag == 'script' and attrs.get('src'):
                scripts.append(attrs['src'])
            if tag == 'link' and 'stylesheet' in attrs.get('rel', '').split():
                styles.append(attrs.get('href', ''))
        self.assertTrue(scripts, 'The desktop entry page must load its JavaScript')
        self.assertTrue(styles, 'The desktop entry page must load its stylesheet')
        for reference in scripts + styles:
            with self.subTest(reference=reference):
                self.assertTrue(local_asset_path(reference).is_file())
        self.assertIn(WEB / 'app.js', [local_asset_path(x) for x in scripts])
        self.assertIn(WEB / 'app.css', [local_asset_path(x) for x in styles])

    def test_runtime_resources_do_not_contact_remote_hosts(self):
        for tag, attrs in self.document.elements:
            if tag in ('iframe', 'object', 'embed', 'base'):
                self.fail(f'Unnecessary embedded or navigable runtime surface: {tag}')
            self.assertNotIn('srcset', attrs, 'Keep runtime asset lookup local and explicit')
            for name in ('src', 'poster'):
                if name in attrs:
                    with self.subTest(tag=tag, attribute=name):
                        self.assertTrue(local_asset_path(attrs[name]).is_file())
            if tag == 'link':
                self.assertFalse(set(attrs.get('rel', '').split()) &
                                 {'preconnect', 'dns-prefetch', 'prefetch', 'prerender'})
                if attrs.get('href'):
                    self.assertTrue(local_asset_path(attrs['href']).is_file())

    def test_styles_use_system_fonts_and_local_resources(self):
        self.assertNotRegex(self.css, r'(?i)@\s*(?:import|font-face)\b')
        for match in re.finditer(r'url\(\s*([\'"]?)(.*?)\1\s*\)', self.css, re.I):
            reference = match.group(2).strip()
            if reference.startswith(('data:', '#')):
                continue
            with self.subTest(reference=reference):
                self.assertTrue(local_asset_path(reference).is_file())

    def test_no_inline_event_handlers_or_inline_javascript(self):
        for tag, attrs in self.document.elements:
            for name, value in attrs.items():
                with self.subTest(tag=tag, attribute=name):
                    self.assertFalse(name.lower().startswith('on'))
                    self.assertFalse((value or '').strip().lower().startswith('javascript:'))
        for script in self.document.inline_scripts:
            self.assertEqual(script['text'].strip(), '', 'Keep executable code in app.js')
            self.assertTrue(script['attributes'].get('src'))

    def test_browser_has_no_network_or_persistent_credential_channel(self):
        prohibited = {
            'direct HTTP': r'\bfetch\s*\(',
            'XHR': r'\bXMLHttpRequest\b',
            'websocket': r'\bWebSocket\b',
            'server events': r'\bEventSource\b',
            'beacon': r'\bsendBeacon\s*\(',
            'worker': r'\b(?:Worker|SharedWorker|serviceWorker)\b',
            'dynamic import': r'\bimport\s*\(',
            'browser storage': r'\b(?:localStorage|sessionStorage|indexedDB)\b',
            'cache persistence': r'\bcaches\s*\.',
            'cookie persistence': r'\bdocument\s*\.\s*cookie\b',
        }
        for name, pattern in prohibited.items():
            with self.subTest(channel=name):
                self.assertNotRegex(self.js, pattern)

    def test_user_data_cannot_reach_html_or_code_execution_sinks(self):
        prohibited = (
            r'\.\s*(?:innerHTML|outerHTML)\b',
            r'\binsertAdjacentHTML\s*\(',
            r'\bdocument\s*\.\s*(?:write|writeln)\s*\(',
            r'\beval\s*\(',
            r'\bnew\s+Function\s*\(',
            r'\bset(?:Timeout|Interval)\s*\(\s*[\'"`]',
            r'\bconsole\s*\.\s*(?:log|debug|info|warn|error|trace)\s*\(',
        )
        for pattern in prohibited:
            with self.subTest(sink=pattern):
                self.assertNotRegex(self.js, pattern)
        self.assertRegex(self.js, r'\.textContent\b')
        self.assertRegex(self.js, r'\b(?:document\.)?createElement\s*\(')

    def test_password_fields_are_masked_and_not_autocompleted(self):
        passwords = [attrs for tag, attrs in self.document.elements
                     if tag == 'input' and attrs.get('type', '').lower() == 'password']
        self.assertTrue(passwords, 'The frontend must provide masked credential inputs')
        for attrs in passwords:
            with self.subTest(field=attrs.get('id') or attrs.get('name')):
                self.assertIn(attrs.get('autocomplete'), ('off', 'new-password'))
                self.assertFalse(attrs.get('value'), 'Do not ship credentials in page defaults')

    def test_file_picker_buttons_match_the_explicit_desktop_allowlist(self):
        # Importing the host does not create a window or import pywebview.
        from recovery_gui.web_host import FILE_KINDS
        for tag, attrs in self.document.elements:
            if 'data-choose' in attrs:
                with self.subTest(field=attrs['data-choose']):
                    self.assertEqual(tag, 'button')
                    self.assertIn(attrs['data-choose'], FILE_KINDS)

    def test_pasted_age_identity_has_one_masked_ephemeral_field(self):
        fields = [(tag, attrs) for tag, attrs in self.document.elements
                  if attrs.get('data-setting') == 'age_identity_text']
        self.assertEqual(len(fields), 1)
        tag, attrs = fields[0]
        self.assertEqual(tag, 'input')
        self.assertEqual(attrs.get('type'), 'password')
        self.assertIn(attrs.get('autocomplete'), ('off', 'new-password'))
        self.assertEqual(attrs.get('spellcheck'), 'false')
        self.assertFalse(attrs.get('value'))
        self.assertLessEqual(int(attrs.get('maxlength', '0')), 65536)
        self.assertGreater(int(attrs.get('maxlength', '0')), 0)
        modes = {attrs['data-age-mode'] for _, attrs in self.document.elements
                 if 'data-age-mode' in attrs}
        self.assertEqual(modes, {'file', 'paste'})


class LocalAssetResolverTests(unittest.TestCase):
    def test_remote_absolute_and_encoded_escape_references_are_refused(self):
        for reference in ('https://cdn.example/app.js', '//cdn.example/app.js',
                          '/app.js', 'C:/app.js', '../app.js',
                          '%2e%2e/app.js', 'app.js?token=example', 'app.js#fragment'):
            with self.subTest(reference=reference):
                with self.assertRaises(ValueError):
                    local_asset_path(reference)

    def test_plain_local_reference_resolves_inside_the_bundle(self):
        self.assertEqual(local_asset_path('app.js'), (WEB / 'app.js').resolve())


if __name__ == '__main__':
    unittest.main()

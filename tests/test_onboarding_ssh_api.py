"""Authenticated loopback API routing with synthetic SSH/HTTP only."""
import base64
import io
import json
import traceback
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request

from recovery_gui.onboarding_infisical import InfisicalClient, InfisicalFailure
from recovery_gui.onboarding_ssh_api import (
    MAX_BODY_BYTES, MAX_WIRE_BYTES, SSH_HTTP_HELPER, SSH_ORIGIN,
    SSHInfisicalOpener, validate_target,
)


PROJECT = 'f80601b1-73fb-49bd-9373-f3687cd5c8eb'
TOKEN = 'synthetic-bearer-private-fixture'
SECRET = 'synthetic-private-$-è-秘密'
TARGET = 'http://127.0.0.1:18080'
FOLDER_QUERY = urlencode(dict(projectId=PROJECT, environment='prod', path='/', recursive='false'))
SECRET_QUERY = urlencode(dict(projectId=PROJECT, environment='prod', secretPath='/example', type='shared',
                              expandSecretReferences='false', includeImports='false'))


def request(method='GET', path='/api/v2/folders', query=FOLDER_QUERY, body=None, **headers):
    return Request(SSH_ORIGIN + path + ('?' + query if query else ''), data=body, method=method,
                   headers=dict(Authorization='Bearer ' + TOKEN, **headers))


class FakeResponse:
    def __init__(self, url, body, status=200):
        self.url, self.body, self.status, self.reads, self.closed = url, body, status, [], False

    def geturl(self): return self.url
    def read(self, size):
        self.reads.append(size)
        return self.body[:size]
    def __enter__(self): return self
    def __exit__(self, *_): self.closed = True


class ErrorBody(io.BytesIO):
    def __init__(self):
        super().__init__((TOKEN + SECRET).encode())
        self.reads = 0
    def read(self, *args):
        self.reads += 1
        return super().read(*args)


class MemoryHTTP:
    def __init__(self):
        self.calls, self.handlers, self.errors = [], [], []
        self.folder, self.secrets = False, {}
        self.failure, self.response = None, None

    def build(self, *handlers):
        self.handlers.append(handlers)
        return self

    def open(self, req, timeout):
        self.calls.append((req, timeout))
        if self.failure:
            raise self.failure
        if self.response:
            return self.response
        parts = urlsplit(req.full_url)
        if parts.scheme != 'http' or parts.netloc != '127.0.0.1:18080':
            raise AssertionError('Synthetic helper attempted a non-loopback route')
        body = json.loads(req.data) if req.data is not None else {}
        if parts.path == '/api/v2/folders':
            if req.get_method() == 'POST':
                self.folder = True
                result = {'folder': {'name': body['name']}}
            else:
                result = {'folders': [{'name': 'example'}] if self.folder else []}
        else:
            name = parts.path.rsplit('/', 1)[-1]
            if req.get_method() == 'POST':
                self.secrets[name] = body['secretValue']
            elif name not in self.secrets:
                error_body = ErrorBody()
                self.errors.append(error_body)
                raise HTTPError(req.full_url, 404, SECRET, {'Private': TOKEN}, error_body)
            result = {'secret': {'secretKey': name, 'secretValue': self.secrets[name]}}
        return FakeResponse(req.full_url, json.dumps(result, ensure_ascii=False).encode())


class MemorySSH:
    def __init__(self, http=None):
        self.http, self.calls = http or MemoryHTTP(), []
        self.result, self.failure = None, None

    def run(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if self.failure:
            raise self.failure
        if self.result is not None:
            return self.result
        if args != ['python3', '-I', '-B', '-c', SSH_HTTP_HELPER]:
            raise AssertionError('Executable arguments are not the fixed helper')
        return execute_helper(kwargs['input'], self.http)


def execute_helper(payload, http):
    # Standard-library HTTP construction remains real; the only opener is fake.
    output = io.StringIO()
    source = io.TextIOWrapper(io.BytesIO(payload), encoding='utf-8')
    with patch('sys.stdin', source), patch('sys.stdout', output), \
            patch('urllib.request.build_opener', http.build):
        exec(compile(SSH_HTTP_HELPER, '<synthetic-ssh-http-helper>', 'exec'), {'__name__': '__main__'})
    return output.getvalue().encode('utf-8')


class SSHAdapterTests(unittest.TestCase):
    def setUp(self):
        self.ssh = MemorySSH()
        self.opener = SSHInfisicalOpener(self.ssh, TARGET)

    def assert_fixed(self, callback, code):
        with self.assertRaises(InfisicalFailure) as caught:
            callback()
        self.assertEqual(str(caught.exception), code)
        text = ''.join(traceback.format_exception(caught.exception))
        for value in (TOKEN, SECRET):
            self.assertNotIn(value, repr(caught.exception))
            self.assertNotIn(value, text)

    def test_only_canonical_literal_loopback_target_is_allowed(self):
        self.assertEqual(validate_target(TARGET + '/'), TARGET)
        for target in ('https://127.0.0.1:18080', 'http://localhost:18080', 'http://127.1:18080',
                       'http://[::1]:18080', 'http://192.0.2.1:18080', 'http://127.0.0.1',
                       'http://127.0.0.1:0', 'http://127.0.0.1:65536', 'http://127.0.0.1:018080',
                       'http://user:password@127.0.0.1:18080', TARGET + '/api', TARGET + '?key=x',
                       TARGET + '#fragment', TARGET + '\n'):
            with self.subTest(target=target):
                self.assert_fixed(lambda: SSHInfisicalOpener(self.ssh, target), 'INFISICAL_SSH_TARGET_INVALID')
        self.assertEqual(self.ssh.calls, [])

    def test_tokens_and_secret_bodies_only_enter_ssh_stdin_never_executable_arguments(self):
        body = json.dumps({'secretValue': SECRET}, ensure_ascii=False).encode('utf-8')
        with self.opener.open(request('POST', '/api/v4/secrets/API_KEY', '', body)) as response:
            self.assertEqual(response.status, 200)
        args, kwargs = self.ssh.calls[0]
        for private in (TOKEN, SECRET):
            self.assertNotIn(private, repr(args))
            self.assertNotIn(private, repr({key: value for key, value in kwargs.items() if key != 'input'}))
            self.assertNotIn(private, repr(self.opener))
        self.assertEqual(set(kwargs), {'input', 'timeout'})
        payload = json.loads(kwargs['input'])
        self.assertEqual(payload['authorization'], 'Bearer ' + TOKEN)
        self.assertEqual(base64.b64decode(payload['body']), body)
        self.assertEqual(payload['target'], TARGET)
        self.assertEqual(kwargs['timeout'], 40)

    def test_full_infisical_client_flow_uses_the_agent_loopback_route(self):
        api = InfisicalClient(SSH_ORIGIN, PROJECT, 'prod', TOKEN, opener=self.opener)
        result = api.ensure('example', {'API_KEY': SECRET})
        self.assertEqual(result, dict(status='PASS', created_keys=['API_KEY'], verified_keys=['API_KEY']))
        self.assertEqual(self.ssh.http.secrets, {'API_KEY': SECRET})
        self.assertTrue(self.ssh.http.folder)
        for req, timeout in self.ssh.http.calls:
            self.assertTrue(req.full_url.startswith(TARGET + '/api/'))
            self.assertEqual(req.get_header('Authorization'), 'Bearer ' + TOKEN)
            self.assertEqual(timeout, 30)
        self.assertNotIn(TOKEN, repr(result))
        self.assertNotIn(SECRET, repr(result))

    def test_response_is_bounded_streaming_and_exposes_exact_virtual_url(self):
        req = request()
        response = self.opener.open(req)
        self.assertEqual(response.geturl(), req.full_url)
        self.assertEqual(response.getcode(), 200)
        self.assertEqual(response.read(0), b'')
        first, rest = response.read(4), response.read()
        self.assertEqual(json.loads(first + rest), {'folders': []})
        self.assertEqual(response.read(99999999), b'')
        self.assertNotIn(SECRET, repr(response))
        response.close()
        self.assertTrue(response.closed)
        with self.assertRaisesRegex(ValueError, '^I/O operation on closed response$'):
            response.read()

    def test_close_releases_response_data_even_when_caller_raises(self):
        response = self.opener.open(request())
        with self.assertRaises(RuntimeError):
            with response:
                raise RuntimeError('synthetic caller interruption')
        self.assertTrue(response.closed)
        self.assertEqual(response._SSHInfisicalResponse__body, b'')

    def test_only_get_post_and_fixed_api_paths_can_enter_ssh(self):
        cases = [('DELETE', '/api/v2/folders', FOLDER_QUERY),
                 ('PUT', '/api/v4/secrets/API_KEY', ''),
                 ('GET', '/api/v1/users', FOLDER_QUERY),
                 ('GET', '/api/v4/secrets/../shared', SECRET_QUERY),
                 ('GET', '/api/v4/secrets/%2e%2e', SECRET_QUERY),
                 ('GET', '//other.example.test/api/v2/folders', FOLDER_QUERY)]
        for method, path, query in cases:
            with self.subTest(method=method, path=path):
                self.assert_fixed(lambda: self.opener.open(request(method, path, query)), 'INFISICAL_SSH_REQUEST_REFUSED')
        self.assertEqual(self.ssh.calls, [])

    def test_virtual_origin_has_no_external_dns_credentials_port_or_fragment(self):
        for url in ('https://external.example.test/api/v2/folders?' + FOLDER_QUERY,
                    SSH_ORIGIN.replace('https:', 'http:') + '/api/v2/folders?' + FOLDER_QUERY,
                    'https://user:password@infisical.ssh.invalid/api/v2/folders?' + FOLDER_QUERY,
                    SSH_ORIGIN + ':443/api/v2/folders?' + FOLDER_QUERY,
                    SSH_ORIGIN + '/api/v2/folders?' + FOLDER_QUERY + '#fragment'):
            req = Request(url, headers={'Authorization': 'Bearer ' + TOKEN})
            self.assert_fixed(lambda: self.opener.open(req), 'INFISICAL_SSH_REQUEST_REFUSED')
        self.assertEqual(self.ssh.calls, [])

    def test_get_query_must_be_exact_encoded_non_importing_infisical_scope(self):
        for query in ('', FOLDER_QUERY + '&unexpected=' + TOKEN, FOLDER_QUERY + '&projectId=' + PROJECT,
                      FOLDER_QUERY.replace('recursive=false', 'recursive=true'),
                      FOLDER_QUERY.replace('%2F', 'http%3A%2F%2Fother.example.test'),
                      FOLDER_QUERY.replace('%2F', '%2f')):
            with self.subTest(query_kind=query[:10]):
                self.assert_fixed(lambda: self.opener.open(request(query=query)), 'INFISICAL_SSH_REQUEST_REFUSED')
        req = request(path='/api/v4/secrets/API_KEY', query=SECRET_QUERY.replace('includeImports=false', 'includeImports=true'))
        self.assert_fixed(lambda: self.opener.open(req), 'INFISICAL_SSH_REQUEST_REFUSED')
        self.assertEqual(self.ssh.calls, [])

    def test_post_must_have_json_object_body_and_no_query(self):
        for body in (None, b'[]', b'not-json', b'\xff', b'x' * (512 * 1024 + 1)):
            self.assert_fixed(lambda: self.opener.open(request('POST', '/api/v4/secrets/API_KEY', '', body)),
                              'INFISICAL_SSH_REQUEST_REFUSED')
        self.assert_fixed(lambda: self.opener.open(request('POST', '/api/v2/folders', FOLDER_QUERY, b'{}')),
                          'INFISICAL_SSH_REQUEST_REFUSED')
        self.assert_fixed(lambda: self.opener.open(request(body=b'{}')), 'INFISICAL_SSH_REQUEST_REFUSED')
        self.assertEqual(self.ssh.calls, [])

    def test_missing_or_header_injected_authorization_is_refused_before_ssh(self):
        for authorization in ('', 'Basic secret', 'Bearer ', 'Bearer token\r\nHost: other', 'Bearer two words'):
            req = request()
            req.add_header('Authorization', authorization)
            self.assert_fixed(lambda: self.opener.open(req), 'INFISICAL_SSH_REQUEST_REFUSED')
        self.assertEqual(self.ssh.calls, [])

    def test_only_fixed_headers_are_forwarded_and_environment_proxies_are_disabled(self):
        req = request(Host='other.example.test', Proxy_authorization='private-proxy', Cookie='private-cookie')
        self.opener.open(req).close()
        headers = dict(self.ssh.http.calls[0][0].header_items())
        self.assertEqual(set(headers), {'Authorization', 'Accept', 'Content-type'})
        handlers = self.ssh.http.handlers[0]
        proxy = next(handler for handler in handlers if isinstance(handler, ProxyHandler))
        redirect = next(handler for handler in handlers if isinstance(handler, HTTPRedirectHandler))
        self.assertEqual(proxy.proxies, {})
        self.assertIsNone(redirect.redirect_request(req, None, 302, 'Found', {}, 'https://other.example.test'))

    def test_http_errors_have_no_upstream_body_headers_or_secret_reason(self):
        for status in (401, 403, 404, 409, 429, 500):
            with self.subTest(status=status):
                body = ErrorBody()
                self.ssh.http.failure = HTTPError(TARGET, status, SECRET, {'Private': TOKEN}, body)
                with self.assertRaises(HTTPError) as caught:
                    self.opener.open(request())
                error = caught.exception
                self.assertEqual(error.code, status)
                self.assertEqual(error.headers, {})
                self.assertEqual(error.read(), b'')
                self.assertEqual(error.geturl(), request().full_url)
                self.assertNotIn(TOKEN, str(error))
                self.assertNotIn(SECRET, str(error))
                error.close()
                self.assertEqual(body.reads, 0)
                self.assertTrue(body.closed)

    def test_infisical_client_preserves_fixed_auth_error_mapping(self):
        body = ErrorBody()
        self.ssh.http.failure = HTTPError(TARGET, 401, SECRET, {'Private': TOKEN}, body)
        api = InfisicalClient(SSH_ORIGIN, PROJECT, 'prod', TOKEN, opener=self.opener)
        self.assert_fixed(lambda: api.inspect('example', {'API_KEY': SECRET}), 'INFISICAL_AUTH_FAILED')

    def test_redirects_are_refused_without_reading_or_forwarding_any_response(self):
        for code in (301, 302, 303, 307, 308):
            body = ErrorBody()
            self.ssh.http.failure = HTTPError(TARGET, code, SECRET, {'Location': 'https://other.example.test/' + TOKEN}, body)
            self.assert_fixed(lambda: self.opener.open(request()), 'INFISICAL_REDIRECT_REFUSED')
            self.assertEqual(body.reads, 0)
            self.assertTrue(body.closed)
        self.ssh.http.failure = None
        response = FakeResponse('https://other.example.test', SECRET.encode())
        self.ssh.http.response = response
        self.assert_fixed(lambda: self.opener.open(request()), 'INFISICAL_REDIRECT_REFUSED')
        self.assertEqual(response.reads, [])
        self.assertTrue(response.closed)

    def test_remote_http_and_ssh_exceptions_never_surface_private_text(self):
        self.ssh.http.failure = URLError(TOKEN + SECRET)
        self.assert_fixed(lambda: self.opener.open(request()), 'INFISICAL_CONNECTION_FAILED')
        self.ssh.failure = RuntimeError(TOKEN + SECRET)
        self.assert_fixed(lambda: self.opener.open(request()), 'INFISICAL_CONNECTION_FAILED')

    def test_oversized_http_body_does_not_cross_ssh(self):
        self.ssh.http.response = FakeResponse(TARGET + '/api/v2/folders?' + FOLDER_QUERY, b'x' * (MAX_BODY_BYTES + 1))
        self.assert_fixed(lambda: self.opener.open(request()), 'INFISICAL_CONNECTION_FAILED')
        self.assertEqual(self.ssh.http.response.reads, [MAX_BODY_BYTES + 1])

    def test_successful_helper_output_fits_the_complete_512k_wire_bound(self):
        self.ssh.http.response = FakeResponse(TARGET + '/api/v2/folders?' + FOLDER_QUERY, b'x' * MAX_BODY_BYTES)
        response = self.opener.open(request())
        self.assertEqual(len(response.read()), MAX_BODY_BYTES)
        self.assertLessEqual(len(execute_helper(self.ssh.calls[0][1]['input'], self.ssh.http)), MAX_WIRE_BYTES)
        response.close()

    def test_corrupt_or_unbounded_ssh_response_is_a_fixed_error(self):
        cases = [(b'not-json' + TOKEN.encode(), 'INFISICAL_RESPONSE_INVALID'),
                 (b'[]', 'INFISICAL_RESPONSE_INVALID'),
                 (b'x' * (MAX_WIRE_BYTES + 1), 'INFISICAL_RESPONSE_TOO_LARGE'),
                 (json.dumps({'status': True, 'body': ''}).encode(), 'INFISICAL_RESPONSE_INVALID'),
                 (json.dumps({'status': 200, 'body': '%%'}).encode(), 'INFISICAL_RESPONSE_INVALID'),
                 (json.dumps({'status': 200, 'body': '', 'headers': {'Private': TOKEN}}).encode(), 'INFISICAL_RESPONSE_INVALID'),
                 (json.dumps({'status': 401, 'body': base64.b64encode(SECRET.encode()).decode()}).encode(), 'INFISICAL_RESPONSE_INVALID')]
        for raw, code in cases:
            with self.subTest(code=code):
                self.ssh.result = raw
                self.assert_fixed(lambda: self.opener.open(request()), code)

    def test_timeout_is_explicit_finite_and_bounded(self):
        for timeout in (0, -1, 61, float('inf'), float('nan'), True, '30'):
            self.assert_fixed(lambda: self.opener.open(request(), timeout=timeout), 'INFISICAL_SSH_REQUEST_REFUSED')
        self.assertEqual(self.ssh.calls, [])

    def test_remote_helper_revalidates_target_path_method_and_scope(self):
        self.opener.open(request()).close()
        good = json.loads(self.ssh.calls[0][1]['input'])
        for key, value in (('target', 'http://192.0.2.1:80'), ('target', TARGET + '/api'),
                           ('path', '/api/v4/secrets/../shared'), ('method', 'DELETE'),
                           ('query', FOLDER_QUERY + '&extra=' + TOKEN), ('authorization', 'Bearer bad\nheader'),
                           ('timeout', 0)):
            http = MemoryHTTP()
            data = dict(good, **{key: value})
            result = execute_helper(json.dumps(data).encode(), http)
            self.assertEqual(json.loads(result), {'status': 0, 'body': ''})
            self.assertEqual(http.calls, [])
            self.assertNotIn(TOKEN, result.decode())


if __name__ == '__main__':
    unittest.main()

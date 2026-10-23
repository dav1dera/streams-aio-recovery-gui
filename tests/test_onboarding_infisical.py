"""Synthetic HTTP contract tests; no network, Tk window or real secret is used."""
import io
import json
import traceback
import unittest
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.request import Request

from recovery_gui.onboarding_infisical import (
    InfisicalClient, InfisicalFailure, _NoRedirect, validate_private_values,
)


ENDPOINT = 'https://infisical.example.test'
PROJECT = 'f80601b1-73fb-49bd-9373-f3687cd5c8eb'
TOKEN = 'synthetic-bearer-do-not-publish'
PRIVATE = 'synthetic-private-$value-è-秘密'


class FakeResponse:
    def __init__(self, url, value=None, *, raw=None, status=200):
        self.url, self.status = url, status
        self.raw = json.dumps(value, ensure_ascii=False).encode('utf-8') if raw is None else raw
        self.read_limits, self.closed = [], False

    def geturl(self):
        return self.url

    def read(self, limit):
        self.read_limits.append(limit)
        return self.raw[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True


class ErrorBody(io.BytesIO):
    def __init__(self):
        super().__init__((PRIVATE + TOKEN).encode('utf-8'))
        self.reads = 0

    def read(self, *args):
        self.reads += 1
        return super().read(*args)


class ScriptedHTTP:
    def __init__(self, *replies):
        self.replies, self.requests = list(replies), []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if not self.replies:
            raise AssertionError('Unexpected HTTP request')
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        if callable(reply):
            return reply(request)
        return FakeResponse(request.full_url, reply)


class MemoryAPI:
    """A tiny strict v2/v4 fake which records every body and read scope."""
    def __init__(self, folder=False, secrets=None, *, persist=True):
        self.folder, self.secrets = folder, dict(secrets or {})
        self.persist, self.requests, self.error_bodies = persist, [], []

    def open(self, request, timeout):
        parts = urlsplit(request.full_url)
        method, path = request.get_method(), parts.path
        query = {key: value[0] for key, value in parse_qs(parts.query).items()}
        body = json.loads(request.data) if request.data is not None else None
        self.requests.append(dict(method=method, path=path, query=query, body=body,
                                  authorization=request.get_header('Authorization'), timeout=timeout))
        if path == '/api/v2/folders' and method == 'GET':
            value = {'folders': [{'name': 'example', 'path': '/'}] if self.folder else []}
        elif path == '/api/v2/folders' and method == 'POST':
            if self.persist:
                self.folder = True
            value = {'folder': {'name': body['name'], 'path': body['path']}}
        elif path.startswith('/api/v4/secrets/'):
            name = unquote(path.rsplit('/', 1)[1])
            if method == 'GET':
                if name not in self.secrets:
                    raw = ErrorBody()
                    self.error_bodies.append(raw)
                    raise HTTPError(request.full_url, 404, 'Not Found', {}, raw)
                value = {'secret': {'secretKey': name, 'secretValue': self.secrets[name]}}
            elif method == 'POST':
                if self.persist:
                    self.secrets[name] = body['secretValue']
                value = {'secret': {'secretKey': name, 'secretValue': body['secretValue']}}
            else:
                raise AssertionError('Mutation outside the create-only contract')
        else:
            raise AssertionError('Unexpected API route')
        return FakeResponse(request.full_url, value)


def client(opener):
    return InfisicalClient(ENDPOINT, PROJECT, 'prod', TOKEN, opener=opener)


class RedactionAndTransportTests(unittest.TestCase):
    def assert_fixed_error(self, operation, expected):
        with self.assertRaises(InfisicalFailure) as caught:
            operation()
        error = caught.exception
        self.assertEqual(str(error), expected)
        self.assertNotIn(PRIVATE, repr(error))
        self.assertNotIn(TOKEN, repr(error))
        formatted = ''.join(traceback.format_exception(error))
        self.assertNotIn(PRIVATE, formatted)
        self.assertNotIn(TOKEN, formatted)
        return error

    def test_client_repr_never_contains_token_or_private_value(self):
        self.assertEqual(repr(client(ScriptedHTTP())), '<InfisicalClient credentials=redacted>')
        self.assertNotIn(TOKEN, repr(client(ScriptedHTTP())))

    def test_constructor_rejects_unsafe_origins_and_credentials_before_http(self):
        opener = ScriptedHTTP()
        for endpoint in ('http://infisical.example.test', 'https://user:password@example.test',
                         ENDPOINT + '/api', ENDPOINT + '?token=' + TOKEN,
                         ENDPOINT + '#fragment', ENDPOINT + ':99999', ENDPOINT + '\n'):
            with self.subTest(endpoint=endpoint):
                self.assert_fixed_error(lambda: InfisicalClient(endpoint, PROJECT, 'prod', TOKEN, opener=opener),
                                        'SERVICE_INFISICAL_ADDRESS_REQUIRED')
        for token in ('', 'two words', 'line\nbreak', 'a\x7fb'):
            self.assert_fixed_error(lambda: InfisicalClient(ENDPOINT, PROJECT, 'prod', token, opener=opener),
                                    'SERVICE_INFISICAL_ACCESS_REQUIRED')
        self.assertEqual(opener.requests, [])

    def test_http_errors_are_fixed_codes_and_bodies_are_closed_without_reading(self):
        mapping = {401: 'INFISICAL_AUTH_FAILED', 403: 'INFISICAL_PERMISSION_DENIED',
                   404: 'INFISICAL_API_VERSION_UNSUPPORTED', 409: 'INFISICAL_SECRET_CONFLICT',
                   429: 'INFISICAL_RATE_LIMITED', 500: 'INFISICAL_API_FAILED'}
        for status, expected in mapping.items():
            with self.subTest(status=status):
                body = ErrorBody()
                error = HTTPError(ENDPOINT + '/private-response', status, PRIVATE, {'Secret': TOKEN}, body)
                http = ScriptedHTTP(error)
                raised = self.assert_fixed_error(lambda: client(http)._request('GET', '/api/v2/folders'), expected)
                self.assertTrue(raised.__suppress_context__)
                self.assertEqual(body.reads, 0)
                self.assertTrue(body.closed)
                self.assertEqual(len(http.requests), 1)

    def test_missing_read_is_none_but_missing_folder_api_is_not_silently_accepted(self):
        body = ErrorBody()
        http = ScriptedHTTP(HTTPError(ENDPOINT, 404, PRIVATE, {}, body))
        self.assertIsNone(client(http)._request('GET', '/api/v4/secrets/KEY', missing=True))
        self.assertEqual(body.reads, 0)
        self.assertTrue(body.closed)

    def test_network_error_reason_is_never_displayed(self):
        for cause in (URLError(PRIVATE + TOKEN), OSError(PRIVATE + TOKEN)):
            self.assert_fixed_error(lambda: client(ScriptedHTTP(cause))._request('GET', '/api/v2/folders'),
                                    'INFISICAL_CONNECTION_FAILED')

    def test_redirect_handler_refuses_before_creating_a_forwarded_request(self):
        request = Request(ENDPOINT + '/api/v2/folders', headers={'Authorization': 'Bearer ' + TOKEN})
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code):
                self.assert_fixed_error(lambda: _NoRedirect().redirect_request(
                    request, None, code, 'Redirect', {}, 'https://other.example.test/collect'),
                    'INFISICAL_REDIRECT_REFUSED')

    def test_a_transport_that_follows_redirects_is_rejected_and_not_read(self):
        response = FakeResponse('https://other.example.test/collect', {'secret': PRIVATE})
        http = ScriptedHTTP(lambda _: response)
        self.assert_fixed_error(lambda: client(http)._request('GET', '/api/v2/folders'),
                                'INFISICAL_REDIRECT_REFUSED')
        self.assertEqual(response.read_limits, [])
        self.assertTrue(response.closed)
        self.assertEqual(len(http.requests), 1)

    def test_invalid_response_shapes_never_disclose_a_response_body(self):
        for raw, expected in ((('invalid ' + PRIVATE).encode('utf-8'), 'INFISICAL_CONNECTION_FAILED'),
                              (b'[]', 'INFISICAL_RESPONSE_INVALID'),
                              ((PRIVATE.encode('utf-8') * 70000), 'INFISICAL_RESPONSE_TOO_LARGE')):
            response = FakeResponse(ENDPOINT + '/api/v2/folders', raw=raw)
            self.assert_fixed_error(lambda: client(ScriptedHTTP(lambda _: response))._request('GET', '/api/v2/folders'),
                                    expected)
            self.assertEqual(response.read_limits, [1024 * 1024 + 1])
            self.assertTrue(response.closed)


class SecretLifecycleTests(unittest.TestCase):
    def test_inspect_missing_folder_is_read_only_and_reports_names_without_values(self):
        api = MemoryAPI()
        result = client(api).inspect('example', {'API_KEY': PRIVATE, 'DATABASE_URL': 'synthetic-db'})
        self.assertEqual(result, dict(status='PASS', folder_exists=False, existing_keys=[],
                                      missing_keys=['API_KEY', 'DATABASE_URL']))
        self.assertEqual([r['method'] for r in api.requests], ['GET'])
        self.assertNotIn(PRIVATE, repr(result))
        self.assertNotIn(TOKEN, repr(result))

    def test_identical_existing_secret_is_reused_without_writes(self):
        api = MemoryAPI(folder=True, secrets={'API_KEY': PRIVATE})
        result = client(api).ensure('example', {'API_KEY': PRIVATE})
        self.assertEqual(result, dict(status='PASS', created_keys=[], verified_keys=['API_KEY']))
        self.assertTrue(all(r['method'] == 'GET' for r in api.requests))
        self.assertNotIn(PRIVATE, repr(result))

    def test_existing_different_secret_is_a_conflict_and_never_overwritten(self):
        api = MemoryAPI(folder=True, secrets={'API_KEY': 'older-private-value'})
        with self.assertRaisesRegex(InfisicalFailure, '^INFISICAL_SECRET_CONFLICT$'):
            client(api).ensure('example', {'API_KEY': PRIVATE})
        self.assertEqual(api.secrets['API_KEY'], 'older-private-value')
        self.assertTrue(all(r['method'] == 'GET' for r in api.requests))

    def test_create_uses_exact_scope_and_body_then_reads_back_unicode_and_dollars(self):
        api = MemoryAPI()
        values = {'Z_TOKEN': 'double"quote and $dollar', 'API_KEY': PRIVATE}
        result = client(api).ensure('example', values)
        self.assertEqual(result, dict(status='PASS', created_keys=['API_KEY', 'Z_TOKEN'],
                                      verified_keys=['API_KEY', 'Z_TOKEN']))
        self.assertEqual(api.secrets, values)
        for request in api.requests:
            self.assertEqual(request['authorization'], 'Bearer ' + TOKEN)
            self.assertEqual(request['timeout'], 30)
            self.assertIn(request['method'], ('GET', 'POST'))
            if request['method'] == 'GET' and request['path'] == '/api/v2/folders':
                self.assertEqual(request['query'], dict(projectId=PROJECT, environment='prod',
                                                        path='/', recursive='false'))
            elif request['method'] == 'GET':
                self.assertEqual(request['query'], dict(projectId=PROJECT, environment='prod',
                    secretPath='/example', type='shared', expandSecretReferences='false', includeImports='false'))
            elif request['path'] == '/api/v2/folders':
                self.assertEqual(request['body'], dict(projectId=PROJECT, environment='prod', name='example', path='/'))
            else:
                name = request['path'].rsplit('/', 1)[1]
                self.assertEqual(request['body'], dict(projectId=PROJECT, environment='prod',
                    secretPath='/example', type='shared', secretValue=values[name], skipMultilineEncoding=True))
        self.assertNotIn(PRIVATE, repr(result))

    def test_existing_folder_missing_secret_is_created_without_recreating_folder(self):
        api = MemoryAPI(folder=True)
        result = client(api).ensure('example', {'API_KEY': PRIVATE})
        self.assertEqual(result['created_keys'], ['API_KEY'])
        writes = [r for r in api.requests if r['method'] == 'POST']
        self.assertEqual([r['path'] for r in writes], ['/api/v4/secrets/API_KEY'])
        self.assertTrue(all(body.closed and not body.reads for body in api.error_bodies))

    def test_readback_failure_cannot_return_a_verified_result(self):
        api = MemoryAPI(folder=True, persist=False)
        with self.assertRaisesRegex(InfisicalFailure, '^INFISICAL_READBACK_FAILED$'):
            client(api).ensure('example', {'API_KEY': PRIVATE})

    def test_interrupted_creation_reuses_created_values_without_updates_or_deletes(self):
        api = MemoryAPI(folder=True)
        transport = api.open
        fail_next = [True]
        def interrupt_once(request, timeout):
            if request.get_method() == 'POST' and request.full_url.endswith('/SECOND') and fail_next[0]:
                fail_next[0] = False
                raise HTTPError(request.full_url, 500, 'Synthetic interruption', {}, ErrorBody())
            return transport(request, timeout)
        api.open = interrupt_once
        values = {'FIRST': PRIVATE, 'SECOND': 'second-synthetic-private'}
        with self.assertRaisesRegex(InfisicalFailure, '^INFISICAL_API_FAILED$'):
            client(api).ensure('example', values)
        self.assertEqual(api.secrets, {'FIRST': PRIVATE})
        result = client(api).ensure('example', values)
        self.assertEqual(result, dict(status='PASS', created_keys=['SECOND'], verified_keys=['FIRST', 'SECOND']))
        self.assertEqual(api.secrets, values)
        self.assertEqual(sum(r['path'].endswith('/FIRST') and r['method'] == 'POST' for r in api.requests), 1)
        self.assertTrue(all(r['method'] in ('GET', 'POST') for r in api.requests))

    def test_duplicate_or_malformed_folder_response_is_refused(self):
        cases = [({'folders': [{'name': 'example'}, {'name': 'example'}]}, 'INFISICAL_FOLDER_CONFLICT'),
                 ({'folders': PRIVATE}, 'INFISICAL_RESPONSE_INVALID'),
                 ({'folders': [PRIVATE]}, 'INFISICAL_RESPONSE_INVALID')]
        for response, code in cases:
            with self.subTest(code=code), self.assertRaisesRegex(InfisicalFailure, '^' + code + '$'):
                client(ScriptedHTTP(response)).inspect('example', {'API_KEY': PRIVATE})

    def test_wrong_key_or_non_string_secret_response_is_refused(self):
        for secret in ({'secretKey': 'OTHER', 'secretValue': PRIVATE},
                       {'secretKey': 'API_KEY', 'secretValue': 123}, PRIVATE):
            with self.subTest(secret_type=type(secret).__name__):
                http = ScriptedHTTP({'folders': [{'name': 'example'}]}, {'secret': secret})
                with self.assertRaisesRegex(InfisicalFailure, '^INFISICAL_RESPONSE_INVALID$'):
                    client(http).inspect('example', {'API_KEY': PRIVATE})

    def test_service_path_injection_is_refused_before_http(self):
        for name in ('../shared', '/shared', 'UPPER', 'example?key=value', 'example/other'):
            http = ScriptedHTTP()
            with self.subTest(name=name), self.assertRaisesRegex(InfisicalFailure, '^SERVICE_NAME_INVALID$'):
                client(http).ensure(name, {'API_KEY': PRIVATE})
            self.assertEqual(http.requests, [])


class PrivateValueContractTests(unittest.TestCase):
    def test_invalid_unicode_is_a_fixed_error_before_any_http(self):
        for value in ('synthetic-private-\ud800-value', 'synthetic-private-\udfff-value'):
            api = MemoryAPI()
            with self.subTest(surrogate=ord(value[18])):
                with self.assertRaisesRegex(InfisicalFailure, '^SERVICE_PRIVATE_VALUES_INVALID$') as caught:
                    client(api).ensure('example', {'API_KEY': value})
                self.assertNotIn(value, repr(caught.exception))
                self.assertEqual(api.requests, [])

    def test_legacy_agent_quote_contract_allows_dollars_double_quotes_and_unicode(self):
        validate_private_values({'API_KEY': PRIVATE, 'OTHER': 'a"b\\c $d ${d} € 秘密'})

    def test_legacy_agent_quote_contract_rejects_unsafe_quoting_without_echoing_value(self):
        for value in ("don't-echo-this", 'trailing\\', 'line\nbreak', 'line\rbreak', 'a\x00b', 'a\tb', 'a\x7fb'):
            with self.subTest(kind=repr(value[:1])):
                with self.assertRaisesRegex(InfisicalFailure, '^SERVICE_PRIVATE_VALUE_QUOTING_UNSUPPORTED$') as caught:
                    validate_private_values({'API_KEY': value})
                self.assertNotIn(value, str(caught.exception))

    def test_values_and_names_must_follow_the_closed_contract(self):
        for values, code in (([], 'SERVICE_PRIVATE_VALUES_INVALID'),
                             ({'API_KEY': ''}, 'SERVICE_PRIVATE_VALUES_INVALID'),
                             ({'API_KEY': None}, 'SERVICE_PRIVATE_VALUES_INVALID'),
                             ({'API_KEY': 'x' * 16385}, 'SERVICE_PRIVATE_VALUES_INVALID'),
                             ({'API-KEY': PRIVATE}, 'SERVICE_VARIABLE_NAME_INVALID'),
                             ({'1KEY': PRIVATE}, 'SERVICE_VARIABLE_NAME_INVALID')):
            with self.subTest(code=code), self.assertRaisesRegex(InfisicalFailure, '^' + code + '$'):
                validate_private_values(values)


if __name__ == '__main__':
    unittest.main()

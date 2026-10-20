"""Infisical HTTP over an already authenticated SSH session.

The HTTPS origin below is a virtual routing marker, never resolved or contacted.
Only a fixed helper runs on the stack VM; its API token and request body travel
on SSH stdin. Successful response bytes remain in memory for InfisicalClient.
No new connection, environment proxy, file, shell interpolation or log is used.
"""
import base64
import binascii
import io
import json
import math
import re
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlencode, urlsplit
from uuid import UUID

from .onboarding_infisical import InfisicalFailure


SSH_ORIGIN = 'https://infisical.ssh.invalid'
MAX_WIRE_BYTES = 512 * 1024
# Keep the complete JSON + base64 response below the SSH wire bound.
MAX_BODY_BYTES = 384 * 1024 - 1024
MAX_REQUEST_BODY_BYTES = 512 * 1024
MAX_INPUT_BYTES = 768 * 1024
PATH_PATTERN = re.compile(r'/api/(?:v2/folders|v4/secrets/[A-Za-z_][A-Za-z0-9_]{0,127})\Z')


def _need(condition, code='INFISICAL_SSH_REQUEST_REFUSED'):
    if not condition:
        raise InfisicalFailure(code)


def validate_target(origin):
    """Only a canonical literal loopback HTTP origin, including a port."""
    try:
        parts = urlsplit(origin)
        valid = (isinstance(origin, str) and parts.scheme == 'http'
                 and parts.hostname == '127.0.0.1' and parts.port is not None
                 and 1 <= parts.port <= 65535 and parts.username is None and parts.password is None
                 and parts.netloc == '127.0.0.1:' + str(parts.port)
                 and parts.path in ('', '/') and not parts.query and not parts.fragment
                 and not any(ord(c) < 33 or ord(c) == 127 for c in origin))
    except (TypeError, ValueError, AttributeError, UnicodeError):
        valid = False
    _need(valid, 'INFISICAL_SSH_TARGET_INVALID')
    return origin.rstrip('/')


def _valid_route(method, path, query):
    _need(method in ('GET', 'POST') and isinstance(path, str) and PATH_PATTERN.fullmatch(path))
    _need(isinstance(query, str) and len(query) <= 2048)
    if method == 'POST':
        _need(not query)
        return
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True, max_num_fields=10)
        values = dict(pairs)
        _need(len(values) == len(pairs) and urlencode(pairs) == query)
        UUID(values.get('projectId', ''))
        _need(re.fullmatch(r'[A-Za-z0-9_-]{1,64}', values.get('environment', '')))
        if path == '/api/v2/folders':
            _need(set(values) == {'projectId', 'environment', 'path', 'recursive'}
                  and values['path'] == '/' and values['recursive'] == 'false')
        else:
            _need(set(values) == {'projectId', 'environment', 'secretPath', 'type',
                                  'expandSecretReferences', 'includeImports'}
                  and re.fullmatch(r'/[a-z][a-z0-9_-]{0,62}', values['secretPath'])
                  and values['type'] == 'shared' and values['expandSecretReferences'] == 'false'
                  and values['includeImports'] == 'false')
    except InfisicalFailure:
        raise
    except (TypeError, ValueError, AttributeError, UnicodeError):
        raise InfisicalFailure('INFISICAL_SSH_REQUEST_REFUSED') from None


# This complete fixed source is the only executable argument sent to SSH.run.
# Validate again at the SSH boundary; no shell, dynamic imports, files or proxy
# configuration are taken from the request or the VM environment.
SSH_HTTP_HELPER = r'''
import base64, json, math, re, sys
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID

MAX_BODY = 384 * 1024 - 1024
MAX_INPUT = 768 * 1024

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def output(status, body=b''):
    print(json.dumps({'status': status, 'body': base64.b64encode(body).decode('ascii')}, separators=(',', ':')))

def main():
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        assert len(raw) <= MAX_INPUT
        data = json.loads(raw)
        assert isinstance(data, dict) and set(data) == {'target', 'method', 'path', 'query', 'authorization', 'body', 'timeout'}
        origin = data['target']
        parts = urlsplit(origin)
        assert isinstance(origin, str) and parts.scheme == 'http' and parts.hostname == '127.0.0.1'
        assert parts.port is not None and 1 <= parts.port <= 65535
        assert parts.netloc == '127.0.0.1:' + str(parts.port)
        assert parts.username is None and parts.password is None and not parts.path and not parts.query and not parts.fragment
        assert not any(ord(c) < 33 or ord(c) == 127 for c in origin)
        method, path, query = data['method'], data['path'], data['query']
        assert method in ('GET', 'POST') and isinstance(path, str)
        assert re.fullmatch(r'/api/(?:v2/folders|v4/secrets/[A-Za-z_][A-Za-z0-9_]{0,127})', path)
        assert isinstance(query, str) and len(query) <= 2048
        if method == 'POST':
            assert not query
        else:
            pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True, max_num_fields=10)
            scope = dict(pairs)
            assert len(scope) == len(pairs) and urlencode(pairs) == query
            UUID(scope.get('projectId', ''))
            assert re.fullmatch(r'[A-Za-z0-9_-]{1,64}', scope.get('environment', ''))
            if path == '/api/v2/folders':
                assert set(scope) == {'projectId', 'environment', 'path', 'recursive'}
                assert scope['path'] == '/' and scope['recursive'] == 'false'
            else:
                assert set(scope) == {'projectId', 'environment', 'secretPath', 'type', 'expandSecretReferences', 'includeImports'}
                assert re.fullmatch(r'/[a-z][a-z0-9_-]{0,62}', scope['secretPath'])
                assert scope['type'] == 'shared' and scope['expandSecretReferences'] == 'false' and scope['includeImports'] == 'false'
        authorization = data['authorization']
        assert isinstance(authorization, str) and authorization.startswith('Bearer ') and 7 < len(authorization) <= 16391
        assert not any(ord(c) < 33 or ord(c) > 126 for c in authorization[7:])
        assert isinstance(data['body'], str)
        body = base64.b64decode(data['body'].encode('ascii'), validate=True)
        assert len(body) <= 512 * 1024
        assert (method == 'GET' and not body) or (method == 'POST' and isinstance(json.loads(body), dict))
        timeout = data['timeout']
        assert type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 60
        url = origin + path + ('?' + query if query else '')
        request = Request(url, data=body if method == 'POST' else None, method=method,
            headers={'Authorization': authorization, 'Accept': 'application/json', 'Content-Type': 'application/json'})
        # ProxyHandler({}) explicitly disables HTTP(S)_PROXY on the VM.
        opener = build_opener(ProxyHandler({}), NoRedirect())
        try:
            with opener.open(request, timeout=timeout) as response:
                status = response.status
                if response.geturl() != url:
                    output(302)
                    return
                if type(status) is not int or not 200 <= status <= 599:
                    output(0)
                    return
                if not 200 <= status < 300:
                    output(status)
                    return
                result = response.read(MAX_BODY + 1)
                assert isinstance(result, bytes) and len(result) <= MAX_BODY
            output(status, result)
        except HTTPError as error:
            status = error.code
            error.close()
            output(status if type(status) is int and 300 <= status <= 599 else 0)
    except Exception:
        # Exception text, upstream headers and error bodies are never emitted.
        output(0)

main()
'''


class SSHInfisicalResponse:
    """Bounded urllib response; closing promptly releases private bytes."""
    def __init__(self, url, status, body):
        self.__url, self.status = url, status
        self.__body, self.__offset, self.closed = body, 0, False

    def __repr__(self):
        return '<SSHInfisicalResponse status=' + str(self.status) + ' body=redacted>'

    def geturl(self):
        return self.__url

    def getcode(self):
        return self.status

    def read(self, size=-1):
        if self.closed:
            raise ValueError('I/O operation on closed response')
        if not isinstance(size, int):
            raise TypeError('Response read size must be an integer')
        end = len(self.__body) if size < 0 else min(len(self.__body), self.__offset + size)
        result = self.__body[self.__offset:end]
        self.__offset = end
        return result

    def close(self):
        self.__body, self.__offset, self.closed = b'', 0, True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class SSHInfisicalOpener:
    def __init__(self, ssh, target_origin):
        self.__target = validate_target(target_origin)
        self.__ssh = ssh

    def __repr__(self):
        return '<SSHInfisicalOpener route=authenticated-ssh credentials=redacted>'

    def open(self, request, timeout=30):
        """Use the existing SSH transport, never a Windows or public DNS route."""
        try:
            url = request.full_url
            parts = urlsplit(url)
            _need(isinstance(url, str) and len(url) <= 4096
                  and parts.scheme == 'https' and parts.netloc == 'infisical.ssh.invalid'
                  and not parts.fragment and not any(ord(c) < 33 or ord(c) == 127 for c in url))
            method, path, query = request.get_method(), parts.path, parts.query
            _valid_route(method, path, query)
            authorization = request.get_header('Authorization', '')
            _need(isinstance(authorization, str) and authorization.startswith('Bearer ')
                  and 7 < len(authorization) <= 16391
                  and not any(ord(c) < 33 or ord(c) > 126 for c in authorization[7:]))
            body = request.data
            if method == 'GET':
                _need(body is None or body == b'')
                body = b''
            else:
                _need(isinstance(body, bytes) and len(body) <= MAX_REQUEST_BODY_BYTES)
                _need(isinstance(json.loads(body), dict))
            _need(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 60)
            payload = json.dumps(dict(target=self.__target, method=method, path=path, query=query,
                authorization=authorization, body=base64.b64encode(body).decode('ascii'), timeout=timeout),
                separators=(',', ':')).encode('utf-8')
            _need(len(payload) <= MAX_INPUT_BYTES)
        except InfisicalFailure:
            raise
        except Exception:
            raise InfisicalFailure('INFISICAL_SSH_REQUEST_REFUSED') from None
        try:
            raw = self.__ssh.run(['python3', '-I', '-B', '-c', SSH_HTTP_HELPER],
                                 input=payload, timeout=timeout + 10)
        except Exception:
            raise InfisicalFailure('INFISICAL_CONNECTION_FAILED') from None
        try:
            _need(isinstance(raw, bytes), 'INFISICAL_RESPONSE_INVALID')
            _need(len(raw) <= MAX_WIRE_BYTES, 'INFISICAL_RESPONSE_TOO_LARGE')
            result = json.loads(raw)
            _need(isinstance(result, dict) and set(result) == {'status', 'body'}, 'INFISICAL_RESPONSE_INVALID')
            status, encoded = result['status'], result['body']
            _need(type(status) is int and isinstance(encoded, str), 'INFISICAL_RESPONSE_INVALID')
            if status == 0:
                _need(not encoded, 'INFISICAL_RESPONSE_INVALID')
                raise InfisicalFailure('INFISICAL_CONNECTION_FAILED')
            _need(200 <= status <= 599, 'INFISICAL_RESPONSE_INVALID')
            if not 200 <= status < 300:
                _need(not encoded, 'INFISICAL_RESPONSE_INVALID')
                if status < 400:
                    raise InfisicalFailure('INFISICAL_REDIRECT_REFUSED')
                # A fresh empty body and headers, never upstream private data.
                raise HTTPError(url, status, 'INFISICAL_HTTP_ERROR', {}, io.BytesIO(b''))
            decoded = base64.b64decode(encoded.encode('ascii'), validate=True)
            _need(len(decoded) <= MAX_BODY_BYTES, 'INFISICAL_RESPONSE_TOO_LARGE')
            return SSHInfisicalResponse(url, status, decoded)
        except (InfisicalFailure, HTTPError):
            raise
        except (ValueError, TypeError, AttributeError, UnicodeError, binascii.Error):
            raise InfisicalFailure('INFISICAL_RESPONSE_INVALID') from None

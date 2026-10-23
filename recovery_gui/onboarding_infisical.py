"""Small, credential-redacting Infisical API adapter for new service secrets.

No calls occur on import. Values are never returned in diagnostics. Existing
secrets may be reused only when their value is identical; this adapter never
updates or deletes them. An interrupted creation is safe to inspect and retry.
"""
import hmac
import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID


class InfisicalFailure(ValueError):
    """Exception messages are fixed codes, without server response bodies."""


def require(condition, code):
    if not condition:
        raise InfisicalFailure(code)


def validate_private_values(values):
    require(isinstance(values, dict), 'SERVICE_PRIVATE_VALUES_INVALID')
    for name, value in values.items():
        require(isinstance(name, str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', name),
                'SERVICE_VARIABLE_NAME_INVALID')
        require(isinstance(value, str) and 0 < len(value) <= 16384,
                'SERVICE_PRIVATE_VALUES_INVALID')
        try:
            value.encode('utf-8')
        except UnicodeError:
            raise InfisicalFailure('SERVICE_PRIVATE_VALUES_INVALID') from None
        # Keep the existing Agent / DR dotenv contract. Do not silently change
        # quoting rules that the backup verifier cannot reconstruct.
        require("'" not in value and not value.endswith('\\')
                and not any(ord(c) < 32 or ord(c) == 127 for c in value),
                'SERVICE_PRIVATE_VALUE_QUOTING_UNSUPPORTED')


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise InfisicalFailure('INFISICAL_REDIRECT_REFUSED')


class InfisicalClient:
    def __init__(self, endpoint, project_id, environment, access_token, *, opener=None):
        try:
            parts = urlsplit(endpoint)
            valid = (parts.scheme == 'https' and parts.hostname and parts.username is None
                     and parts.password is None and not parts.query and not parts.fragment
                     and parts.path in ('', '/') and (parts.port is None or 1 <= parts.port <= 65535)
                     and not any(ord(c) < 33 for c in endpoint))
            UUID(project_id)
        except (ValueError, TypeError, AttributeError):
            valid = False
        require(valid, 'SERVICE_INFISICAL_ADDRESS_REQUIRED')
        require(isinstance(environment, str) and re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', environment),
                'SERVICE_INFISICAL_ENVIRONMENT_INVALID')
        require(isinstance(access_token, str) and 0 < len(access_token) <= 16384
                and not any(ord(c) < 33 or ord(c) == 127 for c in access_token),
                'SERVICE_INFISICAL_ACCESS_REQUIRED')
        self.endpoint = endpoint.rstrip('/')
        self.project_id, self.environment = project_id, environment
        self.__token = access_token
        self.__opener = opener or build_opener(_NoRedirect())

    def __repr__(self):
        return '<InfisicalClient credentials=redacted>'

    def _request(self, method, path, *, query=None, body=None, missing=False):
        url = self.endpoint + path + ('?' + urlencode(query) if query else '')
        try:
            data = None if body is None else json.dumps(body, ensure_ascii=False).encode('utf-8')
            request = Request(url, data=data, method=method,
                              headers={'Authorization': 'Bearer ' + self.__token,
                                       'Accept': 'application/json', 'Content-Type': 'application/json'})
            with self.__opener.open(request, timeout=30) as response:
                require(200 <= response.status < 300, 'INFISICAL_API_FAILED')
                require(response.geturl() == url, 'INFISICAL_REDIRECT_REFUSED')
                raw = response.read(1024 * 1024 + 1)
            require(len(raw) <= 1024 * 1024, 'INFISICAL_RESPONSE_TOO_LARGE')
            result = json.loads(raw)
            require(isinstance(result, dict), 'INFISICAL_RESPONSE_INVALID')
            return result
        except HTTPError as error:
            status = error.code
            error.close()  # Never retain or surface an error body, URL or headers.
            if status == 404 and missing:
                return None
            code = {401: 'INFISICAL_AUTH_FAILED', 403: 'INFISICAL_PERMISSION_DENIED',
                    404: 'INFISICAL_API_VERSION_UNSUPPORTED', 409: 'INFISICAL_SECRET_CONFLICT',
                    429: 'INFISICAL_RATE_LIMITED'}.get(status, 'INFISICAL_API_FAILED')
            raise InfisicalFailure(code) from None
        except InfisicalFailure:
            raise
        except (URLError, OSError, ValueError, TypeError, UnicodeError):
            raise InfisicalFailure('INFISICAL_CONNECTION_FAILED') from None

    def _scope(self):
        return {'projectId': self.project_id, 'environment': self.environment}

    def _folder_exists(self, service):
        result = self._request('GET', '/api/v2/folders',
                               query=dict(self._scope(), path='/', recursive='false'))
        folders = result.get('folders')
        require(isinstance(folders, list) and all(isinstance(f, dict) for f in folders),
                'INFISICAL_RESPONSE_INVALID')
        matches = [f for f in folders if f.get('name') == service]
        require(len(matches) <= 1, 'INFISICAL_FOLDER_CONFLICT')
        return bool(matches)

    def _read(self, service, name):
        result = self._request('GET', '/api/v4/secrets/' + quote(name, safe=''), missing=True,
                               query=dict(self._scope(), secretPath='/' + service, type='shared',
                                          expandSecretReferences='false', includeImports='false'))
        if result is None:
            return None
        secret = result.get('secret')
        require(isinstance(secret, dict) and secret.get('secretKey') == name
                and isinstance(secret.get('secretValue'), str), 'INFISICAL_RESPONSE_INVALID')
        return secret

    def inspect(self, service, values):
        require(isinstance(service, str) and re.fullmatch(r'[a-z][a-z0-9_-]{0,62}', service),
                'SERVICE_NAME_INVALID')
        validate_private_values(values)
        exists = self._folder_exists(service)
        found = []
        for name, value in sorted(values.items()):
            current = self._read(service, name) if exists else None
            if current is not None:
                require(hmac.compare_digest(current['secretValue'].encode(), value.encode()),
                        'INFISICAL_SECRET_CONFLICT')
                found.append(name)
        return {'status': 'PASS', 'folder_exists': exists, 'existing_keys': found,
                'missing_keys': sorted(set(values) - set(found))}

    def ensure(self, service, values):
        """Recheck before writes, create missing items, then read back values.

        A failure retains created items. It never guesses whether deleting a
        secret is safe after another client or the Agent may have consumed it.
        The same exact input can be inspected and retried without overwrites.
        """
        state = self.inspect(service, values)
        if not state['folder_exists']:
            result = self._request('POST', '/api/v2/folders',
                                   body=dict(self._scope(), name=service, path='/'))
            require(isinstance(result.get('folder'), dict), 'INFISICAL_RESPONSE_INVALID')
        created = []
        for name in state['missing_keys']:
            result = self._request('POST', '/api/v4/secrets/' + quote(name, safe=''),
                                   body=dict(self._scope(), secretPath='/' + service, type='shared',
                                             secretValue=values[name], skipMultilineEncoding=True))
            require(isinstance(result.get('secret'), dict), 'INFISICAL_RESPONSE_INVALID')
            created.append(name)
        result = self.inspect(service, values)
        require(not result['missing_keys'], 'INFISICAL_READBACK_FAILED')
        return {'status': 'PASS', 'created_keys': created, 'verified_keys': sorted(values)}

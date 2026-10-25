"""Offline, value-safe planning for adding one Compose service.

This module performs no file, process, network or VM operations. Private values
are held separately from a plan and must never be passed to a report/log writer.
Classification is a suggestion until the caller explicitly selects names.
"""
from dataclasses import dataclass, field
import hashlib
import json
import re
import textwrap
from collections.abc import Mapping

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

from .service_resources import ResourceFailure, inventory as resource_inventory


NAME = re.compile(r"[a-z][a-z0-9_-]{0,62}\Z")
VARIABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@:+-]{0,511}\Z")
PRIVATE_HINT = re.compile(r"PASSWORD|PASSWD|SECRET|TOKEN|CREDENTIAL|API_?KEY|PRIVATE_?KEY|DATABASE_URL|DSN", re.I)
MAX_INPUT = 256 * 1024


class PlanFailure(ValueError):
    """The exception text is a closed code, never an input/YAML error excerpt."""


def _require(ok, code):
    if not ok:
        raise PlanFailure(code)


class _UniqueLoader(yaml.SafeLoader):
    pass


def _mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        _require(isinstance(key_node, ScalarNode) and key_node.tag == 'tag:yaml.org,2002:str',
                 'SERVICE_COMPOSE_KEY_INVALID')
        key = loader.construct_object(key_node, deep=deep)
        _require(key != '<<' and key not in result, 'SERVICE_COMPOSE_DUPLICATE_KEY')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _load(text, *, new=False):
    _require(isinstance(text, str) and 0 < len(text) <= MAX_INPUT and '\0' not in text,
             'SERVICE_COMPOSE_INVALID')
    try:
        if new:
            _require(not any(isinstance(t, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken))
                             for t in yaml.scan(text)), 'SERVICE_COMPOSE_ALIAS_UNSUPPORTED')
        value = yaml.load(text, Loader=_UniqueLoader)
        node = yaml.compose(text, Loader=_UniqueLoader)
        _require(isinstance(value, dict) and isinstance(node, MappingNode), 'SERVICE_COMPOSE_INVALID')
        return value, node
    except (yaml.YAMLError, TypeError, RecursionError):
        raise PlanFailure('SERVICE_COMPOSE_INVALID') from None


def _node_value(node, name):
    for key, value in node.value:
        if key.value == name:
            return key, value
    return None, None


def _linespan(text, node):
    """Whole assignment lines, including an inline comment, without next key."""
    start = text.rfind('\n', 0, node.start_mark.index) + 1
    end = node.end_mark.index
    if end and text[end - 1:end] == '\n':
        return start, end
    end_line = text.rfind('\n', 0, end) + 1
    if end_line > start and not text[end_line:end].strip():
        return start, end_line
    newline = text.find('\n', end)
    return start, len(text) if newline < 0 else newline + 1


def _edit(text, edits):
    for start, end, replacement in sorted(edits, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text


@dataclass(frozen=True)
class VariableCandidate:
    name: str
    source: str
    suggested_private: bool
    selected_private: bool = False
    has_value: bool = False


def _selection_names(names):
    _require(not isinstance(names, (str, bytes)), 'SERVICE_PRIVATE_SELECTION_INVALID')
    try:
        values = list(names)
    except TypeError:
        raise PlanFailure('SERVICE_PRIVATE_SELECTION_INVALID') from None
    _require(all(isinstance(name, str) and VARIABLE.fullmatch(name) for name in values),
             'SERVICE_PRIVATE_SELECTION_INVALID')
    return set(values)


class SensitiveValues(Mapping):
    """Explicitly separate credential carrier; repr/str never includes values."""
    def __init__(self, values=()):
        self.__values = dict(values)

    def __getitem__(self, key):
        return self.__values[key]

    def __iter__(self):
        return iter(self.__values)

    def __len__(self):
        return len(self.__values)

    def __repr__(self):
        return '<SensitiveValues redacted>'

    def as_dict(self):
        """Only for the credential-aware transport, never for diagnostics."""
        return self.__values.copy()


@dataclass(frozen=True, repr=False)
class ServicePlan:
    service_name: str
    image: str
    public_env_path: str
    private_env_path: str
    private_bindings: dict
    inventory: tuple
    compose_fragment: str = field(repr=False)
    public_env_text: str = field(repr=False)
    fingerprint: str
    schema: int = 1
    components: tuple = ()
    service_names: tuple = ()
    images: dict = field(default_factory=dict)
    compose_resources: dict = field(default_factory=dict, repr=False)
    resources: tuple = ()
    configuration_files: tuple = field(default=(), repr=False)

    def __repr__(self):
        return '<ServicePlan schema=' + str(self.schema) + ' contents=redacted>'

    def to_public_dict(self):
        """Value-free metadata: no Compose, env, or configuration file bytes."""
        result = {
            'schema': self.schema, 'service_name': self.service_name,
            'image': self.image, 'public_env_path': self.public_env_path,
            'private_env_path': self.private_env_path,
            'private_bindings': {name: dict(binding) for name, binding in self.private_bindings.items()},
            'variables': [dict(name=v.name, source=v.source, suggested_private=v.suggested_private,
                               selected_private=v.selected_private, has_value=v.has_value)
                          for v in self.inventory], 'fingerprint': self.fingerprint,
        }
        if self.schema == 2:
            result.update(
                service_names=list(self.service_names), images=dict(self.images),
                components=[{key: value for key, value in component.items()
                             if key not in {'compose_fragment', 'public_env_text', 'configuration_files', 'compose_resources'}}
                            for component in self.components],
                compose_resources={kind: list(definitions) for kind, definitions in self.compose_resources.items()},
                resources=[dict(resource) for resource in self.resources],
                configuration_files=[{key: value for key, value in item.items() if key != 'content'}
                                     for item in self.configuration_files])
        return result

    def deployment_payload(self):
        result = dict(self.to_public_dict(), compose_fragment=self.compose_fragment,
                      public_env_text=self.public_env_text)
        if self.schema == 2:
            result.update(components=[dict(item) for item in self.components],
                          compose_resources=dict(self.compose_resources),
                          configuration_files=[dict(item) for item in self.configuration_files])
        return result

    def render_compose(self, existing_compose_text):
        if self.schema == 2:
            return append_bundle(existing_compose_text, self.compose_fragment,
                                 self.service_names, self.compose_resources)
        return append_service(existing_compose_text, self.compose_fragment, self.service_name)


@dataclass(frozen=True, repr=False)
class ServiceAnalysis:
    plan: ServicePlan
    sensitive: SensitiveValues
    inventory: tuple

    def __repr__(self):
        return '<ServiceAnalysis contents=redacted>'


@dataclass(repr=False)
class _EnvValue:
    value: str
    start: int
    end: int
    literal: bool = False


def _env_values(text):
    _require(isinstance(text, str) and len(text) <= MAX_INPUT and '\0' not in text,
             'SERVICE_ENV_INVALID')
    result = {}
    offset = 0
    for line in text.splitlines(keepends=True):
        raw = line.rstrip('\r\n')
        stripped = raw.strip()
        if not stripped or stripped.startswith('#'):
            offset += len(line)
            continue
        match = re.fullmatch(r'\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)', raw)
        _require(match is not None, 'SERVICE_ENV_INVALID')
        key, source = match.groups()
        _require(VARIABLE.fullmatch(key) and key not in result, 'SERVICE_ENV_DUPLICATE_KEY')
        literal = False
        if source.startswith(("'", '"')):
            quote = source[0]
            out, pos = [], 1
            while pos < len(source):
                char = source[pos]
                if char == quote:
                    break
                if char == '\\' and pos + 1 < len(source):
                    following = source[pos + 1]
                    if following == quote or (quote == '"' and following in '\\nrt'):
                        out.append({'n': '\n', 'r': '\r', 't': '\t'}.get(following, following)
                                   if quote == '"' else following)
                        pos += 2
                        continue
                out.append(char)
                pos += 1
            _require(pos < len(source) and re.fullmatch(r'\s*(?:#.*)?', source[pos + 1:]) is not None,
                     'SERVICE_ENV_QUOTING_UNSUPPORTED')
            value, literal = ''.join(out), quote == "'"
        else:
            value = re.split(r'\s+#', source, maxsplit=1)[0].rstrip()
        _require('\n' not in value and '\r' not in value and len(value) <= 16384,
                 'SERVICE_ENV_MULTILINE_UNSUPPORTED')
        result[key] = _EnvValue(value, offset, offset + len(line), literal)
        offset += len(line)
    return result


def _interpolations(value):
    """Tokenize the supported Compose interpolation syntax, including $$ literal."""
    result, index = [], 0
    while index < len(value):
        if value[index] != '$':
            index += 1
            continue
        if value[index:index + 2] == '$$':
            index += 2
            continue
        start = index
        if value[index:index + 2] == '${':
            end = value.find('}', index + 2)
            _require(end >= 0, 'SERVICE_INTERPOLATION_INVALID')
            body = value[index + 2:end]
            match = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)(?:(:-|:\?|:\+|-|\?|\+)([^${}]*))?', body)
            _require(match is not None, 'SERVICE_INTERPOLATION_UNSUPPORTED')
            name, operator, default = match.groups()
            index = end + 1
        else:
            match = re.match(r'\$([A-Za-z_][A-Za-z0-9_]*)', value[index:])
            _require(match is not None, 'SERVICE_INTERPOLATION_INVALID')
            name, operator, default = match.group(1), None, None
            index += len(match.group(0))
        _require(VARIABLE.fullmatch(name), 'SERVICE_VARIABLE_NAME_INVALID')
        result.append((start, index, name, operator, default))
    return result


def _resolve(value, values):
    edits = []
    for start, end, name, operator, default in _interpolations(value):
        present, current = name in values, values.get(name, '')
        if operator == ':-':
            replacement = current if present and current else default
        elif operator == '-':
            replacement = current if present else default
        elif operator in ('+', ':+'):
            replacement = default if present and (current or operator == '+') else ''
        else:
            _require(present and (bool(current) or operator != ':?'), 'SERVICE_VARIABLE_VALUE_REQUIRED')
            replacement = current
        # Replacement is a literal value, never another round of interpolation.
        edits.append((start, end, replacement.replace('$', '$$')))
    return _edit(value, edits)


def _scalar_nodes(node):
    if isinstance(node, MappingNode):
        for key, value in node.value:
            _require('$' not in key.value, 'SERVICE_COMPOSE_KEY_INVALID')
            yield from _scalar_nodes(value)
    elif isinstance(node, SequenceNode):
        for child in node.value:
            yield from _scalar_nodes(child)
    elif isinstance(node, ScalarNode) and node.tag == 'tag:yaml.org,2002:str':
        yield node


def _source(compose_text, service_name):
    value, node = _load(compose_text, new=True)
    start = 0
    if 'services' in value:
        _require(set(value) == {'services'} and isinstance(value['services'], dict),
                 'SERVICE_COMPOSE_TOP_LEVEL_UNSUPPORTED')
        services_key, services_node = _node_value(node, 'services')
        _require(services_node.flow_style is False, 'SERVICE_COMPOSE_FLOW_UNSUPPORTED')
        line_end = compose_text.find('\n', services_key.end_mark.index)
        _require(line_end >= 0, 'SERVICE_COMPOSE_INVALID')
        start = line_end + 1
        services = value['services']
    elif 'image' in value:
        _require(bool(service_name), 'SERVICE_NAME_REQUIRED')
        _require(NAME.fullmatch(service_name), 'SERVICE_NAME_INVALID')
        wrapped = 'services:\n  ' + service_name + ':\n' + textwrap.indent(compose_text, '    ')
        return _source(wrapped, service_name)
    else:
        services, services_node = value, node
    _require(len(services) == 1 and isinstance(services_node, MappingNode), 'SERVICE_EXACTLY_ONE_REQUIRED')
    name = next(iter(services))
    _require(isinstance(name, str) and NAME.fullmatch(name) and (not service_name or name == service_name),
             'SERVICE_NAME_INVALID')
    service = services[name]
    _require(isinstance(service, dict) and isinstance(service.get('image'), str)
             and not ({'build', 'extends', 'include', 'develop'} & set(service)),
             'SERVICE_COMPOSE_FEATURE_UNSUPPORTED')
    key_node, service_node = _node_value(services_node, name)
    _require(isinstance(service_node, MappingNode) and service_node.flow_style is False,
             'SERVICE_COMPOSE_FLOW_UNSUPPORTED')
    # Keep service body bytes, its comments and blank lines. A services wrapper
    # contains no other top-level object, so its tail belongs to this fragment.
    indent = key_node.start_mark.column
    fragment = ''.join(line[min(len(line) - len(line.lstrip(' ')), indent):]
                       for line in compose_text[start:].splitlines(keepends=True))
    fragment = textwrap.indent(fragment, '  ')
    fragment = fragment.rstrip('\r\n') + '\n'
    _, root_node = _load(fragment, new=True)
    _, service_node = _node_value(root_node, name)
    return name, service, fragment, service_node


def _validate_mounts(service, name):
    _require(not ({'configs', 'secrets', 'volumes_from'} & set(service)),
             'SERVICE_EXTERNAL_CONFIGURATION_UNSUPPORTED')
    volumes = service.get('volumes', [])
    _require(isinstance(volumes, list), 'SERVICE_VOLUME_INVALID')
    # The existing DR format captures known AIO/NPM/Infisical state. Adding a
    # Compose mount does not establish a backup/restore contract for its bytes.
    # Never advertise recovery coverage for an arbitrary new persistent volume.
    # tmpfs is intentionally separate: it contains no persistent host data.
    _require(not volumes, 'SERVICE_PERSISTENT_DATA_COVERAGE_REQUIRED')


def _environment(service, service_node):
    environment = service.get('environment', {})
    _, node = _node_value(service_node, 'environment')
    result = {}
    if isinstance(environment, dict):
        for name, value in environment.items():
            _require(VARIABLE.fullmatch(name) and (value is None or type(value) in (str, int, float)),
                     'SERVICE_ENVIRONMENT_INVALID')
            key_node, value_node = _node_value(node, name)
            result[name] = (None if value is None else str(value), key_node, value_node)
    elif isinstance(environment, list):
        for item, child in zip(environment, node.value):
            _require(isinstance(item, str), 'SERVICE_ENVIRONMENT_INVALID')
            name, sep, value = item.partition('=')
            _require(VARIABLE.fullmatch(name) and name not in result, 'SERVICE_ENVIRONMENT_INVALID')
            result[name] = (value if sep else None, child, child)
    else:
        raise PlanFailure('SERVICE_ENVIRONMENT_INVALID')
    return result, node


def _inventory(compose_text, public_env_text, service_name):
    name, service, fragment, service_node = _source(compose_text, service_name)
    env = _env_values(public_env_text)
    environment, environment_node = _environment(service, service_node)
    sources = {key: 'env' for key in env}
    available = {key for key, row in env.items() if row.value is not None}
    for key, (value, _, _) in environment.items():
        sources.setdefault(key, 'compose')
        if value is not None and not _interpolations(value):
            available.add(key)
    for node in _scalar_nodes(service_node):
        for _, _, key, operator, default in _interpolations(node.value):
            sources.setdefault(key, 'interpolation')
            if operator in ('-', ':-'):
                available.add(key)
    candidates = tuple(VariableCandidate(key, source, bool(PRIVATE_HINT.search(key)),
                                         has_value=key in available)
                       for key, source in sorted(sources.items()))
    return name, service, fragment, service_node, env, environment, environment_node, candidates


def _inspect_single(compose_text, public_env_text='', service_name=''):
    """Inventory can be shown before values for required placeholders are entered."""
    return _inventory(compose_text, public_env_text, service_name)[-1]


def _analyze_single(compose_text, public_env_text='', service_name='', private_names=(), private_values=None, *, allow_resources=False):
    """Plan a new service. private_names is an explicit user choice, not a guess."""
    (name, service, fragment, service_node, env, environment, environment_node,
     candidates) = _inventory(compose_text, public_env_text, service_name)
    selected = _selection_names(private_names)
    known = {row.name for row in candidates}
    _require(all(isinstance(key, str) and VARIABLE.fullmatch(key) for key in selected)
             and selected <= known, 'SERVICE_PRIVATE_SELECTION_INVALID')
    private_values = {} if private_values is None else private_values
    _require(isinstance(private_values, dict) and set(private_values) <= selected
             and all(isinstance(v, str) and len(v) <= 16384 and '\0' not in v and '\n' not in v
                     and '\r' not in v for v in private_values.values()), 'SERVICE_PRIVATE_VALUES_INVALID')
    values = {key: row.value for key, row in env.items()}
    # Inline literals can provide values for a selected variable; definitions
    # that disagree are refused rather than selecting an accidental winner.
    for key, (value, _, _) in environment.items():
        if value is not None and not _interpolations(value):
            literal_value = value.replace('$$', '$')
            _require(key not in values or values[key] == literal_value, 'SERVICE_VARIABLE_CONFLICT')
            values.setdefault(key, literal_value)
    values.update(private_values)
    for key in selected:
        _require(key in values and bool(values[key]), 'SERVICE_PRIVATE_VALUE_REQUIRED')
        _require(not any(ord(char) < 32 or ord(char) == 127 for char in values[key])
                 and "'" not in values[key] and not values[key].endswith('\\')
                 and len(values[key]) <= 16384, 'SERVICE_PRIVATE_VALUES_INVALID')
    sensitive = SensitiveValues((key, values[key]) for key in sorted(selected))
    inventory = tuple(VariableCandidate(row.name, row.source, row.suggested_private,
                                        row.name in selected, row.name in values or row.has_value)
                      for row in candidates)
    public_values = {key: value for key, value in values.items() if key not in selected}
    edits, removed = [], []
    for key, row in env.items():
        if key not in selected and not row.literal and _interpolations(row.value):
            # The root Compose .env and a per-service env_file have distinct
            # expansion scopes. Do not accidentally inherit the Windows/VM host
            # environment. A quoted literal is supported; nested public env
            # expansion needs an explicit reviewed value in this first version.
            raise PlanFailure('SERVICE_ENV_INTERPOLATION_UNSUPPORTED')
    for key, (value, key_node, value_node) in environment.items():
        if key not in selected and value is None:
            _require(key in public_values, 'SERVICE_VARIABLE_VALUE_REQUIRED')
            replacement = public_values[key].replace('$', '$$')
            if isinstance(environment_node, SequenceNode):
                replacement = key + '=' + replacement
            encoded = json.dumps(replacement, ensure_ascii=False)
            if isinstance(environment_node, MappingNode) and fragment[value_node.start_mark.index - 1] == ':':
                encoded = ' ' + encoded
            edits.append((value_node.start_mark.index, value_node.end_mark.index,
                          encoded))
    if selected & set(environment):
        _require(environment_node.flow_style is False, 'SERVICE_ENVIRONMENT_FLOW_UNSUPPORTED')
    for key in selected & set(environment):
        _, key_node, value_node = environment[key]
        # Only a private environment assignment may reference a private source.
        # Other Compose fields cannot be satisfied by a container env_file.
        start, end = _linespan(fragment, key_node)
        if value_node.end_mark.line > key_node.start_mark.line:
            _, end = _linespan(fragment, value_node)
        removed.append((start, end))
    if environment and selected >= set(environment):
        key_node, _ = _node_value(service_node, 'environment')
        start, end = _linespan(fragment, key_node)
        removed.append((start, end))
    edits.extend((start, end, '') for start, end in removed)
    for node in _scalar_nodes(service_node):
        if any(start <= node.start_mark.index < end for start, end in removed):
            continue
        tokens = _interpolations(node.value)
        _require(not selected.intersection(t[2] for t in tokens),
                 'SERVICE_PRIVATE_INTERPOLATION_OUTSIDE_ENV')
        if tokens:
            resolved = _resolve(node.value, public_values)
            edits.append((node.start_mark.index, node.end_mark.index, json.dumps(resolved, ensure_ascii=False)))
    fragment = _edit(fragment, edits)
    public_text = _edit(public_env_text, [(row.start, row.end, '') for key, row in env.items() if key in selected])
    # Existing env_file references can only designate these two managed files.
    public_path, private_path = 'data/' + name + '/.env', '.secrets/' + name + '.env'
    files = service.get('env_file', [])
    if isinstance(files, str):
        files = [files]
    _require(isinstance(files, list) and all(isinstance(item, str) and item.removeprefix('./') in
             {public_path, private_path} for item in files), 'SERVICE_ENV_FILE_UNSUPPORTED')
    parsed, parsed_node = _load(fragment, new=True)
    _, new_node = _node_value(parsed_node, name)
    env_key, env_node = _node_value(new_node, 'env_file')
    desired_files = ['./' + public_path] + (['./' + private_path] if selected else [])
    if env_node is not None:
        spans = [_linespan(fragment, env_key)]
        if isinstance(env_node, SequenceNode) and env_node.flow_style is False:
            spans.extend(_linespan(fragment, row) for row in env_node.value)
        fragment = _edit(fragment, [(start, end, '') for start, end in set(spans)])
    if desired_files:
        fragment = fragment.rstrip('\r\n') + '\n    env_file:\n' + ''.join(
            '      - ' + json.dumps(path) + '\n' for path in desired_files)
    output, _ = _load(fragment, new=True)
    actual = output[name]
    if not allow_resources:
        _validate_mounts(actual, name)
    image = actual['image'].replace('$$', '$')
    _require(IMAGE.fullmatch(image) and '$' not in image, 'SERVICE_IMAGE_INVALID')
    if '@' in image:
        _require(re.fullmatch(r'.+@(?:sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})', image),
                 'SERVICE_IMAGE_INVALID')
    # A selected value repeated in a comment or unrelated field is not silently
    # published. Long known values are checked byte-for-byte outside their source.
    for value in sensitive.values():
        _require(len(value) < 4 or not any(value in text for text in (fragment, public_text, image)),
                 'SERVICE_PRIVATE_VALUE_OUTSIDE_ENV')
    bindings = {key: {'folder': '/' + name, 'key': key} for key in sorted(selected)}
    digest = hashlib.sha256(json.dumps(dict(schema=1, service_name=name, compose_fragment=fragment,
        public_env_text=public_text, private_bindings=bindings), sort_keys=True, ensure_ascii=False,
        separators=(',', ':')).encode()).hexdigest()
    plan = ServicePlan(name, image, public_path, private_path, bindings, inventory,
                       fragment, public_text, digest)
    return ServiceAnalysis(plan, sensitive, inventory)


def append_service(existing_compose_text, compose_fragment, service_name):
    """Append one service without round-tripping any existing Compose bytes."""
    _require(isinstance(service_name, str) and NAME.fullmatch(service_name), 'SERVICE_NAME_INVALID')
    addition, _ = _load(compose_fragment, new=True)
    _require(set(addition) == {service_name}, 'SERVICE_EXACTLY_ONE_REQUIRED')
    existing, root_node = _load(existing_compose_text)
    _require(isinstance(existing.get('services'), dict), 'SERVICE_EXISTING_COMPOSE_INVALID')
    if service_name in existing['services']:
        _require(existing['services'][service_name] == addition[service_name], 'SERVICE_ALREADY_EXISTS')
        return existing_compose_text
    _, services_node = _node_value(root_node, 'services')
    _require(isinstance(services_node, MappingNode) and services_node.flow_style is False,
             'SERVICE_EXISTING_COMPOSE_UNSUPPORTED')
    indent = services_node.value[0][0].start_mark.column if services_node.value else 2
    body = textwrap.indent(textwrap.dedent(compose_fragment), ' ' * indent)
    position = services_node.end_mark.index
    position = existing_compose_text.rfind('\n', 0, position) + 1 if position < len(existing_compose_text) else position
    prefix, suffix = existing_compose_text[:position], existing_compose_text[position:]
    newline = '\r\n' if '\r\n' in existing_compose_text else '\n'
    body = body.replace('\r\n', '\n').replace('\n', newline)
    result = prefix + ('' if prefix.endswith(('\n', '\r')) else newline) + newline + body + suffix
    check, _ = _load(result)
    _require(check['services'].get(service_name) == addition[service_name], 'SERVICE_APPEND_INVALID')
    _require(all(check['services'].get(key) == value for key, value in existing['services'].items())
             and {k: v for k, v in check.items() if k != 'services'} ==
                 {k: v for k, v in existing.items() if k != 'services'}, 'SERVICE_APPEND_INVALID')
    return result


def _bundle_document(compose_text, service_name=''):
    value, _ = _load(compose_text, new=True)
    if 'services' in value:
        _require(set(value) <= {'services', 'volumes', 'networks', 'configs', 'version'}
                 and isinstance(value['services'], dict), 'SERVICE_COMPOSE_TOP_LEVEL_UNSUPPORTED')
        services = value['services']
        top = {key: value[key] for key in ('volumes', 'networks', 'configs') if key in value}
    elif 'image' in value:
        _require(bool(service_name), 'SERVICE_NAME_REQUIRED')
        _require(isinstance(service_name, str) and NAME.fullmatch(service_name), 'SERVICE_NAME_INVALID')
        services, top = {service_name: value}, {}
    else:
        services, top = value, {}
    _require(bool(services) and len(services) <= 64 and all(isinstance(name, str) and NAME.fullmatch(name)
             and isinstance(service, dict) for name, service in services.items()), 'SERVICE_NAME_INVALID')
    _require(not service_name or service_name in services, 'SERVICE_NAME_INVALID')
    for name, service in services.items():
        _require(isinstance(service.get('image'), str)
                 and not ({'build', 'extends', 'include', 'develop'} & set(service)),
                 'SERVICE_COMPOSE_FEATURE_UNSUPPORTED')
    primary = service_name or next(iter(services))
    return services, top, primary


def _snippet(name, service):
    return yaml.safe_dump({name: service}, sort_keys=False, allow_unicode=True, width=4096)


def _component_env(public_env_text, service, primary=False):
    """A bundle env supplies interpolation values, not unrelated secrets to peers."""
    values = _env_values(public_env_text)
    _, node = _load(_snippet('component', service), new=True)
    _, service_node = _node_value(node, 'component')
    environment, _ = _environment(service, service_node)
    required = set(environment)
    for scalar in _scalar_nodes(service_node):
        required.update(token[2] for token in _interpolations(scalar.value))
    # Unreferenced explicit env assignments retain the legacy behavior on the
    # selected primary service. Peers only receive variables they reference.
    selected = set(values) if primary else required & set(values)
    return _edit(public_env_text, [(row.start, row.end, '') for key, row in values.items() if key not in selected])


def _bundle_candidates(services, public_env_text, primary):
    records = []
    multiple = len(services) > 1
    for name, service in services.items():
        env = _component_env(public_env_text, service, primary=name == primary) if multiple else public_env_text
        candidates = _inspect_single(_snippet(name, service), env, name)
        records.append((name, service, env, candidates))
    counts = {}
    for _, _, _, candidates in records:
        for row in candidates:
            counts[row.name] = counts.get(row.name, 0) + 1
    used, maps = set(), {}
    for name, _, _, candidates in records:
        mapping = {}
        for row in candidates:
            candidate = row.name if counts[row.name] == 1 else name.replace('-', '_').upper() + '__' + row.name
            # A pre-existing env key can coincide with a generated identifier.
            if candidate in used or (candidate != row.name and candidate in counts):
                candidate = name.replace('-', '_').upper() + '__' + hashlib.sha256(name.encode()).hexdigest()[:8] + '__' + row.name
            if len(candidate) > 128:
                candidate = candidate[:108] + '__' + hashlib.sha256((name + ':' + row.name).encode()).hexdigest()[:16]
            _require(VARIABLE.fullmatch(candidate), 'SERVICE_VARIABLE_NAME_INVALID')
            _require(candidate not in used, 'SERVICE_VARIABLE_NAME_INVALID')
            used.add(candidate)
            mapping[row.name] = candidate
        maps[name] = mapping
    return records, maps


def _resolve_resource_values(value, values):
    if isinstance(value, str):
        return _resolve(value, values) if _interpolations(value) else value
    if isinstance(value, dict):
        return {key: _resolve_resource_values(item, values) for key, item in value.items()}
    if isinstance(value, list):
        return [_resolve_resource_values(item, values) for item in value]
    return value


def inspect_resources(compose_text, public_env_text='', service_name='', configuration_files=(), storage_policies=()):
    """Inventory mounts without requesting missing private environment values."""
    services, top, _ = _bundle_document(compose_text, service_name)
    values = {key: row.value for key, row in _env_values(public_env_text).items()}
    inspected = {name: dict(service) for name, service in services.items()}
    for service in inspected.values():
        for key in ('volumes', 'configs', 'tmpfs'):
            if key in service:
                service[key] = _resolve_resource_values(service[key], values)
    try:
        return resource_inventory(inspected, _resolve_resource_values(top, values),
                                  configuration_files, storage_policies)['resources']
    except ResourceFailure as error:
        raise PlanFailure(str(error)) from None


def inspect_inputs(compose_text, public_env_text='', service_name='', configuration_files=(), storage_policies=()):
    services, top, primary = _bundle_document(compose_text, service_name)
    if len(services) == 1 and not top and not configuration_files and not storage_policies:
        return _inspect_single(compose_text, public_env_text, service_name)
    records, names = _bundle_candidates(services, public_env_text, primary)
    return tuple(VariableCandidate(names[name][row.name], name + ' · ' + row.name + ' (' + row.source + ')',
                                   row.suggested_private, row.selected_private, row.has_value)
                 for name, _, _, candidates in records for row in candidates)


def analyze_inputs(compose_text, public_env_text='', service_name='', private_names=(), private_values=None,
                   configuration_files=(), storage_policies=()):
    services, top, primary = _bundle_document(compose_text, service_name)
    document, _ = _load(compose_text, new=True)
    extended = 'version' in document or len(services) > 1 or bool(top) or bool(configuration_files) or bool(storage_policies) or any(
        service.get('volumes') or service.get('configs') for service in services.values())
    if not extended:
        return _analyze_single(compose_text, public_env_text, service_name, private_names, private_values)
    records, value_names = _bundle_candidates(services, public_env_text, primary)
    known = {global_name for mapping in value_names.values() for global_name in mapping.values()}
    selected = _selection_names(private_names)
    _require(selected <= known and all(isinstance(name, str) for name in selected), 'SERVICE_PRIVATE_SELECTION_INVALID')
    private_values = {} if private_values is None else private_values
    _require(isinstance(private_values, dict) and set(private_values) <= selected, 'SERVICE_PRIVATE_VALUES_INVALID')
    children, sensitive, inventory, bindings = {}, {}, [], {}
    for name, service, env, candidates in records:
        mapping = value_names[name]
        child_private = [key for key, global_name in mapping.items() if global_name in selected]
        child_values = {key: private_values[global_name] for key, global_name in mapping.items() if global_name in private_values}
        child = _analyze_single(_snippet(name, service), env, name, child_private, child_values, allow_resources=True)
        children[name] = child
        for row in child.inventory:
            global_name = mapping[row.name]
            inventory.append(VariableCandidate(global_name, name + ' · ' + row.name + ' (' + row.source + ')',
                                                row.suggested_private, row.selected_private, row.has_value))
            if row.selected_private:
                sensitive[global_name] = child.sensitive[row.name]
                bindings[global_name] = dict(child.plan.private_bindings[row.name])
    public_values = {key: row.value for key, row in _env_values(public_env_text).items()}
    for name, mapping in value_names.items():
        for key, global_name in mapping.items():
            if global_name in selected:
                public_values.pop(key, None)
    selected_keys = {key for mapping in value_names.values() for key, global_name in mapping.items()
                     if global_name in selected}
    if top:
        _, top_node = _load(yaml.safe_dump(top, sort_keys=False), new=True)
        _require(not any(selected_keys.intersection(token[2] for token in _interpolations(node.value))
                         for node in _scalar_nodes(top_node)), 'SERVICE_PRIVATE_INTERPOLATION_OUTSIDE_ENV')
    resolved_top = _resolve_resource_values(top, public_values)
    resolved_services = {name: _load(child.plan.compose_fragment, new=True)[0][name] for name, child in children.items()}
    try:
        resource_plan = resource_inventory(resolved_services, resolved_top, configuration_files, storage_policies)
    except ResourceFailure as error:
        raise PlanFailure(str(error)) from None
    components = []
    for name, child in children.items():
        component = child.plan.deployment_payload()
        component['compose_fragment'] = textwrap.indent(_snippet(name, resource_plan['services'][name]), '  ')
        component['value_names'] = dict(value_names[name])
        component['fingerprint'] = hashlib.sha256(json.dumps(dict(schema=1, service_name=name,
            compose_fragment=component['compose_fragment'], public_env_text=component['public_env_text'],
            private_bindings=component['private_bindings']), sort_keys=True, ensure_ascii=False,
            separators=(',', ':')).encode()).hexdigest()
        components.append(component)
    fragment = ''.join(component['compose_fragment'] for component in components)
    public_strings = [fragment, *(component['public_env_text'] for component in components)]
    public_strings.extend(_strings_in(resource_plan['services']))
    public_strings.extend(_strings_in(resource_plan['compose_resources']))
    public_strings.extend(item['content'] for item in resource_plan['configuration_files'])
    for value in sensitive.values():
        _require(len(value) < 4 or not any(value in text or value in text.replace('$$', '$')
                                         for text in public_strings), 'SERVICE_PRIVATE_VALUE_OUTSIDE_ENV')
    core = dict(schema=2, service_name=primary, service_names=list(services), components=components,
                compose_resources=resource_plan['compose_resources'], resources=resource_plan['resources'],
                configuration_files=resource_plan['configuration_files'], private_bindings=bindings)
    fingerprint = hashlib.sha256(json.dumps(core, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
    chosen = children[primary].plan
    images = {name: child.plan.image for name, child in children.items()}
    plan = ServicePlan(primary, chosen.image, chosen.public_env_path, chosen.private_env_path, bindings,
                       tuple(inventory), fragment, chosen.public_env_text, fingerprint, schema=2,
                       components=tuple(components), service_names=tuple(services), images=images,
                       compose_resources=resource_plan['compose_resources'], resources=resource_plan['resources'],
                       configuration_files=resource_plan['configuration_files'])
    return ServiceAnalysis(plan, SensitiveValues(sensitive), tuple(inventory))



def _strings_in(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _strings_in(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _strings_in(child)


def _mapping_addition(text, node, entries, newline):
    """Build a local edit; existing entries and their comments retain bytes."""
    empty = isinstance(node, ScalarNode) and node.tag == 'tag:yaml.org,2002:null'
    _require(empty or isinstance(node, MappingNode), 'SERVICE_EXISTING_COMPOSE_UNSUPPORTED')
    indent = node.value[0][0].start_mark.column if isinstance(node, MappingNode) and node.value else 2
    body = textwrap.indent(yaml.safe_dump(entries, sort_keys=False, allow_unicode=True, width=4096),
                           ' ' * indent).replace('\n', newline)
    if empty or node.flow_style:
        _require(empty or not node.value, 'SERVICE_EXISTING_COMPOSE_UNSUPPORTED')
        return node.start_mark.index, node.end_mark.index, newline + body
    position = node.end_mark.index
    position = text.rfind('\n', 0, position) + 1 if position < len(text) else position
    prefix = '' if text[:position].endswith(('\n', '\r')) else newline
    return position, position, prefix + newline + body

def append_bundle(existing_compose_text, compose_fragment, service_names, compose_resources):
    """Merge only new service/resource blocks; preserve unrelated existing bytes."""
    additions, _ = _load(compose_fragment, new=True)
    _require(set(additions) == set(service_names), 'SERVICE_BUNDLE_INVALID')
    existing, root_node = _load(existing_compose_text)
    _require(isinstance(existing.get('services'), dict), 'SERVICE_EXISTING_COMPOSE_INVALID')
    expected = dict(existing)
    expected['services'] = dict(existing['services'])
    edits = []
    newline = '\r\n' if '\r\n' in existing_compose_text else '\n'
    new_services = {}
    for name, service in additions.items():
        _require(name not in existing['services'] or existing['services'][name] == service, 'SERVICE_ALREADY_EXISTS')
        if name not in existing['services']:
            new_services[name] = service
        expected['services'][name] = service
    if new_services:
        _, node = _node_value(root_node, 'services')
        edits.append(_mapping_addition(existing_compose_text, node, new_services, newline))
    tail = ''
    for kind, definitions in compose_resources.items():
        _require(kind in {'volumes', 'networks', 'configs'} and isinstance(definitions, dict), 'SERVICE_COMPOSE_RESOURCE_INVALID')
        current = existing.get(kind, {})
        _require(current is None or isinstance(current, dict), 'SERVICE_EXISTING_COMPOSE_UNSUPPORTED')
        current = current or {}
        missing = {}
        for name, definition in definitions.items():
            _require(name not in current or (current[name] or {}) == (definition or {}), 'SERVICE_COMPOSE_RESOURCE_CONFLICT')
            if name not in current:
                missing[name] = definition
        if not missing:
            continue
        expected[kind] = dict(current, **missing)
        if kind not in existing:
            tail += newline + yaml.safe_dump({kind: missing}, sort_keys=False, allow_unicode=True, width=4096).replace('\n', newline)
        else:
            _, node = _node_value(root_node, kind)
            edits.append(_mapping_addition(existing_compose_text, node, missing, newline))
    result = _edit(existing_compose_text, edits)
    if tail:
        result += ('' if result.endswith(('\n', '\r')) else newline) + tail
    actual, _ = _load(result)
    _require(actual == expected, 'SERVICE_APPEND_INVALID')
    return result

"""Public-domain recovery gates, without making DNS or router changes.

The caller holds recovery.lock and has validated the full Compose ownership.
NPM's DNS-01 reissue restores its genuine routes before CometNet's startup.
The temporary nonce is read from Comet's gluetun network namespace, using TLS
verification and normal DNS, to prove the public domain reaches the replacement.
"""
import ipaddress
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
from urllib.parse import urlsplit

ERROR_CODES = frozenset({
    'OPERATIONAL_DEPLOYMENT_REFUSED', 'OPERATIONAL_PROFILE_TRANSACTION_FAILED',
    'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED', 'PUBLIC_DOMAIN_TARGET_MISMATCH',
    'PUBLIC_DOMAIN_PROBE_FAILED', 'PUBLIC_DOMAIN_PROBE_CLEANUP_REQUIRED',
    'PUBLIC_CONTROLLER_CUTOVER_REQUIRED', 'OPERATIONAL_TLS_REQUIRED',
})
CONTROLLERS = frozenset({'cloudflare-ddns', 'watchtower', 'wud', 'deunhealth'})
TLS_CODES = frozenset('TLS_NPM_' + phase + '_FAILED' for phase in (
    'DNS01_ISSUANCE', 'CERTIFICATE', 'ACCESS_LISTS_REBUILD', 'NGINX_GENERATE',
    'NGINX_TEST', 'NGINX_RELOAD', 'TLS_LOOPBACK', 'HTTPS_UPSTREAM'))


def nonce_probe_code(multiple=False):
    """Await an asynchronous Nginx reload without weakening origin evidence.

    Each attempt uses normal DNS, a new verified TLS connection, and the exact
    nonce. A wrong certificate fails immediately. Other transient failures or
    an old configuration can retry for ten seconds; an independent watchdog
    bounds slow DNS or worker shutdown as well. The caller always removes the
    NPM marker after this child exits, including a deadline failure.
    """
    require(type(multiple) is bool, 'PUBLIC_DOMAIN_PROBE_FAILED')
    common = '''import concurrent.futures,http.client,json,os,ssl,sys,threading,time
def check(host,nonce,deadline):
    expected=nonce.encode()
    context=ssl.create_default_context()
    while True:
        remaining=deadline-time.monotonic()
        if remaining<=0:
            return False
        connection=None
        try:
            connection=http.client.HTTPSConnection(host,443,timeout=min(3,remaining),context=context)
            connection.request('GET','/.well-known/streams-aio-recovery/'+nonce)
            response=connection.getresponse()
            matched=response.status==200 and response.read(len(expected)+1)==expected
            if matched:
                return time.monotonic()<deadline
        except ssl.SSLCertVerificationError:
            return False
        except (OSError,http.client.HTTPException):
            pass
        finally:
            if connection is not None:
                connection.close()
        remaining=deadline-time.monotonic()
        if remaining<=0:
            return False
        time.sleep(min(0.5,remaining))
deadline=time.monotonic()+10
watchdog=threading.Timer(11,lambda:os._exit(1))
watchdog.daemon=True
watchdog.start()
try:
'''
    if multiple:
        body = '''    items=json.loads(sys.argv[1]); nonce=sys.argv[2]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        ok=all(pool.map(lambda item:check(item['hostname'],nonce,deadline),items))
'''
    else:
        body = '''    host=sys.argv[1]; nonce=sys.argv[2]
    ok=check(host,nonce,deadline)
'''
    return common + body + '''    raise SystemExit(0 if ok else 1)
finally:
    watchdog.cancel()
'''


def require(ok, code):
    if not ok:
        raise ValueError(code)


def deployment(state, cutover=False):
    record = state.get('operational_deployment')
    require(isinstance(record, dict) and record.get('routing_mode') in ('parallel_test', 'production_recovery')
            and type(cutover) is bool, 'OPERATIONAL_DEPLOYMENT_REFUSED')
    require(not cutover or record['routing_mode'] == 'production_recovery',
            'PUBLIC_CONTROLLER_CUTOVER_REQUIRED')
    # Public controllers can update DNS or replace running images. They are
    # enabled only for an explicitly selected production recovery/cutover.
    if record['routing_mode'] == 'production_recovery':
        require(cutover, 'PUBLIC_CONTROLLER_CUTOVER_REQUIRED')
    try:
        address = ipaddress.ip_address(record.get('domain_target_address'))
    except (TypeError, ValueError):
        raise ValueError('OPERATIONAL_DEPLOYMENT_REFUSED') from None
    require(not address.is_unspecified and not address.is_multicast,
            'OPERATIONAL_DEPLOYMENT_REFUSED')
    return set() if cutover else set(CONTROLLERS)


def cometnet_endpoint(model):
    service = model.get('services', {}).get('cometnet', {})
    environment = service.get('environment', {})
    require(isinstance(environment, dict), 'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')
    value = environment.get('COMETNET_ADVERTISE_URL', '')
    flags = [environment.get(key, 'false') for key in
             ('COMETNET_SKIP_REACHABILITY_CHECK', 'COMETNET_SKIP_TIME_CHECK')]
    require(isinstance(value, str) and not re.search(r'\s', value)
            and all(isinstance(flag, str) and flag.lower() in ('false', '0') for flag in flags),
            'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')
    try:
        endpoint = urlsplit(value)
        port = endpoint.port
    except (ValueError, TypeError):
        raise ValueError('PUBLIC_DOMAIN_CONFIGURATION_REQUIRED') from None
    require(endpoint.scheme == 'wss' and endpoint.hostname and port in (None, 443)
            and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', endpoint.hostname)
            and '.' in endpoint.hostname and not endpoint.username and not endpoint.password
            and not endpoint.query and not endpoint.fragment
            and environment.get('COMETNET_NETWORK_ID') != 'streams-aio-dr-local'
            and environment.get('COMETNET_KEYS_DIR') != '/tmp/streams-aio-cometnet-trial/keys'
            and service.get('network_mode') == 'service:gluetun'
            and model['services'].get('comet', {}).get('network_mode') == 'service:gluetun',
            'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')
    return endpoint.hostname


def selected_container(root, model, service, run):
    ids = run(['docker', 'compose', '--profile', 'all', 'ps', '-aq', service]).decode().split()
    require(len(ids) == 1 and re.fullmatch(r'[0-9a-f]{12,64}', ids[0]), 'PUBLIC_DOMAIN_PROBE_FAILED')
    rows = json.loads(run(['docker', 'inspect', ids[0]]))
    require(isinstance(rows, list) and len(rows) == 1, 'PUBLIC_DOMAIN_PROBE_FAILED')
    row = rows[0]; labels = row.get('Config', {}).get('Labels') or {}
    require(labels.get('com.docker.compose.project.working_dir') == str(root)
            and labels.get('com.docker.compose.project') == model.get('name') == 'streams-aio'
            and labels.get('com.docker.compose.service') == service
            and row.get('Config', {}).get('Image') == model['services'][service]['image']
            and row.get('State', {}).get('Running') is True, 'PUBLIC_DOMAIN_PROBE_FAILED')
    if service == 'npm':
        mounts = {entry.get('Destination'): entry for entry in row.get('Mounts', [])}
        for destination, source in (('/data', root/'data/npm/data'),
                                    ('/etc/letsencrypt', root/'data/npm/data/letsencrypt')):
            require(mounts.get(destination, {}).get('Type') == 'bind'
                    and mounts[destination].get('Source') == str(source), 'PUBLIC_DOMAIN_PROBE_FAILED')
    return ids[0]


def private_run(args, root, payload):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('COMPOSE_', 'INFISICAL_', 'PYTHON'))
           and key not in {'GH_TOKEN', 'GITHUB_TOKEN'}}
    result = subprocess.run(args, cwd=root, env=env, input=payload, capture_output=True, timeout=90)
    require(result.returncode == 0, 'PUBLIC_DOMAIN_PROBE_FAILED')
    return result.stdout


def npm_action(root, run, action):
    require(action in ('reissue', 'verify'), 'PUBLIC_DOMAIN_PROBE_FAILED')
    try:
        run([sys.executable, '-B', Path(__file__).with_name('npm_runtime.py'), action, '--target', root])
    except Exception as error:
        code = (error.args[0] if isinstance(error, ValueError) and len(error.args) == 1
                and isinstance(error.args[0], str) else None)
        raise ValueError(code if code in TLS_CODES else 'TLS_VERIFICATION_FAILED') from None


def verify_public_target(root, model, run, send=None):
    """Probe through the exact runtime namespace; a valid original is refused."""
    root = Path(root); send = send or private_run
    hostname = cometnet_endpoint(model)
    npm = selected_container(root, model, 'npm', run)
    comet = selected_container(root, model, 'comet', run)
    helper = Path(__file__).with_name('npm-domain-probe.mjs').read_text()
    nonce = secrets.token_hex(24)
    args = ['docker', 'exec', '-i', '--user', '0', '--workdir', '/app', npm,
            'node', '--input-type=module', '-e', helper]
    gluetun = model['services'].get('gluetun', {})
    forward_hosts = {'gluetun'}
    if isinstance(gluetun.get('container_name'), str):
        forward_hosts.add(gluetun['container_name'])
    networks = gluetun.get('networks', {})
    require(isinstance(networks, dict), 'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')
    for network in networks.values():
        if isinstance(network, dict):
            forward_hosts.update(value for key, value in network.items()
                                 if key in ('ipv4_address', 'ipv6_address') and isinstance(value, str))
    def marker(action):
        result = json.loads(send(args, root, json.dumps(dict(action=action, hostname=hostname,
                    nonce=nonce, forward_hosts=sorted(forward_hosts), forward_port=8765)).encode()))
        require(result == {'status': 'PASS'}, 'PUBLIC_DOMAIN_PROBE_FAILED')
    # HTTPS validates both the certificate and the ephemeral response body.
    # No redirects, custom resolver, --insecure, proxy environment or logs.
    probe = nonce_probe_code()
    installed = False
    try:
        # Install may have written before failing: cleanup runs even then.
        installed = True
        marker('install')
        try:
            run(['docker', 'exec', comet, 'python', '-c', probe, hostname, nonce])
        except Exception:
            raise ValueError('PUBLIC_DOMAIN_TARGET_MISMATCH') from None
    finally:
        if installed:
            try:
                marker('remove')
            except Exception:
                raise ValueError('PUBLIC_DOMAIN_PROBE_CLEANUP_REQUIRED') from None


def topology_targets(root, state):
    """Private source bindings and the applied replacement rows must agree."""
    require(state.get('aio_recovery') == 'NATIVE_SNAPSHOT_RESTORED'
            and isinstance((state.get('aio_snapshot') or {}).get('deployment'),dict),
            'NPM_TOPOLOGY_BACKUP_REQUIRED')
    spec = importlib.util.spec_from_file_location('operational_npm_topology',
                Path(__file__).with_name('npm_topology.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    path = Path(root)/'.generated/npm-deployment.json'
    require(path.is_file(),'NPM_TOPOLOGY_BACKUP_REQUIRED')
    path = module.checked(path,private=True)
    value = json.loads(path.read_bytes())
    module.validate(value, stack_commit=state.get('public_commit'))
    evidence = state.get('npm_topology')
    saved = module.verify(root, evidence, stack_commit=state.get('public_commit'))
    require(saved['targets'] == state.get('npm_upstream_targets'), 'NPM_TOPOLOGY_EVIDENCE_REQUIRED')
    require(module.fingerprint(value) == evidence['topology_sha256'], 'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')
    require(saved == dict(module.planned(value, saved['targets']), phase='complete'),
            'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')
    local = {(item['table'], item['id']) for item in value['bindings'] if item['role'] != 'external'}
    selected = [dict(id=row['id'], routing=row['routing']) for row in saved['after']
                if row['table'] == 'proxy_host' and ('proxy_host', row['id']) in local]
    return module, value, saved, selected


def verify_all_public_targets(root, model, run, state, send=None):
    """Normal TLS/DNS plus temporary response proof for every local TLS host.

    The NPM restore tool checks certificate and HTTP status. This separate
    proof prevents a working original host from satisfying that check and
    proves the exact replacement routes, including remapped LAN upstreams.
    """
    root = Path(root); send = send or private_run
    module, deployment_value, saved, routes = topology_targets(root, state)
    hostname = cometnet_endpoint(model)
    candidates = [row for row in routes if hostname in row['routing']['domain_names']]
    require(len(candidates) == 1, 'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')
    candidate = candidates[0]
    bindings = [item for item in deployment_value['bindings'] if item['table'] == 'proxy_host'
                and item['id'] == candidate['id'] and item['path'] == ['forward_host']]
    require(len(bindings) == 1 and bindings[0]['role'] in ('stack', 'compose')
            and bindings[0]['service'] == 'gluetun'
            and candidate['routing']['forward_port'] == 8765
            and candidate['routing']['forward_scheme'] == 'http',
            'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')
    npm = selected_container(root, model, 'npm', run)
    comet = selected_container(root, model, 'comet', run)
    helper = Path(__file__).with_name('npm-route-probe.mjs').read_text()
    nonce = secrets.token_hex(24)
    args = ['docker', 'exec', '-i', '--user', '0', '--workdir', '/app', npm,
            'node', '--input-type=module', '-e', helper]
    def marker(action):
        payload = dict(action=action, nonce=nonce, routes=routes,
                       cometnet_id=candidate['id'], cometnet_hostname=hostname)
        try:
            response = json.loads(send(args, root, json.dumps(payload).encode()))
        except Exception:
            raise ValueError('PUBLIC_DOMAIN_PROBE_FAILED') from None
        require(isinstance(response, dict) and response.get('status') == 'PASS', 'PUBLIC_DOMAIN_PROBE_FAILED')
        if action == 'remove':
            require(response == {'status': 'PASS'}, 'PUBLIC_DOMAIN_PROBE_FAILED')
            return response
        require(set(response) == {'status', 'probes', 'hosts', 'skipped_disabled', 'skipped_http'}
                and isinstance(response['probes'], list) and response['probes']
                and len(response['probes']) <= 16384
                and all(type(response[key]) is int and 0 <= response[key] <= len(routes)
                        for key in ('hosts', 'skipped_disabled', 'skipped_http'))
                and response['hosts'] > 0
                and response['hosts'] + response['skipped_disabled'] + response['skipped_http'] == len(routes),
                'PUBLIC_DOMAIN_PROBE_FAILED')
        expected = {(row['id'], domain) for row in routes for domain in row['routing']['domain_names']}
        actual = set()
        for item in response['probes']:
            require(isinstance(item, dict) and set(item) == {'id', 'hostname'}
                    and type(item['id']) is int and isinstance(item['hostname'], str)
                    and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', item['hostname'])
                    and '.' in item['hostname'] and (item['id'], item['hostname']) in expected
                    and (item['id'], item['hostname']) not in actual, 'PUBLIC_DOMAIN_PROBE_FAILED')
            actual.add((item['id'], item['hostname']))
        require((candidate['id'], hostname) in actual and len({item[0] for item in actual}) == response['hosts'],
                'PUBLIC_DOMAIN_PROBE_FAILED')
        active_ids = {item[0] for item in actual}
        require(actual == {(row['id'], domain) for row in routes if row['id'] in active_ids
                           for domain in row['routing']['domain_names']}, 'PUBLIC_DOMAIN_PROBE_FAILED')
        return response
    # Same strict bounded reload wait for every declared hostname. No proxy
    # environment, resolver override, redirect, insecure TLS or response log.
    probe = nonce_probe_code(multiple=True)
    installed = False
    try:
        installed = True
        response = marker('install')
        try:
            run(['docker', 'exec', comet, 'python', '-c', probe,
                 json.dumps(response['probes'], separators=(',', ':')), nonce])
        except Exception:
            raise ValueError('PUBLIC_DOMAIN_TARGET_MISMATCH') from None
    finally:
        if installed:
            try:
                marker('remove')
            except Exception:
                raise ValueError('PUBLIC_DOMAIN_PROBE_CLEANUP_REQUIRED') from None
    # Refuse any unrelated routing drift during the NPM-side temporary proof.
    module.verify(root, state.get('npm_topology'), stack_commit=state.get('public_commit'))
    return dict(hosts=response['hosts'], domains=len(response['probes']),
                skipped_disabled=response['skipped_disabled'], skipped_http=response['skipped_http'])


def before_cometnet(root, model, run, emit, save, state, state_path):
    """Certificates/routes must exist before CometNet's own WSS self-check."""
    emit('TLS', 'RUNNING')
    npm_action(root, run, 'reissue')
    emit('TLS')
    emit('PUBLIC_DOMAINS', 'RUNNING')
    state['public_domain_checks'] = verify_all_public_targets(root, model, run, state)
    state['public_domain_recovery'] = 'TARGET_VERIFIED'
    save(state_path, state)
    emit('PUBLIC_DOMAINS')

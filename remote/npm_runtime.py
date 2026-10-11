"""Run the pinned native NPM recovery with NPM's backend environment.

Docker exec does not inherit CERTBOT_VERSION exported by the backend shell.
The known NPM 2.16.0 helper must source common.sh before invoking Certbot's
Cloudflare plugin. Keep the backup's tracked scripts, native lock, validation,
journal and issuance policy intact; adapt only that exact child invocation.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import stat
import types

SOURCE_HASHES = {
    'scripts/dr.py': 'e20a65c8273c5a16eb55adce8cfbc9f51d9971cea43f1731a2caec935519b059',
    'scripts/npm-dr.py': 'de7e8c4d14f88792f8cb32b211724d3e8306386ce358a4e8ef243e1d3211d7f5',
    'scripts/npm-dr-helper.mjs': 'ec87d93bfa7c2c719047a8a728de5bb7a30022fecbd904d02437d97a9023b8bf',
}
NPM_RUNTIME = '. /usr/bin/common.sh; export HOME="$NPMHOME"; exec node --input-type=module -e "$1"'


def require(ok):
    if not ok:
        raise ValueError('TLS_VERIFICATION_FAILED')


def checked_sources(root):
    root = Path(root).absolute()
    require(not any(path.is_symlink() for path in (root, *root.parents)))
    output = {}
    for relative, expected in SOURCE_HASHES.items():
        path = root/relative
        require(not any(p.is_symlink() for p in (path, *path.parents)) and path.is_file())
        raw = path.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == expected)
        output[relative] = raw.decode('utf-8')
    return root, output


def backend_command(args, helper):
    """Adapt only the verified helper; no interpolation of private input."""
    if list(args[:2]) != ['docker', 'exec']:
        return args
    require(len(args) == 12 and list(args[:7]) == ['docker','exec','-i','--user','0','--workdir','/app']
            and isinstance(args[7], str) and re.fullmatch(r'[0-9a-f]{12,64}', args[7])
            and list(args[8:11]) == ['node','--input-type=module','-e'] and args[11] == helper)
    return [*args[:8], 'bash', '-c', NPM_RUNTIME, 'streams-aio-npm-recovery', helper]


def external_targets(root, state_home):
    """Only a fully verified backup binding can classify an external route."""
    path = Path(state_home).absolute()/'state.json'
    require(not any(p.is_symlink() for p in (path, *path.parents)))
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 1024**2)
    state = json.loads(path.read_bytes())
    require(state.get('target') == str(root) and state.get('preparation') == 'PASS'
            and state.get('application_start_attempted') is True
            and isinstance(state.get('operational_deployment'), dict))
    spec = importlib.util.spec_from_file_location('npm_runtime_policy',Path(__file__).with_name('operational_profile.py'))
    policy = importlib.util.module_from_spec(spec); spec.loader.exec_module(policy)
    _, value, _, local = policy.topology_targets(root,state)
    require(bool(local))
    return external_route_ids(value)


def external_route_ids(value):
    selected = []
    for route in value['routes']:
        if route['table'] != 'proxy_host':
            continue
        bindings = [item for item in value['bindings'] if item['table'] == route['table'] and item['id'] == route['id']]
        # A route with any recovered service/location remains mandatory.
        if bindings and all(item['role'] == 'external' for item in bindings):
            selected.append(route['id'])
    return sorted(selected)


def scoped_helper(helper):
    needle = "      if(input.action==='verify')await checkHttps(name);"
    require(helper.count(needle) == 1)
    replacement = """      if(input.action==='verify') {
        if(input.external_https_hosts.includes(item.saved.id) && item.table==='proxy_host') {
          if(!externalChecked.includes(item.saved.id))externalChecked.push(item.saved.id);
          try { await checkHttps(name); } catch(error) {
            if(!['HTTPS_UPSTREAM_NOT_READY','HTTPS_TIMEOUT'].includes(error?.message))throw error;
            if(!externalUnavailable.includes(item.saved.id))externalUnavailable.push(item.saved.id);
          }
        } else await checkHttps(name);
      }"""
    helper = helper.replace(needle,replacement)
    require(helper.count('  let checked=0;') == 1)
    helper = helper.replace('  let checked=0;','  let checked=0;const externalChecked=[],externalUnavailable=[];')
    needle = "...(input.action==='verify'?{HTTPS:'PASS'}:{})"
    require(helper.count(needle) == 1)
    return helper.replace(needle,"...(input.action==='verify'?{HTTPS:'PASS',EXTERNAL_UPSTREAMS:{schema:1,total:externalChecked.length,unavailable:externalUnavailable.sort((a,b)=>a-b)}}:{})")


def external_report(value, expected):
    require(isinstance(value,dict) and set(value) == {'schema','total','unavailable'}
            and type(value['schema']) is int and value['schema'] == 1
            and type(value['total']) is int and 0 <= value['total'] <= len(expected)
            and isinstance(value['unavailable'],list)
            and all(type(v) is int and v in expected for v in value['unavailable'])
            and value['unavailable'] == sorted(set(value['unavailable']))
            and len(value['unavailable']) <= value['total'])
    return value


def execute(root, action, state_home=None):
    require(action in ('reissue', 'verify'))
    root, sources = checked_sources(root)
    helper = sources['scripts/npm-dr-helper.mjs']
    require(state_home is None or action == 'verify')
    external = external_targets(root,state_home) if state_home is not None else None
    adapted_helper = scoped_helper(helper) if external is not None else helper
    report = None
    # Load only the three content-pinned public scripts. Do not import a module
    # named dr from the working directory or modify the restored Git tree.
    dr = types.ModuleType('dr')
    dr.__file__ = str(root/'scripts/dr.py')
    native = types.ModuleType('native_npm_recovery')
    native.__file__ = str(root/'scripts/npm-dr.py')
    prior_dr = sys.modules.get('dr')
    prior_argv = sys.argv
    try:
        exec(compile(sources['scripts/dr.py'], dr.__file__, 'exec'), dr.__dict__)
        sys.modules['dr'] = dr
        exec(compile(sources['scripts/npm-dr.py'], native.__file__, 'exec'), native.__dict__)
        original = native.command
        def command(args, **kw):
            nonlocal report
            adapted = backend_command(args, helper)
            if list(args[:2]) == ['docker','exec'] and external is not None:
                data = json.loads(kw['input'])
                require(data.get('action') == 'verify' and 'external_https_hosts' not in data)
                data['external_https_hosts'] = external
                kw['input'] = json.dumps(data).encode()
                adapted[-1] = adapted_helper
            raw = original(adapted, **kw)
            if list(args[:2]) == ['docker','exec'] and external is not None:
                result = json.loads(raw)
                require(result.get('status') == 'PASS')
                report = external_report(result.get('EXTERNAL_UPSTREAMS'),external)
            return raw
        native.command = command
        sys.argv = [native.__file__, action, '--target', str(root)]
        native.main()
        if external is not None:
            require(report is not None)
            print('NPM_EXTERNAL_REPORT '+json.dumps(report))
    finally:
        sys.argv = prior_argv
        if prior_dr is None:
            sys.modules.pop('dr', None)
        else:
            sys.modules['dr'] = prior_dr


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('reissue', 'verify'))
    parser.add_argument('--target', required=True)
    parser.add_argument('--state-home')
    args = parser.parse_args()
    try:
        require(os.geteuid() == 0)
        execute(args.target, args.action, args.state_home)
    except Exception:
        # Native/library exceptions may contain domains or credentials.
        print('NPM DR_REFUSED TLS_VERIFICATION_FAILED')
        sys.exit(1)

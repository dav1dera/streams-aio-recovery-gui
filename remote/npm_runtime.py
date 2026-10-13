"""Run the pinned native NPM recovery with NPM's backend environment.

Docker exec does not inherit CERTBOT_VERSION exported by the backend shell.
The known NPM 2.16.0 helper must source common.sh before invoking Certbot's
Cloudflare plugin. Keep the backup's tracked scripts, native lock, validation,
journal and issuance policy intact; adapt only that exact child invocation.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys
import stat
import subprocess
import types

SOURCE_HASHES = {
    'scripts/dr.py': 'e20a65c8273c5a16eb55adce8cfbc9f51d9971cea43f1731a2caec935519b059',
    'scripts/npm-dr.py': 'de7e8c4d14f88792f8cb32b211724d3e8306386ce358a4e8ef243e1d3211d7f5',
    'scripts/npm-dr-helper.mjs': 'ec87d93bfa7c2c719047a8a728de5bb7a30022fecbd904d02437d97a9023b8bf',
}
NPM_RUNTIME = '. /usr/bin/common.sh; export HOME="$NPMHOME"; exec node --input-type=module -e "$1"'
TLS_PHASES = ('DNS01_ISSUANCE', 'CERTIFICATE', 'ACCESS_LISTS_REBUILD',
              'NGINX_GENERATE', 'NGINX_TEST', 'NGINX_RELOAD', 'TLS_LOOPBACK', 'HTTPS_UPSTREAM')
TLS_CODES = frozenset('TLS_NPM_' + phase + '_FAILED' for phase in TLS_PHASES)
MAX_HELPER_STDOUT = 64 * 1024


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


def diagnostic_helper(helper):
    """Instrument only the content-pinned source, retaining private exceptions.

    No restored source file is edited. Phase values are fixed literals and the
    final catch emits only a closed code, never a library message or argument.
    Every replacement must match the reviewed source exactly once.
    """
    changes = (
        ('let recoveryHosts=[];', 'let recoveryHosts=[];let recoveryPhase=null;'),
        ('  const input=JSON.parse(raw);const plan=input.plan;const oldId=plan.certificate.id;',
         "  const input=JSON.parse(raw);const plan=input.plan;const oldId=plan.certificate.id;recoveryPhase='CERTIFICATE';"),
        ('async function checkTls(name) {', "async function checkTls(name) {\n  recoveryPhase='TLS_LOOPBACK';"),
        ('async function checkHttps(name) {', "async function checkHttps(name) {\n  recoveryPhase='HTTPS_UPSTREAM';"),
        ('    if(!validPair(certificate.id,domains))await internalCertificate.requestLetsEncryptSslWithDnsChallenge(certificate,owner.email);',
         "    if(!validPair(certificate.id,domains)) {recoveryPhase='DNS01_ISSUANCE';await internalCertificate.requestLetsEncryptSslWithDnsChallenge(certificate,owner.email);}recoveryPhase='CERTIFICATE';"),
        ("    const {default: accessLists}=await import('/app/models/access_list.js');",
         "    recoveryPhase='ACCESS_LISTS_REBUILD';const {default: accessLists}=await import('/app/models/access_list.js');"),
        ('    for(const [table,model] of Object.entries(models)) {',
         "    recoveryPhase='NGINX_GENERATE';for(const [table,model] of Object.entries(models)) {"),
        ('    await internalNginx.test();await internalNginx.reload();',
         "    recoveryPhase='NGINX_TEST';await internalNginx.test();recoveryPhase='NGINX_RELOAD';await internalNginx.reload();recoveryPhase='CERTIFICATE';"),
        ("  requireCondition(validPair(certificate.id,domains),'CERTIFICATE_OR_KEY_MISSING');",
         "  recoveryPhase='CERTIFICATE';requireCondition(validPair(certificate.id,domains),'CERTIFICATE_OR_KEY_MISSING');"),
        ('  await internalNginx.test();', "  recoveryPhase='NGINX_TEST';await internalNginx.test();"),
        ('  let checked=0;', "  recoveryPhase='TLS_LOOPBACK';let checked=0;"),
        ("  output(JSON.stringify({status:'FAIL',code:'RECOVERY_CHECK_FAILED'})+'\\n');process.exit(1);",
         "  const phases=" + json.dumps(TLS_PHASES) + ";const code=phases.includes(recoveryPhase)?'TLS_NPM_'+recoveryPhase+'_FAILED':'TLS_VERIFICATION_FAILED';output(JSON.stringify({status:'FAIL',code})+'\\n');process.exit(1);"),
    )
    for needle, replacement in changes:
        require(helper.count(needle) == 1)
        helper = helper.replace(needle, replacement)
    return helper


def safe_error_code(error):
    """Only locally raised fixed ValueError codes cross the process boundary."""
    code = (error.args[0] if isinstance(error, ValueError) and len(error.args) == 1
            and isinstance(error.args[0], str) else None)
    return code if code in TLS_CODES else 'TLS_VERIFICATION_FAILED'


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def helper_result(result, action, external=None):
    """Validate even failed child output before discarding private diagnostics."""
    try:
        require(type(result.returncode) is int and isinstance(result.stdout, bytes)
                and 0 < len(result.stdout) <= MAX_HELPER_STDOUT)
        value = json.loads(result.stdout, object_pairs_hook=_unique_object)
        require(isinstance(value, dict))
        if result.returncode != 0:
            require(set(value) == {'status', 'code'} and value['status'] == 'FAIL'
                    and isinstance(value['code'], str) and value['code'] in TLS_CODES)
            raise ValueError(value['code'])
        fields = {'status', 'certificate_id', 'CERTIFICATE', 'ASSOCIATIONS', 'NGINX', 'TLS'}
        if action == 'verify':
            fields.add('HTTPS')
        if external is not None:
            fields.add('EXTERNAL_UPSTREAMS')
        require(set(value) == fields and value['status'] == 'PASS'
                and type(value['certificate_id']) is int and 1 <= value['certificate_id'] <= 2**31 - 1
                and all(value[field] == 'PASS' for field in fields - {'status', 'certificate_id', 'EXTERNAL_UPSTREAMS'}))
        if external is not None:
            external_report(value['EXTERNAL_UPSTREAMS'], external)
        return result.stdout
    except Exception as error:
        raise ValueError(safe_error_code(error)) from None


def private_helper(args, *, action, external=None, **kw):
    """Capture only the exact verified helper; never expose its stderr."""
    try:
        require(set(kw) <= {'input', 'timeout'} and isinstance(kw.get('input'), bytes))
        timeout = kw.pop('timeout', 60)
        require(type(timeout) is int and 0 < timeout <= 1200)
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, **kw)
        return helper_result(result, action, external)
    except Exception as error:
        raise ValueError(safe_error_code(error)) from None


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


def _execute(root, action, state_home=None):
    require(action in ('reissue', 'verify'))
    root, sources = checked_sources(root)
    helper = sources['scripts/npm-dr-helper.mjs']
    require(state_home is None or action == 'verify')
    external = external_targets(root,state_home) if state_home is not None else None
    adapted_helper = diagnostic_helper(scoped_helper(helper) if external is not None else helper)
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
            is_helper = list(args[:2]) == ['docker','exec']
            if is_helper and external is not None:
                data = json.loads(kw['input'])
                require(data.get('action') == 'verify' and 'external_https_hosts' not in data)
                data['external_https_hosts'] = external
                kw['input'] = json.dumps(data).encode()
            if is_helper:
                adapted[-1] = adapted_helper
                raw = private_helper(adapted, action=action, external=external, **kw)
            else:
                raw = original(adapted, **kw)
            if is_helper and external is not None:
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


def execute(root, action, state_home=None):
    """A failure exposes a fixed code without partial success output."""
    captured = io.StringIO()
    try:
        with contextlib.redirect_stdout(captured):
            _execute(root, action, state_home)
    except Exception as error:
        raise ValueError(safe_error_code(error)) from None
    print(captured.getvalue(), end='')


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('reissue', 'verify'))
    parser.add_argument('--target', required=True)
    parser.add_argument('--state-home')
    args = parser.parse_args(argv)
    try:
        require(os.geteuid() == 0)
        execute(args.target, args.action, args.state_home)
    except Exception as error:
        # Native/library exceptions may contain domains or credentials.
        print('NPM DR_REFUSED ' + safe_error_code(error))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

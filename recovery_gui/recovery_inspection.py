"""Read-only classification of both recovery destinations.

Inventory counts alone are never ownership evidence. Every destination also
passes the existing strict probe before the caller can restore or start it.
"""
import json


CHECKPOINT_SCOPE = r'''
import json,os,pwd,stat,sys
from pathlib import Path
runner=Path(sys.argv[1]); target=sys.argv[2]; tag=sys.argv[3]; commit=sys.argv[4]; role=sys.argv[5]
present=False
result=dict(checkpoint_present=False,scope_matches=False,operation_retryable=False,
            early_prestart_verified=False,infrastructure_verified=False,functional_verified=False)
try:
    path=runner/'state.json'
    if any(p.is_symlink() for p in (path,*path.parents)): raise ValueError()
    present=path.exists()
    if not present:
        result.update(scope_matches=True,operation_retryable=True)
        print(json.dumps(result));raise SystemExit(0)
    result['checkpoint_present']=True
    user=pwd.getpwuid(1000)
    expected=Path(user.pw_dir)/'.local/share'/('streams-aio-infisical-recovery' if role=='infisical' else 'streams-aio-recovery')
    expected_target=Path('/opt/infisical') if role=='infisical' else Path(user.pw_dir)/'streams-aio'
    if role not in ('stack','infisical') or user.pw_gid!=1000 or runner!=expected or Path(target)!=expected_target: raise ValueError()
    directory=runner.stat()
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=1000 or stat.S_IMODE(directory.st_mode)!=0o700: raise ValueError()
    item=path.stat()
    if not (stat.S_ISREG(item.st_mode) and item.st_uid==0 and item.st_nlink==1 and stat.S_IMODE(item.st_mode)==0o600): raise ValueError()
    if item.st_size>1024*1024: raise ValueError()
    state=json.loads(path.read_bytes())
    if not isinstance(state,dict) or type(state.get('schema')) is not int or state['schema']!=1 or state.get('runner_version')!='0.2.0': raise ValueError()
    if state.get('machine_id')!=Path('/etc/machine-id').read_text().strip(): raise ValueError()
    if state.get('target')!=target or state.get('tooling_commit')!=commit: raise ValueError()
    completed=state.get('completed');pending=state.get('in_progress')
    if not isinstance(completed,list) or not all(isinstance(name,str) for name in completed) or len(completed)!=len(set(completed)): raise ValueError()
    if 'application_start_attempted' in state and type(state['application_start_attempted']) is not bool: raise ValueError()
    # CLONES and DOWNLOAD persist these fields only after successful completion.
    # A missing field can therefore represent an early, safely retryable job;
    # a present field must always match the selected point.
    if 'public_commit' in state and state['public_commit']!=commit: raise ValueError()
    if role=='stack' and 'public_commit' not in state:
        if completed or pending not in (None,'CLONES') or (pending is None and expected_target.exists()): raise ValueError()
    if 'tag' in state:
        if state['tag']!=tag: raise ValueError()
    elif completed not in ([],['CLONES']) or pending not in (None,'CLONES','DOWNLOAD') or (runner/'ciphertext').exists(): raise ValueError()
    # A clone interrupted before its receipt is never silently adopted. The
    # same output-existence rules as the installer limit other pending retries.
    retryable = pending is None
    if pending=='DOWNLOAD':retryable=completed==['CLONES'] and not (runner/'ciphertext').exists()
    elif pending=='DECRYPT':retryable='DOWNLOAD' in completed and not (runner/'private').exists()
    elif pending=='INPUTS':retryable=role=='stack' and 'INITIALIZE' in completed and not (expected_target/'.secrets/dr-inputs').exists()
    elif pending=='AIO':retryable=role=='stack' and 'NPM' in completed and sys.argv[6]=='snapshot'
    elif pending=='INFISICAL_SERVER':retryable=role=='infisical' and 'INFISICAL_DATABASE' in completed
    # The probe is repeated by the caller after this read. No checkpoint is
    # repaired or written by detection.
    # Startup proves infrastructure only. No functional verification receipt is
    # produced yet: do not infer complete recovery from a startup checkpoint.
    result.update(scope_matches=True,operation_retryable=retryable,
                  early_prestart_verified=(role=='stack' and not expected_target.exists()
                      and completed==[] and pending is None
                      and state.get('application_start_attempted',False) is False
                      and all(state.get(key) is None for key in ('preparation','runtime_profile','operational_deployment','native_agent'))),
                  infrastructure_verified=state.get('operational_recovery')=='STARTED_NEEDS_FUNCTIONAL_TEST')
    print(json.dumps(result))
except Exception:
    result['checkpoint_present']=present
    print(json.dumps(result))
'''


def inspect_recovery(stack, server, request):
    # Lazy import allows backend.py to re-export this function without a cycle.
    from .backend import Failure, SHA, TAG, require
    action = request.get('recovery_action')
    require(action in ('fresh', 'resume'), 'OPERATION_STOPPED')
    require(bool(SHA.fullmatch(request.get('public_commit', '')))
            and bool(TAG.fullmatch(request.get('dr_tag', ''))), 'SELECT_GITHUB_RECOVERY_POINT')
    first = stack.check(fresh=False)
    second = server.check(fresh=False, role='infisical')
    require(first.get('machine_id') and first['machine_id'] != second.get('machine_id'),
            'SEPARATE_RECOVERY_VMS_REQUIRED')
    ready = {}
    for client, role, info in ((stack, 'stack', first), (server, 'infisical', second)):
        if info.get('existing_recovery'):
            require(action != 'fresh', 'EXISTING_STACK_REFUSED')
        home = info['home']
        runner = client.area(home, role)
        target = '/opt/infisical' if role == 'infisical' else home + '/streams-aio'
        # A checkpoint may precede the target directory itself (CLONES for the
        # stack, INFISICAL_CONFIG for the server), so inspect it on every host.
        raw = client.run(['python3', '-B', '-c', CHECKPOINT_SCOPE, runner, target,
                          request['dr_tag'], request['public_commit'], role,
                          request.get('aio_mode','')], sudo=True, timeout=30)
        try:
            checked = json.loads(raw)
            require(isinstance(checked, dict) and set(checked) == {'checkpoint_present','scope_matches','operation_retryable','early_prestart_verified','infrastructure_verified','functional_verified'}
                    and all(type(value) is bool for value in checked.values()), 'FOREIGN_RECOVERY_STATE')
        except (ValueError, TypeError, UnicodeError):
            raise Failure('FOREIGN_RECOVERY_STATE') from None
        require(checked['scope_matches'], 'FOREIGN_RECOVERY_STATE')
        require(not info.get('existing_recovery') or checked['checkpoint_present'], 'FOREIGN_RECOVERY_STATE')
        existing = info.get('existing_recovery') or checked['checkpoint_present']
        if existing:
            require(action != 'fresh', 'EXISTING_STACK_REFUSED')
            require(checked['operation_retryable'], 'INCOMPLETE_STEP_REQUIRES_REVIEW')
            ready[role] = checked['functional_verified']
        else:
            require(not info.get('containers') and not info.get('volumes'), 'FRESH_DOCKER_HOST_REQUIRED')
            ready[role] = False
        # Default/fresh=True enables Docker project, volume, config and
        # checkpoint compatibility checks. The preceding inventory is never
        # substituted for this guard.
        strict = client.check(fresh=True, role=role)
        require(strict.get('machine_id') == info.get('machine_id')
                and strict.get('home') == info.get('home')
                and strict.get('existing_recovery') == info.get('existing_recovery'), 'FOREIGN_RECOVERY_STATE')
        strict = dict(strict, existing_recovery=bool(existing))
        if existing and role == 'stack':
            strict = dict(strict, recovery=dict(strict.get('recovery') or {},
                                               infrastructure_verified=checked['infrastructure_verified']))
            if checked['early_prestart_verified']:
                strict['recovery']['application_start_attempted'] = False
        if role == 'stack':
            first = strict
        else:
            second = strict
    any_existing = first.get('existing_recovery') or second.get('existing_recovery')
    complete = ready['stack'] and (second.get('recovery') or {}).get('infisical_completed') is True
    outcome = 'COMPLETE' if complete else 'RESUMABLE' if any_existing else 'FRESH'
    infrastructure = (first.get('recovery') or {}).get('infrastructure_verified') is True
    return {'stack': first, 'infisical': second, 'outcome': outcome,
            'next_action': 'VERIFY' if complete else 'VERIFY_FUNCTIONAL' if infrastructure else
                           'CONTINUE' if any_existing else 'RESTORE'}

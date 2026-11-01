"""Replace reviewed public configuration of existing services without lifecycle changes.

The first supported scope preserves the complete Compose, public environment,
resource declarations and configuration path set. A separate private journal
keeps the existing service-addition receipt intact and supports crash rollback.
"""
from contextlib import contextmanager
import base64
import copy
import os
from pathlib import PurePosixPath
import stat
from types import SimpleNamespace
import uuid

KIND = 'configuration'
READY = frozenset({'SERVICE_READY', 'PUBLIC_PUBLISHED', 'BACKUP_RUNNING', 'COMPLETE'})
PARTIAL = frozenset({'PREPARED', 'FILES_WRITTEN'})


def _remote(engine):
    # The compressed SSH launcher may execute the Engine in an isolated globals
    # dictionary rather than an importable module. Resolve its actual API from
    # an inherited production method, which also works with test subclasses.
    return SimpleNamespace(**engine.request_identity.__func__.__globals__)


@contextmanager
def _worker_locks(engine):
    if engine.verification_scope == 'local_lab':
        yield
        return
    import fcntl
    r, opened = _remote(engine), []
    try:
        for worker in ('streams-aio-dr', 'streams-aio-public-sync'):
            path = engine.store.safe(engine.layout.home / '.local/state' / worker / 'run.lock')
            try:
                fd = os.open(path, os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0))
                opened.append(fd)
                info = os.fstat(fd)
                r.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                       and info.st_uid in (0, engine.layout.uid) and not info.st_mode & 0o002,
                       'ONBOARDING_CONFIGURATION_LOCK_INVALID')
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise r.Refused('ONBOARDING_OTHER_OPERATION_RUNNING') from None
            except (OSError, ValueError):
                raise r.Refused('ONBOARDING_CONFIGURATION_LOCK_INVALID') from None
        yield
    finally:
        for fd in reversed(opened):
            os.close(fd)


def _head(engine):
    if engine.verification_scope == 'local_lab':
        return None
    r = _remote(engine)
    value = engine.runner.api('repos/' + r.PUBLIC + '/git/ref/heads/main')
    sha = value.get('object', {}).get('sha') if isinstance(value, dict) else None
    r.need(isinstance(sha, str) and r.SHA.fullmatch(sha), 'ONBOARDING_PUBLIC_RECEIPT_INVALID')
    return sha


def _plan(engine, request):
    r = _remote(engine)
    engine.configure_scope(request)
    plan, service = r.plan_document(request.get('plan'))
    r.need(plan.get('schema') == 2 and plan.get('configuration_files')
           and not plan.get('private_bindings')
           and all(not child['private_bindings'] for child in r.components(plan)),
           'ONBOARDING_CONFIGURATION_SCOPE_REQUIRED')
    return plan, service


def _service_identity(r, service):
    r.need(isinstance(service, dict), 'ONBOARDING_CONFIGURATION_STATIC_CHANGED')
    result = copy.deepcopy(service)
    if isinstance(result.get('image'), str):
        result['image'] = r.image_identity(result['image'])
    entries = result.get('env_file', [])
    r.need(isinstance(entries, list) and all(isinstance(value, str) for value in entries),
           'ONBOARDING_CONFIGURATION_STATIC_CHANGED')
    if 'env_file' in result:
        result['env_file'] = [value.removeprefix('./') for value in entries]
    return result


def _snapshot_scope(engine, plan):
    r, root = _remote(engine), engine.layout.root
    compose = engine.store.snapshot(root / 'docker-compose.yml')
    current = r.yaml_document(compose.raw)
    expected = r.yaml_document('services:\n' + plan['compose_fragment'])
    r.need(isinstance(current, dict) and isinstance(current.get('services'), dict),
           'ONBOARDING_CONFIGURATION_STATIC_CHANGED')
    names = set(plan['service_names'])
    r.need(names <= set(current['services']) and set(expected['services']) == names,
           'ONBOARDING_CONFIGURATION_STATIC_CHANGED')
    for name in names:
        r.need(_service_identity(r, current['services'][name]) == _service_identity(r, expected['services'][name]),
               'ONBOARDING_CONFIGURATION_STATIC_CHANGED')
    for kind, definitions in plan['compose_resources'].items():
        r.need(isinstance(current.get(kind), dict)
               and all(current[kind].get(name) == value for name, value in definitions.items()),
               'ONBOARDING_CONFIGURATION_STATIC_CHANGED')
    target = root / 'config/service-resources.json'
    inventory_before = engine.store.snapshot(target)
    inventory = r.load_json(inventory_before.raw)
    r.need(isinstance(inventory, dict) and set(inventory) == {'schema', 'resources', 'configuration_files'}
           and inventory.get('schema') == 1 and isinstance(inventory['resources'], list)
           and isinstance(inventory['configuration_files'], list), 'ONBOARDING_RESOURCE_INVENTORY_INVALID')
    selected_resources = [row for row in inventory['resources'] if isinstance(row, dict) and row.get('service') in names]
    r.need(sorted(selected_resources, key=r.canonical_json) == sorted(plan['resources'], key=r.canonical_json),
           'ONBOARDING_CONFIGURATION_STATIC_CHANGED')
    selected = {}
    for row in inventory['configuration_files']:
        r.need(isinstance(row, dict) and set(row) == {'path', 'mode', 'sha256'}
               and isinstance(row.get('path'), str), 'ONBOARDING_RESOURCE_INVENTORY_INVALID')
        parts = PurePosixPath(row['path']).parts
        if len(parts) >= 4 and parts[0] == 'data' and parts[1] in names and parts[2] == 'public':
            r.need(row['path'] not in selected, 'ONBOARDING_RESOURCE_INVENTORY_INVALID')
            selected[row['path']] = row
    r.need(set(selected) == {row['path'] for row in plan['configuration_files']},
           'ONBOARDING_CONFIGURATION_PATH_SET_CHANGED')
    before = {'compose': compose, 'inventory': inventory_before}
    for child in r.components(plan):
        item = engine.store.snapshot(root / child['public_env_path'])
        r.need(item.raw == child['public_env_text'].encode(), 'ONBOARDING_CONFIGURATION_STATIC_CHANGED')
        before['public_env:' + child['service_name']] = item
    candidate = copy.deepcopy(inventory)
    by_path = {row['path']: row for row in candidate['configuration_files']}
    for row in plan['configuration_files']:
        old = selected[row['path']]
        r.need(type(old.get('mode')) is int and old['mode'] == row['mode'],
               'ONBOARDING_CONFIGURATION_MODE_CHANGED')
        item = engine.store.snapshot(root / row['path'])
        r.need(r.digest(item.raw) == old['sha256']
               and r.metadata_matches(item, old['mode'], item.attributes, public=True),
               'ONBOARDING_CONFIGURATION_SOURCE_CHANGED')
        before['configuration:' + row['path']] = item
        by_path[row['path']]['sha256'] = row['sha256']
    return before, r.canonical_json(candidate) + b'\n'


def _public_candidate(r, plan, inventory_raw):
    files = {row['path']: base64.b64encode(row['content'].encode()).decode()
             for row in plan['configuration_files']}
    files['config/service-resources.json'] = base64.b64encode(inventory_raw).decode()
    return dict(files=files, directories={}, private_keys={})


def _result(engine, journal, status=None):
    return dict(engine.safe_result(journal, status), operation_kind=KIND,
                configuration_updated=journal.get('configuration_updated') is True)


def inspect_configuration(engine, request):
    r = _remote(engine)
    plan, service = _plan(engine, request)
    engine.pipeline_readiness()
    before, inventory_raw = _snapshot_scope(engine, plan)
    probe = r.probe_url(request.get('probe_url', ''), service)
    profile = dict(kind='not_required', output=None, api_address='')
    health_journal = dict(plan=plan, probe_url=probe, agent_profile=profile)
    engine.health(health_journal)
    public_base = _head(engine)
    if engine.verification_scope != 'local_lab':
        engine.runner.public_preflight(_public_candidate(r, plan, inventory_raw))
        r.need(_head(engine) == public_base, 'ONBOARDING_CONFIGURATION_PUBLIC_BASE_MOVED')
    source = dict(kind=KIND, root=str(engine.layout.root), owner=engine.layout.user,
        verification_scope=engine.verification_scope, plan=plan, probe_url=probe,
        before={name: value.identity() for name, value in before.items()}, public_base=public_base,
        machine=r.digest(engine.store.read(PurePosixPath('/etc/machine-id'), 256)))
    return dict(schema=1, status='PREVIEW', operation_kind=KIND, configuration_updated=False,
        fingerprint=r.digest(r.canonical_json(source)), verification_scope=engine.verification_scope,
        service=plan['service_name'], services=plan['service_names'], image=plan['image'], images=plan['images'],
        stack_root=str(engine.layout.root), public_files=[str(PurePosixPath(value.path).relative_to(engine.layout.root)) for value in before.values()],
        private_env=None, private_envs=[], private_keys=[], project_id=request.get('project_id', ''),
        environment=request.get('environment', ''), resources=plan['resources'], agent_kind='not_required',
        agent_output=None, api_address='', application_probe=probe or 'Docker HEALTHCHECK required',
        _plan=plan, _before=before, _inventory_raw=inventory_raw, _public_base=public_base)


def _validate_existing(engine, journal, request):
    r = _remote(engine)
    r.need(journal.get('kind') == KIND and journal.get('root') == str(engine.layout.root)
           and journal.get('owner') == engine.layout.user
           and journal.get('verification_scope') == engine.verification_scope,
           'ONBOARDING_JOB_SCOPE_MISMATCH')
    r.need(engine.operation_matches(journal, request), 'ONBOARDING_JOB_PLAN_MISMATCH')


def _restore_changed(engine, journal):
    r, complete = _remote(engine), True
    for name, output in reversed(list(journal['outputs'].items())):
        if not output.get('changed'):
            continue
        try:
            before = r.Snapshot.restore(output['before'])
            current = engine.store.snapshot(PurePosixPath(output['path']))
            if r.digest(current.raw) == r.digest(before.raw):
                r.need((current.uid, current.gid) == (before.uid, before.gid)
                       and r.metadata_matches(current, before.mode, before.attributes, public=True),
                       'ONBOARDING_CONFIGURATION_RECOVERY_REQUIRED')
                continue
            r.need(r.digest(current.raw) == output['expected']
                   and (current.uid, current.gid) == (before.uid, before.gid)
                   and r.metadata_matches(current, before.mode, before.attributes, public=True),
                   'ONBOARDING_CONFIGURATION_RECOVERY_REQUIRED')
            engine.store.write(PurePosixPath(output['path']), before.raw, before.uid, before.gid,
                               before.mode, current, public=True)
        except Exception:
            complete = False
    return complete


def _recover(engine, journal):
    with _worker_locks(engine):
        restored = _restore_changed(engine, journal)
        journal['phase'] = 'ROLLED_BACK' if restored else 'REVIEW_REQUIRED'
        journal['configuration_updated'] = False
        engine.save(journal)
    _remote(engine).need(restored, 'ONBOARDING_CONFIGURATION_RECOVERY_REQUIRED')


def discover_configuration(engine, request):
    r = _remote(engine)
    _plan(engine, request)
    with engine.operation():
        matches = []
        for path in engine.store.journal_paths(engine.layout.state):
            journal = engine.store.json(path)
            if journal.get('kind') != KIND or journal.get('phase') == 'ROLLED_BACK':
                continue
            if (journal.get('root') != str(engine.layout.root) or journal.get('owner') != engine.layout.user
                    or journal.get('verification_scope') != engine.verification_scope):
                continue
            fingerprint = journal.get('fingerprint')
            if isinstance(fingerprint, str) and r.HASH.fullmatch(fingerprint) \
                    and engine.operation_matches(journal, request, discovering=True):
                matches.append(journal)
        pending = [journal for journal in matches if journal.get('phase') != 'COMPLETE']
        r.need(len(pending) <= 1, 'ONBOARDING_RESUME_AMBIGUOUS')
        completed = []
        if not pending:
            for prior in matches:
                try:
                    engine.unchanged(prior)
                except r.Refused:
                    # A later managed update can legitimately supersede these
                    # bytes. A fresh preview still requires the current files to
                    # match the installed inventory before any new write.
                    continue
                completed.append(prior)
        if not pending and not completed:
            return dict(schema=1, status='NO_JOB', operation_kind=KIND, configuration_updated=False)
        journal = pending[0] if pending else max(completed,
            key=lambda value: (value.get('backup_tag', ''), value['job_id']))
        if journal.get('phase') in PARTIAL:
            _recover(engine, journal)
            return dict(schema=1, status='NO_JOB', operation_kind=KIND, configuration_updated=False)
        r.need(journal.get('phase') in READY, 'ONBOARDING_CONFIGURATION_RECOVERY_REQUIRED')
        engine.unchanged(journal)
        engine.health(journal)
        if journal['phase'] == 'SERVICE_READY' and engine.verification_scope != 'local_lab':
            engine.runner.public_preflight(dict(files={}, directories={}, private_keys={}))
        return dict(_result(engine, journal), fingerprint=journal['fingerprint'])


def apply_configuration(engine, request):
    r = _remote(engine)
    _plan(engine, request)
    with engine.operation():
        job = request.get('job_id') or uuid.uuid4().hex
        path = engine.journal_path(job)
        if engine.store.exists(path):
            journal = engine.store.json(path)
            _validate_existing(engine, journal, request)
            if journal.get('phase') in PARTIAL:
                _recover(engine, journal)
                raise r.Refused('ONBOARDING_CONFIGURATION_RETRY_REQUIRED')
            r.need(journal.get('phase') in READY, 'ONBOARDING_CONFIGURATION_RECOVERY_REQUIRED')
            engine.unchanged(journal)
            engine.health(journal)
            return _result(engine, journal)
        preview = inspect_configuration(engine, request)
        r.need(request.get('fingerprint') == preview['fingerprint'], 'ONBOARDING_PREVIEW_STALE')
        plan, before = preview['_plan'], preview['_before']
        target_by_name = {name: item.raw for name, item in before.items()}
        target_by_name['inventory'] = preview['_inventory_raw']
        for row in plan['configuration_files']:
            target_by_name['configuration:' + row['path']] = row['content'].encode()
        journal = dict(schema=2, kind=KIND, job_id=job, root=str(engine.layout.root), owner=engine.layout.user,
            plan=plan, fingerprint=preview['fingerprint'], phase='PREPARED',
            agent_profile=dict(kind='not_required', output=None, api_address=''),
            verification_scope=engine.verification_scope, request_identity=engine.request_identity(request),
            probe_url=request.get('probe_url', ''), outputs={}, agent_changed=False, private_outputs=[],
            configuration_updated=False)
        for name, old in before.items():
            raw = target_by_name[name]
            journal['outputs'][name] = dict(path=old.path, expected=r.digest(raw), before=old.saved(),
                after=old.identity(), changed=raw != old.raw)
        r.need(len(r.canonical_json(journal)) <= r.MAX_FILE, 'ONBOARDING_CONFIGURATION_JOURNAL_TOO_LARGE')
        with _worker_locks(engine):
            for old in before.values():
                r.need(engine.store.snapshot(PurePosixPath(old.path)).identity() == old.identity(),
                       'ONBOARDING_SOURCE_CHANGED')
            r.need(_head(engine) == preview['_public_base'], 'ONBOARDING_CONFIGURATION_PUBLIC_BASE_MOVED')
            engine.save(journal)
            try:
                # Write only reviewed configuration and inventory bytes. Compose,
                # env files, Agent files, services and data directories are untouched.
                for name, output in journal['outputs'].items():
                    if not output['changed']:
                        continue
                    old = before[name]
                    item = engine.store.write(PurePosixPath(old.path), target_by_name[name], old.uid,
                        old.gid, old.mode, old, public=True)
                    output['after'] = item.identity()
                    engine.save(journal)
                journal['phase'] = 'FILES_WRITTEN'
                engine.save(journal)
                engine.compose('config', '--quiet')
                engine.health(journal)
                journal.update(phase='SERVICE_READY', application_verified=True, configuration_updated=True)
                engine.save(journal)
                return _result(engine, journal)
            except Exception as error:
                restored = _restore_changed(engine, journal)
                journal.update(phase='ROLLED_BACK' if restored else 'REVIEW_REQUIRED',
                    configuration_updated=False, failure_code=str(error) if isinstance(error, r.Refused)
                    else 'ONBOARDING_CONFIGURATION_APPLY_FAILED')
                engine.save(journal)
                return r.refused_result(error, request, stage='FILES', base=_result(engine, journal, 'REFUSED'))

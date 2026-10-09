"""A stopped startup wave reports finite observations without another login."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from recovery_gui.backend import parse_event
from recovery_gui.startup_diagnostic import SERVICES, STATUSES, safe, validate, lines

spec = importlib.util.spec_from_file_location('failed_wave_start', ROOT/'remote/start.py')
start = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {'fcntl':N()} if sys.platform == 'win32' else {}):
    spec.loader.exec_module(start)

CANARY = 'PRIVATE_DIAGNOSTIC_CANARY https://private.example/path?token=secret'
IMAGE = 'registry.invalid/image@sha256:'+'a'*64


def model():
    return dict(name='streams-aio', services={'postgres':{'image':IMAGE}, 'cometnet':{'image':IMAGE}},
                volumes={'pgdata':{'name':'streams-aio_pgdata'}})


def container(root, status='unhealthy', service='postgres'):
    return dict(Id='a'*64, RestartCount=2,
        Config={'Labels':{'com.docker.compose.project':'streams-aio',
            'com.docker.compose.project.working_dir':str(root), 'com.docker.compose.service':service},
            'Env':['PRIVATE='+CANARY], 'Cmd':[CANARY]},
        Mounts=[{'Source':CANARY}],
        State={'Status':'running', 'Running':True, 'OOMKilled':False, 'ExitCode':0,
               'Health':{'Status':status, 'Log':[{'ExitCode':1, 'Output':CANARY}]}})


def volume():
    return {'Name':'streams-aio_pgdata', 'Labels':{'com.docker.compose.project':'streams-aio',
            'com.docker.compose.volume':'pgdata'}, 'Options':{'private':CANARY}}


class Snapshot:
    def __init__(self, root, rows=None, volumes=None):
        self.rows = [container(root)] if rows is None else rows
        self.volumes = [volume()] if volumes is None else volumes
        self.calls = []

    def read(self, args):
        self.calls.append(args)
        if args == ['docker','ps','-aq']:
            return b'\n'.join(row['Id'].encode() for row in self.rows)
        if args[:2] == ['docker','inspect']:
            return json.dumps(self.rows).encode()
        if args == ['docker','volume','ls','-q']:
            return b'\n'.join(row['Name'].encode() for row in self.volumes)
        if args[:3] == ['docker','volume','inspect']:
            return json.dumps(self.volumes).encode()
        raise AssertionError(args)

    def run(self, args, **kwargs):
        self.assert_timeout = kwargs['timeout']
        return N(returncode=0, stdout=self.read(args), stderr=CANARY.encode())


def parsed(diagnostic):
    raw = 'RECOVERY_EVENT '+json.dumps(dict(stage='REFUSED', status='REFUSED',
          code='APPLICATION_HEALTH_WAIT_FAILED', diagnostic=diagnostic))
    return parse_event(raw)


class FailedWaveDiagnostic(unittest.TestCase):
    def test_complete_snapshot_has_missing_and_unhealthy_services_without_private_values(self):
        root = Path('/synthetic/stack')
        snapshot = Snapshot(root)
        report = start.startup_diagnostic(model(), root, ['postgres'], snapshot.read)
        validate(report)
        self.assertEqual(report['status'], 'COMPLETE')
        self.assertEqual(report['services']['postgres'], dict(status='UNHEALTHY', exit_code=0,
                         health_exit_code=1, restarts=2, oom_killed=False))
        self.assertEqual(report['services']['cometnet']['status'], 'NOT_STARTED')
        self.assertNotIn(CANARY, json.dumps(report))
        self.assertNotIn('private.example', json.dumps(report))
        self.assertTrue(all('logs' not in call and 'up' not in call and 'start' not in call for call in snapshot.calls))
        self.assertEqual(parsed(report)['diagnostic'], report)
        self.assertNotIn(CANARY, '\n'.join(lines(report)))

    def test_foreign_container_after_failed_wave_recheck_emits_no_service_metadata(self):
        root = Path('/synthetic/stack')
        row = container(root)
        row['Config']['Labels']['com.docker.compose.project.working_dir'] = '/home/pi/streams-aio'
        report = start.startup_diagnostic(model(), root, ['postgres'], Snapshot(root,[row]).read)
        self.assertEqual(report['status'], 'OWNERSHIP_REFUSED')
        self.assertEqual(report['services'], {})
        self.assertNotIn(CANARY, json.dumps(report))
        self.assertEqual(parsed(report)['code'], 'APPLICATION_HEALTH_WAIT_FAILED')

    def test_foreign_volume_race_never_exposes_container_fields(self):
        root = Path('/synthetic/stack')
        foreign = volume()
        foreign['Labels']['com.docker.compose.project'] = 'unrelated'
        report = start.startup_diagnostic(model(), root, ['postgres'], Snapshot(root,volumes=[foreign]).read)
        self.assertEqual(report['status'], 'OWNERSHIP_REFUSED')
        self.assertEqual(report['services'], {})

    def test_deleted_container_or_failed_probe_preserves_original_refusal(self):
        def failure(args):
            raise RuntimeError(CANARY)
        report = start.startup_diagnostic(model(), Path('/synthetic'), ['postgres'], failure)
        self.assertEqual(report['status'], 'UNAVAILABLE')
        self.assertEqual(parsed(report)['code'], 'APPLICATION_HEALTH_WAIT_FAILED')
        self.assertNotIn(CANARY, json.dumps(report))

    def test_unknown_wave_service_or_model_refuses_before_commands(self):
        calls = []
        for wave, compose in (([CANARY],model()), (['postgres'],{'name':'streams-aio','services':{CANARY:{}}})):
            report = start.startup_diagnostic(compose, Path('/synthetic'), wave, lambda args:calls.append(args))
            self.assertEqual(report['status'], 'UNAVAILABLE')
            self.assertNotIn(CANARY, json.dumps(report))
        self.assertEqual(calls, [])

    def test_collector_and_receiver_use_same_finite_schema(self):
        self.assertEqual(SERVICES, start.DIAGNOSTIC_SERVICES)
        self.assertEqual(STATUSES, start.DIAGNOSTIC_STATUSES)
        self.assertEqual(len(SERVICES), 31)
        report = start.startup_diagnostic(model(), Path('/synthetic'), ['postgres'], Snapshot(Path('/synthetic')).read)
        self.assertEqual(start.diagnostic_safe(report), validate(report))

    def test_invalid_nested_details_redact_but_keep_original_error(self):
        valid = start.startup_diagnostic(model(), Path('/synthetic'), ['postgres'], Snapshot(Path('/synthetic')).read)
        mutations = (lambda row:row.update(private=CANARY),
                     lambda row:row['services']['postgres'].update(private=CANARY),
                     lambda row:row['services'].update({CANARY:row['services']['postgres']}),
                     lambda row:row.update(wave=[CANARY]),
                     lambda row:row.update(status=CANARY),
                     lambda row:row['services']['postgres'].update(exit_code=True),
                     lambda row:row['services']['postgres'].update(restarts=10001),
                     lambda row:row['services']['postgres'].update(status=CANARY),
                     lambda row:row['services']['postgres'].update(oom_killed=CANARY))
        for mutate in mutations:
            report = json.loads(json.dumps(valid))
            mutate(report)
            result = parsed(report)
            self.assertEqual(result['code'], 'APPLICATION_HEALTH_WAIT_FAILED')
            self.assertEqual(result['diagnostic'], safe(report))
            self.assertEqual(result['diagnostic'], start.diagnostic_safe(report))
            self.assertEqual(result['diagnostic']['status'], 'UNAVAILABLE')
            self.assertNotIn(CANARY, json.dumps(result))
            self.assertNotIn(CANARY, '\n'.join(lines(report)))

    def test_metadata_only_allowed_on_specific_failure_event(self):
        diagnostic = start.diagnostic_unavailable()
        for stage, status, code in (('STARTED','PASS','APPLICATION_HEALTH_WAIT_FAILED'),
                                   ('REFUSED','REFUSED','PGBOUNCER_NOT_READY'),
                                   ('REFUSED','PASS','APPLICATION_HEALTH_WAIT_FAILED')):
            self.assertIsNone(parse_event('RECOVERY_EVENT '+json.dumps(dict(
                stage=stage,status=status,code=code,diagnostic=diagnostic))))
        self.assertIsNone(parse_event('RECOVERY_EVENT '+json.dumps(dict(stage='REFUSED',status='REFUSED',
            code='APPLICATION_HEALTH_WAIT_FAILED',diagnostic=diagnostic,private=CANARY))))

    def test_running_after_restart_is_snapshot_not_failure_erasure(self):
        root = Path('/synthetic')
        report = start.startup_diagnostic(model(), root, ['postgres'], Snapshot(root,[container(root,'healthy')]).read)
        event = parsed(report)
        self.assertEqual(event['status'], 'REFUSED')
        self.assertEqual(event['code'], 'APPLICATION_HEALTH_WAIT_FAILED')
        self.assertEqual(event['diagnostic']['services']['postgres']['status'], 'HEALTHY')

    def test_diagnostic_command_budget_is_short_and_cumulative(self):
        root = Path('/synthetic')
        snapshot = Snapshot(root)
        with patch.object(start.time, 'monotonic', side_effect=[0,1,18,21]), \
                patch.object(start.subprocess, 'run', side_effect=snapshot.run) as run:
            report = start.startup_diagnostic(model(), root, ['postgres'])
        self.assertEqual(report['status'], 'UNAVAILABLE')
        self.assertEqual([call.kwargs['timeout'] for call in run.call_args_list], [5,2])

    def test_failed_wave_collects_once_without_restart_and_keeps_checkpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            root, home = Path(temp)/'stack', Path(temp)/'recovery'
            root.mkdir(); home.mkdir(); (root/'config').mkdir()
            state_file = home/'state.json'
            state_file.write_text(json.dumps(dict(target=str(root),machine_id='synthetic',preparation='PASS')))
            (root/'config/dr-manifest.yaml').write_text(json.dumps({'restore_waves':[['postgres'],['cometnet']]}))
            compose = model()
            snapshot = Snapshot(root)
            actions = []
            def call(args, cwd):
                actions.append(args)
                if 'config' in args:
                    return json.dumps(compose).encode()
                if args in (['docker','ps','-aq'], ['docker','volume','ls','-q']):
                    return b''
                if 'up' in args:
                    raise RuntimeError(CANARY)
                raise AssertionError(args)
            checks = N(stack_preflight=lambda *args:None,
                       save=lambda path,value:path.write_text(json.dumps(value)))
            profile = N(validate=lambda *args:True, derived_waves=lambda model,waves:waves,
                        health_dependency_issues=lambda *args:([],[]))
            loader = N(loader=N(exec_module=lambda mod:None))
            original_stat, original_text = Path.stat, Path.read_text
            def stat(path,*args,**kwargs):
                return N(st_mode=0o100600) if path == state_file else original_stat(path,*args,**kwargs)
            def text(path,*args,**kwargs):
                return 'synthetic' if path.as_posix() == '/etc/machine-id' else original_text(path,*args,**kwargs)
            output = io.StringIO()
            with patch.object(Path,'stat',stat), patch.object(Path,'read_text',text), \
                    patch.object(start.importlib.util,'spec_from_file_location',return_value=loader), \
                    patch.object(start.importlib.util,'module_from_spec',side_effect=[checks,profile]), \
                    patch.object(start,'prepare_images'), patch.object(start,'call',side_effect=call), \
                    patch.object(start.subprocess,'run',side_effect=snapshot.run), \
                    contextlib.redirect_stdout(output):
                with self.assertRaises(start.StartupFailure) as refusal:
                    start.start(root,home)
                start.emit_failure(refusal.exception)
            state = json.loads(state_file.read_bytes())
            self.assertEqual(state['application_wave'], ['postgres'])
            self.assertTrue(state['application_start_attempted'])
            self.assertNotIn('application_recovery',state)
            self.assertEqual(len([args for args in actions if 'up' in args]),1)
            self.assertEqual(snapshot.calls, [['docker','ps','-aq'], ['docker','inspect','a'*64],
                                            ['docker','volume','ls','-q'], ['docker','volume','inspect','streams-aio_pgdata']])
            events = [parse_event(line) for line in output.getvalue().splitlines()]
            self.assertEqual(events[-1]['code'], 'APPLICATION_HEALTH_WAIT_FAILED')
            self.assertEqual(events[-1]['diagnostic']['services']['postgres']['status'], 'UNHEALTHY')
            self.assertFalse(any(row and row['stage']=='STARTED' and row['status']=='PASS' for row in events))
            self.assertNotIn(CANARY,output.getvalue())


if __name__ == '__main__':
    unittest.main()

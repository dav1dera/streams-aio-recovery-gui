"""A transient unhealthy check must not erase the original startup budget."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('startup_wait',Path(__file__).parents[1]/'remote/start.py')
start=importlib.util.module_from_spec(spec)
with patch.dict(sys.modules,{'fcntl':N()} if sys.platform=='win32' else {}):
    spec.loader.exec_module(start)

ROOT=Path('/replacement')
REF='example.invalid/comet@sha256:'+'a'*64
IMAGE='sha256:'+'b'*64
CID='c'*64
MODEL={'name':'streams-aio','services':{'comet':{'image':REF}},'volumes':{}}


def container(health='healthy'):
    return {'Id':CID,'Image':IMAGE,'RestartCount':0,'Config':{'Image':REF,
        'Labels':{'com.docker.compose.service':'comet','com.docker.compose.project':'streams-aio',
                  'com.docker.compose.project.working_dir':str(ROOT)},
        'Healthcheck':{'Test':['CMD','python','-m','comet.healthcheck']}},
        'State':{'Running':True,'Status':'running','Paused':False,'Restarting':False,
                 'Dead':False,'OOMKilled':False,'Health':{'Status':health}}}


class Snapshot:
    def __init__(self,rows):
        self.rows=copy.deepcopy(rows);self.now=0;self.calls=[];self.snapshots=0
    def read(self,args):
        self.calls.append(args)
        if args[:3]==['docker','image','inspect']:return IMAGE.encode()
        if 'ps' in args:return CID.encode()
        if args[:2]==['docker','inspect']:
            row=self.rows[min(self.snapshots,len(self.rows)-1)];self.snapshots+=1
            return json.dumps([row]).encode()
        raise AssertionError(args)
    def sleep(self,seconds):self.now+=seconds
    def wait(self,deadline=20):
        start.wait_wave_ready(MODEL,ROOT,['comet'],deadline,self.read,lambda:self.now,self.sleep)


class StartupBudget(unittest.TestCase):
    def test_unhealthy_then_healthy_passes_without_any_start_or_mutation(self):
        s=Snapshot([container('unhealthy'),container('starting'),container()]);s.wait()
        self.assertEqual(s.now,10)
        self.assertEqual(s.snapshots,3)
        self.assertFalse(any('up' in a or 'restart' in a or 'rm' in a for a in s.calls))

    def test_persistent_unhealthy_stops_at_original_deadline(self):
        s=Snapshot([container('unhealthy')])
        with self.assertRaisesRegex(ValueError,'APPLICATION_HEALTH_WAIT_FAILED'):s.wait(deadline=13)
        self.assertEqual(s.now,13)
        self.assertEqual(s.snapshots,3)

    def test_stopped_paused_oom_wrong_image_or_foreign_container_refuse_immediately(self):
        for mutate in (lambda c:c['State'].update(Running=False,Status='exited'),
                       lambda c:c['State'].update(Paused=True),
                       lambda c:c['State'].update(OOMKilled=True),
                       lambda c:c.update(Image='sha256:'+'d'*64),
                       lambda c:c['Config'].update(Image='example:latest'),
                       lambda c:c['Config']['Labels'].update({'com.docker.compose.project':'foreign'}),
                       lambda c:c['State'].update(Health={})):
            row=container('unhealthy');mutate(row);s=Snapshot([row])
            with self.subTest(row=row),self.assertRaises(ValueError):s.wait()
            self.assertEqual(s.now,0)

    def test_restart_or_replacement_during_wait_is_not_hidden(self):
        for key,value in (('RestartCount',1),('Id','d'*64)):
            row=container();row[key]=value;s=Snapshot([container('unhealthy'),row])
            with self.subTest(key=key),self.assertRaises(ValueError):s.wait()

    def test_duplicate_or_missing_selected_service_is_refused(self):
        s=Snapshot([container()])
        original=s.read
        def read(args):return b'' if 'ps' in args else original(args)
        with self.assertRaises(ValueError):
            start.wait_wave_ready(MODEL,ROOT,['comet'],20,read,lambda:0,lambda _:None)

    def test_healthless_service_requires_running_and_declared_health_is_not_skipped(self):
        row=container();row['Config'].pop('Healthcheck');row['State'].pop('Health')
        Snapshot([row]).wait()
        row['State']['Running']=False
        with self.assertRaises(ValueError):Snapshot([row]).wait()

    def test_reader_failure_cannot_become_success(self):
        s=Snapshot([container()])
        with self.assertRaises(RuntimeError):
            start.wait_wave_ready(MODEL,ROOT,['comet'],20,
                lambda _:(_ for _ in ()).throw(RuntimeError('private-canary')),lambda:0,s.sleep)

    def test_compose_error_classification_is_specific_and_redacted(self):
        up=['docker','compose','--profile','all','up','-d','--wait','comet']
        for args,stderr,early in ((up,b'container comet is unhealthy\n',True),
            (up,b'private-canary: daemon failure\n',False),
            (up,b'container comet is unhealthy private-canary\n',False),
            (['docker','inspect','comet'],b'container comet is unhealthy\n',False)):
            with self.subTest(stderr=stderr),patch.object(start.subprocess,'run',return_value=N(returncode=1,stderr=stderr)):
                with self.assertRaises(ValueError) as caught:start.call(args,ROOT)
                self.assertEqual(isinstance(caught.exception,start.EarlyUnhealthy),early)
                self.assertNotIn('private-canary',str(caught.exception))

    def test_fallback_uses_remaining_budget_and_never_starts_a_second_time(self):
        with patch.object(start.time,'monotonic',return_value=100), \
             patch.object(start,'call',side_effect=start.EarlyUnhealthy()) as run, \
             patch.object(start,'wait_wave_ready') as wait:
            start.start_wave(MODEL,ROOT,['comet'])
        self.assertEqual(run.call_count,1)
        wait.assert_called_once_with(MODEL,ROOT,['comet'],400)

    def test_unknown_compose_error_never_enters_health_retry(self):
        with patch.object(start,'call',side_effect=ValueError('private-canary')), \
             patch.object(start,'wait_wave_ready') as wait, \
             patch.object(start,'startup_diagnostic',return_value=start.diagnostic_unavailable()):
            with self.assertRaises(start.StartupFailure):start.start_wave(MODEL,ROOT,['comet'])
        wait.assert_not_called()


if __name__=='__main__':unittest.main()

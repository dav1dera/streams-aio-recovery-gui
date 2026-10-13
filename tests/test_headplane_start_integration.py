"""Headplane setup must run after its controllers, before its normal health wait."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules,{'fcntl':N()} if sys.platform=='win32' else {}):
        spec.loader.exec_module(module)
    return module


start=load('headplane_start_integration','remote/start.py')
profile=load('headplane_start_waves','remote/runtime_profile.py')
headplane_policy=load('headplane_start_real_plan','remote/headplane_recovery.py')


class HeadplaneStartIntegration(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(temporary.cleanup)
        self.root,self.home=Path(temporary.name)/'stack',Path(temporary.name)/'recovery'
        (self.root/'config').mkdir(parents=True)
        self.home.mkdir()
        self.state_path=self.home/'state.json'
        self.state_path.write_text(json.dumps(dict(target=str(self.root),machine_id='replacement',
            preparation='PASS',runtime_profile=dict(id='V3',origin='FIRST_BOOT'),
            operational_deployment=dict(routing_mode='parallel_test',domain_target_address='192.168.1.20'))))
        waves=[['headscale'],['headplane','npm','comet'],['oauth2-proxy'],['cometnet']]
        (self.root/'config/dr-manifest.yaml').write_text(json.dumps(dict(restore_waves=waves)))
        self.model=dict(name='streams-aio',services={name:dict(image=name+'@sha256:'+'a'*64)
                       for name in sum(waves,[])},volumes={})
        self.model['services']['npm']['depends_on']={'headscale':dict(condition='service_healthy')}
        self.model['services']['headplane']['depends_on']={'headscale':dict(condition='service_healthy')}
        self.model['services']['oauth2-proxy']['depends_on']={'headplane':dict(condition='service_started')}
        self.model['services']['cometnet']['depends_on']={'comet':dict(condition='service_healthy')}
        self.actions=[]

    def exercise(self,error=None):
        def run(args,root):
            if 'config' in args:return json.dumps(self.model).encode()
            if args[:3] in (['docker','ps','-aq'],['docker','volume','ls']):return b''
            if 'verify' in args:return b'NPM_EXTERNAL_REPORT {"schema":1,"total":0,"unavailable":[]}\n'
            raise AssertionError(args)

        def planned(root,model):
            self.actions.append('plan-headplane')
            with patch.object(headplane_policy,'controller_plan',return_value={'hostname':'controller.example.org'}):
                return headplane_policy.planned_model(root,model)

        def before(root,home,state,model,run,policy,emit,save):
            self.actions.append('prepare-headplane')
            self.assertEqual(model,self.model)
            self.assertEqual(json.loads(self.state_path.read_bytes()),state)
            if error:raise ValueError(error)

        checks=N(stack_preflight=lambda *a:None,save=lambda path,state:path.write_text(json.dumps(state)))
        runtime=N(validate=lambda *a:True,promote_operational=lambda *a:None,
                  derived_waves=profile.derived_waves,health_dependency_issues=lambda *a:(0,0))
        policy=N(deployment=lambda *a:start.DEFERRED,topology_targets=lambda *a:None,
                 cometnet_endpoint=lambda *a:None,
                 before_cometnet=lambda *a:self.actions.append('cometnet-proof'))
        headplane=N(planned_model=planned,before_headplane=before)
        loader=N(loader=N(exec_module=lambda module:None))
        original_stat,original_text=Path.stat,Path.read_text
        def metadata(path,*args,**kwargs):
            return N(st_mode=0o100600) if path==self.state_path else original_stat(path,*args,**kwargs)
        def text(path,*args,**kwargs):
            return 'replacement' if path==Path('/etc/machine-id') else original_text(path,*args,**kwargs)
        with patch.object(Path,'stat',metadata),patch.object(Path,'read_text',text),\
             patch.object(start.importlib.util,'spec_from_file_location',return_value=loader),\
             patch.object(start.importlib.util,'module_from_spec',side_effect=[checks,runtime,policy,headplane]),\
             patch.object(start,'call',run),\
             patch.object(start,'relocate_local_endpoints'),\
             patch.object(start,'start_wave',side_effect=lambda model,root,wave:self.actions.append(tuple(wave))),\
             patch.object(start,'prepare_images',side_effect=lambda *a,**k:self.actions.append('images')),\
             patch.object(start,'final_service_check',side_effect=lambda *a,**k:self.actions.append('final')),\
             contextlib.redirect_stdout(io.StringIO()):
            start.start(self.root,self.home,tls=True,operational=True)

    def test_https_bootstrap_precedes_headplane_health_wait_without_tailscale_service(self):
        self.exercise()
        prepare=self.actions.index('prepare-headplane')
        npm_wave=next(wave for wave in self.actions if isinstance(wave,tuple) and 'npm' in wave)
        headplane_wave=next(wave for wave in self.actions if isinstance(wave,tuple) and 'headplane' in wave)
        self.assertLess(self.actions.index(npm_wave),prepare)
        oauth_wave=next(wave for wave in self.actions if isinstance(wave,tuple) and 'oauth2-proxy' in wave)
        self.assertLess(self.actions.index(oauth_wave),self.actions.index(npm_wave))
        self.assertLess(self.actions.index(oauth_wave),prepare)
        self.assertLess(prepare,self.actions.index(headplane_wave))
        self.assertIn('final',self.actions)
        self.assertEqual(json.loads(self.state_path.read_bytes())['application_recovery'],'STARTED_NEEDS_FUNCTIONAL_TEST')
        self.assertNotIn('npm',self.model['services']['headplane']['depends_on'])
        self.assertEqual(self.model['services']['oauth2-proxy']['depends_on'],
                         {'headplane':dict(condition='service_started')})

    def test_bootstrap_failure_stops_headplane_and_success_certificate(self):
        with self.assertRaisesRegex(ValueError,'HEADPLANE_CONTROLLER_API_PROBE_FAILED'):
            self.exercise(error='HEADPLANE_CONTROLLER_API_PROBE_FAILED')
        self.assertFalse(any(isinstance(wave,tuple) and 'headplane' in wave for wave in self.actions))
        self.assertNotIn('final',self.actions)
        self.assertNotIn('application_recovery',json.loads(self.state_path.read_bytes()))


if __name__=='__main__':unittest.main()

"""NPM/TLS precedes CometNet, while public controllers are enabled last."""
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

spec=importlib.util.spec_from_file_location('operational_start_tests',Path(__file__).parents[1]/'remote/start.py')
start=importlib.util.module_from_spec(spec)
with patch.dict(sys.modules,{'fcntl':N(LOCK_EX=2,LOCK_NB=4,flock=lambda *args:None)}): spec.loader.exec_module(start)


class OperationalStartup(unittest.TestCase):
    def test_topology_failure_codes_survive_closed_startup_error_boundary(self):
        for code in ('NPM_TOPOLOGY_BACKUP_REQUIRED','NPM_TOPOLOGY_EVIDENCE_REQUIRED',
                     'NPM_TOPOLOGY_SOURCE_DRIFT','NPM_TOPOLOGY_PRIVATE_FILE_REQUIRED'):
            self.assertEqual(start.failure_code(ValueError(code)),code)
        self.assertEqual(start.failure_code(ValueError('private-host.example.invalid')),'APPLICATION_START_REFUSED')
    def exercise(self,cutover=False,fail_proof=False,tls=True):
        temp=tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        root=Path(temp.name)/'stack'; home=Path(temp.name)/'recovery'
        (root/'config').mkdir(parents=True); home.mkdir()
        state_path=home/'state.json'
        state=dict(target=str(root),machine_id='new-machine',preparation='PASS',
            runtime_profile={'id':'V3','origin':'FIRST_BOOT'},private_marker='preserve',
            operational_deployment={'routing_mode':'production_recovery' if cutover else 'parallel_test',
                                    'domain_target_address':'192.0.2.29'})
        state_path.write_text(json.dumps(state))
        waves=[['npm','comet'],['cometnet'],sorted(start.DEFERRED)]
        (root/'config/dr-manifest.yaml').write_text(json.dumps({'restore_waves':waves}))
        services={name:{'image':name+'@sha256:'+'a'*64} for name in sum(waves,[])}
        model={'name':'streams-aio','services':services,'volumes':{}}
        actions=[]
        def runner(args,path):
            actions.append(args)
            if 'config' in args: return json.dumps(model).encode()
            if args[:3]==['docker','ps','-aq'] or args[:3]==['docker','volume','ls']: return b''
            if 'verify' in args:
                self.assertIn('--state-home',args)
                self.assertEqual(args[args.index('--state-home')+1],home)
                return b'NPM_EXTERNAL_REPORT {"schema":1,"total":1,"unavailable":[26]}\n'
            return b''
        def before(root_arg,model_arg,run,emit,save,current,path):
            actions.append(['PUBLIC_PROOF'])
            if fail_proof: raise ValueError('PUBLIC_DOMAIN_TARGET_MISMATCH')
            current['public_domain_recovery']='TARGET_VERIFIED'; save(path,current)
        checks=N(stack_preflight=lambda *args:None,save=lambda path,state:path.write_text(json.dumps(state)))
        profile=N(validate=lambda *args:True,OPERATIONAL_PROFILE='V3',FIRST_BOOT_PROFILE='V1',
            promote_operational=lambda *args:None,derived_waves=lambda model,waves:waves,
            health_dependency_issues=lambda *args:([],[]))
        operational=N(deployment=lambda data,cutover:set() if cutover else start.DEFERRED,
            cometnet_endpoint=lambda model:'synthetic.example',before_cometnet=before,
            topology_targets=lambda *args:actions.append(['TOPOLOGY_PROOF']))
        loader=N(loader=N(exec_module=lambda module:None))
        original_stat,original_text=Path.stat,Path.read_text
        def metadata(path,*args,**kw):
            return N(st_mode=0o100600) if path==state_path else original_stat(path,*args,**kw)
        def text(path,*args,**kw):
            return 'new-machine' if path==Path('/etc/machine-id') else original_text(path,*args,**kw)
        output=io.StringIO(); error=None
        with patch.object(Path,'stat',metadata),patch.object(Path,'read_text',text), \
             patch.object(start.importlib.util,'spec_from_file_location',return_value=loader), \
             patch.object(start.importlib.util,'module_from_spec',side_effect=[checks,profile,operational]), \
             patch.object(start,'call',runner),patch.object(start,'prepare_images'), \
             patch.object(start,'final_service_check',side_effect=lambda *a,**kw:actions.append(['FINAL',kw.get('deferred')])), \
             contextlib.redirect_stdout(output):
            try: start.start(root,home,tls=tls,operational=True,cutover=cutover)
            except ValueError as exc: error=str(exc)
        return error,actions,json.loads(state_path.read_bytes())

    def test_tls_and_identity_proof_run_before_cometnet_and_controllers_last(self):
        error,actions,state=self.exercise(cutover=True)
        self.assertIsNone(error)
        proof=actions.index(['PUBLIC_PROOF'])
        self.assertLess(actions.index(['TOPOLOGY_PROOF']),proof)
        cometnet=next(i for i,args in enumerate(actions) if 'up' in args and args[-1]=='cometnet')
        verify=next(i for i,args in enumerate(actions) if 'verify' in args)
        controllers=next(i for i,args in enumerate(actions) if 'up' in args and 'watchtower' in args)
        self.assertLess(proof,cometnet); self.assertLess(cometnet,verify); self.assertLess(verify,controllers)
        self.assertTrue(state['public_controllers_enabled']); self.assertEqual(state['deferred_controllers'],[])
        self.assertEqual(state['private_marker'],'preserve')
        self.assertEqual(state['public_domain_recovery'],'VERIFIED')
        self.assertEqual(state['external_upstreams'],{'schema':1,'total':1,'unavailable':[26]})

    def test_parallel_domain_test_never_starts_public_controllers(self):
        error,actions,state=self.exercise()
        self.assertIsNone(error)
        self.assertFalse(any('up' in args and 'watchtower' in args for args in actions))
        self.assertEqual(set(state['deferred_controllers']),start.DEFERRED)

    def test_original_domain_or_wrong_routing_stops_before_cometnet(self):
        error,actions,state=self.exercise(fail_proof=True)
        self.assertEqual(error,'PUBLIC_DOMAIN_TARGET_MISMATCH')
        self.assertFalse(any('up' in args and 'cometnet' in args for args in actions))
        self.assertNotIn('operational_recovery',state)

    def test_operational_start_cannot_skip_tls(self):
        error,actions,state=self.exercise(tls=False)
        self.assertEqual(error,'OPERATIONAL_TLS_REQUIRED')
        self.assertFalse(any('up' in args for args in actions))


if __name__=='__main__': unittest.main()

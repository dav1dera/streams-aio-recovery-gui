"""Public domain gates prove replacement identity without bypassing TLS/DNS."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('operational_policy_tests',
    Path(__file__).parents[1]/'remote/operational_profile.py')
policy = importlib.util.module_from_spec(spec); spec.loader.exec_module(policy)


class OperationalGates(unittest.TestCase):
    def model(self):
        return dict(name='streams-aio', services={
            'npm':{'image':'npm@sha256:'+'a'*64},
            'comet':{'image':'comet@sha256:'+'b'*64,'network_mode':'service:gluetun'},
            'cometnet':{'network_mode':'service:gluetun', 'environment':{
                'COMETNET_ADVERTISE_URL':'wss://cometnet.synthetic.example/',
                'COMETNET_BOOTSTRAP_NODES':'["wss://peer.synthetic.example"]'}},
            'gluetun':{'container_name':'gluetun','networks':{'vpn-net':{'ipv4_address':'172.19.0.2'}}}})

    def test_controller_scope_requires_explicit_production_cutover(self):
        state={'operational_deployment':{'routing_mode':'parallel_test','domain_target_address':'192.0.2.29'}}
        self.assertEqual(policy.deployment(state), set(policy.CONTROLLERS))
        with self.assertRaisesRegex(ValueError,'PUBLIC_CONTROLLER_CUTOVER_REQUIRED'):
            policy.deployment(state, True)
        state['operational_deployment']['routing_mode']='production_recovery'
        with self.assertRaisesRegex(ValueError,'PUBLIC_CONTROLLER_CUTOVER_REQUIRED'):
            policy.deployment(state)
        self.assertEqual(policy.deployment(state, True), set())

    def test_public_endpoint_cannot_reuse_trial_or_disable_self_checks(self):
        for change in ({'COMETNET_ADVERTISE_URL':'ws://127.0.0.1:8765'},
                       {'COMETNET_ADVERTISE_URL':'wss://secret@example.org/'},
                       {'COMETNET_ADVERTISE_URL':'wss://cometnet.example.org:8443'},
                       {'COMETNET_SKIP_REACHABILITY_CHECK':'true'},
                       {'COMETNET_SKIP_TIME_CHECK':'1'},
                       {'COMETNET_NETWORK_ID':'streams-aio-dr-local'}):
            model=self.model(); model['services']['cometnet']['environment'].update(change)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError,'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED'):
                policy.cometnet_endpoint(model)
        self.assertEqual(policy.cometnet_endpoint(self.model()),'cometnet.synthetic.example')

    def exercise(self, fail_probe=False, fail_install=False, fail_cleanup=False, foreign=False):
        root=Path('/home/test/streams-aio'); model=self.model(); actions=[]; payloads=[]
        def run(args):
            actions.append(args)
            if 'ps' in args: return (('a' if args[-1]=='npm' else 'b')*64).encode()
            if args[:2]==['docker','inspect']:
                service='npm' if args[-1]=='a'*64 else 'comet'
                row=dict(Config=dict(Image=model['services'][service]['image'],Labels={
                    'com.docker.compose.project.working_dir':str(root),
                    'com.docker.compose.project':'foreign' if foreign else 'streams-aio',
                    'com.docker.compose.service':service}),State={'Running':True})
                if service=='npm': row['Mounts']=[dict(Type='bind',Source=str(root/source),Destination=dest)
                    for source,dest in (('data/npm/data','/data'),('data/npm/data/letsencrypt','/etc/letsencrypt'))]
                return json.dumps([row]).encode()
            if fail_probe: raise RuntimeError('private URL must never leave fixed-code boundary')
            return b''
        def send(args, path, raw):
            value=json.loads(raw); payloads.append(value)
            if value['action']=='install' and fail_install or value['action']=='remove' and fail_cleanup:
                raise ValueError('PUBLIC_DOMAIN_PROBE_FAILED')
            return b'{"status":"PASS"}'
        error=None
        try: policy.verify_public_target(root,model,run,send=send)
        except ValueError as exc: error=str(exc)
        return error,actions,payloads

    def test_identity_probe_uses_normal_tls_dns_from_comets_vpn_namespace(self):
        error,actions,payloads=self.exercise()
        self.assertIsNone(error)
        self.assertEqual([row['action'] for row in payloads],['install','remove'])
        self.assertEqual(payloads[0]['nonce'],payloads[1]['nonce'])
        self.assertEqual(payloads[0]['forward_hosts'],['172.19.0.2','gluetun'])
        probe=actions[-1]
        self.assertEqual(probe[:4],['docker','exec','b'*64,'python'])
        self.assertIn('ssl.create_default_context()',probe[5])
        self.assertNotIn('check_hostname=False',probe[5])
        self.assertNotIn('--insecure',probe)
        self.assertFalse(any('down' in args or 'rm' in args for args in actions))

    def test_original_domain_response_fails_even_with_valid_certificate_and_cleanup_runs(self):
        error,_,payloads=self.exercise(fail_probe=True)
        self.assertEqual(error,'PUBLIC_DOMAIN_TARGET_MISMATCH')
        self.assertEqual([row['action'] for row in payloads],['install','remove'])

    def test_partial_marker_install_is_cleaned_and_cleanup_failure_blocks_success(self):
        error,_,payloads=self.exercise(fail_install=True)
        self.assertEqual(error,'PUBLIC_DOMAIN_PROBE_FAILED')
        self.assertEqual([row['action'] for row in payloads],['install','remove'])
        self.assertEqual(self.exercise(fail_cleanup=True)[0],'PUBLIC_DOMAIN_PROBE_CLEANUP_REQUIRED')

    def test_foreign_container_is_refused_before_npm_marker_write(self):
        error,_,payloads=self.exercise(foreign=True)
        self.assertEqual(error,'PUBLIC_DOMAIN_PROBE_FAILED'); self.assertEqual(payloads,[])

    def exercise_all(self,fail_probe=False,omit_domain=False,wrong_binding=False,fail_cleanup=False):
        root=Path('/home/test/streams-aio');model=self.model();actions=[];payloads=[];verified=[]
        routes=[{'id':7,'routing':{'domain_names':['cometnet.synthetic.example'],'forward_host':'192.0.2.29',
                   'forward_port':8765,'forward_scheme':'http','locations':[],'advanced_config':''}},
                {'id':9,'routing':{'domain_names':['secrets.synthetic.example','second.synthetic.example'],
                   'forward_host':'192.0.2.30','forward_port':80,'forward_scheme':'http','locations':[],
                   'advanced_config':'# preserved'}}]
        value={'bindings':[{'table':'proxy_host','id':7,'path':['forward_host'],
                   'role':'external' if wrong_binding else 'stack','service':'gluetun'},
                          {'table':'proxy_host','id':9,'path':['forward_host'],'role':'infisical','service':'backend'}]}
        class Topology:
            def verify(self,*args,**kw):verified.append(kw);return {}
        def run(args):
            actions.append(args)
            if 'ps' in args:return (('a' if args[-1]=='npm' else 'b')*64).encode()
            if args[:2]==['docker','inspect']:
                service='npm' if args[-1]=='a'*64 else 'comet'
                row=dict(Config=dict(Image=model['services'][service]['image'],Labels={
                    'com.docker.compose.project.working_dir':str(root),'com.docker.compose.project':'streams-aio',
                    'com.docker.compose.service':service}),State={'Running':True})
                if service=='npm':row['Mounts']=[dict(Type='bind',Source=str(root/source),Destination=dest)
                    for source,dest in (('data/npm/data','/data'),('data/npm/data/letsencrypt','/etc/letsencrypt'))]
                return json.dumps([row]).encode()
            compile(args[5],'<multi-domain-probe>','exec')
            if fail_probe:raise RuntimeError('private-domain.example must stay private')
            return b''
        def send(args,path,raw):
            request=json.loads(raw);payloads.append(request)
            if request['action']=='remove':
                if fail_cleanup:raise RuntimeError('secret cleanup error')
                return b'{"status":"PASS"}'
            probes=[{'id':row['id'],'hostname':host} for row in routes for host in row['routing']['domain_names']]
            if omit_domain:probes.pop()
            return json.dumps({'status':'PASS','probes':probes,'hosts':2,'skipped_disabled':0,'skipped_http':0}).encode()
        error=None;result=None
        with patch.object(policy,'topology_targets',return_value=(Topology(),value,{},routes)):
            try:result=policy.verify_all_public_targets(root,model,run,{'public_commit':'a'*40,'npm_topology':{}},send=send)
            except ValueError as exc:error=str(exc)
        return error,result,actions,payloads,verified

    def test_all_local_domains_use_proven_new_upstreams_and_normal_tls(self):
        error,result,actions,payloads,verified=self.exercise_all()
        self.assertIsNone(error)
        self.assertEqual(result,{'hosts':2,'domains':3,'skipped_disabled':0,'skipped_http':0})
        self.assertEqual([row['action'] for row in payloads],['install','remove'])
        self.assertEqual(payloads[0]['routes'][0]['routing']['forward_host'],'192.0.2.29')
        self.assertEqual(payloads[0]['routes'][1]['routing']['forward_host'],'192.0.2.30')
        self.assertEqual(verified,[{'stack_commit':'a'*40}])
        probe=actions[-1]
        self.assertEqual(probe[:4],['docker','exec','b'*64,'python'])
        self.assertIn('ssl.create_default_context()',probe[5])
        self.assertIn('HTTPSConnection',probe[5])
        self.assertNotIn('check_hostname=False',probe[5])

    def test_no_original_can_satisfy_one_of_the_domain_proofs_and_markers_are_cleaned(self):
        error,_,_,payloads,verified=self.exercise_all(fail_probe=True)
        self.assertEqual(error,'PUBLIC_DOMAIN_TARGET_MISMATCH')
        self.assertEqual([row['action'] for row in payloads],['install','remove'])
        self.assertEqual(verified,[])

    def test_omitting_second_domain_of_an_active_host_refused(self):
        error,_,_,payloads,_=self.exercise_all(omit_domain=True)
        self.assertEqual(error,'PUBLIC_DOMAIN_PROBE_FAILED')
        self.assertEqual([row['action'] for row in payloads],['install','remove'])

    def test_cometnet_cannot_be_proven_by_unowned_external_route(self):
        error,_,actions,payloads,_=self.exercise_all(wrong_binding=True)
        self.assertEqual(error,'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')
        self.assertEqual(actions,[]);self.assertEqual(payloads,[])

    def test_all_domain_cleanup_failure_blocks_success(self):
        error,_,_,payloads,_=self.exercise_all(fail_cleanup=True)
        self.assertEqual(error,'PUBLIC_DOMAIN_PROBE_CLEANUP_REQUIRED')
        self.assertEqual([row['action'] for row in payloads],['install','remove'])


if __name__=='__main__': unittest.main()

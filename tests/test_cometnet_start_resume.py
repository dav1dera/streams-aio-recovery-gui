"""The start action migrates the registered trial before resuming normal health gates."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import sys
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('cometnet_resume_start', Path(__file__).parents[1]/'remote/start.py')
start = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {'fcntl':N(LOCK_EX=2, LOCK_NB=4, flock=lambda *args:None)}):
    spec.loader.exec_module(start)

class TrialStart(unittest.TestCase):
    def exercise(self, tls=False, foreign=False):
        with tempfile.TemporaryDirectory() as directory:
            root, home = Path(directory)/'stack', Path(directory)/'recovery'
            root.mkdir(); home.mkdir(); (root/'config').mkdir()
            checkpoint = home/'state.json'
            initial = dict(target=str(root), machine_id='synthetic', preparation='PASS',
                completed=['NPM','AIO'], application_start_attempted=True, application_wave=['cometnet'],
                runtime_profile={'id':'V1','origin':'FIRST_BOOT'}, private_marker='preserve-me')
            checkpoint.write_text(json.dumps(initial))
            (root/'config/dr-manifest.yaml').write_text(json.dumps({'restore_waves':[['comet'],['cometnet']]}))
            model = {'name':'streams-aio','services':{
                'comet':{'image':'g0ldyy/comet@sha256:'+'a'*64},
                'cometnet':{'image':'g0ldyy/comet@sha256:'+'a'*64}},'volumes':{}}
            def container(name):
                return {'Config':{'Labels':{'com.docker.compose.project.working_dir':str(root),
                    'com.docker.compose.project':'foreign' if foreign else 'streams-aio',
                    'com.docker.compose.service':name}}}
            actions, migration = [], []
            def runner(args, path):
                actions.append(args)
                if 'config' in args: return json.dumps(model).encode()
                if args[:3] == ['docker','ps','-aq']: return b'aaaa\nbbbb'
                if args[:3] == ['docker','volume','ls']: return b''
                if args[:2] == ['docker','inspect'] and '--format' not in args:
                    return json.dumps([container('comet'),container('cometnet')]).encode()
                if args[:2] == ['docker','inspect']:
                    return b'\n'.join(json.dumps({'service':name,'project':'streams-aio',
                        'directory':str(root),'running':True,'health':'healthy'}).encode() for name in model['services'])
                if 'ps' in args: return b'aaaa\nbbbb'
                return b''
            def migrate(root_arg, home_arg, state, current, read, tls=False):
                self.assertFalse(tls); self.assertEqual((root_arg,home_arg),(root,home))
                self.assertEqual(state['runtime_profile']['id'],'V1')
                migration.append(True)
                state['runtime_profile']['id']='V2'
                checkpoint.write_text(json.dumps(state))
                model['services']['cometnet']['environment']={'LOCAL_TRIAL':'true'}
            checks = N(stack_preflight=lambda *args:None, save=lambda path,state:path.write_text(json.dumps(state)))
            profile = N(validate=lambda *args:True, FIRST_BOOT_PROFILE='V1',
                migrate_cometnet_trial=migrate, derived_waves=lambda model,waves:waves,
                health_dependency_issues=lambda *args:([],[]))
            loader=N(loader=N(exec_module=lambda module:None))
            original_stat, original_text = Path.stat, Path.read_text
            def stat(path,*args,**kwargs):
                return N(st_mode=0o100600) if path == checkpoint else original_stat(path,*args,**kwargs)
            def text(path,*args,**kwargs):
                return 'synthetic' if path.as_posix() == '/etc/machine-id' else original_text(path,*args,**kwargs)
            output=io.StringIO()
            with patch.object(Path,'stat',stat), patch.object(Path,'read_text',text), \
                 patch.object(start.importlib.util,'spec_from_file_location',return_value=loader), \
                 patch.object(start.importlib.util,'module_from_spec',side_effect=[checks,profile]), \
                 patch.object(start,'call',runner), patch.object(start,'prepare_images'), contextlib.redirect_stdout(output):
                if tls or foreign:
                    with self.assertRaisesRegex(ValueError,'COMETNET_TRIAL_TLS_REFUSED' if tls else 'FOREIGN_CONTAINER_REFUSED'):
                        start.start(root,home,tls=tls)
                else:
                    start.start(root,home)
            return initial,json.loads(checkpoint.read_bytes()),actions,migration,output.getvalue()

    def test_migration_precedes_health_start_and_preserves_prepared_steps(self):
        initial,state,actions,migration,output=self.exercise()
        self.assertEqual(migration,[True])
        self.assertEqual(state['completed'],initial['completed'])
        self.assertEqual(state['private_marker'],'preserve-me')
        self.assertEqual(state['runtime_profile']['id'],'V2')
        self.assertEqual(state['application_recovery'],'STARTED_NEEDS_FUNCTIONAL_TEST')
        self.assertEqual(len([args for args in actions if 'config' in args]),2)
        up=[args for args in actions if 'up' in args]
        self.assertEqual([args[-1] for args in up],['comet','cometnet'])
        self.assertTrue(all('--wait' in args and '--no-deps' in args for args in up))
        self.assertFalse(any('down' in args or 'rm' in args for args in actions))
        self.assertIn('COMETNET_TRIAL',output)

    def test_tls_does_not_change_a_trial_or_start_services(self):
        initial,state,actions,migration,_=self.exercise(tls=True)
        self.assertEqual(state,initial); self.assertFalse(migration)
        self.assertFalse(any('up' in args for args in actions))

    def test_foreign_resource_refuses_before_migration(self):
        initial,state,actions,migration,_=self.exercise(foreign=True)
        self.assertEqual(state,initial); self.assertFalse(migration)
        self.assertFalse(any('up' in args for args in actions))

if __name__ == '__main__':
    unittest.main()

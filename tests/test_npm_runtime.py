"""NPM backend environment, exact source pins and child argument safety."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import json
import unittest
from unittest.mock import patch
from recovery_gui import backend
from recovery_gui import external_dependencies
from recovery_gui.ui_state import phase_status

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('npm_runtime_tests',ROOT/'remote/npm_runtime.py')
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
spec=importlib.util.spec_from_file_location('npm_runtime_policy_tests',ROOT/'remote/operational_profile.py')
policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)


class NativeNPMEnvironment(unittest.TestCase):
    def test_mixed_or_internal_routes_cannot_be_omitted(self):
        value=dict(routes=[dict(table='proxy_host',id=i) for i in (1,2,3,4)],bindings=[
            dict(table='proxy_host',id=1,role='external'),
            dict(table='proxy_host',id=2,role='compose'),
            dict(table='proxy_host',id=3,role='external'),dict(table='proxy_host',id=3,role='infisical')])
        self.assertEqual(runtime.external_route_ids(value),[1])

    def test_external_report_cannot_hide_a_recovered_route(self):
        self.assertEqual(runtime.external_report(dict(schema=1,total=2,unavailable=[26]),[20,26])['unavailable'],[26])
        for value in (dict(schema=1,total=2,unavailable=[2]),dict(schema=1,total=1,unavailable=[26,26]),
                      dict(schema=1,total=2,unavailable=[True]),dict(schema=1,total=0,unavailable=[26])):
            with self.assertRaisesRegex(ValueError,'^TLS_VERIFICATION_FAILED$'):runtime.external_report(value,[20,26])

    def test_closed_warning_crosses_transport_and_stays_visible(self):
        value=dict(schema=1,total=2,unavailable=[26])
        event=dict(stage='EXTERNAL_UPSTREAMS',status='WARNING',diagnostic=value)
        self.assertEqual(backend.parse_event('RECOVERY_EVENT '+json.dumps(event)),event)
        self.assertIn('da verificare',phase_status('EXTERNAL_UPSTREAMS','WARNING')[0])
        self.assertTrue(any('26' in line for line in external_dependencies.lines(value)))
        event['diagnostic']['domain']='private.example.invalid'
        self.assertIsNone(backend.parse_event('RECOVERY_EVENT '+json.dumps(event)))

    def test_warning_is_not_an_unqualified_pass(self):
        event=dict(stage='EXTERNAL_UPSTREAMS',status='PASS',diagnostic=dict(schema=1,total=2,unavailable=[26]))
        self.assertIsNone(backend.parse_event('RECOVERY_EVENT '+json.dumps(event)))

    def test_backend_environment_wraps_verified_helper_as_argument(self):
        helper="console.log('synthetic helper');"
        original=['docker','exec','-i','--user','0','--workdir','/app','a'*64,'node','--input-type=module','-e',helper]
        result=runtime.backend_command(original,helper)
        self.assertEqual(result[:8],original[:8])
        self.assertEqual(result[8:10],['bash','-c'])
        self.assertEqual(result[10],'. /usr/bin/common.sh; export HOME="$NPMHOME"; exec node --input-type=module -e "$1"')
        self.assertEqual(result[-1],helper)
        self.assertNotIn(helper,result[10])
        self.assertEqual(original[8],'node')

    def test_foreign_exec_or_modified_helper_is_refused(self):
        args=['docker','exec','-i','--user','0','--workdir','/app','a'*64,'node','--input-type=module','-e','verified']
        for index,value in ((4,'1000'),(7,'$(private)'),(11,'modified')):
            changed=args.copy();changed[index]=value
            with self.subTest(index=index),self.assertRaisesRegex(ValueError,'^TLS_VERIFICATION_FAILED$'):
                runtime.backend_command(changed,'verified')

    def test_inventory_commands_unchanged(self):
        for args in (['docker','ps','-aq'],['docker','inspect','a'*64]):
            self.assertIs(runtime.backend_command(args,'helper'),args)

    def test_changed_source_refused_before_loading(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'scripts/native.py';path.parent.mkdir();path.write_bytes(b'original\n')
            pins={'scripts/native.py':hashlib.sha256(path.read_bytes()).hexdigest()}
            with patch.object(runtime,'SOURCE_HASHES',pins):
                self.assertEqual(runtime.checked_sources(root)[1],{'scripts/native.py':'original\n'})
                path.write_bytes(b'modified\n')
                with self.assertRaisesRegex(ValueError,'^TLS_VERIFICATION_FAILED$'):runtime.checked_sources(root)

    def test_startup_certificate_actions_use_context_adapter(self):
        for action in ('reissue','verify'):
            commands=[];root=Path('/synthetic/stack')
            policy.npm_action(root,commands.append,action)
            self.assertEqual(Path(commands[0][2]).name,'npm_runtime.py')
            self.assertEqual(commands[0][3:],[action,'--target',root])


if __name__=='__main__':unittest.main()

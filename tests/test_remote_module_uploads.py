"""Every real SSH entry point transfers the current remote dependency set."""
import json
from pathlib import Path
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

from recovery_gui import backend


class RemoteModuleUploads(unittest.TestCase):
    def setUp(self):
        self.home = '/home/replacement'
        self.sent,self.commands = [],[]
        self.connection = backend.SSH.__new__(backend.SSH)
        self.connection.host = N(user='replacement')
        self.connection.check = lambda **kwargs: {'home':self.home}
        self.connection.client = N(open_sftp=lambda: N(chmod=lambda *args:None,
            mkdir=lambda *args,**kwargs:None,close=lambda:None))
        def run(args,**kwargs):
            self.commands.append((args,kwargs))
            return self.home.encode() if args[:2] == ['sh','-c'] else b''
        self.connection.run = run
        def put(sftp,source,destination):
            self.assertTrue(source.is_file(),source.name)
            self.assertFalse(source.is_symlink())
            self.sent.append((source.name,destination))
        self.connection._put = put

    def assert_runtime_modules(self):
        names = {name for name,destination in self.sent}
        self.assertTrue({'recover.py','runtime_profile.py','aio_snapshot.py',
            'operational_profile.py','npm_topology.py','npm-domain-probe.mjs','npm-route-probe.mjs'} <= names)
        self.assertEqual(len(names),len(self.sent))

    def test_prepare_transfers_helpers_and_preserves_selected_schema_two_pin(self):
        request = dict(github_token='synthetic-token',public_commit='b'*40,
            dr_tag='dr-20261010T043000Z',infisical_address='http://127.0.0.1:12345',
            project_id='',environment='',aio_mode='snapshot',operational_profile=True,
            routing_mode='parallel_test',domain_target_address='192.0.2.42',
            npm_upstream_targets={'stack':'192.0.2.29','infisical':'192.0.2.30'})
        stage,raw = self.connection.upload(request)
        self.assert_runtime_modules()
        config = json.loads(raw)
        self.assertEqual(config['public_commit'],request['public_commit'])
        self.assertEqual(config['dr_tag'],request['dr_tag'])
        self.assertEqual(config['aio_mode'],'snapshot')
        self.assertEqual(config['domain_target_address'],'192.0.2.42')
        self.assertEqual(config['npm_upstream_targets'],{'stack':'192.0.2.29','infisical':'192.0.2.30'})
        self.assertTrue(all(destination.startswith(stage+'/remote/') for name,destination in self.sent))

    def test_native_reinstall_transfers_topology_for_runtime_validation(self):
        self.connection.native('install',self.home,self.home+'/streams-aio',metadata={})
        self.assert_runtime_modules()
        self.assertTrue(all(destination.startswith(self.home+'/.local/share/streams-aio-recovery/')
                            for name,destination in self.sent))

    def test_infisical_upload_uses_its_own_user_home_and_never_aio_exports(self):
        self.home = '/home/test2'
        self.connection.host.user = 'test2'
        request = dict(role='infisical',github_token='synthetic-token',public_commit='c'*40,
            dr_tag='dr-20261011T043000Z',infisical_address='',project_id='',environment='',
            aio_mode='snapshot',operational_profile=True,routing_mode='parallel_test',
            domain_target_address='192.0.2.42',aio_payload='/unused/private-payload.json',
            supplemental_inputs='/unused/private-supplement.age',
            aiostreams_exports=['/unused/profile.json'],aiometadata_exports=['/unused/profile.json'])
        stage,raw = self.connection.upload(request)
        self.assert_runtime_modules()
        self.assertTrue(stage.startswith(self.home+'/.local/share/streams-aio-infisical-recovery/'))
        config = json.loads(raw)
        self.assertEqual(config['role'],'infisical')
        self.assertEqual(config['public_commit'],'c'*40)
        self.assertEqual(config['dr_tag'],'dr-20261011T043000Z')
        self.assertEqual(config['aiostreams_exports'],[])
        self.assertEqual(config['aiometadata_exports'],[])
        self.assertNotIn('aio_payload',config)
        self.assertNotIn('supplemental_inputs',config)

    def test_start_transfers_topology_and_uses_actual_account_home(self):
        self.connection.start(True,lambda event:None,operational=True,routing_mode='production_recovery',
                              domain_target_address='192.0.2.42',cutover=True)
        self.assert_runtime_modules()
        args = self.commands[-1][0]
        self.assertIn(self.home+'/streams-aio',args)
        self.assertIn('--operational',args)
        self.assertIn('--cutover',args)
        self.assertEqual(args[args.index('--domain-target-address')+1],'192.0.2.42')


if __name__ == '__main__':
    unittest.main()

"""Cross-layer resource contracts: desktop routing and recovery declarations."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from recovery_gui.service_plan import analyze_inputs
from recovery_gui.web_bridge import WebBridge
from recovery_gui.onboarding import ServiceController, PRIVATE_PROOF_FRAME
from tests.test_onboarding_controller import FakeAPI, FakeSSH, RESOURCE

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('generic_recover_contract',ROOT/'remote/recover.py')
recover=importlib.util.module_from_spec(spec);spec.loader.exec_module(recover)

class GenericContracts(unittest.TestCase):
    def test_duplicate_private_names_route_to_both_service_folders_and_agent_files(self):
        text='services:\n  first:\n    image: example/first:latest\n    environment:\n      PASSWORD: first-private-canary\n  second:\n    image: example/second:latest\n    environment:\n      PASSWORD: second-private-canary\n'
        from recovery_gui.service_plan import inspect_inputs
        names=[row.name for row in inspect_inputs(text) if row.suggested_private]
        analysis=analyze_inputs(text,private_names=names)
        self.assertEqual(len(analysis.sensitive),2)
        ssh,api=FakeSSH(),FakeAPI()
        controller=ServiceController(lambda *_:False,ssh_factory=lambda *a,**k:ssh,
            api_factory=lambda *a,**k:api,resource_dir=RESOURCE,sleeper=lambda _:None)
        connection=dict(host='192.0.2.10',port=22,user='pi',stack_root='/home/pi/streams-aio',verification_scope='local_lab')
        settings=dict(endpoint='https://example.invalid',project_id='f80601b1-73fb-49bd-9373-f3687cd5c8eb',environment='prod',access_token='synthetic')
        receipt=controller.inspect(analysis,connection,settings)
        controller.apply(analysis,connection,settings,receipt)
        self.assertEqual({service:values for action,service,values in api.calls if action=='ensure'},
                         {'first':{'PASSWORD':'first-private-canary'},'second':{'PASSWORD':'second-private-canary'}})
        proofs=[request for _,request in ssh.calls if 'challenge' in request]
        self.assertEqual({item['path'] for item in proofs},{'/home/pi/streams-aio/.secrets/first.env','/home/pi/streams-aio/.secrets/second.env'})
        self.assertTrue(all(set(item['expected'])=={'PASSWORD'} for item in proofs))
        self.assertNotIn('private-canary',json.dumps(analysis.plan.to_public_dict()))

    def test_bridge_exposes_inventory_without_configuration_content(self):
        bridge=WebBridge()
        value=dict(compose='services:\n  demo:\n    image: example/demo:latest\n    volumes:\n      - ./data/demo/public:/config:ro\n',env='',service_name='',configuration_files=[dict(path='data/demo/public/settings.yaml',content='title: configuration-content-canary\n',mode=0o640)])
        result=bridge.analyze_service(value)
        self.assertTrue(result['ok'],result)
        self.assertEqual(len(result['resources']),1)
        result=bridge.prepare_service(dict(value,reviewed=True,private_names=[],private_values={}))
        self.assertTrue(result['ok'],result)
        self.assertNotIn('configuration-content-canary',json.dumps(result))
        self.assertNotIn('content',result['plan']['configuration_files'][0])
        self.assertEqual(result['plan']['configuration_files'][0]['mode'],0o640)
        self.assertNotIn('configuration-content-canary',json.dumps(bridge._report()))

    def test_recovery_restores_public_config_metadata_without_data_archive(self):
        from remote import service_snapshot as snapshot
        with tempfile.TemporaryDirectory() as directory:
            home=Path(directory); root=home/'stack'; target=root/'data/demo/public/settings.yaml'
            target.parent.mkdir(parents=True); target.write_text('title: Example\n',encoding='utf-8')
            (root/'config').mkdir(); raw=dict(schema=1,resources=[],configuration_files=[dict(path='data/demo/public/settings.yaml',mode=0o640,sha256=snapshot.digest(target))])
            (root/snapshot.INVENTORY).write_text(json.dumps(raw))
            job=recover.Recovery.__new__(recover.Recovery);job.root=root;job.private=home/'private';job.private.mkdir();job.tooling=ROOT/'remote'
            job.services()
            target.write_text('modified')
            with self.assertRaisesRegex(recover.Refused,'SERVICES_STATE_CONFIGURATION_CHANGED'):job.services()

    def test_release_assets_allow_services_extension_only_with_native_base(self):
        base=recover.BUNDLE_FILES
        self.assertEqual(recover.bundle_files(base|{recover.AIO_ASSET,recover.SERVICES_ASSET}),base|{recover.AIO_ASSET,recover.SERVICES_ASSET})
        with self.assertRaisesRegex(recover.Refused,'UNEXPECTED_RELEASE_ASSETS'):
            recover.bundle_files(base|{recover.SERVICES_ASSET})


class ServiceSnapshotPreflight(unittest.TestCase):
    """Use real archives and the pinned preflight; only Docker is simulated."""
    def setUp(self):
        from tests.test_service_snapshot import SnapshotFilesystemTests, RUN, COMMIT
        self.fixture = SnapshotFilesystemTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.root = self.fixture.root
        private = self.root.parent / '.local/share/streams-aio-recovery/private'
        private.mkdir(parents=True)
        self.fixture.archive = private / recover.SERVICES_PLAINTEXT
        self.fixture.capture()
        self.fixture.archive.chmod(0o600)
        self.fixture.empty_targets()
        self.evidence = self.fixture.restore()
        self.evidence.pop('checkpoint')
        self.state = dict(target=str(self.root), tag='dr-' + RUN, public_commit=COMMIT,
                          aio_mode='import', services_snapshot=self.evidence)
        self.manifest = dict(references=[], state_units=[dict(id='service-' + row['id'],
            resource_id=row['id'], services=[row['service']], recovery_asset=recover.SERVICES_ASSET,
            classification='REQUIRED_USER_STATE') for row in self.fixture.value['resources']])
        (self.root / 'scripts').mkdir()
        (self.root / 'scripts/dr.py').write_bytes((ROOT / 'tests/fixtures/pinned_dr_preflight.py').read_bytes())
        (self.root / '.dr-fresh-target.json').write_text(json.dumps({'root': str(self.root)}))
        (self.root / 'config/dr-render-plan.json').write_text(json.dumps({'readiness_blockers': []}))
        self.write_manifest()
        self.logical_aio_marker()
        self.calls = []

    def write_manifest(self):
        (self.root / 'config/dr-manifest.yaml').write_text(json.dumps(self.manifest))

    def logical_aio_marker(self):
        generated = self.root / '.generated'
        generated.mkdir(exist_ok=True)
        (generated / 'aio-import-complete.json').write_text(json.dumps(
            {'root': str(self.root), 'versions': {'aiostreams': '2.35.3', 'aiometadata': '3.3.0'}}))
        for name in ('aiostreams', 'aiometadata'):
            target = self.root / ('data/' + name + '/data/db.sqlite')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'logical importer database fixture')

    def transport(self, arguments, code, **kwargs):
        arguments = list(map(str, arguments))
        self.calls.append(arguments)
        if arguments[:3] == ['docker', 'compose', '--profile']:
            return json.dumps(self.fixture.model).encode()
        return self.fixture.docker(arguments, code)

    def check(self):
        from unittest.mock import patch
        original = Path.read_text
        def read_text(path, *args, **kwargs):
            return 'snapshot-machine' if path.as_posix() == '/etc/machine-id' else original(path, *args, **kwargs)
        with patch.object(recover, 'command', self.transport), patch.object(Path, 'read_text', read_text):
            return recover.stack_preflight(self.root, self.state)

    def test_real_pinned_preflight_accepts_verified_generic_units_with_logical_aio(self):
        self.check()
        self.assertTrue(any(row[:3] == ['docker', 'compose', '--profile'] for row in self.calls))
        self.assertFalse(any(row[0] == recover.sys.executable for row in self.calls))

    def test_checkpoint_alone_missing_evidence_and_scope_changes_refuse_before_preflight(self):
        import copy
        original = copy.deepcopy(self.state)
        for field, value in (('services_snapshot', None), ('tag', 'dr-20261025T195959Z'),
                             ('public_commit', 'f' * 40), ('target', '/foreign')):
            with self.subTest(field=field):
                self.state = dict(original, **{field: value})
                with self.assertRaises(recover.Refused): self.check()
        self.state = original
        for field, value in (('resources', ['one']), ('inventory_sha256', '0' * 64), ('archive_sha256', '0' * 64)):
            with self.subTest(field=field):
                self.state['services_snapshot'] = dict(original['services_snapshot'], **{field: value})
                with self.assertRaisesRegex(recover.Refused, 'SERVICES_STATE_CHECKPOINT_CHANGED'): self.check()
        self.assertEqual(self.calls, [])

    def test_deleted_or_changed_restored_data_cannot_pass_prestart(self):
        path = self.fixture.first / 'nested/file.bin'
        original = path.read_bytes()
        path.write_bytes(b'tampered')
        with self.assertRaisesRegex(recover.Refused, 'SERVICES_STATE_RESTORED_DATA_CHANGED'): self.check()
        path.write_bytes(original)
        path.unlink()
        with self.assertRaisesRegex(recover.Refused, 'SERVICES_STATE_RESTORED_DATA_CHANGED'): self.check()

    def test_raw_inventory_archive_and_public_configuration_are_rechecked(self):
        inventory = self.root / 'config/service-resources.json'
        original = inventory.read_bytes()
        inventory.write_bytes(original + b'\n')
        with self.assertRaisesRegex(recover.Refused, 'SERVICES_STATE_CHECKPOINT_CHANGED'): self.check()
        inventory.write_bytes(original)
        archive_bytes = self.fixture.archive.read_bytes()
        self.fixture.archive.write_bytes(archive_bytes + b'changed')
        with self.assertRaisesRegex(recover.Refused, 'SERVICES_STATE_CHECKPOINT_CHANGED'): self.check()
        self.fixture.archive.write_bytes(archive_bytes)
        configuration = self.root / 'data/demo/public/settings.yaml'
        configuration.parent.mkdir(parents=True)
        configuration.write_bytes(b'title: Public\n')
        configuration.chmod(0o640)
        self.fixture.value['configuration_files'] = [dict(path=configuration.relative_to(self.root).as_posix(),
            mode=0o640, sha256=hashlib.sha256(configuration.read_bytes()).hexdigest())]
        self.fixture.write_inventory()
        # A new public declaration cannot be attached to the old archive/checkpoint.
        with self.assertRaisesRegex(recover.Refused, 'SERVICES_STATE_CHECKPOINT_CHANGED'): self.check()
        configuration.write_bytes(b'changed')
        with self.assertRaisesRegex(recover.Refused, 'SERVICES_STATE_CONFIGURATION_CHANGED'): self.check()

    def test_generic_verification_does_not_hide_legacy_or_foreign_unit_failures(self):
        for unit in (dict(id='npm-routing', classification='REQUIRED_USER_STATE', services=['npm']),
                     dict(id='service-unknown', resource_id='unknown', recovery_asset=recover.SERVICES_ASSET,
                          classification='REQUIRED_USER_STATE', services=['demo']),
                     dict(id='service-one', resource_id='one', recovery_asset='other.age',
                          classification='REQUIRED_USER_STATE', services=['demo']),
                     dict(id='service-one', resource_id='one', recovery_asset=recover.SERVICES_ASSET,
                          classification='REQUIRED_USER_STATE', services=['npm'])):
            with self.subTest(unit=unit):
                original = list(self.manifest['state_units'])
                self.manifest['state_units'].append(unit)
                self.write_manifest()
                with self.assertRaisesRegex(recover.Refused, 'FRESH_RENDERER_REFUSED'): self.check()
                self.manifest['state_units'] = original

    def test_post_start_checks_bindings_without_requiring_unchanged_application_bytes(self):
        (self.fixture.first / 'nested/file.bin').write_bytes(b'application changes its data')
        self.state['application_start_attempted'] = True
        self.check()
        self.state['services_snapshot']['archive_sha256'] = '0' * 64
        with self.assertRaisesRegex(recover.Refused, 'SERVICES_STATE_CHECKPOINT_CHANGED'): self.check()

    def test_no_generic_data_keeps_original_logical_renderer_command(self):
        from unittest.mock import patch
        self.fixture.value['resources'] = []
        self.fixture.write_inventory()
        self.fixture.archive.unlink()
        self.state.pop('services_snapshot')
        with patch.object(recover, 'command', return_value=b'') as command:
            recover.stack_preflight(self.root, self.state)
        self.assertEqual(command.call_count, 1)
        self.assertEqual(command.call_args.args[0], [recover.sys.executable, '-B', self.root / 'scripts/dr.py',
                         'preflight', '--target', self.root, '--mode', 'fresh'])

    def test_native_aio_and_generic_snapshots_both_require_real_renderer_truth(self):
        from unittest.mock import patch
        self.state.update(aio_mode='snapshot', aio_recovery='NATIVE_SNAPSHOT_RESTORED',
                          machine_id='snapshot-machine', completed=['NPM', 'AIO'])
        (self.root / '.generated/aio-import-complete.json').unlink()
        with patch.object(recover, 'verify_aio_snapshot') as verify_aio:
            self.check()
            verify_aio.assert_called_once_with(self.root, self.state)
        self.manifest['state_units'].append(dict(id='npm-routing', services=['npm'], classification='REQUIRED_USER_STATE'))
        self.write_manifest()
        with patch.object(recover, 'verify_aio_snapshot'), self.assertRaisesRegex(recover.Refused, 'FRESH_RENDERER_REFUSED'):
            self.check()

    def test_manual_aio_cannot_exempt_unverified_generic_aio_units(self):
        from unittest.mock import patch
        self.state.update(aio_mode='manual', aio_recovery='MANUAL_PENDING', machine_id='snapshot-machine', completed=['NPM', 'AIO'])
        (self.root / '.generated/aio-import-complete.json').unlink()
        self.check()
        self.manifest['state_units'].append(dict(id='service-unknown', resource_id='unknown',
            recovery_asset=recover.SERVICES_ASSET, classification='REQUIRED_USER_STATE', services=['aiostreams']))
        self.write_manifest()
        with self.assertRaisesRegex(recover.Refused, 'FRESH_RENDERER_REFUSED'): self.check()
        self.manifest['state_units'][-1].pop('resource_id')
        self.manifest['state_units'][-1].pop('recovery_asset')
        self.write_manifest()
        with self.assertRaisesRegex(recover.Refused, 'FRESH_RENDERER_REFUSED'): self.check()


if __name__=='__main__':unittest.main()
"""Bundle deployment transactions against an isolated in-memory VM."""
import copy
import json
import unittest
from unittest.mock import patch

import yaml

from remote import service_onboarding as remote
from tests.test_service_onboarding_remote import FakeEngine, FakeRunner, LAYOUT, MemoryStore, ROOT, COMPOSE, plan, template_keys, private_proof


def bundle():
    first = plan(False)
    first['value_names'] = {}
    service = yaml.safe_load('services:\n' + first['compose_fragment'])['services']['demo']
    service['volumes'] = [dict(type='bind', source='data/demo/state', target='/state', read_only=False),
                          dict(type='bind', source='/var/run/docker.sock', target='/var/run/docker.sock', read_only=True),
                          dict(type='bind', source='data/demo/public/config', target='/config', read_only=True)]
    first['compose_fragment'] = ''.join('  ' + line + '\n' for line in yaml.safe_dump({'demo': service}, sort_keys=False).splitlines())
    second = dict(schema=1, service_name='sidecar', image='example/sidecar:latest',
                  compose_fragment='  sidecar:\n    image: example/sidecar:latest\n    depends_on: [demo]\n    env_file: [./data/sidecar/.env]\n    volumes:\n      - type: volume\n        source: sidecar-state\n        target: /var/lib/sidecar\n        read_only: false\n',
                  public_env_path='data/sidecar/.env', public_env_text='', private_env_path='.secrets/sidecar.env',
                  private_bindings={}, value_names={})
    rows = [dict(id='1'*20, service='demo', type='bind', source='data/demo/state', target='/state',
                 read_only=False, role='data', recovery={'method': 'stopped_archive'}),
            dict(id='2'*20, service='demo', type='bind', source='/var/run/docker.sock', target='/var/run/docker.sock',
                 read_only=True, role='runtime', recovery={'method': 'recreate'}),
            dict(id='3'*20, service='demo', type='bind', source='data/demo/public/config', target='/config',
                 read_only=True, role='external', recovery={'method': 'recreate'}),
            dict(id='4'*20, service='sidecar', type='volume', source='sidecar-state', target='/var/lib/sidecar',
                 read_only=False, role='data', recovery={'method': 'stopped_archive'})]
    return dict({key: value for key, value in first.items() if key != 'value_names'}, schema=2, components=[first, second], service_names=['demo', 'sidecar'],
                images={'demo': first['image'], 'sidecar': second['image']},
                compose_fragment=first['compose_fragment'] + second['compose_fragment'],
                compose_resources={'volumes': {'sidecar-state': {}}}, resources=rows,
                configuration_files=[dict(path='data/demo/public/config/settings.yaml', content='title: Example\n', mode=0o644)])


class BundleRunner(FakeRunner):
    def run(self, args, code, timeout=120, user=False):
        result = super().run(args, code, timeout, user)
        if list(map(str, args))[:3] == ['systemctl', 'restart', remote.AGENT_UNIT]:
            for row in yaml.safe_load(self.store.read(self.agent_config))['templates']:
                keys = template_keys(row['template-content'])
                if keys:
                    self.store.put(row['destination-path'], ''.join(key + "='offline-example-token'\n" for key in keys).encode(),
                                   0, 1001, 0o640)
        return result

    def build_release(self):
        super().build_release()
        self.downloads[remote.SERVICES_ASSET] = b'age-encryption.org/v1\nservices-state'
        manifest = json.loads(self.downloads['manifest.json'])
        manifest['artifacts'][remote.SERVICES_ASSET] = {
            'sha256': remote.digest(self.downloads[remote.SERVICES_ASSET]),
            'size': len(self.downloads[remote.SERVICES_ASSET])}
        manifest['services_inventory_sha256'] = remote.digest(self.store.read(ROOT/'config/service-resources.json'))
        self.downloads['manifest.json'] = json.dumps(manifest).encode()
        self.downloads['SHA256SUMS'] = ''.join(remote.digest(raw) + '  ' + name + '\n'
            for name, raw in self.downloads.items() if name != 'SHA256SUMS').encode()
        self.assets = [{'id': index + 1, 'name': name, 'size': len(raw), 'state': 'uploaded'}
                       for index, (name, raw) in enumerate(self.downloads.items())]
        self.release['assets'] = self.assets


class BundleRemoteTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.store.put(remote.PurePosixPath('/usr/local/sbin/streams-aio-services-dr-backup'), b'# installed\n', 1001, 1001, 0o640)
        self.runner = BundleRunner(self.store)
        self.engine = FakeEngine(LAYOUT, self.runner, self.store)
        self.selected = bundle()
        self.request = dict(action='apply', root=str(ROOT), plan=self.selected, project_id='example-project',
                            environment='prod', probe_url='', job_id='5'*32)

    def apply(self):
        self.request['fingerprint'] = self.engine.inspect(self.request)['fingerprint']
        self.request['private_proof'] = private_proof(self.request['plan'])
        return self.engine.apply(self.request)

    def test_bundle_merged_with_existing_services_and_top_level_resources(self):
        merged = remote.merge_compose(COMPOSE, self.selected)
        self.assertTrue(merged.startswith(COMPOSE[:COMPOSE.index(b'networks:')]))
        self.assertIn(b'# existing comment', merged)
        parsed = yaml.safe_load(merged)
        self.assertEqual(set(parsed['services']), {'redis', 'demo', 'sidecar'})
        self.assertEqual(parsed['networks'], yaml.safe_load(COMPOSE)['networks'])
        self.assertEqual(parsed['volumes'], {'sidecar-state': {}})

    def test_apply_creates_public_configs_and_inventory_then_starts_only_new_services(self):
        result = self.apply()
        self.assertEqual(result['status'], 'SERVICE_READY')
        self.assertEqual(result['services'], ['demo', 'sidecar'])
        self.assertEqual(self.store.read(ROOT/'data/demo/public/config/settings.yaml'), b'title: Example\n')
        inventory = json.loads(self.store.read(ROOT/'config/service-resources.json'))
        self.assertEqual(len(inventory['resources']), 4)
        self.assertNotIn('content', inventory['configuration_files'][0])
        up = next(args for args, _ in self.runner.calls if 'up' in args)
        self.assertEqual(up[-3:], ['--', 'demo', 'sidecar'])
        self.assertNotIn('redis', up)
        self.assertIn((['test', '-S', '/var/run/docker.sock'], False), self.runner.calls)

    def test_config_failure_rolls_back_every_file_and_retains_existing_bytes(self):
        self.runner.fail_config = True
        self.assertEqual(self.apply()['code'], 'ONBOARDING_COMPOSE_COMMAND_FAILED')
        journal = self.store.json(self.engine.journal_path(self.request['job_id']))
        self.assertEqual(journal['phase'], 'ROLLED_BACK')
        self.assertEqual(self.store.read(ROOT/'docker-compose.yml'), COMPOSE)
        for path in ('data/demo/.env', 'data/sidecar/.env', 'data/demo/public/config/settings.yaml', 'config/service-resources.json'):
            self.assertFalse(self.store.exists(ROOT/path))
        self.assertFalse(self.runner.started)

    def test_declared_image_volume_requires_deterministic_mount(self):
        self.runner.image_volumes = {'/uncovered': {}}
        result = self.apply()
        self.assertEqual(result['code'], 'ONBOARDING_ANONYMOUS_VOLUME_MAPPING_REQUIRED')
        self.assertFalse(self.runner.started)

    def test_mapped_image_volume_is_allowed(self):
        self.runner.image_volumes = {'/state': {}}
        self.selected['components'][1]['image'] = self.selected['components'][0]['image']
        self.selected['images']['sidecar'] = self.selected['images']['demo']
        # Keep both image declarations covered independently.
        self.selected['components'][1]['compose_fragment'] = self.selected['components'][1]['compose_fragment'].replace('example/sidecar:latest', 'example/demo:latest').replace('/var/lib/sidecar', '/state')
        self.selected['resources'][3]['target'] = '/state'
        self.selected['compose_fragment'] = ''.join(child['compose_fragment'] for child in self.selected['components'])
        self.assertEqual(self.apply()['status'], 'SERVICE_READY')

    def test_existing_definition_conflicts_and_path_traversal_are_closed_errors(self):
        self.selected['compose_resources']['networks'] = {'default': {'driver': 'host'}}
        with self.assertRaisesRegex(remote.Refused, 'ONBOARDING_COMPOSE_RESOURCE_CONFLICT'):
            self.engine.inspect(self.request)
        self.selected = bundle(); self.request['plan'] = self.selected
        self.selected['configuration_files'][0]['path'] = 'data/demo/../../escape'
        with self.assertRaisesRegex(remote.Refused, 'ONBOARDING_RESOURCE_PATH_INVALID'):
            self.engine.inspect(self.request)

    def test_resource_inventory_must_match_actual_mount(self):
        self.selected['resources'][0]['source'] = 'data/demo/not-the-compose-source'
        with self.assertRaisesRegex(remote.Refused, 'ONBOARDING_MOUNT_INVENTORY_MISMATCH'):
            self.engine.inspect(self.request)

    def test_persistent_bundle_requires_installed_backup_capability_before_mutation(self):
        del self.store.files[str(remote.PurePosixPath('/usr/local/sbin/streams-aio-services-dr-backup'))]
        with self.assertRaisesRegex(remote.Refused, 'ONBOARDING_RESOURCE_BACKUP_CAPABILITY_REQUIRED'):
            self.engine.inspect(self.request)
        self.assertEqual(self.store.read(ROOT/'docker-compose.yml'), COMPOSE)
        self.assertFalse(self.store.writes)

    def test_inspect_returns_only_config_hashes_and_paths(self):
        with patch.object(remote, 'Engine', FakeEngine):
            public = remote.handle(dict(self.request, action='inspect'), runner=self.runner, store=self.store, layout=LAYOUT)
        self.assertEqual(public['status'], 'PREVIEW')
        self.assertNotIn('title: Example', json.dumps(public))
        self.assertIn('data/demo/public/config/settings.yaml', public['public_files'])

    def test_private_components_render_separate_env_files_with_original_keys(self):
        aggregate = {}
        for child in self.selected['components']:
            child['private_bindings'] = {'ApiToken': {'folder': '/' + child['service_name'], 'key': 'ApiToken'}}
            global_id = child['service_name'].upper() + '_ApiToken'
            child['value_names'] = {'ApiToken': global_id}
            aggregate[global_id] = child['private_bindings']['ApiToken']
            document = yaml.safe_load('services:\n' + child['compose_fragment'])
            document['services'][child['service_name']]['env_file'].append('./' + child['private_env_path'])
            child['compose_fragment'] = ''.join('  ' + line + '\n' for line in yaml.safe_dump(document['services'], sort_keys=False).splitlines())
        self.selected['private_bindings'] = aggregate
        self.selected['compose_fragment'] = ''.join(child['compose_fragment'] for child in self.selected['components'])
        self.assertEqual(self.apply()['status'], 'SERVICE_READY')
        for child in self.selected['components']:
            output = self.store.read(ROOT/child['private_env_path'])
            self.assertEqual(output, b"ApiToken='offline-example-token'\n")
        self.assertNotIn('offline-example-token', json.dumps(self.engine.safe_result(
            self.store.json(self.engine.journal_path(self.request['job_id'])))))

    def test_finalize_requires_encrypted_resource_asset_and_exact_inventory_binding(self):
        self.assertEqual(self.apply()['status'], 'SERVICE_READY')
        path = self.engine.journal_path(self.request['job_id'])
        journal = self.store.json(path)
        journal.update(phase='PUBLIC_PUBLISHED', public_commit=self.runner.public_commit)
        self.engine.save(journal)
        self.runner.public_files['config/service-resources.json'] = self.store.read(ROOT/'config/service-resources.json')
        with patch.object(self.engine, 'public_readback'):
            self.assertEqual(self.engine.finalize(self.request)['status'], 'BACKUP_RUNNING')
            result = self.engine.finalize(self.request)
        self.assertEqual(result['status'], 'COMPLETE')
        self.assertTrue(result['backup_integrity_verified'])
        journal = self.store.json(path)
        self.assertIn(remote.SERVICES_ASSET, journal['backup_assets'])

    def test_finalize_refuses_resource_inventory_not_bound_to_release(self):
        self.assertEqual(self.apply()['status'], 'SERVICE_READY')
        path = self.engine.journal_path(self.request['job_id'])
        journal = self.store.json(path)
        journal.update(phase='PUBLIC_PUBLISHED', public_commit=self.runner.public_commit)
        self.engine.save(journal)
        with patch.object(self.engine, 'public_readback'):
            self.engine.finalize(self.request)
            manifest = json.loads(self.runner.downloads['manifest.json'])
            manifest.pop('services_inventory_sha256')
            self.runner.downloads['manifest.json'] = json.dumps(manifest).encode()
            for row in self.runner.assets:
                if row['name'] == 'manifest.json':
                    row['size'] = len(self.runner.downloads['manifest.json'])
            with self.assertRaisesRegex(remote.Refused, 'ONBOARDING_BACKUP_RESOURCE_COVERAGE_MISMATCH'):
                self.engine.finalize(self.request)

    def test_data_resource_cannot_masquerade_as_runtime(self):
        self.selected['resources'][0].update(role='runtime', recovery={'method': 'recreate'})
        with self.assertRaisesRegex(remote.Refused, 'ONBOARDING_RUNTIME_POLICY_INVALID'):
            self.engine.inspect(self.request)


if __name__ == '__main__':
    unittest.main()



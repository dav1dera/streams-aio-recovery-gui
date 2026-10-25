"""Offline storage fixtures; no filesystem or Docker access."""
import unittest

from recovery_gui.service_resources import ResourceFailure, inventory


class ServiceResourceTests(unittest.TestCase):
    def plan(self, mounts, **kwargs):
        return inventory({'demo': {'image': 'example/demo:latest', 'volumes': mounts}}, **kwargs)

    def test_bind_named_anonymous_and_runtime_are_distinct(self):
        result = self.plan(['./data/demo/store:/store', 'cache:/cache', '/scratch',
                            '/var/run/docker.sock:/var/run/docker.sock:ro', '/proc:/host/proc:ro'])
        resources = result['resources']
        self.assertEqual([r['type'] for r in resources], ['bind', 'volume', 'volume', 'bind', 'bind'])
        self.assertEqual([r['recovery']['method'] for r in resources],
                         ['stopped_archive', 'stopped_archive', 'stopped_archive', 'recreate', 'recreate'])
        self.assertEqual(resources[0]['source'], 'data/demo/store')
        self.assertEqual(resources[3]['role'], 'runtime')
        self.assertEqual(set(result['compose_resources']['volumes']), {'cache', resources[2]['source']})
        self.assertEqual(result, self.plan(['./data/demo/store:/store', 'cache:/cache', '/scratch',
                                         '/var/run/docker.sock:/var/run/docker.sock:ro', '/proc:/host/proc:ro']))

    def test_long_mounts_tmpfs_and_external_volume(self):
        result = self.plan([
            {'type': 'bind', 'source': './data/demo/state', 'target': '/state', 'bind': {'create_host_path': False}},
            {'type': 'volume', 'source': 'existing', 'target': '/existing', 'volume': {'nocopy': True, 'subpath': 'nested'}},
            {'type': 'tmpfs', 'target': '/tmp', 'tmpfs': {'size': '64m', 'mode': 0o1777}},
        ], compose_resources={'volumes': {'existing': {'external': True}}})
        self.assertEqual([r['recovery']['method'] for r in result['resources']],
                         ['stopped_archive', 'external', 'recreate'])
        self.assertEqual(result['services']['demo']['volumes'][0]['source'], 'data/demo/state')

    def test_public_files_covered_by_directory_or_compose_config(self):
        files = [{'path': 'data/demo/public/settings/settings.yaml', 'content': 'title: Demo\n', 'mode': '0644'},
                 {'path': 'data/demo/public/extra.ini', 'content': '[demo]\n', 'mode': 0o640}]
        result = inventory({'demo': {'image': 'example/demo', 'volumes': ['./data/demo/public/settings:/config:ro'],
                                    'configs': [{'source': 'extra', 'target': '/etc/demo/extra.ini'}]}},
                           {'configs': {'extra': {'file': './data/demo/public/extra.ini'}}}, files)
        self.assertEqual([r['recovery']['method'] for r in result['resources']], ['recreate', 'recreate'])
        self.assertEqual(result['configuration_files'][0]['mode'], 0o644)
        self.assertEqual(len(result['configuration_files'][0]['sha256']), 64)
        self.assertEqual(result['compose_resources']['configs']['extra']['file'], './data/demo/public/extra.ini')

    def test_invalid_paths_and_configuration_are_closed(self):
        for mount in ['../outside:/state', './data/demo/../../outside:/state', '/x:/same', {'type': 'bind', 'source': 'x', 'target': 'relative'}]:
            with self.subTest(mount=mount):
                with self.assertRaises(ResourceFailure):
                    self.plan([mount])
        with self.assertRaisesRegex(ResourceFailure, '^SERVICE_MOUNT_TARGET_DUPLICATE$'):
            self.plan(['cache:/same', 'other:/same'])
        for path in ['../outside', '/etc/settings', 'data/other/settings.yaml', 'data/demo/.env', 'data/demo/.secrets/x']:
            with self.subTest(path=path):
                with self.assertRaises(ResourceFailure):
                    self.plan(['./data/demo:/config:ro'], files=[{'path': path, 'content': 'public'}])
        with self.assertRaisesRegex(ResourceFailure, '^SERVICE_CONFIGURATION_NOT_MOUNTED$'):
            self.plan([], files=[{'path': 'data/demo/public/public.yaml', 'content': 'public'}])

    def test_policies_cannot_mislabel_runtime_or_data(self):
        for policy in [{'service': 'demo', 'target': '/state', 'method': 'recreate'},
                       {'service': 'demo', 'target': '/state', 'method': 'recreate', 'role': 'runtime'},
                       {'service': 'demo', 'target': '/state', 'method': 'recreate', 'role': 'config'}]:
            with self.subTest(policy=policy):
                with self.assertRaises(ResourceFailure):
                    self.plan(['./data/demo/state:/state'], policies=[policy])
        with self.assertRaisesRegex(ResourceFailure, '^SERVICE_RUNTIME_ARCHIVE_REFUSED$'):
            self.plan(['/var/run/docker.sock:/socket:ro'],
                      policies=[{'service': 'demo', 'target': '/socket', 'method': 'stopped_archive'}])
        with self.assertRaisesRegex(ResourceFailure, '^SERVICE_DATA_RESOURCE_OUTSIDE_STACK$'):
            self.plan(['/srv/state:/state'])
        result = self.plan(['/srv/state:/state'], policies=[{'service': 'demo', 'target': '/state', 'method': 'external'}])
        self.assertEqual(result['resources'][0]['role'], 'external')
        self.assertEqual(result['resources'][0]['recovery']['method'], 'external')

    def test_public_seeded_configuration_cannot_overlap_archive_data(self):
        with self.assertRaisesRegex(ResourceFailure, '^SERVICE_CONFIGURATION_DATA_OVERLAP$'):
            self.plan(['./data/demo:/state'])
        with self.assertRaisesRegex(ResourceFailure, '^SERVICE_CONFIGURATION_DATA_OVERLAP$'):
            self.plan(['./data/demo/public:/state', './data/demo/public/settings.yaml:/settings:ro'],
                      files=[{'path': 'data/demo/public/settings.yaml', 'content': 'public'}])
        with self.assertRaisesRegex(ResourceFailure, '^SERVICE_CONFIGURATION_NOT_MOUNTED$'):
            self.plan(['./data/demo/public/settings.yaml:/settings'],
                      files=[{'path': 'data/demo/public/settings.yaml', 'content': 'public'}])

    def test_nonlocal_volume_requires_explicit_external_policy(self):
        for definition in ({'driver': 'nfs'}, {'driver_opts': {'type': 'nfs', 'device': ':/data'}}):
            with self.subTest(definition=definition):
                with self.assertRaisesRegex(ResourceFailure, '^SERVICE_VOLUME_DRIVER_UNSUPPORTED$'):
                    self.plan(['remote:/data'], compose_resources={'volumes': {'remote': definition}})
                result = self.plan(['remote:/data'], compose_resources={'volumes': {'remote': definition}},
                                   policies=[{'service': 'demo', 'target': '/data', 'method': 'external'}])
                self.assertEqual(result['resources'][0]['recovery']['method'], 'external')

    def test_policy_alias_and_unknown_target(self):
        policy = {'service': 'demo', 'target': '/state', 'recovery': {'method': 'stopped_archive'}}
        self.assertEqual(self.plan(['./data/demo/state:/state'], policies=[policy])['resources'][0]['role'], 'data')
        with self.assertRaisesRegex(ResourceFailure, '^SERVICE_STORAGE_POLICY_TARGET_MISSING$'):
            self.plan([], policies=[policy])


if __name__ == '__main__':
    unittest.main()


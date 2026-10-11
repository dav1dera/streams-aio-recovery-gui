"""Ordinary local inputs survive deletion from Infisical; credentials stay live."""
import ast
import importlib.util
from pathlib import Path
from types import SimpleNamespace as N
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('local_input_recovery', ROOT / 'remote/recover.py')
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class LocalInputs(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.plan = dict(required_values=['/stack-network/DEFAULT_SUBNET', '/service/API_KEY',
                                          '/service/BASE_URL'],
                         service_folder_exports={}, env_files={}, additional_input_folders=[])
        self.local = {'/stack-network/DEFAULT_SUBNET': '172.22.0.0/24',
                      '/service/BASE_URL': 'https://service.example.invalid'}
        self.remote = {'/stack-network': {'DEFAULT_SUBNET': '172.22.0.0/24'},
                       '/service': {'API_KEY': 'private-canary',
                                    'BASE_URL': 'https://service.example.invalid'}}
        def read(**kwargs):
            folder = kwargs['secret_path']
            self.calls.append(folder)
            return N(imports=[], secrets=[N(secretKey=k, secretValue=v, secretValueHidden=False)
                                          for k, v in self.remote[folder].items()])
        self.client = N(secrets=N(list_secrets=read))
        self.dr = N(all_paths=lambda plan: sorted({ref.rsplit('/', 1)[0]
                                                   for ref in plan['required_values']}),
                    folder_file=lambda folder: folder.lstrip('/') + '.goenv')

    def run_inputs(self, local_values=None):
        return recovery.collect_inputs(self.plan, self.dr, self.client, 'project', 'prod',
                                       local_values=local_values)

    @staticmethod
    def decode(raw):
        return {line.partition('=')[0]: ast.literal_eval(line.partition('=')[2])
                for line in raw.decode().splitlines()}

    def test_legacy_backup_reads_every_folder(self):
        self.run_inputs()
        self.assertEqual(set(self.calls), {'/stack-network', '/service'})

    def test_deleted_configuration_restored_while_credentials_stay_live(self):
        del self.remote['/stack-network']
        del self.remote['/service']['BASE_URL']
        result = self.run_inputs(self.local)
        self.assertEqual(self.calls, ['/service'])
        self.assertEqual(self.decode(result['stack-network.goenv']),
                         {'DEFAULT_SUBNET': '172.22.0.0/24'})
        self.assertEqual(self.decode(result['service.goenv']),
                         {'API_KEY': 'private-canary', 'BASE_URL': 'https://service.example.invalid'})

    def test_equal_duplicates_in_mixed_folder_are_accepted(self):
        result = self.run_inputs(self.local)
        self.assertEqual(self.decode(result['service.goenv'])['BASE_URL'], self.local['/service/BASE_URL'])

    def test_conflicting_duplicates_stop_without_value_in_error(self):
        self.remote['/service']['BASE_URL'] = 'https://private-canary.invalid'
        with self.assertRaisesRegex(recovery.Refused, '^LOCAL_CONFIG_CONFLICT$'):
            self.run_inputs(self.local)

    def test_dynamic_aio_folder_is_always_read_and_keeps_new_secrets(self):
        self.plan['required_values'] = ['/aiostreams/BASE_URL']
        self.plan['service_folder_exports'] = {
            '.secrets/aiostreams.env': {'path': '/aiostreams', 'overrides': {}}}
        self.remote = {'/aiostreams': {'NEW_API_KEY': 'new-private-canary'}}
        result = self.run_inputs({'/aiostreams/BASE_URL': 'https://aio.example.invalid'})
        self.assertEqual(self.calls, ['/aiostreams'])
        self.assertEqual(self.decode(result['aiostreams.goenv']),
                         {'NEW_API_KEY': 'new-private-canary', 'BASE_URL': 'https://aio.example.invalid'})

    def test_unknown_local_reference_is_refused_before_api(self):
        with self.assertRaisesRegex(recovery.Refused, '^LOCAL_CONFIG_REFERENCE_NOT_APPROVED$'):
            self.run_inputs({'/unknown/BASE_URL': 'https://unknown.example.invalid'})
        self.assertFalse(self.calls)


if __name__ == '__main__':
    unittest.main()

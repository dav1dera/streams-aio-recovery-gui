"""Relocation edits only topology-proven application endpoint fields."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location('local_endpoint_tests',
    Path(__file__).parents[1] / 'remote/local_endpoints.py')
local = importlib.util.module_from_spec(spec)
spec.loader.exec_module(local)


@unittest.skipUnless(os.name == 'nt' or os.geteuid() == 0, 'Linux integration requires root ownership')
class LocalEndpoints(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'stack'
        self.home = Path(temporary.name) / 'recovery'
        self.root.mkdir()
        self.home.mkdir(mode=0o700)
        self.state = {'npm_upstream_targets': {'stack': '192.0.2.71', 'infisical': '192.0.2.72'}}
        (self.home / 'state.json').write_text(json.dumps(self.state))
        (self.home / 'state.json').chmod(0o600)
        self.context = {'schema': 1, 'topology_sha256': 'a' * 64, 'mapping': {
            '192.0.2.41': '192.0.2.71', '192.0.2.42': '192.0.2.71', '192.0.2.51': '192.0.2.72',
            'fd00::41': 'fd00::71'}}
        self.headscale = {'server_url': 'https://headscale.example.invalid', 'private_field': 'canary-secret',
            'dns': {'nameservers': {'global': ['192.0.2.41']}, 'extra_records': [
                {'name': 'app.example.invalid', 'type': 'A', 'value': '192.0.2.41'},
                {'name': 'secrets.example.invalid', 'type': 'A', 'value': '192.0.2.51'},
                {'name': 'ipv6.example.invalid', 'type': 'AAAA', 'value': 'fd00::41'},
                {'name': 'external.example.invalid', 'type': 'A', 'value': '192.0.2.61'},
                {'name': 'txt.example.invalid', 'type': 'TXT', 'value': '192.0.2.41'}]}}
        self.honey = {'ui': {'href': 'http://192.0.2.41/ui', 'trusted_domains': ['192.0.2.41']}, 'services': [
            {'name': 'stack', 'href': 'HTTP://192.0.2.42:09000/a%2Fb?q=192.0.2.41#f', 'icon': 'http://192.0.2.41/icon'},
            {'name': 'infisical', 'href': 'https://192.0.2.51:8443/path?x=1'},
            {'name': 'ipv6', 'href': 'http://[fd00::41]:81/'},
            {'name': 'external', 'href': 'http://192.0.2.61:90/'},
            {'name': 'hostname', 'href': 'https://app.example.invalid/192.0.2.41'},
            {'name': 'empty', 'href': '#'}]}
        self.write('headscale', self.headscale)
        self.write('honey', self.honey)
        self.runner = Mock(side_effect=AssertionError('No external command is authorized'))

    def path(self, service):
        return self.root / local.FILES[service]

    def write(self, service, value):
        path = self.path(service)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2), encoding='utf-8')
        path.chmod(0o660)
        if os.name != 'nt':
            os.chown(path, 1000, 1000)

    def save(self, path, value):
        self.assertEqual(path, self.home / 'state.json')
        local.atomic(path, local.encoded(value), {'uid': 0, 'gid': 0, 'mode': 0o600})

    def apply(self):
        with patch.object(local, 'topology', return_value=copy.deepcopy(self.context)):
            return local.apply(self.root, self.home, self.state, self.runner, self.save)

    def test_verified_source_roles_are_mapped_without_other_dns_or_link_changes(self):
        before_metadata = {name: local.metadata(self.path(name)) for name in local.FILES}
        result = self.apply()
        self.assertEqual(result['rewritten'], ['headscale', 'honey'])
        self.assertEqual(result['changed_files'], 2)
        expected_headscale = copy.deepcopy(self.headscale)
        for record, target in zip(expected_headscale['dns']['extra_records'],
                                  ['192.0.2.71', '192.0.2.72', 'fd00::71']):
            record['value'] = target
        expected_honey = copy.deepcopy(self.honey)
        for entry, value in zip(expected_honey['services'], [
            'HTTP://192.0.2.71:09000/a%2Fb?q=192.0.2.41#f',
            'https://192.0.2.72:8443/path?x=1', 'http://[fd00::71]:81/']):
            entry['href'] = value
        self.assertEqual(json.loads(self.path('headscale').read_bytes()), expected_headscale)
        self.assertEqual(json.loads(self.path('honey').read_bytes()), expected_honey)
        self.assertEqual({name: local.metadata(self.path(name)) for name in local.FILES}, before_metadata)
        journal = (self.home / local.JOURNAL).read_bytes()
        self.assertNotIn(b'canary-secret', journal)
        self.assertNotIn(b'example.invalid', journal)
        self.assertEqual(json.loads(journal)['phase'], 'complete')
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE((self.home / local.JOURNAL).stat().st_mode), 0o600)
            self.assertEqual((self.home / local.JOURNAL).stat().st_uid, 0)
        self.runner.assert_not_called()

    def test_completed_apply_is_idempotent_and_refuses_any_later_file_drift(self):
        first = self.apply()
        before = {name: (self.path(name).read_bytes(), self.path(name).stat().st_ino) for name in local.FILES}
        result = self.apply()
        self.assertEqual(result['rewritten'], [])
        self.assertEqual(result['sha256'], first['sha256'])
        self.assertEqual({name: (self.path(name).read_bytes(), self.path(name).stat().st_ino)
                          for name in local.FILES}, before)
        drift = json.loads(self.path('honey').read_bytes())
        drift['ui']['trusted_domains'] = ['other.example.invalid']
        self.write('honey', drift)
        with self.assertRaisesRegex(ValueError, '^' + local.DRIFT + '$'):
            self.apply()

    def test_partial_atomic_write_resumes_using_closed_before_after_hashes(self):
        original = local.atomic
        def interrupted(path, raw, identity):
            if path == self.path('honey'):
                raise OSError('private detail must be sanitized')
            original(path, raw, identity)
        with patch.object(local, 'atomic', side_effect=interrupted), self.assertRaisesRegex(ValueError, '^' + local.ERROR + '$'):
            self.apply()
        self.assertEqual(json.loads((self.home / local.JOURNAL).read_bytes())['phase'], 'planned')
        self.assertEqual(json.loads(self.path('headscale').read_bytes())['dns']['extra_records'][0]['value'], '192.0.2.71')
        self.assertNotIn('local_endpoints', self.state)
        result = self.apply()
        self.assertEqual(result['rewritten'], ['honey'])
        self.assertEqual(json.loads((self.home / local.JOURNAL).read_bytes())['phase'], 'complete')

    def test_changed_plan_and_missing_proof_refuse_before_any_write(self):
        self.apply()
        before = self.path('honey').read_bytes()
        self.context['mapping']['192.0.2.41'] = '192.0.2.99'
        with self.assertRaisesRegex(ValueError, '^' + local.ERROR + '$'):
            self.apply()
        self.assertEqual(self.path('honey').read_bytes(), before)
        with patch.object(local, 'topology', side_effect=ValueError('private detail')):
            with self.assertRaisesRegex(ValueError, '^' + local.ERROR + '$'):
                local.apply(self.root, self.home, self.state, self.runner, self.save)

    def test_hardlinked_application_file_is_refused_without_modification(self):
        alias = self.root / 'linked-config'
        before = self.path('honey').read_bytes()
        original_stat = Path.stat
        def linked_stat(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            if path == self.path('honey'):
                return os.stat_result((*info[:3], 2, *info[4:]))
            return info
        # Windows sandbox cannot create hard links; exercise the same kernel
        # metadata refusal there, while Linux uses a real hard-linked file.
        if os.name == 'nt':
            with patch.object(Path, 'stat', linked_stat), self.assertRaisesRegex(ValueError, '^' + local.ERROR + '$'):
                self.apply()
        else:
            os.link(self.path('honey'), alias)
            with self.assertRaisesRegex(ValueError, '^' + local.ERROR + '$'):
                self.apply()
        self.assertFalse((self.home / local.JOURNAL).exists())
        self.assertEqual(self.path('honey').read_bytes(), before)

    def test_source_addresses_come_only_from_operational_topology_proof(self):
        policy = SimpleNamespace(topology_targets=Mock())
        proof = SimpleNamespace(address=lambda address: address, fingerprint=lambda value: 'b' * 64)
        value = {'source': {'stack_addresses': ['192.0.2.111', '192.0.2.112'],
                            'infisical_address': '192.0.2.113'}}
        policy.topology_targets.return_value = (proof, value, {'targets': self.state['npm_upstream_targets']}, [])
        loader = SimpleNamespace(exec_module=lambda module: None)
        with patch.object(local.importlib.util, 'spec_from_file_location', return_value=SimpleNamespace(loader=loader)), \
                patch.object(local.importlib.util, 'module_from_spec', return_value=policy):
            context = local.topology(self.root, self.state)
        policy.topology_targets.assert_called_once_with(self.root, self.state)
        self.assertEqual(context['mapping'], {'192.0.2.111': '192.0.2.71',
            '192.0.2.112': '192.0.2.71', '192.0.2.113': '192.0.2.72'})


if __name__ == '__main__':
    unittest.main()

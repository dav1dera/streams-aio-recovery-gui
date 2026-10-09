"""NPM relocation changes only exact, source-proven local structured hosts."""
import copy
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('npm_topology_tests',
    Path(__file__).parents[1] / 'remote/npm_topology.py')
topology = importlib.util.module_from_spec(spec); spec.loader.exec_module(topology)


@contextmanager
def database(path):
    db = sqlite3.connect(path)
    try:
        with db:
            yield db
    finally:
        db.close()


@unittest.skipUnless(os.name == 'nt' or os.geteuid() == 0,
                     'Real root-private topology integration runs in the dedicated CI ownership step')
class NPMTopology(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / topology.DATABASE
        self.db.parent.mkdir(parents=True)
        (self.root / '.generated').mkdir()
        self.model = {'services': {
            'gluetun': {'ports': [{'published': '8765', 'target': 8765, 'protocol': 'tcp'}],
                        'networks': {'default': {'ipv4_address': '172.20.0.2'}}},
            'aiostreams': {'container_name': 'aio', 'ports': [{'published': '3100', 'target': 3000}],
                          'networks': {'default': {'aliases': ['aio-app']}}},
            'npm': {'ports': [{'published': '443', 'target': 443}]}}}
        with database(self.db) as db:
            db.executescript('''
                CREATE TABLE proxy_host(id INTEGER PRIMARY KEY,is_deleted INTEGER,domain_names TEXT,
                  forward_host TEXT,forward_port INTEGER,forward_scheme TEXT,locations TEXT,advanced_config TEXT,
                  enabled INTEGER,certificate_id INTEGER,ssl_forced INTEGER,access_list_id INTEGER);
                CREATE TABLE stream(id INTEGER PRIMARY KEY,is_deleted INTEGER,
                  forwarding_host TEXT,forwarding_port INTEGER);
            ''')
            fixtures = [
                (1, '192.0.2.11', 8765, []),
                (2, '192.0.2.28', 80, []),
                (3, '192.0.2.2', 8006, []),
                (4, 'aio', 3000, [{'path': '/alt', 'forward_host': '192.0.2.11',
                                  'forward_port': 3100, 'forward_scheme': 'http', 'advanced_config': ''}]),
                (5, '172.20.0.2', 8765, []),
            ]
            for identity, host, port, locations in fixtures:
                db.execute('INSERT INTO proxy_host VALUES(?,0,?,?,?,\'http\',?,\'\',0,1,1,7)',
                           (identity, json.dumps(['synthetic-' + str(identity) + '.example.invalid']),
                            host, port, json.dumps(locations)))
            db.execute('INSERT INTO stream VALUES(8,0,\'192.0.2.11\',3100)')
        self.db.chmod(0o600)
        if os.name != 'nt' and os.geteuid() == 0:
            os.chown(self.db,1000,1000)
        self.targets = {'stack': '192.0.2.29', 'infisical': '192.0.2.30'}
        self.value = self.capture()

    def capture(self):
        return topology.capture(self.db, self.model, stack_commit='a' * 40,
            stack_addresses=['192.0.2.11'], infisical_address='192.0.2.28', infisical_port=80)

    def runner(self, args):
        self.assertEqual(args, ['docker', 'ps', '-aq'])
        return b''

    def test_classifies_owned_published_ports_and_preserves_external_private_endpoint(self):
        report = topology.report(self.value)
        self.assertEqual(report['bindings'], {'compose': 2, 'external': 1, 'infisical': 1, 'stack': 3})
        self.assertNotIn('192.0.2.', json.dumps(report))
        self.assertNotIn('.example.invalid', json.dumps(report))
        self.assertEqual(next(r for r in report['rows'] if r['id'] == 1)['service'], 'gluetun')

    def test_preparation_changes_only_local_host_fields_and_custom_location(self):
        evidence = topology.prepare(self.root, self.value, self.targets, self.runner)
        saved = topology.verify(self.root, evidence, stack_commit='a' * 40)
        self.assertEqual(evidence['changed_rows'], 4)
        after = {r['id']: r['routing'] for r in saved['after']}
        self.assertEqual(after[1]['forward_host'], self.targets['stack'])
        self.assertEqual(after[2]['forward_host'], self.targets['infisical'])
        self.assertEqual(after[3]['forward_host'], '192.0.2.2')
        self.assertEqual(after[4]['forward_host'], 'aio')
        self.assertEqual(after[4]['locations'][0]['forward_host'], self.targets['stack'])
        self.assertEqual(after[5]['forward_host'], '172.20.0.2')
        self.assertEqual(after[8]['forwarding_host'], self.targets['stack'])
        with database(self.db) as db:
            self.assertEqual(db.execute('SELECT enabled,certificate_id,ssl_forced,access_list_id '
                                       'FROM proxy_host WHERE id=1').fetchone(), (0, 1, 1, 7))
        again = topology.prepare(self.root, self.value, self.targets, self.runner)
        self.assertEqual(again, evidence)

    def test_unknown_source_host_port_is_not_inferred_or_rewritten(self):
        with database(self.db) as db:
            db.execute('UPDATE proxy_host SET forward_port=9999 WHERE id=1')
        with self.assertRaisesRegex(topology.Refused, '^NPM_TOPOLOGY_ENDPOINT_UNPROVEN$'):
            self.capture()

    def test_ambiguous_published_port_is_refused(self):
        self.model['services']['other'] = {'ports': [{'published': '8765', 'target': 8765}]}
        with self.assertRaisesRegex(topology.Refused, '^NPM_TOPOLOGY_ENDPOINT_UNPROVEN$'):
            self.capture()

    def test_unassigned_single_label_hostname_is_refused(self):
        with database(self.db) as db:
            db.execute('UPDATE proxy_host SET forward_host=\'not-owned\' WHERE id=3')
        with self.assertRaisesRegex(topology.Refused, '^NPM_TOPOLOGY_SERVICE_UNPROVEN$'):
            self.capture()

    def test_original_ip_in_advanced_config_needs_explicit_mapping_review(self):
        with database(self.db) as db:
            db.execute('UPDATE proxy_host SET advanced_config=? WHERE id=1',
                       ('proxy_pass http://192.0.2.11:8765;',))
        with self.assertRaisesRegex(topology.Refused, '^NPM_TOPOLOGY_UNCLASSIFIED_REFERENCE$'):
            self.capture()

    def test_local_ip_nested_snippet_is_not_replaced_as_text(self):
        with database(self.db) as db:
            location = {'path': '/', 'forward_host': 'aio', 'forward_port': 3000,
                        'forward_scheme': 'http', 'advanced_config': 'set $auth http://192.0.2.28/;'}
            db.execute('UPDATE proxy_host SET locations=? WHERE id=4', (json.dumps([location]),))
        with self.assertRaisesRegex(topology.Refused, '^NPM_TOPOLOGY_UNCLASSIFIED_REFERENCE$'):
            self.capture()

    def test_entire_routing_inventory_is_covered_including_external_hosts(self):
        changed = copy.deepcopy(self.value)
        changed['bindings'].pop()
        with self.assertRaisesRegex(topology.Refused, '^NPM_TOPOLOGY_INVALID$'):
            topology.validate(changed, stack_commit='a' * 40)
        changed = copy.deepcopy(self.value)
        changed['routes'][2]['routing']['forward_host'] = 'changed.example.invalid'
        with self.assertRaisesRegex(topology.Refused, '^NPM_TOPOLOGY_INVALID$'):
            topology.validate(changed, stack_commit='a' * 40)

    def test_wrong_stack_commit_or_role_cannot_override_backup_binding(self):
        with self.assertRaisesRegex(topology.Refused, '^NPM_TOPOLOGY_INVALID$'):
            topology.validate(self.value, stack_commit='b' * 40)
        changed = copy.deepcopy(self.value)
        changed['bindings'][0]['role'] = 'external'; changed['bindings'][0]['service'] = None
        with self.assertRaisesRegex(topology.Refused, '^NPM_TOPOLOGY_INVALID$'):
            topology.validate(changed, stack_commit='a' * 40)

    def test_target_ips_must_be_distinct_concrete_canonical_addresses(self):
        for targets in ({'stack': '0.0.0.0', 'infisical': '192.0.2.30'},
                        {'stack': '192.0.2.29', 'infisical': '192.0.2.29'},
                        {'stack': 'new-host', 'infisical': '192.0.2.30'}):
            with self.subTest(targets=targets), self.assertRaises(topology.Refused):
                topology.planned(self.value, targets)

    def test_mounted_npm_database_is_never_modified(self):
        before = self.db.read_bytes()
        def run(args):
            if args == ['docker', 'ps', '-aq']: return ('a' * 64).encode()
            return json.dumps([{'Mounts': [{'Source': str(self.db.parent)}]}]).encode()
        with self.assertRaisesRegex(topology.Refused, '^NPM_TOPOLOGY_ALREADY_MOUNTED$'):
            topology.prepare(self.root, self.value, self.targets, run)
        self.assertEqual(before, self.db.read_bytes())
        self.assertFalse((self.root / topology.JOURNAL).exists())

    def test_drift_in_an_unchanged_external_route_blocks_the_whole_apply(self):
        with database(self.db) as db:
            db.execute('UPDATE proxy_host SET forward_host=\'other.example.invalid\' WHERE id=3')
        with self.assertRaisesRegex(topology.Refused, '^NPM_TOPOLOGY_SOURCE_DRIFT$'):
            topology.prepare(self.root, self.value, self.targets, self.runner)
        self.assertEqual(topology.rows(self.db)[0]['routing']['forward_host'], '192.0.2.11')

    def test_interrupted_after_atomic_sql_commit_reconciles_the_private_journal(self):
        original = topology.save
        def save(path, value, **kw):
            if value['phase'] == 'complete': raise OSError('synthetic final journal failure')
            original(path, value, **kw)
        with patch.object(topology, 'save', side_effect=save), self.assertRaises(OSError):
            topology.prepare(self.root, self.value, self.targets, self.runner)
        self.assertEqual(json.loads((self.root / topology.JOURNAL).read_bytes())['phase'], 'planned')
        self.assertEqual(topology.rows(self.db)[0]['routing']['forward_host'], self.targets['stack'])
        evidence = topology.prepare(self.root, self.value, self.targets, self.runner)
        self.assertEqual(topology.verify(self.root, evidence, stack_commit='a' * 40)['phase'], 'complete')

    def test_completed_journal_refuses_new_destination_or_runtime_route_drift(self):
        evidence = topology.prepare(self.root, self.value, self.targets, self.runner)
        changed = dict(self.targets, stack='192.0.2.99')
        with self.assertRaisesRegex(topology.Refused, '^NPM_TOPOLOGY_JOURNAL_INVALID$'):
            topology.prepare(self.root, self.value, changed, self.runner)
        with database(self.db) as db:
            db.execute('UPDATE proxy_host SET forward_host=\'192.0.2.11\' WHERE id=1')
        with self.assertRaisesRegex(topology.Refused, '^NPM_TOPOLOGY_SOURCE_DRIFT$'):
            topology.verify(self.root, evidence, stack_commit='a' * 40)

    @unittest.skipUnless(os.name != 'nt' and hasattr(os,'geteuid') and os.geteuid() == 0, 'Linux root ownership gate')
    def test_application_database_and_private_control_journal_keep_distinct_ownership(self):
        evidence = topology.prepare(self.root,self.value,self.targets,self.runner)
        self.assertEqual((self.db.stat().st_uid,self.db.stat().st_gid),(1000,1000))
        self.assertEqual((self.root/topology.JOURNAL).stat().st_uid,0)
        self.assertEqual(topology.verify(self.root,evidence,stack_commit='a'*40)['phase'],'complete')

    @unittest.skipUnless(os.name != 'nt' and hasattr(os,'geteuid') and os.geteuid() == 0, 'Linux root ownership gate')
    def test_wrong_database_owner_refused_before_journal_or_sql_update(self):
        os.chown(self.db,0,0)
        before=self.db.read_bytes()
        with self.assertRaisesRegex(topology.Refused,'^NPM_TOPOLOGY_DATABASE_IDENTITY_REQUIRED$'):
            topology.prepare(self.root,self.value,self.targets,self.runner)
        self.assertEqual(self.db.read_bytes(),before)
        self.assertFalse((self.root/topology.JOURNAL).exists())


if __name__ == '__main__':
    unittest.main()

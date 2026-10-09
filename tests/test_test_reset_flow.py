"""The GUI can restart only the explicitly bounded test pair after two preflights."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from recovery_gui import backend


def request():
    return dict(host='192.168.178.29', user='test', port='22',
                infisical_host='192.168.178.30', infisical_user='test2', infisical_port='22',
                dr_tag='dr-20261006T210601Z', public_commit='28f6ca7cc6f5fd10418fc0af2926815927ef98c8',
                aio_mode='manual', github_token='private-token-canary', restart_test=True)


class TestResetFlow(unittest.TestCase):
    def test_original_hosts_and_unreviewed_choices_cannot_reach_ssh(self):
        for changed in ({'host': '192.168.178.11'}, {'infisical_host': '192.168.178.28'},
                        {'user': 'pi'}, {'infisical_user': 'infiscal'}, {'port': '2222'},
                        {'infisical_port': '2222'}, {'dr_tag': 'dr-20261004T023903Z'},
                        {'public_commit': '0'*40}, {'aio_mode': 'import'}):
            stack, server = Mock(), Mock()
            with self.subTest(changed=changed), self.assertRaisesRegex(backend.Failure, '^TEST_RESET_SCOPE_REFUSED$'):
                backend.inspect_test_reset(stack, server, dict(request(), **changed))
            self.assertFalse(stack.mock_calls or server.mock_calls)
        with self.assertRaisesRegex(backend.Failure, '^TEST_RESET_SCOPE_REFUSED$'):
            backend.validate_test_reset_choice(request(), tls=True)

    def fixtures(self):
        events = []
        clients = []
        for role, digit in (('stack', '1'), ('infisical', '2')):
            client = Mock()
            client.check.side_effect = lambda role=role, digit=digit, **kw: dict(machine_id=digit*32)
            def reset(mode, chosen_role, data, info, ticket=None, role=role):
                self.assertEqual(role, chosen_role)
                events.append((role, mode))
                if mode == 'inspect':
                    return dict(role=role, status='READY', ticket='a'*64, machine_id=info['machine_id'], containers=12, volumes=6)
                self.assertEqual(ticket, 'a'*64)
                return dict(role=role, status='RESET', archive='/var/lib/streams-aio-test-reset/'+role+'/synthetic')
            client.test_reset.side_effect = reset
            clients.append(client)
        github = Mock()
        github.choices.return_value = ([request()['dr_tag']], request()['public_commit'])
        github.get.return_value = {'sha': request()['public_commit']}
        return clients, github, events

    def test_both_hosts_are_inspected_before_the_first_reset(self):
        clients, github, events = self.fixtures()
        data = request()
        with patch.object(backend, 'GitHub', return_value=github):
            backend.restart_test_hosts(*clients, data, Mock())
        self.assertEqual(events, [('stack', 'inspect'), ('infisical', 'inspect'), ('stack', 'reset'), ('infisical', 'reset')])
        self.assertEqual(len(data['test_reset_archives']), 2)
        self.assertIs(data['restart_test'], False)
        self.assertNotIn('canary', json.dumps(data['test_reset_archives']))

    def test_second_inspection_failure_preserves_both_hosts(self):
        clients, github, events = self.fixtures()
        clients[1].test_reset.side_effect = backend.Failure('TEST_RESET_FOREIGN_RUNTIME_REFUSED')
        with patch.object(backend, 'GitHub', return_value=github), self.assertRaises(backend.Failure):
            backend.restart_test_hosts(*clients, request(), Mock())
        self.assertEqual(events, [('stack', 'inspect')])
        self.assertEqual(clients[0].test_reset.call_count, 1)

    def test_github_access_is_checked_before_any_host_operation(self):
        clients, github, events = self.fixtures()
        github.choices.side_effect = backend.Failure('GITHUB_AUTH_FAILED')
        with patch.object(backend, 'GitHub', return_value=github), self.assertRaisesRegex(backend.Failure, 'GITHUB_AUTH_FAILED'):
            backend.restart_test_hosts(*clients, request(), Mock())
        self.assertFalse(events)
        for client in clients:
            client.check.assert_not_called()

    def test_same_machine_is_refused_before_inspection(self):
        clients, github, events = self.fixtures()
        clients[1].check.side_effect = lambda **kw: dict(machine_id='1'*32)
        with self.assertRaisesRegex(backend.Failure, 'SEPARATE_RECOVERY_VMS_REQUIRED'):
            backend.inspect_test_reset(*clients, request())
        self.assertFalse(events)

    def test_archive_receipt_survives_a_later_reset_failure(self):
        clients, github, events = self.fixtures()
        old = clients[1].test_reset.side_effect
        def fail_after_inspection(mode, *args, **kw):
            if mode == 'reset':
                raise backend.Failure('TEST_RESET_OPERATION_FAILED')
            return old(mode, *args, **kw)
        clients[1].test_reset.side_effect = fail_after_inspection
        data = request()
        with patch.object(backend, 'GitHub', return_value=github), self.assertRaises(backend.Failure):
            backend.restart_test_hosts(*clients, data, Mock())
        self.assertEqual(data['test_reset_archives'], [('stack', '/var/lib/streams-aio-test-reset/stack/synthetic')])
        self.assertIs(data['restart_test'], True)

    def test_complete_flow_cleans_then_uses_the_normal_restore(self):
        clients, github, events = self.fixtures()
        stack, server = clients
        for client, role, digit in ((stack, 'stack', '1'), (server, 'infisical', '2')):
            def check(role=role, digit=digit, **kw):
                events.append((role, 'check-resume' if kw.get('fresh') is False else 'check-fresh'))
                return dict(machine_id=digit*32, home='/home/'+('test' if role=='stack' else 'test2'))
            client.check.side_effect = check
            client.prepare.side_effect = lambda *args, role=role: events.append((role, 'prepare'))
        stack.start.side_effect = lambda *args: events.append(('stack', 'start'))
        bridge = Mock()
        bridge.__enter__ = Mock(return_value='http://synthetic-api')
        bridge.__exit__ = Mock(return_value=False)
        data = dict(request(), native_agent=False)
        with patch.object(backend, 'GitHub', return_value=github), patch.object(backend, 'APIBridge', return_value=bridge):
            backend.restore_all(stack, server, data, Mock())
        self.assertEqual(events, [('stack', 'check-resume'), ('infisical', 'check-resume'),
                                  ('stack', 'inspect'), ('infisical', 'inspect'),
                                  ('stack', 'reset'), ('infisical', 'reset'),
                                  ('stack', 'check-fresh'), ('infisical', 'check-fresh'),
                                  ('infisical', 'prepare'), ('stack', 'prepare'), ('stack', 'start')])
        self.assertIs(data['restart_test'], False)

    def test_failure_after_reset_retries_without_resetting_the_new_attempt(self):
        clients, github, events = self.fixtures()
        clients[1].prepare.side_effect = backend.Failure('INFISICAL_RESTORE_FAILED')
        data = dict(request(), native_agent=False)
        with patch.object(backend, 'GitHub', return_value=github):
            for _ in range(2):
                with self.assertRaisesRegex(backend.Failure, 'INFISICAL_RESTORE_FAILED'):
                    backend.restore_all(*clients, data, Mock())
        self.assertIs(data['restart_test'], False)
        self.assertEqual(events.count(('stack', 'reset')), 1)
        self.assertEqual(events.count(('infisical', 'reset')), 1)

    def test_selected_recovery_point_is_verified_before_any_host(self):
        for tags, sha, code in (([], request()['public_commit'], 'PUBLISHED_RELEASE_REQUIRED'),
                               ([request()['dr_tag']], '0'*40, 'PUBLIC_COMMIT_UNAVAILABLE')):
            clients, github, events = self.fixtures()
            github.choices.return_value = (tags, '0'*40)
            github.get.return_value = {'sha': sha}
            with patch.object(backend, 'GitHub', return_value=github), self.assertRaisesRegex(backend.Failure, code):
                backend.restart_test_hosts(*clients, request(), Mock())
            self.assertFalse(events)

    def test_transport_drops_arbitrary_metadata_and_sends_no_github_credential(self):
        transport = backend.SSH.__new__(backend.SSH)
        good = dict(role='stack', machine_id='1'*32, containers=12, volumes=6, ticket='a'*64, status='READY')
        transport.run = Mock(return_value=json.dumps(good).encode())
        with patch.object(backend, 'resources', return_value=ROOT/'remote'):
            self.assertEqual(transport.test_reset('inspect', 'stack', request(), {'machine_id': '1'*32}), good)
            sent = transport.run.call_args.kwargs['input']
            self.assertTrue(sent.startswith(b'STREAMS_TEST_RESET_V1\n'))
            self.assertEqual(set(json.loads(sent.split(b'\n')[1])), {'tag', 'commit', 'machine_id'})
            self.assertNotIn('canary', transport.run.call_args.kwargs['input'].decode())
            for bad in (dict(good, value='private-canary'), dict(good, ticket='private-canary'),
                        dict(good, containers=True), dict(good, role='original')):
                transport.run.return_value = json.dumps(bad).encode()
                with self.subTest(bad=bad), self.assertRaisesRegex(backend.Failure, '^TEST_RESET_METADATA_REFUSED$'):
                    transport.test_reset('inspect', 'stack', request(), {'machine_id': '1'*32})

    def test_reset_receipt_accepts_only_the_fixed_role_and_generated_archive_path(self):
        transport = backend.SSH.__new__(backend.SSH)
        good = dict(role='stack', status='RESET', archive='/var/lib/streams-aio-test-reset/stack/20261008T120000Z-012345abcdef')
        transport.run = Mock(return_value=json.dumps(good).encode())
        with patch.object(backend, 'resources', return_value=ROOT/'remote'):
            self.assertEqual(transport.test_reset('reset', 'stack', request(), {'machine_id': '1'*32}, 'a'*64), good)
            transport.run.return_value = json.dumps(dict(good, archive=None)).encode()
            self.assertIsNone(transport.test_reset('reset', 'stack', request(), {'machine_id': '1'*32}, 'a'*64)['archive'])
            for bad in (dict(good, archive='/root/private-canary'), dict(good, archive='/var/lib/streams-aio-test-reset/stack/..'),
                        dict(good, status='READY'), dict(good, role='infisical'), dict(good, value='private-canary')):
                transport.run.return_value = json.dumps(bad).encode()
                with self.subTest(bad=bad), self.assertRaisesRegex(backend.Failure, '^TEST_RESET_METADATA_REFUSED$'):
                    transport.test_reset('reset', 'stack', request(), {'machine_id': '1'*32}, 'a'*64)


if __name__ == '__main__':
    unittest.main()

import json
from pathlib import Path
import queue
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from recovery_gui.backend import Failure, GitHub, PRIVATE, restore_all
from recovery_gui.recovery_inspection import inspect_recovery
from recovery_gui.ui_dashboard import App
from recovery_gui.ui_state import operational_request, phase_status, machine_status, phase_for


TAG = 'dr-20261006T210601Z'
COMMIT = '28f6ca7cc6f5fd10418fc0af2926815927ef98c8'


class Destination:
    def __init__(self, machine, existing=False, containers=0, operational=False):
        self.info = dict(machine_id=machine, home='/home/test', containers=containers,
                         volumes=0, existing_recovery=existing,
                         recovery={'infisical_completed': operational})
        self.operational = operational
        self.calls = []
        self.failure = None
        self.scope = True
        self.checkpoint = existing
        self.retryable = True

    def check(self, fresh=True, role='stack'):
        self.calls.append(('check', fresh, role))
        if fresh and self.failure:
            raise Failure(self.failure)
        return dict(self.info)

    def area(self, home, role):
        return home + '/runner-' + role

    def run(self, args, **kwargs):
        self.calls.append(('run', args, kwargs))
        return json.dumps(dict(checkpoint_present=self.checkpoint,scope_matches=self.scope,
                               operation_retryable=self.retryable,
                               early_prestart_verified=self.checkpoint and not self.info['existing_recovery'],
                               infrastructure_verified=self.operational,
                               functional_verified=False)).encode()


class InspectionTests(unittest.TestCase):
    def request(self, action='resume'):
        return dict(recovery_action=action, dr_tag=TAG, public_commit=COMMIT)

    def test_new_pair_checks_both_hosts_without_writing(self):
        first, second = Destination('a'), Destination('b')
        result = inspect_recovery(first, second, self.request('fresh'))
        self.assertEqual(result['outcome'], 'FRESH')
        for client,role in ((first,'stack'),(second,'infisical')):
            self.assertEqual(client.calls[0],('check',False,role))
            self.assertEqual(client.calls[-1],('check',True,role))
            self.assertEqual(len([call for call in client.calls if call[0]=='run']),1)
            self.assertTrue(client.calls[1][2]['sudo'])

    def test_resume_requires_scope_and_strict_docker_ownership(self):
        first, second = Destination('a', True, 20), Destination('b', True, 3)
        first.failure = 'FOREIGN_CONTAINER_REFUSED'
        with self.assertRaisesRegex(Failure, 'FOREIGN_CONTAINER_REFUSED'):
            inspect_recovery(first, second, self.request())
        self.assertEqual(first.calls[-1], ('check', True, 'stack'))

    def test_fresh_never_resets_existing_resources(self):
        first, second = Destination('a', True, 20), Destination('b')
        with self.assertRaisesRegex(Failure, 'EXISTING_STACK_REFUSED'):
            inspect_recovery(first, second, self.request('fresh'))
        self.assertFalse(any(call[0] == 'run' for call in first.calls))

    def test_same_machine_and_wrong_recovery_point_stop_detection(self):
        with self.assertRaisesRegex(Failure, 'SEPARATE_RECOVERY_VMS_REQUIRED'):
            inspect_recovery(Destination('a'), Destination('a'), self.request())
        first, second = Destination('a', True), Destination('b', True)
        first.scope = False
        with self.assertRaisesRegex(Failure, 'FOREIGN_RECOVERY_STATE'):
            inspect_recovery(first, second, self.request())

    def test_prepared_and_started_need_functional_checks_not_fake_complete(self):
        first, second = Destination('a', True), Destination('b', True, operational=True)
        first.info['recovery'] = {'prepared': True, 'application_start_attempted': True}
        self.assertEqual(inspect_recovery(first, second, self.request())['outcome'], 'RESUMABLE')
        first.operational = True
        detected = inspect_recovery(first, second, self.request())
        self.assertEqual(detected['outcome'], 'RESUMABLE')
        self.assertEqual(detected['next_action'], 'VERIFY_FUNCTIONAL')
        self.assertTrue(detected['stack']['recovery']['infrastructure_verified'])

    def test_checkpoint_before_target_exists_is_resumable_and_never_fresh(self):
        for role in ('stack','infisical'):
            with self.subTest(role=role):
                first,second=Destination('a'),Destination('b')
                selected=first if role=='stack' else second
                selected.checkpoint=True
                detected=inspect_recovery(first,second,self.request())
                self.assertEqual(detected['outcome'],'RESUMABLE')
                self.assertTrue(detected[role]['existing_recovery'])
                if role=='stack':self.assertIs(detected[role]['recovery']['application_start_attempted'],False)
                self.assertIn(('check',True,role),selected.calls)
                with self.assertRaisesRegex(Failure,'EXISTING_STACK_REFUSED'):
                    inspect_recovery(first,second,self.request('fresh'))

    def test_uncertain_pending_phase_is_not_automatically_retried(self):
        first,second=Destination('a'),Destination('b')
        first.checkpoint=True;first.retryable=False
        with self.assertRaisesRegex(Failure,'INCOMPLETE_STEP_REQUIRES_REVIEW'):
            inspect_recovery(first,second,self.request())


class DashboardFlowTests(unittest.TestCase):
    def test_operational_defaults_require_snapshot_https_goal_and_no_reset(self):
        data = operational_request({'host': '192.168.1.10'}, 'resume')
        self.assertEqual(data['aio_mode'], 'snapshot')
        self.assertTrue(data['operational_profile'])
        self.assertTrue(data['native_agent'])
        self.assertFalse(data['restart_test'])
        self.assertEqual(data['routing_mode'], 'parallel_test')
        self.assertEqual(data['domain_target_address'], '')

    def test_preparation_and_start_do_not_certify_operational_restore(self):
        self.assertEqual(phase_status('STARTED', 'PASS'), ('Controllo superato', 'active'))
        self.assertEqual(phase_status('AIO', 'SKIPPED'), ('Non completato', 'pending'))
        self.assertEqual(phase_status('OPERATIONAL_READY', 'PASS'), ('Verificato', 'ok'))
        self.assertEqual(phase_for('PUBLIC_DOMAINS'), 'Domini')
        self.assertEqual(phase_for('NPM_TOPOLOGY'), 'Domini')
        self.assertEqual(phase_for('OPERATIONAL_PROFILE'), 'Stack')
        self.assertEqual(phase_for('PUBLIC_CONTROLLERS'), 'Servizi')
        self.assertEqual(machine_status({'existing_recovery': True, 'containers': 28,
                                        'volumes': 6, 'recovery': {'prepared': True}})[0],
                         'Pronta per continuare')

    def test_one_click_uses_backend_detection_before_guarded_restore_and_closes_connections(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / 'key.txt'
            key.write_text('test-private-identity-fixture')
            data = dict(host='192.168.1.10', user='test', port='22', password='private one',
                        ssh_key='', key_password='', sudo_password='', infisical_host='192.168.1.11',
                        infisical_user='test2', infisical_port='22', infisical_password='private two',
                        infisical_key='', infisical_key_password='', infisical_sudo_password='',
                        dr_tag=TAG, public_commit=COMMIT, github_token='fixture', age_identity=str(key), supplemental_inputs='',
                        domain_target_address='192.168.1.10')
            # Exercise the production action without creating a Tk window.
            view = Mock()
            view.snapshot.return_value = data
            view.files = {}
            view.backup_has_aio = True
            view.host.side_effect = App.host
            view.infisical_host.side_effect = App.infisical_host
            view.cancelled = threading.Event()
            view.events = queue.Queue()
            view.job.side_effect = lambda action: action()
            connections = [Mock(name='stack'), Mock(name='infisical')]
            calls = []
            def inspect(*args):
                calls.append('detect')
                return {'outcome': 'RESUMABLE'}
            def restore(*args, **kwargs):
                calls.append('restore')
                self.assertTrue(kwargs['tls'])
                self.assertEqual(args[2]['aio_mode'], 'snapshot')
                self.assertEqual(args[2]['recovery_action'], 'resume')
            with patch('recovery_gui.ui_dashboard.backend.SSH', side_effect=connections), \
                 patch('recovery_gui.ui_dashboard.backend.resolve_resume_request',side_effect=lambda a,b,r:r), \
                 patch('recovery_gui.ui_dashboard.GitHub') as github, \
                 patch('recovery_gui.ui_dashboard.backend.inspect_recovery', side_effect=inspect, create=True), \
                 patch('recovery_gui.ui_dashboard.backend.restore_all', side_effect=restore):
                github.return_value.point.return_value=dict(tag=TAG,public_commit=COMMIT,aio_snapshot=True)
                App.recover(view, 'resume')
            self.assertEqual(calls, ['detect', 'restore'])
            for connection in connections:
                connection.close.assert_called_once()
            recorded = list(view.events.queue)
            self.assertEqual([event[0] for event in recorded], ['resumed_selection','detected', 'finished'])
            self.assertNotIn('private one', json.dumps(recorded))

    def test_detection_refusal_never_calls_restore_but_closes_both_connections(self):
        with tempfile.TemporaryDirectory() as directory:
            key = Path(directory) / 'key.txt'
            key.write_text('test-private-identity-fixture')
            data = dict(host='192.168.1.10', user='test', port='22', password='one', ssh_key='',
                        key_password='', sudo_password='', infisical_host='192.168.1.11',
                        infisical_user='test2', infisical_port='22', infisical_password='two',
                        infisical_key='', infisical_key_password='', infisical_sudo_password='',
                        dr_tag=TAG, public_commit=COMMIT, age_identity=str(key), supplemental_inputs='',
                        domain_target_address='192.168.1.10')
            view = Mock()
            view.snapshot.return_value = data
            view.files, view.backup_has_aio = {}, True
            view.host.side_effect, view.infisical_host.side_effect = App.host, App.infisical_host
            view.cancelled, view.events = threading.Event(), queue.Queue()
            view.job.side_effect = lambda action: action()
            clients = [Mock(), Mock()]
            with patch('recovery_gui.ui_dashboard.backend.SSH', side_effect=clients), \
                 patch('recovery_gui.ui_dashboard.backend.inspect_recovery', side_effect=Failure('FOREIGN_CONTAINER_REFUSED'), create=True), \
                 patch('recovery_gui.ui_dashboard.backend.restore_all') as restore:
                with self.assertRaisesRegex(Failure, 'FOREIGN_CONTAINER_REFUSED'):
                    App.recover(view, 'fresh')
                restore.assert_not_called()
            for client in clients:
                client.close.assert_called_once()

    def test_missing_or_invalid_domain_target_stops_fresh_action_before_ssh(self):
        for action in ('fresh',):
            for target in ('', 'not-an-ip', '0.0.0.0', '224.0.0.1'):
                with self.subTest(action=action, target=target):
                    view = Mock()
                    view.snapshot.return_value = dict(host='192.168.1.10', domain_target_address=target)
                    view.files = {}
                    with patch('recovery_gui.ui_dashboard.backend.SSH') as connect, \
                         patch('recovery_gui.ui_dashboard.backend.restore_all') as restore:
                        App.recover(view, action)
                    connect.assert_not_called()
                    restore.assert_not_called()
                    view.job.assert_not_called()
                    view.show_error.assert_called_once_with('PUBLIC_DOMAIN_CONFIGURATION_REQUIRED')

    def test_operational_profile_never_infers_public_address_from_ssh_host(self):
        data = operational_request(dict(host='192.168.1.10', routing_mode='production_recovery'), 'fresh')
        self.assertEqual(data['domain_target_address'], '')
        self.assertEqual(data['routing_mode'], 'production_recovery')


class RecoveryPointUITests(unittest.TestCase):
    def point(self, snapshot=True):
        import hashlib
        base = {'npm-database.sqlite.age', 'infisical-agent-infisical-agent.tar.gz.age',
                'infisical-config.tar.gz.age', 'infisical-postgres.dump.age',
                'infisical-postgres-globals.sql.age', 'manifest.json', 'SHA256SUMS'}
        names = base | ({'aio-state.tar.gz.age'} if snapshot else set())
        manifest = dict(schema=2, run=TAG[3:], repository=PRIVATE, stack_commit=COMMIT,
                        artifacts={name: {} for name in names - {'manifest.json', 'SHA256SUMS'}})
        raw = json.dumps(manifest).encode()
        sums = (hashlib.sha256(raw).hexdigest() + '  manifest.json\n' +
                ''.join('0' * 64 + '  ' + name + '\n' for name in sorted(names - {'manifest.json', 'SHA256SUMS'}))).encode()
        assets = [dict(name=name, id=index + 1, size=len(raw if name == 'manifest.json' else sums))
                  for index, name in enumerate(sorted(names))]
        release = dict(tag_name=TAG, draft=False, assets=assets)
        github = GitHub('fixture-token-not-real')
        github.get = Mock(side_effect=lambda path: release if '/releases/tags/' in path else {'object': {'sha': COMMIT}})
        github.asset = Mock(side_effect=lambda asset: raw if asset['name'] == 'manifest.json' else sums)
        return github, release

    def test_complete_point_associates_manifest_commit_and_snapshot_flag(self):
        github, release = self.point()
        self.assertEqual(github.point(TAG), dict(tag=TAG, public_commit=COMMIT, aio_snapshot=True))

    def test_legacy_point_is_explicitly_missing_automatic_aio(self):
        github, release = self.point(snapshot=False)
        self.assertEqual(github.point(TAG)['aio_snapshot'], False)
        github.asset.assert_not_called()

    def test_unexpected_or_duplicate_asset_is_refused(self):
        for duplicate in (True, False):
            github, release = self.point()
            release['assets'].append(release['assets'][0] if duplicate else dict(name='extra-private.json', id=999, size=10))
            with self.assertRaisesRegex(Failure, 'UNEXPECTED_RELEASE_ASSETS'):
                github.point(TAG)

    def test_change_backup_loads_its_own_manifest_point(self):
        view = Mock()
        variables = {'github_token': Mock(), 'dr_tag': Mock()}
        variables['github_token'].get.return_value = 'fixture-token-not-real'
        variables['dr_tag'].get.return_value = TAG
        view.var.side_effect = lambda key: variables[key]
        view.events = queue.Queue()
        view.job.side_effect = lambda action, **kwargs: action()
        point = dict(tag=TAG, public_commit=COMMIT, aio_snapshot=True)
        with patch('recovery_gui.ui_dashboard.GitHub') as service:
            service.return_value.point.return_value = point
            App.load_point(view)
        service.return_value.point.assert_called_once_with(TAG)
        self.assertEqual(view.events.get_nowait(), ('point', point))


class BackendPreflightTests(unittest.TestCase):
    def request(self, action='fresh', target='192.168.1.10'):
        return operational_request(dict(host='192.168.1.10', dr_tag=TAG, public_commit=COMMIT,
                                        github_token='fixture', domain_target_address=target), action)

    def test_missing_target_refuses_both_actions_before_any_remote_mutation(self):
        for action in ('fresh', 'resume'):
            stack, server = Mock(), Mock()
            with patch('recovery_gui.backend.GitHub') as github, \
                 patch('recovery_gui.backend.inspect_recovery') as inspect:
                with self.assertRaisesRegex(Failure, 'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED'):
                    restore_all(stack, server, self.request(action, ''), Mock(), tls=True)
            github.assert_not_called()
            inspect.assert_not_called()
            self.assertEqual(stack.mock_calls, [])
            self.assertEqual(server.mock_calls, [])

    def test_missing_aio_capsule_and_wrong_manifest_commit_stop_before_ssh_prepare(self):
        for point, code in ((dict(aio_snapshot=False, public_commit=COMMIT), 'AIO_SNAPSHOT_BACKUP_REQUIRED'),
                            (dict(aio_snapshot=True, public_commit='f' * 40), 'DR_STACK_COMMIT_MISMATCH')):
            stack, server = Mock(), Mock()
            with patch('recovery_gui.backend.GitHub') as github, \
                 patch('recovery_gui.backend.inspect_recovery') as inspect:
                github.return_value.point.return_value = point
                with self.assertRaisesRegex(Failure, code):
                    restore_all(stack, server, self.request(), Mock(), tls=True)
            inspect.assert_not_called()
            self.assertEqual(stack.mock_calls, [])
            self.assertEqual(server.mock_calls, [])

    def test_inspection_refusal_blocks_prepare_and_start(self):
        stack, server = Mock(), Mock()
        with patch('recovery_gui.backend.GitHub') as github, \
             patch('recovery_gui.backend.inspect_recovery', side_effect=Failure('EXISTING_STACK_REFUSED')):
            github.return_value.point.return_value = dict(aio_snapshot=True, public_commit=COMMIT)
            with self.assertRaisesRegex(Failure, 'EXISTING_STACK_REFUSED'):
                restore_all(stack, server, self.request(), Mock(), tls=True)
        self.assertEqual(stack.mock_calls, [])
        self.assertEqual(server.mock_calls, [])

    def test_early_owned_checkpoint_reaches_restore_through_real_inspection_and_resume_gate(self):
        # Only transport/install calls are mocked: real inspection, ownership
        # sequencing, the legacy first-start gate and restore_all all execute.
        stack,server=Destination('a'),Destination('b')
        stack.checkpoint=True
        for client,address in ((stack,'192.168.1.10'),(server,'192.168.1.11')):
            client.prepare,client.start,client.native=Mock(),Mock(),Mock(return_value=b'{"public_key":"ssh-ed25519 fixture"}')
            client.restored_port=Mock(return_value=80)
            client.host=Mock(address=address,port=22)
            client.client=Mock()
            client.client.get_transport.return_value.getpeername.return_value=(address,22)
            key=client.client.get_transport.return_value.get_remote_server_key.return_value
            key.get_name.return_value='ssh-ed25519'
            key.get_base64.return_value='fixture'
        callback=Mock()
        with patch('recovery_gui.backend.GitHub') as github,patch('recovery_gui.backend.APIBridge') as bridge:
            github.return_value.point.return_value=dict(aio_snapshot=True,public_commit=COMMIT)
            bridge.return_value.__enter__.return_value='http://127.0.0.1:18180'
            restore_all(stack,server,self.request('resume'),callback,tls=True)
        server.prepare.assert_called_once()
        stack.prepare.assert_called_once()
        stack.start.assert_called_once_with(True,callback,operational=True,cutover=False,
            routing_mode='parallel_test',domain_target_address='192.168.1.10')
        self.assertIn(('check',True,'stack'),stack.calls)
        callback.assert_any_call(dict(stage='OPERATIONAL_READY',status='PASS'))

    def test_new_schema_two_point_and_distinct_target_users_survive_whole_backend_flow(self):
        new_tag,new_pin='dr-20261011T043000Z','b'*40
        stack,server=Destination('replacement-stack'),Destination('replacement-vault')
        stack.info.update(home='/home/test',user='test')
        server.info.update(home='/home/test2',user='test2')
        ordered=[]
        for client,name,address,user in ((stack,'stack','192.168.178.29','test'),
                                         (server,'infisical','192.168.178.30','test2')):
            client.prepare=Mock(side_effect=lambda request,callback,name=name: ordered.append((name,request)))
            client.start=Mock()
            client.native=Mock(return_value=b'{"public_key":"ssh-ed25519 fixture"}')
            client.restored_port=Mock(return_value=80)
            client.host=Mock(address=address,port=22,user=user)
            client.client=Mock()
            client.client.get_transport.return_value.getpeername.return_value=(address,22)
            key=client.client.get_transport.return_value.get_remote_server_key.return_value
            key.get_name.return_value='ssh-ed25519';key.get_base64.return_value='fixture'
        request=self.request('fresh','192.0.2.42')
        request.update(dr_tag=new_tag,public_commit=new_pin,routing_mode='production_recovery')
        with patch('recovery_gui.backend.GitHub') as github,patch('recovery_gui.backend.APIBridge') as bridge:
            github.return_value.point.return_value=dict(tag=new_tag,aio_snapshot=True,public_commit=new_pin)
            bridge.return_value.__enter__.return_value='http://127.0.0.1:19876'
            callback=Mock()
            restore_all(stack,server,request,callback,tls=True)
        self.assertEqual([role for role,data in ordered],['infisical','stack'])
        for role,data in ordered:
            self.assertEqual(data['dr_tag'],new_tag)
            self.assertEqual(data['public_commit'],new_pin)
            self.assertEqual(data['aio_mode'],'snapshot')
            self.assertEqual(data['role'],role)
        self.assertEqual(ordered[1][1]['infisical_address'],'http://127.0.0.1:19876')
        self.assertEqual(ordered[1][1]['npm_upstream_targets'],
            {'stack':'192.168.178.29','infisical':'192.168.178.30'})
        self.assertEqual(ordered[0][1]['npm_upstream_targets'],ordered[1][1]['npm_upstream_targets'])
        self.assertTrue(ordered[1][1]['ssh_bridge'])
        server.native.assert_called_once_with('authorize','/home/test2','/opt/infisical',callback=callback,
            metadata={'public_key':'ssh-ed25519 fixture'})
        stack.native.assert_any_call('key','/home/test','/home/test/streams-aio')
        stack.native.assert_any_call('install','/home/test','/home/test/streams-aio',callback=callback,
            metadata={'host':'192.168.178.30','port':22,'api_port':80,'host_key':'ssh-ed25519 fixture'})
        stack.start.assert_called_once_with(True,callback,operational=True,cutover=True,
            routing_mode='production_recovery',domain_target_address='192.0.2.42')


if __name__ == '__main__':
    unittest.main()

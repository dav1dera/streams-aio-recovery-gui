import json
from pathlib import Path
import queue
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from recovery_gui.backend import Failure
from recovery_gui.recovery_inspection import resolve_resume_request
from recovery_gui.ui_dashboard import App
from test_inspection_scope import scope, initialized, COMMIT, TAG


class SelectionReadTests(unittest.TestCase):
    def test_empty_and_early_checkpoint_preserve_distinction(self):
        self.assertEqual(scope(None,selection=True),{'present':False})
        row=scope(initialized(),selection=True)
        self.assertTrue(row['present']);self.assertIsNone(row['tag'])
        self.assertEqual(row['public_commit'],COMMIT)

    def test_saved_point_and_deployment_are_read_without_private_fields(self):
        state=initialized();state.update(tag=TAG,public_commit=COMMIT,password='PRIVATE_CANARY')
        state['operational_deployment']=dict(schema=1,routing_mode='parallel_test',domain_target_address='192.168.178.29',
            uid=1000,gid=1000,user='test',home='/home/test',target=state['target'],machine_id='machine-a',
            tag=TAG,public_commit=COMMIT,tooling_commit=COMMIT)
        row=scope(state,selection=True)
        self.assertEqual(row['routing_mode'],'parallel_test')
        self.assertEqual(row['domain_target_address'],'192.168.178.29')
        self.assertNotIn('PRIVATE_CANARY',json.dumps(row))
        state['operational_deployment']['public_commit']='c'*40
        self.assertEqual(scope(state,selection=True),{'refused':True})

    def test_foreign_machine_ownership_symlinks_and_invalid_point_are_refused(self):
        for kwargs in (dict(checkpoint_uid=1000),dict(checkpoint_mode=0o644),dict(runner_uid=0),dict(symlink='/home/test')):
            with self.subTest(kwargs=kwargs):self.assertEqual(scope(initialized(),selection=True,**kwargs),{'refused':True})
        for field,value in (('machine_id','foreign'),('public_commit','a'*40),('tag','PRIVATE_CANARY'),('schema',True)):
            state=initialized();state[field]=value
            with self.subTest(field=field):self.assertEqual(scope(state,selection=True),{'refused':True})

    def test_old_infisical_point_uses_its_tooling_pin(self):
        state=initialized('infisical');state['tag']=TAG
        self.assertEqual(scope(state,'infisical',selection=True)['public_commit'],COMMIT)


class ResumeSelectionTests(unittest.TestCase):
    def destination(self,machine,row):
        client=Mock()
        client.check.return_value=dict(machine_id=machine,home='/home/test',existing_recovery=row.get('present',False))
        client.area.return_value='/home/test/runner'
        client.run.return_value=json.dumps(row).encode()
        return client

    def row(self,**kwargs):
        return dict(present=True,tag=TAG,public_commit=COMMIT,routing_mode=None,domain_target_address=None,**kwargs)

    def request(self):
        return dict(recovery_action='resume',dr_tag='dr-20261010T024001Z',public_commit='a'*40,
                    routing_mode='production_recovery',domain_target_address='192.168.178.11')

    def test_resume_uses_existing_point_and_routing_before_strict_scope_check(self):
        row=self.row();row.update(routing_mode='parallel_test',domain_target_address='192.168.178.29')
        first=self.destination('a',row);second=self.destination('b',self.row())
        original=self.request()
        with patch('recovery_gui.recovery_inspection.inspect_recovery') as strict:
            result=resolve_resume_request(first,second,original)
        self.assertEqual(result['dr_tag'],TAG);self.assertEqual(result['public_commit'],COMMIT)
        self.assertEqual(result['routing_mode'],'parallel_test');self.assertEqual(result['domain_target_address'],'192.168.178.29')
        strict.assert_called_once_with(first,second,result)
        self.assertEqual(original,self.request())
        self.assertTrue(first.run.call_args.kwargs['sudo'])

    def test_inconsistent_hosts_and_foreign_state_stop_without_adoption(self):
        for row in (dict(self.row(),tag='dr-20261004T023903Z'),dict(self.row(),public_commit='f'*40),{'refused':True},dict(self.row(),extra='PRIVATE_CANARY')):
            with self.subTest(row=row),patch('recovery_gui.recovery_inspection.inspect_recovery') as strict:
                with self.assertRaisesRegex(Failure,'FOREIGN_RECOVERY_STATE'):
                    resolve_resume_request(self.destination('a',self.row()),self.destination('b',row),self.request())
                strict.assert_not_called()

    def test_strict_guard_failure_is_preserved_and_no_resources_are_adopted(self):
        with patch('recovery_gui.recovery_inspection.inspect_recovery',side_effect=Failure('FOREIGN_CONTAINER_REFUSED')):
            with self.assertRaisesRegex(Failure,'FOREIGN_CONTAINER_REFUSED'):
                resolve_resume_request(self.destination('a',self.row()),self.destination('b',self.row()),self.request())

    def test_same_machine_and_fresh_action_do_not_adopt_checkpoints(self):
        with patch('recovery_gui.recovery_inspection.inspect_recovery') as strict:
            with self.assertRaisesRegex(Failure,'SEPARATE_RECOVERY_VMS_REQUIRED'):
                resolve_resume_request(self.destination('a',self.row()),self.destination('a',self.row()),self.request())
            strict.assert_not_called()
        first,second=Mock(),Mock();request=dict(self.request(),recovery_action='fresh')
        self.assertEqual(resolve_resume_request(first,second,request),request)
        self.assertFalse(first.mock_calls or second.mock_calls)


class ResumeDashboardTests(unittest.TestCase):
    def view(self,key):
        data=dict(host='192.168.178.29',user='test',port='22',password='PRIVATE_CANARY',ssh_key='',
            key_password='',sudo_password='',infisical_host='192.168.178.30',infisical_user='test2',
            infisical_port='22',infisical_password='PRIVATE_CANARY',infisical_key='',infisical_key_password='',
            infisical_sudo_password='',github_token='PRIVATE_CANARY',dr_tag='',public_commit='',age_identity=str(key),
            supplemental_inputs='',domain_target_address='',routing_mode='production_recovery')
        view=Mock();view.snapshot.return_value=data
        view.files={};view.backup_has_aio=False
        view.host.side_effect=App.host;view.infisical_host.side_effect=App.infisical_host
        view.cancelled=threading.Event();view.events=queue.Queue();view.job.side_effect=lambda fn:fn()
        return view

    def test_resume_discovers_saved_inputs_when_ui_fields_are_empty_or_stale(self):
        with tempfile.TemporaryDirectory() as directory:
            key=Path(directory)/'key.txt';key.write_text('fixture')
            view=self.view(key);clients=[Mock(),Mock()]
            def resolve(a,b,r):return dict(r,dr_tag=TAG,public_commit=COMMIT,routing_mode='parallel_test',domain_target_address='192.168.178.29')
            with patch('recovery_gui.ui_dashboard.backend.SSH',side_effect=clients), \
                 patch('recovery_gui.ui_dashboard.backend.resolve_resume_request',side_effect=resolve), \
                 patch('recovery_gui.ui_dashboard.GitHub') as github, \
                 patch('recovery_gui.ui_dashboard.backend.inspect_recovery',return_value={'outcome':'RESUMABLE'}) as inspect, \
                 patch('recovery_gui.ui_dashboard.backend.restore_all') as restore:
                github.return_value.point.return_value=dict(tag=TAG,public_commit=COMMIT,aio_snapshot=True)
                App.recover(view,'resume')
            github.return_value.point.assert_called_once_with(TAG)
            self.assertEqual(restore.call_args.args[2]['routing_mode'],'parallel_test')
            self.assertEqual(restore.call_args.args[2]['dr_tag'],TAG)
            inspect.assert_called_once()
            self.assertNotIn('PRIVATE_CANARY',json.dumps(list(view.events.queue)))
            for client in clients:client.close.assert_called_once()

    def test_discovered_point_still_requires_matching_github_manifest_and_aio_capsule(self):
        for point,code in ((dict(public_commit='f'*40,aio_snapshot=True),'DR_STACK_COMMIT_MISMATCH'),
                           (dict(public_commit=COMMIT,aio_snapshot=False),'AIO_SNAPSHOT_BACKUP_REQUIRED')):
            with self.subTest(code=code),tempfile.TemporaryDirectory() as directory:
                key=Path(directory)/'key.txt';key.write_text('fixture')
                view=self.view(key);clients=[Mock(),Mock()]
                with patch('recovery_gui.ui_dashboard.backend.SSH',side_effect=clients), \
                     patch('recovery_gui.ui_dashboard.backend.resolve_resume_request',side_effect=lambda a,b,r:dict(r,dr_tag=TAG,public_commit=COMMIT)), \
                     patch('recovery_gui.ui_dashboard.GitHub') as github, \
                     patch('recovery_gui.ui_dashboard.backend.restore_all') as restore:
                    github.return_value.point.return_value=point
                    with self.assertRaisesRegex(Failure,code):App.recover(view,'resume')
                    restore.assert_not_called()
                for client in clients:client.close.assert_called_once()


if __name__=='__main__':unittest.main()

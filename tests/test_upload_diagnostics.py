"""Upload failures expose only fixed codes and identify the target phase."""
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock
from recovery_gui.backend import Failure,SSH,parse_event
from recovery_gui.ui_state import phase_for

class UploadDiagnostics(unittest.TestCase):
    def connection(self):
        job=SSH.__new__(SSH);job.host=N(user='fixture');job.run=Mock()
        return job

    def test_private_sftp_exception_is_replaced_by_fixed_code(self):
        for role,stage in (('infisical','INFISICAL_TRANSFER'),('stack','STACK_TRANSFER')):
            with self.subTest(role=role):
                job=self.connection();job.upload=Mock(side_effect=PermissionError('private-canary'))
                events=[]
                with self.assertRaisesRegex(Failure,'^SSH_UPLOAD_FAILED$'):
                    job.prepare({'role':role},events.append)
                self.assertEqual(events,[dict(stage=stage,status='RUNNING')])
                job.run.assert_not_called()

    def test_specific_refusal_remains_specific_without_starting_bootstrap(self):
        job=self.connection();job.upload=Mock(side_effect=Failure('SSH_UPLOAD_PATH_REFUSED'))
        events=[]
        with self.assertRaisesRegex(Failure,'^SSH_UPLOAD_PATH_REFUSED$'):
            job.prepare({'role':'infisical'},events.append)
        job.run.assert_not_called()

    def test_transfer_completes_before_starting_bootstrap(self):
        job=self.connection();job.upload=Mock(return_value=('/fixture/upload',b'{}\n'))
        events=[]
        job.run.side_effect=lambda *a,**kw:self.assertEqual(events,[
            dict(stage='INFISICAL_TRANSFER',status='RUNNING'),dict(stage='INFISICAL_TRANSFER',status='PASS')])
        job.prepare({'role':'infisical'},events.append)
        self.assertEqual(job.run.call_args.kwargs['input'],b'STREAMS_INPUT_V1\n{}\n')

    def test_transfer_events_reach_the_matching_phase(self):
        import json
        for stage,phase in (('INFISICAL_TRANSFER','Infisical'),('STACK_TRANSFER','Stack')):
            self.assertEqual(phase_for(stage),phase)
            row=dict(stage=stage,status='RUNNING')
            self.assertEqual(parse_event('RECOVERY_EVENT '+json.dumps(row)),row)

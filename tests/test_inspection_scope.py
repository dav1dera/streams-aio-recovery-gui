"""Exercise the exact standalone remote read-only checkpoint scope code."""
import contextlib
import io
import json
from pathlib import PurePosixPath
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from recovery_gui.recovery_inspection import CHECKPOINT_SCOPE

COMMIT='b'*40
TAG='dr-20261006T210601Z'


def scope(state,role='stack',*,target_present=False,ciphertext=False,private=False,
          checkpoint_uid=0,checkpoint_mode=0o600,runner_uid=1000,symlink=None):
    home='/home/test'
    target='/opt/infisical' if role=='infisical' else home+'/streams-aio'
    runner=home+'/.local/share/streams-aio-'+('infisical-recovery' if role=='infisical' else 'recovery')
    files={'/etc/machine-id':b'machine-a\n'}
    directories={runner}
    if state is not None:files[runner+'/state.json']=json.dumps(state).encode()
    if target_present:directories.add(target)
    if ciphertext:directories.add(runner+'/ciphertext')
    if private:directories.add(runner+'/private')
    class ReadOnlyPath:
        def __init__(self,value):self.value=str(PurePosixPath(str(value)))
        def __str__(self):return self.value
        def __eq__(self,other):return self.value==str(other)
        def __truediv__(self,other):return ReadOnlyPath(PurePosixPath(self.value)/other)
        @property
        def parents(self):return [ReadOnlyPath(p) for p in PurePosixPath(self.value).parents]
        def is_symlink(self):return self.value==symlink
        def exists(self):return self.value in files or self.value in directories
        def read_bytes(self):return files[self.value]
        def read_text(self):return self.read_bytes().decode()
        def stat(self):
            if self.value==runner:return SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=runner_uid)
            if self.value not in files:raise FileNotFoundError()
            return SimpleNamespace(st_mode=stat.S_IFREG|checkpoint_mode,st_uid=checkpoint_uid,
                                   st_nlink=1,st_size=len(files[self.value]))
    output=io.StringIO()
    fake_pwd=SimpleNamespace(getpwuid=lambda uid:SimpleNamespace(pw_dir=home,pw_gid=1000))
    with patch('pathlib.Path',ReadOnlyPath),patch.dict(sys.modules,{'pwd':fake_pwd}), \
         patch.object(sys,'argv',['scope',runner,target,TAG,COMMIT,role,'snapshot']), \
         contextlib.redirect_stdout(output):
        try:exec(compile(CHECKPOINT_SCOPE,'checkpoint_scope','exec'),{})
        except SystemExit as error:
            if error.code:raise
    return json.loads(output.getvalue())


def initialized(role='stack'):
    return dict(schema=1,runner_version='0.2.0',machine_id='machine-a',
                target='/opt/infisical' if role=='infisical' else '/home/test/streams-aio',
                tooling_commit=COMMIT,completed=[],in_progress=None)


class CheckpointScopeTests(unittest.TestCase):
    def test_no_checkpoint_is_distinct_from_wrong_scope(self):
        result=scope(None)
        self.assertFalse(result['checkpoint_present'])
        self.assertTrue(result['scope_matches'])

    def test_checkpoint_before_clones_resumes_without_tag_or_public_commit(self):
        for role in ('stack','infisical'):
            with self.subTest(role=role):
                result=scope(initialized(role),role)
                self.assertTrue(result['checkpoint_present'])
                self.assertTrue(result['scope_matches'])
                self.assertTrue(result['operation_retryable'])
                self.assertFalse(result['infrastructure_verified'])
                self.assertEqual(result['early_prestart_verified'],role=='stack')

    def test_failed_download_can_retry_only_without_installed_ciphertext(self):
        state=initialized();state.update(completed=['CLONES'],public_commit=COMMIT,in_progress='DOWNLOAD')
        result=scope(state,target_present=True)
        self.assertTrue(result['scope_matches'])
        self.assertTrue(result['operation_retryable'])
        self.assertFalse(scope(state,target_present=True,ciphertext=True)['scope_matches'])

    def test_completed_download_requires_tag_and_stack_clone_requires_commit(self):
        state=initialized();state.update(completed=['CLONES','DOWNLOAD'],public_commit=COMMIT)
        self.assertFalse(scope(state,target_present=True)['scope_matches'])
        state=initialized();state.update(completed=['CLONES'],tag=TAG)
        self.assertFalse(scope(state,target_present=True)['scope_matches'])

    def test_present_point_fields_always_match(self):
        for field,value in (('tag','dr-20261004T023903Z'),('public_commit','a'*40),('tooling_commit','a'*40)):
            state=initialized();state[field]=value
            self.assertFalse(scope(state)['scope_matches'])

    def test_old_infisical_checkpoint_uses_tooling_pin(self):
        state=initialized('infisical')
        state.update(completed=['CLONES','DOWNLOAD','DECRYPT','INFISICAL_CONFIG','INFISICAL_DATABASE','INFISICAL_SERVER'],tag=TAG)
        result=scope(state,'infisical',target_present=True)
        self.assertTrue(result['scope_matches'])
        self.assertTrue(result['operation_retryable'])

    def test_clone_and_database_interruptions_require_review(self):
        state=initialized();state['in_progress']='CLONES'
        result=scope(state,target_present=True)
        self.assertTrue(result['scope_matches'])
        self.assertFalse(result['operation_retryable'])
        state=initialized('infisical');state.update(completed=['CLONES','DOWNLOAD','DECRYPT','INFISICAL_CONFIG'],tag=TAG,in_progress='INFISICAL_DATABASE')
        result=scope(state,'infisical',target_present=True)
        self.assertTrue(result['scope_matches'])
        self.assertFalse(result['operation_retryable'])

    def test_private_files_machine_target_home_and_ownership_remain_required(self):
        state=initialized()
        for kwargs in (dict(checkpoint_uid=1000),dict(checkpoint_mode=0o644),dict(runner_uid=0),
                       dict(symlink='/home/test')):
            with self.subTest(kwargs=kwargs):self.assertFalse(scope(state,**kwargs)['scope_matches'])
        for field,value in (('machine_id','another-machine'),('target','/home/other/streams-aio'),('schema',True),('completed',['CLONES','CLONES'])):
            changed=dict(state);changed[field]=value
            with self.subTest(field=field):self.assertFalse(scope(changed)['scope_matches'])

    def test_only_empty_preclone_checkpoint_proves_no_start_attempt(self):
        for change in ({'application_start_attempted':True},{'preparation':'PASS'},
                       {'runtime_profile':{}},{'operational_deployment':{}},{'native_agent':'ACTIVE_NO_RESTART_HOOKS'}):
            state=initialized();state.update(change)
            self.assertFalse(scope(state)['early_prestart_verified'])
        state=initialized();state['application_start_attempted']='false'
        self.assertFalse(scope(state)['scope_matches'])


if __name__=='__main__':unittest.main()

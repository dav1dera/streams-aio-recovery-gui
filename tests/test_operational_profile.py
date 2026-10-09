"""V3 removes only the isolated trial delta and preserves all restored data."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

path=Path(__file__).parents[1]/'tests/test_cometnet_trial_profile.py'
spec=importlib.util.spec_from_file_location('operational_trial_fixture',path)
fixture=importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
policy=fixture.policy


class SourceIdentity(unittest.TestCase):
    def test_new_operational_source_uses_actual_ssh_user_and_selected_commit(self):
        with patch.object(policy,'state_commit',return_value='c'*40), \
             patch.dict(sys.modules,{'pwd':N(getpwuid=lambda uid:N(pw_name='new-replacement'))}):
            self.assertEqual(policy.source_identity('/home/new-replacement/streams-aio'),
                             ('new-replacement','c'*40))
        with patch.object(policy,'state_commit',return_value=None):
            self.assertEqual(policy.source_identity('/synthetic/legacy'),('test',policy.COMMIT))


class OperationalProfile(fixture.TrialProfile):
    # Inherited transaction/security tests continue checking old V1/V2 bytes.
    def production_runner(self, args):
        if args[:3]==['docker','compose','--env-file']:
            if args.count('-f')==2:
                return json.dumps(self.base).encode()
            desired=fixture.fixtures.effective(self.root,self.base,first_boot=True)
            if self.bad_candidate:
                desired['services']['comet']['environment']['DATABASE_URL']='corrupted'
            if self.resource_race: self.containers[-1]['Id']='f'*64
            return json.dumps(desired).encode()
        return self.runner(args)

    def promote(self):
        record=dict(schema=1,routing_mode='parallel_test',domain_target_address='192.0.2.29')
        with patch.object(policy,'deployment_record',return_value=record), \
             patch.object(policy,'deployment_scope',lambda root,home,state:(root,home)):
            return policy.promote_operational(self.root,self.home,self.state,self.model,self.production_runner,
                                              'parallel_test','192.0.2.29')

    def test_operational_promotion_restores_actual_env_and_keeps_database_agent_and_private_inputs(self):
        self.migrate()
        password=(self.root/policy.TRIAL_PASSWORD).read_bytes()
        self.model['services']['cometnet']['environment'].update(policy.COMETNET_TRIAL_ENV)
        self.model['services']['cometnet']['environment']['COMETNET_NETWORK_PASSWORD']=password[:-1].decode()
        self.state['application_recovery']='STARTED_NEEDS_FUNCTIONAL_TEST'; self.save_state()
        before=copy.deepcopy(self.state); before_sources=policy.source_hashes(self.root,True)
        self.assertEqual(self.promote()['profile'],policy.OPERATIONAL_PROFILE)
        self.assertEqual((self.root/policy.ARTIFACT).read_bytes(),policy.overlay(self.root,True))
        self.assertFalse((self.root/policy.TRIAL_PASSWORD).exists())
        self.assertEqual(self.state['native_agent'],before['native_agent'])
        self.assertEqual(self.state['completed'],before['completed'])
        self.assertEqual(self.state['aio_recovery'],before['aio_recovery'])
        self.assertEqual(policy.source_hashes(self.root,True),before_sources)
        archives=list((self.home/'runtime-profile/operational-v3').iterdir())
        self.assertEqual((archives[0]/'trial.password').read_bytes(),password)
        self.assertEqual(json.loads((archives[0]/'state.json').read_bytes()),before)
        self.assertNotIn(password[:-1].decode(),json.dumps(self.state))
        self.assertEqual(self.promote(),{'applied':False,'profile':policy.OPERATIONAL_PROFILE})

    def test_operational_checkpoint_commit_failure_rolls_back_overlay_password_and_state(self):
        self.migrate(); password=(self.root/policy.TRIAL_PASSWORD).read_bytes()
        self.model['services']['cometnet']['environment'].update(policy.COMETNET_TRIAL_ENV)
        self.model['services']['cometnet']['environment']['COMETNET_NETWORK_PASSWORD']=password[:-1].decode()
        before=(self.home/'state.json').read_bytes(); overlay=(self.root/policy.ARTIFACT).read_bytes()
        self.fail_state_commit=True
        with self.assertRaisesRegex(policy.Refused,'OPERATIONAL_PROFILE_TRANSACTION_FAILED'): self.promote()
        self.assertEqual((self.home/'state.json').read_bytes(),before)
        self.assertEqual((self.root/policy.ARTIFACT).read_bytes(),overlay)
        self.assertEqual((self.root/policy.TRIAL_PASSWORD).read_bytes(),password)

    def test_operational_candidate_cannot_change_private_database_url(self):
        self.bad_candidate=True
        before=(self.home/'state.json').read_bytes()
        with self.assertRaisesRegex(policy.Refused,'RUNTIME_PROFILE_CANDIDATE_REFUSED'): self.promote()
        self.assertEqual((self.home/'state.json').read_bytes(),before)
        self.assertEqual((self.root/policy.ARTIFACT).read_bytes(),self.old_artifact)

    def test_operational_ownership_race_prevents_commit(self):
        self.resource_race=True
        before=(self.home/'state.json').read_bytes()
        with self.assertRaisesRegex(policy.Refused,'RUNTIME_PROFILE_CHANGED'): self.promote()
        self.assertEqual((self.home/'state.json').read_bytes(),before)


if __name__=='__main__': unittest.main()

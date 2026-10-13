"""Private Tailscale binding, rotation and transaction safety regressions."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tailscale_profile_fixture', ROOT/'tests/test_cometnet_trial_profile.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
policy = fixture.policy
def fixture_environment(number):
    # Assemble deliberately synthetic values at runtime; these are not credentials.
    return (b'TS_AUTH' + b'KEY=' + b'synthetic-' + b'headscale-'
            + f'key-{number:04d}'.encode() + b'\nTS_AUTH_ONCE=true\n')


KEY = fixture_environment(1)
SECOND_KEY = fixture_environment(2)


class KeyFormat(unittest.TestCase):
    def test_only_canonical_noninterpolated_private_dotenv_is_accepted(self):
        self.assertEqual(policy.parse_tailscale_env(KEY), 'synthetic-headscale-key-0001')
        for size in (16, 512):
            self.assertEqual(policy.parse_tailscale_env(
                b'TS_AUTHKEY=' + b'a'*size + b'\nTS_AUTH_ONCE=true\n'), 'a'*size)
        for raw in (b'', b'TS_AUTHKEY=\nTS_AUTH_ONCE=true\n', KEY.replace(b'true', b'false'),
                    KEY.replace(b'\n', b'\r\n'), KEY + b'OTHER=value\n', KEY + KEY,
                    KEY.replace(b'key-0001', b'key 0001'), KEY.replace(b'key-0001', b'key$0001'),
                    KEY.replace(b'key-0001', b'key#0001'), KEY.replace(b'key-0001', b'key"0001'),
                    KEY.replace(b'key-0001', b"key'0001"), KEY[:-1], KEY.decode(),
                    b'TS_AUTHKEY=' + b'a'*513 + b'\nTS_AUTH_ONCE=true\n',
                    b'TS_AUTHKEY=' + b'a'*15 + b'\nTS_AUTH_ONCE=true\n'):
            with self.subTest(raw_type=type(raw).__name__, length=len(raw)), \
                    self.assertRaisesRegex(policy.Refused, '^TAILSCALE_PROFILE_KEY_REFUSED$'):
                policy.parse_tailscale_env(raw)


class TailscaleProfile(unittest.TestCase):
    save_state = fixture.TrialProfile.save_state

    def setUp(self):
        fixture.TrialProfile.setUp(self)
        for index, (name, service) in enumerate(self.base['services'].items(), 1):
            if not isinstance(service.get('image'), str) or '@sha256:' not in service['image']:
                service['image'] = 'synthetic/' + name + '@sha256:' + format(index, '064x')
        self.base['services']['tailscale'] = dict(image=policy.TAILSCALE_IMAGE, network_mode='host',
            environment={'TS_AUTHKEY': '', 'TS_AUTH_ONCE': 'false', 'TS_HOSTNAME': 'preserved-node',
                         'TS_EXTRA_ARGS': '--login-server=https://headscale.example.test'},
            volumes=[dict(type='bind', source=str(self.root/'data/tailscale'), target='/var/lib/tailscale')],
            depends_on={'headscale': {'condition':'service_started', 'required':True}})
        self.base['services']['headscale'] = dict(image=policy.HEADSCALE_IMAGE,
            healthcheck={'test':['CMD','headscale','health']},
            volumes=[dict(type='bind', source=str(self.root/'data/headscale'), target='/var/lib/headscale')])
        self.base['services']['npm'] = dict(image=policy.NPM_IMAGE,
            healthcheck={'test':['CMD','/usr/bin/check-health']},
            depends_on={'postgres':{'condition':'service_healthy', 'required':True}})
        self.model = fixture.fixtures.effective(self.root, self.base, first_boot=True)
        for row in self.containers:
            row['Config']['Image'] = self.model['services'][row['Config']['Labels']['com.docker.compose.service']]['image']
        for index, name in enumerate(('tailscale','headscale','npm'), 20):
            self.containers.append(dict(Id=format(index, '064x'), Config=dict(
                Image=self.model['services'][name]['image'], Labels={
                    'com.docker.compose.project':'streams-aio',
                    'com.docker.compose.project.working_dir':str(self.root),
                    'com.docker.compose.service':name})))
        self.preserved_files = {}
        for name in ('data/npm/data/database.sqlite', 'data/aiostreams/data/db.sqlite',
                     'data/aiometadata/data/db.sqlite', 'data/tailscale/tailscaled.state',
                     'data/headscale/db.sqlite', 'synthetic-volumes/postgres-cluster/18/docker/PG_VERSION'):
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('initialized-preserved-data:' + name).encode())
            self.preserved_files[path] = path.read_bytes()
        self.fail_key_commit = False
        self.candidate_mutation = None
        self.key_race = False
        self.old_model_drift = False

    def file_info(self, path):
        if Path(path) == self.root/policy.TAILSCALE_ENV:
            self.assertTrue(Path(path).is_file())
            return SimpleNamespace(st_uid=1000, st_gid=1000, st_mode=stat.S_IFREG|0o600, st_nlink=1)
        return fixture.TrialProfile.file_info(self, path)

    def atomic(self, path, raw, mode, uid, gid):
        if Path(path) == self.root/policy.TAILSCALE_ENV and self.fail_key_commit:
            self.fail_key_commit = False
            raise OSError('synthetic key write failure')
        fixture.TrialProfile.atomic(self, path, raw, mode, uid, gid)

    def desired(self, key):
        desired = fixture.fixtures.effective(self.root, self.base, first_boot=True)
        service = desired['services']['tailscale']
        service['environment'].update(TS_AUTHKEY=key, TS_AUTH_ONCE='true')
        service['depends_on'].update({name:dict(condition='service_healthy', required=True)
                                      for name in ('headscale','npm')})
        return desired

    def runner(self, args):
        if args[:3] == ['docker', 'compose', '--env-file']:
            self.calls.append(args)
            if args.count('-f') == 2:
                return json.dumps(self.base).encode()
            path = Path(args[max(index for index, arg in enumerate(args) if arg == '-f') + 1])
            text = path.read_text()
            key_path = Path(json.loads(next(line.split(': ',1)[1] for line in text.splitlines()
                                             if line.strip().startswith('- path:'))))
            desired = self.desired(policy.parse_tailscale_env(key_path.read_bytes()))
            if self.bad_candidate:
                desired['services']['comet']['environment']['DATABASE_URL'] = 'changed-private-credential'
            if self.candidate_mutation:
                self.candidate_mutation(desired)
            if self.resource_race:
                self.containers[-1]['Id'] = 'f'*64
            if self.drift_after_candidate:
                (self.root/'data/postgres/init/init.sql').write_bytes(b'changed private SQL')
            if self.key_race:
                (self.root/policy.TAILSCALE_ENV).write_bytes(KEY.replace(b'0001', b'0003'))
            if self.old_model_drift:
                self.model['services']['tailscale']['environment']['TS_HOSTNAME'] = 'foreign-change'
            return json.dumps(desired).encode()
        return fixture.TrialProfile.runner(self, args)

    def migrate(self, raw=KEY):
        result = policy.migrate_tailscale(self.root, self.home, self.state, self.model, self.runner, raw)
        if result['applied']:
            self.model = self.desired(policy.parse_tailscale_env(raw))
        return result

    def assert_preserved(self):
        self.assertEqual({path:path.read_bytes() for path in self.preserved_files}, self.preserved_files)
        self.assertEqual((self.root/'.env').read_bytes(), self.effective_env)
        self.assertFalse(list((self.root/'.generated').glob('.tailscale-*')))

    def test_started_checkpoint_binds_private_key_and_preserves_all_restored_state(self):
        before = copy.deepcopy(self.state)
        original_runtime = copy.deepcopy((self.containers, self.volumes))
        self.assertEqual(self.migrate(), {'applied':True, 'profile':policy.FIRST_BOOT_PROFILE})
        self.assertEqual({key:value for key,value in self.state.items() if key != 'runtime_profile'},
                         {key:value for key,value in before.items() if key != 'runtime_profile'})
        self.assertEqual((self.containers, self.volumes), original_runtime)
        self.assertEqual((self.root/policy.TAILSCALE_ENV).read_bytes(), KEY)
        self.assertEqual(self.state['runtime_profile']['tailscale_sha256'], policy.sha(KEY))
        self.assertEqual((self.root/policy.ARTIFACT).read_bytes(),
                         policy.overlay(self.root, first_boot=True, tailscale=True))
        self.assertTrue(policy.validate(self.root, self.home, self.state))
        token = policy.parse_tailscale_env(KEY)
        self.assertNotIn(token, json.dumps(self.state))
        self.assertNotIn(token, repr(self.calls))
        self.assertNotIn(token.encode(), (self.root/policy.ARTIFACT).read_bytes())
        archives = list((self.home/policy.TAILSCALE_MIGRATION_BACKUP).iterdir())
        self.assertEqual(len(archives), 1)
        self.assertEqual(json.loads((archives[0]/'state.json').read_bytes()), before)
        self.assertEqual((archives[0]/'runtime.compose.yaml').read_bytes(), self.old_artifact)
        self.assertNotIn(token.encode(), (archives[0]/'journal.json').read_bytes())
        for path, mode, uid, gid in self.writes:
            if path == self.root/policy.TAILSCALE_ENV:
                self.assertEqual((mode,uid,gid), (0o600,1000,1000))
            if path.is_relative_to(self.home/policy.TAILSCALE_MIGRATION_BACKUP):
                self.assertEqual((mode,uid,gid), (0o600,0,0))
        self.assert_preserved()

    def test_same_registered_key_is_validated_noop_without_docker_calls(self):
        self.migrate()
        before = (self.home/'state.json').read_bytes()
        self.assertEqual(policy.migrate_tailscale(self.root, self.home, self.state, {},
            lambda args:self.fail('No-op must not query Docker'), KEY),
            {'applied':False, 'profile':policy.FIRST_BOOT_PROFILE})
        self.assertEqual((self.home/'state.json').read_bytes(), before)

    def test_rotation_archives_old_private_key_and_preserves_profile_and_data(self):
        self.migrate()
        before = copy.deepcopy(self.state)
        self.assertTrue(self.migrate(SECOND_KEY)['applied'])
        self.assertEqual((self.root/policy.TAILSCALE_ENV).read_bytes(), SECOND_KEY)
        self.assertEqual(self.state['runtime_profile']['id'], policy.FIRST_BOOT_PROFILE)
        archives = list((self.home/policy.TAILSCALE_MIGRATION_BACKUP).iterdir())
        previous = [path for path in archives if (path/'tailscale.env').exists()]
        self.assertEqual(len(previous), 1)
        self.assertEqual((previous[0]/'tailscale.env').read_bytes(), KEY)
        self.assertEqual(json.loads((previous[0]/'state.json').read_bytes()), before)
        self.assertTrue(policy.validate(self.root, self.home, self.state))
        self.assert_preserved()

    def test_failed_key_artifact_or_checkpoint_commit_restores_every_live_artifact(self):
        for bound in (False, True):
            if bound:
                self.migrate()
            old_state = (self.home/'state.json').read_bytes()
            old_artifact = (self.root/policy.ARTIFACT).read_bytes()
            old_key = (self.root/policy.TAILSCALE_ENV).read_bytes() if bound else None
            before = copy.deepcopy(self.state)
            for flag in ('fail_key_commit','fail_artifact_commit','fail_state_commit'):
                with self.subTest(bound=bound, flag=flag):
                    setattr(self, flag, True)
                    with self.assertRaisesRegex(policy.Refused, '^TAILSCALE_PROFILE_TRANSACTION_FAILED$'):
                        self.migrate(SECOND_KEY)
                    self.assertEqual((self.home/'state.json').read_bytes(), old_state)
                    self.assertEqual((self.root/policy.ARTIFACT).read_bytes(), old_artifact)
                    self.assertEqual(self.state, before)
                    if bound:
                        self.assertEqual((self.root/policy.TAILSCALE_ENV).read_bytes(), old_key)
                    else:
                        self.assertFalse((self.root/policy.TAILSCALE_ENV).exists())
                    self.assertTrue(policy.validate(self.root, self.home, self.state))
                    self.assert_preserved()

    def test_candidate_cannot_change_private_urls_hostname_health_or_other_dependencies(self):
        changes = (
            lambda obj:obj['services']['comet']['environment'].update(DATABASE_URL='changed'),
            lambda obj:obj['services']['tailscale']['environment'].update(TS_AUTHKEY='wrong-private-key'),
            lambda obj:obj['services']['tailscale']['environment'].update(TS_AUTH_ONCE='false'),
            lambda obj:obj['services']['tailscale']['environment'].update(TS_HOSTNAME='changed'),
            lambda obj:obj['services']['headscale'].pop('healthcheck'),
            lambda obj:obj['services']['tailscale']['depends_on'].update(npm={'condition':'service_started'}),
            lambda obj:obj['services']['postgres'].update(user='1000:1000'))
        before = (self.home/'state.json').read_bytes()
        for change in changes:
            with self.subTest(change=changes.index(change)):
                self.candidate_mutation = change
                with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_CANDIDATE_REFUSED'):
                    self.migrate()
                self.assertEqual((self.home/'state.json').read_bytes(), before)
                self.assertFalse((self.root/policy.TAILSCALE_ENV).exists())
                self.assertEqual((self.root/policy.ARTIFACT).read_bytes(), self.old_artifact)
                self.assert_preserved()

    def test_unexpected_existing_effective_delta_refuses_before_archiving(self):
        self.model['services']['comet']['environment']['DATABASE_URL'] = 'unregistered-delta'
        with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_CANDIDATE_REFUSED'):
            self.migrate()
        self.assertEqual(self.writes, [])

    def test_foreign_runtime_and_changed_pinned_images_refuse_before_archiving(self):
        row = self.containers[-1]
        row['Config']['Labels']['com.docker.compose.project'] = 'foreign'
        with self.assertRaisesRegex(policy.Refused, 'DOCKER_OWNERSHIP_REFUSED'):
            self.migrate()
        row['Config']['Labels']['com.docker.compose.project'] = 'streams-aio'
        row['Config']['Image'] = 'foreign/image@sha256:' + 'f'*64
        with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_IMAGE_CHANGED'):
            self.migrate()
        row['Config']['Image'] = self.model['services']['npm']['image']
        self.base['services']['tailscale']['image'] = 'tailscale/tailscale:latest'
        self.model['services']['tailscale']['image'] = 'tailscale/tailscale:latest'
        with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_IMAGE_CHANGED'):
            self.migrate()
        self.assertEqual(self.writes, [])

    def test_drift_after_staging_prevents_any_live_commit(self):
        before = (self.home/'state.json').read_bytes()
        self.resource_race = True
        with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_CHANGED'):
            self.migrate()
        self.assertEqual((self.home/'state.json').read_bytes(), before)
        self.assertFalse((self.root/policy.TAILSCALE_ENV).exists())
        self.assertEqual((self.root/policy.ARTIFACT).read_bytes(), self.old_artifact)
        self.assert_preserved()

    def test_rotation_rechecks_existing_private_key_before_commit(self):
        self.migrate()
        before = (self.home/'state.json').read_bytes()
        self.key_race = True
        with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_CHANGED'):
            self.migrate(SECOND_KEY)
        self.assertEqual((self.home/'state.json').read_bytes(), before)
        self.assertNotEqual((self.root/policy.TAILSCALE_ENV).read_bytes(), SECOND_KEY)
        self.assert_preserved()

    def test_source_drift_after_candidate_keeps_live_profile_and_checkpoint(self):
        before = (self.home/'state.json').read_bytes()
        self.drift_after_candidate = True
        with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_SOURCE_CHANGED'):
            self.migrate()
        self.assertEqual((self.home/'state.json').read_bytes(),before)
        self.assertEqual((self.root/policy.ARTIFACT).read_bytes(),self.old_artifact)
        self.assertFalse((self.root/policy.TAILSCALE_ENV).exists())
        self.assert_preserved()

    def test_same_key_noop_still_refuses_changed_private_file(self):
        self.migrate()
        (self.root/policy.TAILSCALE_ENV).write_bytes(SECOND_KEY)
        with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_CHANGED'):
            policy.migrate_tailscale(self.root,self.home,self.state,{},
                lambda args:self.fail('Changed profile must refuse before Docker calls'),KEY)

    def test_registered_binding_rejects_extra_missing_fields_and_bad_private_metadata(self):
        self.migrate()
        before = copy.deepcopy(self.state)
        for change in ({'extra':'unexpected'}, {'tailscale_artifact':'../foreign.env'},
                       {'tailscale_sha256':'0'*64}):
            self.state = copy.deepcopy(before)
            self.state['runtime_profile'].update(change)
            self.save_state()
            with self.subTest(change=change), self.assertRaises(policy.Refused):
                policy.validate(self.root, self.home, self.state)
        self.state = copy.deepcopy(before)
        self.state['runtime_profile'].pop('tailscale_sha256')
        self.save_state()
        with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_CHANGED'):
            policy.validate(self.root, self.home, self.state)
        self.state = before
        self.save_state()
        for uid,gid,mode in ((0,1000,0o600),(1000,0,0o600),(1000,1000,0o640)):
            def info(path):
                value = self.file_info(path)
                if Path(path) == self.root/policy.TAILSCALE_ENV:
                    value.st_uid, value.st_gid, value.st_mode = uid,gid,stat.S_IFREG|mode
                return value
            with self.subTest(uid=uid,gid=gid,mode=mode), patch.object(policy,'regular',info), \
                    self.assertRaisesRegex(policy.Refused,'TAILSCALE_PROFILE_KEY_REFUSED'):
                policy.validate(self.root,self.home,self.state)
        (self.root/policy.TAILSCALE_ENV).unlink()
        with self.assertRaisesRegex(policy.Refused,'TAILSCALE_PROFILE_KEY_REFUSED'):
            policy.validate(self.root,self.home,self.state)

    def test_orphan_private_key_is_not_adopted(self):
        (self.root/policy.TAILSCALE_ENV).write_bytes(KEY)
        with self.assertRaisesRegex(policy.Refused, 'RUNTIME_PROFILE_CHANGED'):
            self.migrate()
        self.assertEqual(self.writes, [])

    def test_operational_promotion_retains_binding_and_rotation_is_supported(self):
        self.migrate()
        record = dict(schema=1,routing_mode='parallel_test',domain_target_address='192.0.2.29')
        with patch.object(policy,'deployment_record',return_value=record), \
             patch.object(policy,'deployment_scope',lambda root,home,state:(root,home)):
            result = policy.promote_operational(self.root,self.home,self.state,self.model,self.runner,
                                                'parallel_test','192.0.2.29')
            self.assertEqual(result, {'applied':True,'profile':policy.OPERATIONAL_PROFILE})
            self.assertEqual((self.root/policy.TAILSCALE_ENV).read_bytes(),KEY)
            self.assertEqual(self.state['runtime_profile']['tailscale_sha256'],policy.sha(KEY))
            self.assertEqual((self.root/policy.ARTIFACT).read_bytes(),
                             policy.overlay(self.root,first_boot=True,tailscale=True))
            self.assertTrue(policy.validate(self.root,self.home,self.state))
            self.assertEqual(self.migrate(SECOND_KEY)['profile'],policy.OPERATIONAL_PROFILE)
        self.assert_preserved()

    def test_trial_migration_cannot_drop_private_binding(self):
        self.migrate()
        before = (self.home/'state.json').read_bytes()
        with self.assertRaisesRegex(policy.Refused, 'COMETNET_TRIAL_SCOPE_REFUSED'):
            policy.migrate_cometnet_trial(self.root,self.home,self.state,self.model,self.runner)
        self.assertEqual((self.home/'state.json').read_bytes(),before)
        self.assertTrue(policy.validate(self.root,self.home,self.state))

    def test_trial_profile_requires_operational_promotion_before_tailscale_binding(self):
        policy.migrate_cometnet_trial(self.root,self.home,self.state,self.model,
                                     lambda args:fixture.TrialProfile.runner(self,args))
        before = (self.home/'state.json').read_bytes()
        self.writes.clear()
        with self.assertRaisesRegex(policy.Refused, 'TAILSCALE_PROFILE_SCOPE_REFUSED'):
            self.migrate()
        self.assertEqual(self.writes,[])
        self.assertEqual((self.home/'state.json').read_bytes(),before)
        self.assertFalse((self.root/policy.TAILSCALE_ENV).exists())

    def test_failed_operational_promotion_preserves_private_binding_and_profile(self):
        self.migrate()
        before = (self.home/'state.json').read_bytes()
        old_artifact = (self.root/policy.ARTIFACT).read_bytes()
        record = dict(schema=1,routing_mode='parallel_test',domain_target_address='192.0.2.29')
        self.fail_state_commit = True
        with patch.object(policy,'deployment_record',return_value=record), \
             patch.object(policy,'deployment_scope',lambda root,home,state:(root,home)), \
             self.assertRaisesRegex(policy.Refused,'OPERATIONAL_PROFILE_TRANSACTION_FAILED'):
            policy.promote_operational(self.root,self.home,self.state,self.model,self.runner,
                                       'parallel_test','192.0.2.29')
        self.assertEqual((self.home/'state.json').read_bytes(),before)
        self.assertEqual((self.root/policy.ARTIFACT).read_bytes(),old_artifact)
        self.assertEqual((self.root/policy.TAILSCALE_ENV).read_bytes(),KEY)
        self.assertTrue(policy.validate(self.root,self.home,self.state))
        self.assert_preserved()


@unittest.skipUnless(os.name == 'posix' and hasattr(os,'geteuid') and os.geteuid() == 0,
                     'Real UID/mode enforcement requires the root Linux helper')
class LinuxPrivateKey(unittest.TestCase):
    def test_private_key_is_0600_user_owned_and_hardlinked_key_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'.generated').mkdir()
            path = root/policy.TAILSCALE_ENV
            policy.atomic(path,KEY,0o600,1000,1000)
            info = path.stat()
            self.assertEqual((info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)),(1000,1000,0o600))
            self.assertEqual(policy.tailscale_private_env(root,policy.sha(KEY)),KEY)
            os.link(path,root/'.generated/second-link')
            with self.assertRaisesRegex(policy.Refused,'RUNTIME_PROFILE_PATH_REFUSED'):
                policy.tailscale_private_env(root,policy.sha(KEY))


if __name__ == '__main__':
    unittest.main()

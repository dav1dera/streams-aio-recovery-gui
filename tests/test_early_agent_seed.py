"""New Compose/private env recovery from exact encrypted Agent templates.

The archive, public renderer, staging and output promotion are real. The CLI
transport uses synthetic template output; no network or real credential is read.
"""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'remote'))
import native_agent as agent
import recover as recovery


class EarlyAgentSeed(unittest.TestCase):
    def setUp(self):
        fixture_root = ROOT.parent/'gui-test-tmp' if os.name == 'nt' else None
        if fixture_root is not None:
            fixture_root.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=fixture_root)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root, self.home = self.base/'stack', self.base/'recovery'
        (self.root/'config').mkdir(parents=True)
        (self.root/'data/new').mkdir(parents=True)
        (self.home/'private').mkdir(parents=True)
        self.uid = os.getuid() if hasattr(os,'getuid') else 0
        self.gid = os.getgid() if hasattr(os,'getgid') else 0
        self.plan = dict(readiness_blockers=[],required_values=['/existing/TOKEN'],
            env_files={'.secrets/existing.env':{'TOKEN':{'path':'/existing','key':'TOKEN'}}},
            service_folder_exports={},root_env={},files=[],runtime_fields={},
            postgres_bootstrap={'destination':'.generated/postgres.sql'})
        (self.root/'config/dr-render-plan.json').write_text(json.dumps(self.plan))
        self.plan_before = (self.root/'config/dr-render-plan.json').read_bytes()
        self.compose = {'services':{'new':{'image':'example.invalid/new:1',
            'env_file':['data/new/.env','.secrets/new.env']}}}
        self.write_compose()
        (self.root/'data/new/.env').write_text('WORKERS=4\nLOG_LEVEL=debug\n')
        (self.root/'.dr-fresh-target.json').write_text(json.dumps({'root':str(self.root)}))
        inputs = self.root/'.secrets/dr-inputs'
        inputs.mkdir(parents=True)
        (inputs/'existing.goenv').write_text('TOKEN="old-private-canary"\n')
        (inputs/'existing.goenv').chmod(0o600)
        self.archive = self.home/'private/infisical-agent.tar.gz'
        self.rows = [self.row('new')]
        self.write_archive()
        self.rendered_configs = []
        # Preserve all production checks on POSIX. Windows has no ownership or
        # owner-only mode model, so emulate only those unavailable stat fields.
        if os.name == 'nt':
            original_stat = Path.stat
            def windows_stat(path,*args,**kwargs):
                original = original_stat(path,*args,**kwargs)
                values = list(original)
                values[0] = (stat.S_IFDIR|0o750 if stat.S_ISDIR(original.st_mode)
                             else stat.S_IFREG|0o600)
                values[4],values[5] = self.uid,self.gid
                return os.stat_result(values)
            self.enter(patch.object(Path,'stat',windows_stat))
            self.enter(patch.object(os,'O_NOFOLLOW',0,create=True))
            self.enter(patch.object(os,'fchown',lambda *args:None,create=True))
            self.enter(patch.object(os,'fchmod',lambda *args:None,create=True))
            self.enter(patch.object(os,'geteuid',lambda:0,create=True))
        self.enter(patch.object(os,'chown',lambda *args:None,create=True))
        self.enter(patch.object(agent,'pinned_cli',return_value=Path('/synthetic-cli')))
        self.enter(patch.object(agent,'command',side_effect=self.cli))
        self.renderer = recovery.load_module(ROOT/'tests/fixtures/pinned_dr_renderer.py','seed_pinned_fixture')

    def enter(self,manager):
        value = manager.__enter__()
        self.addCleanup(manager.__exit__,None,None,None)
        return value

    def row(self,name,source_root='/home/pi/streams-aio'):
        return {'destination-path':source_root+'/.secrets/'+name+'.env',
            'template-content':'{{ range secret "project" "prod" "/explicit-custom-folder" }}'+name+'{{ end }}',
            'config':{'execute':{'command':'PRIVATE_HOOK_MUST_NEVER_RUN'}},
            'extra-private-field':'MUST_NOT_REPLAY'}

    def write_compose(self):
        (self.root/'docker-compose.yml').write_text(json.dumps(self.compose))

    def write_archive(self,extras=None):
        config = {'infisical':{'address':'https://old-api.example.invalid'},
            'auth':{'type':'universal-auth','config':{'client-id':'/etc/infisical/client-id',
                'client-secret':'/etc/infisical/client-secret'}},'templates':self.rows}
        files = {'etc/infisical/agent-config.json':json.dumps(config).encode(),
            'etc/infisical/client-id':b'client-id-private-canary',
            'etc/infisical/client-secret':b'client-secret-private-canary'}
        files.update(extras or {})
        with tarfile.open(self.archive,'w:gz') as archive:
            for name,raw in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                archive.addfile(member,io.BytesIO(raw))
        self.archive.chmod(0o600)

    def cli(self,args,code,**kwargs):
        self.assertEqual(code,'AGENT_FIRST_RENDER_FAILED')
        self.assertEqual(args[:5],['sudo','-H','-u','synthetic','--'])
        config = json.loads(Path(args[-1]).read_bytes())
        self.rendered_configs.append(config)
        self.assertEqual(config['infisical'],{'address':'http://127.0.0.1:43123','exit-after-auth':True})
        self.assertNotIn('PRIVATE_HOOK_MUST_NEVER_RUN',json.dumps(config))
        self.assertNotIn('MUST_NOT_REPLAY',json.dumps(config))
        self.assertNotIn('client-secret-private-canary',json.dumps(config))
        for index,row in enumerate(config['templates']):
            output = Path(row['destination-path'])
            output.write_bytes(('API_KEY=new-private-canary-'+str(index)+'\n').encode())
            output.chmod(0o600)
        return b''

    def seed(self):
        return agent.seed_required_envs(self.root,self.home,self.archive,self.plan,
            'http://127.0.0.1:43123',uid=self.uid,gid=self.gid,user='synthetic')

    def public_render(self):
        dr = self.renderer
        with patch.object(dr,'sql_bootstrap',return_value=b'SELECT 1;'),contextlib.redirect_stdout(io.StringIO()):
            dr.render(N(target=str(self.root),input_dir=None,mode='fresh',synthetic=True,deployment_gid=self.gid))

    def test_new_service_reaches_first_compose_inspection_without_public_mapping_edits(self):
        job = recovery.Recovery.__new__(recovery.Recovery)
        job.root,job.home,job.private,job.tooling = self.root,self.home,self.home/'private',ROOT/'remote'
        job.state = {'completed':[],'in_progress':None}
        job.state_path = self.home/'state.json'
        job.config = {'infisical_address':'http://127.0.0.1:43123','ssh_bridge':True}
        trace = []
        for method in ('auth','validate_resume','clones','download','decrypt','initialize','inputs','npm','aio'):
            setattr(job,method,Mock())
        run_script = job.run_script
        def script(name,action,*extra,**kwargs):
            trace.append(action)
            if action == 'render':
                return run_script(name,action,*extra,**kwargs)
        job.run_script = script
        real_seed = agent.seed_required_envs
        def native_seed(*args,**kwargs):
            trace.append('private-seed')
            root_before = (self.root/'.env').read_bytes()
            result = real_seed(self.root,self.home,self.archive,self.plan,'http://127.0.0.1:43123',
                               uid=self.uid,gid=self.gid,user='synthetic')
            self.assertEqual((self.root/'.env').read_bytes(),root_before)
            return result
        def command(args,code,**kwargs):
            if code == 'FRESH_RENDERER_REFUSED':
                self.public_render()
            return b''
        def first_compose():
            trace.append('first-compose')
            self.assertIn('WORKERS=4',(self.root/'data/new/.env').read_text())
            self.assertIn('new-private-canary',(self.root/'.secrets/new.env').read_text())
            self.assertIn('old-private-canary',(self.root/'.secrets/existing.env').read_text())
        job.prepare_first_boot = first_compose
        with patch.object(recovery,'load_module',return_value=agent), \
             patch.object(recovery,'command',side_effect=command), \
             patch.object(recovery,'stack_preflight'),patch.object(recovery,'event'), \
             patch.object(agent,'seed_required_envs',side_effect=native_seed):
            job.prepare()
        self.assertLess(trace.index('render'),trace.index('private-seed'))
        self.assertLess(trace.index('private-seed'),trace.index('first-compose'))
        self.assertEqual(job.state['preparation'],'PASS')
        self.assertEqual(set(job.state['agent_seed']['outputs']),{'.secrets/new.env'})
        self.assertNotIn('private-canary',json.dumps(job.state))
        self.assertEqual((self.root/'config/dr-render-plan.json').read_bytes(),self.plan_before)
        marker = json.loads((self.root/'.generated/dr-render-complete.json').read_bytes())
        self.assertNotIn('.secrets/new.env',marker['outputs'])

    def test_second_generation_destination_rebases_and_public_templates_remain_unwatched(self):
        self.rows = [self.row('new','/home/test/streams-aio'),
            {'destination-path':'/home/test/streams-aio/data/new/.env','template-content':'WORKERS=4'}]
        self.write_archive()
        before = (self.root/'data/new/.env').read_bytes()
        outputs = self.seed()
        self.assertEqual(set(outputs),{'.secrets/new.env'})
        self.assertEqual((self.root/'data/new/.env').read_bytes(),before)
        self.assertEqual(len(self.rendered_configs[0]['templates']),1)

    def test_known_and_optional_targets_need_no_cli_or_archive(self):
        self.compose['services']['new']['env_file'] = ['.secrets/existing.env',
            {'path':'.secrets/optional.env','required':False}]
        self.write_compose()
        self.archive.unlink()
        self.assertEqual(self.seed(),{})
        self.assertEqual(self.rendered_configs,[])

    def test_missing_duplicate_escaped_or_mixed_mapping_refuses_before_cli(self):
        examples = [([self.row('other')],'AGENT_SEED_MAPPING_INCOMPLETE'),
            ([self.row('new'),self.row('new')],'AGENT_DUPLICATE_DESTINATION'),
            ([dict(self.row('new'),**{'destination-path':'/home/pi/streams-aio/.secrets/../new.env'})],
                'AGENT_TEMPLATE_PATH_UNSUPPORTED'),
            ([self.row('new'),self.row('other','/home/test/streams-aio')],'AGENT_TEMPLATE_ROOT_NOT_UNIQUE')]
        for rows,code in examples:
            with self.subTest(code=code):
                self.rows = rows
                self.write_archive()
                with self.assertRaisesRegex(agent.Refused,'^'+code+'$'):
                    self.seed()
                self.assertFalse((self.root/'.secrets/new.env').exists())
                self.assertEqual(self.rendered_configs,[])

    def test_missing_source_and_invalid_compose_path_refuse_before_cli(self):
        self.rows = [dict(self.row('new'),**{'source-path':'/etc/infisical/missing-template'})]
        self.write_archive()
        with self.assertRaisesRegex(agent.Refused,'^PRIVATE_INPUT_FILE_REQUIRED$'):
            self.seed()
        self.compose['services']['new']['env_file'] = ['.secrets/../new.env']
        self.write_compose()
        with self.assertRaisesRegex(agent.Refused,'^AGENT_SEED_TARGET_INVALID$'):
            self.seed()
        self.assertEqual(self.rendered_configs,[])

    def test_partial_cli_success_promotes_no_outputs_and_emits_no_private_details(self):
        self.compose['services']['new']['env_file'].append('.secrets/second.env')
        self.write_compose()
        self.rows.append(self.row('second'))
        self.write_archive()
        def partial(args,code,**kwargs):
            config = json.loads(Path(args[-1]).read_bytes())
            path = Path(config['templates'][0]['destination-path'])
            path.write_bytes(b'private-canary')
            path.chmod(0o600)
            return b''
        out,err = io.StringIO(),io.StringIO()
        with patch.object(agent,'command',side_effect=partial), \
             contextlib.redirect_stdout(out),contextlib.redirect_stderr(err), \
             self.assertRaisesRegex(agent.Refused,'^AGENT_FIRST_RENDER_FAILED$'):
            self.seed()
        self.assertFalse((self.root/'.secrets/new.env').exists())
        self.assertFalse((self.root/'.secrets/second.env').exists())
        self.assertEqual(out.getvalue()+err.getvalue(),'')
        self.assertFalse(any(self.home.glob('agent-seed-*')))

    def test_seed_evidence_checks_exact_paths_hashes_and_changes(self):
        outputs = self.seed()
        agent.verify_seeded_envs(self.root,self.plan,outputs,uid=self.uid,gid=self.gid)
        for changed in ({},dict(outputs,**{'../../outside':'0'*64}),{'.secrets/new.env':'private-canary'}):
            with self.assertRaisesRegex(agent.Refused,'^AGENT_SEED_CHECKPOINT_INVALID$'):
                agent.verify_seeded_envs(self.root,self.plan,changed,uid=self.uid,gid=self.gid)
        path = self.root/'.secrets/new.env'
        path.write_bytes(b'rotated-private-canary')
        with self.assertRaisesRegex(agent.Refused,'^AGENT_SEED_OUTPUT_CHANGED$'):
            agent.verify_seeded_envs(self.root,self.plan,outputs,uid=self.uid,gid=self.gid)
        agent.verify_seeded_envs(self.root,self.plan,outputs,check_hash=False,uid=self.uid,gid=self.gid)
        path.unlink()
        with self.assertRaisesRegex(agent.Refused,'^AGENT_SEED_OUTPUT_CHANGED$'):
            agent.verify_seeded_envs(self.root,self.plan,outputs,uid=self.uid,gid=self.gid)

    def test_unmapped_required_root_interpolation_refuses_without_modifying_root_values(self):
        (self.root/'.env').write_bytes(b'COMPOSE_PROJECT_NAME=streams-aio\nPUBLIC_VALUE=preserve-exactly\n')
        original = (self.root/'.env').read_bytes()
        for expression in ('${NEW_PRIVATE}','${NEW_PRIVATE:?required}','$NEW_PRIVATE',
                           '${OPTIONAL:-${NEW_PRIVATE}}','${OPTIONAL:-$NEW_PRIVATE}'):
            self.compose['services']['new']['environment'] = {'PRIVATE':expression}
            self.write_compose()
            with self.assertRaisesRegex(agent.Refused,'^AGENT_SEED_ROOT_ENV_MAPPING_REQUIRED$'):
                self.seed()
            self.assertEqual((self.root/'.env').read_bytes(),original)
        # Escaped dollars and optional defaults do not create required inputs;
        # mapping keys are not interpolated by Compose.
        self.compose['services']['new']['environment'] = {
            '${KEY_IS_NOT_INTERPOLATED}':'$${CONTAINER_ONLY}',
            'DEFAULT':'${OPTIONAL:-${NESTED_DEFAULT:-public}}',
            'PROJECT':'${COMPOSE_PROJECT_NAME}'}
        self.write_compose()
        self.seed()
        self.assertEqual((self.root/'.env').read_bytes(),original)

    def test_resume_requires_seed_evidence_and_allows_only_later_agent_rotation(self):
        outputs = self.seed()
        job = recovery.Recovery.__new__(recovery.Recovery)
        job.root,job.tooling = self.root,ROOT/'remote'
        job.state = {}
        actual_verify = agent.verify_seeded_envs
        def verify(*args,**kwargs):
            return actual_verify(*args,**kwargs,uid=self.uid,gid=self.gid)
        with patch.object(recovery,'load_module',return_value=agent), \
             patch.object(agent,'verify_seeded_envs',side_effect=verify):
            with self.assertRaisesRegex(recovery.Refused,'^AGENT_SEED_CHECKPOINT_REQUIRED$'):
                job.verify_seeded_envs()
            job.state['agent_seed'] = {'schema':1,'outputs':outputs}
            job.verify_seeded_envs()
            (self.root/'.secrets/new.env').write_bytes(b'newly-rotated-private-canary')
            with self.assertRaisesRegex(recovery.Refused,'^AGENT_SEED_OUTPUT_CHANGED$'):
                job.verify_seeded_envs()
            job.state.update(preparation='PASS',native_agent='ACTIVE_NO_RESTART_HOOKS')
            job.verify_seeded_envs()
            self.compose['services']['new']['env_file'] = ['.secrets/existing.env']
            self.write_compose()
            job.state.pop('agent_seed')
            job.verify_seeded_envs()

    def test_disabled_continuous_agent_refuses_seed_and_flag_reaches_remote_config(self):
        job = recovery.Recovery.__new__(recovery.Recovery)
        job.root,job.home,job.private,job.tooling = self.root,self.home,self.home/'private',ROOT/'remote'
        job.config,job.state = {'native_agent':False},{}
        with patch.object(recovery,'load_module',return_value=agent), \
             self.assertRaisesRegex(recovery.Refused,'^AGENT_SEED_CONTINUOUS_AGENT_REQUIRED$'):
            job.seed_private_envs()
        self.assertEqual(self.rendered_configs,[])
        sys.path.insert(0,str(ROOT))
        from recovery_gui.backend import SSH,Host
        ssh = SSH.__new__(SSH)
        ssh.host = Host('vm.example.invalid',password='synthetic')
        ssh.check = lambda:{'home':'/home/test'}
        ssh.run = lambda *a,**k:None
        ssh.client = N(open_sftp=lambda:N(chmod=lambda *a:None,mkdir=lambda *a,**k:None,close=lambda:None))
        ssh._put = lambda *a:None
        request = dict(github_token='synthetic',public_commit='a'*40,dr_tag='dr-20261004T023903Z',
                       infisical_address='',project_id='',environment='',native_agent=False)
        _,raw = ssh.upload(request)
        self.assertIs(json.loads(raw)['native_agent'],False)

    def render_job(self):
        self.public_render()
        job = recovery.Recovery.__new__(recovery.Recovery)
        job.root,job.home,job.private,job.tooling = self.root,self.home,self.home/'private',ROOT/'remote'
        job.state_path = self.home/'state.json'
        job.config = {'public_commit':'a'*40,'infisical_address':'http://127.0.0.1:43123','ssh_bridge':True}
        job.state = dict(schema=1,machine_id='synthetic-machine',target=str(self.root),
            tooling_commit='a'*40,runner_version=recovery.RUNNER_VERSION,
            completed=['CLONES','DOWNLOAD','DECRYPT','INITIALIZE','INPUTS'],in_progress='RENDER')
        job.record_render_base()
        return job

    def reload_pending_job(self,job):
        actual_stat,actual_text = Path.stat,Path.read_text
        def home_stat(path,*args,**kwargs):
            info = actual_stat(path,*args,**kwargs)
            if path == self.home:
                values = list(info)
                values[0],values[4] = stat.S_IFDIR|0o700,1000
                return os.stat_result(values)
            return info
        def text(path,*args,**kwargs):
            if path.as_posix() == '/etc/machine-id':
                return 'synthetic-machine'
            return actual_text(path,*args,**kwargs)
        args = N(target=str(self.root),state_home=str(self.home),config_data=job.config)
        with patch.object(Path,'stat',home_stat),patch.object(Path,'read_text',text):
            return recovery.Recovery(args)

    def test_second_promotion_failure_retries_only_journal_owned_files(self):
        self.compose['services']['new']['env_file'].append('.secrets/second.env')
        self.write_compose()
        self.rows.append(self.row('second'))
        self.write_archive()
        unrelated = self.root/'.secrets/unrelated.env'
        unrelated.write_bytes(b'unrelated-private-canary')
        actual_replace = os.replace
        def fail_second(source,destination):
            if Path(destination) == self.root/'.secrets/second.env':
                raise OSError('synthetic-interruption')
            return actual_replace(source,destination)
        with patch.object(os,'replace',side_effect=fail_second),self.assertRaises(OSError):
            self.seed()
        self.assertTrue((self.root/'.secrets/new.env').exists())
        self.assertFalse((self.root/'.secrets/second.env').exists())
        journal = self.home/'agent-seed-journal.json'
        self.assertNotIn('private-canary',journal.read_text())
        outputs = self.seed()
        self.assertEqual(set(outputs),{'.secrets/new.env','.secrets/second.env'})
        self.assertEqual(unrelated.read_bytes(),b'unrelated-private-canary')
        self.assertEqual(len(self.rendered_configs),2)

    def test_partial_seed_tampering_or_scope_change_refuses_before_any_cleanup(self):
        self.compose['services']['new']['env_file'] += ['.secrets/second.env','.secrets/third.env']
        self.write_compose()
        self.rows += [self.row('second'),self.row('third')]
        self.write_archive()
        actual_replace = os.replace
        def fail_third(source,destination):
            if Path(destination) == self.root/'.secrets/third.env':
                raise OSError('synthetic-interruption')
            return actual_replace(source,destination)
        with patch.object(os,'replace',side_effect=fail_third),self.assertRaises(OSError):
            self.seed()
        first,second = self.root/'.secrets/new.env',self.root/'.secrets/second.env'
        original = first.read_bytes()
        second.write_bytes(b'tampered-private-canary')
        with self.assertRaisesRegex(agent.Refused,'^AGENT_SEED_OUTPUT_CHANGED$'):
            self.seed()
        self.assertEqual(first.read_bytes(),original)
        self.assertEqual(second.read_bytes(),b'tampered-private-canary')
        self.compose['services']['new']['environment'] = {'PUBLIC_SETTING':'changed'}
        self.write_compose()
        with self.assertRaisesRegex(agent.Refused,'^AGENT_SEED_JOURNAL_INVALID$'):
            self.seed()
        self.assertEqual(first.read_bytes(),original)
        self.assertEqual(len(self.rendered_configs),1)

    def test_pending_render_after_promotion_reuses_verified_seed_without_cli(self):
        job = self.render_job()
        real_seed = agent.seed_required_envs
        def seed_once(*args,**kwargs):
            return real_seed(self.root,self.home,self.archive,self.plan,'http://127.0.0.1:43123',
                             uid=self.uid,gid=self.gid,user='synthetic')
        real_save = recovery.save
        def interrupted_checkpoint(path,value):
            if 'RENDER' in value.get('completed',[]):
                raise OSError('synthetic-post-promotion-interruption')
            return real_save(path,value)
        with patch.object(recovery,'load_module',return_value=agent), \
             patch.object(agent,'seed_required_envs',side_effect=seed_once), \
             patch.object(recovery,'save',side_effect=interrupted_checkpoint), \
             patch.object(recovery,'event'),self.assertRaises(OSError):
            job.step('RENDER',lambda:job.run_script('dr.py','render','--mode','fresh',root=True))
        self.assertNotIn('agent_seed',json.loads(job.state_path.read_bytes()))
        before = (self.root/'.secrets/new.env').read_bytes()
        resumed = self.reload_pending_job(job)
        def resume_seed(*args,**kwargs):
            return real_seed(self.root,self.home,self.archive,self.plan,'http://127.0.0.1:43123',
                             uid=self.uid,gid=self.gid,user='synthetic')
        with patch.object(recovery,'load_module',return_value=agent), \
             patch.object(agent,'seed_required_envs',side_effect=resume_seed), \
             patch.object(recovery,'command') as command,patch.object(recovery,'event'):
            resumed.step('RENDER',lambda:resumed.run_script('dr.py','render','--mode','fresh',root=True))
        command.assert_not_called()  # The pinned public renderer is not rerun.
        self.assertEqual(len(self.rendered_configs),1)
        self.assertEqual((self.root/'.secrets/new.env').read_bytes(),before)
        self.assertIn('RENDER',resumed.state['completed'])
        self.assertEqual(set(resumed.state['agent_seed']['outputs']),{'.secrets/new.env'})

    def test_pending_render_requires_complete_unchanged_public_render_evidence(self):
        job = self.render_job()
        (self.root/'.secrets/existing.env').write_bytes(b'changed-old-private-output')
        with self.assertRaisesRegex(recovery.Refused,'^AGENT_RENDER_BASE_CHANGED$'):
            self.reload_pending_job(job)
        job.state.pop('render_base')
        recovery.save(job.state_path,job.state)
        with self.assertRaisesRegex(recovery.Refused,'^INCOMPLETE_STEP_REQUIRES_REVIEW$'):
            self.reload_pending_job(job)

    def test_compose_include_and_extends_refuse_without_guessing_external_targets(self):
        self.compose['include'] = ['other.yml']
        self.write_compose()
        with self.assertRaisesRegex(agent.Refused,'^AGENT_SEED_COMPOSE_INCLUDE_UNSUPPORTED$'):
            self.seed()
        self.compose.pop('include')
        self.compose['services']['new']['extends'] = {'file':'other.yml','service':'other'}
        self.write_compose()
        with self.assertRaisesRegex(agent.Refused,'^AGENT_SEED_COMPOSE_EXTENDS_UNSUPPORTED$'):
            self.seed()
        self.assertEqual(self.rendered_configs,[])


if __name__ == '__main__':
    unittest.main()

import copy
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT/'remote'))
import recover
with patch.dict(sys.modules, {'fcntl':N()} if sys.platform == 'win32' else {}):
    import infisical_server as server
from recovery_gui.backend import APIBridge, Failure, restore_all, parse_event
from recovery_gui.codes import ERROR_CODES


def model():
    return dict(name='infisical', services={
        'db': dict(image='postgres:14-alpine', environment={'POSTGRES_USER':'infisical'},
                   volumes=[dict(type='volume',source='pg_data',target='/var/lib/postgresql/data')]),
        'redis': dict(image='redis',volumes=[dict(type='volume',source='redis_data',target='/data')]),
        'backend':dict(image='infisical/infisical:v0.165.16', environment={
            'ENCRYPTION_KEY':'encryption-canary', 'AUTH_SECRET':'auth-canary',
            'DB_CONNECTION_URI':'postgres://infisical:password-canary@db:5432/infisical',
            'REDIS_URL':'redis://redis:6379'}, ports=[dict(target=8080,published='80',protocol='tcp')])},
        volumes={'pg_data':dict(name='infisical_pg_data'),'redis_data':dict(name='infisical_redis_data')})


def archive(path, names):
    with tarfile.open(path, 'w:gz') as tar:
        for name in names:
            member = tarfile.TarInfo(name)
            value = b'private-canary'
            member.size = len(value)
            tar.addfile(member,io.BytesIO(value))


class InfisicalRestoreSafety(unittest.TestCase):
    def test_deployment_matches_reviewed_metadata(self):
        p = server.profile()
        self.assertEqual(p['database_user'],'infisical')
        self.assertEqual(p['postgres_major'],14)
        self.assertEqual(set(p['images']), {'backend','db','redis'})
        self.assertTrue(all('@sha256:' in value for value in p['images'].values()))

    def test_config_layouts_preserve_keys_without_restoring_other_paths(self):
        for prefix in ('','./','opt/infisical/'):
            with tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                archive(base/'config.tar.gz',[prefix+'.env',prefix+'docker-compose.prod.yml'])
                server.unpack_config(base/'config.tar.gz',base/'out')
                self.assertEqual(set(x.name for x in (base/'out').iterdir()),server.CONFIG_NAMES)
                self.assertEqual((base/'out/.env').read_bytes(),b'private-canary')

    def test_config_unknown_files_and_traversal_fail_before_extraction(self):
        for extra in ('../escape','/etc/passwd','unexpected.key','opt/infisical/.env'):
            with tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                archive(base/'config.tar.gz',['.env','docker-compose.prod.yml',extra])
                with self.assertRaises(server.Refused):
                    server.unpack_config(base/'config.tar.gz',base/'out')
                self.assertFalse((base/'out').exists())

    def test_config_links_and_duplicate_names_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            archive(base/'config.tar.gz',['.env','.env','docker-compose.prod.yml'])
            with self.assertRaisesRegex(server.Refused,'DUPLICATE_INFISICAL_CONFIG_ENTRY'):
                server.unpack_config(base/'config.tar.gz',base/'out')
            with tarfile.open(base/'config.tar.gz','w:gz') as tar:
                item = tarfile.TarInfo('.env')
                item.type, item.linkname = tarfile.SYMTYPE, '/etc/private'
                tar.addfile(item)
            with self.assertRaisesRegex(server.Refused,'UNSAFE_INFISICAL_CONFIG_ARCHIVE'):
                server.unpack_config(base/'config.tar.gz',base/'out')

    def test_model_keeps_application_keys_and_pins_every_image(self):
        live = model()
        result = server.checked_model(live, server.profile())
        self.assertEqual(result['services']['backend']['environment'],live['services']['backend']['environment'])
        self.assertEqual(server.api_port(result),80)
        self.assertTrue(all('@sha256:' in row['image'] and row['platform']=='linux/amd64'
                            for row in result['services'].values()))
        self.assertEqual(live['services']['db']['image'],'postgres:14-alpine')

    def test_unreviewed_secrets_external_database_or_mounted_host_refused(self):
        mutations = [
            lambda m:m['services']['backend']['environment'].pop('ENCRYPTION_KEY'),
            lambda m:m['services']['backend']['environment'].update(DB_CONNECTION_URI='postgres://infisical:canary@production/infisical'),
            lambda m:m['services']['db'].update(ports=[dict(target=5432,published='5432')]),
            lambda m:m['services']['backend'].update(privileged=True),
            lambda m:m['services']['backend'].update(volumes=[dict(type='bind',source='/etc',target='/etc')]),
            lambda m:m['volumes']['pg_data'].update(external=True),
            lambda m:m.update(networks={'default':dict(external=True)})]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                live = model()
                mutate(live)
                with self.assertRaises(server.Refused) as caught:
                    server.checked_model(live,server.profile())
                self.assertNotIn('canary',str(caught.exception))

    def test_raw_compose_rejects_extra_env_files_and_host_binds_before_resolution(self):
        live = dict(services={name:{} for name in server.SERVICES})
        server.validate_raw_compose(json.dumps(live))
        for change in ({'env_file':'/etc/private'},{'volumes':['/etc:/etc']},{'build':'.'}):
            candidate = copy.deepcopy(live)
            candidate['services']['backend'].update(change)
            with self.assertRaises(server.Refused):
                server.validate_raw_compose(json.dumps(candidate))

    def test_http_is_accepted_only_for_explicit_loopback_ssh_bridge(self):
        self.assertEqual(recover.validate_address('http://127.0.0.1:43123',True),'http://127.0.0.1:43123')
        for url in ('http://192.168.1.2:80','http://localhost:123','http://127.0.0.1',
                    'http://user:canary@127.0.0.1:123','http://127.0.0.1:123?token=canary'):
            with self.assertRaises(recover.Refused):
                recover.validate_address(url,True)
        with self.assertRaises(recover.Refused):
            recover.validate_address('http://127.0.0.1:43123')

    def test_both_hosts_preflight_before_mutation_and_restore_order(self):
        stack, other = Mock(), Mock()
        stack.check.return_value={'machine_id':'stack'}
        other.check.return_value={'machine_id':'infisical'}
        other.restored_port.return_value=80
        order=[]
        stack.check.side_effect=lambda *a,**k:order.append('check-stack') or {'machine_id':'stack'}
        other.check.side_effect=lambda *a,**k:order.append('check-server') or {'machine_id':'infisical'}
        other.prepare.side_effect=lambda *a:order.append('restore-server')
        stack.prepare.side_effect=lambda *a:order.append('prepare-stack')
        stack.start.side_effect=lambda *a:order.append('start-stack')
        bridge = Mock()
        bridge.__enter__ = Mock(return_value='http://127.0.0.1:54321')
        bridge.__exit__ = Mock(return_value=False)
        with patch('recovery_gui.backend.APIBridge',return_value=bridge):
            restore_all(stack,other,{'native_agent':False},lambda e:None)
        self.assertEqual(order,['check-stack','check-server','restore-server','prepare-stack','start-stack'])
        self.assertTrue(stack.prepare.call_args.args[0]['ssh_bridge'])
        self.assertEqual(stack.prepare.call_args.args[0]['infisical_address'],'http://127.0.0.1:54321')
        self.assertEqual(other.prepare.call_args.args[0]['aiostreams_exports'],[])
        bridge.__exit__.assert_called_once()

    def test_same_machine_or_failed_preflight_never_restores_anything(self):
        stack, other = Mock(), Mock()
        stack.check.return_value=other.check.return_value={'machine_id':'same'}
        with self.assertRaisesRegex(Failure,'SEPARATE_RECOVERY_VMS_REQUIRED'):
            restore_all(stack,other,{},lambda e:None)
        stack.prepare.assert_not_called()
        other.prepare.assert_not_called()
        other.check.side_effect=Failure('FRESH_DOCKER_HOST_REQUIRED')
        with self.assertRaises(Failure):
            restore_all(stack,other,{},lambda e:None)
        other.prepare.assert_not_called()

    def test_native_agent_scope_override_refused_before_any_remote_action(self):
        for name in ('project_id', 'environment', 'client_id_file', 'client_secret_file'):
            stack, other = Mock(), Mock()
            with self.assertRaisesRegex(Failure, 'NATIVE_AGENT_REQUIRES_RECOVERED_SCOPE'):
                restore_all(stack, other, {name: 'fixture'}, lambda e: None)
            stack.check.assert_not_called()
            other.prepare.assert_not_called()

    def test_tunnel_listens_only_on_stack_loopback_and_closes_on_error(self):
        stack, other = Mock(), Mock()
        transport = stack.client.get_transport.return_value
        transport.request_port_forward.return_value=43321
        bridge=APIBridge(stack,other,80)
        channel=Mock()
        bridge.channels.append(channel)
        with self.assertRaises(RuntimeError):
            with bridge as address:
                self.assertEqual(address,'http://127.0.0.1:43321')
                raise RuntimeError('fixture')
        self.assertEqual(transport.request_port_forward.call_args.args,('127.0.0.1',0))
        transport.cancel_port_forward.assert_called_once_with('127.0.0.1',43321)
        channel.close.assert_called_once()

    def test_restore_roles_stop_on_sql_error_and_keep_owners(self):
        recovery=server.InfisicalRecovery.__new__(server.InfisicalRecovery)
        recovery.deployment=server.profile()
        recovery.state={'postgres_bootstrap_user':'recovery_fixture'}
        recovery.runtime=lambda:None
        recovery.private=Path('/private')
        calls=[]
        readiness=iter([b'f\n',server.Refused('INFISICAL_RESTORE_COMMAND_FAILED'),b't\n'])
        readiness_checks=[]
        def compose(args,**kwargs):
            calls.append((args,kwargs))
            if args[-1]=="SELECT current_setting('listen_addresses') <> ''":
                readiness_checks.append(args)
                reply=next(readiness)
                if isinstance(reply,Exception):
                    raise reply
                return reply
            if kwargs.get('input'):
                self.assertEqual(len(readiness_checks),3,'No SQL writes during temporary startup/restart')
            if args[-1].startswith('SELECT count'):
                return b't\n'
            return b''
        recovery.compose=compose
        listing=b'; dbname: infisical\n; Dumped from database version: 14.24\n'
        with (patch.object(server,'private_file',return_value=N(read_bytes=lambda:b'fixture')),
              patch.object(server,'command',return_value=listing),
              patch.object(server.time,'sleep') as sleep):
            recovery.database()
        self.assertEqual(sleep.call_count,2)
        globals_call=next((args,kw) for args,kw in calls if kw.get('input')==b'fixture' and 'psql' in args)
        self.assertIn('ON_ERROR_STOP=1',globals_call[0])
        self.assertIn('--single-transaction',globals_call[0])
        dump_call=next(args for args,kw in calls if 'pg_restore' in args)
        self.assertIn('--exit-on-error',dump_call)
        self.assertNotIn('--no-owner',dump_call)
        self.assertTrue(any('createdb' in args and '-O' in args and 'infisical' in args for args,kw in calls))
        self.assertTrue(any('NOLOGIN' in str(args) for args,kw in calls))

    def test_fixed_new_events_are_displayed_without_private_data(self):
        for stage in ('INFISICAL_CONFIG','INFISICAL_DATABASE','INFISICAL_SERVER'):
            self.assertEqual(parse_event('RECOVERY_EVENT '+json.dumps(dict(stage=stage,status='PASS')))['stage'],stage)
        self.assertIn('INFISICAL_RESTORE_FAILED',ERROR_CODES)

    def test_github_token_is_not_in_docker_process_environment(self):
        with (patch.object(recover,'GITHUB_TOKEN','token-canary'),
             patch.dict(recover.os.environ,{'GH_TOKEN':'inherited-canary','GITHUB_TOKEN':'inherited-canary'}),
              patch.object(recover.subprocess,'run',return_value=N(returncode=0,stdout=b'')) as run):
            recover.command(['docker','compose','config'],'DOCKER_ACCESS_REQUIRED')
        env=run.call_args.kwargs['env']
        self.assertNotIn('GH_TOKEN',env)
        self.assertNotIn('GITHUB_TOKEN',env)


if __name__ == '__main__':
    unittest.main()

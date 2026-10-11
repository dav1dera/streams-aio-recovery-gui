"""Fresh input completeness, explicit manual AIO and scoped encrypted fallback.

All files and API values are synthetic; no network, real key or VM is read.
"""
import ast
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fresh_input_recovery', ROOT/'remote/recover.py')
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
TAG = 'dr-20261006T210601Z'
COMMIT = '28f6ca7cc6f5fd10418fc0af2926815927ef98c8'


def renderer():
    return recovery.load_module(ROOT/'tests/fixtures/pinned_dr_renderer.py', 'input_fixture_renderer')


def plan():
    return dict(required_values=[recovery.AIO_BINDINGS_REF, recovery.OAUTH_ALLOWLIST_REF, '/service/TOKEN'],
                additional_input_folders=['/dr'], private_dr_bindings_ref=recovery.AIO_BINDINGS_REF,
                readiness_blockers=[], env_files={'.secrets/service.env': {
                    'TOKEN': {'path': '/service', 'key': 'TOKEN'}}}, service_folder_exports={}, root_env={},
                files=[dict(destination='data/oauth2-proxy/allowed-emails.txt',
                            format='oauth2-allowlist', ref=recovery.OAUTH_ALLOWLIST_REF, mode='0640')],
                runtime_fields={}, postgres_bootstrap={'destination': '.generated/init.sql'})


class Inputs(unittest.TestCase):
    def setUp(self):
        base = ROOT.parent/'gui-test-tmp' if sys.platform == 'win32' else None
        if base is not None:
            base.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        if sys.platform == 'win32':
            def private(path, outside=()):
                path = recovery.safe_path(path)
                recovery.require(path.is_file() and all(not path.is_relative_to(x) for x in outside),
                                 'PRIVATE_INPUT_FILE_REQUIRED')
                return path
            guard = patch.object(recovery, 'private_file', private)
            guard.start()
            self.addCleanup(guard.stop)

    def client(self, folders):
        self.calls = []
        def read(**kwargs):
            folder = kwargs['secret_path']
            self.calls.append(folder)
            if folder not in folders:
                raise RuntimeError('synthetic-api-404-private-canary')
            return N(imports=[], secrets=[N(secretKey=key, secretValue=value, secretValueHidden=False)
                                         for key, value in folders[folder].items()])
        return N(secrets=N(list_secrets=read))

    def test_manual_reads_no_absent_registry_and_preserves_every_other_requirement(self):
        original = plan()
        expected = copy.deepcopy(original)
        client = self.client({'/service': {'TOKEN': 'token-canary'},
                              '/oauth2-proxy': {'ALLOWED_EMAILS': 'one@example.invalid\n'}})
        snapshots = recovery.collect_inputs(original, renderer(), client, 'project', 'prod', aio_mode='manual')
        self.assertEqual(original, expected)
        self.assertEqual(set(self.calls), {'/service', '/oauth2-proxy'})
        self.assertEqual(set(snapshots), {'service.goenv', 'oauth2-proxy.goenv'})
        self.assertNotIn('dr.goenv', snapshots)

    def test_manual_cannot_defer_another_dr_input_or_registry_config_binding(self):
        original = plan()
        original['required_values'].append('/dr/OTHER_REQUIRED')
        client = self.client({'/service': {'TOKEN': 'canary'}, '/oauth2-proxy': {'ALLOWED_EMAILS': 'a@example.invalid'},
                              '/dr': {}})
        with self.assertRaisesRegex(recovery.Refused, '^REQUIRED_INFISICAL_KEY_MISSING$'):
            recovery.collect_inputs(original, renderer(), client, 'project', 'prod', aio_mode='manual')
        self.assertIn('/dr', self.calls)
        original = plan()
        original['env_files']['.secrets/other.env'] = {'IDENTITY': {'path': '/dr', 'key': 'AIO_PROFILE_BINDINGS'}}
        # A bound registry cannot be waived; no fake identity is synthesized.
        with self.assertRaisesRegex(recovery.Refused, '^MANUAL_AIO_INPUT_CONTRACT_INVALID$'):
            recovery.input_plan(original, 'manual')
        original = plan()
        original['files'].append({'ref': recovery.AIO_BINDINGS_REF})
        with self.assertRaisesRegex(recovery.Refused, '^MANUAL_AIO_INPUT_CONTRACT_INVALID$'):
            recovery.input_plan(original, 'manual')

    def test_import_still_requires_the_real_registry(self):
        client = self.client({'/service': {'TOKEN': 'canary'}, '/oauth2-proxy': {'ALLOWED_EMAILS': 'a@example.invalid'}})
        with self.assertRaisesRegex(RuntimeError, 'synthetic-api-404'):
            recovery.collect_inputs(plan(), renderer(), client, 'project', 'prod')
        self.assertIn('/dr', self.calls)

    def test_missing_oauth_allowlist_stops_manual_without_a_supplement(self):
        client = self.client({'/service': {'TOKEN': 'canary'}, '/oauth2-proxy': {}})
        with self.assertRaisesRegex(recovery.Refused, '^OAUTH_ALLOWLIST_SUPPLEMENT_REQUIRED$'):
            recovery.collect_inputs(plan(), renderer(), client, 'project', 'prod', aio_mode='manual')

    def test_supplement_fills_only_missing_allowlist_and_never_overwrites_api(self):
        for present in (False, True):
            with self.subTest(present=present):
                actual = 'authoritative@example.invalid\n'
                client = self.client({'/service': {'TOKEN': 'canary'},
                                      '/oauth2-proxy': {'ALLOWED_EMAILS': actual} if present else {}})
                used = set()
                snapshots = recovery.collect_inputs(plan(), renderer(), client, 'project', 'prod',
                    aio_mode='manual', supplemental={recovery.OAUTH_ALLOWLIST_REF: 'backup@example.invalid\n'},
                    applied=used)
                value = ast.literal_eval(snapshots['oauth2-proxy.goenv'].decode().partition('=')[2])
                self.assertEqual(value, actual if present else 'backup@example.invalid\n')
                self.assertEqual(used, set() if present else {recovery.OAUTH_ALLOWLIST_REF})
        with self.assertRaisesRegex(recovery.Refused, '^RECOVERY_SUPPLEMENT_INVALID$'):
            recovery.collect_inputs(plan(), renderer(), client, 'project', 'prod', aio_mode='manual',
                                     supplemental={'/service/TOKEN': 'other-canary'})

    def test_fallback_does_not_waive_hidden_imported_or_other_missing_secrets(self):
        client = self.client({'/service': {}, '/oauth2-proxy': {}})
        with self.assertRaisesRegex(recovery.Refused, '^REQUIRED_INFISICAL_KEY_MISSING$'):
            recovery.collect_inputs(plan(), renderer(), client, 'project', 'prod', aio_mode='manual',
                                     supplemental={recovery.OAUTH_ALLOWLIST_REF: 'a@example.invalid'})
        client = N(secrets=N(list_secrets=lambda **kwargs: N(imports=['private-canary'], secrets=[])))
        with self.assertRaisesRegex(recovery.Refused, '^INFISICAL_IMPORTS_REQUIRE_MAPPING_REVIEW$'):
            recovery.collect_inputs(plan(), renderer(), client, 'project', 'prod', aio_mode='manual',
                                     supplemental={recovery.OAUTH_ALLOWLIST_REF: 'a@example.invalid'})

    def test_explicit_email_security_contract(self):
        for value in ('', '*@example.invalid', 'example.invalid', 'a@example.invalid\ra@example.invalid',
                      'a@example.invalid\na@example.invalid', 'a@example.invalid\0', None):
            with self.subTest(value=value), self.assertRaisesRegex(recovery.Refused, '^OAUTH_ALLOWLIST_INVALID$'):
                recovery.validate_allowlist(value)

    def database_plan(self):
        original = plan()
        original['env_files']['.secrets/cometnet.env'] = {'DATABASE_URL': {'path': '/cometnet', 'key': 'DATABASE_URL'}}
        original['postgres_bootstrap']['connections'] = [{'ref': '/comet/DATABASE_URL', 'service': 'comet'}]
        return original

    def test_cometnet_database_matches_provisioned_role_password_and_database_through_pooler(self):
        values = {'/comet/DATABASE_URL': 'role:p%40ss@postgres:5432/appdb',
                  '/cometnet/DATABASE_URL': 'postgresql://role:p%40ss@pgbouncer:6432/appdb'}
        original = copy.deepcopy(values)
        recovery.validate_database_mappings(self.database_plan(), renderer(), values)
        self.assertEqual(values, original)

    def test_independent_cometnet_database_role_password_or_missing_mapping_refuses_privately(self):
        for value in ('postgresql://role:private-canary@pgbouncer/appdb',
                      'postgresql://other:password@pgbouncer/appdb',
                      'postgresql://role:password@pgbouncer/other', 'invalid-private-canary'):
            values = {'/comet/DATABASE_URL': 'postgresql://role:password@postgres/appdb',
                      '/cometnet/DATABASE_URL': value}
            with self.subTest(value=value), self.assertRaisesRegex(recovery.Refused,
                    '^COMETNET_DATABASE_NOT_PROVISIONED$') as error:
                recovery.validate_database_mappings(self.database_plan(), renderer(), values)
            self.assertNotIn('canary', str(error.exception))

    def supplement(self, data):
        identity, ciphertext = self.home/'key.txt', self.home/'inputs.age'
        identity.write_bytes(b'AGE-SECRET-KEY-1CANARY\n')
        ciphertext.write_bytes(b'authenticated-ciphertext-canary')
        identity.chmod(0o600)
        ciphertext.chmod(0o600)
        def run(args, code):
            if args[0] == 'age-keygen':
                self.assertEqual(Path(args[-1]).read_bytes(), identity.read_bytes())
            else:
                self.assertEqual(args[-1], ciphertext)
                output = Path(args[args.index('--output')+1])
                output.write_text(json.dumps(data))
                output.chmod(0o600)
            return b''
        return identity, ciphertext, run

    def envelope(self):
        return dict(schema=1, tag=TAG, commit=COMMIT,
                    request={'allowed_emails': 'restored@example.invalid\n', 'app_password': 'private-canary'},
                    payload={'aiostreams': [{'private': 'ignored-canary'}]})

    def test_scoped_companion_uses_only_email_list_and_keeps_original_files(self):
        identity, ciphertext, run = self.supplement(self.envelope())
        before = {path: path.read_bytes() for path in (identity, ciphertext)}
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            values, provenance = recovery.read_supplemental_inputs(identity, ciphertext, self.home, TAG, COMMIT, run=run)
        self.assertEqual(values, {recovery.OAUTH_ALLOWLIST_REF: 'restored@example.invalid\n'})
        self.assertEqual(set(provenance), {'schema', 'tag', 'commit', 'ciphertext_sha256'})
        self.assertEqual(provenance['ciphertext_sha256'], recovery.digest(ciphertext))
        self.assertEqual({path: path.read_bytes() for path in before}, before)
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(set(self.home.iterdir()), {identity, ciphertext})

    def test_wrong_release_commit_schema_or_email_is_refused_without_private_details(self):
        for field, value, code in (('tag', 'dr-20261004T023903Z', 'RECOVERY_SUPPLEMENT_SCOPE_CHANGED'),
                                    ('commit', '0'*40, 'RECOVERY_SUPPLEMENT_SCOPE_CHANGED'),
                                    ('schema', True, 'RECOVERY_SUPPLEMENT_INVALID'),
                                    ('request', {'allowed_emails': '*@example.invalid'}, 'OAUTH_ALLOWLIST_INVALID')):
            data = dict(self.envelope(), **{field: value})
            identity, ciphertext, run = self.supplement(data)
            with self.subTest(field=field), self.assertRaisesRegex(recovery.Refused, '^'+code+'$') as error:
                recovery.read_supplemental_inputs(identity, ciphertext, self.home, TAG, COMMIT, run=run)
            self.assertNotIn('canary', str(error.exception))
            self.assertFalse(any(self.home.glob('supplement-*')))

    def test_wrong_identity_age_failure_keeps_original_supplement_and_key(self):
        identity, ciphertext, _ = self.supplement(self.envelope())
        before = {path: path.read_bytes() for path in (identity, ciphertext)}
        def refuse(args, code):
            if args[0] == 'age':
                raise recovery.Refused('AGE_NO_MATCHING_RECIPIENT')
        with self.assertRaisesRegex(recovery.Refused, '^AGE_NO_MATCHING_RECIPIENT$'):
            recovery.read_supplemental_inputs(identity, ciphertext, self.home, TAG, COMMIT, run=refuse)
        self.assertEqual({path: path.read_bytes() for path in before}, before)

    def test_real_inputs_step_combines_authenticated_snapshot_with_scoped_companion(self):
        original = plan()
        root = self.home/'stack'
        (root/'config').mkdir(parents=True)
        public = root/'config/dr-render-plan.json'
        public.write_text(json.dumps(original))
        public_before = public.read_bytes()
        identity, ciphertext, run = self.supplement(self.envelope())
        client_id, client_secret = self.home/'client-id', self.home/'client-secret'
        for path in (client_id, client_secret):
            path.write_text('private-login-canary')
            path.chmod(0o600)
        client = self.client({'/service': {'TOKEN': 'live-token-canary'}, '/oauth2-proxy': {}})
        client.auth = N(universal_auth=N(login=Mock()))
        client.api = N(session=N(request=Mock(), trust_env=True))
        client.close = Mock()
        job = recovery.Recovery.__new__(recovery.Recovery)
        job.root, job.home = root, self.home
        job.private = self.home/'private'
        job.manager, job.tooling = self.home/'manager', self.home/'tooling'
        job.config = dict(aio_mode='manual', supplemental_inputs=str(ciphertext), age_identity=str(identity),
                          infisical_address='https://infisical.example.invalid', project_id='project',
                          environment='prod', client_id_file=str(client_id), client_secret_file=str(client_secret))
        job.state = dict(tag=TAG, public_commit=COMMIT)
        decrypt = recovery.read_supplemental_inputs
        def decrypt_with_fixture(*args):
            return decrypt(*args, run=run)
        with patch.dict(sys.modules, {'infisical_sdk': N(InfisicalSDKClient=Mock(return_value=client))}), \
             patch.object(recovery, 'read_supplemental_inputs', side_effect=decrypt_with_fixture), \
             patch.object(recovery, 'load_module', return_value=renderer()):
            job.inputs()
        client.auth.universal_auth.login.assert_called_once()
        client.close.assert_called_once()
        self.assertEqual(job.state['input_aio_mode'], 'manual')
        self.assertEqual(job.state['supplemental_inputs']['applied'], [recovery.OAUTH_ALLOWLIST_REF])
        self.assertNotIn('restored@example.invalid', json.dumps(job.state))
        self.assertNotIn('private-login-canary', json.dumps(job.state))
        self.assertEqual(public.read_bytes(), public_before)
        self.assertEqual({p.name for p in (root/'.secrets/dr-inputs').iterdir()},
                         {'service.goenv', 'oauth2-proxy.goenv'})

    def test_changed_manual_input_mode_blocks_before_resume_commands(self):
        job = recovery.Recovery.__new__(recovery.Recovery)
        job.state = {'completed': ['INPUTS'], 'input_aio_mode': 'manual'}
        job.config = {'aio_mode': 'import'}
        with patch.object(recovery, 'command') as command, \
             self.assertRaisesRegex(recovery.Refused, '^RECOVERY_AIO_MODE_CHANGED$'):
            job.validate_resume()
        command.assert_not_called()

    def test_first_boot_registration_is_between_empty_state_and_npm_and_reuses_record(self):
        job = recovery.Recovery.__new__(recovery.Recovery)
        job.root, job.home = self.home/'stack', self.home
        job.root.mkdir()
        job.tooling = self.home/'tooling'
        job.state, job.config = {'completed': [], 'in_progress': None}, {'aio_mode': 'manual'}
        job.state_path = self.home/'state.json'
        trace = []
        for name in ('auth', 'validate_resume', 'clones', 'download', 'decrypt', 'initialize', 'inputs', 'npm', 'aio'):
            setattr(job, name, lambda name=name: trace.append(name))
        job.run_script = lambda name, action, *args, **kwargs: trace.append(action)
        class PolicyRefused(ValueError):
            pass
        pins = recovery.load_module(ROOT/'remote/runtime_profile.py', 'fresh_input_runtime_policy')
        policy = N(Refused=PolicyRefused, FIRST_BOOT_IMAGES=pins.FIRST_BOOT_IMAGES,
                   PG_IMAGE=pins.PG_IMAGE, DNS_IMAGE=pins.DNS_IMAGE,
                   OAUTH_IMAGE=pins.OAUTH_IMAGE, PGBOUNCER_IMAGE=pins.PGBOUNCER_IMAGE,
                   validate=lambda root, home, state: bool(state.get('runtime_profile')))
        def check_scope(root, home, state, installing):
            self.assertTrue(installing)
            self.assertEqual(state['in_progress'], None)
            self.assertEqual(set(state['completed']), {'CLONES','DOWNLOAD','DECRYPT','INITIALIZE','INPUTS','RENDER','EMPTY_STATE'})
            trace.append('profile-scope')
        policy.first_boot_scope = check_scope
        def apply(root, home, state, model, command):
            trace.append('profile-apply')
            state['runtime_profile'] = {'origin': 'FIRST_BOOT'}
        policy.apply_fresh = apply
        def command(args, code, **kwargs):
            if args[:2] == ['docker', 'ps'] or args[:3] == ['docker', 'volume', 'ls']:
                return b''
            if code == 'RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED':
                return None
            if args[:2] == ['docker', 'pull']:
                trace.append('image-pull')
                return b''
            if args[-2:] == ['--format', 'json']:
                trace.append('profile-compose')
                return b'{"services":{}}'
            self.assertEqual(args[-1], '--quiet')
            return b''
        with patch.object(recovery, 'command', side_effect=command), \
             patch.object(recovery, 'load_module', return_value=policy), \
             patch.object(recovery, 'stack_preflight'), patch.object(recovery, 'event'):
            job.prepare()
            self.assertLess(trace.index('prepare-state'), trace.index('profile-scope'))
            self.assertLess(trace.index('image-pull'), trace.index('profile-apply'))
            self.assertLess(trace.index('profile-apply'), trace.index('npm'))
            before = list(trace)
            job.prepare_first_boot()
            self.assertEqual(trace, before)
        self.assertEqual(job.state['preparation'], 'PASS')

    def test_first_boot_scope_refusal_prevents_pull_and_profile_failure_prevents_npm(self):
        job = recovery.Recovery.__new__(recovery.Recovery)
        job.config = {}
        job.root, job.home, job.tooling = self.home/'stack', self.home, self.home/'tooling'
        job.state = {'completed': [], 'in_progress': None}
        class PolicyRefused(ValueError):
            pass
        policy = N(Refused=PolicyRefused, validate=Mock(return_value=False),
                   first_boot_scope=Mock(side_effect=PolicyRefused('RUNTIME_PROFILE_SCOPE_REFUSED')))
        with patch.object(recovery, 'load_module', return_value=policy), \
             patch.object(recovery, 'command') as command, \
             self.assertRaisesRegex(recovery.Refused, '^RUNTIME_PROFILE_SCOPE_REFUSED$'):
            job.prepare_first_boot()
        command.assert_not_called()
        job.state_path = self.home/'state.json'
        job.auth, job.validate_resume = Mock(), Mock()
        job.clones, job.download, job.decrypt, job.initialize, job.inputs = (Mock() for _ in range(5))
        job.npm, job.aio, job.run_script = Mock(), Mock(), Mock()
        job.prepare_first_boot = Mock(side_effect=recovery.Refused('RUNTIME_PROFILE_COMMAND_FAILED'))
        with patch.object(recovery, 'command', return_value=b''), patch.object(recovery, 'event'), \
             self.assertRaisesRegex(recovery.Refused, '^RUNTIME_PROFILE_COMMAND_FAILED$'):
            job.prepare()
        job.npm.assert_not_called()
        job.aio.assert_not_called()

    @unittest.skipUnless(os.name == 'posix', 'Pinned renderer verifies real POSIX private permissions')
    def test_real_pinned_renderer_manual_view_leaves_public_plan_and_marker_integrity(self):
        root = self.home/'stack'
        (root/'config').mkdir(parents=True)
        original = plan()
        public = root/'config/dr-render-plan.json'
        public.write_text(json.dumps(original))
        before = public.read_bytes()
        (root/'.dr-fresh-target.json').write_text(json.dumps({'root': str(root)}))
        dr = recovery.configure_renderer(renderer(), 'manual')
        client = self.client({'/service': {'TOKEN': 'real-private-canary'}, '/oauth2-proxy': {}})
        snapshots = recovery.collect_inputs(original, dr, client, 'project', 'prod', aio_mode='manual',
                                             supplemental={recovery.OAUTH_ALLOWLIST_REF: 'one@example.invalid\n'})
        recovery.write_inputs(root/'.secrets/dr-inputs', snapshots)
        with patch.object(dr, 'sql_bootstrap', return_value=b'SELECT 1;\n'), contextlib.redirect_stdout(io.StringIO()):
            dr.render(N(target=str(root), input_dir=None, mode='fresh', synthetic=True, deployment_gid=os.getgid()))
        self.assertEqual(public.read_bytes(), before)
        self.assertEqual((root/'data/oauth2-proxy/allowed-emails.txt').read_text(), 'one@example.invalid\n')
        self.assertEqual((root/'.secrets/service.env').read_text(), 'TOKEN="real-private-canary"\n')
        marker = json.loads((root/'.generated/dr-render-complete.json').read_bytes())
        self.assertEqual(marker['root'], str(root))
        self.assertIn('data/oauth2-proxy/allowed-emails.txt', marker['outputs'])
        self.assertFalse((root/'.secrets/dr-inputs/dr.goenv').exists())


if __name__ == '__main__':
    unittest.main()

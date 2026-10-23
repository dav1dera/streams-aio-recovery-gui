"""Pinned first-boot cache reuse and finite, private command failure reporting.

All Docker results and private files are synthetic. No daemon or VM is used.
"""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT/'remote'/file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


recovery = module('first_boot_recovery', 'recover.py')
profile = module('first_boot_policy', 'runtime_profile.py')
CANARY = 'synthetic-password-that-must-stay-private'


def metadata(reference, **changes):
    item = dict(Id='sha256:'+'a'*64, Os='linux', Architecture='amd64', RepoDigests=[reference])
    item.update(changes)
    return json.dumps(item).encode()


class FirstBootCommands(unittest.TestCase):
    def setUp(self):
        directory = ROOT.parent/'gui-test-tmp' if os.name == 'nt' else None
        if directory is not None:
            directory.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=directory)
        self.addCleanup(self.temp.cleanup)
        self.root, self.home = Path(self.temp.name)/'stack', Path(self.temp.name)/'runner'
        self.root.mkdir(); self.home.mkdir()
        (self.root/'.generated').mkdir()
        self.job = recovery.Recovery.__new__(recovery.Recovery)
        self.job.root, self.job.home, self.job.tooling = self.root, self.home, self.home/'tooling'
        self.job.state = dict(completed=sorted(profile.FIRST_BOOT_STAGES), in_progress=None,
                              aio_recovery='MANUAL_PENDING', private_hashes={'preserved': 'synthetic'})
        self.before = copy.deepcopy(self.job.state)
        self.state_path = self.home/'state.json'
        self.state_path.write_text(json.dumps(self.before))
        self.state_raw = self.state_path.read_bytes()
        self.protected = self.root/'private-restored-data'
        self.protected.write_bytes(b'synthetic restored database and settings')
        self.protected_raw = self.protected.read_bytes()
        self.policy = N(Refused=profile.Refused, FIRST_BOOT_IMAGES=profile.FIRST_BOOT_IMAGES,
                        PG_IMAGE=profile.PG_IMAGE, DNS_IMAGE=profile.DNS_IMAGE,
                        OAUTH_IMAGE=profile.OAUTH_IMAGE, PGBOUNCER_IMAGE=profile.PGBOUNCER_IMAGE,
                        first_boot_images=Mock(return_value=profile.FIRST_BOOT_IMAGES),
                        validate=Mock(return_value=False), first_boot_scope=Mock(), apply_fresh=Mock())
        self.calls = []

    def runner(self, args, code, **kwargs):
        self.calls.append((args, code, kwargs))
        if code == 'RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED':
            return metadata(args[-1])
        if code == 'RUNTIME_PROFILE_COMPOSE_CONFIG_FAILED':
            return b'{"services":{}}'
        return b''

    def invoke(self, runner=None):
        with patch.object(recovery, 'load_module', return_value=self.policy), \
                patch.object(recovery, 'command', side_effect=runner or self.runner):
            self.job.prepare_first_boot()

    def unchanged(self):
        self.assertEqual(self.job.state, self.before)
        self.assertEqual(self.state_path.read_bytes(), self.state_raw)
        self.assertEqual(self.protected.read_bytes(), self.protected_raw)

    def test_offline_exact_cached_pins_do_not_pull_and_policy_checks_still_run(self):
        self.invoke()
        inspected = [args[-1] for args, code, _ in self.calls
                     if code == 'RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED']
        self.assertEqual(inspected, list(profile.FIRST_BOOT_IMAGES))
        self.assertFalse(any(args[:2] == ['docker', 'pull'] for args, _, _ in self.calls))
        self.policy.first_boot_scope.assert_called_once_with(self.root, self.home, self.job.state, installing=True)
        self.policy.first_boot_images.assert_called_once_with(self.root, {'services': {}})
        self.policy.apply_fresh.assert_called_once()
        self.unchanged()

    def test_only_missing_pin_is_pulled_once_by_exact_digest_with_bounded_timeout(self):
        def runner(args, code, **kwargs):
            if code == 'RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED' and args[-1] == profile.OAUTH_IMAGE:
                self.calls.append((args, code, kwargs)); return None
            return self.runner(args, code, **kwargs)
        self.invoke(runner)
        pulls = [(args, code, kwargs) for args, code, kwargs in self.calls if args[:2] == ['docker', 'pull']]
        self.assertEqual(pulls, [(['docker', 'pull', profile.OAUTH_IMAGE],
                                'RUNTIME_PROFILE_OAUTH_PULL_FAILED', dict(cwd=self.root, timeout=300))])
        self.policy.apply_fresh.assert_called_once()
        self.unchanged()

    def test_cache_and_pull_follow_the_selected_backup_instead_of_legacy_constants(self):
        selected = (*profile.FIRST_BOOT_IMAGES[:3],
                    'edoburu/pgbouncer@sha256:8638aa563607256d3c7440437534195f1066a92b68015d89ae9d6b935b444a6d')
        self.assertNotEqual(selected[-1], profile.PGBOUNCER_IMAGE)
        self.policy.first_boot_images.return_value = selected
        def runner(args, code, **kwargs):
            if code == 'RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED' and args[-1] == selected[-1]:
                self.calls.append((args, code, kwargs))
                return None
            return self.runner(args, code, **kwargs)
        self.invoke(runner)
        inspected = [args[-1] for args, code, _ in self.calls
                     if code == 'RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED']
        self.assertEqual(inspected, list(selected))
        self.assertNotIn(profile.PGBOUNCER_IMAGE, inspected)
        self.assertEqual([args[-1] for args, _, _ in self.calls if args[:2] == ['docker', 'pull']],
                         [selected[-1]])
        self.unchanged()

    def test_registered_profile_reuses_without_any_command(self):
        self.policy.validate.return_value = True
        self.invoke()
        self.assertEqual(self.calls, [])
        self.policy.first_boot_scope.assert_not_called()
        self.policy.apply_fresh.assert_not_called()
        self.unchanged()

    def test_scope_refusal_prevents_cache_inspection(self):
        self.policy.first_boot_scope.side_effect = profile.Refused('RUNTIME_PROFILE_SCOPE_REFUSED')
        with self.assertRaisesRegex(recovery.Refused, '^RUNTIME_PROFILE_SCOPE_REFUSED$'):
            self.invoke()
        self.assertEqual(self.calls, [])
        self.unchanged()

    def test_each_pull_failure_has_its_alias_code_and_preserves_prior_phases(self):
        for image, expected in zip(profile.FIRST_BOOT_IMAGES, recovery.FIRST_BOOT_PULL_CODES):
            def runner(args, code, **kwargs):
                if code == 'RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED' and args[-1] == image:
                    return None
                if args[:2] == ['docker', 'pull']:
                    raise recovery.Refused(code)
                return self.runner(args, code, **kwargs)
            with self.subTest(image=image), self.assertRaisesRegex(recovery.Refused, '^'+expected+'$'):
                self.invoke(runner)
            self.policy.apply_fresh.assert_not_called()
            self.unchanged()

    def test_cache_failure_does_not_guess_miss_or_pull(self):
        def runner(args, code, **kwargs):
            if code == 'RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED':
                self.calls.append((args, code, kwargs))
                raise recovery.Refused(code)
            return self.runner(args, code, **kwargs)
        with self.assertRaisesRegex(recovery.Refused, '^RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED$'):
            self.invoke(runner)
        self.assertEqual([code for _, code, _ in self.calls],
                         ['RUNTIME_PROFILE_COMPOSE_CONFIG_FAILED', 'RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED'])
        self.assertEqual(self.calls[-1][0][-1], profile.PG_IMAGE)
        self.policy.apply_fresh.assert_not_called()
        self.unchanged()

    def test_cache_wrong_digest_repository_platform_and_malformed_json_refuse(self):
        invalid = [b'not-json '+CANARY.encode(), b'[]',
                   metadata(profile.PG_IMAGE, Architecture='arm64'),
                   metadata(profile.PG_IMAGE, Os='windows'),
                   metadata(profile.PG_IMAGE, Id='sha256:invalid'),
                   metadata(profile.PG_IMAGE, RepoDigests=[]),
                   metadata(profile.PG_IMAGE, RepoDigests=['postgres@sha256:'+'b'*64]),
                   metadata(profile.PG_IMAGE, RepoDigests=['foreign/postgres@'+profile.PG_IMAGE.split('@')[1]])]
        for raw in invalid:
            with self.subTest(raw=raw), patch.object(recovery, 'command', return_value=raw), \
                    self.assertRaisesRegex(recovery.Refused, '^RUNTIME_PROFILE_IMAGE_CACHE_INVALID$'):
                recovery.first_boot_cached_image(profile.PG_IMAGE, self.root)
        self.unchanged()

    def test_docker_hub_repository_spelling_aliases_preserve_exact_digest(self):
        for prefix in ('', 'docker.io/', 'index.docker.io/', 'registry-1.docker.io/'):
            alias = prefix+'library/'+profile.PG_IMAGE
            with self.subTest(alias=alias), patch.object(recovery, 'command', return_value=metadata(alias)):
                self.assertTrue(recovery.first_boot_cached_image(profile.PG_IMAGE, self.root))
        alias = 'docker.io/'+profile.DNS_IMAGE
        with patch.object(recovery, 'command', return_value=metadata(alias)):
            self.assertTrue(recovery.first_boot_cached_image(profile.DNS_IMAGE, self.root))

    def test_initial_compose_invalid_json_or_non_object_has_separate_code(self):
        for raw in (b'private='+CANARY.encode(), b'[]', b'null', b'\xff'):
            def runner(args, code, **kwargs):
                if code == 'RUNTIME_PROFILE_COMPOSE_CONFIG_FAILED': return raw
                return self.runner(args, code, **kwargs)
            with self.subTest(raw=raw), self.assertRaisesRegex(recovery.Refused, '^RUNTIME_PROFILE_COMPOSE_CONFIG_INVALID$'):
                self.invoke(runner)
            self.policy.apply_fresh.assert_not_called()
            self.unchanged()

    def test_callback_failure_shapes_preserve_finite_code_and_policy_type(self):
        cases = [
            (['docker','compose','version','--short'], 'RUNTIME_PROFILE_COMPOSE_VERSION_FAILED'),
            (['docker','compose','--env-file','private.env','config','--format','json'], 'RUNTIME_PROFILE_COMPOSE_CONFIG_FAILED'),
            (['sudo','-H','-u','test','--','git','-C',str(self.root),'rev-parse','HEAD'], 'RUNTIME_PROFILE_GIT_READ_FAILED'),
            (['sudo','-H','-u','test','--','git','-C',str(self.root),'show','commit:scripts/dr.py'], 'RUNTIME_PROFILE_GIT_READ_FAILED'),
            (['docker','ps','-aq'], 'RUNTIME_PROFILE_DOCKER_RESOURCE_CHECK_FAILED'),
            (['docker','volume','ls','-q'], 'RUNTIME_PROFILE_DOCKER_RESOURCE_CHECK_FAILED'),
            (['docker','volume','inspect','owned'], 'RUNTIME_PROFILE_DOCKER_RESOURCE_CHECK_FAILED'),
            (['docker','inspect','owned'], 'RUNTIME_PROFILE_DOCKER_RESOURCE_CHECK_FAILED'),
            (['docker','image','inspect','--format','reviewed-format',profile.PG_IMAGE], 'RUNTIME_PROFILE_IMAGE_INSPECT_FAILED'),
            (['docker','image','save',profile.PG_IMAGE], 'RUNTIME_PROFILE_IMAGE_SAVE_FAILED'),
            (['unexpected',CANARY], 'RUNTIME_PROFILE_COMMAND_FAILED'),
        ]
        for args, expected in cases:
            def apply(root, home, state, model, run):
                with self.assertRaisesRegex(profile.Refused, '^'+expected+'$'):
                    run(args)
                raise profile.Refused(expected)
            self.policy.apply_fresh.side_effect = apply
            def runner(call, code, **kwargs):
                if call == args: raise recovery.Refused(code)
                return self.runner(call, code, **kwargs)
            with self.subTest(expected=expected, args=args), \
                    self.assertRaisesRegex(recovery.Refused, '^'+expected+'$'):
                self.invoke(runner)
            self.unchanged()

    def test_policy_transaction_rolls_back_candidate_and_preserves_code_and_private_data(self):
        original_env = ('PRIVATE='+CANARY+'\nCOMPOSE_FILE=\''+profile.BASE_COMPOSE+'\'\n').encode()
        env_path = self.root/'.env'
        env_path.write_bytes(original_env)
        self.policy.apply_fresh.side_effect = lambda root, home, state, model, run: profile.commit_profile(
            root, home, state, model, run, lambda: {'preserved': 'volume'}, origin='FIRST_BOOT')
        info = N(st_mode=stat.S_IFREG | 0o640, st_uid=0, st_gid=1000, st_nlink=1)
        def atomic(path, raw, mode, uid, gid): Path(path).write_bytes(raw)
        def runner(args, code, **kwargs):
            if args[:3] == ['docker','compose','--env-file']:
                # This command runs only after the policy writes its candidate.
                self.assertTrue((self.root/profile.ARTIFACT).is_file())
                raise recovery.Refused(code)
            return self.runner(args, code, **kwargs)
        with patch.object(profile, 'source_hashes', return_value={'synthetic': 'unchanged'}), \
                patch.object(profile, 'env_metadata', return_value=info), \
                patch.object(profile, 'regular', return_value=info), \
                patch.object(profile, 'private_directory'), patch.object(profile, 'atomic', side_effect=atomic), \
                patch.object(profile, 'overlay', return_value=b'synthetic candidate'), \
                self.assertRaisesRegex(recovery.Refused, '^RUNTIME_PROFILE_COMPOSE_CONFIG_FAILED$'):
            self.invoke(runner)
        self.assertEqual(env_path.read_bytes(), original_env)
        self.assertFalse((self.root/profile.ARTIFACT).exists())
        self.assertEqual((self.home/profile.BACKUP).read_bytes(), original_env)
        self.unchanged()

    def test_malformed_image_and_resource_json_retains_operation_code(self):
        cases = [(['docker','image','inspect','--format','reviewed-format',profile.PG_IMAGE],
                  'RUNTIME_PROFILE_IMAGE_INSPECT_FAILED', (b'not-json', b'[]', b'\xff')),
                 (['docker','volume','inspect','owned'],
                  'RUNTIME_PROFILE_DOCKER_RESOURCE_CHECK_FAILED', (b'not-json', b'{}', b'\xff')),
                 (['docker','inspect','owned'],
                  'RUNTIME_PROFILE_DOCKER_RESOURCE_CHECK_FAILED', (b'not-json', b'null', b'\xff'))]
        for args, expected, invalid in cases:
            self.policy.apply_fresh.side_effect = lambda root, home, state, model, run: run(args)
            for raw in invalid:
                def runner(call, code, **kwargs):
                    if call == args: return raw
                    return self.runner(call, code, **kwargs)
                with self.subTest(expected=expected, raw=raw), \
                        self.assertRaisesRegex(recovery.Refused, '^'+expected+'$'):
                    self.invoke(runner)
                self.unchanged()

    def test_unrecognized_callback_refusal_cannot_echo_arbitrary_text(self):
        args = ['docker','image','save',profile.PG_IMAGE]
        self.policy.apply_fresh.side_effect = lambda root, home, state, model, run: run(args)
        def runner(call, code, **kwargs):
            if call == args: raise recovery.Refused(CANARY)
            return self.runner(call, code, **kwargs)
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaisesRegex(recovery.Refused, '^RUNTIME_PROFILE_COMMAND_FAILED$'):
            self.invoke(runner)
        self.assertEqual(out.getvalue()+err.getvalue(), '')
        self.unchanged()

    def test_image_inspect_response_shape_matches_selected_docker_formatter(self):
        cases = [
            (['docker', 'image', 'inspect', profile.PG_IMAGE], b'[{"Id":"synthetic"}]'),
            (['docker', 'image', 'inspect', '--format', 'json', profile.PG_IMAGE],
             b'[{"Id":"synthetic"}]'),
            (['docker', 'image', 'inspect', '--format', '{{json .Config.Healthcheck}}', profile.PG_IMAGE],
             b'null'),
            (['docker', 'image', 'inspect', '--format', '{{json .Config.Healthcheck}}', profile.PG_IMAGE],
             b'{"Test":["CMD","synthetic"]}'),
        ]
        for args, expected in cases:
            def apply(root, home, state, model, run):
                self.assertEqual(run(args), expected)
            self.policy.apply_fresh.side_effect = apply
            def runner(call, code, **kwargs):
                if call == args: return expected
                return self.runner(call, code, **kwargs)
            with self.subTest(format=args):
                self.invoke(runner)
            self.unchanged()

    def test_unformatted_image_inspect_still_refuses_malformed_or_object_response(self):
        args = ['docker', 'image', 'inspect', profile.PG_IMAGE]
        self.policy.apply_fresh.side_effect = lambda root, home, state, model, run: run(args)
        for raw in (b'not-json', b'{}', b'null', b'\xff'):
            def runner(call, code, **kwargs):
                if call == args: return raw
                return self.runner(call, code, **kwargs)
            with self.subTest(raw=raw), self.assertRaisesRegex(
                    recovery.Refused, '^RUNTIME_PROFILE_IMAGE_INSPECT_FAILED$'):
                self.invoke(runner)
            self.unchanged()

    def command_probe(self, result=None, failure=None, args=None, code=None):
        args = args or ['docker','image','inspect','--format',recovery.FIRST_BOOT_CACHE_FORMAT,profile.PG_IMAGE]
        code = code or 'RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED'
        with patch.object(recovery.subprocess, 'run', return_value=result, side_effect=failure), \
                contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            try: return recovery.command(args, code, timeout=60)
            finally: self.assertEqual(out.getvalue()+err.getvalue(), '')

    def test_only_exact_missing_image_diagnostic_means_cache_miss(self):
        for prefix in ('Error response from daemon: No such image: ', 'Error: No such image: '):
            result = N(returncode=1, stdout=b'', stderr=(prefix+profile.PG_IMAGE+'\n').encode())
            self.assertIsNone(self.command_probe(result))
        for error in (b'permission denied '+CANARY.encode(), b'Cannot connect to Docker daemon',
                      b'Error response from daemon: No such image: postgres:latest',
                      ('Error: No such image: '+profile.DNS_IMAGE).encode(),
                      ('Error: No such image: '+profile.PG_IMAGE+'\n'+CANARY).encode()):
            with self.subTest(error=error), \
                    self.assertRaisesRegex(recovery.Refused, '^RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED$'):
                self.command_probe(N(returncode=1, stdout=b'', stderr=error))

    def test_missing_diagnostic_with_other_code_or_shape_is_not_a_cache_miss(self):
        result = N(returncode=1, stdout=b'', stderr=('Error: No such image: '+profile.PG_IMAGE).encode())
        with self.assertRaisesRegex(recovery.Refused, '^RUNTIME_PROFILE_IMAGE_INSPECT_FAILED$'):
            self.command_probe(result, code='RUNTIME_PROFILE_IMAGE_INSPECT_FAILED')
        with self.assertRaisesRegex(recovery.Refused, '^RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED$'):
            self.command_probe(result, args=['docker','image','inspect',profile.PG_IMAGE])

    def test_command_timeout_and_os_error_are_finite_and_private(self):
        for failure in (OSError(CANARY), subprocess.TimeoutExpired(['private-command'],60,stderr=CANARY.encode())):
            with self.subTest(failure=type(failure).__name__), \
                    self.assertRaisesRegex(recovery.Refused, '^RUNTIME_PROFILE_IMAGE_CACHE_INSPECT_FAILED$'):
                self.command_probe(failure=failure)

    def test_failed_child_stdout_stderr_is_not_logged_for_each_operation_code(self):
        result = N(returncode=1, stdout=CANARY.encode(), stderr=CANARY.encode())
        for code in recovery.FIRST_BOOT_COMMAND_CODES:
            with self.subTest(code=code), self.assertRaisesRegex(recovery.Refused, '^'+code+'$'):
                self.command_probe(result, args=['docker','pull',profile.PG_IMAGE],code=code)


if __name__ == '__main__':
    unittest.main()

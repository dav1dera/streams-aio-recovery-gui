"""Closed NPM failure transport and reconciliation of relocated bind mounts."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('start_relocation_tls_tests', ROOT / 'remote/start.py')
start = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {'fcntl': N(LOCK_EX=2, LOCK_NB=4, flock=lambda *args: None)}):
    spec.loader.exec_module(start)


class SafeNPMFailureTransport(unittest.TestCase):
    CANARY = 'SecretCanaryToken-private-controller.example.invalid'

    def setUp(self):
        self.root = Path('/synthetic/stack').absolute()
        self.home = Path('/synthetic/private').absolute()
        self.resource = Path(start.__file__).with_name('npm_runtime.py')

    def args(self, action='reissue'):
        return [sys.executable, '-B', self.resource, action, '--target', self.root]

    def result(self, stdout, exit_code=1):
        return N(returncode=exit_code, stdout=stdout, stderr=self.CANARY.encode())

    def test_safe_code_propagates_only_from_failed_npm_runtime_invocation(self):
        for code in start.TLS_CODES:
            for args in (self.args(), self.args('verify'),
                         self.args('verify') + ['--state-home', self.home]):
                output = io.StringIO()
                with self.subTest(code=code, action=args[3]), \
                        patch.object(start.subprocess, 'run', return_value=self.result(('NPM DR_REFUSED ' + code + '\n').encode())), \
                        contextlib.redirect_stdout(output), self.assertRaisesRegex(ValueError, '^' + code + '$'):
                    start.call(args, self.root)
                self.assertEqual(output.getvalue(), '')

    def test_matching_output_from_another_command_cannot_forge_tls_phase(self):
        code = 'TLS_NPM_NGINX_TEST_FAILED'
        variants = [
            ['another-python', *self.args()[1:]],
            [sys.executable, self.resource, 'reissue', '--target', self.root],
            [sys.executable, '-B', self.resource.with_name('untrusted.py'), 'reissue', '--target', self.root],
            [sys.executable, '-B', self.resource, 'unknown', '--target', self.root],
            self.args() + ['--unknown'],
            self.args()[:-1] + [self.home],
            self.args() + ['--state-home', self.home],
            ['docker', 'exec', 'untrusted'],
        ]
        for args in variants:
            with self.subTest(args=args), \
                    patch.object(start.subprocess, 'run', return_value=self.result(('NPM DR_REFUSED ' + code).encode())), \
                    self.assertRaisesRegex(ValueError, '^SERVICE_START_OR_CHECK_FAILED$'):
                start.call(args, self.root)

    def test_private_unknown_or_mixed_output_remains_generic(self):
        code = 'TLS_NPM_DNS01_ISSUANCE_FAILED'
        outputs = [
            self.CANARY.encode(),
            ('NPM DR_REFUSED ' + self.CANARY).encode(),
            ('NPM DR_REFUSED ' + code + ' ' + self.CANARY).encode(),
            ('NPM DR_REFUSED ' + code + '\n' + self.CANARY).encode(),
            ('NPM CERTIFICATE PASS\nNPM DR_REFUSED ' + code).encode(),
            ('NPM DR_REFUSED ' + code + '\nNPM DR_REFUSED ' + code).encode(),
            b'NPM DR_REFUSED TLS_VERIFICATION_FAILED', b'',
            b'\xffNPM DR_REFUSED ' + code.encode(),
        ]
        for output in outputs:
            with self.subTest(length=len(output)), \
                    patch.object(start.subprocess, 'run', return_value=self.result(output)), \
                    self.assertRaisesRegex(ValueError, '^SERVICE_START_OR_CHECK_FAILED$') as caught:
                start.call(self.args(), self.root)
            self.assertNotIn(self.CANARY, str(caught.exception))

    def test_success_exit_does_not_reinterpret_output_as_an_error(self):
        raw = b'NPM DR_REFUSED TLS_NPM_NGINX_TEST_FAILED\n'
        with patch.object(start.subprocess, 'run', return_value=self.result(raw, exit_code=0)):
            self.assertEqual(start.call(self.args(), self.root), raw)


class RelocatedContainerReconciliation(unittest.TestCase):
    def setUp(self):
        self.root = Path('/synthetic/stack').absolute()
        self.home = Path('/synthetic/private').absolute()
        self.state = {}
        self.model = dict(name='streams-aio', services={name: {} for name in
            ('headscale', 'headplane', 'honey', 'npm', 'comet')})
        self.digest = 'a' * 64
        self.evidence = dict(schema=1, sha256=self.digest, changed_files=2,
                             affected=['headscale', 'honey'], rewritten=['headscale', 'honey'])

    def row(self, name, *, foreign=False):
        return dict(Config=dict(Labels={
            'com.docker.compose.service': name,
            'com.docker.compose.project': 'foreign' if foreign else 'streams-aio',
            'com.docker.compose.project.working_dir': str(self.root)}))

    def invoke(self, containers, *, evidence=None, child=None, apply_error=None):
        calls, saves, emitted = [], [], []
        value = evidence if evidence is not None else self.evidence
        def apply(root, home, state, run, save):
            if apply_error:
                raise ValueError(apply_error)
            state['local_endpoints'] = {key: value[key] for key in ('schema', 'sha256', 'changed_files')}
            return value
        module = N(apply=Mock(side_effect=apply))
        loader = N(loader=N(exec_module=lambda module: None))
        def command(args, root):
            calls.append(args)
            if child:
                return child(args, root)
            return b''
        def save(path, state):
            saves.append((path, json.loads(json.dumps(state))))
        with patch.object(start.importlib.util, 'spec_from_file_location', return_value=loader), \
                patch.object(start.importlib.util, 'module_from_spec', return_value=module), \
                patch.object(start, 'call', side_effect=command), \
                patch.object(start, 'emit', side_effect=lambda *args: emitted.append(args)):
            start.relocate_local_endpoints(self.root, self.home, self.state, self.model, containers, save)
        return calls, saves, emitted, module

    def test_changed_headscale_and_honey_recreate_only_affected_existing_services_once(self):
        containers = [self.row(name) for name in ('headscale', 'headplane', 'honey', 'npm', 'comet')]
        calls, saves, events, module = self.invoke(containers)
        self.assertEqual(calls, [[
            'docker', 'compose', '--profile', 'all', 'up', '-d', '--no-deps',
            '--force-recreate', 'headplane', 'headscale', 'honey']])
        self.assertEqual(self.state['local_endpoints_runtime'], self.digest)
        self.assertEqual(len(saves), 1)
        self.assertEqual(saves[0][0], self.home / 'state.json')
        self.assertEqual(events, [('LOCAL_ENDPOINTS', 'RUNNING'), ('LOCAL_ENDPOINTS',)])
        module.apply.assert_called_once()
        resumed = dict(self.evidence, rewritten=[])
        calls, saves, _, module = self.invoke(containers, evidence=resumed)
        self.assertEqual(calls, [])
        self.assertEqual(saves, [])
        module.apply.assert_called_once()

    def test_fresh_install_does_not_create_workloads_during_relocation(self):
        calls, saves, _, _ = self.invoke([])
        self.assertEqual(calls, [])
        self.assertEqual(len(saves), 1)
        self.assertEqual(self.state['local_endpoints_runtime'], self.digest)

    def test_headplane_is_added_only_when_existing_headscale_config_changed(self):
        containers = [self.row(name) for name in ('headscale', 'headplane', 'honey')]
        calls, _, _, _ = self.invoke(containers, evidence=dict(self.evidence, affected=['honey']))
        self.assertEqual(calls[0][-1:], ['honey'])
        self.assertNotIn('headscale', calls[0])
        self.assertNotIn('headplane', calls[0])

    def test_absent_and_foreign_services_are_not_recreated(self):
        containers = [self.row('headscale'), self.row('honey', foreign=True), self.row('unrelated')]
        calls, _, _, _ = self.invoke(containers)
        self.assertEqual(calls[0][-1:], ['headscale'])
        self.assertNotIn('honey', calls[0])
        self.assertNotIn('headplane', calls[0])

    def test_failed_recreate_does_not_commit_runtime_hash_and_resume_retries(self):
        containers = [self.row(name) for name in ('headscale', 'headplane', 'honey')]
        def fail(args, root):
            raise ValueError('SERVICE_START_OR_CHECK_FAILED')
        with self.assertRaisesRegex(ValueError, '^SERVICE_START_OR_CHECK_FAILED$'):
            self.invoke(containers, child=fail)
        self.assertNotIn('local_endpoints_runtime', self.state)
        calls, _, _, _ = self.invoke(containers, evidence=dict(self.evidence, rewritten=[]))
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.state['local_endpoints_runtime'], self.digest)

    def test_relocation_source_drift_prevents_recreation_and_runtime_commit(self):
        with self.assertRaisesRegex(ValueError, '^LOCAL_ENDPOINTS_SOURCE_DRIFT$'):
            self.invoke([self.row('headscale')], apply_error='LOCAL_ENDPOINTS_SOURCE_DRIFT')
        self.assertNotIn('local_endpoints_runtime', self.state)


if __name__ == '__main__':
    unittest.main()

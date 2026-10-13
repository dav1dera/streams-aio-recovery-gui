"""NPM backend environment, exact source pins and child argument safety."""
import hashlib
import importlib.util
import contextlib
import io
from pathlib import Path
import tempfile
import json
import subprocess
import shutil
import types
import unittest
from unittest.mock import patch
from recovery_gui import backend
from recovery_gui import external_dependencies
from recovery_gui.ui_state import phase_status

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('npm_runtime_tests',ROOT/'remote/npm_runtime.py')
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
spec=importlib.util.spec_from_file_location('npm_runtime_policy_tests',ROOT/'remote/operational_profile.py')
policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)


class NativeNPMEnvironment(unittest.TestCase):
    def test_mixed_or_internal_routes_cannot_be_omitted(self):
        value=dict(routes=[dict(table='proxy_host',id=i) for i in (1,2,3,4)],bindings=[
            dict(table='proxy_host',id=1,role='external'),
            dict(table='proxy_host',id=2,role='compose'),
            dict(table='proxy_host',id=3,role='external'),dict(table='proxy_host',id=3,role='infisical')])
        self.assertEqual(runtime.external_route_ids(value),[1])

    def test_external_report_cannot_hide_a_recovered_route(self):
        self.assertEqual(runtime.external_report(dict(schema=1,total=2,unavailable=[26]),[20,26])['unavailable'],[26])
        for value in (dict(schema=1,total=2,unavailable=[2]),dict(schema=1,total=1,unavailable=[26,26]),
                      dict(schema=1,total=2,unavailable=[True]),dict(schema=1,total=0,unavailable=[26])):
            with self.assertRaisesRegex(ValueError,'^TLS_VERIFICATION_FAILED$'):runtime.external_report(value,[20,26])

    def test_closed_warning_crosses_transport_and_stays_visible(self):
        value=dict(schema=1,total=2,unavailable=[26])
        event=dict(stage='EXTERNAL_UPSTREAMS',status='WARNING',diagnostic=value)
        self.assertEqual(backend.parse_event('RECOVERY_EVENT '+json.dumps(event)),event)
        self.assertIn('da verificare',phase_status('EXTERNAL_UPSTREAMS','WARNING')[0])
        self.assertTrue(any('26' in line for line in external_dependencies.lines(value)))
        event['diagnostic']['domain']='private.example.invalid'
        self.assertIsNone(backend.parse_event('RECOVERY_EVENT '+json.dumps(event)))

    def test_warning_is_not_an_unqualified_pass(self):
        event=dict(stage='EXTERNAL_UPSTREAMS',status='PASS',diagnostic=dict(schema=1,total=2,unavailable=[26]))
        self.assertIsNone(backend.parse_event('RECOVERY_EVENT '+json.dumps(event)))

    def test_backend_environment_wraps_verified_helper_as_argument(self):
        helper="console.log('synthetic helper');"
        original=['docker','exec','-i','--user','0','--workdir','/app','a'*64,'node','--input-type=module','-e',helper]
        result=runtime.backend_command(original,helper)
        self.assertEqual(result[:8],original[:8])
        self.assertEqual(result[8:10],['bash','-c'])
        self.assertEqual(result[10],'. /usr/bin/common.sh; export HOME="$NPMHOME"; exec node --input-type=module -e "$1"')
        self.assertEqual(result[-1],helper)
        self.assertNotIn(helper,result[10])
        self.assertEqual(original[8],'node')

    def test_foreign_exec_or_modified_helper_is_refused(self):
        args=['docker','exec','-i','--user','0','--workdir','/app','a'*64,'node','--input-type=module','-e','verified']
        for index,value in ((4,'1000'),(7,'$(private)'),(11,'modified')):
            changed=args.copy();changed[index]=value
            with self.subTest(index=index),self.assertRaisesRegex(ValueError,'^TLS_VERIFICATION_FAILED$'):
                runtime.backend_command(changed,'verified')

    def test_inventory_commands_unchanged(self):
        for args in (['docker','ps','-aq'],['docker','inspect','a'*64]):
            self.assertIs(runtime.backend_command(args,'helper'),args)

    def test_changed_source_refused_before_loading(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'scripts/native.py';path.parent.mkdir();path.write_bytes(b'original\n')
            pins={'scripts/native.py':hashlib.sha256(path.read_bytes()).hexdigest()}
            with patch.object(runtime,'SOURCE_HASHES',pins):
                self.assertEqual(runtime.checked_sources(root)[1],{'scripts/native.py':'original\n'})
                path.write_bytes(b'modified\n')
                with self.assertRaisesRegex(ValueError,'^TLS_VERIFICATION_FAILED$'):runtime.checked_sources(root)

    def test_startup_certificate_actions_use_context_adapter(self):
        for action in ('reissue','verify'):
            commands=[];root=Path('/synthetic/stack')
            policy.npm_action(root,commands.append,action)
            self.assertEqual(Path(commands[0][2]).name,'npm_runtime.py')
            self.assertEqual(commands[0][3:],[action,'--target',root])


class SafeTLSPhaseDiagnostics(unittest.TestCase):
    CANARY = 'SecretCanaryCloudflareToken-PrivateExample.invalid'

    @staticmethod
    def success(action='reissue', external=None):
        value = dict(status='PASS', certificate_id=7, CERTIFICATE='PASS',
                     ASSOCIATIONS='PASS', NGINX='PASS', TLS='PASS')
        if action == 'verify':
            value['HTTPS'] = 'PASS'
        if external is not None:
            value['EXTERNAL_UPSTREAMS'] = external
        return json.dumps(value).encode()

    @staticmethod
    def failure(code):
        return json.dumps(dict(status='FAIL', code=code)).encode()

    def result(self, stdout, returncode=1):
        return subprocess.CompletedProcess(['private-child'], returncode, stdout, self.CANARY.encode())

    def test_real_pinned_helper_is_instrumented_without_changing_source(self):
        path = ROOT / 'tests/fixtures/npm-dr-helper-pinned.mjs'
        raw = path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), runtime.SOURCE_HASHES['scripts/npm-dr-helper.mjs'])
        text = raw.decode('utf-8')
        adapted = runtime.diagnostic_helper(text)
        self.assertEqual(path.read_bytes(), raw)
        self.assertNotEqual(adapted, text)
        for phase in runtime.TLS_PHASES:
            self.assertIn("recoveryPhase='" + phase + "'", adapted)
        self.assertNotIn("code:'RECOVERY_CHECK_FAILED'", adapted)
        # Existing policy/issuance decisions remain in the helper.
        self.assertIn('if(!validPair(certificate.id,domains))', adapted)
        self.assertIn('requestLetsEncryptSslWithDnsChallenge(certificate,owner.email)', adapted)
        self.assertIn('rejectUnauthorized:true', adapted)

    def test_external_route_scope_and_tls_instrumentation_compose(self):
        text = (ROOT / 'tests/fixtures/npm-dr-helper-pinned.mjs').read_text()
        adapted = runtime.diagnostic_helper(runtime.scoped_helper(text))
        self.assertIn('external_https_hosts.includes(item.saved.id)', adapted)
        self.assertIn("recoveryPhase='HTTPS_UPSTREAM'", adapted)
        self.assertIn("if(!['HTTPS_UPSTREAM_NOT_READY','HTTPS_TIMEOUT'].includes(error?.message))throw error", adapted)

    @unittest.skipUnless(shutil.which('node'), 'Node is required to syntax-check the generated helper')
    def test_generated_helpers_parse_as_real_node_modules_without_execution(self):
        text = (ROOT / 'tests/fixtures/npm-dr-helper-pinned.mjs').read_text()
        for helper in (runtime.diagnostic_helper(text), runtime.diagnostic_helper(runtime.scoped_helper(text))):
            result = subprocess.run([shutil.which('node'), '--check', '--input-type=module'],
                                    input=helper.encode(), capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, 'Generated public helper must parse as a Node module')

    def test_missing_or_duplicate_source_anchor_is_refused(self):
        text = (ROOT / 'tests/fixtures/npm-dr-helper-pinned.mjs').read_text()
        for changed in (text.replace('async function checkTls(name) {', 'async function renamed(name) {'),
                        text + '\nasync function checkTls(name) { }\n'):
            with self.assertRaisesRegex(ValueError, '^TLS_VERIFICATION_FAILED$'):
                runtime.diagnostic_helper(changed)

    def test_exact_nonzero_failure_preserves_each_closed_phase(self):
        for code in runtime.TLS_CODES:
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, '^' + code + '$'):
                runtime.helper_result(self.result(self.failure(code)), 'reissue')

    def test_untrusted_failure_shape_codes_or_success_exit_fail_closed(self):
        known = next(iter(runtime.TLS_CODES))
        samples = [b'', b'not-json ' + self.CANARY.encode(),
                   json.dumps(dict(status='FAIL', code=known, domain=self.CANARY)).encode(),
                   self.failure(known + ' ' + self.CANARY), self.failure(self.CANARY),
                   self.failure('RECOVERY_CHECK_FAILED'),
                   self.failure('TLS_VERIFICATION_FAILED'), self.success(),
                   self.failure(known) + b'\n' + self.CANARY.encode(),
                   b'{"status":"FAIL","code":"'+ known.encode() + b'","code":"'+known.encode()+b'"}',
                   b' ' * (runtime.MAX_HELPER_STDOUT + 1)]
        for raw in samples:
            with self.subTest(length=len(raw)), self.assertRaisesRegex(ValueError, '^TLS_VERIFICATION_FAILED$'):
                runtime.helper_result(self.result(raw), 'reissue')
        with self.assertRaisesRegex(ValueError, '^TLS_VERIFICATION_FAILED$'):
            runtime.helper_result(self.result(self.failure(known), returncode=0), 'reissue')

    def test_success_output_is_closed_and_cannot_forward_private_values(self):
        raw = self.success()
        self.assertEqual(runtime.helper_result(self.result(raw, 0), 'reissue'), raw)
        for mutation in ('private-field', 'private-status', 'id-bool', 'wrong-action'):
            value = json.loads(raw)
            if mutation == 'private-field': value['private'] = self.CANARY
            elif mutation == 'private-status': value['CERTIFICATE'] = self.CANARY
            elif mutation == 'id-bool': value['certificate_id'] = True
            else: value['HTTPS'] = 'PASS'
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, '^TLS_VERIFICATION_FAILED$'):
                runtime.helper_result(self.result(json.dumps(value).encode(), 0), 'reissue')

    def test_success_external_report_still_requires_only_proven_external_routes(self):
        report = dict(schema=1, total=2, unavailable=[26])
        raw = self.success('verify', report)
        self.assertEqual(runtime.helper_result(self.result(raw, 0), 'verify', [20, 26]), raw)
        with self.assertRaisesRegex(ValueError, '^TLS_VERIFICATION_FAILED$'):
            runtime.helper_result(self.result(raw, 0), 'verify', [2])

    def test_private_child_stderr_timeout_and_large_stdout_never_escape(self):
        args = ['docker', 'exec', 'verified-private-helper']
        for response in (self.result(self.failure('TLS_NPM_DNS01_ISSUANCE_FAILED')),
                         self.result(self.CANARY.encode()),
                         self.result(b' ' * (runtime.MAX_HELPER_STDOUT + 1))):
            with patch.object(runtime.subprocess, 'run', return_value=response) as run:
                output = io.StringIO()
                with contextlib.redirect_stdout(output), self.assertRaises(ValueError) as caught:
                    runtime.private_helper(args, action='reissue', input=b'PrivateInput', timeout=1200)
                self.assertNotIn(self.CANARY, str(caught.exception))
                self.assertEqual(output.getvalue(), '')
                self.assertEqual(run.call_args.kwargs['stdout'], subprocess.PIPE)
                self.assertEqual(run.call_args.kwargs['stderr'], subprocess.PIPE)
        with patch.object(runtime.subprocess, 'run', side_effect=subprocess.TimeoutExpired(args, 1200,
                output=self.CANARY.encode(), stderr=self.CANARY.encode())):
            with self.assertRaisesRegex(ValueError, '^TLS_VERIFICATION_FAILED$'):
                runtime.private_helper(args, action='reissue', input=b'PrivateInput', timeout=1200)

    def test_execute_captures_partial_output_and_sanitizes_unknown_errors(self):
        known = 'TLS_NPM_NGINX_TEST_FAILED'
        for failure in (ValueError(known), RuntimeError(self.CANARY), ValueError(known + self.CANARY)):
            def failing(*args):
                print(self.CANARY)
                raise failure
            output = io.StringIO()
            with patch.object(runtime, '_execute', failing), contextlib.redirect_stdout(output):
                with self.assertRaises(ValueError) as caught:
                    runtime.execute(Path('/synthetic'), 'reissue')
            self.assertEqual(output.getvalue(), '')
            self.assertEqual(str(caught.exception), known if failure.args == (known,) else 'TLS_VERIFICATION_FAILED')

    def test_execute_retains_known_success_output(self):
        output = io.StringIO()
        with patch.object(runtime, '_execute', lambda *args: print('NPM REISSUE PASS')), contextlib.redirect_stdout(output):
            runtime.execute(Path('/synthetic'), 'reissue')
        self.assertEqual(output.getvalue(), 'NPM REISSUE PASS\n')

    def test_cli_failure_is_one_safe_line_with_no_traceback_or_credentials(self):
        known = 'TLS_NPM_ACCESS_LISTS_REBUILD_FAILED'
        for error in (ValueError(known), RuntimeError(self.CANARY)):
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(runtime.os, 'geteuid', return_value=0, create=True), \
                    patch.object(runtime, 'execute', side_effect=error), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = runtime.main(['reissue', '--target', '/synthetic'])
            self.assertEqual(result, 1)
            self.assertEqual(stdout.getvalue(), 'NPM DR_REFUSED ' + (known if error.args == (known,) else 'TLS_VERIFICATION_FAILED') + '\n')
            self.assertEqual(stderr.getvalue(), '')

    def test_policy_propagates_only_matching_closed_codes(self):
        self.assertEqual(policy.TLS_CODES, runtime.TLS_CODES)
        for code in runtime.TLS_CODES:
            def run(args): raise ValueError(code)
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, '^' + code + '$'):
                policy.npm_action(Path('/synthetic'), run, 'reissue')
        for failure in (RuntimeError(self.CANARY), ValueError('TLS_NPM_NGINX_TEST_FAILED ' + self.CANARY)):
            def run(args): raise failure
            with self.assertRaisesRegex(ValueError, '^TLS_VERIFICATION_FAILED$'):
                policy.npm_action(Path('/synthetic'), run, 'reissue')

    def test_private_helper_only_intercepts_exact_verified_docker_shape(self):
        helper = (ROOT / 'tests/fixtures/npm-dr-helper-pinned.mjs').read_text()
        source = ('def command(args, **kw):\n    raise RuntimeError("unexpected native child")\n'
                  'def main():\n    command(["docker","exec","-i","--user","0","--workdir","/app",'
                  '"'+ 'a' * 64 +'","node","--input-type=module","-e",'+repr(helper)+'], input=b"{}", timeout=1200)\n')
        sources = {'scripts/dr.py': '', 'scripts/npm-dr.py': source,
                   'scripts/npm-dr-helper.mjs': helper}
        with patch.object(runtime, 'checked_sources', return_value=(Path('/synthetic'), sources)), \
                patch.object(runtime, 'private_helper', return_value=self.success()) as child:
            runtime.execute(Path('/synthetic'), 'reissue')
        self.assertEqual(child.call_count, 1)
        argv = child.call_args.args[0]
        self.assertEqual(argv[8:10], ['bash', '-c'])
        self.assertEqual(argv[10], runtime.NPM_RUNTIME)
        self.assertIn("recoveryPhase='DNS01_ISSUANCE'", argv[-1])
        self.assertNotEqual(argv[-1], helper)
        # A changed child argument cannot reach subprocess or bypass pin checks.
        sources['scripts/npm-dr.py'] = source.replace('"--user","0"', '"--user","1000"')
        with patch.object(runtime, 'checked_sources', return_value=(Path('/synthetic'), sources)), \
                patch.object(runtime, 'private_helper', return_value=self.success()) as child:
            with self.assertRaisesRegex(ValueError, '^TLS_VERIFICATION_FAILED$'):
                runtime.execute(Path('/synthetic'), 'reissue')
        child.assert_not_called()


if __name__=='__main__':unittest.main()

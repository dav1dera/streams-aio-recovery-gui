"""The isolated worker receives compressed sources without touching stdin."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zlib

from recovery_gui.onboarding import (MAX_REMOTE_ARGUMENT, MAX_REMOTE_SOURCE,
    ONBOARDING_FRAME, OnboardingError, REMOTE_WORKER, packed_remote_source)
from tests import test_onboarding_controller as fixtures


def packed(source):
    return base64.b64encode(zlib.compress(source.encode(), level=9)).decode('ascii')


class CompressedWorkerTests(unittest.TestCase):
    def worker(self, engine, helper, data=b'', configuration=None):
        # A minimal module stands in for the worker's already-installed PyYAML.
        # The actual child still runs isolated and receives exactly three argv blobs.
        program = "import sys,types;sys.modules['yaml']=types.ModuleType('yaml');" + REMOTE_WORKER
        return subprocess.run([sys.executable, '-I', '-c', program, engine, helper, configuration if configuration is not None else packed('CONFIGURATION_MARKER = True\n')], input=data,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=15)

    def test_large_helper_roundtrips_in_isolated_worker_and_preserves_sudo_frame(self):
        helper = '# synthetic trusted helper padding\n' * 6000 + 'MARKER = "module-loaded"\n'
        engine = ('import service_tooling,service_configuration\n'
                  'assert service_configuration.CONFIGURATION_MARKER\n'
                  'print(json.dumps({"marker":service_tooling.MARKER,"stdin":sys.stdin.buffer.read().hex()}))\n')
        self.assertGreater(len(helper.encode()), 128 * 1024)
        blobs = [packed(engine), packed(helper)]
        self.assertTrue(all(len(blob) < MAX_REMOTE_ARGUMENT for blob in blobs))
        data = b'synthetic-sudo-password\n' + ONBOARDING_FRAME + b'{"action":"inspect"}\n'
        result = self.worker(*blobs, data)
        self.assertEqual(result.stderr, b'')
        self.assertEqual(json.loads(result.stdout), dict(marker='module-loaded', stdin=data.hex()))

    def test_large_third_configuration_module_is_loaded_after_bounded_expansion(self):
        configuration = '# configuration helper padding\n' * 6000 + 'CONFIGURATION_MARKER = True\n'
        self.assertGreater(len(configuration), 128 * 1024)
        result = self.worker(packed('import service_configuration;print(json.dumps({"loaded":service_configuration.CONFIGURATION_MARKER}))'),
            packed('TOOLING_MARKER = True'), configuration=packed(configuration))
        self.assertEqual(json.loads(result.stdout), {'loaded': True})
        self.assertEqual(result.stderr, b'')
        result = self.worker(packed('print("unexpected")'), packed('TOOLING_MARKER = True'), configuration='not-base64!')
        self.assertEqual(json.loads(result.stdout)['status'], 'REFUSED')
        self.assertNotIn(b'unexpected', result.stdout)

    def test_expansion_bomb_is_refused_before_engine_or_helper_executes(self):
        result = self.worker(packed('print("engine-ran")'), packed('#' * (MAX_REMOTE_SOURCE + 1)))
        self.assertEqual(json.loads(result.stdout)['code'], 'ONBOARDING_PYTHON_ENVIRONMENT_REQUIRED')
        self.assertNotIn(b'engine-ran', result.stdout)
        self.assertEqual(result.stderr, b'')

    def test_malformed_or_trailing_compressed_sources_are_refused(self):
        for helper in ('not-base64!', base64.b64encode(zlib.compress(b'x=1') + b'trailing').decode()):
            with self.subTest(helper=helper[:12]):
                result = self.worker(packed('print("engine-ran")'), helper)
                self.assertEqual(json.loads(result.stdout)['status'], 'REFUSED')
                self.assertNotIn(b'engine-ran', result.stdout)
                self.assertEqual(result.stderr, b'')

    def test_desktop_bounds_both_expansion_and_kernel_argument(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'source.py'
            path.write_bytes(b'#' * (MAX_REMOTE_SOURCE + 1))
            with self.assertRaisesRegex(OnboardingError, '^SERVICE_TRANSPORT_FAILED$'):
                packed_remote_source(path)
            # Deterministic incompressible source bytes exercise the argv bound.
            raw = b''.join(__import__('hashlib').sha256(str(i).encode()).digest() for i in range(5000))
            path.write_bytes(raw)
            with self.assertRaisesRegex(OnboardingError, '^SERVICE_TRANSPORT_FAILED$'):
                packed_remote_source(path)

    def test_controller_transports_both_modules_compressed(self):
        case = fixtures.ControllerTests()
        case.setUp()
        case.inspect()
        args, request = case.ssh.calls[0]
        self.assertEqual(len(args), 8)
        for name, blob in zip(('service_onboarding.py', 'service_tooling.py', 'service_configuration.py'), args[-3:]):
            self.assertLessEqual(len(blob), MAX_REMOTE_ARGUMENT)
            self.assertEqual(zlib.decompress(base64.b64decode(blob)), (fixtures.RESOURCE / name).read_bytes())
        self.assertEqual(request['action'], 'discover')


if __name__ == '__main__':
    unittest.main()

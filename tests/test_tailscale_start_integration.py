"""Exercise real startup scheduling around the private enrollment boundary."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT/relative)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {'fcntl': N()} if sys.platform == 'win32' else {}):
        spec.loader.exec_module(module)
    return module


start = load('tailscale_start_integration', 'remote/start.py')
profile = load('tailscale_start_profile', 'remote/runtime_profile.py')
recovery = load('tailscale_start_recovery', 'remote/tailscale_recovery.py')


class TailscaleStartupIntegration(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(directory.cleanup)
        self.root, self.home = Path(directory.name)/'stack', Path(directory.name)/'recovery'
        (self.root/'config').mkdir(parents=True)
        self.home.mkdir()
        config = self.root/'data/headscale/data/config/config.yaml'
        config.parent.mkdir(parents=True)
        config.write_text('{"server_url":"https://controller.example.invalid"}')
        self.state_path = self.home/'state.json'
        self.state_path.write_text(json.dumps(dict(target=str(self.root), machine_id='replacement',
            preparation='PASS', runtime_profile=dict(id='V3', origin='FIRST_BOOT'),
            operational_deployment=dict(routing_mode='parallel_test', domain_target_address='192.168.1.20'),
            private_marker='preserved')))
        waves = [['postgres', 'headscale', 'tailscale', 'comet'], ['npm'], ['cometnet'], sorted(start.DEFERRED)]
        (self.root/'config/dr-manifest.yaml').write_text(json.dumps(dict(restore_waves=waves)))
        self.model = dict(name='streams-aio', services={name: dict(image=name+'@sha256:'+'a'*64)
            for name in sum(waves, [])}, volumes={})
        self.model['services']['npm']['depends_on'] = {'postgres': {'condition': 'service_healthy'}}
        self.model['services']['tailscale'].update(network_mode='host', environment={
            'TS_EXTRA_ARGS': '--login-server=https://controller.example.invalid', 'TS_AUTHKEY': 'old-key'})
        self.actions, self.wave_models = [], []
        self.bootstrap_count = 0

    def exercise(self, *, dns_error=None, enrollment_error=None):
        def run(args, root):
            if 'config' in args:
                return json.dumps(self.model).encode()
            if args[:3] == ['docker', 'ps', '-aq'] or args[:3] == ['docker', 'volume', 'ls']:
                return b''
            if 'verify' in args:
                return b'NPM_EXTERNAL_REPORT {"schema":1,"total":0,"unavailable":[]}\n'
            raise AssertionError(args)

        def before_tail(root, home, state, actual, run, runtime_profile, policy, emit):
            self.actions.append('enrollment')
            self.assertEqual(actual, self.model)
            self.assertEqual(json.loads(self.state_path.read_bytes()), state)
            if enrollment_error:
                raise ValueError(enrollment_error)
            if not state['runtime_profile'].get('tailscale_artifact'):
                # This spy replaces only the separately tested bootstrap transaction.
                # Its input must be the actual Compose, without scheduling-only deltas.
                self.assertNotIn('depends_on', actual['services']['tailscale'])
                self.bootstrap_count += 1
                updated = recovery.planned_model(self.root, actual)
                updated['services']['tailscale']['environment'].update(TS_AUTHKEY='replacement-key', TS_AUTH_ONCE='true')
                state['runtime_profile']['tailscale_artifact'] = '.generated/tailscale-recovery.env'
                self.state_path.write_text(json.dumps(state))
                self.model = updated
            return self.model

        def dns(*args):
            self.actions.append('dns')
            if dns_error:
                raise ValueError(dns_error)

        def wave(actual, root, selected):
            self.actions.append(tuple(selected))
            self.assertEqual(json.loads(self.state_path.read_bytes())['application_wave'], selected)
            self.wave_models.append((selected, copy.deepcopy(actual)))

        checks = N(stack_preflight=lambda *args: None,
                   save=lambda path, state: path.write_text(json.dumps(state)))
        runtime_profile = N(validate=lambda *args: True, OPERATIONAL_PROFILE='V3', FIRST_BOOT_PROFILE='V1',
            promote_operational=lambda *args: None, derived_waves=profile.derived_waves,
            health_dependency_issues=lambda *args: (0, 0))
        policy = N(deployment=lambda *args: start.DEFERRED, topology_targets=lambda *args: None,
            cometnet_endpoint=lambda *args: None,
            before_cometnet=lambda *args: self.actions.append('cometnet-proof'))
        tail_policy = N(planned_model=recovery.planned_model, preflight_dns=dns, before_tailscale=before_tail)
        loader = N(loader=N(exec_module=lambda module: None))
        original_stat, original_text = Path.stat, Path.read_text
        def metadata(path, *args, **kwargs):
            return N(st_mode=0o100600) if path == self.state_path else original_stat(path, *args, **kwargs)
        def text(path, *args, **kwargs):
            return 'replacement' if path == Path('/etc/machine-id') else original_text(path, *args, **kwargs)
        with patch.object(Path, 'stat', metadata), patch.object(Path, 'read_text', text), \
                patch.object(start, 'relocate_local_endpoints'), \
                patch.object(start.importlib.util, 'spec_from_file_location', return_value=loader), \
                patch.object(start.importlib.util, 'module_from_spec', side_effect=[checks, runtime_profile, policy, tail_policy]), \
                patch.object(start, 'call', run), patch.object(start, 'start_wave', wave), \
                patch.object(start, 'prepare_images', side_effect=lambda *a, **kw: self.actions.append('images')), \
                patch.object(start, 'final_service_check', side_effect=lambda *a, **kw: self.actions.append('final')), \
                contextlib.redirect_stdout(io.StringIO()):
            start.start(self.root, self.home, tls=True, operational=True)
        return json.loads(self.state_path.read_bytes())

    def test_controller_waves_precede_enrollment_and_updated_model_reaches_consumers(self):
        state = self.exercise()
        index = self.actions.index('enrollment')
        self.assertLess(self.actions.index(('postgres', 'headscale', 'comet')), index)
        self.assertLess(self.actions.index(('npm',)), index)
        tail_wave = next((names, model) for names, model in self.wave_models if 'tailscale' in names)
        self.assertEqual(tail_wave[1]['services']['tailscale']['environment']['TS_AUTHKEY'], 'replacement-key')
        self.assertLess(index, self.actions.index(tuple(tail_wave[0])))
        self.assertEqual(state['private_marker'], 'preserved')
        self.assertEqual(state['application_recovery'], 'STARTED_NEEDS_FUNCTIONAL_TEST')
        self.assertNotIn('application_wave', state)
        self.assertFalse(any('watchtower' in names for names, model in self.wave_models))

    def test_dns_refusal_preserves_prepared_checkpoint_before_images_or_start(self):
        before = self.state_path.read_bytes()
        with self.assertRaisesRegex(ValueError, '^TAILSCALE_CONTROLLER_DNS_MISMATCH$'):
            self.exercise(dns_error='TAILSCALE_CONTROLLER_DNS_MISMATCH')
        self.assertEqual(self.actions, ['dns'])
        self.assertEqual(self.state_path.read_bytes(), before)

    def test_enrollment_refusal_prevents_tailscale_cometnet_and_final_success(self):
        with self.assertRaisesRegex(ValueError, '^TAILSCALE_HEADSCALE_ENROLLMENT_REQUIRED$'):
            self.exercise(enrollment_error='TAILSCALE_HEADSCALE_ENROLLMENT_REQUIRED')
        self.assertFalse(any('tailscale' in names or 'cometnet' in names for names, model in self.wave_models))
        self.assertNotIn('final', self.actions)
        state = json.loads(self.state_path.read_bytes())
        self.assertTrue(state['application_start_attempted'])
        self.assertNotIn('application_recovery', state)
        self.assertEqual(state['private_marker'], 'preserved')

    def test_resume_retains_registered_model_without_replaying_enrollment(self):
        self.exercise()
        bound = copy.deepcopy(self.model)
        self.actions.clear()
        self.wave_models.clear()
        state = self.exercise()
        self.assertEqual(self.bootstrap_count, 1)
        self.assertEqual(self.model, bound)
        self.assertEqual(state['runtime_profile']['tailscale_artifact'], '.generated/tailscale-recovery.env')


if __name__ == '__main__':
    unittest.main()

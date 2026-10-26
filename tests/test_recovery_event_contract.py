"""Exercise the real preparation emitter and the closed desktop event receiver."""
import ast
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

from recovery_gui import backend
from recovery_gui.ui_state import phase_for

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('event_contract_recovery', ROOT/'remote/recover.py')
remote = importlib.util.module_from_spec(spec)
spec.loader.exec_module(remote)


def literal_stages(path, emitters):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    result = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        name = (node.func.id if isinstance(node.func, ast.Name) else
                node.func.attr if isinstance(node.func, ast.Attribute) else None)
        if name in emitters and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            result.add(node.args[0].value)
    return result


class EventContract(unittest.TestCase):
    def test_all_literal_prepare_agent_and_start_stages_reach_the_desktop(self):
        sender_stages = set()
        for name in ('recover.py', 'infisical_server.py', 'native_agent.py'):
            stages = literal_stages(ROOT/'remote'/name, {'event', 'step'})
            self.assertTrue(stages, name)
            self.assertLessEqual(stages, remote.EVENTS, name)
            sender_stages.update(stages)
        for name in ('start.py', 'operational_profile.py'):
            stages = literal_stages(ROOT/'remote'/name, {'emit'})
            self.assertTrue(stages, name)
            sender_stages.update(stages)
        self.assertIn('NPM_TOPOLOGY', sender_stages)
        self.assertLessEqual(sender_stages, backend.STAGES)
        for stage in sender_stages:
            for status in ('RUNNING', 'PASS'):
                item = dict(stage=stage, status=status)
                self.assertEqual(backend.parse_event('RECOVERY_EVENT '+json.dumps(item)), item)
        self.assertEqual(phase_for('NPM_TOPOLOGY'), 'Domini')
        # The visible dashboard label must accompany the newly accepted stage.
        dashboard = ast.parse((ROOT/'recovery_gui/ui_dashboard.py').read_text(encoding='utf-8'))
        labels = [value.value for node in ast.walk(dashboard) if isinstance(node, ast.Dict)
                  for key, value in zip(node.keys, node.values)
                  if isinstance(key, ast.Constant) and key.value == 'NPM_TOPOLOGY'
                  and isinstance(value, ast.Constant) and isinstance(value.value, str)]
        self.assertEqual(labels, ['Collegamenti NPM alle nuove VM'])

    def test_operational_prepare_uses_real_emitter_around_topology_before_prepared(self):
        with tempfile.TemporaryDirectory() as directory:
            job = remote.Recovery.__new__(remote.Recovery)
            job.home = Path(directory)
            job.root = job.home/'stack'
            job.tooling = ROOT/'remote'
            job.state_path = job.home/'state.json'
            job.state = dict(completed=[], in_progress=None)
            job.config = dict(operational_profile=True, routing_mode='parallel_test',
                              domain_target_address='192.0.2.29')
            actions = []
            for name in ('auth', 'validate_resume', 'clones', 'download', 'decrypt', 'initialize',
                         'inputs', 'prepare_first_boot', 'npm', 'aio', 'services', 'prepare_topology'):
                setattr(job, name, lambda name=name: actions.append(name))
            job.run_script = lambda name, action, *args, **kwargs: actions.append(action)
            policy = N(deployment_record=lambda *args: {'schema': 1})
            output = io.StringIO()
            with (patch.object(remote, 'command', return_value=b''),
                  patch.object(remote, 'load_module', return_value=policy),
                  patch.object(remote, 'stack_preflight', side_effect=lambda *args: actions.append('preflight')),
                  contextlib.redirect_stdout(output)):
                job.prepare()
            events = [backend.parse_event(line) for line in output.getvalue().splitlines()]
            self.assertTrue(events)
            self.assertNotIn(None, events, 'Every real sender event must cross the SSH receiver unchanged')
            stages = [item['stage'] for item in events]
            self.assertEqual([item for item in events if item['stage'] == 'NPM_TOPOLOGY'],
                             [dict(stage='NPM_TOPOLOGY', status='RUNNING'),
                              dict(stage='NPM_TOPOLOGY', status='PASS')])
            self.assertLess(stages.index('AIO'), stages.index('NPM_TOPOLOGY'))
            self.assertLess(stages.index('NPM_TOPOLOGY'), stages.index('PREFLIGHT'))
            self.assertLess(stages.index('PREFLIGHT'), stages.index('PREPARED'))
            self.assertLess(actions.index('aio'), actions.index('prepare_topology'))
            self.assertLess(actions.index('prepare_topology'), actions.index('preflight'))
            self.assertEqual(json.loads(job.state_path.read_bytes())['preparation'], 'PASS')

    def test_unknown_stage_and_unapproved_status_remain_rejected(self):
        for stage, status in (('PRIVATE_CANARY_STAGE', 'PASS'), ('NPM_TOPOLOGY', 'PRIVATE_CANARY_STATUS')):
            with self.subTest(stage=stage, status=status), self.assertRaisesRegex(remote.Refused, '^INVALID_EVENT$'):
                remote.event(stage, status)
            self.assertIsNone(backend.parse_event('RECOVERY_EVENT '+json.dumps(dict(stage=stage, status=status))))


if __name__ == '__main__':
    unittest.main()

"""Real POSIX handoff from the pinned renderer to the continuous Agent."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'remote'))
import native_agent as agent


@unittest.skipUnless(os.name == 'posix', 'Real Linux ownership and permission bits')
class NativeOutputPermissions(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()/'stack'
        self.root.mkdir()
        (self.root/'config').mkdir()
        self.plan = {'readiness_blockers': [], 'env_files': {
            '.secrets/comet.env': {'API_KEY': {'path': '/fixture', 'key': 'KEY'}}},
            'service_folder_exports': {}, 'root_env': {}, 'files': [],
            'required_values': ['/fixture/KEY'], 'runtime_fields': {},
            'postgres_bootstrap': {'destination': '.generated/postgres.sql'}}
        (self.root/'config/dr-render-plan.json').write_text(json.dumps(self.plan))
        (self.root/'.dr-fresh-target.json').write_text(json.dumps({'root': str(self.root)}))
        inputs = self.root/'.secrets/dr-inputs'
        inputs.mkdir(parents=True, mode=0o700)
        (inputs/'fixture.goenv').write_text('KEY="synthetic-secret-canary"\n')
        (inputs/'fixture.goenv').chmod(0o600)
        fixture = ROOT/'tests/fixtures/pinned_dr_renderer.py'
        spec = importlib.util.spec_from_file_location('native_permissions_pinned_dr', fixture)
        renderer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(renderer)
        # Exercise the real env renderer/exclusive writer/marker. PostgreSQL
        # bootstrap content is unrelated to this permission handoff.
        with patch.object(renderer, 'sql_bootstrap', return_value=b'SELECT 1;'), \
                contextlib.redirect_stdout(io.StringIO()):
            renderer.render(N(target=str(self.root), input_dir=None, mode='fresh',
                              synthetic=True, deployment_gid=os.getgid()))
        self.output = self.root/'.secrets/comet.env'
        self.rows = [{'destination-path': str(self.output)}]
        self.marker = self.root/'.generated/dr-render-complete.json'

    def handoff(self, rows=None):
        # CI's numeric user differs from the replacement VM's mandatory 1000.
        # Actual filesystem mode/ownership checks remain enabled in the test.
        agent.prepare_private_outputs(rows or self.rows, self.root, self.plan,
                                      uid=os.getuid(), gid=os.getgid())

    def test_real_renderer_handoff_and_repeat_preserve_content_and_marker(self):
        raw, marker = self.output.read_bytes(), self.marker.read_bytes()
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o640)
        with self.assertRaisesRegex(agent.Refused, 'PRIVATE_INPUT_REQUIRES_MODE_600'):
            agent.private_file(self.output)
        for attempt in range(2):
            self.handoff()
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
            self.assertEqual(self.output.read_bytes(), raw)
            self.assertEqual(self.marker.read_bytes(), marker)
            agent.private_file(self.output)

    def test_group_read_requires_both_public_plan_and_render_marker(self):
        for kind in ('plan', 'marker'):
            with self.subTest(kind=kind):
                original = dict(self.plan['env_files'])
                marker = json.loads(self.marker.read_bytes())
                if kind == 'plan':
                    self.plan['env_files'] = {}
                else:
                    marker['outputs'] = []
                    agent.save(self.marker, marker)
                with self.assertRaisesRegex(agent.Refused, 'AGENT_PRIVATE_OUTPUT_PERMISSIONS_INVALID'):
                    self.handoff()
                self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o640)
                self.plan['env_files'] = original

    def test_wrong_owner_or_group_is_refused_without_mutation(self):
        actual_stat = Path.stat
        for field in ('st_uid', 'st_gid'):
            def metadata(path, *args, **kwargs):
                actual = actual_stat(path, *args, **kwargs)
                if path != self.output:
                    return actual
                values = {name: getattr(actual, name) for name in ('st_mode', 'st_uid', 'st_gid', 'st_nlink')}
                values[field] = 1234567
                return N(**values)
            with self.subTest(field=field), patch.object(Path, 'stat', metadata):
                with self.assertRaisesRegex(agent.Refused, 'AGENT_PRIVATE_OUTPUT_PERMISSIONS_INVALID'):
                    self.handoff()
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o640)

    def test_world_group_write_and_special_bits_remain_refused(self):
        for mode in (0o644, 0o660, 0o1640, 0o4640):
            self.output.chmod(mode)
            with self.subTest(mode=mode), self.assertRaisesRegex(
                    agent.Refused, 'AGENT_PRIVATE_OUTPUT_PERMISSIONS_INVALID'):
                self.handoff()
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), mode)

    def test_hardlink_or_symlink_is_never_reowned_or_chmodded(self):
        alias = self.root/'alias'
        os.link(self.output, alias)
        with self.assertRaisesRegex(agent.Refused, 'AGENT_PRIVATE_OUTPUT_INVALID'):
            self.handoff()
        self.assertEqual(stat.S_IMODE(alias.stat().st_mode), 0o640)
        alias.unlink()
        alias.symlink_to(self.output)
        with self.assertRaisesRegex(agent.Refused, 'SYMLINK_PATH_REFUSED'):
            self.handoff([{'destination-path': str(alias)}])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o640)

    def test_later_bad_output_refuses_the_whole_set_before_changes(self):
        second = self.root/'.secrets/second.env'
        second.write_bytes(b'second-synthetic-canary')
        second.chmod(0o644)
        with self.assertRaisesRegex(agent.Refused, 'AGENT_PRIVATE_OUTPUT_PERMISSIONS_INVALID'):
            self.handoff(self.rows + [{'destination-path': str(second)}])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(second.stat().st_mode), 0o644)

    def test_private_credentials_still_require_owner_only_access(self):
        credential = self.root/'private-identity'
        credential.write_bytes(b'synthetic-identity-canary')
        credential.chmod(0o640)
        with self.assertRaisesRegex(agent.Refused, 'PRIVATE_INPUT_REQUIRES_MODE_600'):
            agent.private_file(credential)
        self.assertEqual(stat.S_IMODE(credential.stat().st_mode), 0o640)

    def test_foreign_marker_and_destination_escape_are_refused(self):
        marker = json.loads(self.marker.read_bytes())
        marker['root'] = str(self.root/'other')
        agent.save(self.marker, marker)
        with self.assertRaisesRegex(agent.Refused, 'AGENT_RENDER_MARKER_INVALID'):
            self.handoff()
        marker['root'] = str(self.root)
        agent.save(self.marker, marker)
        with self.assertRaisesRegex(agent.Refused, 'AGENT_PRIVATE_OUTPUT_INVALID'):
            self.handoff([{'destination-path': str(self.root/'outside.env')}])
        self.assertFalse((self.root/'outside.env').exists())


if __name__ == '__main__':
    unittest.main()

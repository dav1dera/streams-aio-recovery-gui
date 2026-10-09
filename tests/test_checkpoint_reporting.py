import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from recovery_gui.app import host_check_message
from recovery_gui.backend import Failure, check_first_boot_resume, restore_all
from recovery_gui.codes import ERROR_CODES

spec = importlib.util.spec_from_file_location('checkpoint_reporting_probe', ROOT/'remote/probe.py')
probe = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {'pwd': N()} if sys.platform == 'win32' else {}):
    spec.loader.exec_module(probe)


class CheckpointReporting(unittest.TestCase):
    def test_only_fixed_phase_flags_are_exposed(self):
        data = dict(preparation='PASS', application_start_attempted=True,
                    runtime_profile={'private-canary': 'private-canary'},
                    completed=['NPM', 'AIO'], private_hashes={'private-canary': 'private-canary'},
                    environment='private-canary', tag='private-canary')
        public = probe.checkpoint_summary(data)
        self.assertEqual(public, dict(prepared=True, application_start_attempted=True,
                                     runtime_profile_recorded=True, npm_completed=True, aio_completed=True,
                                     infisical_completed=False))
        self.assertNotIn('canary', json.dumps(public))
        for attempted in ('private-canary', 1, None):
            self.assertIsNone(probe.checkpoint_summary(dict(application_start_attempted=attempted))[
                'application_start_attempted'])
        self.assertIs(probe.checkpoint_summary({})['application_start_attempted'], False)

    def probe_fixture(self, populated):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target, runner = root/'stack', root/'runner'
            target.mkdir()
            runner.mkdir()
            state_path = runner/'state.json'
            state = dict(target=str(target), machine_id='fixture-machine', preparation='PASS',
                         application_start_attempted=populated, completed=['NPM', 'AIO'])
            state_path.write_text(json.dumps(state))
            original_read, original_stat = Path.read_text, Path.stat

            def read(path, *args, **kw):
                if path.name == 'os-release':
                    return 'ID=ubuntu\nVERSION_ID="26.04"\nVERSION_CODENAME=resolute\n'
                if path.name == 'machine-id':
                    return 'fixture-machine\n'
                return original_read(path, *args, **kw)

            def metadata(path, *args, **kw):
                result = original_stat(path, *args, **kw)
                # Synthetic fixture metadata; Windows has no Linux private mode.
                return N(st_mode=result.st_mode & ~0o077) if path == state_path else result

            def docker(args, **kw):
                return N(returncode=0, stdout=b'fixture-id\n' if populated else b'')

            with patch.object(Path, 'read_text', read), patch.object(Path, 'stat', metadata), \
                 patch.object(probe.pwd, 'getpwuid', return_value=N(pw_gid=1000, pw_name='test', pw_dir=str(root)), create=True), \
                 patch.object(os, 'uname', return_value=N(machine='x86_64'), create=True), \
                 patch.object(probe.shutil, 'which', return_value='/usr/bin/docker'), \
                 patch.object(probe.subprocess, 'run', docker), \
                 patch.object(probe, 'checked_stack_runtime') as owned:
                result = probe.probe(target, runner, fresh=True)
                self.assertEqual(owned.call_count, int(populated))
            return result

    def test_probe_reports_phases_on_empty_and_owned_runtime_paths(self):
        for populated in (False, True):
            with self.subTest(populated=populated):
                result = self.probe_fixture(populated)
                self.assertTrue(result['existing_recovery'])
                self.assertEqual(result['containers'], int(populated))
                self.assertEqual(result['volumes'], int(populated))
                self.assertIs(result['recovery']['application_start_attempted'], populated)
                self.assertTrue(result['recovery']['npm_completed'])

    def test_gui_describes_existing_state_without_claiming_a_fresh_vm(self):
        info = dict(os='Ubuntu 26.04', containers=12, volumes=4, existing_recovery=True,
                    recovery=probe.checkpoint_summary(dict(preparation='PASS', application_start_attempted=True)))
        text = host_check_message(info)
        for phrase in ('12 container', '4 volumi', 'Recupero precedente', 'avvio già tentato', 'assente'):
            self.assertIn(phrase, text)
        self.assertNotIn('nessun container', text)
        info.update(containers=0, volumes=0, existing_recovery=False, recovery=None)
        self.assertEqual(host_check_message(info), 'VM stack verificata: Ubuntu 26.04 amd64; 0 container, 0 volumi Docker.')
        self.assertIn('VM Infisical', host_check_message(info, role='infisical'))

    def test_infisical_message_uses_its_own_completed_stage(self):
        info = dict(os='Ubuntu 26.04', containers=3, volumes=2, existing_recovery=True,
                    recovery=probe.checkpoint_summary(dict(completed=['INFISICAL_CONFIG', 'INFISICAL_SERVER'])))
        text = host_check_message(info, role='infisical')
        self.assertIn('3 container, 2 volumi', text)
        self.assertIn('Recupero Infisical completato nel checkpoint', text)
        self.assertNotIn('avvio non ancora tentato', text)
        self.assertNotIn('preparazione parziale', text)
        self.assertNotIn('Profilo di compatibilità', text)

    def test_unreviewed_legacy_start_stops_before_any_server_operation(self):
        for attempted in (True, None):
            first = dict(existing_recovery=True, recovery=dict(application_start_attempted=attempted,
                                                              runtime_profile_recorded=False))
            stack, server = Mock(), Mock()
            stack.check.return_value = first
            with self.subTest(attempted=attempted), self.assertRaisesRegex(
                    Failure, '^RUNTIME_PROFILE_PRESTART_CHECKPOINT_REQUIRED$'):
                restore_all(stack, server, {}, Mock())
            self.assertEqual(stack.method_calls, [('check', (), {})])
            self.assertEqual(server.method_calls, [])
        self.assertIn('RUNTIME_PROFILE_PRESTART_CHECKPOINT_REQUIRED', ERROR_CODES)

    def test_new_prestart_and_recorded_profiles_keep_their_resume_path(self):
        for info in (dict(existing_recovery=False, recovery=None),
                     dict(existing_recovery=True, recovery=dict(application_start_attempted=False,
                                                                runtime_profile_recorded=False)),
                     dict(existing_recovery=True, recovery=dict(application_start_attempted=True,
                                                                runtime_profile_recorded=True))):
            with self.subTest(info=info):
                check_first_boot_resume(info)


if __name__ == '__main__':
    unittest.main()

"""Closed recovery failures remain guided errors through event transport."""
import json
from pathlib import Path
import re
import unittest

from recovery_gui.app import ERRORS
from recovery_gui.backend import parse_event
from recovery_gui.codes import ERROR_CODES
from recovery_gui.ui_state import error_destination


ROOT=Path(__file__).resolve().parents[1]


class DashboardErrors(unittest.TestCase):
    def test_all_native_capsule_and_topology_codes_survive_with_guided_text(self):
        names=set()
        for file in ('aio_snapshot.py','npm_topology.py'):
            names.update(re.findall(r"'((?:AIO_SNAPSHOT_|NPM_TOPOLOGY_)[A-Z0-9_]+)'",
                                   (ROOT/'remote'/file).read_text()))
        names.add('NPM_TOPOLOGY_BACKUP_REQUIRED')
        self.assertTrue(names)
        for code in names:
            with self.subTest(code=code):
                self.assertIn(code,ERROR_CODES)
                self.assertIn(code,ERRORS)
                self.assertGreater(len(ERRORS[code]),35)
                event=dict(stage='REFUSED',status='REFUSED',code=code)
                self.assertEqual(parse_event('RECOVERY_EVENT '+json.dumps(event)),event)

    def test_interrupted_transactions_are_directed_to_their_preserved_status(self):
        for code in ('AIO_SNAPSHOT_JOURNAL_INVALID','NPM_TOPOLOGY_JOURNAL_INVALID',
                     'NPM_TOPOLOGY_EVIDENCE_REQUIRED','NPM_TOPOLOGY_SOURCE_DRIFT',
                     'NPM_TOPOLOGY_DATABASE_IDENTITY_REQUIRED'):
            self.assertEqual(error_destination(code)[0],0)
        for code in ('NPM_TOPOLOGY_BACKUP_REQUIRED','NPM_TOPOLOGY_TARGET_INVALID',
                     'PUBLIC_DOMAIN_CONFIGURATION_REQUIRED','AIO_SNAPSHOT_ARCHIVE_INVALID'):
            self.assertEqual(error_destination(code)[0],1)
        self.assertEqual(error_destination('OAUTH_ALLOWLIST_SUPPLEMENT_REQUIRED')[0],2)

    def test_guidance_does_not_require_removed_wizard_controls_or_manual_reset(self):
        self.assertNotIn('passo Backup',ERRORS['OAUTH_ALLOWLIST_SUPPLEMENT_REQUIRED'])
        for code in ('RUNTIME_PROFILE_POSTGRES_PULL_FAILED','RUNTIME_PROFILE_DNS_PULL_FAILED',
                     'RUNTIME_PROFILE_OAUTH_PULL_FAILED','RUNTIME_PROFILE_PGBOUNCER_PULL_FAILED'):
            self.assertIn('Rileva e continua',ERRORS[code])
            self.assertNotIn('Ricomincia il test',ERRORS[code])

    def test_controller_dns_failure_points_to_the_visible_overview_card(self):
        code='TAILSCALE_CONTROLLER_DNS_MISMATCH'
        self.assertEqual(error_destination(code)[0],0)
        self.assertIn('non modifica il DNS',ERRORS[code])
        self.assertEqual(parse_event('RECOVERY_EVENT '+json.dumps(dict(stage='REFUSED',status='REFUSED',code=code)))['code'],code)


if __name__=='__main__':
    unittest.main()

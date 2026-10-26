"""Public configuration mode checks with bounded POSIX ACL compatibility."""
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from remote import recover
from remote import service_onboarding as onboarding

ROOT = Path(__file__).resolve().parents[1]
UNDEFINED = 0xffffffff


def acl_bytes(*, owner=6, group_object=7, mask=7, other=4, named=True):
    entries = [(1, owner, UNDEFINED)]
    if named:
        entries.append((2, 6, 12345))
    entries += [(4, group_object, UNDEFINED), (16, mask, UNDEFINED), (32, other, UNDEFINED)]
    return struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *row) for row in entries)


class PublicConfigurationModeTests(unittest.TestCase):
    def target(self, mode=0o674, kind=stat.S_IFREG):
        target = mock.Mock(spec=Path)
        target.stat.return_value = SimpleNamespace(st_mode=kind | mode)
        return target

    def check(self, mode=0o674, declared=0o644, raw=None, *, kind=stat.S_IFREG):
        target = self.target(mode, kind)
        with mock.patch.object(recover.os, 'getxattr', return_value=acl_bytes() if raw is None else raw, create=True):
            return recover.public_configuration_mode_matches(target, declared)

    def test_exact_portable_mode_needs_no_acl_exception(self):
        target = self.target(0o644)
        with mock.patch.object(recover.os, 'getxattr', create=True) as reader:
            self.assertTrue(recover.public_configuration_mode_matches(target, 0o644))
        reader.assert_not_called()

    def test_inherited_group_object_can_exceed_the_installed_mask(self):
        # chmod sets ACL_MASK to r--; a later access watcher recalculates rwx.
        # The inherited GROUP_OBJ remains rwx throughout, so comparing it with
        # the declared r-- bits would reject a valid default ACL.
        self.assertTrue(self.check(raw=acl_bytes(group_object=7, mask=7)))
        self.assertTrue(self.check(mode=0o664, raw=acl_bytes(group_object=4, mask=6)))

    def test_owning_group_keeps_declared_access_even_with_a_wide_mask(self):
        for owning_group in range(8):
            with self.subTest(owning_group=owning_group):
                accepted = self.check(raw=acl_bytes(group_object=owning_group, mask=7))
                self.assertEqual(accepted, bool(owning_group & 4))

    def test_owner_other_special_and_narrowed_masks_are_not_exempted(self):
        for mode in (0o474, 0o676, 0o4674, 0o634):
            with self.subTest(mode=oct(mode)):
                self.assertFalse(self.check(mode=mode))
        self.assertFalse(self.check(mode=0o674, kind=stat.S_IFDIR))
        for declared in (True, '644', -1, 0o1000):
            with self.subTest(declared=declared):
                self.assertFalse(self.check(declared=declared))

    def test_group_mode_drift_without_readable_extended_acl_is_refused(self):
        target = self.target()
        with mock.patch.object(recover.os, 'getxattr', side_effect=OSError(errno.ENODATA, 'No ACL'), create=True):
            self.assertFalse(recover.public_configuration_mode_matches(target, 0o644))

    def test_malformed_or_inconsistent_acl_cannot_explain_mode_drift(self):
        valid = acl_bytes()
        malformed = [b'', valid[:3], struct.pack('<I', 1) + valid[4:], valid + b'x',
                     b'x' * 65537, acl_bytes(named=False), acl_bytes(mask=6),
                     acl_bytes(owner=4), acl_bytes(other=0),
                     valid + struct.pack('<HHI', 16, 7, UNDEFINED),
                     valid + struct.pack('<HHI', 2, 6, 12345),
                     valid + struct.pack('<HHI', 2, 8, 99),
                     valid + struct.pack('<HHI', 64, 7, UNDEFINED),
                     valid + struct.pack('<HHI', 2, 7, UNDEFINED)]
        for raw in malformed:
            with self.subTest(raw_length=len(raw)):
                self.assertFalse(self.check(raw=raw))

    def test_private_output_metadata_remains_exact(self):
        item = onboarding.Snapshot('/synthetic/.secrets/demo.env', b'not-a-credential',
                                   uid=0, gid=1001, mode=0o670,
                                   attributes={'system.posix_acl_access': acl_bytes(other=0)})
        self.assertFalse(onboarding.metadata_matches(item, 0o640, {}, public=False))


@unittest.skipUnless(os.environ.get('RECOVERY_PUBLIC_ACL_INTEGRATION') == '1',
                     'Requires explicit RECOVERY_PUBLIC_ACL_INTEGRATION=1 and Linux ACL tools')
class RealPublicConfigurationACLTests(unittest.TestCase):
    def setfacl(self, target, entries):
        result = subprocess.run(['setfacl', '-m', entries, str(target)], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, 'REAL_ACL_SETUP_FAILED')

    def test_real_default_acl_install_restore_and_watcher_mask_recalculation(self):
        self.assertEqual(sys.platform, 'linux')
        self.assertIsNotNone(shutil.which('setfacl'), 'REAL_ACL_TOOL_REQUIRED')
        with tempfile.TemporaryDirectory(prefix='recovery-public-acl-') as temporary:
            base = Path(temporary).resolve()
            root = base / 'stack'
            target = root / 'data/demo/public/settings.yaml'
            target.parent.mkdir(parents=True)
            (root / 'config').mkdir()
            uid, gid = os.getuid(), os.getgid()
            named_uid = uid + 1
            self.setfacl(target.parent, 'd:u::rwx,d:u:' + str(named_uid)
                         + ':rwx,d:g::rwx,d:m::rwx,d:o::r--')
            raw = b'title: Real ACL fixture\n'
            installed = onboarding.Store().write(target, raw, uid, gid, 0o644, public=True)
            self.assertEqual(installed.mode, 0o644)
            inherited = os.getxattr(target, 'system.posix_acl_access')
            entries = list(struct.iter_unpack('<HHI', inherited[4:]))
            self.assertIn((4, 7, UNDEFINED), entries)
            self.assertIn((16, 4, UNDEFINED), entries)
            self.setfacl(target, 'u:' + str(named_uid) + ':rw-')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o674)
            self.assertTrue(recover.public_configuration_mode_matches(target, 0o644))
            inventory = dict(schema=1, resources=[], configuration_files=[dict(
                path='data/demo/public/settings.yaml', mode=0o644,
                sha256=hashlib.sha256(raw).hexdigest())])
            inventory_path = root / 'config/service-resources.json'
            inventory_raw = (json.dumps(inventory) + '\n').encode()
            inventory_path.write_bytes(inventory_raw)
            self.assertEqual(recover.verify_service_snapshot(root, {}), {})
            self.assertEqual(inventory_path.read_bytes(), inventory_raw)
            self.assertEqual(target.read_bytes(), raw)
            self.setfacl(target, 'g::---,m::rwx')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o674)
            with self.assertRaisesRegex(recover.Refused, 'SERVICES_STATE_CONFIGURATION_CHANGED'):
                recover.verify_service_snapshot(root, {})
            self.setfacl(target, 'g::rwx')
            self.assertEqual(recover.verify_service_snapshot(root, {}), {})
            # The normal restorer installs the portable mode; the existing
            # access watcher can then recalculate its host-local ACL mask.
            job = recover.Recovery.__new__(recover.Recovery)
            job.root, job.private, job.tooling = root, base / 'private', ROOT / 'remote'
            job.private.mkdir()
            job.services()
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o644)
            self.setfacl(target, 'u:' + str(named_uid) + ':rw-')
            self.assertEqual(recover.verify_service_snapshot(root, {}), {})
            target.chmod(0o676)
            with self.assertRaisesRegex(recover.Refused, 'SERVICES_STATE_CONFIGURATION_CHANGED'):
                recover.verify_service_snapshot(root, {})
            target.chmod(0o644)
            target.write_bytes(b'changed public configuration\n')
            with self.assertRaisesRegex(recover.Refused, 'SERVICES_STATE_CONFIGURATION_CHANGED'):
                recover.verify_service_snapshot(root, {})
            self.assertEqual(inventory_path.read_bytes(), inventory_raw)


if __name__ == '__main__':
    unittest.main()

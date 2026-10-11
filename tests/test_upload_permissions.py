"""Real root-to-UID-1000 upload staging permissions, without SSH or secrets."""
import errno
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT_POSIX = os.name == 'posix' and os.geteuid() == 0 and hasattr(os, 'fork')
AREA_NAMES = ('streams-aio-recovery', 'streams-aio-infisical-recovery')
OLD_SETUP = '''import os,sys
from pathlib import Path
area,stage=map(Path,sys.argv[1:])
os.umask(0o077)
if not area.exists():
    area.mkdir(parents=True,mode=0o700)
    os.chown(area,1000,1000)
stage.mkdir(mode=0o700)
os.chown(stage,1000,1000)
'''


class UploadPermissionIntegrationRequirement(unittest.TestCase):
    def test_requested_permission_integration_cannot_silently_skip(self):
        if os.environ.get('RECOVERY_UPLOAD_PERMISSION_INTEGRATION') == '1':
            self.assertTrue(ROOT_POSIX, 'Upload permission integration requires POSIX root and fork')


@unittest.skipUnless(ROOT_POSIX, 'Requires POSIX root and a real UID 1000 child')
class RealUploadPermissions(unittest.TestCase):
    def setUp(self):
        # UID 1000 must traverse the outer fixture while every home stays private.
        self.temp = tempfile.TemporaryDirectory(prefix='recovery-upload-', dir='/var/tmp')
        self.addCleanup(self.temp.cleanup)
        self.outer = Path(self.temp.name)
        self.outer.chmod(0o711)
        self.home = self.make_home('user')
        self.area = self.home / '.local/share' / AREA_NAMES[0]
        self.stage = self.area / ('upload-' + 'a' * 32)

    def make_home(self, name):
        home = self.outer / name
        home.mkdir(mode=0o700)
        os.chown(home, 1000, 1000)
        return home

    def setup_stage(self, area=None, stage=None, source=None):
        if source is None:
            from recovery_gui.upload_staging import SETUP
            source = SETUP
        return subprocess.run([sys.executable, '-B', '-c', source,
                               str(area or self.area), str(stage or self.stage)],
                              capture_output=True, timeout=20)

    def assert_private_user_directory(self, path):
        info = path.stat()
        self.assertTrue(stat.S_ISDIR(info.st_mode))
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)),
                         (1000, 1000, 0o700))

    def as_user_write(self, stage):
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            result, status = {}, 1
            try:
                os.setgroups([])
                os.setgid(1000)
                os.setuid(1000)
                os.umask(0o077)
                (stage / 'uid1000-canary').write_bytes(b'upload-fixture')
                result = dict(ok=True, uid=os.geteuid(), gid=os.getegid())
                status = 0
            except OSError as error:
                result = dict(ok=False, errno=error.errno)
            finally:
                os.write(write_fd, json.dumps(result).encode())
                os.close(write_fd)
                os._exit(status)
        os.close(write_fd)
        try:
            raw = os.read(read_fd, 4096)
        finally:
            os.close(read_fd)
        _, status = os.waitpid(child, 0)
        self.assertTrue(os.WIFEXITED(status), 'UID 1000 child must exit normally')
        return os.WEXITSTATUS(status), json.loads(raw)

    def assert_user_can_upload(self, stage=None):
        stage = stage or self.stage
        self.assertEqual(self.as_user_write(stage), (0, dict(ok=True, uid=1000, gid=1000)))
        marker = stage / 'uid1000-canary'
        self.assertEqual(marker.read_bytes(), b'upload-fixture')
        info = marker.stat()
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)),
                         (1000, 1000, 0o600))

    def snapshot(self):
        result = {}
        for path in [self.outer, *sorted(self.outer.rglob('*'))]:
            info = path.lstat()
            payload = (os.readlink(path) if stat.S_ISLNK(info.st_mode)
                       else path.read_bytes() if stat.S_ISREG(info.st_mode) else None)
            result[str(path.relative_to(self.outer))] = (
                info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_nlink, payload)
        return result

    def assert_refused_unchanged(self, area=None, stage=None):
        before = self.snapshot()
        result = self.setup_stage(area, stage)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout), {'error': 'SSH_UPLOAD_PATH_REFUSED'})
        self.assertEqual(result.stderr, b'')
        self.assertEqual(self.snapshot(), before)

    def make_user_parents(self, area=None):
        area = area or self.area
        for path in (area.parent.parent, area.parent, area):
            path.mkdir(mode=0o700)
            os.chown(path, 1000, 1000)

    def make_legacy_parents(self):
        result = self.setup_stage(source=OLD_SETUP)
        self.assertEqual(result.returncode, 0, result.stderr)
        for parent in (self.area.parent.parent, self.area.parent):
            info = parent.stat()
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)),
                             (0, 0, 0o700))

    def test_old_setup_reproduces_fresh_home_permission_denied(self):
        self.make_legacy_parents()
        status, result = self.as_user_write(self.stage)
        self.assertEqual(status, 1)
        self.assertEqual(result, dict(ok=False, errno=errno.EACCES))
        self.assertFalse((self.stage / 'uid1000-canary').exists())

    def test_fresh_setup_allows_real_user_upload_for_both_roles(self):
        for index, name in enumerate(AREA_NAMES):
            with self.subTest(role=name):
                home = self.make_home('fresh-' + str(index))
                area = home / '.local/share' / name
                stage = area / ('upload-' + 'b' * 32)
                result = self.setup_stage(area, stage)
                self.assertEqual(result.returncode, 0, result.stderr)
                for directory in (area.parent.parent, area.parent, area, stage):
                    self.assert_private_user_directory(directory)
                self.assert_user_can_upload(stage)

    def test_retry_repairs_only_confined_legacy_parents_and_preserves_old_stage(self):
        self.make_legacy_parents()
        old_stage = self.stage
        marker = old_stage / 'preserved'
        marker.write_bytes(b'previous-upload')
        marker.chmod(0o600)
        before = marker.stat()
        self.stage = self.area / ('upload-' + 'c' * 32)
        result = self.setup_stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        for directory in (self.area.parent.parent, self.area.parent, self.area, self.stage):
            self.assert_private_user_directory(directory)
        after = marker.stat()
        self.assertEqual((after.st_ino, after.st_uid, after.st_gid, after.st_mode),
                         (before.st_ino, before.st_uid, before.st_gid, before.st_mode))
        self.assertEqual(marker.read_bytes(), b'previous-upload')
        self.assert_user_can_upload()

    def test_existing_user_parent_modes_and_unrelated_files_are_preserved(self):
        self.make_user_parents()
        self.area.parent.parent.chmod(0o755)
        self.area.parent.chmod(0o750)
        unrelated = self.area.parent.parent / 'user-file'
        unrelated.write_bytes(b'preserved-user-file')
        os.chown(unrelated, 1000, 1000)
        unrelated.chmod(0o640)
        checkpoint = self.area / 'state.json'
        checkpoint.write_bytes(b'preserved-checkpoint')
        checkpoint.chmod(0o600)
        before = self.snapshot()
        result = self.setup_stage()
        self.assertEqual(result.returncode, 0, result.stderr)
        after = self.snapshot()
        for name, info in before.items():
            # Creating a new stage changes its parent's directory link count.
            self.assertEqual(after[name][:4] + after[name][5:], info[:4] + info[5:], name)
        self.assert_user_can_upload()

    def test_unrelated_children_of_either_root_parent_refuse_before_repair(self):
        for index, depth in enumerate((1, 2)):
            with self.subTest(depth=depth):
                self.home = self.make_home('unrelated-' + str(index))
                self.area = self.home / '.local/share' / AREA_NAMES[0]
                self.stage = self.area / ('upload-' + 'd' * 32)
                self.make_legacy_parents()
                parent = self.area.parent if depth == 1 else self.area.parent.parent
                (parent / 'unrelated').write_bytes(b'preserve-root-file')
                self.stage = self.area / ('upload-' + 'e' * 32)
                self.assert_refused_unchanged()

    def test_root_owned_area_is_refused_without_repairing_parents(self):
        self.make_legacy_parents()
        os.chown(self.area, 0, 0)
        self.stage = self.area / ('upload-' + 'f' * 32)
        self.assert_refused_unchanged()

    def test_group_writable_area_is_refused_without_repairing_parents(self):
        self.make_legacy_parents()
        self.area.chmod(0o770)
        self.stage = self.area / ('upload-' + 'f' * 32)
        self.assert_refused_unchanged()

    def test_foreign_owner_or_group_is_refused_without_mutation(self):
        for index, location in enumerate(('home', 'local', 'share', 'area')):
            owners = ((1001, 1000), (1000, 1001)) if location in ('home', 'area') else ((1001, 1000),)
            for uid, gid in owners:
                with self.subTest(location=location, uid=uid, gid=gid):
                    home = self.make_home('foreign-' + str(index) + '-' + str(uid) + '-' + str(gid))
                    area = home / '.local/share' / AREA_NAMES[0]
                    stage = area / ('upload-' + 'a' * 32)
                    self.make_user_parents(area)
                    target = dict(home=home, local=area.parent.parent, share=area.parent, area=area)[location]
                    os.chown(target, uid, gid)
                    self.assert_refused_unchanged(area, stage)

    def test_symlink_parents_area_or_stage_are_refused_without_mutation(self):
        for index, location in enumerate(('local', 'share', 'area', 'stage')):
            with self.subTest(location=location):
                home = self.make_home('symlink-' + str(index))
                area = home / '.local/share' / AREA_NAMES[0]
                stage = area / ('upload-' + 'a' * 32)
                self.make_user_parents(area)
                outside = self.make_home('outside-' + str(index))
                (outside / 'preserved').write_bytes(b'outside-fixture')
                target = dict(local=area.parent.parent, share=area.parent, area=area, stage=stage)[location]
                if target.exists():
                    target.rename(home / 'original')
                target.symlink_to(outside, target_is_directory=True)
                self.assert_refused_unchanged(area, stage)

    def test_existing_stage_and_malformed_stage_names_are_refused(self):
        self.make_user_parents()
        self.stage.mkdir(mode=0o700)
        os.chown(self.stage, 1000, 1000)
        (self.stage / 'preserved').write_bytes(b'existing-stage')
        self.assert_refused_unchanged()
        for name in ('upload-' + 'a' * 31, 'upload-' + 'A' * 32, 'other-' + 'a' * 32):
            with self.subTest(name=name):
                self.assert_refused_unchanged(stage=self.area / name)

    def test_foreign_area_name_and_stage_outside_area_are_refused(self):
        area = self.home / '.local/share/foreign-recovery'
        self.assert_refused_unchanged(area, area / ('upload-' + 'a' * 32))
        self.assert_refused_unchanged(stage=self.home / ('upload-' + 'a' * 32))


if __name__ == '__main__':
    unittest.main()

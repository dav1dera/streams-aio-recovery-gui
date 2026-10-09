"""No real credentials, private identities, databases or GitHub mutations."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("dr", Path(__file__).resolve().parents[1] / "scripts/dr-releases.py")
dr = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dr)
COMMIT = "a" * 40
STANZA = b"-> X25519 " + b"A" * 43 + b"\n" + b"A" * 43 + b"\n"
# Structural fixtures for transport tests, never used as production backups.
ENVELOPE = b"age-encryption.org/v1\n" + STANZA * 2 + b"--- " + b"A" * 43 + b"\n" + b"x" * 64


def make_bundle(base, run="20260930T165153Z", remote=None):
    remote = remote or run
    sources = {}
    for component, names in dr.COMPONENTS.items():
        directory = base / component
        directory.mkdir(parents=True)
        for name in names:
            (directory / name).write_bytes(ENVELOPE)
        (directory / "SHA256SUMS").write_text("".join(f"{dr.digest(directory / n)}  {n}\n" for n in names), encoding="ascii")
        label = "nginx-proxy-manager" if component == "npm" else component
        stamp = remote if component == "infisical" else run
        (directory / "manifest.txt").write_text(f"snapshot={stamp}\ncomponent={label}\nencryption=age\nrecipients=2\n", encoding="ascii")
        sources[component] = directory
    bundle = base / "bundle"
    dr.prepare(run, remote, COMMIT, sources, bundle)
    return bundle


class FakeGitHub:
    def __init__(self):
        self.rows = []
        self.files = {}
        self.tags = {}
        self.calls = []
        self.fail_upload = False
        self.corrupt_download = None
        self.fail_delete = False

    def preflight(self):
        pass

    def releases(self):
        return copy.deepcopy(self.rows)

    def assets(self, release):
        return [{"id": (release["id"], name), "name": name, "state": "uploaded", "size": len(data)}
                for name, data in self.files[release["id"]].items()]

    def download(self, asset, destination):
        data = self.files[asset["id"][0]][asset["name"]]
        if self.corrupt_download == asset["name"]:
            data = data[:-1] + b"!"
        destination.write_bytes(data)

    def tag_commit(self, tag):
        return self.tags[tag]

    def api(self, endpoint):
        if endpoint.startswith("git/commits/"):
            return {"sha": endpoint.rsplit("/", 1)[1]}
        if endpoint.startswith("git/matching-refs/tags/"):
            prefix = endpoint.rsplit("/", 1)[1]
            return [{"ref": f"refs/tags/{tag}", "object": {"type": "commit", "sha": sha}}
                    for tag, sha in self.tags.items() if tag.startswith(prefix)]
        return copy.deepcopy(next(r for r in self.rows if r["id"] == int(endpoint.rsplit("/", 1)[1])))

    def call(self, args):
        self.calls.append(args)
        operation, tag = args[1:3]
        if operation == "create":
            row = {"id": len(self.files) + 1, "tag_name": tag, "name": args[args.index("--title") + 1],
                   "body": Path(args[args.index("--notes-file") + 1]).read_text(), "draft": True,
                   "prerelease": False, "target_commitish": args[args.index("--target") + 1]}
            self.rows.append(row)
            self.files[row["id"]] = {}
            return
        row = next(r for r in self.rows if r["tag_name"] == tag)
        if operation == "upload":
            files = args[3:args.index("--repo")]
            for index, path in enumerate(files):
                if self.fail_upload and index == 1:
                    raise dr.Failure("simulated upload failure")
                self.files[row["id"]][Path(path).name] = Path(path).read_bytes()
        elif operation == "edit":
            row["draft"] = False
            self.tags[tag] = row["target_commitish"]
        elif operation == "delete":
            if self.fail_delete:
                raise dr.Failure("simulated delete failure")
            self.rows.remove(row)
            self.tags.pop(tag)
        else:
            raise AssertionError(operation)

    def seed(self, bundle):
        manifest = dr.bundle_check(bundle)
        tag = f"dr-{manifest['run']}"
        row = {"id": len(self.files) + 1, "tag_name": tag, "name": f"DR {manifest['run']}",
               "body": dr.MARKER, "draft": False, "prerelease": False, "target_commitish": COMMIT}
        self.rows.append(row)
        self.files[row["id"]] = {name: (bundle / name).read_bytes() for name in dr.BUNDLE_FILES}
        self.tags[tag] = COMMIT


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.github = FakeGitHub()

    def tearDown(self):
        self.temporary.cleanup()

    def test_publish_readback_and_idempotent_retry(self):
        bundle = make_bundle(self.base, remote="20260930T165155Z")
        dr.publish(self.github, bundle)
        self.assertFalse(self.github.rows[0]["draft"])
        self.assertTrue((bundle.parent / "published.json").exists())
        calls = len(self.github.calls)
        dr.publish(self.github, bundle)
        self.assertEqual(calls, len(self.github.calls))
        self.assertEqual(dr.bundle_check(bundle)["infisical_snapshot"], "20260930T165155Z")

    def test_new_draft_visibility_lag_retries_reads_without_duplicate_creation(self):
        bundle = make_bundle(self.base)
        normal_call = self.github.call
        normal_releases = self.github.releases
        hidden = [0]
        def call(args):
            result = normal_call(args)
            if args[1] == "create":
                hidden[0] = 3
            return result
        def releases():
            if hidden[0]:
                hidden[0] -= 1
                return []
            return normal_releases()
        self.github.call = call
        self.github.releases = releases
        with mock.patch.object(dr.time, "sleep") as sleep:
            dr.publish(self.github, bundle)
            self.assertEqual(sleep.call_count, 3)
        self.assertEqual(sum(args[1] == "create" for args in self.github.calls), 1)
        self.assertEqual(len(self.github.rows), 1)
        self.assertFalse(self.github.rows[0]["draft"])

    def test_unconfirmed_draft_stops_without_upload_or_second_creation(self):
        bundle = make_bundle(self.base)
        self.github.releases = lambda: []
        with mock.patch.object(dr.time, "sleep") as sleep:
            with self.assertRaises(dr.Failure):
                dr.publish(self.github, bundle)
            self.assertEqual(sleep.call_count, 4)
            with self.assertRaises(dr.Failure):
                dr.publish(self.github, bundle)
        self.assertEqual(sum(args[1] == "create" for args in self.github.calls), 1)
        self.assertFalse(any(args[1] in ("upload", "edit", "delete") for args in self.github.calls))
        self.assertFalse((bundle.parent / "published.json").exists())

    def test_lost_creation_response_is_recovered_without_replaying_write(self):
        bundle = make_bundle(self.base)
        normal_call = self.github.call
        def call(args):
            result = normal_call(args)
            if args[1] == "create":
                raise dr.Failure("simulated lost write response")
            return result
        self.github.call = call
        with self.assertRaises(dr.Failure):
            dr.publish(self.github, bundle)
        self.github.call = normal_call
        dr.publish(self.github, bundle)
        self.assertEqual(sum(args[1] == "create" for args in self.github.calls), 1)

    def test_publication_visibility_lag_cannot_bypass_retention(self):
        bundle = make_bundle(self.base)
        normal_call = self.github.call
        normal_releases = self.github.releases
        stale = [0]
        def call(args):
            result = normal_call(args)
            if args[1] == "edit":
                stale[0] = 2
            return result
        def releases():
            rows = normal_releases()
            if stale[0]:
                stale[0] -= 1
                for row in rows:
                    row["draft"] = True
            return rows
        self.github.call = call
        self.github.releases = releases
        with mock.patch.object(dr.time, "sleep") as sleep:
            dr.publish(self.github, bundle)
            self.assertEqual(sleep.call_count, 2)
        self.assertTrue((bundle.parent / "published.json").exists())

    def test_asset_listing_lag_retries_before_publication(self):
        bundle = make_bundle(self.base)
        normal_call = self.github.call
        normal_assets = self.github.assets
        stale = [0]
        def call(args):
            result = normal_call(args)
            if args[1] == "upload":
                stale[0] = 2
            return result
        def assets(release):
            if stale[0]:
                stale[0] -= 1
                return []
            return normal_assets(release)
        self.github.call = call
        self.github.assets = assets
        with mock.patch.object(dr.time, "sleep") as sleep:
            dr.publish(self.github, bundle)
            self.assertEqual(sleep.call_count, 2)
        self.assertEqual(sum(args[1] == "upload" for args in self.github.calls), 1)

    def test_interrupted_upload_stays_draft_and_resumes(self):
        bundle = make_bundle(self.base)
        self.github.fail_upload = True
        with self.assertRaises(dr.Failure):
            dr.publish(self.github, bundle)
        self.assertTrue(self.github.rows[0]["draft"])
        self.assertFalse((bundle.parent / "published.json").exists())
        self.assertTrue(all((bundle / name).exists() for name in dr.BUNDLE_FILES))
        self.github.fail_upload = False
        dr.publish(self.github, bundle)
        self.assertEqual(len(self.github.rows), 1)

    def test_corrupt_download_prevents_publish_and_pruning(self):
        bundle = make_bundle(self.base)
        self.github.corrupt_download = sorted(dr.ASSETS)[0]
        with self.assertRaises(dr.Failure):
            dr.publish(self.github, bundle)
        self.assertTrue(self.github.rows[0]["draft"])
        self.assertFalse(any(c[1] == "delete" for c in self.github.calls))
        self.assertFalse((bundle.parent / "published.json").exists())

    def test_rotation_keeps_five_and_preserves_unrelated_releases(self):
        for number in range(1, 7):
            self.github.seed(make_bundle(self.base / str(number), f"202609{number:02}T040000Z"))
        unrelated = {"id": 99, "tag_name": "dr-20260901T010000Z", "name": "manual", "body": "manual", "draft": False}
        self.github.rows.append(unrelated)
        dr.prune(self.github)
        self.assertEqual(len(self.github.rows), 6)
        self.assertIn(unrelated, self.github.rows)
        self.assertNotIn("dr-20260901T040000Z", self.github.tags)
        self.assertEqual(len(self.github.tags), 5)
        self.assertIn("--cleanup-tag", self.github.calls[-1])

    def test_bad_retained_backup_prevents_any_deletion(self):
        for number in range(1, 7):
            self.github.seed(make_bundle(self.base / str(number), f"202609{number:02}T040000Z"))
        self.github.corrupt_download = "manifest.json"
        with self.assertRaises((dr.Failure, ValueError)):
            dr.prune(self.github)
        self.assertEqual(len(self.github.rows), 6)
        self.assertFalse(self.github.calls)

    def test_retention_failure_prevents_cleanup_receipt(self):
        for number in range(1, 6):
            self.github.seed(make_bundle(self.base / str(number), f"202609{number:02}T040000Z"))
        bundle = make_bundle(self.base / "current")
        self.github.fail_delete = True
        with self.assertRaises(dr.Failure):
            dr.publish(self.github, bundle)
        self.assertFalse((bundle.parent / "published.json").exists())
        self.github.fail_delete = False
        dr.publish(self.github, bundle)
        self.assertEqual(len(self.github.rows), 5)

    def test_existing_tag_collision_does_not_upload(self):
        bundle = make_bundle(self.base)
        self.github.tags["dr-20260930T165153Z"] = "b" * 40
        with self.assertRaises(dr.Failure):
            dr.publish(self.github, bundle)
        self.assertFalse(self.github.calls)

    def test_renamed_plaintext_and_single_recipient_are_rejected(self):
        path = self.base / "plaintext.age"
        for data in (b"password=test-only", b"age-encryption.org/v1\n" + STANZA + b"--- " + b"A" * 43 + b"\n" + b"x" * 64):
            path.write_bytes(data)
            with self.assertRaises(dr.Failure):
                dr.age_check(path)

    def test_checksum_traversal_duplicate_and_missing_are_rejected(self):
        bundle = make_bundle(self.base)
        sums = bundle / "SHA256SUMS"
        original = sums.read_text()
        for text in (original + original.splitlines()[0] + "\n", original.replace("manifest.json", "../manifest.json"),
                     "\n".join(original.splitlines()[1:]) + "\n"):
            sums.write_text(text)
            with self.assertRaises(dr.Failure):
                dr.bundle_check(bundle)

    def test_plaintext_sidecar_and_private_identity_are_rejected(self):
        bundle = make_bundle(self.base)
        directory = self.base / "npm"
        (directory / "secrets.env").write_text("test-only")
        with self.assertRaises(dr.Failure):
            dr.component_check("npm", directory, "20260930T165153Z")
        (directory / "secrets.env").unlink()
        (directory / "manifest.txt").write_bytes(b"AGE-SE" + b"CRET-KEY-" + b"TEST-ONLY")
        with self.assertRaises(dr.Failure):
            dr.component_check("npm", directory, "20260930T165153Z")
        self.assertTrue(bundle.exists())

    def test_unknown_metadata_is_not_uploaded(self):
        make_bundle(self.base)
        manifest = self.base / "npm/manifest.txt"
        with manifest.open("a") as stream:
            stream.write("api_token=test-only\n")
        with self.assertRaises(dr.Failure):
            dr.component_check("npm", manifest.parent, "20260930T165153Z")

    def test_state_inside_git_and_invalid_date_are_rejected(self):
        with self.assertRaises(dr.Failure):
            dr.state_check(self.base / "repo/state", self.base / "repo")
        for value in ("20260230T165153Z", "../../outside", "20260930T165153Z\n"):
            with self.assertRaises(dr.Failure):
                dr.snapshot(value)

    def test_gh_pagination_and_errors_never_print_stderr(self):
        with mock.patch.object(dr.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b'[{"id":1}]\n[{"id":2}]\n', b"")) as run:
            self.assertEqual(dr.GitHub().releases(), [{"id": 1}, {"id": 2}])
            self.assertIn("--paginate", run.call_args.args[0])
            self.assertNotIn("--slurp", run.call_args.args[0])
        secret = b"FAKE-CREDENTIAL-MUST-NOT-APPEAR"
        with mock.patch.object(dr.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", secret)):
            with self.assertRaises(dr.Failure) as error:
                dr.GitHub().preflight()
            self.assertNotIn(secret.decode(), str(error.exception))

    def test_pagination_accepts_empty_pages_and_all_whitespace_formats(self):
        for data in (b'[{"id":1}][{"id":2}]', b' \n[{"id":1}]\r\n[]\n[{"id":2}] \n'):
            with mock.patch.object(dr.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, data, b"")):
                self.assertEqual(dr.GitHub().releases(), [{"id": 1}, {"id": 2}])
        with mock.patch.object(dr.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b'[]\n', b"")):
            self.assertEqual(dr.GitHub().releases(), [])

    def test_pagination_rejects_missing_malformed_and_unexpected_pages(self):
        for data in (b'', b' \n', b'{"id":1}', b'[]\n[{"id":', b'[[]]', b'[] unexpected'):
            with mock.patch.object(dr.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, data, b"")):
                with self.assertRaises((dr.Failure, ValueError)):
                    dr.GitHub().releases()

    def test_migration_imports_only_complete_sets_from_history(self):
        repo = self.base / "legacy"
        repo.mkdir()
        for number in (1, 2):
            run = f"202609{number:02}T040000Z"
            make_bundle(self.base / f"source-{number}", run)
            for component in dr.COMPONENTS:
                shutil.copytree(self.base / f"source-{number}" / component, repo / "encrypted" / component / run)
        shutil.copytree(self.base / "source-1/npm", repo / "encrypted/npm/20260903T040000Z")
        aio = repo / "encrypted/aiostreams/export.age"
        aio.parent.mkdir()
        aio.write_bytes(b"UNTOUCHED-TEST-ONLY")
        subprocess.run(["git", "init", "--quiet", str(repo)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=DR Test", "-c", "user.email=dr-test@example.invalid",
                        "commit", "--quiet", "-m", "Isolated historical fixtures"], check=True, capture_output=True)
        source = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
        with mock.patch.object(dr, "GitHub", return_value=self.github):
            dr.migrate(repo, self.base / "state", source)
            dr.migrate(repo, self.base / "state", source)
        self.assertEqual(len(self.github.rows), 2)
        self.assertEqual({r["target_commitish"] for r in self.github.rows}, {source})
        self.assertEqual(aio.read_bytes(), b"UNTOUCHED-TEST-ONLY")
        self.assertTrue((repo / "encrypted/npm/20260903T040000Z").exists())

    def test_cleanup_requires_receipt_and_matching_originals(self):
        repo = self.base / "repo"
        state = self.base / "state"
        repo.mkdir()
        run = "20260930T165153Z"
        bundle = make_bundle(state / "runs" / run, run)
        state.chmod(0o700)
        for component in ("npm", "infisical-agent"):
            shutil.copytree(bundle.parent / component, repo / "encrypted" / component / run)
        with self.assertRaises(dr.Failure):
            dr.cleanup_local(repo, state, run)
        dr.publish(self.github, bundle)
        path = repo / "encrypted/npm" / run / "database.sqlite.age"
        path.write_bytes(ENVELOPE + b"changed")
        directory = path.parent
        (directory / "SHA256SUMS").write_text(f"{dr.digest(path)}  database.sqlite.age\n", encoding="ascii")
        with self.assertRaises(dr.Failure):
            dr.cleanup_local(repo, state, run)
        self.assertTrue(path.exists())
        path.write_bytes(ENVELOPE)
        (directory / "SHA256SUMS").write_text(f"{dr.digest(path)}  database.sqlite.age\n", encoding="ascii")
        dr.cleanup_local(repo, state, run)
        self.assertFalse(path.exists())

    @unittest.skipIf(os.name == "nt", "symlink creation requires privileges on Windows; exercised in Linux CI")
    def test_symlink_artifact_and_parent_are_rejected(self):
        bundle = make_bundle(self.base)
        alias = self.base / "alias"
        alias.symlink_to(bundle, target_is_directory=True)
        with self.assertRaises(dr.Failure):
            dr.bundle_check(alias)
        name = sorted(dr.ASSETS)[0]
        (bundle / name).unlink()
        (bundle / name).symlink_to(self.base / "npm/database.sqlite.age")
        with self.assertRaises(dr.Failure):
            dr.bundle_check(bundle)


if __name__ == "__main__":
    with contextlib.redirect_stdout(io.StringIO()):
        unittest.main()

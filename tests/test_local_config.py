"""Synthetic contract tests; never read VM files or personal configuration."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import importlib.util

spec = importlib.util.spec_from_file_location(
    'recovery_local_config_test', Path(__file__).resolve().parents[1] / 'remote/local_config.py')
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class LocalConfigurationContract(unittest.TestCase):
    def setUp(self):
        self.area = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.addCleanup(self.area.cleanup)
        self.root = Path(self.area.name)
        self.approved = {"/stack-network/DEFAULT_SUBNET", "/aiostreams/PORT"}
        self.values = {"/stack-network/DEFAULT_SUBNET": "10.55.0.0/24"}
        self.path = self.root / contract.ARCHIVE_RELATIVE_PATH

    def write(self, document=None, raw=None):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(raw if raw is not None else json.dumps(document or {
            "schema": 1, "values": self.values}).encode())
        self.path.chmod(0o600)

    def test_old_archive_without_map_returns_empty_mapping(self):
        self.assertEqual(contract.load_local_config(self.root, self.approved), {})

    def test_exact_canonical_file_loads_only_approved_values(self):
        self.write()
        self.assertEqual(contract.load_local_config(self.root, self.approved), self.values)

    def test_unapproved_credential_name_is_refused_without_disclosure(self):
        self.write({"schema": 1, "values": {"/shared/DB_PASSWORD": "canary-password"}})
        with self.assertRaises(contract.ConfigRefused) as failure:
            contract.load_local_config(self.root, self.approved)
        self.assertEqual(str(failure.exception), "LOCAL_CONFIG_REFERENCE_NOT_APPROVED")
        self.assertNotIn("canary", str(failure.exception))
        self.assertNotIn("PASSWORD", str(failure.exception))

    def test_schema_requires_exact_keys_and_integer_version(self):
        for document in ({"schema": True, "values": {}}, {"schema": 2, "values": {}},
                         {"schema": 1, "values": {}, "path": "outside"},
                         {"schema": 1, "values": []}):
            with self.subTest(document=document), self.assertRaises(contract.ConfigRefused):
                contract.validate_document(document, self.approved)

    def test_malformed_references_are_refused_even_if_caller_approves_them(self):
        for ref in ("stack-network/KEY", "/../KEY", "/folder/lowercase", "/folder//KEY",
                    "/folder/KEY/", "/folder/KEY\\OTHER", "/folder/KEY\0"):
            with self.subTest(ref=ref), self.assertRaises(contract.ConfigRefused):
                contract.validate_document({"schema": 1, "values": {ref: "ordinary"}}, {ref})

    def test_duplicate_json_keys_and_invalid_json_are_refused(self):
        for raw in (b'{"schema":1,"schema":1,"values":{}}',
                    b'{"schema":1,"values":{"/aiostreams/PORT":"1","/aiostreams/PORT":"2"}}',
                    b'not json', b'\xff'):
            self.write(raw=raw)
            with self.subTest(raw=raw), self.assertRaises(contract.ConfigRefused):
                contract.load_local_config(self.root, self.approved)

    def test_string_count_and_total_size_limits(self):
        for value in (123, None, "has\0nul", "x" * (contract.MAX_VALUE_BYTES + 1), "\ud800"):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(contract.ConfigRefused):
                contract.validate_document({"schema": 1, "values": {"/aiostreams/PORT": value}}, self.approved)
        with patch.object(contract, "MAX_VALUES", 1), self.assertRaises(contract.ConfigRefused):
            contract.validate_document({"schema": 1, "values": {}}, self.approved)
        with patch.object(contract, "MAX_BYTES", 8), self.assertRaises(contract.ConfigRefused):
            contract.validate_document({"schema": 1, "values": self.values}, self.approved)

    def test_file_size_limit_before_parsing(self):
        self.write(raw=b"x" * (contract.MAX_BYTES + 1))
        with self.assertRaisesRegex(contract.ConfigRefused, "^LOCAL_CONFIG_FILE_INVALID$"):
            contract.load_local_config(self.root, self.approved)

    def test_duplicate_basename_is_not_a_fallback(self):
        self.write()
        other = self.root / "elsewhere" / self.path.name
        other.parent.mkdir()
        other.write_text("{}")
        with self.assertRaisesRegex(contract.ConfigRefused, "^LOCAL_CONFIG_NOT_UNIQUE$"):
            contract.load_local_config(self.root, self.approved)

    def test_noncanonical_file_without_canonical_file_is_refused(self):
        (self.root / self.path.name).write_text("{}")
        with self.assertRaisesRegex(contract.ConfigRefused, "^LOCAL_CONFIG_NOT_UNIQUE$"):
            contract.load_local_config(self.root, self.approved)

    @unittest.skipIf(os.name == "nt", "Linux mode contract")
    def test_linux_file_permissions_and_hardlinks_are_refused(self):
        self.write()
        self.path.chmod(0o644)
        with self.assertRaisesRegex(contract.ConfigRefused, "^LOCAL_CONFIG_FILE_PERMISSIONS$"):
            contract.load_local_config(self.root, self.approved)
        self.path.chmod(0o600)
        os.link(self.path, self.root / "hardlink")
        with self.assertRaisesRegex(contract.ConfigRefused, "^LOCAL_CONFIG_FILE_INVALID$"):
            contract.load_local_config(self.root, self.approved)

    def test_symlink_is_refused_when_host_allows_creation(self):
        self.write()
        link = self.root / "unexpected-link"
        try:
            link.symlink_to(self.path)
        except OSError:
            self.skipTest("Host does not allow symlink creation")
        with self.assertRaisesRegex(contract.ConfigRefused, "^LOCAL_CONFIG_UNSAFE_PATH$"):
            contract.load_local_config(self.root, self.approved)

    def test_merge_preserves_live_credentials_and_accepts_identical_duplicate(self):
        remote = {"DEFAULT_SUBNET": "10.55.0.0/24", "AUTH_TOKEN": "synthetic-live-token"}
        result = contract.merge_folder_values("/stack-network", remote, self.values, self.approved)
        self.assertEqual(result, remote)
        self.assertIsNot(result, remote)
        self.assertEqual(remote["AUTH_TOKEN"], "synthetic-live-token")

    def test_merge_adds_local_values_only_to_matching_folder(self):
        values = dict(self.values, **{"/aiostreams/PORT": "3000"})
        result = contract.merge_folder_values("/aiostreams", {"TOKEN": "live"}, values, self.approved)
        self.assertEqual(result, {"TOKEN": "live", "PORT": "3000"})

    def test_conflicting_duplicate_stops_without_returning_either_value(self):
        remote = {"DEFAULT_SUBNET": "10.66.0.0/24"}
        with self.assertRaisesRegex(contract.ConfigRefused, "^LOCAL_CONFIG_CONFLICT$"):
            contract.merge_folder_values("/stack-network", remote, self.values, self.approved)
        self.assertEqual(remote, {"DEFAULT_SUBNET": "10.66.0.0/24"})

    def test_only_complete_nondynamic_folders_can_skip_remote_reads(self):
        plan = {"required_values": ["/stack-network/DEFAULT_SUBNET", "/aiostreams/PORT"],
                "service_folder_exports": {".secrets/aiostreams.env": {"path": "/aiostreams"}},
                "additional_input_folders": ["/extra"]}
        local = dict(self.values, **{"/aiostreams/PORT": "3000"})
        self.assertEqual(contract.local_only_folders(plan, local, self.approved), {"/stack-network"})
        plan["required_values"].append("/stack-network/AUTH_TOKEN")
        self.assertEqual(contract.local_only_folders(plan, local, self.approved), set())


if __name__ == "__main__":
    unittest.main()

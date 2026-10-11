"""Candidate ordinary-config contract; no network, rendering or live mutation.

The caller approves complete reference names after classifying their values.
This module never infers that a parameter is ordinary from its name.
"""
import json
import os
from pathlib import Path
import re
import stat


ARCHIVE_RELATIVE_PATH = Path("etc/infisical/local-stack-config.json")
MAX_BYTES = 1024 * 1024
MAX_VALUES = 512
MAX_VALUE_BYTES = 65536
MAX_ARCHIVE_ENTRIES = 4096
_FOLDER = re.compile(r"/(?:[A-Za-z0-9_-]{1,64})(?:/[A-Za-z0-9_-]{1,64}){0,7}\Z")
_KEY = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")


class ConfigRefused(Exception):
    """Errors expose fixed codes, never reference names or values."""


def _need(condition, code="LOCAL_CONFIG_INVALID"):
    if not condition:
        raise ConfigRefused(code)


def _folder(value):
    _need(isinstance(value, str) and _FOLDER.fullmatch(value) is not None)
    return value


def _reference(value):
    _need(isinstance(value, str) and len(value) <= 512 and "/" in value)
    folder, key = value.rsplit("/", 1)
    _folder(folder)
    _need(_KEY.fullmatch(key) is not None)
    return value


def _value(value):
    _need(isinstance(value, str) and "\0" not in value)
    try:
        _need(len(value.encode("utf-8")) <= MAX_VALUE_BYTES)
    except UnicodeError:
        raise ConfigRefused("LOCAL_CONFIG_INVALID") from None
    return value


def _approved(refs):
    _need(isinstance(refs, (set, frozenset, list, tuple)) and len(refs) <= MAX_VALUES,
          "LOCAL_CONFIG_POLICY_INVALID")
    try:
        return {_reference(ref) for ref in refs}
    except ConfigRefused:
        raise ConfigRefused("LOCAL_CONFIG_POLICY_INVALID") from None


def _validated_values(values, approved_refs):
    approved = _approved(approved_refs)
    _need(isinstance(values, dict) and len(values) <= MAX_VALUES)
    result = {}
    for ref, value in values.items():
        _reference(ref)
        _need(ref in approved, "LOCAL_CONFIG_REFERENCE_NOT_APPROVED")
        result[ref] = _value(value)
    try:
        _need(len(json.dumps(result, ensure_ascii=False).encode("utf-8")) <= MAX_BYTES)
    except UnicodeError:
        raise ConfigRefused("LOCAL_CONFIG_INVALID") from None
    return result


def validate_document(document, approved_refs):
    _need(isinstance(document, dict) and set(document) == {"schema", "values"}
          and type(document["schema"]) is int and document["schema"] == 1)
    return _validated_values(document["values"], approved_refs)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, "LOCAL_CONFIG_DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _no_symlinks(path):
    for item in (path, *path.parents):
        _need(not item.is_symlink()
              and not (hasattr(item, "is_junction") and item.is_junction()),
              "LOCAL_CONFIG_UNSAFE_PATH")


def load_local_config(archive_root, approved_refs):
    """Read only the fixed path inside an already validated extracted archive.

    An absent map means the legacy Infisical-only format. Alternative filenames
    and caller-supplied paths are deliberately unsupported.
    """
    _approved(approved_refs)
    root = Path(archive_root).absolute()
    try:
        _no_symlinks(root)
        _need(root.is_dir(), "LOCAL_CONFIG_ARCHIVE_INVALID")
        expected = root / ARCHIVE_RELATIVE_PATH
        count = 0
        for candidate in root.rglob("*"):
            count += 1
            _need(count <= MAX_ARCHIVE_ENTRIES, "LOCAL_CONFIG_ARCHIVE_INVALID")
            _need(not candidate.is_symlink()
                  and not (hasattr(candidate, "is_junction") and candidate.is_junction()),
                  "LOCAL_CONFIG_UNSAFE_PATH")
            if candidate.name == ARCHIVE_RELATIVE_PATH.name:
                _need(candidate == expected, "LOCAL_CONFIG_NOT_UNIQUE")
        _no_symlinks(expected)
        if not expected.exists():
            return {}
        info = expected.lstat()
        _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
              and info.st_size <= MAX_BYTES, "LOCAL_CONFIG_FILE_INVALID")
        if os.name != "nt":
            _need(stat.S_IMODE(info.st_mode) == 0o600, "LOCAL_CONFIG_FILE_PERMISSIONS")
        descriptor = os.open(expected, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_BINARY", 0))
        with os.fdopen(descriptor, "rb") as source:
            opened = os.fstat(source.fileno())
            _need((opened.st_dev, opened.st_ino) == (info.st_dev, info.st_ino)
                  and stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
                  and opened.st_size <= MAX_BYTES, "LOCAL_CONFIG_FILE_CHANGED")
            if os.name != "nt":
                _need(stat.S_IMODE(opened.st_mode) == 0o600, "LOCAL_CONFIG_FILE_PERMISSIONS")
            raw = source.read(MAX_BYTES + 1)
        _need(len(raw) <= MAX_BYTES, "LOCAL_CONFIG_FILE_INVALID")
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        return validate_document(document, approved_refs)
    except ConfigRefused:
        raise
    except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
        raise ConfigRefused("LOCAL_CONFIG_FILE_INVALID") from None


def merge_folder_values(folder, remote_values, local_values, approved_refs):
    """Return a copy with approved local values; never replace a differing key."""
    _folder(folder)
    _need(isinstance(remote_values, dict) and len(remote_values) <= 4096)
    local = _validated_values(local_values, approved_refs)
    result = {}
    for key, value in remote_values.items():
        _need(isinstance(key, str) and _KEY.fullmatch(key) is not None)
        result[key] = _value(value)
    for ref, value in local.items():
        local_folder, key = ref.rsplit("/", 1)
        if local_folder != folder:
            continue
        _need(key not in result or result[key] == value, "LOCAL_CONFIG_CONFLICT")
        result[key] = value
    return result


def local_only_folders(plan, local_values, approved_refs):
    """Folders safe to skip: all required refs local, no dynamic folder export.

    Additional input folders without explicit required refs are never skipped.
    The caller still reads every remaining Infisical folder normally.
    """
    local = _validated_values(local_values, approved_refs)
    _need(isinstance(plan, dict) and isinstance(plan.get("required_values"), list)
          and len(plan["required_values"]) <= 4096, "LOCAL_CONFIG_PLAN_INVALID")
    exports = plan.get("service_folder_exports", {})
    _need(isinstance(exports, dict), "LOCAL_CONFIG_PLAN_INVALID")
    dynamic = set()
    try:
        for row in exports.values():
            _need(isinstance(row, dict) and "path" in row)
            dynamic.add(_folder(row["path"]))
        required = {}
        for ref in plan["required_values"]:
            _reference(ref)
            required.setdefault(ref.rsplit("/", 1)[0], set()).add(ref)
    except ConfigRefused:
        raise ConfigRefused("LOCAL_CONFIG_PLAN_INVALID") from None
    return {folder for folder, refs in required.items()
            if folder not in dynamic and refs <= local.keys()}

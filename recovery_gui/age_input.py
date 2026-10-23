"""Validate a selected identity file or one native age identity held in RAM.

The pasted mode creates no local file. Native age itself verifies the checksum
and recipient match on the destination; this module only normalizes its input.
"""
from pathlib import Path
import re
import unicodedata


MAX_IDENTITY_BYTES = 65536
NATIVE = re.compile(r'AGE-SECRET-KEY-1[A-Z0-9]+\Z')


class AgeInputFailure(ValueError):
    """A fixed public code, never an identity or an operating-system message."""


def _need(value, code):
    if not value:
        raise AgeInputFailure(code)


def validate_pasted_identity(text):
    """Return exactly one canonical native private line, without echoing it."""
    _need(isinstance(text, str), 'AGE_PRIVATE_IDENTITY_REQUIRED')
    try:
        encoded = text.encode('utf-8')
    except UnicodeError:
        raise AgeInputFailure('AGE_IDENTITY_ENCODING_INVALID') from None
    _need(len(encoded) <= MAX_IDENTITY_BYTES, 'AGE_IDENTITY_FILE_INVALID')
    text = text.removeprefix('\ufeff')
    _need(not any(unicodedata.category(character) in ('Cc', 'Cf') and character not in '\r\n'
                  for character in text), 'AGE_PRIVATE_IDENTITY_REQUIRED')
    lines = [line.strip() for line in text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
             if line.strip() and not line.lstrip().startswith('#')]
    _need(not any(line.startswith('age1') for line in lines), 'AGE_PUBLIC_KEY_NOT_IDENTITY')
    _need(len(lines) == 1 and NATIVE.fullmatch(lines[0]), 'AGE_PRIVATE_IDENTITY_REQUIRED')
    return (lines[0] + '\n').encode('ascii')


def validate_identity_input(snapshot):
    """Validate the chosen mode. File mode deliberately keeps existing checks."""
    _need(isinstance(snapshot, dict), 'AGE_IDENTITY_FILE_INVALID')
    mode = snapshot.get('age_identity_mode', 'file')
    _need(mode in ('file', 'paste'), 'AGE_IDENTITY_FILE_INVALID')
    if mode == 'paste':
        validate_pasted_identity(snapshot.get('age_identity_text', ''))
        return None
    value = snapshot.get('age_identity', '')
    _need(isinstance(value, str) and bool(value), 'AGE_IDENTITY_FILE_REQUIRED')
    try:
        path = Path(value)
        _need(path.is_file(), 'AGE_IDENTITY_FILE_REQUIRED')
        _need(not path.is_symlink() and path.stat().st_size <= MAX_IDENTITY_BYTES,
              'AGE_IDENTITY_FILE_INVALID')
    except AgeInputFailure:
        raise
    except (OSError, ValueError, TypeError):
        raise AgeInputFailure('AGE_IDENTITY_FILE_INVALID') from None
    return None

"""Endpoint-scoped SSH trust. Only the application's public key store is written."""
import base64
import hashlib
import os
from pathlib import Path
import tempfile
import threading


_STORE_LOCK = threading.RLock()


def fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


def endpoint(address, port):
    return address if port == 22 else '[' + address + ']:' + str(port)


def _matches(label, peer):
    from paramiko import HostKeys
    return label == peer or label.startswith('|1|') and HostKeys.hash_host(peer, label) == label


def without_peer(keys, peer):
    from paramiko import HostKeys
    result = HostKeys()
    # Rebuild individual aliases: changing one IP must preserve aliases on the
    # same original line, other ports, other algorithms and hashed host entries.
    for label in keys.keys():
        if not _matches(label, peer):
            for kind, key in keys[label].items():
                result.add(label, kind, key)
    return result


def trusted_keys(path, peer):
    from paramiko import HostKeys
    system, local = HostKeys(), HostKeys()
    try:
        system.load(str(Path.home() / '.ssh' / 'known_hosts'))
    except FileNotFoundError:
        pass
    if path.exists():
        local.load(str(path))
    # An identity explicitly verified in this app overrides a stale system
    # entry for this endpoint, without editing the system's known_hosts file.
    result = without_peer(system, peer) if local.lookup(peer) is not None else system
    for label in local.keys():
        for kind, key in local[label].items():
            result.add(label, kind, key)
    return result


def remember(path, peer, key):
    from paramiko import HostKeys
    with _STORE_LOCK:
        if path.is_symlink():
            raise OSError('SSH identity store must be a regular file')
        current = HostKeys()
        if path.exists():
            current.load(str(path))
        updated = without_peer(current, peer)
        updated.add(peer, key.get_name(), key)
        fd, temporary = tempfile.mkstemp(prefix='.known-hosts-', dir=path.parent)
        os.close(fd)
        try:
            os.chmod(temporary, 0o600)
            updated.save(temporary)
            with open(temporary, 'r+b') as stream:
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

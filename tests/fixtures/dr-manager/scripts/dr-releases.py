#!/usr/bin/env python3
"""Publish already encrypted DR assets. No identities, decryption or token printing."""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

REPOSITORY = "dav1dera/streams-aio-dr"
PREFIX = f"repos/{REPOSITORY}"
MARKER = "streams-aio-dr-managed:v1"
KEEP = 5
COMPONENTS = {
    "npm": ("database.sqlite.age",),
    "infisical-agent": ("infisical-agent.tar.gz.age",),
    "infisical": ("config.tar.gz.age", "postgres.dump.age", "postgres-globals.sql.age"),
}
ASSETS = {f"{component}-{name}" for component, names in COMPONENTS.items() for name in names}
BUNDLE_FILES = ASSETS | {"manifest.json", "SHA256SUMS"}
OPTIONAL_COMPONENTS = {"aio": ("state.tar.gz.age",)}
ALL_COMPONENTS = {**COMPONENTS, **OPTIONAL_COMPONENTS}
AIO_ASSET = "aio-state.tar.gz.age"
COMPLETE_ASSETS = ASSETS | {AIO_ASSET}
COMPLETE_BUNDLE_FILES = COMPLETE_ASSETS | {"manifest.json", "SHA256SUMS"}
PRIVATE_MARKERS = (b"AGE-SE" + b"CRET-KEY-", b"-----BEGIN " + b"PRIVATE KEY-----",
                   b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----", b"-----BEGIN RSA " + b"PRIVATE KEY-----")


class Failure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def confirm_read(read, confirmed, message):
    # Only reads are retried. A write is never replayed because a list is stale.
    for delay in (0, 1, 2, 4, 8):
        if delay:
            time.sleep(delay)
        value = read()
        if confirmed(value):
            return value
    raise Failure(message)


def snapshot(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", value), "invalid snapshot ID")
    try:
        dt.datetime.strptime(value, "%Y%m%dT%H%M%SZ")
    except ValueError:
        raise Failure("invalid snapshot date") from None
    return value


def commit_id(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value), "invalid source commit")
    return value


def file_bytes(path, limit=None):
    safe_path(path)
    require(path.is_file() and not path.is_symlink(), "missing or unsafe file")
    if limit is not None:
        require(path.stat().st_size <= limit, "oversized metadata")
    return path.read_bytes()


def scan_private(data):
    require(not any(marker in data for marker in PRIVATE_MARKERS), "private identity detected")


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def safe_path(path):
    require(not any(part.is_symlink() for part in (path, *path.parents)), "symlink in artifact path")


def age_check(path):
    safe_path(path)
    require(path.is_file() and not path.is_symlink(), "unsafe encrypted artifact")
    with path.open("rb") as stream:
        header = stream.read(8192)
        require(header.startswith(b"age-encryption.org/v1\n"), "artifact is not a native age envelope")
        lines = header.split(b"\n")
        require(len(lines) > 5, "truncated age header")
        index, recipients = 1, 0
        # Existing producers encrypt to PRIMARY + RECOVERY X25519 recipients.
        while index < len(lines) and lines[index].startswith(b"-> "):
            stanza = lines[index].split(b" ")
            require(len(stanza) == 3 and stanza[1] == b"X25519" and index + 1 < len(lines), "unexpected age recipient")
            for value in (stanza[2], lines[index + 1]):
                require(re.fullmatch(rb"[A-Za-z0-9+/]{43}", value) is not None, "malformed age stanza")
                require(len(base64.b64decode(value + b"=", validate=True)) == 32, "malformed age recipient")
            recipients += 1
            index += 2
        require(recipients >= 2 and index < len(lines), "PRIMARY and RECOVERY recipients required")
        require(re.fullmatch(rb"--- [A-Za-z0-9+/]{43}", lines[index]) is not None, "malformed age header MAC")
        header_size = sum(len(line) + 1 for line in lines[:index + 1])
        require(path.stat().st_size >= header_size + 32, "truncated age ciphertext")
        scan_private(header)
        tail = header[-128:]
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            scan_private(tail + chunk)
            tail = chunk[-128:]


def exact_files(directory, names):
    safe_path(directory)
    require(directory.is_dir() and not directory.is_symlink(), "unsafe snapshot directory")
    require({entry.name for entry in directory.iterdir()} == set(names), "unexpected or missing snapshot file")
    for name in names:
        require((directory / name).is_file() and not (directory / name).is_symlink(), "unsafe snapshot entry")


def check_sums(directory, names):
    data = file_bytes(directory / "SHA256SUMS", 4096)
    scan_private(data)
    found = {}
    for line in data.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([A-Za-z0-9_.-]+)", line)
        require(match is not None, "unsafe checksum entry")
        value, name = match.groups()
        require(name in names and name not in found, "unexpected or duplicate checksum target")
        found[name] = value
    require(set(found) == set(names), "incomplete checksum coverage")
    for name, value in found.items():
        require(digest(directory / name) == value, "SHA256 mismatch")


def component_check(component, directory, stamp):
    snapshot(stamp)
    names = ALL_COMPONENTS[component]
    exact_files(directory, set(names) | {"SHA256SUMS", "manifest.txt"})
    check_sums(directory, names)
    for name in names:
        age_check(directory / name)
    # Original producer manifests are NEVER uploaded; release metadata is generated.
    data = file_bytes(directory / "manifest.txt", 4096)
    scan_private(data)
    fields = {}
    patterns = {
        "snapshot": re.escape(stamp), "encryption": "age", "recipients": "2",
        "component": {"npm": "nginx-proxy-manager", "infisical-agent": "infisical-agent", "infisical": "infisical",
                      "aio": "aio-native-sqlite"}[component],
        "source": r"[A-Za-z0-9_./-]{1,256}", "backup_method": r"sqlite-online-backup|logical",
        "contains_secret_zero": "yes", "contains_agent_config": "yes", "contains_systemd_unit": "yes",
        "hostname": r"[A-Za-z0-9.-]{1,128}", "infisical_image": r"[A-Za-z0-9_./:@-]{1,256}",
        "postgres_image": r"[A-Za-z0-9_./:@-]{1,256}", "redis_image": r"[A-Za-z0-9_./:@-]{1,256}",
        "redis_backup_required": "no",
        "stack_commit": r"[0-9a-f]{40}",
    }
    for line in data.decode("ascii").splitlines():
        key, sep, value = line.partition("=")
        require(sep and key in patterns and key not in fields, "unexpected producer metadata")
        require(re.fullmatch(patterns[key], value), "invalid producer metadata")
        fields[key] = value
    require({"snapshot", "component", "encryption", "recipients"} <= fields.keys(), "missing producer metadata")
    if component == "aio":
        require(fields.get("backup_method") == "sqlite-online-backup" and "stack_commit" in fields,
                "missing native AIO compatibility binding")
    else:
        require("stack_commit" not in fields, "unexpected producer metadata")
    return fields


def prepare(run, remote_snapshot, commit, sources, bundle, stack_commit=None):
    snapshot(run)
    snapshot(remote_snapshot)
    commit_id(commit)
    complete = "aio" in sources
    require(set(sources) == set(COMPONENTS) | ({"aio"} if complete else set()), "unexpected component set")
    require((stack_commit is not None) == complete, "native AIO requires stack commit")
    if complete:
        commit_id(stack_commit)
    for component, directory in sources.items():
        fields = component_check(component, directory, remote_snapshot if component == "infisical" else run)
        if component == "aio":
            require(fields["stack_commit"] == stack_commit, "native AIO stack commit mismatch")
    require(not bundle.exists() and not bundle.is_symlink(), "bundle already exists; use publish to resume")
    bundle.mkdir(parents=True, mode=0o700)
    artifacts = {}
    for component, directory in sources.items():
        for name in ALL_COMPONENTS[component]:
            asset = f"{component}-{name}"
            shutil.copyfile(directory / name, bundle / asset)
            (bundle / asset).chmod(0o600)
            artifacts[asset] = {"sha256": digest(bundle / asset), "size": (bundle / asset).stat().st_size}
    manifest = {"schema": 2 if complete else 1, "managed_by": MARKER, "repository": REPOSITORY,
                "run": run, "local_snapshot": run, "infisical_snapshot": remote_snapshot,
                "source_commit": commit, "encryption": "age", "artifacts": artifacts}
    if complete:
        manifest['stack_commit'] = stack_commit
    (bundle / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="ascii")
    (bundle / "SHA256SUMS").write_text("".join(f"{digest(bundle / name)}  {name}\n" for name in sorted(set(artifacts) | {"manifest.json"})), encoding="ascii")
    return bundle_check(bundle)


def bundle_check(bundle):
    data = file_bytes(bundle / "manifest.json", 8192)
    scan_private(data)
    manifest = json.loads(data)
    require(isinstance(manifest, dict) and type(manifest.get('schema')) is int and manifest['schema'] in (1, 2),
            "invalid release schema")
    complete = manifest['schema'] == 2
    assets = COMPLETE_ASSETS if complete else ASSETS
    exact_files(bundle, assets | {"manifest.json", "SHA256SUMS"})
    check_sums(bundle, assets | {"manifest.json"})
    require(set(manifest) == {"schema", "managed_by", "repository", "run", "local_snapshot",
                             "infisical_snapshot", "source_commit", "encryption", "artifacts"}
            | ({"stack_commit"} if complete else set()), "unexpected release metadata")
    require(manifest["managed_by"] == MARKER
            and manifest["repository"] == REPOSITORY and manifest["encryption"] == "age", "invalid release metadata")
    snapshot(manifest["run"])
    require(snapshot(manifest["local_snapshot"]) == manifest["run"], "local snapshot differs from run ID")
    snapshot(manifest["infisical_snapshot"])
    commit_id(manifest["source_commit"])
    if complete:
        commit_id(manifest['stack_commit'])
    require(set(manifest["artifacts"]) == assets, "incomplete artifact manifest")
    for name, info in manifest["artifacts"].items():
        require(set(info) == {"sha256", "size"}, "unexpected artifact metadata")
        age_check(bundle / name)
        require(info == {"sha256": digest(bundle / name), "size": (bundle / name).stat().st_size}, "artifact manifest mismatch")
    return manifest


class GitHub:
    def call(self, args, output=None):
        env = os.environ.copy()
        env.update(GH_PROMPT_DISABLED="1", GH_HOST="github.com", GIT_TERMINAL_PROMPT="0")
        try:
            result = subprocess.run(["gh", *args], env=env, stdin=subprocess.DEVNULL,
                                    stdout=output if output else subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        except OSError:
            raise Failure("GitHub CLI unavailable") from None
        operation = "api" if args[0] == "api" else "release " + args[1]
        require(result.returncode == 0, f"GitHub {operation} command failed (exit {result.returncode})")
        return result.stdout if output is None else None

    def api(self, endpoint, paginated=False):
        args = ["api", "--hostname", "github.com", "--method", "GET", "--header", "Cache-Control: no-cache",
                f"{PREFIX}/{endpoint}" if endpoint else PREFIX]
        if paginated:
            args.append("--paginate")
        data = self.call(args)
        if not paginated:
            return json.loads(data)
        # gh --paginate emits one JSON document per page. Decode every page here
        # instead of relying on --slurp (unavailable before gh 2.48).
        text = data.decode("utf-8")
        decoder = json.JSONDecoder()
        cursor, pages, items = 0, 0, []
        while cursor < len(text):
            while cursor < len(text) and text[cursor].isspace():
                cursor += 1
            if cursor == len(text):
                break
            page, cursor = decoder.raw_decode(text, cursor)
            require(isinstance(page, list) and all(isinstance(item, dict) for item in page), "invalid paginated response")
            items.extend(page)
            pages += 1
        require(pages > 0, "missing paginated response")
        return items

    def preflight(self):
        repository = self.api("")
        require(repository.get("private") is True and repository.get("full_name") == REPOSITORY
                and repository.get("permissions", {}).get("push") is True, "private repository with write access required")

    def releases(self):
        return self.api("releases?per_page=100", paginated=True)

    def assets(self, release):
        return self.api(f"releases/{int(release['id'])}/assets?per_page=100", paginated=True)

    def download(self, asset, destination):
        require(asset.get("state") == "uploaded" and isinstance(asset.get("size"), int) and asset["size"] > 0,
                "incomplete release asset")
        with destination.open("xb") as stream:
            self.call(["api", "--hostname", "github.com", "--method", "GET", "--header", "Accept: application/octet-stream",
                       f"{PREFIX}/releases/assets/{int(asset['id'])}"], output=stream)
        require(destination.stat().st_size == asset["size"], "download size mismatch")

    def tag_commit(self, tag):
        ref = self.api(f"git/ref/tags/{tag}")
        obj = ref["object"]
        require(obj["type"] == "commit", "DR tag must point directly to its source commit")
        return commit_id(obj["sha"])


def managed(release):
    tag = release.get("tag_name", "")
    return (re.fullmatch(r"dr-[0-9]{8}T[0-9]{6}Z", tag) is not None
            and release.get("name") == f"DR {tag[3:]}"
            and (release.get("body") or "").splitlines()[:1] == [MARKER])


def download_verified(github, release, expected=None, wait_for_assets=False):
    require(managed(release) and release.get("prerelease") is False, "unmanaged or invalid DR release")
    expected_files = (set(bundle_check(expected)['artifacts']) | {"manifest.json", "SHA256SUMS"}
                      if expected is not None else None)
    def complete_assets(value):
        names = {asset['name'] for asset in value}
        return names == expected_files if expected_files is not None else names in (BUNDLE_FILES, COMPLETE_BUNDLE_FILES)
    def read_assets():
        result = github.assets(release)
        require(len({a["name"] for a in result}) == len(result)
                and all(a["name"] in COMPLETE_BUNDLE_FILES and a.get("state") == "uploaded" for a in result),
                "unexpected or incomplete release asset")
        return result
    assets = (confirm_read(read_assets, complete_assets, "uploaded assets not confirmed")
              if wait_for_assets else read_assets())
    require(complete_assets(assets),
            "unexpected or missing release asset")
    with tempfile.TemporaryDirectory(prefix="streams-aio-dr-verify-") as temporary:
        directory = Path(temporary)
        for asset in assets:
            github.download(asset, directory / asset["name"])
        manifest = bundle_check(directory)
        require(release["tag_name"] == f"dr-{manifest['run']}", "release snapshot mismatch")
        if expected is not None:
            for name in expected_files:
                require(digest(directory / name) == digest(expected / name), "uploaded asset differs from local copy")
        if not release["draft"]:
            require(github.tag_commit(release["tag_name"]) == manifest["source_commit"], "source tag mismatch")
        return manifest


def prune(github, published_tag=None):
    def published_releases():
        return [r for r in github.releases() if managed(r) and not r["draft"]]
    releases = (confirm_read(published_releases, lambda rows: any(r["tag_name"] == published_tag for r in rows),
                             "new published release not visible to retention")
                if published_tag else published_releases())
    require(len({r["tag_name"] for r in releases}) == len(releases), "duplicate DR release")
    releases.sort(key=lambda r: snapshot(r["tag_name"][3:]), reverse=True)
    # Validate EVERY retained recovery point before any destructive API call.
    for release in releases[:KEEP]:
        download_verified(github, release)
    for release in releases[KEEP:]:
        download_verified(github, release)
        github.call(["release", "delete", release["tag_name"], "--repo", REPOSITORY, "--yes", "--cleanup-tag"])
        print(f"DR_RELEASE_PRUNED {release['tag_name']}")
    deleted_tags = {r["tag_name"] for r in releases[KEEP:]}
    remaining = confirm_read(published_releases,
                             lambda rows: len(rows) <= KEEP and not any(r["tag_name"] in deleted_tags for r in rows),
                             "release retention incomplete")
    print(f"RETENTION PASS keep={KEEP}")


def publish(github, bundle):
    manifest = bundle_check(bundle)
    bundle_files = set(manifest['artifacts']) | {'manifest.json', 'SHA256SUMS'}
    github.preflight()
    tag = f"dr-{manifest['run']}"
    require(github.api(f"git/commits/{manifest['source_commit']}").get("sha") == manifest["source_commit"], "source commit unavailable")
    def find_release():
        rows = [r for r in github.releases() if r["tag_name"] == tag]
        require(len(rows) <= 1, "duplicate release tag")
        return rows
    creation_record = bundle.parent / "draft-requested.json"
    creation_intent = {"tag": tag, "manifest_sha256": digest(bundle / "manifest.json")}
    if creation_record.exists() or creation_record.is_symlink():
        require(json.loads(file_bytes(creation_record, 4096)) == creation_intent, "draft creation record mismatch")
    matches = find_release()
    if not matches:
        refs = github.api(f"git/matching-refs/tags/{tag}")
        require(not any(ref.get("ref") == f"refs/tags/{tag}" for ref in refs), "existing tag collision")
        if not creation_record.exists():
            # Persist intent before the write. If the API commits but the response
            # is lost, resuming can only rediscover this draft, never create twice.
            safe_path(creation_record)
            with creation_record.open("x", encoding="ascii") as record:
                record.write(json.dumps(creation_intent) + "\n")
            with tempfile.TemporaryDirectory(prefix="streams-aio-dr-notes-") as temporary:
                notes = Path(temporary) / "notes.txt"
                notes.write_text(f"{MARKER}\nEncrypted DR backup. SHA256 read-back required. Retention: {KEEP}.\n", encoding="ascii")
                github.call(["release", "create", tag, "--repo", REPOSITORY, "--target", manifest["source_commit"],
                             "--draft", "--latest=false", "--title", f"DR {manifest['run']}", "--notes-file", str(notes)])
        matches = confirm_read(find_release, lambda rows: len(rows) == 1, "draft creation unconfirmed")
    release = matches[0]
    require(managed(release) and release.get("prerelease") is False, "release tag collision")
    if release["draft"]:
        require(release.get("target_commitish") == manifest["source_commit"], "draft source commit mismatch")
        assets = github.assets(release)
        require(len({a["name"] for a in assets}) == len(assets) and all(a["name"] in bundle_files for a in assets),
                "unexpected draft asset")
        with tempfile.TemporaryDirectory(prefix="streams-aio-dr-resume-") as temporary:
            for asset in assets:
                destination = Path(temporary) / asset["name"]
                github.download(asset, destination)
                require(digest(destination) == digest(bundle / asset["name"]), "draft asset mismatch; refusing overwrite")
        missing = sorted(bundle_files - {a["name"] for a in assets})
        if missing:
            github.call(["release", "upload", tag, *(str(bundle / name) for name in missing), "--repo", REPOSITORY])
        release = github.api(f"releases/{int(release['id'])}")
        download_verified(github, release, bundle, wait_for_assets=True)
        refs = github.api(f"git/matching-refs/tags/{tag}")
        for ref in refs:
            if ref.get("ref") == f"refs/tags/{tag}":
                require(ref.get("object", {}).get("type") == "commit"
                        and ref["object"].get("sha") == manifest["source_commit"],
                        "draft tag collision")
        github.call(["release", "edit", tag, "--repo", REPOSITORY, "--draft=false", "--latest=false"])
    release_id = int(release["id"])
    release = confirm_read(lambda: github.api(f"releases/{release_id}"),
                           lambda value: value.get("draft") is False, "publication unconfirmed")
    download_verified(github, release, bundle)
    print(f"RELEASE_UPLOAD_VERIFY PASS tag={tag}")
    prune(github, published_tag=tag)
    receipt = {"tag": tag, "manifest_sha256": digest(bundle / "manifest.json")}
    (bundle.parent / "published.json").write_text(json.dumps(receipt) + "\n", encoding="ascii")


def state_check(state, repo):
    safe_path(state)
    safe_path(state / "runs")
    safe_path(state / "migration")
    require(state.is_absolute(), "state directory must be absolute")
    require(not state.is_symlink(), "state directory cannot be a symlink")
    require(not state.resolve().is_relative_to(repo.resolve()), "state directory must be outside Git")
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        require(state.stat().st_uid == os.getuid() and state.stat().st_mode & 0o077 == 0,
                "state directory must be owned by the service user with mode 700")


def repository_check(repo):
    result = subprocess.run(["git", "-C", str(repo), "ls-files", "-z"], capture_output=True, check=True)
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        relative = Path(os.fsdecode(raw))
        path = repo / relative
        require(not path.is_symlink(), "symlink tracked in repository")
        if path.is_file():
            with path.open("rb") as stream:
                tail = b""
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    scan_private(tail + chunk)
                    tail = chunk[-128:]
        require(not (relative.parts[0] == "encrypted" and len(relative.parts) > 1
                     and relative.parts[1] in ALL_COMPONENTS and path.suffix == ".age"), "DR binaries still tracked; migrate before enabling")
    encrypted = repo / "encrypted"
    if encrypted.exists():
        safe_path(encrypted)
        for path in encrypted.rglob("*"):
            require(not path.is_symlink(), "unsafe encrypted tree")
            if path.is_file():
                require(path.suffix == ".age" or path.name in {"SHA256SUMS", "manifest.txt"}, "plaintext in encrypted tree")
                if path.suffix == ".age":
                    age_check(path)
                else:
                    scan_private(file_bytes(path, 8192))


def cleanup_local(repo, state, run):
    snapshot(run)
    state_check(state, repo)
    run_dir = state / "runs" / run
    bundle = run_dir / "bundle"
    manifest = bundle_check(bundle)
    receipt = json.loads(file_bytes(run_dir / "published.json", 4096))
    require(receipt == {"tag": f"dr-{run}", "manifest_sha256": digest(bundle / "manifest.json")}, "verified publication receipt missing")
    targets = [repo / "encrypted" / component / run for component in ("npm", "infisical-agent")]
    targets.append(run_dir)
    for path in targets:
        safe_path(path)
        require(not path.is_symlink() and path.resolve().is_relative_to(repo.resolve() if path != run_dir else state.resolve()),
                "unsafe cleanup target")
    for component, path in zip(("npm", "infisical-agent"), targets[:2]):
        if path.exists():
            component_check(component, path, run)
            for name in COMPONENTS[component]:
                require(digest(path / name) == digest(bundle / f"{component}-{name}"), "local backup changed after publication")
    aio = run_dir / 'aio'
    if aio.exists() or aio.is_symlink():
        require(manifest['schema'] == 2, 'unexpected native AIO copy; preserving local data')
        fields = component_check('aio', aio, run)
        require(fields['stack_commit'] == manifest['stack_commit']
                and digest(aio / 'state.tar.gz.age') == digest(bundle / AIO_ASSET),
                'native AIO backup changed after publication')
    for path in targets:
        if path.exists():
            shutil.rmtree(path)
    print("LOCAL_TEMP_CLEANUP PASS")


def migrate(repo, state, source):
    commit_id(source)
    state_check(state, repo)
    github = GitHub()
    github.preflight()
    tree = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "--name-only", source],
                          capture_output=True, check=True).stdout.decode("ascii").splitlines()
    paths = set(tree)
    snapshots = sorted({path.split("/")[2] for path in paths
                        if path.startswith("encrypted/npm/") and len(path.split("/")) == 4}, reverse=True)
    complete = []
    for run in snapshots:
        snapshot(run)
        needed = {f"encrypted/{component}/{run}/{name}" for component, names in COMPONENTS.items()
                  for name in (*names, "SHA256SUMS", "manifest.txt")}
        if needed <= paths:
            complete.append(run)
    require(bool(complete), "no complete legacy snapshot sets; history preserved")
    # Import newest sets first; at most five complete historical recovery points.
    for run in complete[:KEEP]:
        destination = state / "migration" / run
        require(not destination.is_symlink(), "unsafe migration directory")
        sources = {}
        for component, names in COMPONENTS.items():
            directory = destination / component
            require(not directory.is_symlink(), "unsafe migration component")
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            for name in (*names, "SHA256SUMS", "manifest.txt"):
                path = directory / name
                if not path.exists():
                    with path.open("xb") as output:
                        subprocess.run(["git", "-C", str(repo), "show", f"{source}:encrypted/{component}/{run}/{name}"],
                                       stdout=output, stderr=subprocess.DEVNULL, check=True)
            sources[component] = directory
        bundle = destination / "bundle"
        if not bundle.exists():
            prepare(run, run, source, sources, bundle)
        else:
            require(bundle_check(bundle)["source_commit"] == source, "migration source changed")
        publish(github, bundle)
    print(f"MIGRATION PASS complete_sets={min(len(complete), KEEP)}; unmatched legacy files remain in Git history")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("preflight")
    sub.add_parser("prune")
    p = sub.add_parser("state-check")
    p.add_argument("state", type=Path)
    p.add_argument("repo", type=Path)
    p = sub.add_parser("repository-check")
    p.add_argument("repo", type=Path)
    p = sub.add_parser("component-check")
    p.add_argument("component", choices=ALL_COMPONENTS)
    p.add_argument("directory", type=Path)
    p.add_argument("snapshot")
    p = sub.add_parser("prepare")
    for arg in ("run", "remote-snapshot", "commit"):
        p.add_argument(f"--{arg}", required=True)
    for arg in ("npm", "agent", "infisical", "bundle"):
        p.add_argument(f"--{arg}", type=Path, required=True)
    p.add_argument('--aio', type=Path)
    p.add_argument('--stack-commit')
    p = sub.add_parser("publish")
    p.add_argument("bundle", type=Path)
    p = sub.add_parser("remote-snapshot")
    p.add_argument("bundle", type=Path)
    p = sub.add_parser("cleanup-local")
    p.add_argument("repo", type=Path)
    p.add_argument("state", type=Path)
    p.add_argument("run")
    p = sub.add_parser("migrate")
    p.add_argument("repo", type=Path)
    p.add_argument("state", type=Path)
    p.add_argument("source")
    args = parser.parse_args()
    if args.command == "preflight":
        github = GitHub()
        github.preflight()
        require(not any(managed(r) and r["draft"] for r in github.releases()), "recover incomplete DR draft before starting another run")
    elif args.command == "prune":
        github = GitHub()
        github.preflight()
        prune(github)
    elif args.command == "state-check":
        state_check(args.state, args.repo)
    elif args.command == "repository-check":
        repository_check(args.repo)
    elif args.command == "component-check":
        component_check(args.component, args.directory, args.snapshot)
    elif args.command == "prepare":
        sources = {"npm": args.npm, "infisical-agent": args.agent, "infisical": args.infisical}
        if args.aio is not None:
            sources['aio'] = args.aio
        prepare(args.run, args.remote_snapshot, args.commit, sources, args.bundle, stack_commit=args.stack_commit)
    elif args.command == "publish":
        publish(GitHub(), args.bundle)
    elif args.command == "remote-snapshot":
        print(bundle_check(args.bundle)["infisical_snapshot"])
    elif args.command == "cleanup-local":
        cleanup_local(args.repo, args.state, args.run)
    elif args.command == "migrate":
        migrate(args.repo, args.state, args.source)


if __name__ == "__main__":
    try:
        main()
    except Failure as error:
        print(f"DR_RELEASES FAIL: {error}; backup copies preserved", file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("DR_RELEASES FAIL: operation stopped; backup copies preserved", file=sys.stderr)
        sys.exit(1)

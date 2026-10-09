"""Synthetic Docker/containerd save archives, bound to inspected OCI IDs.

The fixture follows Docker29's vendored containerd exporter: original blobs,
a synthetic index.json wrapper, and a host-selected Docker manifest.json row.
No Docker daemon, image download, container, private input or VM is used.
"""
import copy
import gzip
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('oci_archive_policy', ROOT/'remote/runtime_profile.py')
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)

OCI_INDEX = 'application/vnd.oci.image.index.v1+json'
OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
OCI_CONFIG = 'application/vnd.oci.image.config.v1+json'
OCI_LAYER = 'application/vnd.oci.image.layer.v1.tar'
DOCKER_INDEX = 'application/vnd.docker.distribution.manifest.list.v2+json'
DOCKER_MANIFEST = 'application/vnd.docker.distribution.manifest.v2+json'
DOCKER_CONFIG = 'application/vnd.docker.container.image.v1+json'
DOCKER_LAYER = 'application/vnd.docker.image.rootfs.diff.tar'
CODE = '^RUNTIME_PROFILE_IMAGE_ARCHIVE_REFUSED$'
USER = 'nonroot:nonroot'


def encoded(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True).encode()


def packed(rows, duplicate=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for name, raw in list(rows.items()) + ([] if duplicate is None else [duplicate]):
            member = tarfile.TarInfo(name)
            if isinstance(raw, tarfile.TarInfo):
                archive.addfile(raw)
            else:
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
    return stream.getvalue()


def export(nesting=1, compress=False, docker_types=False, foreign=False, referrer=False,
           config_changes=None, layer_rows=None, duplicate_amd64=False, descriptor_change=None):
    rows = {}
    index_type = DOCKER_INDEX if docker_types else OCI_INDEX
    manifest_type = DOCKER_MANIFEST if docker_types else OCI_MANIFEST
    config_type = DOCKER_CONFIG if docker_types else OCI_CONFIG
    layer_type = DOCKER_LAYER if docker_types else OCI_LAYER
    if compress: layer_type += '.gzip' if docker_types else '+gzip'
    layer_rows = layer_rows or [
        {'etc/passwd': b'nonroot:x:0:0::/:/sbin/nologin\n', 'etc/group': b'nonroot:x:0:\n'},
        {'etc/.wh..wh..opq': b'', 'etc/passwd': b'nonroot:x:65532:65532::/:/sbin/nologin\n',
         'etc/group': b'nonroot:x:65532:\n'},
    ]
    diff_raws = [packed(item) for item in layer_rows]
    layer_raws = [gzip.compress(raw, mtime=0) if compress else raw for raw in diff_raws]

    def store(raw, media_type, platform=None):
        digest = 'sha256:' + profile.sha(raw)
        rows['blobs/sha256/'+digest[7:]] = raw
        desc = dict(mediaType=media_type, digest=digest, size=len(raw))
        if platform is not None: desc['platform'] = platform
        return desc

    layers = [store(raw, layer_type) for raw in layer_raws]
    config = dict(os='linux', architecture='amd64', config={'User': USER},
                  rootfs={'type': 'layers', 'diff_ids': ['sha256:'+profile.sha(raw) for raw in diff_raws]})
    if config_changes: config.update(config_changes)
    config_descriptor = store(encoded(config), config_type)
    manifest = dict(schemaVersion=2, mediaType=manifest_type, config=config_descriptor, layers=layers)
    if descriptor_change: descriptor_change(manifest)
    leaf = store(encoded(manifest), manifest_type, {'os': 'linux', 'architecture': 'amd64'})
    target = copy.deepcopy(leaf)
    target.pop('platform')
    for index in range(nesting):
        children = [copy.deepcopy(leaf if index == 0 else target)]
        if index == 0 and foreign:
            children.append(dict(mediaType=manifest_type, digest='sha256:'+'b'*64, size=123,
                                 platform={'os': 'linux', 'architecture': 'arm64'}))
        if index == 0 and duplicate_amd64:
            children.append(copy.deepcopy(leaf))
        target = store(encoded(dict(schemaVersion=2, mediaType=index_type, manifests=children)), index_type)
    wrapper = [target]
    if referrer:
        wrapper.append(dict(mediaType=OCI_MANIFEST, digest='sha256:'+'c'*64, size=234,
                            annotations={'vnd.docker.reference.type':'attestation-manifest'},
                            platform={'os':'unknown','architecture':'unknown'}))
    rows['oci-layout'] = encoded({'imageLayoutVersion':'1.0.0'})
    rows['index.json'] = encoded(dict(schemaVersion=2, mediaType=OCI_INDEX, manifests=wrapper))
    config_name = 'blobs/sha256/'+config_descriptor['digest'][7:]
    names = ['blobs/sha256/'+item['digest'][7:] for item in layers]
    rows['manifest.json'] = encoded([dict(Config=config_name, Layers=names, RepoTags=None)])
    return rows, target['digest'], dict(target=target, leaf=leaf, config=config_descriptor,
                                      layers=layers, config_name=config_name, layer_names=names)


class OCIImageArchive(unittest.TestCase):
    def refused(self, rows, image_id, **kwargs):
        with self.assertRaisesRegex(profile.Refused, CODE):
            profile.image_account(packed(rows), image_id, USER, **kwargs)

    def test_direct_and_nested_index_ids_with_oci_and_docker_types_resolve_verified_accounts(self):
        for nesting in (0,1,2,4):
            for docker_types in (False,True):
                for compress in (False,True):
                    rows, identifier, _ = export(nesting, compress, docker_types)
                    with self.subTest(nesting=nesting, docker_types=docker_types, compress=compress):
                        self.assertEqual(profile.image_account(packed(rows), identifier, USER), (65532,65532))

    def test_absent_unselected_foreign_platform_and_wrapper_referrer_are_allowed(self):
        rows, identifier, _ = export(foreign=True, referrer=True, compress=True)
        self.assertEqual(profile.image_account(packed(rows), identifier, USER), (65532,65532))

    def test_config_id_legacy_route_does_not_require_oci_layout(self):
        rows, _, evidence = export(compress=True)
        rows.pop('oci-layout'); rows.pop('index.json')
        identifier = evidence['config']['digest']
        self.assertEqual(profile.image_account(packed(rows), identifier, USER), (65532,65532))

    def test_modern_id_must_be_unique_in_export_root_wrapper(self):
        rows, identifier, evidence = export()
        self.refused(rows, 'sha256:'+'0'*64)
        wrapper = json.loads(rows['index.json'])
        wrapper['manifests'].append(evidence['target'])
        rows['index.json'] = encoded(wrapper)
        self.refused(rows, identifier)

    def test_missing_or_corrupt_selected_root_manifest_config_or_layer_refuses(self):
        original, identifier, evidence = export()
        names = ['blobs/sha256/'+evidence[key]['digest'][7:] for key in ('target','leaf','config')]
        names += evidence['layer_names']
        for name in names:
            for change in ('missing','corrupt'):
                rows = original.copy()
                if change == 'missing': rows.pop(name)
                else: rows[name] += b'corruption'
                with self.subTest(name=name, change=change): self.refused(rows, identifier)

    def test_root_descriptor_size_and_media_type_must_match_verified_blob(self):
        original, identifier, _ = export()
        for change in ({'size':1}, {'size':True}, {'mediaType':'application/unknown'}):
            rows = original.copy()
            wrapper = json.loads(rows['index.json'])
            wrapper['manifests'][0].update(change)
            rows['index.json'] = encoded(wrapper)
            with self.subTest(change=change): self.refused(rows, identifier)

    def test_duplicate_amd64_candidates_and_excess_descriptor_depth_refuse(self):
        for rows, identifier, _ in (export(duplicate_amd64=True), export(nesting=5)):
            self.refused(rows, identifier)

    def test_direct_and_index_config_must_prove_linux_amd64(self):
        for nesting in (0,1):
            for changes in ({'architecture':'arm64'}, {'os':'windows'}, {'architecture':None}, {'os':None}):
                rows, identifier, _ = export(nesting=nesting, config_changes=changes)
                with self.subTest(nesting=nesting, changes=changes): self.refused(rows, identifier)

    def test_config_path_and_bytes_must_equal_host_selected_docker_manifest_row(self):
        original, identifier, evidence = export()
        rows = original.copy()
        alias = 'synthetic-config-alias.json'
        rows[alias] = rows[evidence['config_name']]
        item = json.loads(rows['manifest.json']); item[0]['Config'] = alias
        rows['manifest.json'] = encoded(item)
        self.refused(rows, identifier)
        rows = original.copy()
        different = json.loads(rows[evidence['config_name']])
        different['created'] = 'synthetic-unlinked-config'
        wrong = encoded(different)
        wrong_name = 'blobs/sha256/'+profile.sha(wrong)
        rows[wrong_name] = wrong
        item = json.loads(rows['manifest.json']); item[0]['Config'] = wrong_name
        rows['manifest.json'] = encoded(item)
        self.refused(rows, identifier)

    def test_layer_paths_and_order_must_match_authenticated_selected_manifest(self):
        original, identifier, evidence = export()
        for names in (list(reversed(evidence['layer_names'])),
                      [evidence['layer_names'][0]]*2,
                      [evidence['layer_names'][0], 'alias-layer.tar']):
            rows = original.copy()
            rows['alias-layer.tar'] = rows[evidence['layer_names'][1]]
            item = json.loads(rows['manifest.json']); item[0]['Layers'] = names
            rows['manifest.json'] = encoded(item)
            with self.subTest(names=names): self.refused(rows, identifier)

    def test_selected_config_and_layer_descriptor_size_and_digest_are_verified(self):
        changes = [lambda item: item['config'].update(size=1),
                   lambda item: item['config'].update(digest='sha256:'+'0'*64),
                   lambda item: item['layers'][0].update(size=1),
                   lambda item: item['layers'][0].update(size=512*1024**2+1),
                   lambda item: item['layers'][0].update(digest='sha256:'+'0'*64)]
        for change in changes:
            rows, identifier, _ = export(descriptor_change=change)
            self.refused(rows, identifier)

    def test_layout_wrapper_and_selected_document_schema_are_required(self):
        original, identifier, _ = export()
        for name, value in (('oci-layout', {'imageLayoutVersion':'2.0.0'}),
                            ('index.json', {'schemaVersion':2,'mediaType':'application/unknown','manifests':[]}),
                            ('index.json', [])):
            rows = original.copy(); rows[name] = encoded(value)
            with self.subTest(name=name, value=value): self.refused(rows, identifier)
        rows, identifier, _ = export(descriptor_change=lambda item: item.update(schemaVersion=1))
        self.refused(rows, identifier)

    def test_raw_compressed_digest_and_decoded_diff_id_are_both_required(self):
        rows, identifier, evidence = export(compress=True)
        # A different gzip header keeps decoded tar/account bytes unchanged.
        layer_name = evidence['layer_names'][0]
        raw = rows[layer_name]
        rows[layer_name] = raw[:4]+b'\x01\x00\x00\x00'+raw[8:]
        self.refused(rows, identifier)
        rows, identifier, _ = export(config_changes={'rootfs': {
            'type':'layers','diff_ids':['sha256:'+'0'*64]*2}}, compress=True)
        self.refused(rows, identifier)

    def test_unknown_compression_and_descriptor_compression_mismatch_refuse(self):
        for compress, media_type in ((False,OCI_LAYER+'+gzip'), (True,OCI_LAYER),
                                     (False,OCI_LAYER+'+zstd'), (False,'application/unknown')):
            rows, identifier, _ = export(compress=compress,
                descriptor_change=lambda item: item['layers'][0].update(mediaType=media_type))
            with self.subTest(compress=compress, media_type=media_type): self.refused(rows, identifier)

    def test_whiteout_removal_path_escape_and_symlink_account_are_not_trusted(self):
        lower = {'etc/passwd': b'nonroot:x:65532:65532::/:/sbin/nologin\n',
                 'etc/group': b'nonroot:x:65532:\n'}
        link = tarfile.TarInfo('etc/passwd'); link.type = tarfile.SYMTYPE; link.linkname = '/private/passwd'
        for layer_rows in ([lower,{'etc/.wh.passwd':b''}],
                           [lower,{'../etc/passwd':b'nonroot:x:0:0::/:/bin/sh\n'}],
                           [lower,{'etc/passwd':link}]):
            rows, identifier, _ = export(layer_rows=layer_rows)
            self.refused(rows, identifier)

    def test_duplicate_outer_entries_and_oci_blob_symlink_refuse(self):
        rows, identifier, evidence = export()
        with self.assertRaisesRegex(profile.Refused, CODE):
            profile.image_account(packed(rows, ('manifest.json',rows['manifest.json'])), identifier, USER)
        name = 'blobs/sha256/'+evidence['target']['digest'][7:]
        link = tarfile.TarInfo(name); link.type=tarfile.SYMTYPE; link.linkname=evidence['config_name']
        rows[name]=link
        self.refused(rows, identifier)

    def test_descriptor_cycle_is_refused_before_recursing(self):
        # A real SHA256 self-cycle cannot be constructed. Mock hashing only to
        # exercise the bounded traversal guard independently of that property.
        identifier='sha256:'+'a'*64
        desc=dict(mediaType=OCI_INDEX,digest=identifier,size=1)
        body=encoded(dict(schemaVersion=2,mediaType=OCI_INDEX,manifests=[desc]))
        desc['size']=len(body)
        body=encoded(dict(schemaVersion=2,mediaType=OCI_INDEX,manifests=[desc]))
        desc['size']=len(body)
        body=encoded(dict(schemaVersion=2,mediaType=OCI_INDEX,manifests=[desc]))
        data={'oci-layout':encoded({'imageLayoutVersion':'1.0.0'}),
              'index.json':encoded(dict(schemaVersion=2,mediaType=OCI_INDEX,manifests=[desc])),
              'blobs/sha256/'+'a'*64:body}
        with patch.object(profile,'sha',return_value='a'*64), self.assertRaisesRegex(profile.Refused,CODE):
            profile.verified_oci_layers(lambda name,maximum:data[name],identifier,'unused',b'',[],512*1024**2)


if __name__ == '__main__':
    unittest.main()

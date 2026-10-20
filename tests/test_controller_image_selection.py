"""Controller checks use the selected backup pins, with synthetic Docker only."""
import contextlib
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location('selected_' + name, ROOT/'remote'/(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runtime = load('runtime_profile')
tailscale = load('tailscale_recovery')
headplane = load('headplane_recovery')
REPOSITORIES = dict(tailscale='tailscale/tailscale', headscale='headscale/headscale',
                    npm='jc21/nginx-proxy-manager', headplane='ghcr.io/tale/headplane')


class ControllerImageSelection(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(temporary.cleanup)
        self.root, self.home = Path(temporary.name)/'streams-aio', Path(temporary.name)/'private'
        (self.root/'config').mkdir(parents=True)
        self.home.mkdir()
        self.references = {name: repository + '@sha256:' + str(index)*64
                           for index, (name, repository) in enumerate(REPOSITORIES.items(), 1)}
        self.model = dict(name='streams-aio', services={name: dict(image=image, platform='linux/amd64')
                    for name, image in self.references.items()})
        self.model['services']['tailscale']['network_mode'] = 'host'
        self.ids = {name: chr(97 + index)*64 for index, name in enumerate(REPOSITORIES)}
        self.image_ids = {name: 'sha256:' + format(10 + index, 'x')*64 for index, name in enumerate(REPOSITORIES)}
        self.rows = {}
        self.calls = []
        for name, identifier in self.ids.items():
            mounts = ({'/data': 'data/npm/data', '/etc/letsencrypt': 'data/npm/data/letsencrypt'}
                if name == 'npm' else {'/etc/headscale': 'data/headscale/data/config',
                    '/var/lib/headscale': 'data/headscale/data/lib',
                    '/var/run/headscale': 'data/headscale/data/run'} if name == 'headscale'
                else {'/etc/headplane/config.yaml': headplane.CONFIG,
                      '/var/lib/headplane': 'data/headplane/data',
                      '/etc/headscale/config.yaml': headplane.HEADSCALE_CONFIG} if name == 'headplane' else {})
            self.rows[name] = dict(Id=identifier, Image=self.image_ids[name],
                Config=dict(Image=self.references[name], Labels={
                    'com.docker.compose.project': 'streams-aio',
                    'com.docker.compose.project.working_dir': str(self.root),
                    'com.docker.compose.service': name}),
                State=dict(Running=True, Health=dict(Status='healthy')),
                HostConfig=dict(NetworkMode='host' if name == 'tailscale' else 'streams-aio_default'),
                Mounts=[dict(Type='bind', Source=str(self.root/source), Destination=target)
                        for target, source in mounts.items()])
        self.write_locks()

    def write_locks(self):
        self.locks = {name: dict(image=image, platform='linux/amd64')
                      for name, image in self.references.items()}
        (self.root/'config/image-lock.json').write_text(json.dumps(self.locks))
        (self.root/'config/compose.dr.yaml').write_text(json.dumps(dict(services=self.locks)))

    @contextlib.contextmanager
    def selected_scope(self):
        # Scope/checkpoint identity is covered by runtime tests. Here the real
        # resolver reads both lock files, while only the already-proven commit
        # result and the trusted module loader are replaced.
        fake_spec = N(loader=N(exec_module=lambda module: None))
        with patch.object(runtime, 'state_commit', return_value='a'*40), \
             patch.object(importlib.util, 'spec_from_file_location', return_value=fake_spec) as loader, \
             patch.object(importlib.util, 'module_from_spec', return_value=runtime):
            yield
        self.assertTrue(loader.call_args_list)
        self.assertTrue(all(call.args[1] == ROOT/'remote/runtime_profile.py'
                            for call in loader.call_args_list))

    def docker(self, args):
        self.calls.append(args)
        if args[:6] == ['docker', 'compose', '--profile', 'all', 'ps', '-aq']:
            return self.ids[args[-1]].encode()
        if args[:2] == ['docker', 'inspect']:
            name = next(name for name, value in self.ids.items() if value == args[-1])
            return json.dumps([self.rows[name]]).encode()
        if args[:5] == ['docker', 'image', 'inspect', '--format', '{{json .Id}}']:
            name = next(name for name, row in self.model['services'].items() if row['image'] == args[-1])
            return json.dumps(self.image_ids[name]).encode()
        self.fail('Only exact readonly Docker commands are allowed')

    def test_new_controller_digests_use_exact_selected_reference_and_actual_image_id(self):
        with self.selected_scope():
            for name in tailscale.PINS:
                self.assertNotEqual(self.references[name], tailscale.PINS[name])
                self.assertEqual(tailscale.checked_container(self.root, self.model, name, self.docker), self.ids[name])
            self.assertEqual(headplane._headplane_container(self.root, self.model, self.docker), self.ids['headplane'])
        inspected = [args[-1] for args in self.calls if args[:3] == ['docker', 'image', 'inspect']]
        self.assertEqual(inspected, list(self.references.values())[:3] + [self.references['headplane']])

    def test_hub_aliases_and_descriptive_tags_keep_repository_and_digest_identity(self):
        self.model['services']['tailscale']['image'] = 'docker.io/' + self.references['tailscale']
        self.model['services']['headscale']['image'] = self.references['headscale'].replace('@', ':stable@')
        self.rows['tailscale']['Config']['Image'] = 'index.docker.io/' + self.references['tailscale']
        self.rows['headscale']['Config']['Image'] = 'registry-1.docker.io/' + self.references['headscale']
        self.model['services']['headplane']['image'] = self.references['headplane'].replace('@', ':latest@')
        with self.selected_scope():
            for name in ('tailscale', 'headscale'):
                self.assertEqual(tailscale.checked_container(self.root, self.model, name, self.docker), self.ids[name])
            self.assertEqual(headplane._headplane_container(self.root, self.model, self.docker), self.ids['headplane'])

    def test_changed_lock_digest_or_vendor_never_reaches_docker(self):
        initial = copy.deepcopy(self.model)
        for name, error in (('tailscale', 'TAILSCALE_CONTROLLER_IMAGE_REFUSED'),
                            ('headplane', headplane.SCOPE)):
            for mode in ('digest', 'vendor', 'platform', 'missing'):
                with self.subTest(name=name, mode=mode):
                    self.model = copy.deepcopy(initial)
                    self.write_locks()
                    if mode == 'digest':
                        self.model['services'][name]['image'] = REPOSITORIES[name] + '@sha256:' + '9'*64
                    elif mode == 'vendor':
                        value = 'attacker/controller@sha256:' + '9'*64
                        self.model['services'][name]['image'] = value
                        self.locks[name]['image'] = value
                        (self.root/'config/image-lock.json').write_text(json.dumps(self.locks))
                        (self.root/'config/compose.dr.yaml').write_text(json.dumps(dict(services=self.locks)))
                    elif mode == 'platform':
                        self.model['services'][name]['platform'] = 'linux/arm64'
                    else:
                        self.model['services'].pop(name)
                    self.calls.clear()
                    with self.selected_scope(), self.assertRaisesRegex(ValueError, '^'+error+'$'):
                        if name == 'tailscale':
                            tailscale.checked_container(self.root, self.model, name, self.docker)
                        else:
                            headplane._headplane_container(self.root, self.model, self.docker)
                    self.assertFalse(self.calls)

    def test_container_reference_and_actual_image_id_cannot_substitute_another_image(self):
        for name, error in (('tailscale', 'TAILSCALE_CONTROLLER_IMAGE_REFUSED'),
                            ('headplane', headplane.SCOPE)):
            for field, value in (('reference', REPOSITORIES[name] + '@sha256:' + '9'*64),
                                 ('reference', 'attacker/controller@sha256:' + '1'*64),
                                 ('reference', REPOSITORIES[name] + ':latest'),
                                 ('id', 'sha256:' + '9'*64)):
                with self.subTest(name=name, field=field, value=value):
                    original = copy.deepcopy(self.rows[name])
                    if field == 'reference': self.rows[name]['Config']['Image'] = value
                    else: self.rows[name]['Image'] = value
                    with self.selected_scope(), self.assertRaisesRegex(ValueError, '^'+error+'$'):
                        if name == 'tailscale':
                            tailscale.checked_container(self.root, self.model, name, self.docker)
                        else:
                            headplane._headplane_container(self.root, self.model, self.docker)
                    self.rows[name] = original

    def test_ownership_health_and_mount_checks_still_refuse_new_pins(self):
        for mutation, error in (('owner', 'TAILSCALE_CONTROLLER_OWNERSHIP_REFUSED'),
                                ('health', 'TAILSCALE_CONTROLLER_NOT_HEALTHY'),
                                ('mount', 'TAILSCALE_CONTROLLER_OWNERSHIP_REFUSED')):
            initial = copy.deepcopy(self.rows['headscale'])
            if mutation == 'owner': self.rows['headscale']['Config']['Labels']['com.docker.compose.project'] = 'other'
            elif mutation == 'health': self.rows['headscale']['State']['Health']['Status'] = 'unhealthy'
            else: self.rows['headscale']['Mounts'][0]['Source'] = '/outside/config'
            with self.selected_scope(), self.assertRaisesRegex(ValueError, '^'+error+'$'):
                tailscale.checked_container(self.root, self.model, 'headscale', self.docker)
            self.rows['headscale'] = initial
        self.rows['headplane']['Mounts'][0]['Source'] = '/outside/config'
        with self.selected_scope(), self.assertRaisesRegex(ValueError, '^'+headplane.SCOPE+'$'):
            headplane._headplane_container(self.root, self.model, self.docker)

    def test_headplane_scope_accepts_selected_image_without_weakening_checkpoint(self):
        state = dict(target=str(self.root), machine_id='synthetic', public_commit='a'*40,
                     preparation='PASS', completed=['EMPTY_STATE'], runtime_profile=dict(origin='FIRST_BOOT'))
        (self.home/'state.json').write_text(json.dumps(state))
        (self.home/'state.json').chmod(0o600)
        (self.root/'config/dr-manifest.yaml').write_text(json.dumps(dict(state_units=[dict(
            id='headscale-enrollments', services=['headscale'], path_or_type=headplane.DATABASE,
            classification='OPTIONAL_RUNTIME_STATE', backup_required=False)])))
        database = self.root/headplane.DATABASE
        database.parent.mkdir(parents=True)
        database.write_bytes(b'SQLite format 3\0' + b'0'*64)
        database.chmod(0o600)
        original_read = Path.read_text
        def read(path, *args, **kwargs):
            return 'synthetic' if path == Path('/etc/machine-id') else original_read(path, *args, **kwargs)
        with self.selected_scope(), patch.object(Path, 'read_text', read):
            self.assertEqual(headplane._scope(self.root, self.home, state, self.model), (self.root, self.home))
            with self.assertRaisesRegex(ValueError, '^'+headplane.SCOPE+'$'):
                headplane._scope(self.root, self.home, dict(state, extra='unsaved'), self.model)

    def test_legacy_loader_keeps_fixed_pins_and_does_not_adopt_a_new_model(self):
        legacy = dict(name='streams-aio', services={name: dict(image=image)
                      for name, image in tailscale.PINS.items()})
        reference, same_image = tailscale._image_selection(self.root, legacy, 'tailscale')
        self.assertEqual(reference, tailscale.PINS['tailscale'])
        self.assertTrue(same_image(reference))
        self.assertFalse(same_image(self.references['tailscale']))
        reference, same_image = headplane._image_selection(self.root,
            dict(name='streams-aio', services=dict(headplane=dict(image=headplane.HEADPLANE_IMAGE))))
        self.assertEqual(reference, headplane.HEADPLANE_IMAGE)
        self.assertTrue(same_image(reference))
        self.assertFalse(same_image(self.references['headplane']))


if __name__ == '__main__':
    unittest.main()

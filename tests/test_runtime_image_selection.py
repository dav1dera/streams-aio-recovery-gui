"""Current backup pins traverse real compatibility gates and transactions.

The pins below are a public backup projection, deliberately independent of the
runtime module's historical constants. Docker and Linux filesystem metadata are
simulated; selection, model validation, image archives and apply_fresh are real.
"""
import copy
import json
from pathlib import Path
import re
import stat
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

from tests import test_lab_runtime_scope as scope_fixture
from tests import test_runtime_profile as archive_fixture


policy = archive_fixture.profile
PINS = {
    'postgres': 'postgres@sha256:650d7a867dc5336eff67802a1417fcc801821d73d824c608e80afbde792fe6e1',
    'dnscrypt-proxy': 'klutchell/dnscrypt-proxy@sha256:a98e8d13314fa8b75620026441b1d6581e2b55189509a794500c5c86064df810',
    'oauth2-proxy': 'quay.io/oauth2-proxy/oauth2-proxy@sha256:8498b0d0ef0a7b29686414000a08aee467f02d0299c9ed1e006a8f33fc017916',
    'pgbouncer': 'edoburu/pgbouncer@sha256:8638aa563607256d3c7440437534195f1066a92b68015d89ae9d6b935b444a6d',
    'comet': 'g0ldyy/comet@sha256:dca62133336e02784d02aaad861381820674d1c8e3e98a03797610b81ee4defe',
    'cometnet': 'g0ldyy/comet@sha256:dca62133336e02784d02aaad861381820674d1c8e3e98a03797610b81ee4defe',
    'tailscale': 'tailscale/tailscale@sha256:87c55d6be56ad85b3d8bceca5f87f73de288c609131460dd1be1874c250cc41d',
    'headscale': 'headscale/headscale@sha256:780ed2f9e85719a2211277433f2c8afb45105d0d25031949a6848a485f9e216d',
    'npm': 'jc21/nginx-proxy-manager@sha256:4393e642e233e5efd5adeb7f10918d4aaea71c9ed875b94190273fc8e87f9594',
    'aiomanager': 'ghcr.io/sonicx161/aiomanager@sha256:d054c8b5795e93ce828098eddd7e0f1a07da2d6e31c91c8d1c3412256ec3c7ac',
    'gluetun': 'qmcgaw/gluetun@sha256:12df8b20528d4cd5e9b6e827d40f2886cf78e53e7e9afc750050648c31183793',
}
FIRST_BOOT_SERVICES = ('postgres', 'dnscrypt-proxy', 'oauth2-proxy', 'pgbouncer')


def backup_model(root):
    services = {name: dict(image=reference, platform='linux/amd64') for name, reference in PINS.items()}
    services['postgres'].update(environment={'PGDATA': '/var/lib/postgresql/data',
        'POSTGRES_PASSWORD': 'synthetic-private-password'}, volumes=[
        dict(type='bind', source=str(root/'data/postgres/init'), target='/docker-entrypoint-initdb.d'),
        dict(type='volume', source='pgdata', target='/var/lib/postgresql/data'),
        dict(type='bind', source=str(root/'data/postgres/postgresql.conf'), target='/var/lib/postgresql/data/postgresql.conf'),
        dict(type='volume', source='postgres-cluster', target='/var/lib/postgresql')])
    services['dnscrypt-proxy']['volumes'] = [dict(type='bind', source=str(root/'data/dnscrypt-proxy/data'), target='/config')]
    services['oauth2-proxy']['volumes'] = [dict(type='bind', source=str(root/'data/oauth2-proxy/allowed-emails.txt'),
                                              target='/etc/oauth2-proxy/allowed-emails.txt', read_only=True)]
    services['pgbouncer'].update(healthcheck={'test': ['CMD', 'pg_isready']},
        environment={'DB_USER': 'postgres', 'DB_PASSWORD': 'synthetic-private-password'},
        depends_on={'postgres': {'condition': 'service_healthy'}}, volumes=[
            dict(type='bind', source=str(root/'data/pgbouncer/data/pgbouncer.ini'), target='/etc/pgbouncer/pgbouncer.ini', read_only=True),
            dict(type='bind', source=str(root/'.generated/pgbouncer/userlist.txt'), target='/etc/pgbouncer/userlist.txt')])
    services['aiomanager']['environment'] = {'DATABASE_URL': 'postgresql://synthetic@pgbouncer/db'}
    services['comet']['depends_on'] = {'pgbouncer': {'condition': 'service_healthy'}}
    services['cometnet'].update(entrypoint=['python', '-m', 'comet.cometnet.standalone'],
        network_mode='service:gluetun', user='1000:1000',
        environment={'COMETNET_LISTEN_PORT': '8765', 'COMETNET_HTTP_PORT': '8766'},
        healthcheck={'test': ['CMD', 'public-health']})
    services['tailscale']['network_mode'] = 'host'
    for name in ('headscale', 'npm'):
        services[name]['healthcheck'] = {'test': ['CMD', 'check']}
    return dict(name='streams-aio', services=services,
                volumes={name: {'name': 'streams-aio_' + name} for name in ('pgdata', 'postgres-cluster')})


class RuntimeImageSelectionTests(unittest.TestCase):
    def setUp(self):
        self.scope = scope_fixture.LabScope('test_current_tag_commit_and_new_account_have_real_nonlegacy_scope')
        self.scope.setUp()
        self.addCleanup(self.scope.doCleanups)
        self.root, self.home, self.state = self.scope.root, self.scope.home, self.scope.state
        self.model = backup_model(self.root)
        self.commands = []
        self.lock = {name: {'image': image} for name, image in PINS.items()}
        self.override = {'services': {name: {'image': image, 'platform': 'linux/amd64'} for name, image in PINS.items()}}
        files = ('docker-compose.yml', 'config/dr-manifest.yaml', 'data/postgres/.env',
            'data/postgres/postgresql.conf', 'data/postgres/init/init.sql',
            'data/dnscrypt-proxy/data/dnscrypt-proxy.toml', 'data/oauth2-proxy/allowed-emails.txt',
            'data/pgbouncer/data/pgbouncer.ini', '.secrets/preserved.env',
            'data/aiostreams/data/db.sqlite', 'data/aiometadata/data/db.sqlite')
        for name in files:
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('synthetic-private-preserved:' + name).encode())
        self.renderer = archive_fixture.PINNED_USERLIST_RENDERER
        (self.root/'scripts').mkdir()
        (self.root/'scripts/dr.py').write_bytes(self.renderer)
        (self.root/'.generated/pgbouncer').mkdir(parents=True)
        (self.root/'.generated/pgbouncer/userlist.txt').write_text('"postgres" "synthetic-private-password"\n')
        self.original_env = b"PRIVATE=synthetic-private-preserved\nCOMPOSE_FILE='docker-compose.yml:config/compose.dr.yaml'\n"
        (self.root/'.env').write_bytes(self.original_env)
        self.save_public_pins()
        layers = {'etc/passwd': b'nonroot:x:65532:65532::/:/sbin/nologin\n', 'etc/group': b'nonroot:x:65532:\n'}
        normal, normal_id = archive_fixture.image_save([layers])
        postgres, postgres_id = archive_fixture.image_save([{'etc/passwd': b'postgres:x:70:70::/:/bin/sh\n',
            'etc/group': b'postgres:x:70:\n'}], user='')
        pooler, pooler_id = archive_fixture.image_save([{'etc/passwd': b'postgres:x:70:70::/:/bin/sh\n',
            'etc/group': b'postgres:x:70:\n'}], user='postgres')
        self.archives = {PINS['postgres']: postgres, PINS['dnscrypt-proxy']: normal,
                         PINS['oauth2-proxy']: normal, PINS['pgbouncer']: pooler}
        self.images = {
            PINS['postgres']: dict(Id=postgres_id, Os='linux', Architecture='amd64',
                                  Env=['PG_MAJOR=18', 'PGDATA=/var/lib/postgresql/18/docker'], User=''),
            PINS['dnscrypt-proxy']: dict(Id=normal_id, Os='linux', Architecture='amd64', Env=[], User='nonroot:nonroot'),
            PINS['oauth2-proxy']: dict(Id=normal_id, Os='linux', Architecture='amd64', Env=[], User='nonroot:nonroot'),
            PINS['pgbouncer']: dict(Id=pooler_id, Os='linux', Architecture='amd64', Env=[], User='postgres')}
        for item in (patch.object(policy, 'regular', side_effect=self.metadata),
                     patch.object(policy, 'private_directory'), patch.object(policy, 'dns_permissions'),
                     patch.object(policy, 'private_bind_metadata'), patch.object(policy, 'bind_readable', return_value=True),
                     patch.object(policy, 'atomic', side_effect=self.atomic)):
            item.start()
            self.addCleanup(item.stop)

    def save_public_pins(self):
        (self.root/'config/image-lock.json').write_text(json.dumps(self.lock))
        (self.root/'config/compose.dr.yaml').write_text(json.dumps(self.override))

    def metadata(self, path):
        path = Path(path)
        self.assertTrue(path.is_file())
        if path == self.root/'.env': uid, gid, mode = 0, 1000, 0o640
        elif path == self.root/'data/postgres/init/init.sql': uid, gid, mode = 70, 70, 0o640
        elif path in (self.root/policy.ARTIFACT, self.root/policy.TRIAL_PASSWORD): uid, gid, mode = 1000, 1000, 0o600
        else: uid, gid, mode = 0, 0, 0o600
        return N(st_uid=uid, st_gid=gid, st_mode=stat.S_IFREG | mode, st_nlink=1,
                 st_size=path.stat().st_size)

    def atomic(self, path, raw, mode, uid, gid):
        Path(path).write_bytes(raw)

    def io_run(self, args):
        self.commands.append(args)
        self.assertFalse(set(map(str, args)) & {'create', 'up', 'down', 'run', 'start', 'stop', 'rm', 'pull', 'push'})
        if args[:3] == ['docker', 'compose', 'version']: return b'2.40.1\n'
        if args[0] == 'sudo': return self.renderer if 'show' in args else self.scope.commit.encode()
        if args[:2] == ['docker', 'ps']: return b''
        if args[:3] == ['docker', 'volume', 'ls']: return b''
        if args[:3] == ['docker', 'image', 'inspect']: return json.dumps(self.images[args[-1]]).encode()
        if args[:3] == ['docker', 'image', 'save']: return self.archives[args[-1]]
        if args[:3] == ['docker', 'compose', '--env-file']:
            result = archive_fixture.effective(self.root, self.model, first_boot=True)
            raw = (self.root/policy.ARTIFACT).read_text()
            match = re.search(r'COMETNET_NETWORK_PASSWORD: "([0-9a-f]{64})"', raw)
            if match:
                result['services']['cometnet']['environment'].update(policy.COMETNET_TRIAL_ENV)
                result['services']['cometnet']['environment']['COMETNET_NETWORK_PASSWORD'] = match.group(1)
            return json.dumps(result).encode()
        self.fail('Unexpected operation: ' + repr(args))

    def preserved_private(self):
        return {str(path.relative_to(self.root)): path.read_bytes() for path in (
            self.root/'.secrets/preserved.env', self.root/'data/postgres/init/init.sql',
            self.root/'.generated/pgbouncer/userlist.txt', self.root/'data/aiostreams/data/db.sqlite',
            self.root/'data/aiometadata/data/db.sqlite')}

    def test_current_public_backup_pins_pass_actual_base_and_first_boot_models(self):
        selected = policy.selected_runtime_images(self.root, self.model)
        self.assertEqual(selected['pgbouncer'], PINS['pgbouncer'])
        self.assertEqual(selected['tailscale'], PINS['tailscale'])
        self.assertEqual(selected['headscale'], PINS['headscale'])
        self.assertEqual(policy.first_boot_images(self.root, self.model), tuple(PINS[name] for name in FIRST_BOOT_SERVICES))
        policy.base_model(self.root, self.model)
        policy.first_boot_model(self.root, self.model)

    def test_actual_apply_fresh_checks_selected_images_and_preserves_private_material(self):
        before = self.preserved_private()
        result = policy.apply_fresh(self.root, self.home, self.state, self.model, self.io_run)
        self.assertTrue(result['applied'])
        inspected = {args[-1] for args in self.commands if args[:3] == ['docker', 'image', 'inspect']}
        self.assertEqual(inspected, {PINS[name] for name in FIRST_BOOT_SERVICES})
        self.assertEqual(self.preserved_private(), before)
        self.assertIn(b'PRIVATE=synthetic-private-preserved\n', (self.root/'.env').read_bytes())
        self.assertEqual(self.model['services']['pgbouncer']['image'], PINS['pgbouncer'])
        self.assertTrue(policy.validate(self.root, self.home, self.state))

    def test_docker_hub_aliases_preserve_digest_and_pass_real_model_gates(self):
        aliases = {'postgres': 'docker.io/library/' + PINS['postgres'],
                   'dnscrypt-proxy': 'registry-1.docker.io/' + PINS['dnscrypt-proxy'],
                   'pgbouncer': 'index.docker.io/' + PINS['pgbouncer']}
        for name, reference in aliases.items(): self.model['services'][name]['image'] = reference
        policy.base_model(self.root, self.model)
        policy.first_boot_model(self.root, self.model)

    def test_lock_override_model_digest_repository_or_platform_disagreement_refuses(self):
        baseline = copy.deepcopy(self.model)
        changes = ({'image': 'edoburu/pgbouncer@sha256:' + '1'*64},
                   {'image': 'other/pgbouncer@sha256:' + PINS['pgbouncer'].split('@sha256:')[1]},
                   {'image': 'edoburu/pgbouncer:latest'}, {'platform': 'linux/arm64'}, {'build': '.'})
        for change in changes:
            self.model = copy.deepcopy(baseline)
            self.model['services']['pgbouncer'].update(change)
            with self.subTest(change=change), self.assertRaises(policy.Refused):
                policy.first_boot_model(self.root, self.model)
        self.model = baseline
        self.override['services']['pgbouncer']['image'] = 'edoburu/pgbouncer@sha256:' + '2'*64
        self.save_public_pins()
        with self.assertRaises(policy.Refused): policy.base_model(self.root, self.model)
        self.assertFalse(self.commands)

    def test_architecture_pg_major_and_absent_user_metadata_refuse_without_mutation(self):
        before = self.preserved_private()
        baseline = copy.deepcopy(self.images)
        for change in ({'Architecture': 'arm64'}, {'Env': ['PG_MAJOR=17']}, {'User': None}):
            self.images = copy.deepcopy(baseline)
            self.images[PINS['postgres']].update(change)
            with self.subTest(change=change), self.assertRaises(policy.Refused):
                policy.apply_fresh(self.root, self.home, self.state, self.model, self.io_run)
            self.assertEqual(self.preserved_private(), before)
            self.assertEqual((self.root/'.env').read_bytes(), self.original_env)
            self.assertNotIn('runtime_profile', self.state)
            self.assertFalse((self.root/policy.ARTIFACT).exists())


if __name__ == '__main__':
    unittest.main()

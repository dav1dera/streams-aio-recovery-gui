import copy
from contextlib import closing
import gzip
import importlib.util
import io
import json
import re
import os
from pathlib import Path
import sqlite3
import stat
import tarfile
import tempfile
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('runtime_profile_test', ROOT/'remote/runtime_profile.py')
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)

# Public renderer contract from selected commit28f6ca7. Inline so uploaded
# Linux regressions do not depend on another checkout being on that host.
PINNED_USERLIST_RENDERER = r'''import base64,hashlib,hmac,re
class Refused(Exception): pass
def require(ok,code):
 if not ok: raise Refused(code)
def userlist_entries(content):
 entries={}
 pattern=re.compile(r'^\s*"((?:[^"]|"")*)"\s+"((?:[^"]|"")*)"(?:\s+.*)?$')
 for line in content.splitlines():
  if not line.strip() or line.lstrip().startswith(('#',';')):continue
  match=pattern.fullmatch(line);require(match is not None,'USERLIST_FORMAT_UNSUPPORTED')
  user,credential=(part.replace('""','"') for part in match.groups())
  require(user not in entries,'USERLIST_DUPLICATE_USER');entries[user]=credential
 return entries
def verified_role_password(user,password,credential):
 require(credential is not None,'USERLIST_ROLE_MISSING')
 if credential.startswith('SCRAM-SHA-256$'):
  try:
   _,params,keys=credential.split('$');iterations,salt=params.split(':');stored,server=keys.split(':');iterations=int(iterations)
   require(0<iterations<=1000000,'SCRAM_ITERATIONS_UNSUPPORTED')
   require(password.isascii(),'SCRAM_NON_ASCII_REQUIRES_SASLPREP_REVIEW')
   salted=hashlib.pbkdf2_hmac('sha256',password.encode(),base64.b64decode(salt,validate=True),iterations)
   client=hmac.new(salted,b'Client Key',hashlib.sha256).digest()
   valid=hmac.compare_digest(hashlib.sha256(client).digest(),base64.b64decode(stored,validate=True)) and hmac.compare_digest(hmac.new(salted,b'Server Key',hashlib.sha256).digest(),base64.b64decode(server,validate=True))
  except (ValueError,TypeError):raise Refused('SCRAM_FORMAT_UNSUPPORTED')
  require(valid,'USERLIST_PASSWORD_CONFLICT');return credential
 require(not credential.startswith('md5'),'LEGACY_MD5_REQUIRES_EXPLICIT_BACKEND_AUTH_REVIEW')
 require(hmac.compare_digest(password,credential),'USERLIST_PASSWORD_CONFLICT');return password
'''.encode()

# Dependency/health projection of public commit 28f6ca7, merged with its DR
# image locks. Kept inline so the Linux recovery tests need no YAML package.
PUBLIC_DEPENDENCIES = json.loads(r'''{"services":{"tailscale":{"network_mode":"host","healthcheck":{"test":["CMD","wget","--spider","-q","http://127.0.0.1:9002/healthz"],"interval":"1m","timeout":"5s","retries":3,"start_period":"10s"},"image":"tailscale/tailscale@sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065"},"portainer":{"image":"portainer/portainer-ce@sha256:4d616db18cfeb5dd41a69c0958bc825c84483ea9cde1106eb82a5d26f3bd8b0e"},"dnscrypt-proxy":{"healthcheck":{"test":["CMD","dnscrypt-proxy","--version"],"interval":"30s","timeout":"10s","retries":3},"image":"klutchell/dnscrypt-proxy@sha256:a98e8d13314fa8b75620026441b1d6581e2b55189509a794500c5c86064df810"},"headscale":{"healthcheck":{"test":["CMD","headscale","health"]},"image":"headscale/headscale@sha256:8833f828b414c0907b7e5c71da76473216fe17cce0818a166b536ec552c0903f"},"headplane":{"depends_on":{"headscale":{"condition":"service_healthy"}},"healthcheck":{"test":["CMD","/bin/hp_healthcheck"],"interval":"30s","timeout":"5s","start_period":"5s","retries":3},"image":"ghcr.io/tale/headplane@sha256:394483fd2336ce6b15df360c3e118ddfd45eb8140fe21df9f2611077f5d79d22"},"npm":{"depends_on":{"postgres":{"condition":"service_healthy"}},"healthcheck":{"test":["CMD","/usr/bin/check-health"]},"image":"jc21/nginx-proxy-manager@sha256:4393e642e233e5efd5adeb7f10918d4aaea71c9ed875b94190273fc8e87f9594"},"cloudflare-ddns":{"image":"favonia/cloudflare-ddns@sha256:5e61736b982b87d84a1120b4767c4deff0f2cc55ca3ee9dcb1dc58623039b5cb"},"aiometadata":{"depends_on":{"redis":{"condition":"service_healthy"}},"image":"ghcr.io/cedya77/aiometadata@sha256:9bff687d7f213e401475951cb0be882eeec45d919e0659a2a7dc58d9b329c67e"},"mediaflow-proxy-light":{"image":"ghcr.io/mhdzumair/mediaflow-proxy-light@sha256:44e10959417a2de569a998af28bd59ac14ab34225795de8326f60699717fbb5b"},"aiostreams":{"depends_on":{"gluetun":{"condition":"service_healthy"}},"image":"ghcr.io/viren070/aiostreams@sha256:754ff8adeaee95d31ff88ef7478f40a647f944092b4588861c6fccfe9d1659d6"},"pgbouncer":{"depends_on":{"postgres":{"condition":"service_healthy"}},"healthcheck":{"test":["CMD","pg_isready","-h","postgres"]},"image":"edoburu/pgbouncer@sha256:9c78945868a6a142c7fc40ccd843bbe5a606df163c7ffce4de70e0d628d696a2"},"postgres":{"healthcheck":{"test":["CMD-SHELL","pg_isready -U postgres"],"interval":"10s","timeout":"5s","retries":5},"image":"postgres@sha256:650d7a867dc5336eff67802a1417fcc801821d73d824c608e80afbde792fe6e1"},"redis":{"healthcheck":{"test":["CMD","echo","ok"],"interval":"10s","timeout":"5s","retries":5},"image":"redis@sha256:718f745deb7dfefeac6eed7041fc7ec9476b50e61b247932682457c41adafa0e"},"watchtower":{"image":"nickfedor/watchtower@sha256:2f8f2a9bd21a195b3b650409532a20f6aada8ef5834f00d0d7a999dee0779a81"},"honey":{"image":"ghcr.io/dani3l0/honey@sha256:fe6ce43acf93a211ab63cf247e4ce573cb63a41608092f0bffb1b3bf72527ac5"},"teamspeak":{"image":"teamspeaksystems/teamspeak6-server@sha256:d845f803aecf842c2df034c959c23ff2462357bacafb3807500885c5ec170fa1"},"microwarp":{"image":"ghcr.io/ccbkkb/microwarp@sha256:d5b709efd49dbec3a965c617eb263b46cdf1449e65776d1b9a351927439b2b17"},"gost":{"depends_on":["microwarp"],"image":"gogost/gost@sha256:55f05a58541f69bd7aa5fb9ee24fda12669430fb71489496473ecf15c32bcc8e"},"oauth2-proxy":{"depends_on":["headplane"],"image":"quay.io/oauth2-proxy/oauth2-proxy@sha256:8498b0d0ef0a7b29686414000a08aee467f02d0299c9ed1e006a8f33fc017916"},"easyproxy":{"depends_on":{"gluetun":{"condition":"service_healthy"}},"image":"ghcr.io/realbestia1/easyproxy@sha256:212c93d6ceb056a0d2bb96a45135f84c72a7024d9353628969cf04e0527f6775"},"streamvix":{"depends_on":{"gluetun":{"condition":"service_healthy"}},"image":"qwertyuiop8899/streamvix@sha256:192a23280b4cbdcc46f592eab2cb3997d19bf45c08f32475e52867717a845ccd"},"tvvoo":{"depends_on":{"gluetun":{"condition":"service_healthy"}},"image":"qwertyuiop8899/tvvoo@sha256:fc408f45a2c33ec917056300b192cbc61cb3ae61740c85d281336095db4c81c2"},"aiomanager":{"healthcheck":{"test":["CMD","/nodejs/bin/node","server/healthcheck.js"],"interval":"1m","timeout":"10s","retries":5,"start_period":"15s"},"image":"ghcr.io/sonicx161/aiomanager@sha256:d054c8b5795e93ce828098eddd7e0f1a07da2d6e31c91c8d1c3412256ec3c7ac"},"deunhealth":{"network_mode":"none","image":"qmcgaw/deunhealth@sha256:db1e4fcd3aceeb0da34a83f7a8a5432df586e6d0388ddb6ad8dd7b479e4aa25d"},"gluetun":{"healthcheck":{"test":["CMD","/gluetun-entrypoint","healthcheck"],"interval":"5s","timeout":"5s","retries":1,"start_period":"40s"},"image":"qmcgaw/gluetun@sha256:12df8b20528d4cd5e9b6e827d40f2886cf78e53e7e9afc750050648c31183793"},"comet":{"depends_on":{"postgres":{"condition":"service_healthy"},"gluetun":{"condition":"service_healthy"},"pgbouncer":{"condition":"service_healthy"}},"network_mode":"service:gluetun","image":"g0ldyy/comet@sha256:dca62133336e02784d02aaad861381820674d1c8e3e98a03797610b81ee4defe"},"cometnet":{"depends_on":{"postgres":{"condition":"service_healthy"},"comet":{"condition":"service_healthy"},"gluetun":{"condition":"service_healthy"},"pgbouncer":{"condition":"service_healthy"}},"network_mode":"service:gluetun","healthcheck":{"test":["CMD","python","-c","import http.client; c=http.client.HTTPConnection('127.0.0.1',8766,timeout=5); c.request('GET','/health'); raise SystemExit(0 if c.getresponse().status == 200 else 1)"],"interval":"30s","timeout":"5s","retries":3,"start_period":"30s"},"image":"g0ldyy/comet@sha256:dca62133336e02784d02aaad861381820674d1c8e3e98a03797610b81ee4defe"},"stremthru":{"depends_on":{"postgres":{"condition":"service_healthy"},"gluetun":{"condition":"service_healthy"},"redis":{"condition":"service_healthy"},"pgbouncer":{"condition":"service_healthy"}},"network_mode":"service:gluetun","image":"muniftanjim/stremthru@sha256:3db9d5f373759fdbab97366ad6a106288eb753e9a07c9ec0f0e096acc8553321"},"jackett":{"depends_on":{"gluetun":{"condition":"service_healthy"}},"network_mode":"service:gluetun","image":"lscr.io/linuxserver/jackett@sha256:7b19f4f6ac33d855ca9226600ecbd096ee678f66da28b13a7c09980b035ff583"},"seanime":{"depends_on":{"gluetun":{"condition":"service_healthy"}},"network_mode":"service:gluetun","healthcheck":{"test":"wget -qO- http://127.0.0.1:43211/api/v1/status","interval":"5m","timeout":"10s","retries":5,"start_period":"10s"},"image":"umagistr/seanime@sha256:d74dcac9d5c29f74d980cccf5311a2212fe202b85308032d8665a15469824363"},"seanime-shared":{"depends_on":{"gluetun":{"condition":"service_healthy"}},"network_mode":"service:gluetun","healthcheck":{"test":"wget -qO- http://127.0.0.1:43311/api/v1/status","interval":"5m","timeout":"10s","retries":5,"start_period":"10s"},"image":"umagistr/seanime@sha256:d74dcac9d5c29f74d980cccf5311a2212fe202b85308032d8665a15469824363"}},"waves":[["aiomanager","cloudflare-ddns","deunhealth","dnscrypt-proxy","gluetun","headscale","honey","mediaflow-proxy-light","microwarp","portainer","postgres","redis","tailscale","teamspeak","watchtower"],["aiometadata","aiostreams","easyproxy","gost","headplane","jackett","npm","pgbouncer","seanime","seanime-shared","streamvix","tvvoo"],["comet","oauth2-proxy","stremthru"],["cometnet"]]}''')


def facts():
    return dict(pgdata_nonempty=True, pgdata_legacy=True, sql_readable=True,
                dnscrypt_permission_denied=True, legacy_pg_version=False,
                versioned_pg_version=False, pg_major=18, dnscrypt_uid=65532,
                dnscrypt_gid=65532, aiomanager_endpoint='PGBOUNCER')


def model(root, first_boot=False):
    result = dict(name='streams-aio', services={
        'postgres': dict(image=profile.PG_IMAGE, environment={'PGDATA': '/var/lib/postgresql/data',
                            'POSTGRES_PASSWORD': 'synthetic-password'}, volumes=[
            dict(type='bind', source=str(root/'data/postgres/init'), target='/docker-entrypoint-initdb.d'),
            dict(type='volume', source='pgdata', target='/var/lib/postgresql/data'),
            dict(type='bind', source=str(root/'data/postgres/postgresql.conf'),
                 target='/var/lib/postgresql/data/postgresql.conf'),
            dict(type='volume', source='postgres-cluster', target='/var/lib/postgresql')]),
        'dnscrypt-proxy': dict(image=profile.DNS_IMAGE, volumes=[
            dict(type='bind', source=str(root/'data/dnscrypt-proxy/data'), target='/config')]),
        'aiomanager': dict(environment={'DATABASE_URL': 'postgresql://synthetic@pgbouncer/db'}),
        'pgbouncer': dict(healthcheck={'test': ['CMD', 'check']},
                         depends_on={'postgres': dict(condition='service_healthy')}),
        'comet': dict(depends_on={'pgbouncer': dict(condition='service_healthy')}),
    }, volumes={key: {'name': 'streams-aio_' + key} for key in ('pgdata', 'postgres-cluster')})
    if first_boot:
        result['services']['oauth2-proxy'] = dict(image=profile.OAUTH_IMAGE, volumes=[
            dict(type='bind', source=str(root/'data/oauth2-proxy/allowed-emails.txt'),
                 target='/etc/oauth2-proxy/allowed-emails.txt', read_only=True)])
        result['services']['pgbouncer'].update(image=profile.PGBOUNCER_IMAGE, volumes=[
            dict(type='bind', source=str(root/'data/pgbouncer/data/pgbouncer.ini'),
                 target='/etc/pgbouncer/pgbouncer.ini', read_only=True),
            dict(type='bind', source=str(root/'.generated/pgbouncer/userlist.txt'),
                 target='/etc/pgbouncer/userlist.txt')])
        result['services']['pgbouncer']['environment'] = {'DB_USER': 'postgres', 'DB_PASSWORD': 'synthetic-password'}
    return result


def effective(root, source, first_boot=False):
    result = copy.deepcopy(source)
    result['services']['postgres']['environment']['PGDATA'] = '/var/lib/postgresql/18/docker'
    result['services']['postgres']['volumes'] = [
        dict(type='bind', source=str(root/'data/postgres/init'), target='/docker-entrypoint-initdb.d',
             read_only=True, bind={'create_host_path': False}),
        dict(type='volume', source='postgres-cluster', target='/var/lib/postgresql'),
        dict(type='volume', source='pgdata', target='/legacy-postgresql-data', read_only=True),
        dict(type='bind', source=str(root/'data/postgres/postgresql.conf'), target='/etc/postgresql/streams-aio.conf',
             read_only=True, bind={'create_host_path': False}),
    ]
    result['services']['dnscrypt-proxy']['user'] = '1000:1000'
    result['services']['aiomanager']['depends_on'] = {'pgbouncer': dict(condition='service_healthy', required=True)}
    if first_boot:
        result['services']['oauth2-proxy']['group_add'] = ['1000']
        result['services']['pgbouncer']['group_add'] = ['1000']
    return result


def image_save(layers=None, user='nonroot:nonroot', compress=False):
    if layers is None:
        layers = [{'etc/passwd': b'nonroot:x:65532:65532::/:/sbin/nologin\n',
                   'etc/group': b'nonroot:x:65532:\n'}]
    packed = []
    for rows in layers:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as archive:
            for name, raw in rows.items():
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
        packed.append(stream.getvalue())
    config = json.dumps(dict(config={'User': user}, rootfs={
        'diff_ids': ['sha256:' + profile.sha(raw) for raw in packed]})).encode()
    config_name = profile.sha(config) + '.json'
    layer_names = [str(index) + '/layer.tar' for index in range(len(packed))]
    manifest = json.dumps([dict(Config=config_name, Layers=layer_names)]).encode()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        rows = {'manifest.json': manifest, config_name: config}
        rows.update({name: gzip.compress(raw) if compress else raw
                     for name, raw in zip(layer_names, packed)})
        for name, raw in rows.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    return stream.getvalue(), 'sha256:' + profile.sha(config)


class FirstBootImage(unittest.TestCase):
    def test_verified_image_layers_resolve_named_user_without_creating_container(self):
        for compressed in (False, True):
            raw, identifier = image_save(compress=compressed)
            self.assertEqual(profile.image_account(raw, identifier, 'nonroot:nonroot'), (65532, 65532))
        raw, identifier = image_save([{'etc/passwd': b'postgres:x:70:70::/:/bin/sh\n'}], user='')
        self.assertEqual(profile.image_account(raw, identifier, '', lookup='postgres'), (70, 70))

    def test_whiteouts_do_not_leave_stale_accounts_from_lower_layer(self):
        lower = {'etc/passwd': b'nonroot:x:0:0::/:/bin/sh\n', 'etc/group': b'nonroot:x:0:\n'}
        upper = {'etc/.wh..wh..opq': b'',
                 'etc/passwd': b'nonroot:x:65532:65532::/:/sbin/nologin\n',
                 'etc/group': b'nonroot:x:65532:\n'}
        raw, identifier = image_save([lower, upper])
        self.assertEqual(profile.image_account(raw, identifier, 'nonroot:nonroot'), (65532, 65532))
        raw, identifier = image_save([lower, {'etc/.wh.passwd': b''}])
        with self.assertRaisesRegex(profile.Refused, 'IMAGE_ARCHIVE_REFUSED'):
            profile.image_account(raw, identifier, 'nonroot:nonroot')

    def test_changed_config_or_layer_and_malformed_archive_are_refused(self):
        raw, identifier = image_save()
        for archive, expected_id, user in ((raw, 'sha256:' + '0' * 64, 'nonroot:nonroot'),
                                           (raw, identifier, 'other'),
                                           (b'not a tar archive', identifier, 'nonroot:nonroot')):
            with self.subTest(user=user), self.assertRaises(profile.Refused):
                profile.image_account(archive, expected_id, user)
        # The inner bytes no longer match the image config's layer diff ID.
        changed = raw.replace(b'nonroot:x:65532:65532', b'nonroot:x:65533:65533')
        with self.assertRaisesRegex(profile.Refused, 'IMAGE_ARCHIVE_REFUSED'):
            profile.image_account(changed, identifier, 'nonroot:nonroot')


class FirstBootChecks(unittest.TestCase):
    def setUp(self):
        directory = ROOT.parent/'gui-test-tmp' if os.name == 'nt' else None
        self.temp = tempfile.TemporaryDirectory(dir=directory)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/'streams-aio'
        self.root.mkdir()
        self.volumes_root = Path(self.temp.name)/'volumes'
        self.volumes_root.mkdir()
        init = self.root/'data/postgres/init'
        init.mkdir(parents=True)
        (init/'init.sql').write_bytes(b'reviewed init SQL')
        renderer = self.root/'scripts/dr.py'
        renderer.parent.mkdir()
        self.renderer = PINNED_USERLIST_RENDERER
        renderer.write_bytes(self.renderer)
        userlist = self.root/'.generated/pgbouncer/userlist.txt'
        userlist.parent.mkdir(parents=True)
        userlist.write_text('"postgres" "synthetic-password"\n')
        self.model = model(self.root, first_boot=True)
        self.archive, image_id = image_save()
        postgres_archive, postgres_id = image_save([{'etc/passwd': b'postgres:x:70:70::/:/bin/sh\n',
                                                     'etc/group': b'postgres:x:70:\n'}], user='')
        pooler_archive, pooler_id = image_save([{'etc/passwd': b'postgres:x:70:70::/:/bin/sh\n',
                                                'etc/group': b'postgres:x:70:\n'}], user='postgres')
        self.archives = {profile.DNS_IMAGE: self.archive, profile.PG_IMAGE: postgres_archive,
                         profile.OAUTH_IMAGE: self.archive, profile.PGBOUNCER_IMAGE: pooler_archive}
        self.images = {
            profile.PG_IMAGE: dict(Id=postgres_id, Os='linux', Architecture='amd64',
                Env=['PG_MAJOR=18', 'PGDATA=/var/lib/postgresql/18/docker'], User=''),
            profile.DNS_IMAGE: dict(Id=image_id, Os='linux', Architecture='amd64',
                Env=[], User='nonroot:nonroot'),
            profile.OAUTH_IMAGE: dict(Id=image_id, Os='linux', Architecture='amd64',
                Env=[], User='nonroot:nonroot'),
            profile.PGBOUNCER_IMAGE: dict(Id=pooler_id, Os='linux', Architecture='amd64',
                Env=[], User='postgres')}
        self.containers, self.volumes, self.commands = b'', [], []
        self.patches = [patch.object(profile, 'dns_permissions'),
                        patch.object(profile, 'private_bind_metadata'),
                        patch.object(profile, 'bind_readable', return_value=True),
                        patch.object(profile, 'regular', return_value=N(st_uid=70, st_gid=70,
                            st_mode=stat.S_IFREG | 0o640, st_nlink=1)),
                        patch.object(profile, 'DOCKER_VOLUME_ROOT', self.volumes_root)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def docker_run(self, args):
        self.commands.append(args)
        self.assertFalse(set(args) & {'create', 'up', 'down', 'run', 'stop', 'rm', 'prune'})
        if args[:3] == ['docker', 'compose', 'version']: return b'2.40.1\n'
        if args[0] == 'sudo': return self.renderer if 'show' in args else profile.COMMIT.encode()
        if args[:2] == ['docker', 'ps']: return self.containers
        if args[:3] == ['docker', 'volume', 'ls']:
            return '\n'.join(row['Name'] for row in self.volumes).encode()
        if args[:3] == ['docker', 'volume', 'inspect']: return json.dumps(self.volumes).encode()
        if args[:3] == ['docker', 'image', 'inspect']: return json.dumps(self.images[args[-1]]).encode()
        if args[:3] == ['docker', 'image', 'save']: return self.archives[args[-1]]
        self.fail('Unexpected command: ' + repr(args))

    def add_volume(self, key='pgdata', project='streams-aio'):
        path = self.volumes_root/('streams-aio_' + key)/'_data'
        path.mkdir(parents=True)
        self.volumes.append(dict(Name='streams-aio_' + key, Mountpoint=str(path), Labels={
            'com.docker.compose.project': project, 'com.docker.compose.volume': key}))
        return path

    def test_fresh_images_and_config_pass_without_containers_or_created_volumes(self):
        self.assertEqual(profile.readonly_first_boot_checks(self.root, self.model, self.docker_run),
                         {'pgdata': 'streams-aio_pgdata', 'postgres-cluster': 'streams-aio_postgres-cluster'})
        self.assertIn(['docker', 'image', 'save', profile.DNS_IMAGE], self.commands)
        self.assertEqual(self.volumes, [])

    def test_existing_container_foreign_volume_or_nonempty_volume_is_refused(self):
        self.containers = b'existing-container'
        with self.assertRaisesRegex(profile.Refused, 'FRESH_HOST_REQUIRED'):
            profile.readonly_first_boot_checks(self.root, self.model, self.docker_run)
        self.containers = b''
        path = self.add_volume(project='other')
        with self.assertRaisesRegex(profile.Refused, 'OWNERSHIP_REFUSED'):
            profile.readonly_first_boot_checks(self.root, self.model, self.docker_run)
        self.volumes[0]['Labels']['com.docker.compose.project'] = 'streams-aio'
        profile.readonly_first_boot_checks(self.root, self.model, self.docker_run)
        (path/'PG_VERSION').write_bytes(b'18\n')
        with self.assertRaisesRegex(profile.Refused, 'DATABASE_PRESENT'):
            profile.readonly_first_boot_checks(self.root, self.model, self.docker_run)
        (path/'PG_VERSION').unlink()
        (path/'unexpected-private-state').write_bytes(b'preserve me')
        with self.assertRaisesRegex(profile.Refused, 'FRESH_HOST_REQUIRED'):
            profile.readonly_first_boot_checks(self.root, self.model, self.docker_run)
        self.assertTrue((path/'unexpected-private-state').is_file())

    def test_actual_image_major_architecture_account_and_endpoint_are_checked(self):
        old = copy.deepcopy(self.images)
        for field, value in (('Architecture', 'arm64'), ('Env', ['PG_MAJOR=17'])):
            self.images[profile.PG_IMAGE][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(profile.Refused, 'IMAGE_CHANGED'):
                profile.readonly_first_boot_checks(self.root, self.model, self.docker_run)
            self.images = copy.deepcopy(old)
        self.images[profile.DNS_IMAGE]['User'] = '1000:1000'
        with self.assertRaisesRegex(profile.Refused, 'DNS_IDENTITY_REFUSED'):
            profile.readonly_first_boot_checks(self.root, self.model, self.docker_run)
        self.images = copy.deepcopy(old)
        self.model['services']['aiomanager']['environment']['DATABASE_URL'] = 'postgresql://private@other/db'
        with self.assertRaisesRegex(profile.Refused, 'DEPENDENCY_REFUSED'):
            profile.readonly_first_boot_checks(self.root, self.model, self.docker_run)

    def test_first_boot_scope_preserves_older_prestart_phases_but_refuses_attempted_start(self):
        state = dict(completed=sorted(profile.FIRST_BOOT_STAGES))
        with patch.object(profile, 'identity_scope', return_value=(self.root, Path(self.temp.name))):
            profile.first_boot_scope(self.root, Path(self.temp.name), state, installing=True)
            for changed in ({**state, 'completed': state['completed'] + ['NPM']},
                            {**state, 'completed': state['completed'] + ['NPM', 'AIO'],
                             'preparation': 'PASS', 'application_start_attempted': False}):
                before = copy.deepcopy(changed)
                profile.first_boot_scope(self.root, Path(self.temp.name), changed, installing=True)
                self.assertEqual(changed, before)
            for changed in ({**state, 'application_start_attempted': True},
                            {**state, 'application_start_attempted': 0},
                            {**state, 'application_start_attempted': None},
                            {**state, 'preparation': 'FAILED'},
                            {**state, 'completed': state['completed'] + ['STARTED']}):
                with self.subTest(state=changed), self.assertRaisesRegex(
                        profile.Refused, '^RUNTIME_PROFILE_PRESTART_CHECKPOINT_REQUIRED$'):
                    profile.first_boot_scope(self.root, Path(self.temp.name), changed, installing=True)
            for changed in (
                            {**state, 'completed': ['RENDER']},
                            {**state, 'completed': state['completed'] + ['RENDER']}):
                with self.subTest(state=changed), self.assertRaises(profile.Refused):
                    profile.first_boot_scope(self.root, Path(self.temp.name), changed, installing=True)
            # Once registered, normal later phases retain validation support.
            profile.first_boot_scope(self.root, Path(self.temp.name),
                {**state, 'completed': state['completed'] + ['NPM', 'AIO'],
                 'application_start_attempted': True, 'preparation': 'PASS'})

    def test_pooler_admin_row_must_preexist_and_match_without_mutating_userlist(self):
        path = self.root/'.generated/pgbouncer/userlist.txt'
        for content in ('"other" "synthetic-password"\n',
                        ' "postgres" "synthetic-password"\n',
                        '"postgres" "different"\n',
                        '"postgres" "synthetic-password"\n"postgres" "synthetic-password"\n'):
            path.write_text(content)
            before = path.read_bytes()
            with self.subTest(content=content), self.assertRaisesRegex(profile.Refused, 'SQL_CHANGED'):
                profile.verify_pgbouncer_userlist(self.root, self.model, self.docker_run)
            self.assertEqual(path.read_bytes(), before)


class PureProfile(unittest.TestCase):
    def test_overlay_preserves_sql_old_volume_and_inert_config(self):
        raw = profile.overlay(Path('/home/test/streams-aio')).decode()
        self.assertIn('volumes: !override', raw)
        self.assertIn('target: /var/lib/postgresql\n', raw)
        self.assertIn('target: /legacy-postgresql-data', raw)
        self.assertIn('target: /etc/postgresql/streams-aio.conf', raw)
        self.assertIn('source: pgdata', raw)
        self.assertIn('user: "1000:1000"', raw)
        self.assertNotIn('command:', raw)
        self.assertNotIn('POSTGRES_PASSWORD', raw)
        self.assertNotIn('DATABASE_URL', raw)

    def test_first_boot_adds_only_reviewed_supplemental_groups(self):
        root = Path('/home/test/streams-aio')
        raw = profile.overlay(root, first_boot=True).decode()
        self.assertTrue(raw.startswith(profile.overlay(root).decode()))
        self.assertIn('  oauth2-proxy:\n    group_add:\n      - "1000"', raw)
        self.assertIn('  pgbouncer:\n    group_add:\n      - "1000"', raw)
        base = model(root, first_boot=True)
        profile.first_boot_model(root, base)
        profile.candidate_model(root, base, effective(root, base, first_boot=True), first_boot=True)
        candidate = effective(root, base, first_boot=True)
        candidate['services']['oauth2-proxy']['user'] = '0:0'
        with self.assertRaisesRegex(profile.Refused, 'CANDIDATE_REFUSED'):
            profile.candidate_model(root, base, candidate, first_boot=True)
        base['services']['pgbouncer']['group_add'] = ['other-group']
        with self.assertRaisesRegex(profile.Refused, 'IMAGE_CHANGED'):
            profile.first_boot_model(root, base)

    def test_compose_pointer_changes_only_one_line_preserving_private_bytes(self):
        for quote in ('', "'", '"'):
            for end in (b'\n', b'\r\n'):
                with self.subTest(quote=quote, newline=end):
                    line = ('COMPOSE_FILE=' + quote + profile.BASE_COMPOSE + quote).encode()
                    private = b'PRIVATE="synthetic $ value"' + end
                    raw = private + line + end + b'# Preserve comments' + end
                    updated = profile.compose_line(raw, profile.BASE_COMPOSE, profile.EFFECTIVE_COMPOSE)
                    self.assertTrue(updated.startswith(private))
                    self.assertTrue(updated.endswith(end + b'# Preserve comments' + end))
                    profile.compose_line(updated, profile.EFFECTIVE_COMPOSE)
        for raw in (b'', b'COMPOSE_FILE=production\n',
                    ('COMPOSE_FILE=' + profile.BASE_COMPOSE + '\n') .encode() * 2):
            with self.subTest(raw=raw), self.assertRaisesRegex(profile.Refused, 'RUNTIME_PROFILE_ENV_REFUSED'):
                profile.compose_line(raw, profile.BASE_COMPOSE, profile.EFFECTIVE_COMPOSE)

    def test_missing_or_non_boolean_evidence_refuses(self):
        profile.evidence(facts())
        for key, value in facts().items():
            data = facts()
            data.pop(key)
            with self.subTest(key=key), self.assertRaisesRegex(profile.Refused, 'EVIDENCE_REQUIRED'):
                profile.evidence(data)
            if type(value) is bool:
                data = facts()
                data[key] = int(value)
                with self.subTest(integer=key), self.assertRaises(profile.Refused):
                    profile.evidence(data)

    def test_exact_base_layout_and_images_required(self):
        root = Path('/home/test/streams-aio')
        base = model(root)
        profile.base_model(root, base)
        cases = []
        changed = copy.deepcopy(base)
        changed['services']['postgres']['image'] = 'postgres:latest'
        cases.append(changed)
        changed = copy.deepcopy(base)
        changed['services']['postgres']['volumes'].pop()
        cases.append(changed)
        changed = copy.deepcopy(base)
        changed['services']['postgres']['environment']['PGDATA'] = '/existing/database'
        cases.append(changed)
        changed = copy.deepcopy(base)
        changed['volumes']['pgdata']['external'] = True
        cases.append(changed)
        changed = copy.deepcopy(base)
        changed['services']['postgres']['command'] = ['postgres', '-c', 'config_file=/custom']
        cases.append(changed)
        for case in cases:
            with self.subTest(case=case), self.assertRaises(profile.Refused):
                profile.base_model(root, case)

    def test_candidate_cannot_change_secrets_images_network_or_command(self):
        root = Path('/home/test/streams-aio')
        base = model(root)
        candidate = effective(root, base)
        profile.candidate_model(root, base, candidate)
        for service, field, value in (
                ('postgres', 'image', 'postgres:latest'),
                ('postgres', 'command', ['postgres', '-c', 'config_file=/custom']),
                ('dnscrypt-proxy', 'user', '0:0'),
                ('aiomanager', 'environment', {'DATABASE_URL': 'different'}),
                ('comet', 'ports', [{'published': '9999', 'target': 80}])):
            changed = copy.deepcopy(candidate)
            changed['services'][service][field] = value
            with self.subTest(service=service, field=field), \
                    self.assertRaisesRegex(profile.Refused, 'CANDIDATE_REFUSED'):
                profile.candidate_model(root, base, changed)

    def test_dependency_wave_moves_aiomanager_after_pgbouncer(self):
        root = Path('/home/test/streams-aio')
        data = effective(root, model(root))
        data['services']['postgres']['healthcheck'] = {'test': ['CMD', 'pg_isready']}
        original = [['aiomanager', 'postgres', 'dnscrypt-proxy'], ['pgbouncer'], ['comet']]
        result = profile.derived_waves(data, original)
        indexes = {name: i for i, wave in enumerate(result) for name in wave}
        self.assertGreater(indexes['aiomanager'], indexes['pgbouncer'])
        self.assertGreater(indexes['pgbouncer'], indexes['postgres'])
        self.assertEqual(original[0][0], 'aiomanager')
        cyclic = copy.deepcopy(data)
        cyclic['services']['postgres']['depends_on'] = {'pgbouncer': {'condition': 'service_started'}}
        with self.assertRaisesRegex(profile.Refused, 'DEPENDENCY_REFUSED'):
            profile.derived_waves(cyclic, original)
        missing = copy.deepcopy(data)
        missing['services']['pgbouncer']['depends_on']['foreign'] = {'condition': 'service_started'}
        with self.assertRaises(profile.Refused):
            profile.derived_waves(missing, original)

    def test_foreign_container_or_volume_cannot_be_adopted(self):
        root = Path('/home/test/streams-aio')
        base = model(root)
        def fixtures(foreign_container=False, foreign_volume=False):
            containers = [dict(Config=dict(Labels={
                'com.docker.compose.project': 'production' if foreign_container else 'streams-aio',
                'com.docker.compose.project.working_dir': str(root),
                'com.docker.compose.service': name})) for name in ('postgres', 'dnscrypt-proxy', 'aiomanager')]
            volumes = [dict(Name='streams-aio_' + key, Labels={
                'com.docker.compose.project': 'production' if foreign_volume else 'streams-aio',
                'com.docker.compose.volume': key}) for key in ('pgdata', 'postgres-cluster')]
            def run(args):
                if args[1] == 'ps': return b'a b c'
                if args[1] == 'inspect': return json.dumps(containers).encode()
                if args[2] == 'ls': return b'v1 v2'
                return json.dumps(volumes).encode()
            return run
        profile.owned_runtime(root, base, fixtures())
        for container, volume in ((True, False), (False, True)):
            with self.subTest(container=container), self.assertRaisesRegex(profile.Refused, 'OWNERSHIP_REFUSED'):
                profile.owned_runtime(root, base, fixtures(container, volume))

    def test_named_user_is_resolved_from_captured_readonly_tar(self):
        container = dict(Id='known-container', Config={'User': 'nonroot:nonroot'})
        calls = []
        def run(args):
            calls.append(args)
            name = args[2].rsplit('/', 1)[1]
            raw = {'passwd': b'nonroot:x:65532:65532:User:/home/nonroot:/bin/false\n',
                   'group': b'nonroot:x:65532:\n'}[name]
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w') as archive:
                item = tarfile.TarInfo(name)
                item.size = len(raw)
                archive.addfile(item, io.BytesIO(raw))
            return stream.getvalue()
        self.assertEqual(profile.container_account(run, container), (65532, 65532))
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(row[:2] == ['docker', 'cp'] for row in calls))


class HealthDependencies(unittest.TestCase):
    def fixture(self):
        return dict(services={
            'provider': {'image': 'example/provider@sha256:' + 'a' * 64},
            'consumer': {'depends_on': {'provider': {'condition': 'service_healthy'}}},
        })

    def test_image_inherited_health_is_accepted_and_cached_by_digest(self):
        data = self.fixture()
        data['services']['second-provider'] = dict(data['services']['provider'])
        data['services']['consumer']['depends_on']['second-provider'] = {'condition': 'service_healthy'}
        calls = []
        def run(args):
            calls.append(args)
            self.assertEqual(args[:5], ['docker', 'image', 'inspect', '--format', '{{json .Config.Healthcheck}}'])
            return b'{"Test":["CMD","health-program"],"Interval":1000000}'
        self.assertEqual(profile.health_dependency_issues(data, run), (0, 0))
        self.assertEqual(len(calls), 1)
        self.assertEqual(profile.derived_waves(data, [['provider', 'second-provider'], ['consumer']]),
                         [['provider', 'second-provider'], ['consumer']])

    def test_no_test_compose_override_still_inherits_image(self):
        for health in ({'interval': '10s'}, {'disable': False}, {'test': []}, {'test': None}):
            data = self.fixture()
            data['services']['provider']['healthcheck'] = health
            with self.subTest(health=health):
                self.assertEqual(profile.health_dependency_issues(
                    data, lambda args: b'{"Test":["CMD-SHELL","check"]}'), (0, 0))

    def test_explicit_disable_or_none_cannot_satisfy_healthy_dependency(self):
        for health in ({'disable': True}, {'test': ['NONE']}, {'test': 'NONE'}):
            data = self.fixture()
            data['services']['provider']['healthcheck'] = health
            def no_inspect(args):
                self.fail('An explicitly disabled override must not consult image health')
            with self.subTest(health=health):
                self.assertEqual(profile.health_dependency_issues(data, no_inspect), (1, 0))
                with self.assertRaisesRegex(profile.Refused, 'DEPENDENCY_REFUSED'):
                    profile.derived_waves(data, [['provider'], ['consumer']])

    def test_usable_explicit_override_needs_no_image_inspection(self):
        for test in (['CMD', 'check'], ['CMD-SHELL', 'check'], 'check'):
            data = self.fixture()
            data['services']['provider']['healthcheck'] = {'test': test}
            with self.subTest(test=test):
                self.assertEqual(profile.health_dependency_issues(
                    data, lambda args: self.fail('Explicit healthcheck is already effective')), (0, 0))

    def test_malformed_or_absent_actual_health_is_failure_not_pending(self):
        for raw in (b'null', b'{}', b'not-json', b'[]', b'{"Test":"check"}',
                    b'{"Test":["NONE"]}', b'{"Test":["CMD"]}', b'{"Test":["CMD",""]}'):
            with self.subTest(raw=raw):
                self.assertEqual(profile.health_dependency_issues(self.fixture(), lambda args: raw), (1, 0))
        for health in ({'test': ['CMD']}, {'test': [1, 2]}, {'test': 42}, {'disable': 1}):
            data = self.fixture()
            data['services']['provider']['healthcheck'] = health
            with self.subTest(override=health):
                self.assertEqual(profile.health_dependency_issues(
                    data, lambda args: self.fail('Malformed override must be refused first')), (1, 0))

    def test_unavailable_image_is_pending_and_unpinned_image_is_refused(self):
        def unavailable(args):
            raise OSError('synthetic local image unavailable')
        self.assertEqual(profile.health_dependency_issues(self.fixture(), unavailable), (0, 1))
        data = self.fixture()
        data['services']['provider']['image'] = 'example/provider:latest'
        self.assertEqual(profile.health_dependency_issues(
            data, lambda args: self.fail('Unpinned image must not be inspected')), (1, 0))

    def test_full_public_31_service_graph_accepts_comet_inherited_health(self):
        data = copy.deepcopy(PUBLIC_DEPENDENCIES)
        self.assertEqual(len(data['services']), 31)
        self.assertNotIn('healthcheck', data['services']['comet'])
        calls = []
        def inspect(args):
            calls.append(args)
            self.assertEqual(args[-1], data['services']['comet']['image'])
            return b'{"Test":["CMD","python","-m","comet.healthcheck"]}'
        self.assertEqual(profile.health_dependency_issues(data, inspect), (0, 0))
        self.assertEqual(len(calls), 1)
        self.assertEqual(profile.derived_waves(data, data['waves']), data['waves'])
        # The registered correction changes only AIOManager's provider order.
        data['services']['aiomanager']['depends_on'] = {'pgbouncer': {'condition': 'service_healthy'}}
        waves = profile.derived_waves(data, data['waves'])
        positions = {name: index for index, wave in enumerate(waves) for name in wave}
        self.assertGreater(positions['aiomanager'], positions['pgbouncer'])
        self.assertEqual(len(positions), 31)
        self.assertEqual(set(positions), set(data['services']))


class Transaction(unittest.TestCase):
    def setUp(self):
        directory = ROOT.parent/'gui-test-tmp' if os.name == 'nt' else None
        if directory is not None:
            directory.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=directory)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/'streams-aio'
        self.home = Path(self.temp.name)/'runner'
        self.root.mkdir()
        self.home.mkdir()
        (self.root/'.generated').mkdir()
        self.state = dict(schema=1, extra='preserved', completed=['PREFLIGHT'])
        (self.home/'state.json').write_text(json.dumps(self.state))
        names = ('docker-compose.yml', 'config/compose.dr.yaml', 'config/dr-manifest.yaml',
                 'data/postgres/.env', 'data/postgres/postgresql.conf', 'data/postgres/init/init.sql',
                 'data/dnscrypt-proxy/data/dnscrypt-proxy.toml')
        for name in names:
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('synthetic ' + name).encode())
        self.original_env = ('PRIVATE=synthetic\nCOMPOSE_FILE=\'' + profile.BASE_COMPOSE + '\'\n').encode()
        (self.root/'.env').write_bytes(self.original_env)
        self.model = model(self.root)
        self.patches = [patch.object(profile, 'scope', lambda root, home, state: (Path(root), Path(home))),
                        patch.object(profile, 'readonly_checks', lambda *args: {
                            'pgdata': 'streams-aio_pgdata', 'postgres-cluster': 'streams-aio_postgres-cluster'}),
                        patch.object(profile, 'regular', self.file_info),
                        patch.object(profile, 'private_directory', lambda path: None),
                        patch.object(profile, 'atomic', self.atomic)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.fail_commit = False

    def file_info(self, path):
        path = Path(path)
        self.assertTrue(path.is_file())
        if path == self.root/'.env': uid, gid, mode = 0, 1000, 0o640
        elif path in (self.root/profile.ARTIFACT, self.root/profile.TRIAL_PASSWORD): uid, gid, mode = 1000, 1000, 0o600
        else: uid, gid, mode = 0, 0, 0o600
        return N(st_uid=uid, st_gid=gid, st_mode=stat.S_IFREG | mode, st_nlink=1)

    def atomic(self, path, raw, mode, uid, gid):
        path = Path(path)
        if path == self.home/'state.json' and self.fail_commit:
            raise OSError('synthetic failure')
        path.write_bytes(raw)

    def fake_run(self, args):
        self.assertEqual(args[:3], ['docker', 'compose', '--env-file'])
        self.assertNotIn('up', args)
        self.assertNotIn('stop', args)
        self.assertNotIn('down', args)
        return json.dumps(effective(self.root, self.model)).encode()

    def test_success_registers_only_reviewed_pointer_and_keeps_sources(self):
        original = profile.source_hashes(self.root)
        result = profile.apply(self.root, self.home, self.state, self.model, facts(), self.fake_run)
        self.assertEqual(result, dict(applied=True, profile=profile.PROFILE))
        self.assertEqual(profile.source_hashes(self.root), original)
        self.assertEqual(self.state['extra'], 'preserved')
        self.assertEqual((self.home/profile.BACKUP).read_bytes(), self.original_env)
        self.assertTrue(profile.validate(self.root, self.home, self.state))
        def no_queries(args):
            self.fail('Idempotent validation must not reapply to an initialized database')
        again = profile.apply(self.root, self.home, self.state, {}, {}, no_queries)
        self.assertEqual(again, dict(applied=False, profile=profile.PROFILE))

    def test_commit_failure_rolls_back_pointer_and_artifact_but_preserves_backup(self):
        state_before = (self.home/'state.json').read_bytes()
        self.fail_commit = True
        with self.assertRaisesRegex(profile.Refused, 'TRANSACTION_FAILED'):
            profile.apply(self.root, self.home, self.state, self.model, facts(), self.fake_run)
        self.assertEqual((self.root/'.env').read_bytes(), self.original_env)
        self.assertEqual((self.home/'state.json').read_bytes(), state_before)
        self.assertNotIn('runtime_profile', self.state)
        self.assertFalse((self.root/profile.ARTIFACT).exists())
        self.assertEqual((self.home/profile.BACKUP).read_bytes(), self.original_env)

    def test_candidate_failure_never_changes_env_or_checkpoint(self):
        state_before = (self.home/'state.json').read_bytes()
        def bad(args):
            candidate = effective(self.root, self.model)
            candidate['services']['postgres']['environment']['POSTGRES_PASSWORD'] = 'changed'
            return json.dumps(candidate).encode()
        with self.assertRaisesRegex(profile.Refused, 'CANDIDATE_REFUSED'):
            profile.apply(self.root, self.home, self.state, self.model, facts(), bad)
        self.assertEqual((self.root/'.env').read_bytes(), self.original_env)
        self.assertEqual((self.home/'state.json').read_bytes(), state_before)
        self.assertFalse((self.root/profile.ARTIFACT).exists())

    def test_registered_artifact_source_or_env_drift_is_rejected(self):
        profile.apply(self.root, self.home, self.state, self.model, facts(), self.fake_run)
        original = (self.root/profile.ARTIFACT).read_bytes()
        (self.root/profile.ARTIFACT).write_bytes(original + b'# changed\n')
        with self.assertRaisesRegex(profile.Refused, 'PROFILE_CHANGED'):
            profile.validate(self.root, self.home, self.state)
        (self.root/profile.ARTIFACT).write_bytes(original)
        (self.root/'data/postgres/init/init.sql').write_bytes(b'changed SQL')
        with self.assertRaisesRegex(profile.Refused, 'SOURCE_CHANGED'):
            profile.validate(self.root, self.home, self.state)

    def test_registered_env_metadata_is_rechecked_before_reading_its_values(self):
        profile.apply(self.root, self.home, self.state, self.model, facts(), self.fake_run)
        for uid, gid, mode in ((65532, 1000, 0o600), (0, 0, 0o600), (1000, 1000, 0o644)):
            def bad_metadata(path):
                info = self.file_info(path)
                if Path(path) == self.root/'.env':
                    info.st_uid, info.st_gid, info.st_mode = uid, gid, stat.S_IFREG | mode
                return info
            with self.subTest(uid=uid, gid=gid, mode=mode), \
                    patch.object(profile, 'regular', bad_metadata), \
                    self.assertRaisesRegex(profile.Refused, 'ENV_REFUSED'):
                profile.validate(self.root, self.home, self.state)
        def replaced_env(path):
            if Path(path) == self.root/'.env':
                raise profile.Refused('RUNTIME_PROFILE_PATH_REFUSED')
            return self.file_info(path)
        with patch.object(profile, 'regular', replaced_env), \
                self.assertRaisesRegex(profile.Refused, 'PATH_REFUSED'):
            profile.validate(self.root, self.home, self.state)

    def test_orphan_artifact_is_never_adopted(self):
        (self.root/profile.ARTIFACT).write_bytes(profile.overlay(self.root))
        with self.assertRaisesRegex(profile.Refused, 'PROFILE_CHANGED'):
            profile.validate(self.root, self.home, self.state)

    def prepare_first_boot_fixture(self):
        self.model = model(self.root, first_boot=True)
        self.model['services']['comet']['image'] = profile.COMETNET_IMAGE
        self.model['services']['gluetun'] = {'image':'synthetic-gluetun'}
        self.model['services']['cometnet'] = dict(image=profile.COMETNET_IMAGE,
            entrypoint=['python','-m','comet.cometnet.standalone'],
            network_mode='service:gluetun', user='1000:1000',
            healthcheck={'test':['CMD','public-health']},
            environment={'COMETNET_LISTEN_PORT':'8765','COMETNET_HTTP_PORT':'8766'})
        self.state['completed'] = sorted(profile.FIRST_BOOT_STAGES)
        (self.home/'state.json').write_text(json.dumps(self.state))
        for name in ('data/oauth2-proxy/allowed-emails.txt', 'data/pgbouncer/data/pgbouncer.ini',
                     '.generated/pgbouncer/userlist.txt', 'scripts/dr.py'):
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'synthetic private file')
        patches = [patch.object(profile, 'identity_scope',
                    lambda root, home, state: (Path(root), Path(home))),
                   patch.object(profile, 'readonly_first_boot_checks', lambda *args: {
                       'pgdata': 'streams-aio_pgdata', 'postgres-cluster': 'streams-aio_postgres-cluster'})]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def fresh_run(self, args):
        self.assertEqual(args[:3], ['docker', 'compose', '--env-file'])
        result = effective(self.root, self.model, first_boot=True)
        raw = (self.root/profile.ARTIFACT).read_text()
        password = re.search(r'COMETNET_NETWORK_PASSWORD: "([0-9a-f]{64})"', raw).group(1)
        result['services']['cometnet']['environment'].update(profile.COMETNET_TRIAL_ENV)
        result['services']['cometnet']['environment']['COMETNET_NETWORK_PASSWORD'] = password
        return json.dumps(result).encode()

    def test_first_boot_transaction_registers_before_preparation_and_remains_idempotent(self):
        self.prepare_first_boot_fixture()
        original = profile.source_hashes(self.root, first_boot=True)
        result = profile.apply_fresh(self.root, self.home, self.state, self.model, self.fresh_run)
        self.assertEqual(result, dict(applied=True, profile=profile.COMETNET_TRIAL_PROFILE))
        self.assertEqual(self.state['runtime_profile']['origin'], 'FIRST_BOOT')
        self.assertEqual(profile.source_hashes(self.root, first_boot=True), original)
        self.assertTrue(profile.validate(self.root, self.home, self.state))
        self.state.update(preparation='PASS', application_start_attempted=True)
        self.state['completed'] += ['NPM', 'AIO']
        (self.home/'state.json').write_text(json.dumps(self.state))
        self.assertTrue(profile.validate(self.root, self.home, self.state))
        def no_queries(args):
            self.fail('Idempotent first-boot profile must not inspect or alter initialized data')
        self.assertEqual(profile.apply_fresh(self.root, self.home, self.state, {}, no_queries),
                         dict(applied=False, profile=profile.COMETNET_TRIAL_PROFILE))
        self.state['runtime_profile']['origin'] = 'guessed'
        with self.assertRaisesRegex(profile.Refused, 'PROFILE_CHANGED'):
            profile.validate(self.root, self.home, self.state)

    def test_older_prepared_checkpoint_registers_profile_without_replaying_private_databases(self):
        self.prepare_first_boot_fixture()
        self.state.update(preparation='PASS', application_start_attempted=False,
                          aio_recovery='MANUAL_PENDING', application_recovery='NOT_VERIFIED')
        self.state['completed'] += ['NPM', 'AIO']
        (self.home/'state.json').write_text(json.dumps(self.state))
        preserved = []
        for relative in ('data/npm/data/database.sqlite', 'data/aiostreams/data/db.sqlite',
                         'data/aiometadata/data/db.sqlite'):
            path = self.root/relative
            path.parent.mkdir(parents=True, exist_ok=True)
            with closing(sqlite3.connect(path)) as database:
                with database:
                    database.execute('CREATE TABLE preserved (value TEXT)')
                    database.execute('INSERT INTO preserved VALUES (?)', ('synthetic restored configuration',))
            preserved.append(path)
        marker = self.root/'.generated/aio-import-complete.json'
        marker.write_text(json.dumps(dict(root=str(self.root), synthetic=True)))
        preserved.append(marker)
        before_files = {path: path.read_bytes() for path in preserved}
        before_state = copy.deepcopy(self.state)
        result = profile.apply_fresh(self.root, self.home, self.state, self.model, self.fresh_run)
        self.assertEqual(result, dict(applied=True, profile=profile.COMETNET_TRIAL_PROFILE))
        self.assertEqual({key: value for key, value in self.state.items() if key != 'runtime_profile'}, before_state)
        self.assertEqual({path: path.read_bytes() for path in preserved}, before_files)
        self.assertTrue(profile.validate(self.root, self.home, self.state))
        self.assertEqual(profile.apply_fresh(self.root, self.home, self.state, {},
            lambda args: self.fail('Registered migration must not repeat any runtime operation')),
            dict(applied=False, profile=profile.COMETNET_TRIAL_PROFILE))

    def test_started_legacy_checkpoint_is_refused_before_any_runtime_or_artifact_write(self):
        self.prepare_first_boot_fixture()
        self.state.update(preparation='PASS', application_start_attempted=True)
        self.state['completed'] += ['NPM', 'AIO']
        (self.home/'state.json').write_text(json.dumps(self.state))
        before = (self.home/'state.json').read_bytes()
        with self.assertRaisesRegex(profile.Refused, '^RUNTIME_PROFILE_PRESTART_CHECKPOINT_REQUIRED$'):
            profile.apply_fresh(self.root, self.home, self.state, self.model,
                lambda args: self.fail('A started checkpoint must be refused before querying Docker'))
        self.assertEqual((self.home/'state.json').read_bytes(), before)
        self.assertEqual((self.root/'.env').read_bytes(), self.original_env)
        self.assertFalse((self.root/profile.ARTIFACT).exists())
        self.assertFalse((self.home/profile.BACKUP).exists())

    def test_legacy_migration_preserves_checkpoint_when_physical_host_is_not_empty_or_owned(self):
        self.prepare_first_boot_fixture()
        self.state.update(preparation='PASS', application_start_attempted=False)
        self.state['completed'] += ['NPM', 'AIO']
        (self.home/'state.json').write_text(json.dumps(self.state))
        before = (self.home/'state.json').read_bytes()
        for code in ('RUNTIME_PROFILE_FRESH_HOST_REQUIRED',
                     'RUNTIME_PROFILE_DOCKER_OWNERSHIP_REFUSED',
                     'RUNTIME_PROFILE_DATABASE_PRESENT'):
            with self.subTest(code=code), patch.object(profile, 'readonly_first_boot_checks',
                    side_effect=profile.Refused(code)), self.assertRaisesRegex(profile.Refused, '^' + code + '$'):
                profile.apply_fresh(self.root, self.home, self.state, self.model, self.fresh_run)
            self.assertEqual((self.home/'state.json').read_bytes(), before)
            self.assertEqual((self.root/'.env').read_bytes(), self.original_env)
            self.assertFalse((self.root/profile.ARTIFACT).exists())
            self.assertFalse((self.home/profile.BACKUP).exists())

    def test_first_boot_transaction_rolls_back_uncommitted_artifact_and_pointer(self):
        self.prepare_first_boot_fixture()
        before = (self.home/'state.json').read_bytes()
        self.fail_commit = True
        with self.assertRaisesRegex(profile.Refused, 'TRANSACTION_FAILED'):
            profile.apply_fresh(self.root, self.home, self.state, self.model, self.fresh_run)
        self.assertEqual((self.home/'state.json').read_bytes(), before)
        self.assertEqual((self.root/'.env').read_bytes(), self.original_env)
        self.assertFalse((self.root/profile.ARTIFACT).exists())
        self.assertEqual((self.home/profile.BACKUP).read_bytes(), self.original_env)


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() == 0,
                     'Real numeric UID/mode checks require the root Linux helper')
class LinuxFiles(unittest.TestCase):
    def test_first_boot_numeric_account_and_supplemental_group_read_private_binds(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            sql = base/'init'
            sql.mkdir()
            os.chown(sql, 70, 70)
            os.chmod(sql, 0o750)
            profile.atomic(sql/'init.sql', b'reviewed SQL', 0o640, 70, 70)
            self.assertTrue(profile.bind_readable(sql, 'init.sql', 70, 70))
            self.assertFalse(profile.bind_readable(sql, 'init.sql', 999, 999))
            allow = base/'allowed'
            allow.mkdir()
            os.chown(allow, 1000, 1000)
            os.chmod(allow, 0o750)
            profile.atomic(allow/'allowlist.txt', b'private allowlist', 0o640, 1000, 1000)
            profile.private_bind_metadata(allow/'allowlist.txt', 1000)
            self.assertFalse(profile.bind_readable(allow, 'allowlist.txt', 65532, 65532))
            self.assertTrue(profile.bind_readable(allow, 'allowlist.txt', 65532, 65532, groups=(1000,)))
            self.assertTrue(profile.bind_readable(allow, 'allowlist.txt', 70, 70, groups=(1000,)))

    def test_atomic_private_modes_and_empty_cluster_checks_reject_real_data(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            root = base/'stack'
            root.mkdir()
            conf = root/'data/postgres/postgresql.conf'
            conf.parent.mkdir(parents=True)
            conf.write_bytes(b'public configuration')
            volumes_root = base/'volumes'
            volumes = {}
            for key in ('pgdata', 'postgres-cluster'):
                mount = volumes_root/('streams-aio_' + key)/'_data'
                mount.mkdir(parents=True)
                volumes[key] = dict(Name='streams-aio_' + key, Mountpoint=str(mount))
            legacy = Path(volumes['pgdata']['Mountpoint'])
            (legacy/'postgresql.conf').write_bytes(b'')
            parent = Path(volumes['postgres-cluster']['Mountpoint'])
            (parent/'data').mkdir()
            with patch.object(profile, 'DOCKER_VOLUME_ROOT', volumes_root):
                profile.empty_clusters(volumes, root)
                (legacy/'PG_VERSION').write_bytes(b'18\n')
                with self.assertRaisesRegex(profile.Refused, 'DATABASE_PRESENT'):
                    profile.empty_clusters(volumes, root)
                (legacy/'PG_VERSION').unlink()
                (legacy/'unknown-state').mkdir()
                with self.assertRaisesRegex(profile.Refused, 'LAYOUT_REFUSED'):
                    profile.empty_clusters(volumes, root)
            destination = base/'private-artifact'
            profile.atomic(destination, b'known bytes', 0o600, 1000, 1000)
            info = destination.stat()
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (1000, 1000, 0o600))
            self.assertEqual(destination.read_bytes(), b'known bytes')
            os.link(destination, base/'second-link')
            with self.assertRaisesRegex(profile.Refused, 'PATH_REFUSED'):
                profile.env_metadata(destination)


if __name__ == '__main__':
    unittest.main()

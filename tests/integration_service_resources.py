"""Opt-in Linux/root roundtrip with real Docker, local volumes and age.

Only the two random Compose projects created here are removed. Identities and
plaintext capsules remain inside the private temporary test directory.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from remote import service_snapshot as snapshot

ENABLED=(os.environ.get('RUN_SERVICE_RESOURCES_INTEGRATION')=='1' and sys.platform=='linux'
         and hasattr(os,'geteuid') and os.geteuid()==0)
IMAGE_TAG='busybox:1.37.0'
RUN='20261025T190000Z'
COMMIT='a'*40


def invoke(args,code='INTEGRATION_COMMAND_FAILED'):
    result=subprocess.run([str(value) for value in args],capture_output=True,timeout=300,
        env={key:value for key,value in os.environ.items() if not key.startswith(('COMPOSE_','DOCKER_HOST','DOCKER_CONTEXT'))})
    if result.returncode!=0:raise AssertionError(code)
    return result.stdout


def runtime_runner(args,code):
    return invoke(args,code)


def compose(root,project,*arguments):
    return invoke(['docker','compose','--project-directory',root,'-f',root/'docker-compose.yml',
                   '-p',project,*arguments],'INTEGRATION_COMPOSE_FAILED')


def healthy(root,project):
    for _ in range(60):
        identities=compose(root,project,'ps','-a','-q','--','fixture').decode().split()
        if len(identities)==1:
            value=json.loads(invoke(['docker','inspect','--format','{{json .State}}',identities[0]]))
            if value.get('Status')=='running' and value.get('Health',{}).get('Status')=='healthy':return
            if value.get('Status') in ('exited','dead'):raise AssertionError('INTEGRATION_CONTAINER_EXITED')
        time.sleep(1)
    raise AssertionError('INTEGRATION_HEALTH_TIMEOUT')


def write_stack(root,project,pinned,inventory_raw):
    root.mkdir(mode=0o700)
    (root/'config').mkdir(mode=0o700)
    (root/snapshot.INVENTORY).write_bytes(inventory_raw)
    script=r"""test -S /var/run/docker.sock
if [ ! -f /bind/record.bin ]; then printf 'bind\000\001payload\n' > /bind/record.bin; fi
if [ ! -f /volume/record.bin ]; then printf 'volume\000\002payload\n' > /volume/record.bin; fi
while :; do sleep 3600; done
"""
    document={'services':{'fixture':{'image':pinned,'network_mode':'none',
        'command':['sh','-ec',script],
        'healthcheck':{'test':['CMD-SHELL','test -s /bind/record.bin && test -s /volume/record.bin && test -S /var/run/docker.sock'],
                       'interval':'1s','timeout':'3s','retries':30},
        'volumes':[{'type':'bind','source':'./data/fixture/bind','target':'/bind'},
                   {'type':'volume','source':'fixture-data','target':'/volume'},
                   {'type':'bind','source':'/var/run/docker.sock','target':'/var/run/docker.sock','read_only':True}]}},
        'volumes':{'fixture-data':{'name':project+'-data','driver':'local'}}}
    (root/'docker-compose.yml').write_text(json.dumps(document),encoding='utf-8')


@unittest.skipUnless(ENABLED,'Requires explicit RUN_SERVICE_RESOURCES_INTEGRATION=1 on Linux as root')
class RealServiceResourcesIntegration(unittest.TestCase):
    def test_stopped_bind_named_volume_and_runtime_socket_roundtrip(self):
        for executable in ('docker','age','age-keygen'):
            self.assertIsNotNone(shutil.which(executable),'INTEGRATION_DEPENDENCY_MISSING')
        invoke(['docker','info','--format','{{.ServerVersion}}'],'INTEGRATION_DOCKER_REQUIRED')
        invoke(['docker','compose','version'],'INTEGRATION_COMPOSE_REQUIRED')
        self.assertTrue(Path('/var/run/docker.sock').is_socket(),'INTEGRATION_SOCKET_REQUIRED')
        projects=[]
        with tempfile.TemporaryDirectory(prefix='services-real-integration-') as temporary:
            base=Path(temporary).resolve();base.chmod(0o700)
            try:
                invoke(['docker','pull',IMAGE_TAG],'INTEGRATION_IMAGE_PULL_FAILED')
                identities=json.loads(invoke(['docker','image','inspect','--format','{{json .RepoDigests}}',IMAGE_TAG]))
                pins=[image for image in identities if isinstance(image,str) and image.split('@',1)[0] in ('busybox','docker.io/library/busybox')]
                self.assertTrue(pins,'INTEGRATION_IMAGE_DIGEST_REQUIRED')
                pinned=pins[0]
                suffix=uuid.uuid4().hex[:12]
                source_project='recovery-svc-'+suffix+'-source'
                fresh_project='recovery-svc-'+suffix+'-restored'
                source=base/'source';fresh=base/'restored'
                inventory={'schema':1,'configuration_files':[],'resources':[
                    {'id':'fixture-bind','service':'fixture','type':'bind','source':'data/fixture/bind','target':'/bind',
                     'read_only':False,'role':'data','recovery':{'method':'stopped_archive'}},
                    {'id':'fixture-volume','service':'fixture','type':'volume','source':'fixture-data','target':'/volume',
                     'read_only':False,'role':'data','recovery':{'method':'stopped_archive'}},
                    {'id':'fixture-runtime','service':'fixture','type':'bind','source':'/var/run/docker.sock','target':'/var/run/docker.sock',
                     'read_only':True,'role':'runtime','recovery':{'method':'recreate'}}]}
                inventory_raw=snapshot.canonical(inventory)
                write_stack(source,source_project,pinned,inventory_raw)
                (source/'data/fixture/bind').mkdir(parents=True,mode=0o750)
                projects.append((source,source_project))
                compose(source,source_project,'up','-d','--pull','never')
                healthy(source,source_project)
                model=json.loads(compose(source,source_project,'config','--format','json'))
                archive=base/'services-state.tar.gz'
                manifest=snapshot.capture(source,archive,run_id=RUN,source_commit=COMMIT,model=model,
                                          images={'fixture':pinned},runner=runtime_runner)
                self.assertEqual({entry['id'] for entry in manifest['entries']},{'fixture-bind','fixture-volume'})
                healthy(source,source_project)  # Capture must restart the real writer.
                original_archive=archive.read_bytes()
                original_hash=hashlib.sha256(original_archive).hexdigest()
                # Real age encrypts to two ephemeral identities; either identity
                # must independently recover exactly the captured archive bytes.
                recipients=[];identities=[]
                for number in (1,2):
                    identity=base/('identity-'+str(number)+'.txt')
                    invoke(['age-keygen','-o',identity],'INTEGRATION_IDENTITY_FAILED')
                    identity.chmod(0o600);identities.append(identity)
                    recipients.append(invoke(['age-keygen','-y',identity],'INTEGRATION_IDENTITY_FAILED').decode().strip())
                self.assertNotEqual(recipients[0],recipients[1])
                encrypted=base/'services-state.tar.gz.age'
                invoke(['age','--encrypt','-r',recipients[0],'-r',recipients[1],'-o',encrypted,archive],
                       'INTEGRATION_ENCRYPTION_FAILED')
                self.assertTrue(encrypted.read_bytes().startswith(b'age-encryption.org/v1\n'))
                for number,identity in enumerate(identities,1):
                    recovered=base/('decrypted-'+str(number)+'.tar.gz')
                    invoke(['age','--decrypt','-i',identity,'-o',recovered,encrypted],'INTEGRATION_DECRYPTION_FAILED')
                    self.assertEqual(snapshot.digest(recovered),original_hash)
                    self.assertEqual(recovered.read_bytes(),original_archive)
                compose(source,source_project,'down','--volumes','--remove-orphans')
                write_stack(fresh,fresh_project,pinned,inventory_raw)
                projects.append((fresh,fresh_project))
                fresh_model=json.loads(compose(fresh,fresh_project,'config','--format','json'))
                evidence=snapshot.restore(archive,fresh,run_id=RUN,source_commit=COMMIT,model=fresh_model,runner=runtime_runner)
                evidence.pop('checkpoint')
                self.assertEqual(snapshot.verify_restored(fresh,archive,evidence,fresh_model,
                    before_start=True,runner=runtime_runner),evidence)
                self.assertEqual((fresh/'data/fixture/bind/record.bin').read_bytes(),b'bind\x00\x01payload\n')
                destinations=snapshot.paths(fresh,inventory,fresh_model,runtime_runner)
                self.assertEqual((destinations['fixture-volume']/'record.bin').read_bytes(),b'volume\x00\x02payload\n')
                self.assertEqual(snapshot.digest(archive),original_hash)
                compose(fresh,fresh_project,'up','-d','--pull','never')
                healthy(fresh,fresh_project)
                snapshot.verify_restored(fresh,archive,evidence,fresh_model,before_start=False,runner=runtime_runner)
            finally:
                # The generated project names and local Compose files delimit
                # cleanup; no global container, volume or image pruning occurs.
                cleanup_failed=False
                for root,project in reversed(projects):
                    try:compose(root,project,'down','--volumes','--remove-orphans')
                    except Exception:cleanup_failed=True
                if cleanup_failed:raise AssertionError('INTEGRATION_PROJECT_CLEANUP_FAILED')


if __name__=='__main__':unittest.main()

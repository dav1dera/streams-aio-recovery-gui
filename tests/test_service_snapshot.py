"""Real filesystem archive roundtrips; Docker calls use an explicit fake runner."""
import copy
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from remote import service_snapshot as snapshot

RUN='20261025T190000Z'
COMMIT='a'*40
IMAGE='example/test@sha256:'+'b'*64


class DockerFixture:
    """Only container state/metadata is simulated, never the archive filesystem."""
    def __init__(self, root, services):
        self.calls=[]
        self.rows=[]
        self.fail_stop=False
        for index, (name, sources) in enumerate(services.items()):
            self.rows.append(dict(Id=str(index+1)*64,Image='sha256:'+name,
                Config={'Labels':{'com.docker.compose.service':name,'com.docker.compose.project.working_dir':str(root)}},
                State={'Running':True},Mounts=[{'Source':str(source),'RW':True} for source in sources]))
        self.volumes={}

    def __call__(self,args,code):
        args=list(map(str,args));self.calls.append(args)
        if args[:3]==['docker','ps','-aq']:
            return '\n'.join(row['Id'] for row in self.rows).encode()
        if args[:2]==['docker','inspect']:
            return json.dumps(self.rows).encode()
        if args[:3]==['docker','image','inspect']:
            return json.dumps([{'RepoDigests':[IMAGE]}]).encode()
        if args[:2]==['docker','stop']:
            for row in self.rows:
                if row['Id'] in args[4:]: row['State']['Running']=False
            if self.fail_stop: raise snapshot.Refused(code)
            return b''
        if args[:2]==['docker','start']:
            for row in self.rows:
                if row['Id'] in args[2:]: row['State']['Running']=True
            return b''
        if args[:3]==['docker','volume','ls']:
            return '\n'.join(self.volumes).encode()
        if args[:3]==['docker','volume','inspect']:
            return json.dumps([{'Driver':'local','Options':None,'Mountpoint':str(self.volumes[args[3]])}]).encode()
        raise AssertionError('Unexpected fake Docker command: '+str(args))


class SnapshotFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.base=Path(self.temporary.name)
        self.root=self.base/'stack';self.root.mkdir()
        (self.root/'config').mkdir();(self.root/'data').mkdir()
        self.first=self.root/'data/demo/state';self.first.mkdir(parents=True)
        self.second=self.root/'data/second/state';self.second.mkdir(parents=True)
        (self.first/'nested').mkdir()
        (self.first/'nested/file.bin').write_bytes(bytes(range(256))*100)
        (self.first/'empty').write_bytes(b'')
        (self.second/'db.sqlite').write_bytes(b'closed-database-fixture\x00bytes')
        self.value={'schema':1,'resources':[self.resource('one','demo','data/demo/state','/state'),
            self.resource('two','second','data/second/state','/state')],'configuration_files':[]}
        self.write_inventory()
        self.model={'services':{'demo':{'image':IMAGE,'volumes':[{'type':'bind','source':str(self.first),'target':'/state'}]},
                                'second':{'image':IMAGE,'volumes':[{'type':'bind','source':str(self.second),'target':'/state'}]}}}
        self.docker=DockerFixture(self.root,{'demo':[self.first],'second':[self.second]})
        self.archive=self.base/'services.tar.gz'

    def tearDown(self): self.temporary.cleanup()

    @staticmethod
    def resource(identifier,service,source,target):
        return dict(id=identifier,service=service,type='bind',source=source,target=target,
                    read_only=False,role='data',recovery={'method':'stopped_archive'})

    def write_inventory(self):
        # Deliberate indentation proves capsule/release hashes bind exact public bytes.
        (self.root/snapshot.INVENTORY).write_text(json.dumps(self.value,indent=2)+'\n',encoding='utf-8')

    def capture(self):
        return snapshot.capture(self.root,self.archive,run_id=RUN,source_commit=COMMIT,
            model=self.model,images={'demo':IMAGE,'second':IMAGE},runner=self.docker)

    def empty_targets(self):
        for target in (self.first,self.second):
            shutil.rmtree(target);target.mkdir()
        for row in self.docker.rows: row['State']['Running']=False

    def restore(self):
        return snapshot.restore(self.archive,self.root,run_id=RUN,source_commit=COMMIT,model=self.model,runner=self.docker)

    def rewrite_archive(self, transform):
        with tarfile.open(self.archive,'r:gz') as bundle:
            entries=[(copy.copy(item),bundle.extractfile(item).read() if item.isfile() else None) for item in bundle.getmembers()]
        transform(entries)
        self.archive.unlink()
        with tarfile.open(self.archive,'w:gz') as bundle:
            for item,raw in entries:
                if raw is not None:item.size=len(raw)
                bundle.addfile(item,io.BytesIO(raw) if raw is not None else None)

    def test_roundtrip_real_directories_binary_empty_files_and_metadata(self):
        if os.name!='nt':(self.first/'nested/file.bin').chmod(0o640)
        result=self.capture()
        self.assertEqual(result['inventory_sha256'],snapshot.digest(self.root/snapshot.INVENTORY))
        self.assertTrue(all(row['State']['Running'] for row in self.docker.rows))
        self.empty_targets();receipt=self.restore()
        self.assertEqual((self.first/'nested/file.bin').read_bytes(),bytes(range(256))*100)
        self.assertEqual((self.first/'empty').read_bytes(),b'')
        self.assertEqual((self.second/'db.sqlite').read_bytes(),b'closed-database-fixture\x00bytes')
        self.assertEqual(receipt['resources'],['one','two'])
        self.assertEqual(json.loads(Path(receipt['checkpoint']).read_bytes())['phase'],'COMPLETE')
        if os.name!='nt':self.assertEqual((self.first/'nested/file.bin').stat().st_mode&0o777,0o640)

    def test_capture_failure_and_partial_stop_always_restart_original_writers(self):
        self.docker.fail_stop=True
        with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_STOP_FAILED'):self.capture()
        self.assertTrue(all(row['State']['Running'] for row in self.docker.rows))
        self.assertTrue(any(args[:2]==['docker','start'] for args in self.docker.calls))

    def test_archive_failure_always_restarts_original_writers(self):
        with patch.object(tarfile.TarFile,'add',side_effect=OSError('fixture I/O failure')):
            with self.assertRaises(OSError):self.capture()
        self.assertTrue(all(row['State']['Running'] for row in self.docker.rows))

    def test_second_install_failure_rolls_back_first_and_original_empty_targets(self):
        self.capture();self.empty_targets()
        first_identity=self.first.stat().st_ino
        original_replace=os.replace
        fail=[True]
        def replace(source,destination):
            if fail[0] and Path(source).name=='content' and Path(destination)==self.second:
                fail[0]=False;raise OSError('fixture second install failure')
            return original_replace(source,destination)
        with patch.object(snapshot.os,'replace',side_effect=replace):
            with self.assertRaises(OSError):self.restore()
        self.assertEqual(list(self.first.iterdir()),[])
        self.assertEqual(list(self.second.iterdir()),[])
        self.assertEqual(self.first.stat().st_ino,first_identity)
        checkpoint=next(self.base.glob('.services-restore-*.json'))
        self.assertEqual(json.loads(checkpoint.read_bytes())['phase'],'ROLLED_BACK')
        self.assertFalse(list(self.root.rglob('.service-restore-*')))
        # A clean rollback can safely be retried in the same private work folder.
        self.restore()
        self.assertTrue((self.first/'nested/file.bin').exists())

    def test_invalid_late_archive_member_never_installs_any_data(self):
        self.capture();self.empty_targets()
        def malicious(entries):
            item=tarfile.TarInfo('data/two/../../escape');item.size=3
            entries.append((item,b'bad'))
        self.rewrite_archive(malicious)
        with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_UNSAFE_ARCHIVE'):self.restore()
        self.assertEqual(list(self.first.iterdir()),[]);self.assertEqual(list(self.second.iterdir()),[])
        self.assertFalse((self.root/'escape').exists())

    def test_links_in_archive_are_refused_before_install(self):
        self.capture();self.empty_targets()
        def malicious(entries):
            item=tarfile.TarInfo('data/two/linked');item.type=tarfile.SYMTYPE;item.linkname='/etc/shadow'
            entries.append((item,None))
        self.rewrite_archive(malicious)
        with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_UNSAFE_ARCHIVE'):self.restore()
        self.assertEqual(list(self.first.iterdir()),[])

    def test_capture_refuses_filesystem_hardlinks_and_restarts_services(self):
        try:os.link(self.first/'empty',self.first/'linked')
        except OSError:self.skipTest('Host filesystem does not allow hardlinks')
        with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_DATA_LINK_UNSUPPORTED'):self.capture()
        self.assertTrue(all(row['State']['Running'] for row in self.docker.rows))

    def test_runtime_and_config_resources_never_enter_archive(self):
        self.value['resources'] += [dict(id='config',service='demo',type='config',source='config:settings',target='/settings',
                read_only=True,role='config',recovery={'method':'recreate'}),
            dict(id='runtime',service='demo',type='bind',source='/var/run/docker.sock',target='/var/run/docker.sock',
                read_only=True,role='runtime',recovery={'method':'recreate'})]
        self.write_inventory();self.capture()
        with tarfile.open(self.archive) as bundle:
            self.assertFalse(any('runtime' in item.name or 'config' in item.name for item in bundle.getmembers()))

    def test_raw_inventory_binding_and_image_binding_are_required(self):
        self.capture();self.empty_targets()
        self.model['services']['demo']['image']='example/other@sha256:'+'c'*64
        with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_IMAGES_CHANGED'):self.restore()
        self.model['services']['demo']['image']=IMAGE
        (self.root/snapshot.INVENTORY).write_bytes((self.root/snapshot.INVENTORY).read_bytes()+b'\n')
        with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_BINDING_MISMATCH'):self.restore()
        self.assertEqual(list(self.first.iterdir()),[])

    def test_existing_data_and_external_writers_are_not_overwritten(self):
        self.capture()
        for row in self.docker.rows:row['State']['Running']=False
        with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_EXISTING_DATA_REFUSED'):self.restore()
        self.archive.unlink()
        external=copy.deepcopy(self.docker.rows[0]);external['Id']='f'*64
        external['State']['Running']=True
        external['Config']['Labels']['com.docker.compose.project.working_dir']='/another/stack'
        self.docker.rows.append(external)
        with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_EXTERNAL_WRITER_REFUSED'):self.capture()
        self.assertTrue(self.docker.rows[-1]['State']['Running'])

    def test_named_volume_root_can_be_saved_but_cannot_contain_its_own_archive(self):
        volume=self.base/'docker-volumes/demo/_data';volume.mkdir(parents=True)
        (volume/'state').write_bytes(b'volume bytes')
        self.value['resources'][0].update(type='volume',source='demo-state')
        self.write_inventory()
        self.model['volumes']={'demo-state':{'name':'project_demo-state','driver':'local'}}
        self.model['services']['demo']['volumes'][0].update(type='volume',source='demo-state')
        self.docker.rows[0]['Mounts'][0]['Source']=str(volume)
        self.docker.volumes['project_demo-state']=volume
        self.capture();self.archive.unlink()
        self.archive=volume/'cannot-save-here.tar.gz'
        with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_PRIVATE_OUTPUT_REQUIRED'):self.capture()
        self.assertFalse(self.archive.exists())

    def test_interrupted_checkpoint_requires_review(self):
        self.capture();self.empty_targets()
        checkpoint=self.base/('.services-restore-'+snapshot.digest(self.archive)[:16]+'.json')
        checkpoint.write_bytes(snapshot.canonical({'archive_sha256':snapshot.digest(self.archive),'phase':'INSTALLING','targets':[]}))
        with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_INTERRUPTED_REVIEW_REQUIRED'):self.restore()
        self.assertEqual(list(self.first.iterdir()),[])

    def test_regular_file_mount_roundtrip_without_existing_destination(self):
        shutil.rmtree(self.first)
        self.first=self.root/'data/demo/database.sqlite'
        self.first.write_bytes(b'file mount bytes\x00end')
        self.value['resources'][0]['source']='data/demo/database.sqlite';self.write_inventory()
        self.model['services']['demo']['volumes'][0]['source']=str(self.first)
        self.docker.rows[0]['Mounts'][0]['Source']=str(self.first)
        self.capture();self.first.unlink();shutil.rmtree(self.second);self.second.mkdir()
        for row in self.docker.rows:row['State']['Running']=False
        self.restore()
        self.assertEqual(self.first.read_bytes(),b'file mount bytes\x00end')
        self.assertTrue((self.second/'db.sqlite').exists())

    def test_named_local_volume_roundtrip_restores_actual_volume_directory(self):
        volume=self.base/'docker-volumes/demo/_data';volume.mkdir(parents=True)
        (volume/'nested').mkdir();(volume/'nested/state').write_bytes(b'local named volume data')
        self.value['resources'][0].update(type='volume',source='demo-state');self.write_inventory()
        self.model['volumes']={'demo-state':{'name':'project_demo-state','driver':'local'}}
        self.model['services']['demo']['volumes'][0].update(type='volume',source='demo-state')
        self.docker.rows[0]['Mounts'][0]['Source']=str(volume)
        self.docker.volumes['project_demo-state']=volume
        self.capture();shutil.rmtree(volume);volume.mkdir()
        shutil.rmtree(self.second);self.second.mkdir()
        for row in self.docker.rows:row['State']['Running']=False
        self.restore()
        self.assertEqual((volume/'nested/state').read_bytes(),b'local named volume data')

    def test_writer_started_during_restore_preserves_data_for_review(self):
        self.capture();self.empty_targets()
        original_replace=os.replace;fail=[True]
        def replace(source,destination):
            if fail[0] and Path(source).name=='content' and Path(destination)==self.second:
                fail[0]=False
                self.docker.rows[0]['State']['Running']=True
                raise OSError('fixture concurrent writer')
            return original_replace(source,destination)
        with patch.object(snapshot.os,'replace',side_effect=replace):
            with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_RESTORE_REVIEW_REQUIRED'):self.restore()
        self.assertTrue((self.first/'nested/file.bin').exists())
        checkpoint=next(self.base.glob('.services-restore-*.json'))
        journal=json.loads(checkpoint.read_bytes())
        self.assertEqual(journal['phase'],'REVIEW_REQUIRED')
        self.assertTrue(any(Path(row['temporary']).exists() for row in journal['targets']))

    def test_verify_restored_detects_changed_bytes_extra_and_missing_files_before_start(self):
        self.capture();self.empty_targets();receipt=self.restore();receipt.pop('checkpoint')
        self.assertEqual(snapshot.verify_restored(self.root,self.archive,receipt,self.model,runner=self.docker),receipt)
        file=self.first/'nested/file.bin';original=file.read_bytes();file.write_bytes(b'changed')
        with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_RESTORED_DATA_CHANGED'):
            snapshot.verify_restored(self.root,self.archive,receipt,self.model,runner=self.docker)
        file.write_bytes(original)
        extra=self.first/'new-data';extra.write_bytes(b'extra')
        with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_RESTORED_DATA_CHANGED'):
            snapshot.verify_restored(self.root,self.archive,receipt,self.model,runner=self.docker)
        extra.unlink();(self.first/'empty').unlink()
        with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_RESTORED_DATA_CHANGED'):
            snapshot.verify_restored(self.root,self.archive,receipt,self.model,runner=self.docker)

    def test_verify_after_start_allows_application_writes_but_keeps_binding_and_target_checks(self):
        self.capture();self.empty_targets();receipt=self.restore();receipt.pop('checkpoint')
        for row in self.docker.rows:row['State']['Running']=True
        (self.first/'nested/file.bin').write_bytes(b'legitimate application write')
        self.assertEqual(snapshot.verify_restored(self.root,self.archive,receipt,self.model,before_start=False,runner=self.docker),receipt)
        self.model['services']['demo']['image']='other/image@sha256:'+'d'*64
        with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_IMAGES_CHANGED'):
            snapshot.verify_restored(self.root,self.archive,receipt,self.model,before_start=False,runner=self.docker)
        self.model['services']['demo']['image']=IMAGE
        shutil.rmtree(self.first)
        with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_SOURCE_MISSING'):
            snapshot.verify_restored(self.root,self.archive,receipt,self.model,before_start=False,runner=self.docker)

    def test_verify_rejects_changed_archive_receipt_and_inventory(self):
        self.capture();self.empty_targets();receipt=self.restore();receipt.pop('checkpoint')
        changed=dict(receipt,archive_sha256='0'*64)
        with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_CHECKPOINT_CHANGED'):
            snapshot.verify_restored(self.root,self.archive,changed,self.model,runner=self.docker)
        path=self.root/snapshot.INVENTORY;path.write_bytes(path.read_bytes()+b'\n')
        with self.assertRaisesRegex(snapshot.Refused,'SERVICES_STATE_CHECKPOINT_CHANGED'):
            snapshot.verify_restored(self.root,self.archive,receipt,self.model,runner=self.docker)


if __name__=='__main__':unittest.main()

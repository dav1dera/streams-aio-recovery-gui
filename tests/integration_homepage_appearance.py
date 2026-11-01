"""Opt-in real Homepage v2.7/Chromium appearance check using public synthetic data."""
from contextlib import suppress
import json,os,shutil,socket,subprocess,sys,tempfile,time,unittest,uuid
from pathlib import Path
from urllib.error import URLError
from urllib.request import ProxyHandler,build_opener
import yaml

ROOT=Path(__file__).resolve().parents[1]
FIXTURE=ROOT/'tests/homepage-appearance-fixture'
ENABLED=os.environ.get('RUN_HOMEPAGE_APPEARANCE_INTEGRATION')=='1'
HOMEPAGE_IMAGE='ghcr.io/gethomepage/homepage:v2.7.0'
FIXTURE_IMAGE='python:3.12-slim'

def invoke(arguments,code,*,timeout=300,env=None,logfile=None):
    clean={key:value for key,value in (env or os.environ).items() if not key.startswith('COMPOSE_') and key not in ('DOCKER_HOST','DOCKER_CONTEXT')}
    try:
        result=subprocess.run([str(x) for x in arguments],capture_output=True,timeout=timeout,env=clean)
    except (OSError,subprocess.SubprocessError):
        raise AssertionError(code) from None
    if logfile is not None:
        Path(logfile).write_bytes(result.stdout+b"\n"+result.stderr)
    if result.returncode:
        raise AssertionError(code) from None
    return result.stdout

def loopback_port():
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as stream:
        stream.bind(('127.0.0.1',0));return stream.getsockname()[1]

@unittest.skipUnless(ENABLED,'Requires RUN_HOMEPAGE_APPEARANCE_INTEGRATION=1 and isolated Linux Docker/Chromium')
class HomepageAppearance(unittest.TestCase):
    def test_real_homepage_theme_at_four_viewports(self):
        self.assertEqual(os.name,'posix','HOMEPAGE_APPEARANCE_LINUX_REQUIRED')
        node=shutil.which(os.environ.get('NODE_BINARY','node'))
        self.assertIsNotNone(node,'HOMEPAGE_APPEARANCE_NODE_REQUIRED')
        invoke(['docker','info','--format','{{.ServerVersion}}'],'HOMEPAGE_APPEARANCE_DOCKER_REQUIRED')
        invoke(['docker','compose','version'],'HOMEPAGE_APPEARANCE_COMPOSE_REQUIRED')
        project='homepage-appearance-'+uuid.uuid4().hex[:12]
        artifacts=Path(os.environ.get('RECOVERY_APPEARANCE_ARTIFACT_DIR',str(ROOT/'.artifacts/homepage-appearance'))).resolve()
        artifacts.mkdir(parents=True,exist_ok=True)
        port=loopback_port()
        with tempfile.TemporaryDirectory(prefix='homepage-appearance-') as temporary:
            area=Path(temporary).resolve();config=area/'config';config.mkdir(mode=0o755)
            for name in ('settings.yaml','services.yaml','widgets.yaml','custom.css','docker.yaml','bookmarks.yaml','kubernetes.yaml','proxmox.yaml','custom.js'):
                target=config/name;target.write_bytes((FIXTURE/name).read_bytes());target.chmod(0o644)
            document={'name':project,'services':{
                'glances-fixture':{'image':FIXTURE_IMAGE,'command':['python','/fixture/glances_fixture.py','--port','61208'],
                    'volumes':[{'type':'bind','source':str(FIXTURE),'target':'/fixture','read_only':True}],
                    'networks':['appearance']},
                'homepage':{'image':HOMEPAGE_IMAGE,'ports':['127.0.0.1:'+str(port)+':3000'],
                    'environment':{'HOMEPAGE_ALLOWED_HOSTS':'127.0.0.1:'+str(port)+',localhost:'+str(port),'TZ':'UTC','HOSTNAME':'0.0.0.0','LOG_TARGETS':'both'},
                    'volumes':[{'type':'bind','source':str(config),'target':'/app/config','read_only':True}],
                    'tmpfs':['/app/logs:rw,nosuid,nodev,size=16777216,mode=1777'],
                    'depends_on':['glances-fixture'],'networks':['frontend','appearance']}},
                'networks':{'frontend':{},'appearance':{'internal':True}}}
            compose=area/'compose.yaml';compose.write_text(yaml.safe_dump(document,sort_keys=False),encoding='utf-8')
            base=['docker','compose','--project-name',project,'--file',compose]
            started=False;passed=False
            try:
                invoke([*base,'pull'],'HOMEPAGE_APPEARANCE_IMAGE_PULL_FAILED',timeout=600)
                started=True
                invoke([*base,'up','-d'],'HOMEPAGE_APPEARANCE_START_FAILED')
                # Published ports require a non-internal gateway network; the
                # fake Glances backend stays attached only to the internal one.
                published=invoke([*base,'port','homepage','3000'],'HOMEPAGE_APPEARANCE_PORT_QUERY_FAILED').decode().strip()
                self.assertEqual(published,'127.0.0.1:'+str(port),'HOMEPAGE_APPEARANCE_PORT_NOT_PUBLISHED')
                (artifacts/'runtime-status.json').write_text(json.dumps({'published_port':published,'homepage_image':HOMEPAGE_IMAGE,'fixture_network':'internal','frontend_network':'loopback-published'},indent=2)+'\n',encoding='utf-8')
                origin='http://127.0.0.1:'+str(port)
                opener=build_opener(ProxyHandler({}));deadline=time.monotonic()+120
                while time.monotonic()<deadline:
                    try:
                        with opener.open(origin+'/api/healthcheck',timeout=3) as response:
                            if response.status==200:break
                    except (OSError,URLError):pass
                    time.sleep(1)
                else:raise AssertionError('HOMEPAGE_APPEARANCE_START_TIMEOUT')
                env=dict(os.environ,APPEARANCE_BASE_URL=origin,APPEARANCE_FIXTURE_DIR=str(FIXTURE),APPEARANCE_OUTPUT_DIR=str(artifacts))
                invoke([node,FIXTURE/'check_appearance.cjs'],'HOMEPAGE_APPEARANCE_BROWSER_FAILED',timeout=180,env=env,logfile=artifacts/'browser.log')
                result=json.loads((artifacts/'appearance-results.json').read_text(encoding='utf-8'))
                self.assertEqual(result.get('status'),'PASS')
                self.assertEqual(result.get('real_homepage_version'),'v2.7.0')
                self.assertEqual(result.get('service_links'),23)
                self.assertEqual(result.get('visible_container_rows'),5)
                self.assertEqual(len(result.get('viewports',[])),4)
                for width in (1280,1600,2560,390):
                    self.assertTrue((artifacts/('homepage-'+str(width)+'.png')).is_file())
                passed=True
            finally:
                if started:
                    with suppress(Exception):
                        logs=invoke([*base,'logs','--no-color','--tail','100'],'HOMEPAGE_APPEARANCE_LOGS_FAILED')
                        (artifacts/'compose.log').write_bytes(logs)
                        if not passed:
                            # Only this test's public synthetic configuration is
                            # mounted into these containers; no real endpoint or
                            # credential is available to their logs.
                            sys.stderr.write('HOMEPAGE_APPEARANCE_FIXTURE_LOGS\n'+logs.decode('utf-8',errors='replace')[-6000:]+'\n')
                    invoke([*base,'down','--volumes','--remove-orphans'],'HOMEPAGE_APPEARANCE_CLEANUP_FAILED')

if __name__=='__main__':unittest.main()

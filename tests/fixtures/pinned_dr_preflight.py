# Unmodified preflight functions from public commit 28f6ca7cc6f5fd10418fc0af2926815927ef98c8.
# Full original dr.py SHA256: e20a65c8273c5a16eb55adce8cfbc9f51d9971cea43f1731a2caec935519b059
import json,sqlite3,os
from pathlib import Path

class Refused(Exception):pass

def require(ok,code):
 if not ok:raise Refused(code)

def load(path):return json.loads(Path(path).read_text())

def path_for(root,relative):
 path=Path(relative);require(not path.is_absolute() and '..' not in path.parts,'UNSAFE_RELATIVE_PATH')
 target=root/path
 for parent in (target,*target.parents):
  if parent==root.parent:break
  require(not parent.is_symlink(),'SYMLINK_REFUSED')
 require(target.resolve().is_relative_to(root),'TARGET_OUTSIDE_FRESH_ROOT');return target

def context(args,marked=True):
 root=Path(args.target).resolve();plan=load(root/'config/dr-render-plan.json')
 if marked:
  marker=load(root/'.dr-fresh-target.json');require(marker.get('root')==str(root),'FRESH_TARGET_MARKER_REQUIRED')
 return root,plan

def required_user_state_present(root,unit):
 check=unit.get('read_only_check')
 if not check:return False
 path=path_for(root,check['file'])
 if not path.is_file():return False
 try:
  with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
   db.execute('PRAGMA query_only=ON')
   return all(db.execute('SELECT 1 FROM "'+table+'" LIMIT 1').fetchone() is not None for table in check['nonempty_tables'])
 except sqlite3.Error:return False

def preflight(args):
 root,plan=context(args);manifest=load(root/'config/dr-manifest.yaml');failures=[]
 for row in manifest['references']:
  source=row['SOURCE'];method=row['RESTORE_METHOD']
  if row['TYPE']=='HOST_PREREQUISITE':
   if not args.synthetic and not Path(source).exists():failures.append((row['SERVICE'],'HOST_PREREQUISITE_MISSING'))
  elif method in ('TRACKED_PUBLIC','TRACKED_SANITIZED_TEMPLATE','INFISICAL_AGENT_RENDER','BOOTSTRAP_GENERATED') and not source.startswith(('container:','image:','infisical:')):
   if not (root/source).exists():failures.append((row['SERVICE'],'REQUIRED_SOURCE_MISSING'))
  elif method=='RUNTIME_BACKUP_RESTORE':
   if args.mode=='restore' and not args.synthetic and not source.startswith('volume:') and not (root/source).exists():failures.append((row['SERVICE'],'RUNTIME_RESTORE_MISSING'))
 if not args.synthetic:
  for unit in manifest['state_units']:
   if unit['classification'] in ('REQUIRED_IDENTITY_STATE','REQUIRED_USER_STATE') and not required_user_state_present(root,unit):failures.append((','.join(unit['services']),unit['id']+':REQUIRED_USER_CONFIGURATION_NOT_RECONSTRUCTED'))
  for blocker in plan['readiness_blockers']:failures.append((blocker['component'],blocker['code']))
  marker=root/'.generated/aio-import-complete.json'
  if not marker.is_file():failures.append(('aio','PRIVATE_DR_PAYLOAD_IMPORT_REQUIRED'))
  else:
   imported=load(marker)
   if imported.get('root')!=str(root) or imported.get('versions')!={'aiostreams':'2.35.3','aiometadata':'3.3.0'}:failures.append(('aio','PRIVATE_DR_IMPORT_MARKER_INVALID'))
   for service in ('aiostreams','aiometadata'):
    if not (root/f'data/{service}/data/db.sqlite').is_file():failures.append((service,'PRIVATE_DR_DATABASE_MISSING'))
 for service,code in failures:print(service,code)
 require(not failures,'DR_PREFLIGHT_BLOCKED')
 print('DR_PREFLIGHT PASS')

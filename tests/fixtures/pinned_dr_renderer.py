#!/usr/bin/env python3
"""Fresh-host provisioning only. Never starts containers or modifies Infisical."""
import argparse,ast,base64,hashlib,hmac,json,os,re,shutil,sqlite3,stat,subprocess,sys,tomllib,urllib.parse
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
def exclusive(path,content,mode=0o640):
 path.parent.mkdir(parents=True,exist_ok=True,mode=0o750)
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as file:file.write(content);file.flush();os.fsync(file.fileno());os.fchmod(file.fileno(),mode)
def context(args,marked=True):
 root=Path(args.target).resolve();plan=load(root/'config/dr-render-plan.json')
 if marked:
  marker=load(root/'.dr-fresh-target.json');require(marker.get('root')==str(root),'FRESH_TARGET_MARKER_REQUIRED')
 return root,plan
def initialize(args):
 root,plan=context(args,False)
 # No runtime/config directory may predate the explicit fresh-host marker.
 require(not any((root/name).exists() or (root/name).is_symlink() for name in ('.env','.secrets','.generated','.dr-fresh-target.json')),'INITIALIZED_DEPLOYMENT_REFUSED')
 destinations={entry['destination'] for entry in plan['files']}|{plan['postgres_bootstrap']['destination']}
 for item in destinations:require(not path_for(root,item).exists(),'EXISTING_CONFIG_REFUSED')
 for entry in (root/'data').glob('*/data'):require(not entry.exists(),'EXISTING_RUNTIME_DIRECTORY_REFUSED')
 exclusive(root/'.dr-fresh-target.json',json.dumps({'root':str(root),'version':1}).encode(),0o600)
 print('FRESH_TARGET INITIALIZED')
def all_paths(plan):
 paths={ref.rsplit('/',1)[0] for ref in plan['required_values']}
 paths.update(row['path'] for row in plan['service_folder_exports'].values());paths.update(plan.get('additional_input_folders',[]));return sorted(paths)
def folder_file(path):return path.strip('/').replace('/','__')+'.goenv'
def agent_config(args):
 root,plan=context(args)
 require(args.project_id and args.environment and args.address and args.client_id_file and args.client_secret_file,'AUTH_CONFIGURATION_ARGUMENTS_REQUIRED')
 require(urllib.parse.urlsplit(args.address).scheme=='https' or urllib.parse.urlsplit(args.address).hostname in ('localhost','127.0.0.1'),'HTTPS_INFISICAL_REQUIRED')
 templates=[]
 for path in all_paths(plan):
  # Go printf %q preserves quotes, newlines, dollar signs and arbitrary UTF-8.
  # The renderer parses string literals with ast.literal_eval, never eval.
  content='{{ range secret '+json.dumps(args.project_id)+' '+json.dumps(args.environment)+' '+json.dumps(path)+' }}{{ .Key }}={{ printf "%q" .Value }}\n{{ end }}'
  destination=path_for(root,'.secrets/dr-inputs/'+folder_file(path));destination.parent.mkdir(parents=True,exist_ok=True,mode=0o750)
  templates.append({'template-content':content,'destination-path':str(destination),'config':{'polling-interval':'60s'}})
 config={'infisical':{'address':args.address},'auth':{'type':'universal-auth','config':{'client-id':str(Path(args.client_id_file).resolve()),'client-secret':str(Path(args.client_secret_file).resolve()),'remove_client_secret_on_read':False}},'templates':templates}
 output=path_for(root,'.generated/dr-agent.json');exclusive(output,(json.dumps(config,indent=2)+'\n').encode(),0o600)
 print('AGENT_CONFIG PREPARED')
def read_values(root,plan,input_dir):
 directory=Path(input_dir).resolve() if input_dir else root/'.secrets/dr-inputs';values={}
 for path in all_paths(plan):
  file=directory/folder_file(path);require(file.is_file() and not file.is_symlink(),'INFISICAL_FOLDER_RENDER_MISSING')
  require(not file.stat().st_mode&0o007,'PRIVATE_INPUT_WORLD_ACCESSIBLE')
  for line in file.read_text().splitlines():
   if not line.strip():continue
   key,sep,encoded=line.partition('=');require(sep and re.fullmatch(r'[A-Z][A-Z0-9_]*',key),'INVALID_EXPORTED_KEY')
   value=ast.literal_eval(encoded);require(isinstance(value,str),'EXPORTED_VALUE_NOT_STRING')
   ref=path+'/'+key;require(ref not in values,'DUPLICATE_EXPORTED_KEY');values[ref]=value
 for ref in plan['required_values']:require(ref in values,'REQUIRED_INFISICAL_KEY_MISSING:'+ref)
 return values
def dotenv(value):
 require('\0' not in value and all(ord(c)>=32 or c in '\n\r\t' for c in value),'UNSUPPORTED_ENV_CONTROL_CHARACTER')
 return json.dumps(value,ensure_ascii=False).replace('$','$$')
def sql_literal(value):require('\0' not in value,'SQL_NUL_REFUSED');return "'"+value.replace("'","''")+"'"
def sql_identifier(value):require(value and '\0' not in value,'INVALID_SQL_IDENTIFIER');return '"'+value.replace('"','""')+'"'
def postgres_connection(value,service):
 # Comet accepts authority-only connection strings; other services use URIs.
 if service=='comet' and '://' not in value:value='postgresql://'+value
 uri=urllib.parse.urlsplit(value);require(uri.scheme in ('postgres','postgresql'),'POSTGRES_URI_REQUIRED')
 user=urllib.parse.unquote(uri.username or '');password=urllib.parse.unquote(uri.password or '');database=urllib.parse.unquote(uri.path.lstrip('/'))
 require(user and password and database and '/' not in database,'POSTGRES_URI_FIELDS_REQUIRED')
 return user,password,database
def userlist_entries(content):
 entries={}
 # PgBouncer uses doubled double-quotes inside quoted fields, not shell quoting.
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
def sql_bootstrap(plan,values):
 lines=['-- FRESH CLUSTER ONLY. PostgreSQL entrypoint skips initialization on restored PGDATA.',r'\set ON_ERROR_STOP on','SET standard_conforming_strings = on;']
 entries=userlist_entries(values[plan['postgres_bootstrap']['userlist_ref']])
 seen=set()
 for item in plan['postgres_bootstrap']['connections']:
  user,password,database=postgres_connection(values[item['ref']],item['service'])
  credential=verified_role_password(user,password,entries.get(user))
  require((user,database) not in seen,'DUPLICATE_DATABASE_MAPPING');seen.add((user,database))
  u,p,d=map(sql_literal,(user,credential,database))
  lines.extend(["SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', "+u+', '+p+')', 'WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '+u+')',r'\gexec'])
  if item['service'] in ('comet','stremthru'):lines.append('ALTER ROLE '+sql_identifier(user)+' SET synchronous_commit = off;')
  if item['service']=='comet':lines.append('ALTER ROLE '+sql_identifier(user)+' SET work_mem = '+sql_literal(plan['postgres_bootstrap']['public_work_mem'])+';')
  lines.extend(["SELECT format('CREATE DATABASE %I OWNER %I', "+d+', '+u+')','WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = '+d+')',r'\gexec'])
 admin=plan['postgres_bootstrap'].get('admin_user','postgres')
 if admin in entries:
  credential=verified_role_password(admin,values[plan['postgres_bootstrap']['admin_password_ref']],entries[admin])
  lines.append('ALTER ROLE '+sql_identifier(admin)+' PASSWORD '+sql_literal(credential)+';')
 return ('\n'.join(lines)+'\n').encode()
def runtime_fields(args):
 root,plan=context(args);require(args.snapshot_dir,'RUNTIME_SNAPSHOT_DIRECTORY_REQUIRED')
 snapshot=Path(args.snapshot_dir).resolve();require(snapshot!=root and not snapshot.is_relative_to(root),'SEPARATE_SNAPSHOT_REQUIRED')
 # Only runtime identity/session fields are retained from a supplied backup.
 # The command never reads production automatically and never copies configs.
 result={}
 for name,fields in plan['runtime_fields'].items():
  source=path_for(snapshot,name);require(source.is_file(),'RUNTIME_FIELD_SOURCE_MISSING')
  obj=load(source)
  if isinstance(obj,dict):result[name]={key:obj[key] for key in fields if key in obj}
  elif isinstance(obj,list):result[name]=[entry for entry in obj if isinstance(entry,dict) and entry.get('type') in fields]
 exclusive(path_for(root,'.generated/runtime-fields.json'),json.dumps(result).encode(),0o600)
 print('RUNTIME_FIELDS PREPARED')
def render(args):
 root,plan=context(args)
 require(not plan['readiness_blockers'],'DECLARATIVE_PROVENANCE_BLOCKERS_UNRESOLVED')
 values=read_values(root,plan,args.input_dir);outputs=[]
 overlay_path=root/'.generated/runtime-fields.json';runtime_overlay=load(overlay_path) if overlay_path.is_file() else {}
 if args.mode=='restore':require(overlay_path.is_file(),'RUNTIME_FIELD_OVERLAY_REQUIRED_IN_RESTORE_MODE')
 def env_file(destination,bindings,extra=None):
  data=dict(extra or {})
  for key,ref in bindings.items():
   value=values[ref['path']+'/'+ref['key']]
   if key in data:require(data[key]==value,'SHARED_AND_SERVICE_VALUE_CONFLICT')
   data[key]=value
  outputs.append((destination,(''.join(key+'='+dotenv(value)+'\n' for key,value in sorted(data.items()))).encode(),0o640))
 for destination,bindings in plan['env_files'].items():env_file(destination,bindings)
 for destination,spec in plan['service_folder_exports'].items():
  exported={key.rsplit('/',1)[1]:value for key,value in values.items() if key.rsplit('/',1)[0]==spec['path']}
  require(exported,'INITIAL_SERVICE_EXPORT_EMPTY')
  env_file(destination,spec['overrides'],exported)
 env_file('.env',plan['root_env'],{'COMPOSE_PROJECT_NAME':'streams-aio','COMPOSE_FILE':'docker-compose.yml:config/compose.dr.yaml'})
 for item in plan['files']:
  if item['format']=='oauth2-allowlist':
   value=values[item['ref']]
   require('\x00' not in value and '\r' not in value,'ALLOWLIST_INVALID_CONTROL_CHARACTER')
   entries=[line.strip() for line in value.splitlines() if line.strip() and not line.lstrip().startswith('#')]
   require(entries and len(entries)==len(set(entries)),'ALLOWLIST_EMPTY_OR_DUPLICATE')
   require(all(re.fullmatch(r"[A-Za-z0-9.!#$%&'+/=?^_`{|}~-]+@[A-Za-z0-9.-]+",line) and '*' not in line for line in entries),'ALLOWLIST_EXPLICIT_EMAILS_REQUIRED')
   raw=(value if value.endswith('\n') else value+'\n').encode()
  elif item['format']=='opaque':raw=values[item['ref']].encode()
  else:
   text=(root/item['template']).read_text()
   if item['format']=='json':
    def replace(value):
     if isinstance(value,dict):return {k:replace(v) for k,v in value.items()}
     if isinstance(value,list):return [replace(v) for v in value]
     if isinstance(value,str):return re.sub(r'@@INFISICAL:([^@]+)@@',lambda m:values[m[1]],value)
     return value
    obj=replace(json.loads(text));overlay=runtime_overlay.get(item['destination'])
    if overlay is not None:
     fields=plan['runtime_fields'].get(item['destination'],[])
     if isinstance(obj,dict):
      require(isinstance(overlay,dict) and set(overlay)<=set(fields),'UNAPPROVED_RUNTIME_FIELDS');obj.update(overlay)
     elif isinstance(obj,list):
      require(isinstance(overlay,list) and all(entry.get('type') in fields for entry in overlay),'UNAPPROVED_RUNTIME_FIELDS')
      by_id={entry['id']:entry for entry in overlay};obj=[by_id.get(entry.get('id'),entry) for entry in obj]
    raw=(json.dumps(obj,indent=2,ensure_ascii=False)+'\n').encode()
   elif item['format']=='toml':
    # Markers occupy JSON-compatible TOML string literals. Insert escaped
    # content, preserving the original public TOML structure and comments.
    text=re.sub(r'@@INFISICAL:([^@]+)@@',lambda m:json.dumps(values[m[1]],ensure_ascii=False)[1:-1],text)
    tomllib.loads(text);raw=text.encode()
   elif item['format']=='ini-token':
    def ini_value(match):
     value=values[match[1]];require(re.fullmatch(r'[a-zA-Z0-9_-]+',value),'INI_TOKEN_FORMAT_UNSUPPORTED');return value
    raw=re.sub(r'@@INFISICAL:([^@]+)@@',ini_value,text).encode()
   else:
    require('@@INFISICAL:' not in text,'UNSUPPORTED_TEXT_TEMPLATE_BINDING');raw=text.encode()
  require(b'@@INFISICAL:' not in raw and b'INFISICAL:/' not in raw,'UNRESOLVED_TEMPLATE_REFERENCE')
  outputs.append((item['destination'],raw,int(item['mode'],8)))
 outputs.append((plan['postgres_bootstrap']['destination'],sql_bootstrap(plan,values),0o640))
 # Validate the entire output set before the first filesystem mutation.
 require(len({path for path,_,_ in outputs})==len(outputs),'DUPLICATE_DESTINATION')
 marker=path_for(root,'.generated/dr-render-complete.json')
 require(not marker.exists() and not marker.is_symlink(),'EXISTING_RENDER_MARKER_REFUSED')
 for rel,raw,mode in outputs:
  target=path_for(root,rel);require(not target.exists() and not target.is_symlink(),'EXISTING_CONFIG_REFUSED:'+rel)
 ownership={item['destination']:(item.get('uid',0),item.get('gid',args.deployment_gid)) for item in plan['files']}
 ownership[plan['postgres_bootstrap']['destination']]=(70,70)
 if not args.synthetic:require(os.geteuid()==0,'ROOT_REQUIRED_FOR_GENERATED_FILE_OWNERSHIP')
 if not args.synthetic and any(item.get('named_acl') for item in plan['files']):require(shutil.which('setfacl'),'SETFACL_REQUIRED_FOR_CONFIG_PERMISSIONS')
 file_specs={item['destination']:item for item in plan['files']}
 for rel,raw,mode in outputs:
  target=path_for(root,rel);uid,gid=ownership.get(rel,(0,args.deployment_gid));created=[];parent=target.parent
  while parent!=root and not parent.exists():created.append(parent);parent=parent.parent
  exclusive(target,raw,mode)
  if not args.synthetic:
   os.chown(target,uid,gid)
   for directory in created:os.chown(directory,uid,gid);os.chmod(directory,0o750)
   entries=file_specs.get(rel,{}).get('named_acl',[])
   if entries:
    # Reproduce numeric named access entries. The mode is then reapplied so
    # the ACL mask cannot grant permissions beyond the declared private mode.
    result=subprocess.run(['setfacl','-m',','.join(entries),str(target)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    require(result.returncode==0,'GENERATED_CONFIG_ACL_FAILED');os.chmod(target,mode)
    # Named readers/writers also need traversal of the newly created parent
    # directories. Existing directories (including restored state) are untouched.
    directory_entries=[]
    for entry in entries:
     parts=entry.split(':')
     if len(parts)==3 and parts[0] in ('user','group') and parts[1]:directory_entries.append(parts[0]+':'+parts[1]+':'+('rwx' if 'w' in parts[2] else 'r-x'))
    if directory_entries:
     for directory in created:
      result=subprocess.run(['setfacl','-m',','.join(directory_entries),str(directory)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
      require(result.returncode==0,'GENERATED_DIRECTORY_ACL_FAILED')
 exclusive(path_for(root,'.generated/dr-render-complete.json'),json.dumps({'root':str(root),'outputs':[path for path,_,_ in outputs]}).encode(),0o600)
 print('RENDER PASS FILES='+str(len(outputs)))
def prepare_state(args):
 root,plan=context(args);manifest=load(root/'config/dr-manifest.yaml')
 marker=path_for(root,'.generated/dr-render-complete.json')
 require(marker.is_file() and load(marker).get('root')==str(root),'DECLARATIVE_RENDER_REQUIRED_BEFORE_STATE_PREPARATION')
 directories=manifest['quick_redeploy']['empty_directories']
 for item in directories:
  target=path_for(root,item['path']);require(not target.exists() or target.is_dir(),'STATE_DIRECTORY_TYPE_CONFLICT')
 if not args.synthetic:require(os.geteuid()==0,'ROOT_REQUIRED_FOR_STATE_DIRECTORY_OWNERSHIP')
 created=0
 for item in sorted(directories,key=lambda row:len(Path(row['path']).parts)):
  target=path_for(root,item['path'])
  if target.exists():continue
  target.mkdir(parents=True,mode=int(item['mode'],8));created+=1
  if not args.synthetic:os.chown(target,item['uid'],item['gid']);os.chmod(target,int(item['mode'],8))
 print('EMPTY_STATE_DIRECTORIES PASS CREATED='+str(created))
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
def main():
 parser=argparse.ArgumentParser();parser.add_argument('command',choices=['init','agent-config','runtime-fields','render','prepare-state','preflight']);parser.add_argument('--target',required=True);parser.add_argument('--project-id');parser.add_argument('--environment',default='prod');parser.add_argument('--address');parser.add_argument('--client-id-file');parser.add_argument('--client-secret-file');parser.add_argument('--input-dir');parser.add_argument('--snapshot-dir');parser.add_argument('--mode',choices=['fresh','restore'],default='fresh');parser.add_argument('--deployment-gid',type=int,default=1000);parser.add_argument('--synthetic',action='store_true');args=parser.parse_args()
 os.umask(0o027)
 {'init':initialize,'agent-config':agent_config,'runtime-fields':runtime_fields,'render':render,'prepare-state':prepare_state,'preflight':preflight}[args.command](args)
if __name__=='__main__':
 try:main()
 except Exception as exc:print('DR_REFUSED',str(exc) if isinstance(exc,Refused) else type(exc).__name__);sys.exit(1)

"""Install the pinned native Agent and an SSH-only API path on replacement VMs."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import socket
import stat
import tarfile
import tempfile
import time

from recover import (Refused, agent_bootstrap, command, digest, event, private_file,
                     require, safe_path, save, unpack_agent, archived_local_inputs)

VERSION = '0.43.137'
CLI_URL = 'https://github.com/Infisical/cli/releases/download/v0.43.137/cli_0.43.137_linux_amd64.tar.gz'
CLI_SHA256 = '308a90c7f9c307cb9c348d352a797a3a63b02e1a7836adbe8afddfd75c855531'
TUNNEL_USER = 'streams-aio-tunnel'
LOCAL_PORT = 18180


def preserve_local_inputs(backup, plan, destination=Path('/etc/infisical')):
    """Keep local settings and template provenance available for later backups."""
    values = archived_local_inputs(backup, plan)
    if not values:
        return
    source = private_file(backup/'etc/infisical/local-stack-agent-source.json')
    require(source.stat().st_size <= 1024*1024, 'LOCAL_CONFIG_FILE_INVALID')
    try:
        def unique(pairs):
            result = {}
            for key,value in pairs:
                require(key not in result, 'LOCAL_CONFIG_DUPLICATE_JSON_KEY')
                result[key] = value
            return result
        obj = json.loads(source.read_bytes(),object_pairs_hook=unique)
        require(isinstance(obj,dict) and set(obj)=={'schema','templates'}
                and type(obj['schema']) is int and obj['schema']==1
                and isinstance(obj['templates'],dict) and 2<=len(obj['templates'])<=200,
                'LOCAL_CONFIG_INVALID')
        require({'.secrets/aiostreams.env','.secrets/aiometadata.env'} <= obj['templates'].keys(),
                'LOCAL_CONFIG_INVALID')
        for path,content in obj['templates'].items():
            relative = PurePosixPath(path)
            require(isinstance(path,str) and not relative.is_absolute()
                    and '..' not in relative.parts and '\\' not in path
                    and relative.as_posix()==path and re.fullmatch(r'[A-Za-z0-9_./-]+',path)
                    and isinstance(content,str) and len(content.encode('utf-8'))<=1024*1024,
                    'LOCAL_CONFIG_INVALID')
            require(all(ord(c)>=32 or c in '\t\r\n' for c in content),'LOCAL_CONFIG_INVALID')
    except (ValueError,TypeError,UnicodeError):
        raise Refused('LOCAL_CONFIG_INVALID') from None
    destination = safe_path(destination)
    destination.mkdir(mode=0o700,parents=True,exist_ok=True)
    require(destination.is_dir() and destination.stat().st_uid==0
            and not destination.stat().st_mode & 0o022,'LOCAL_CONFIG_UNSAFE_PATH')
    write_owned(destination/'local-stack-config.json',
                private_file(backup/'etc/infisical/local-stack-config.json').read_bytes(),0,0)
    write_owned(destination/'local-stack-agent-source.json',source.read_bytes(),0,0)


def checkpoint(home, target, server=False):
    state = json.loads(private_file(safe_path(home)/'state.json').read_bytes())
    require(state.get('machine_id') == Path('/etc/machine-id').read_text().strip()
            and state.get('target') == str(target), 'FOREIGN_RECOVERY_STATE')
    require('INFISICAL_SERVER' in state.get('completed',[]) if server else state.get('preparation') == 'PASS',
            'PREPARED_REPLACEMENT_REQUIRED')
    return state


def write_owned(path, raw, uid=1000, gid=1000):
    path = safe_path(path)
    if path.exists():
        require(path.is_file() and path.read_bytes() == raw, 'AGENT_EXISTING_INSTALLATION_CHANGED')
    else:
        with path.open('xb') as file:
            file.write(raw)
    path.chmod(0o600)
    os.chown(path,uid,gid)


def public_key_text(output):
    """Canonical OpenSSH key without its optional, non-key comment."""
    require(isinstance(output, str) and '\n' not in output.strip()
            and '\r' not in output.strip(), 'AGENT_TUNNEL_PUBLIC_KEY_INVALID')
    fields = output.strip().split(None, 2)
    require(len(fields) >= 2 and fields[0] == 'ssh-ed25519'
            and re.fullmatch(r'[A-Za-z0-9+/=]+', fields[1]),
            'AGENT_TUNNEL_PUBLIC_KEY_INVALID')
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except ValueError:
        raise Refused('AGENT_TUNNEL_PUBLIC_KEY_INVALID') from None
    prefix = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'
    require(len(blob) == len(prefix) + 32 and blob.startswith(prefix),
            'AGENT_TUNNEL_PUBLIC_KEY_INVALID')
    return ' '.join(fields[:2])


def key(home, target):
    checkpoint(home,target)
    destination = safe_path(home/'agent-tunnel-key')
    if not destination.exists():
        require(not (home/'agent-tunnel-key.pub').exists(), 'AGENT_EXISTING_INSTALLATION_CHANGED')
        command(['ssh-keygen','-q','-t','ed25519','-N','','-C','streams-aio-recovery-tunnel',
                 '-f',destination], 'AGENT_TUNNEL_KEY_CREATION_FAILED')
    private_file(destination)
    os.chown(destination,1000,1000)
    public = public_key_text(command(['ssh-keygen','-y','-f',destination],
                                     'AGENT_TUNNEL_KEY_CREATION_FAILED').decode())
    # Public key only, consumed by the desktop without entering UI logs.
    print(json.dumps({'public_key':public}))


def authorize_owned_key(path, public, port, uid, gid):
    """Replace a previous recovery key only in the verified dedicated account.

    A replacement stack has a new private key even when the Infisical VM is
    reused. The caller has verified that VM's checkpoint and account marker;
    only our single, identically restricted authorization may be rotated.
    """
    path = safe_path(path)
    public = public_key_text(public)
    require(type(port) is int and 1 <= port <= 65535, 'INFISICAL_API_PORT_REQUIRES_REVIEW')
    options = 'restrict,port-forwarding,permitopen="127.0.0.1:'+str(port)+'",command="/bin/false" '
    raw = (options+public+'\n').encode()
    if not path.exists():
        write_owned(path, raw, uid, gid)
        return
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == uid and info.st_gid == gid
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 4096,
            'AGENT_EXISTING_INSTALLATION_CHANGED')
    previous = path.read_bytes()
    try:
        old_public = previous.removeprefix(options.encode()).removesuffix(b'\n').decode('ascii')
        require(previous == (options+public_key_text(old_public)+'\n').encode(),
                'AGENT_EXISTING_INSTALLATION_CHANGED')
    except (UnicodeError, Refused):
        raise Refused('AGENT_EXISTING_INSTALLATION_CHANGED') from None
    if previous == raw:
        return
    fd, name = tempfile.mkstemp(prefix='.recovery-key-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o600)
            os.fchown(output.fileno(), uid, gid)
        # Keep an unexpected concurrent change from being mistaken for the
        # old, validated recovery authorization.
        current = safe_path(path).stat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(all(getattr(current, field) == getattr(info, field) for field in fields)
                and path.read_bytes() == previous, 'AGENT_EXISTING_INSTALLATION_CHANGED')
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def authorize(home, target, config):
    import pwd
    state = checkpoint(home,target,True)
    port = state['api_port']
    require(type(port) is int and 1 <= port <= 65535, 'INFISICAL_API_PORT_REQUIRES_REVIEW')
    public = config['public_key']
    require(isinstance(public,str) and re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+',public),
            'AGENT_TUNNEL_PUBLIC_KEY_INVALID')
    account_home = safe_path(Path('/var/lib/streams-aio-tunnel'))
    try:
        account = pwd.getpwnam(TUNNEL_USER)
        require(account.pw_dir == str(account_home) and account.pw_shell == '/bin/false',
                'AGENT_TUNNEL_ACCOUNT_CONFLICT')
        owner = private_file(account_home/'recovery-owner')
        info = owner.stat()
        require(info.st_uid == info.st_gid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600
                and owner.read_text() == state['machine_id'],
                'AGENT_TUNNEL_ACCOUNT_CONFLICT')
    except KeyError:
        require(not account_home.exists(), 'AGENT_TUNNEL_ACCOUNT_CONFLICT')
        command(['useradd','--system','--create-home','--home-dir',account_home,
                 '--shell','/bin/false',TUNNEL_USER], 'AGENT_TUNNEL_ACCOUNT_CREATION_FAILED')
        account = pwd.getpwnam(TUNNEL_USER)
        write_owned(account_home/'recovery-owner',state['machine_id'].encode(),0,0)
    directory = safe_path(account_home/'.ssh')
    directory.mkdir(mode=0o700,exist_ok=True)
    os.chown(directory,account.pw_uid,account.pw_gid)
    authorize_owned_key(directory/'authorized_keys',public,port,account.pw_uid,account.pw_gid)
    # Restrict only the new dedicated account. Existing administration logins
    # keep their original SSH behavior. Remote forwards/shells are unavailable.
    raw = ('Match User '+TUNNEL_USER+'\n    AllowTcpForwarding local\n'
           '    PermitOpen 127.0.0.1:'+str(port)+'\n    PermitTTY no\n'
           '    X11Forwarding no\n    AllowAgentForwarding no\n    ForceCommand /bin/false\nMatch all\n').encode()
    write_owned(Path('/etc/ssh/sshd_config.d/70-streams-aio-tunnel.conf'),raw,0,0)
    command(['/usr/sbin/sshd','-t'], 'AGENT_SSH_CONFIGURATION_REFUSED')
    command(['systemctl','reload','ssh.service'], 'AGENT_SSH_CONFIGURATION_REFUSED')


def private_templates(obj, archive, root):
    """Keep recovered private env mappings; mutable app config is initialized once."""
    import yaml
    result = []
    require(isinstance(obj,dict) and isinstance(obj.get('templates'),list)
            and 0 < len(obj['templates']) <= 200, 'AGENT_BOOTSTRAP_CONFIG_NOT_UNIQUE')
    source_root = None
    for original in obj['templates']:
        require(isinstance(original,dict), 'AGENT_TEMPLATE_PATH_UNSUPPORTED')
        row = copy.deepcopy(original)
        destination = row.get('destination-path')
        require(isinstance(destination,str), 'AGENT_TEMPLATE_PATH_UNSUPPORTED')
        old = PurePosixPath(destination)
        require(old.is_absolute() and old.as_posix() == destination and '\\' not in destination
                and '..' not in old.parts and len(old.parts) >= 5
                and old.parts[1] == 'home' and re.fullmatch(r'[a-z_][a-z0-9_-]*',old.parts[2])
                and old.parts[3] == 'streams-aio',
                'AGENT_TEMPLATE_PATH_UNSUPPORTED')
        # The explicit archived destination determines the old host root.
        # This also accepts backups made by a previously recovered Agent.
        current_root = PurePosixPath(*old.parts[:4])
        require(source_root is None or source_root == current_root, 'AGENT_TEMPLATE_ROOT_NOT_UNIQUE')
        source_root = current_root
        relative = old.relative_to(source_root)
        # Public templates and mutable application-owned files are never watched.
        if not relative.parts or relative.parts[0] != '.secrets':
            continue
        require(relative.suffix in ('.env','.goenv','.txt') and len(relative.parts) >= 2,
                'AGENT_PRIVATE_TEMPLATE_REQUIRES_REVIEW')
        if 'source-path' in row:
            source = PurePosixPath(row.pop('source-path'))
            require(source.is_absolute() and '..' not in source.parts, 'AGENT_TEMPLATE_PATH_UNSUPPORTED')
            row['template-content'] = private_file(archive / str(source).lstrip('/')).read_text()
        require(isinstance(row.get('template-content'),str), 'AGENT_TEMPLATE_PATH_UNSUPPORTED')
        row['destination-path'] = str(safe_path(root/str(relative)))
        # Do not replay private execute.command hooks while rebuilding a host.
        row['config'] = {'polling-interval':'60s'}
        row = {key:row[key] for key in ('template-content','destination-path','config')}
        result.append(row)
    require(bool(result), 'AGENT_PRIVATE_TEMPLATE_REQUIRES_REVIEW')
    require(len({row['destination-path'] for row in result}) == len(result), 'AGENT_DUPLICATE_DESTINATION')
    return result


def required_private_envs(root, plan):
    """New required Compose env files; no secret folder or key is inferred."""
    import yaml
    root = safe_path(root)
    compose = safe_path(root/'docker-compose.yml')
    require(compose.is_file() and compose.stat().st_size <= 4*1024*1024, 'AGENT_SEED_COMPOSE_INVALID')
    try:
        obj = yaml.safe_load(compose.read_bytes())
        require(isinstance(obj,dict) and isinstance(obj.get('services'),dict), 'AGENT_SEED_COMPOSE_INVALID')
        require('include' not in obj, 'AGENT_SEED_COMPOSE_INCLUDE_UNSUPPORTED')
        # New service secrets belong in their explicit private env template.
        # Never silently turn an unmapped required root interpolation into an
        # empty string or replace the public renderer's root .env policy.
        declared = set(plan.get('root_env',{})) | {'COMPOSE_PROJECT_NAME','COMPOSE_FILE'}
        def check_root(value):
            if isinstance(value,dict):
                for item in value.values():
                    check_root(item)
            elif isinstance(value,list):
                for item in value:
                    check_root(item)
            elif isinstance(value,str):
                offset = 0
                while offset < len(value):
                    if value[offset:offset+2] == '$$':
                        offset += 2
                        continue
                    if value[offset] != '$':
                        offset += 1
                        continue
                    if value[offset:offset+2] == '${':
                        end, depth = offset+2,1
                        while end < len(value) and depth:
                            depth += (value[end] == '{')-(value[end] == '}')
                            end += 1
                        if depth:
                            break  # Compose retains validation of malformed syntax.
                        expression = value[offset+2:end-1]
                        match = re.fullmatch(r'([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-+?])(.*))?',expression,re.S)
                        if match and match[2] in (None,'?',':?'):
                            require(match[1] in declared, 'AGENT_SEED_ROOT_ENV_MAPPING_REQUIRED')
                        elif match:
                            # A default may itself require a private variable.
                            # Optional outer names must not hide missing inputs.
                            check_root(match[3])
                        offset = end
                    else:
                        match = re.match(r'\$([A-Za-z_][A-Za-z0-9_]*)',value[offset:])
                        if match:
                            require(match[1] in declared, 'AGENT_SEED_ROOT_ENV_MAPPING_REQUIRED')
                            offset += len(match[0])
                        else:
                            offset += 1
        check_root(obj)
        targets = set()
        for service in obj['services'].values():
            require(isinstance(service,dict), 'AGENT_SEED_COMPOSE_INVALID')
            require('extends' not in service, 'AGENT_SEED_COMPOSE_EXTENDS_UNSUPPORTED')
            entries = service.get('env_file',[])
            if isinstance(entries,(str,dict)):
                entries = [entries]
            require(isinstance(entries,list), 'AGENT_SEED_COMPOSE_INVALID')
            for entry in entries:
                require(isinstance(entry,(str,dict)), 'AGENT_SEED_COMPOSE_INVALID')
                name = entry if isinstance(entry,str) else entry.get('path')
                required = True if isinstance(entry,str) else entry.get('required',True)
                require(isinstance(name,str) and type(required) is bool, 'AGENT_SEED_COMPOSE_INVALID')
                name = name.removeprefix('./')
                relative = PurePosixPath(name)
                if not relative.parts or relative.parts[0] != '.secrets':
                    continue
                require(not relative.is_absolute() and '..' not in relative.parts
                        and relative.as_posix() == name and '\\' not in name
                        and re.fullmatch(r'\.secrets/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.env',name),
                        'AGENT_SEED_TARGET_INVALID')
                if required:
                    targets.add(name)
        require(len(targets) <= 200, 'AGENT_SEED_TARGET_INVALID')
        known = set(plan['env_files']) | set(plan.get('service_folder_exports',{}))
        return sorted(targets-known)
    except (ValueError,TypeError,KeyError,UnicodeError,yaml.YAMLError):
        raise Refused('AGENT_SEED_COMPOSE_INVALID') from None


def recovered_private_templates(archive, root):
    import yaml
    candidates = [path for path in archive.rglob('*') if path.is_file()
                  and path.name in ('agent-config.json','agent-config.yaml','agent-config.yml')]
    require(len(candidates) == 1, 'AGENT_BOOTSTRAP_CONFIG_NOT_UNIQUE')
    try:
        obj = yaml.safe_load(private_file(candidates[0]).read_bytes())
    except (ValueError,TypeError,UnicodeError,yaml.YAMLError):
        raise Refused('AGENT_BOOTSTRAP_CONFIG_NOT_UNIQUE') from None
    return private_templates(obj,archive,root)


def pinned_cli(area, user):
    archive = area/'cli.tar.gz'
    if not archive.exists():
        command(['curl','--fail','--silent','--show-error','--location','--proto','=https',
                 '--proto-redir','=https','--max-time','180','--output',archive,CLI_URL], 'AGENT_CLI_DOWNLOAD_FAILED')
    binary = install_cli(archive)
    require(command(['sudo','-H','-u',user,'--',binary,'--version'],
                    'AGENT_CLI_VERSION_MISMATCH').decode().strip() == 'infisical version '+VERSION,
            'AGENT_CLI_VERSION_MISMATCH')
    return binary


def reconcile_seed_journal(root, journal, scope, targets, uid, gid):
    """Reuse a complete seed or remove only a fully verified partial seed."""
    if not journal.exists():
        require(all(not safe_path(root/name).exists() for name in targets), 'AGENT_SEED_EXISTING_OUTPUT')
        return None
    info = private_file(journal).stat()
    require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1 and info.st_size <= 1024*1024,
            'AGENT_SEED_JOURNAL_INVALID')
    try:
        evidence = json.loads(journal.read_bytes())
    except (ValueError,UnicodeError):
        raise Refused('AGENT_SEED_JOURNAL_INVALID') from None
    require(isinstance(evidence,dict) and set(evidence) == {'schema','scope','outputs'}
            and type(evidence['schema']) is int and evidence['schema'] == 1
            and evidence['scope'] == scope and isinstance(evidence['outputs'],dict)
            and set(evidence['outputs']) == set(targets)
            and all(isinstance(value,str) and re.fullmatch(r'[0-9a-f]{64}',value)
                    for value in evidence['outputs'].values()), 'AGENT_SEED_JOURNAL_INVALID')
    existing = []
    fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    for name, expected in evidence['outputs'].items():
        path = safe_path(root/name)
        if path.exists():
            info = path.stat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == uid and info.st_gid == gid
                    and digest(path) == expected, 'AGENT_SEED_OUTPUT_CHANGED')
            existing.append((path,tuple(getattr(info,field) for field in fields),expected))
    if len(existing) == len(targets):
        return evidence['outputs']
    # Validate the entire partial set before deleting any file. A missing file
    # is allowed; an unjournaled or changed file is never replaced or removed.
    for path, metadata, expected in existing:
        info = safe_path(path).stat()
        require(tuple(getattr(info,field) for field in fields) == metadata
                and digest(path) == expected, 'AGENT_SEED_OUTPUT_CHANGED')
        path.unlink()
    return None


def seed_required_envs(root, home, archive, plan, address, *, uid=1000, gid=1000, user=None):
    """Render exact archived mappings once, before the first Compose inspection.

    This prepares only new required .secrets env files. Root .env interpolation
    remains governed by the public renderer's explicit root_env bindings.
    """
    targets = required_private_envs(root,plan)
    if not targets:
        return {}
    root, home = safe_path(root), safe_path(home)
    journal = safe_path(home/'agent-seed-journal.json')
    scope = dict(root=str(root),archive_sha256=digest(private_file(archive)),
                 plan_sha256=digest(safe_path(root/'config/dr-render-plan.json')),
                 compose_sha256=digest(safe_path(root/'docker-compose.yml')),uid=uid,gid=gid)
    if user is None:
        import pwd
        user = pwd.getpwuid(uid).pw_name
    with tempfile.TemporaryDirectory(prefix='agent-seed-',dir=home) as name:
        area = safe_path(Path(name))
        os.chown(area,uid,gid)
        backup = area/'backup'
        unpack_agent(private_file(archive),backup)
        recovered = agent_bootstrap(backup)
        rows = recovered_private_templates(backup,root)
        by_path = {Path(row['destination-path']).relative_to(root).as_posix():row for row in rows}
        require(set(targets) <= by_path.keys(), 'AGENT_SEED_MAPPING_INCOMPLETE')
        selected = [by_path[path] for path in targets]
        resumed = reconcile_seed_journal(root,journal,scope,targets,uid,gid)
        if resumed is not None:
            return resumed
        for field in ('client_id','client_secret'):
            write_owned(area/field,private_file(recovered[field]).read_bytes(),uid,gid)
        config = dict(infisical={'address':address},
                      auth={'type':'universal-auth','config':{'client-id':str(area/'client_id'),
                            'client-secret':str(area/'client_secret'),'remove_client_secret_on_read':False}},
                      templates=selected)
        binary = pinned_cli(area,user)
        # Root promotes the staged output; the deployment user needs traversal,
        # not write access to the private input directories or extracted archive.
        parents = set()
        for path in targets:
            parent = safe_path(root/path).parent
            while parent != root:
                parents.add(parent)
                parent = parent.parent
        for parent in sorted(parents,key=lambda p:len(p.parts)):
            if parent.exists():
                info = parent.stat()
                require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0,uid)
                        and not info.st_mode & 0o022, 'AGENT_SEED_TARGET_INVALID')
            else:
                parent.mkdir(mode=0o750)
                parent.chmod(0o750)
                os.chown(parent,0,gid)
        def journal_outputs(destinations, material):
            require(destinations == [safe_path(root/path) for path in targets], 'AGENT_SEED_JOURNAL_INVALID')
            outputs = {path:hashlib.sha256(raw).hexdigest() for path,raw in zip(targets,material)}
            save(journal,{'schema':1,'scope':scope,'outputs':outputs})
        first_render(config,area,binary,user,uid,gid,before_promote=journal_outputs)
    outputs = {path:digest(private_file(root/path)) for path in targets}
    verify_seeded_envs(root,plan,outputs,uid=uid,gid=gid)
    return outputs


def verify_seeded_envs(root, plan, outputs, *, check_hash=True, uid=1000, gid=1000):
    """Private preparation evidence; a later continuous Agent may rotate values."""
    require(isinstance(outputs,dict) and set(outputs) == set(required_private_envs(root,plan))
            and all(isinstance(value,str) and re.fullmatch(r'[0-9a-f]{64}',value) for value in outputs.values()),
            'AGENT_SEED_CHECKPOINT_INVALID')
    for name, expected in outputs.items():
        path = safe_path(root/name)
        require(path.is_file(), 'AGENT_SEED_OUTPUT_CHANGED')
        info = path.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == uid and info.st_gid == gid,
                'AGENT_SEED_OUTPUT_CHANGED')
        require(not check_hash or digest(path) == expected, 'AGENT_SEED_OUTPUT_CHANGED')


def tunnel_unit(home,user,host,port,api_port):
    require(re.fullmatch(r'[A-Za-z0-9.:-]+',host) and type(port) is int and 1 <= port <= 65535
            and type(api_port) is int and 1 <= api_port <= 65535
            and re.fullmatch(r'[a-z_][a-z0-9_-]*',user), 'SSH_ADDRESS_REQUIRED')
    args = ['/usr/bin/ssh','-N','-T','-o','BatchMode=yes','-o','IdentitiesOnly=yes',
            '-o','StrictHostKeyChecking=yes','-o','ExitOnForwardFailure=yes',
            '-o','ServerAliveInterval=15','-o','ServerAliveCountMax=3',
            '-o','UserKnownHostsFile='+str(home/'agent-known-hosts'),'-i',home/'agent-tunnel-key',
            '-p',str(port),'-L','127.0.0.1:'+str(LOCAL_PORT)+':127.0.0.1:'+str(api_port),
            TUNNEL_USER+'@'+host]
    return ('[Unit]\nDescription=Encrypted API path to recovered Infisical\n'
            'Wants=network-online.target\nAfter=network-online.target\n[Service]\n'
            'Type=simple\nUser='+user+'\nGroup='+user+'\nExecStart='+shlex.join([str(x) for x in args])+
            '\nRestart=always\nRestartSec=5s\nUMask=0077\nStandardOutput=null\nStandardError=null\n'
            '[Install]\nWantedBy=multi-user.target\n').encode()


def prepare_private_outputs(rows, root, plan, uid=1000, gid=1000):
    """Hand rendered env files to the Agent without relaxing private inputs."""
    root = safe_path(root)
    marker = json.loads(private_file(root/'.generated/dr-render-complete.json').read_bytes())
    require(marker.get('root') == str(root) and isinstance(marker.get('outputs'), list)
            and all(isinstance(path, str) for path in marker['outputs']), 'AGENT_RENDER_MARKER_INVALID')
    generated = (set(plan['env_files']) | set(plan.get('service_folder_exports', {}))) & set(marker['outputs'])
    outputs = []
    # Validate the complete set before altering any owner or permission.
    for row in rows:
        output = safe_path(Path(row['destination-path']))
        require(output.is_relative_to(root/'.secrets'), 'AGENT_PRIVATE_OUTPUT_INVALID')
        if output.exists():
            info = output.stat()
            mode = stat.S_IMODE(info.st_mode)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'AGENT_PRIVATE_OUTPUT_INVALID')
            require(info.st_uid in (0, uid), 'AGENT_PRIVATE_OUTPUT_PERMISSIONS_INVALID')
            if mode == 0o640:
                # The pinned renderer creates these specific env outputs as
                # root:deployment-group 0640. The running Agent owns them 0600.
                require(output.relative_to(root).as_posix() in generated and info.st_gid == gid,
                        'AGENT_PRIVATE_OUTPUT_PERMISSIONS_INVALID')
            else:
                require(mode == 0o600, 'AGENT_PRIVATE_OUTPUT_PERMISSIONS_INVALID')
        outputs.append(output)
    for output in outputs:
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chown(output.parent, uid, gid)
        if output.exists():
            output.chmod(0o600)
            os.chown(output, uid, gid)
            private_file(output)


def install_cli(archive, library=Path('/usr/local/lib/streams-aio-recovery'), uid=0, gid=0):
    """Only the checksum-verified public executable gets traversable parents."""
    require(digest(archive) == CLI_SHA256, 'AGENT_CLI_SHA256_MISMATCH')
    library = safe_path(library)
    binary = library / 'infisical'
    with tarfile.open(archive, 'r:gz') as tar:
        members = [m for m in tar.getmembers() if m.name == 'infisical']
        require(len(members) == 1 and members[0].isfile()
                and 0 < members[0].size < 256 * 1024**2, 'AGENT_CLI_ARCHIVE_INVALID')
        with tar.extractfile(members[0]) as source:
            raw = source.read()
    if library.exists():
        info = library.stat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and info.st_gid == gid
                and stat.S_IMODE(info.st_mode) in (0o700, 0o755)
                and set(library.iterdir()) <= {binary}, 'AGENT_CLI_LIBRARY_REFUSED')
    if binary.exists():
        info = binary.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == uid and info.st_gid == gid and binary.read_bytes() == raw,
                'AGENT_EXISTING_INSTALLATION_CHANGED')
    library.mkdir(mode=0o755, exist_ok=True)
    # mkdir(mode=0755) alone becomes 0700 under the installer's umask 0077.
    # Do not apply this to the private recovery venv or credential directories.
    library.chmod(0o755)
    write_owned(binary, raw, uid, gid)
    binary.chmod(0o755)
    return binary


def first_render(agent, area, binary, user, uid=1000, gid=1000, dry_run=False, before_promote=None):
    """Require every fresh output before replacing any prepared env file.

    The pinned CLI can report a write error while exiting successfully, so an
    exit code and the existence of old destination files are insufficient.
    """
    with tempfile.TemporaryDirectory(prefix='first-render-', dir=area) as name:
        directory = safe_path(Path(name))
        os.chown(directory, uid, gid)
        isolated = copy.deepcopy(agent)
        isolated['infisical']['exit-after-auth'] = True
        paths = []
        for index, row in enumerate(isolated['templates']):
            path = directory / ('output-' + str(index))
            row['destination-path'] = str(path)
            paths.append(path)
        config = directory / 'config.json'
        save(config, isolated)
        os.chown(config, uid, gid)
        # sudo may reset the caller's umask to 0022. The pinned CLI creates
        # template files with os.Create (0666 before umask), so set 0077
        # after changing user. Positional arguments preserve literal paths.
        command(['sudo', '-H', '-u', user, '--', '/bin/sh', '-c',
                 'umask 077; exec "$@"', 'streams-aio-agent',
                 binary, 'agent', '--config', config],
                'AGENT_FIRST_RENDER_FAILED', timeout=180)
        material = []
        for path in paths:
            require(path.is_file() and not path.is_symlink(), 'AGENT_FIRST_RENDER_FAILED')
            info = path.stat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600
                    and info.st_uid == uid and info.st_gid == gid,
                    'AGENT_FIRST_RENDER_FAILED')
            material.append(path.read_bytes())
        # The complete audit runs the actual installer's rendering path,
        # including private permissions, without promoting any live output.
        if dry_run:
            return len(paths)
        destinations = [safe_path(Path(row['destination-path'])) for row in agent['templates']]
        for path in destinations:
            if path.exists():
                info = path.stat()
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == uid,
                        'AGENT_PRIVATE_OUTPUT_PERMISSIONS_INVALID')
        if before_promote is not None:
            before_promote(destinations,material)
        for path, raw in zip(destinations, material):
            fd, temp = tempfile.mkstemp(prefix='.agent-render-', dir=path.parent)
            try:
                with os.fdopen(fd, 'wb') as output:
                    output.write(raw)
                    output.flush()
                    os.fsync(output.fileno())
                    os.fchmod(output.fileno(), 0o600)
                    os.fchown(output.fileno(), uid, gid)
                os.replace(temp, path)
            finally:
                if os.path.exists(temp):
                    os.unlink(temp)
        return len(paths)


def install(home,root,config):
    import pwd
    state = checkpoint(home,root)
    user = pwd.getpwuid(1000).pw_name
    host,port,api = config['host'],config['port'],config['api_port']
    unit = tunnel_unit(home,user,host,port,api)
    host_key = config['host_key']
    require(re.fullmatch(r'(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/=]+',host_key),
            'AGENT_TUNNEL_HOST_KEY_INVALID')
    peer = host if port == 22 else '['+host+']:'+str(port)
    write_owned(home/'agent-known-hosts',(peer+' '+host_key+'\n').encode())
    key(home,root)
    unit_path = Path('/etc/systemd/system/streams-aio-infisical-tunnel.service')
    first = not unit_path.exists()
    if first:
        with socket.socket() as sock:
            try:
                sock.bind(('127.0.0.1',LOCAL_PORT))
            except OSError:
                raise Refused('AGENT_API_PORT_IN_USE') from None
    write_owned(unit_path,unit,0,0)
    command(['systemctl','daemon-reload'],'AGENT_SYSTEMD_INSTALL_FAILED')
    command(['systemctl','enable','--now','streams-aio-infisical-tunnel.service'],'AGENT_TUNNEL_NOT_READY')
    import urllib.request
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    for attempt in range(40):
        try:
            active = command(['systemctl','is-active','streams-aio-infisical-tunnel.service'],'AGENT_TUNNEL_NOT_READY')
            with opener.open('http://127.0.0.1:'+str(LOCAL_PORT)+'/api/status',timeout=3) as response:
                if active.strip() == b'active' and response.status == 200:
                    break
        except Exception:
            pass
        time.sleep(1)
    else:
        raise Refused('AGENT_TUNNEL_NOT_READY')
    area = safe_path(home/'native-agent')
    area.mkdir(mode=0o700,exist_ok=True)
    os.chown(area,1000,1000)
    if not (area/'backup').exists():
        unpack_agent(private_file(home/'private/infisical-agent.tar.gz'),area/'backup')
    recovered = agent_bootstrap(area/'backup')
    rows = recovered_private_templates(area/'backup',root)
    plan = json.loads((root/'config/dr-render-plan.json').read_bytes())
    preserve_local_inputs(area/'backup',plan)
    # Refuse an incomplete native mapping instead of losing secret updates.
    require(set(str(root/path) for path in plan['env_files']) <= {row['destination-path'] for row in rows},
            'AGENT_ENV_MAPPING_INCOMPLETE')
    prepare_private_outputs(rows, root, plan)
    for name in ('client_id','client_secret'):
        write_owned(area/name,private_file(recovered[name]).read_bytes())
    agent = dict(infisical={'address':'http://127.0.0.1:'+str(LOCAL_PORT)},
                 auth={'type':'universal-auth','config':{'client-id':str(area/'client_id'),
                       'client-secret':str(area/'client_secret'),'remove_client_secret_on_read':False}},
                 templates=rows)
    save(area/'agent-config.json',agent)
    os.chown(area/'agent-config.json',1000,1000)
    binary = pinned_cli(area,user)
    once = copy.deepcopy(agent)
    once['infisical']['exit-after-auth'] = True
    save(area/'agent-once.json',once)
    os.chown(area/'agent-once.json',1000,1000)
    first_render(agent, area, binary, user)
    raw = ('[Unit]\nDescription=Recovered Infisical native Agent\n'
           'Requires=streams-aio-infisical-tunnel.service\nAfter=streams-aio-infisical-tunnel.service\n'
           '[Service]\nType=simple\nUser='+user+'\nGroup='+user+'\nWorkingDirectory='+str(root)+
           '\nExecStart='+str(binary)+' agent --config '+str(area/'agent-config.json')+
           '\nRestart=always\nRestartSec=5s\nUMask=0077\nStandardOutput=null\nStandardError=null\n'
           '[Install]\nWantedBy=multi-user.target\n').encode()
    write_owned(Path('/etc/systemd/system/infisical-agent.service'),raw,0,0)
    command(['systemctl','daemon-reload'],'AGENT_SYSTEMD_INSTALL_FAILED')
    command(['systemctl','enable','--now','infisical-agent.service'],'AGENT_SYSTEMD_INSTALL_FAILED')
    require(command(['systemctl','is-active','infisical-agent.service'],'AGENT_SYSTEMD_INSTALL_FAILED').strip()==b'active',
            'AGENT_SYSTEMD_INSTALL_FAILED')
    state['native_agent'] = 'ACTIVE_NO_RESTART_HOOKS'
    state['native_agent_version'] = VERSION
    state['api_transport'] = 'PERSISTENT_SSH_LOOPBACK'
    save(home/'state.json',state)
    event('NATIVE_AGENT')


def main():
    import argparse
    import sys
    import fcntl
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('key','authorize','install'))
    parser.add_argument('--target',required=True)
    parser.add_argument('--state-home',required=True)
    args=parser.parse_args()
    require(os.geteuid()==0,'ROOT_RECOVERY_INSTALLER_REQUIRED')
    os.umask(0o077)
    home,root=safe_path(Path(args.state_home)),safe_path(Path(args.target))
    with (home/'recovery.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.action=='key':
            key(home,root)
        else:
            raw=sys.stdin.buffer.read(1024**2+1)
            require(len(raw)<=1024**2,'RECOVERY_REQUEST_TOO_LARGE')
            # sudo -S may leave an unused password line with NOPASSWD. Framed
            # public metadata follows it; private keys never leave the stack.
            parts=raw.split(b'STREAMS_NATIVE_V1\n',1)
            require(len(parts)==2,'RECOVERY_REQUEST_REQUIRED')
            config=json.loads(parts[1])
            (authorize if args.action=='authorize' else install)(home,root,config)


if __name__=='__main__':
    try:
        main()
    except Exception as error:
        event('REFUSED','REFUSED',str(error) if isinstance(error,Refused) else 'AGENT_INSTALL_FAILED')
        raise SystemExit(1)

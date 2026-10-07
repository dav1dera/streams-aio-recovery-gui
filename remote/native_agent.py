"""Install the pinned native Agent and an SSH-only API path on replacement VMs."""
import base64
import copy
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import socket
import tarfile
import tempfile
import time

from recover import (Refused, agent_bootstrap, command, digest, event, private_file,
                     require, safe_path, save, unpack_agent)

VERSION = '0.43.137'
CLI_URL = 'https://github.com/Infisical/cli/releases/download/v0.43.137/cli_0.43.137_linux_amd64.tar.gz'
CLI_SHA256 = '308a90c7f9c307cb9c348d352a797a3a63b02e1a7836adbe8afddfd75c855531'
TUNNEL_USER = 'streams-aio-tunnel'
LOCAL_PORT = 18180


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
        require((account_home/'recovery-owner').read_text() == state['machine_id'],
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
    options = 'restrict,port-forwarding,permitopen="127.0.0.1:'+str(port)+'",command="/bin/false" '
    write_owned(directory/'authorized_keys',(options+public+'\n').encode(),account.pw_uid,account.pw_gid)
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
    require(isinstance(obj.get('templates'),list), 'AGENT_BOOTSTRAP_CONFIG_NOT_UNIQUE')
    for original in obj['templates']:
        row = copy.deepcopy(original)
        destination = row.get('destination-path')
        require(isinstance(destination,str), 'AGENT_TEMPLATE_PATH_UNSUPPORTED')
        old = PurePosixPath(destination)
        source_root = PurePosixPath('/home/pi/streams-aio')
        require(old.is_relative_to(source_root) and '..' not in old.parts,
                'AGENT_TEMPLATE_PATH_UNSUPPORTED')
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


def install(home,root,config):
    import pwd
    import yaml
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
    candidates = [path for path in (area/'backup').rglob('*') if path.is_file()
                  and path.name in ('agent-config.json','agent-config.yaml','agent-config.yml')]
    require(len(candidates) == 1, 'AGENT_BOOTSTRAP_CONFIG_NOT_UNIQUE')
    obj = yaml.safe_load(candidates[0].read_bytes())
    rows = private_templates(obj,area/'backup',root)
    plan = json.loads((root/'config/dr-render-plan.json').read_bytes())
    # Refuse an incomplete native mapping instead of losing secret updates.
    require(set(str(root/path) for path in plan['env_files']) <= {row['destination-path'] for row in rows},
            'AGENT_ENV_MAPPING_INCOMPLETE')
    for row in rows:
        output = safe_path(Path(row['destination-path']))
        output.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        os.chown(output.parent,1000,1000)
        if output.exists():
            private_file(output)
            os.chown(output,1000,1000)
    for name in ('client_id','client_secret'):
        write_owned(area/name,private_file(recovered[name]).read_bytes())
    agent = dict(infisical={'address':'http://127.0.0.1:'+str(LOCAL_PORT)},
                 auth={'type':'universal-auth','config':{'client-id':str(area/'client_id'),
                       'client-secret':str(area/'client_secret'),'remove_client_secret_on_read':False}},
                 templates=rows)
    save(area/'agent-config.json',agent)
    os.chown(area/'agent-config.json',1000,1000)
    archive = area/'cli.tar.gz'
    if not archive.exists():
        command(['curl','--fail','--silent','--show-error','--location','--proto','=https',
                 '--proto-redir','=https','--max-time','180','--output',archive,CLI_URL], 'AGENT_CLI_DOWNLOAD_FAILED')
    require(digest(archive) == CLI_SHA256, 'AGENT_CLI_SHA256_MISMATCH')
    library = safe_path(Path('/usr/local/lib/streams-aio-recovery'))
    library.mkdir(mode=0o755,exist_ok=True)
    binary = library/'infisical'
    with tarfile.open(archive,'r:gz') as tar:
        members = [member for member in tar.getmembers() if member.name == 'infisical' and member.isfile()]
        require(len(members) == 1 and 0 < members[0].size < 256*1024**2, 'AGENT_CLI_ARCHIVE_INVALID')
        with tar.extractfile(members[0]) as source:
            raw = source.read()
        write_owned(binary,raw,0,0)
        binary.chmod(0o755)
    require(command([binary,'--version'],'AGENT_CLI_VERSION_MISMATCH').decode().strip() == 'infisical version '+VERSION,
            'AGENT_CLI_VERSION_MISMATCH')
    once = copy.deepcopy(agent)
    once['infisical']['exit-after-auth'] = True
    save(area/'agent-once.json',once)
    os.chown(area/'agent-once.json',1000,1000)
    command(['sudo','-H','-u',user,'--',binary,'agent','--config',area/'agent-once.json'],
            'AGENT_FIRST_RENDER_FAILED',timeout=180)
    for row in rows:
        output = safe_path(Path(row['destination-path']))
        require(output.is_file(), 'AGENT_FIRST_RENDER_FAILED')
        output.chmod(0o600)
        os.chown(output,1000,1000)
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

"""Private upload directories created for the authenticated deployment account."""

SETUP = r'''
import json,os,re,stat,sys
from pathlib import Path

def need(value):
    if not value:raise ValueError()

try:
    need(os.geteuid()==0 and len(sys.argv)==3)
    area,stage=map(Path,sys.argv[1:])
    share,local,home=area.parent,area.parent.parent,area.parent.parent.parent
    need(area.is_absolute() and area.name in ('streams-aio-recovery','streams-aio-infisical-recovery')
         and share.name=='share' and local.name=='.local'
         and stage.parent==area and re.fullmatch(r'upload-[0-9a-f]{32}',stage.name))
    need(not any(p.is_symlink() for p in (stage,*stage.parents)))
    info=home.stat()
    need(stat.S_ISDIR(info.st_mode) and (info.st_uid,info.st_gid)==(1000,1000)
         and not stat.S_IMODE(info.st_mode)&0o022)
    records={};repairs=set()
    for path,expected_child in ((local,'share'),(share,area.name),(area,None)):
        if not path.exists():continue
        info=path.stat();mode=stat.S_IMODE(info.st_mode)
        need(stat.S_ISDIR(info.st_mode) and not mode&0o022)
        if path==area:
            need((info.st_uid,info.st_gid)==(1000,1000) and mode==0o700)
        elif info.st_uid==1000:
            need(mode&0o100)
        elif (info.st_uid,info.st_gid)==(0,0) and mode==0o700:
            # The old uploader created only these two root-only parents.
            # Repair that exact scaffolding; unrelated root data is refused.
            need(all(child.name==expected_child for child in path.iterdir()))
            repairs.add(path)
        else:
            need(info.st_uid==0 and mode&0o001)
        records[path]=(info.st_dev,info.st_ino)
    need(not stage.exists())
    os.umask(0o077)
    descriptors=[]
    try:
        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
        parent=os.open(home,flags);descriptors.append(parent)
        for path in (local,share,area,stage):
            created=path not in records
            if created:os.mkdir(path.name,0o700,dir_fd=parent)
            child=os.open(path.name,flags,dir_fd=parent);descriptors.append(child)
            info=os.fstat(child)
            if not created:need((info.st_dev,info.st_ino)==records[path])
            if created or path in repairs:os.fchown(child,1000,1000)
            parent=child
    finally:
        for descriptor in reversed(descriptors):os.close(descriptor)
except Exception:
    print(json.dumps({'error':'SSH_UPLOAD_PATH_REFUSED'}))
    raise SystemExit(1)
'''

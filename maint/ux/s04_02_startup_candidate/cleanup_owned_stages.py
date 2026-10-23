"""Dispose only the two receipt-bound inert stages from startup145."""
import hashlib,json,os,signal,socket,stat,subprocess,sys
from pathlib import Path

BACK=Path('/var/run/osmap-service-admission-root-0464576abc319cc7')
FRONT=Path('/tmp/osmap-pxp-stage-e242601cc38f8f97')
RECEIPT_SHA='4db1618f4ed1c2d15b1550e8a808336b776139d5d45a7e9b58fb687daef1839c'
report={'schema':'osmap-startup145-stage-cleanup-v1','result':'FAIL','removed_files':0,
    'removed_directories':0,'service_or_account_operations':False}
def require(value,reason):
    if not value:raise RuntimeError(reason)
def identity(m):return(m.st_dev,m.st_ino,m.st_uid,m.st_gid,m.st_mode,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns)
def read(path,cap,owner=0):
    m=path.lstat();require(stat.S_ISREG(m.st_mode)and m.st_uid==m.st_gid==owner and m.st_nlink==1
        and not m.st_mode&0o022 and 0<m.st_size<=cap,'file_custody')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        require(identity(os.fstat(fd))==identity(m),'file_open_changed')
        chunks=[];total=0
        while total<=cap:
            part=os.read(fd,min(16384,cap+1-total))
            if not part:break
            chunks.append(part);total+=len(part)
        raw=b''.join(chunks)
        require(len(raw)==m.st_size and identity(os.fstat(fd))==identity(m)
            and identity(path.lstat())==identity(m),'file_read_changed')
        return raw,identity(m)
    finally:os.close(fd)


def cleanup_owned(back,front,receipt_sha,owner=0,run_fstat=subprocess.run):
    """Validate the complete receipt graph before deleting exact owned leaves."""
    raw,receipt_identity=read(back/'stage-ownership.json',131072,owner)
    require(hashlib.sha256(raw).hexdigest()==receipt_sha,'receipt_hash')
    receipt=json.loads(raw)
    require(set(receipt)=={'schema','source_commit','compiler_receipt_sha256','packet_sha256',
        'not_after_utc','backend','frontend','backend_identity','frontend_identity','disposition',
        'files','historical_pid_signals','admission_sha256'},'receipt_fields')
    require(receipt['schema']=='osmap-single-host-stage-v1'
        and receipt['backend']==str(back)and receipt['frontend']==str(front)
        and receipt['source_commit']=='b4bc371bd645ea009e4d257b269c73bd7294c8e9','receipt_scope')
    require(receipt['historical_pid_signals']is False and receipt['disposition']=='STAGES_RETAINED',
        'receipt_disposition')
    for root,key in ((back,'backend_identity'),(front,'frontend_identity')):
        m=root.lstat();require(root.resolve()==root and stat.S_ISDIR(m.st_mode)
            and stat.S_IMODE(m.st_mode)==0o700 and m.st_uid==m.st_gid==owner
            and identity(m)[:6]==tuple(receipt[key])[:6],'stage_identity')
    files={Path(k):tuple(v)for k,v in receipt['files'].items()}
    birth,birth_identity=read(back/'stage-birth.json',4096,owner)
    b=json.loads(birth);require(set(b)=={'schema','backend','backend_identity','source_commit',
        'packet_sha256','not_after_utc','disposition'},'birth_fields')
    require(b['schema']=='osmap-single-host-stage-birth-v1'and b['backend']==str(back)
        and b['source_commit']==receipt['source_commit']
        and b['packet_sha256']==receipt['packet_sha256']
        and tuple(b['backend_identity'])[:6]==tuple(receipt['backend_identity'])[:6],'birth_binding')
    files[back/'stage-birth.json']=birth_identity;files[back/'stage-ownership.json']=receipt_identity
    require(all(p.parent in (back,front)for p in files),'leaf_scope')
    require(set(back.iterdir())|set(front.iterdir())==set(files),'exact_leaf_set')
    for p,want in files.items():
        m=p.lstat();require(identity(m)==want and stat.S_ISREG(m.st_mode)
            and m.st_nlink==1 and m.st_uid==m.st_gid==owner,'leaf_identity')
    for root in (back,front):
        check=run_fstat(['/usr/bin/fstat','-n',*(str(p)for p in files if p.parent==root)],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8)
        require(check.returncode==0 and not check.stderr and len(check.stdout)<=1048576,'fstat_result')
        # The existing fixture uses this same exact-file fstat absence check.
        lines=check.stdout.splitlines();require(lines and lines[0].split()[:4]==[b'USER',b'CMD',b'PID',b'FD'],'fstat_header')
        require(len(lines)==1,'owned_leaf_still_open')
    for p,want in files.items():
        require(identity(p.lstat())==want,'leaf_changed_before_unlink')
        p.unlink();report['removed_files']+=1
    for root,key in ((front,'frontend_identity'),(back,'backend_identity')):
        require(identity(root.lstat())[:6]==tuple(receipt[key])[:6]and not tuple(root.iterdir()),'directory_changed')
        root.rmdir();report['removed_directories']+=1
    require(not os.path.lexists(back)and not os.path.lexists(front),'stages_not_absent')
    report.update(result='PASS',stage_paths_absent=True,open_leaf_references_absent=True)


def main():
    require((os.getuid(),os.geteuid(),socket.gethostname(),os.uname().sysname)==
        (0,0,'obsd1.blackbagsecurity.com','OpenBSD'),'target')
    cleanup_owned(BACK,FRONT,RECEIPT_SHA)
if __name__=='__main__':
    def stop(*_):raise RuntimeError('cleanup_deadline')
    signal.signal(signal.SIGALRM,stop);signal.alarm(30)
    try:main()
    except BaseException as error:report['failure']=str(error)if type(error)is RuntimeError else type(error).__name__
    finally:signal.alarm(0)
    print(json.dumps(report,sort_keys=True));sys.exit(0 if report['result']=='PASS'else 1)

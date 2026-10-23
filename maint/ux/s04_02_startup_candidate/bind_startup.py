"""Bind the retained Build141 packet to the corrected startup-only sources."""
import base64,hashlib,importlib.util,json,os,stat,subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parent
HISTORICAL=Path('/home/foo/Downloads/osmap-ux-s04/t03-progressive-20261023/milestone1-startup145')
REPO=Path('/home/foo/Workspace/OSMAP')
BUILD_SOURCE_COMMIT='b4bc371bd645ea009e4d257b269c73bd7294c8e9'


def require(value,code):
    if not value:raise RuntimeError(code)


def private(path,cap=4*1024*1024):
    m=path.lstat();require(stat.S_ISREG(m.st_mode)and m.st_uid==os.geteuid()and m.st_nlink==1
        and stat.S_IMODE(m.st_mode)==0o600 and 0<m.st_size<=cap,'private_input_custody')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=(m.st_dev,m.st_ino,m.st_mode,m.st_uid,m.st_gid,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns)
        ident=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        require(ident(os.fstat(fd))==before,'private_open');raw=os.read(fd,cap+1)
        require(len(raw)==m.st_size and ident(os.fstat(fd))==before and ident(path.lstat())==before,'private_continuity');return raw
    finally:os.close(fd)


def repository_source(path,cap=2*1024*1024):
    m=path.lstat();require(stat.S_ISREG(m.st_mode)and m.st_uid==os.geteuid()
        and m.st_nlink==1 and 0<m.st_size<=cap,
        'repository_source_custody')
    return path.read_bytes()


def source_packet():
    retained=private(HISTORICAL/'startup-bound-packet.json')
    require(hashlib.sha256(retained).hexdigest()=='c903271b7a535a1f92465216fd47189af6727efa35d207e106793db646fbf313',
        'retained_packet_pin')
    envelope=json.loads(retained)
    require(set(envelope)=={'root_source','packet'}and type(envelope['packet'])is dict,
        'retained_packet_shape')
    value=envelope['packet']
    spec=importlib.util.spec_from_file_location('candidate_stage_root',ROOT/'stage_root.py')
    stage_root=importlib.util.module_from_spec(spec);spec.loader.exec_module(stage_root)
    sources={}
    for name,pin in stage_root.SOURCE_PINS.items():
        path=ROOT/'startup_only.py'if name=='backend/startup_only.py'else ROOT/'sources'/name
        raw=private(path)
        require(hashlib.sha256(raw).hexdigest()==pin,'candidate_source_pin_'+name.replace('/','_'))
        sources[name]=base64.b64encode(raw).decode()
    value['sources']=sources
    return value


def packet():
    value=source_packet()
    # Build141 contains password_native_authority from BUILD_SOURCE_COMMIT.
    # The current corrected source no longer admits an OpenBSD release pin, so
    # a matching file hash is not sufficient authority to execute that binary.
    baseline=subprocess.check_output(
        ['git','show',BUILD_SOURCE_COMMIT+':src/openbsd.rs'],cwd=REPO,timeout=5)
    current=repository_source(REPO/'src/openbsd.rs')
    require(hashlib.sha256(current).digest()==hashlib.sha256(baseline).digest(),
        'retained_build_obsolete_openbsd_authority')
    return value

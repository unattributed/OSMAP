"""Fixed installed hash candidate custody, without production profile activation.

Hashes bind exact observed ELF bytes; this code never executes a loader, module
or metadata tool, parses a caller graph, or opens an operator configuration.
Public identity text admission belongs to the separate typed identity component.
"""
import hashlib,os,socket,stat,sys
from pathlib import Path
from authoritative_password import Refused
from account_hash_identity import _bound,_identity,AUTHORITY
from account_hash_graph_pins import FILES,MODULE_DIRECTORY,MODULE_NAMES,MODULE_CUSTODY,MODULE_ANCESTRY,SEARCH_DIRECTORY,SEARCH_CUSTODY,SEARCH_ANCESTRY,SEARCH_ENTRIES

FILE_CAP=64*1024*1024;TOTAL_CAP=128*1024*1024;DIRECTORY_ENTRY_CAP=256
# No public or private account database is unveiled to the hash child.
# Parent-side public passwd/group admission remains in HashChildIdentity.
PROMISES=b'stdio rpath wpath cpath prot_exec exec'

def _directory_identity(a):
    return (a.st_dev,a.st_ino,a.st_uid,a.st_gid,a.st_mode)

def _parents(path,budget,deadline):
    rows=[]
    for p in path.parents:
        _bound(budget,deadline);a=p.lstat()
        if not stat.S_ISDIR(a.st_mode) or a.st_uid!=0 or a.st_mode&0o022 or not a.st_mode&0o001:
            raise Refused('hash graph ancestry unavailable')
        rows.append((str(p),)+_directory_identity(a))
    return tuple(rows)

def _read(path,budget,deadline,total,limit,expected=None):
    allowed={row[0] for row in FILES}
    if str(path)not in allowed:raise Refused('hash graph fixed leaf unavailable')
    _bound(budget,deadline);parents=_parents(path,budget,deadline);before=path.lstat()
    # Only fixed public package objects. Owner
    # writes remain privileged; no immutable flag or privileged-race claim.
    executable=str(path)=='/usr/local/bin/doveadm'
    link_cap=64 if '.so'in path.name and not executable else 1
    if (not stat.S_ISREG(before.st_mode) or before.st_uid!=0
            or not 1<=before.st_nlink<=link_cap or before.st_mode&0o6022
            or not before.st_mode&0o004 or not 0<before.st_size<=min(limit,FILE_CAP)
            or total[0]+before.st_size>TOTAL_CAP or (executable and not before.st_mode&0o111)):
        raise Refused('hash graph public object unavailable')
    if expected is not None and (_identity(before)!=expected[0] or parents!=expected[2]):
        raise Refused('hash graph measured custody unavailable')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        if _identity(os.fstat(fd))!=_identity(before):raise Refused('hash graph public object changed')
        digest=hashlib.sha256();count=0
        while count<=limit:
            _bound(budget,deadline);part=os.read(fd,min(4096,limit+1-count))
            if not part:break
            count+=len(part);digest.update(part)
        result=(_identity(before),digest.hexdigest(),parents)
        if (count!=before.st_size or _identity(os.fstat(fd))!=_identity(before)
                or _identity(path.lstat())!=_identity(before) or _parents(path,budget,deadline)!=parents):
            raise Refused('hash graph public object changed')
        if expected is not None and result!=expected:raise Refused('hash graph public bytes changed')
        total[0]+=count;_bound(budget,deadline);return result
    finally:os.close(fd)

def _modules(budget,deadline):
    path=Path(MODULE_DIRECTORY);_bound(budget,deadline)
    parents=_parents(path,budget,deadline);before=path.lstat()
    if (not stat.S_ISDIR(before.st_mode) or _directory_identity(before)!=MODULE_CUSTODY
            or parents!=MODULE_ANCESTRY or before.st_uid!=0 or before.st_mode&0o022):
        raise Refused('hash graph module directory unavailable')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_DIRECTORY)
    try:
        if _directory_identity(os.fstat(fd))!=MODULE_CUSTODY:raise Refused('hash graph module directory changed')
        names=[]
        with os.scandir(fd) as entries:
            for entry in entries:
                _bound(budget,deadline);names.append(entry.name)
                if len(names)>DIRECTORY_ENTRY_CAP:raise Refused('hash graph module directory bound unavailable')
        # Stronger than inventory's .so filtering: ALL entries must be these
        # exact five public modules before inherited directory read is sealed.
        if (tuple(sorted(names))!=tuple(sorted(MODULE_NAMES))
                or _directory_identity(os.fstat(fd))!=MODULE_CUSTODY
                or _directory_identity(path.lstat())!=MODULE_CUSTODY
                or _parents(path,budget,deadline)!=parents):
            raise Refused('hash graph module membership changed')
        return MODULE_CUSTODY,parents,tuple(sorted(names))
    finally:os.close(fd)

def _search_parents(path,budget,deadline):
    rows=[]
    for parent in path.parents:
        _bound(budget,deadline);a=parent.lstat()
        if not stat.S_ISDIR(a.st_mode) or a.st_uid!=0 or a.st_mode&0o022 or not a.st_mode&0o001:
            raise Refused('hash search ancestry unavailable')
        rows.append((str(parent),)+_identity(a))
    return tuple(rows)

def _search_directory(budget,deadline):
    # One fixed public loader RPATH directory. Its read grant is recursive;
    # this custody observes only ALL immediate names/metadata, not descendants.
    path=Path(SEARCH_DIRECTORY);_bound(budget,deadline)
    before=path.lstat();parents=_search_parents(path,budget,deadline)
    if (not stat.S_ISDIR(before.st_mode) or before.st_uid!=0 or before.st_mode&0o022
            or _identity(before)!=SEARCH_CUSTODY or parents!=SEARCH_ANCESTRY):
        raise Refused('hash search directory unavailable')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_DIRECTORY)
    try:
        if _identity(os.fstat(fd))!=SEARCH_CUSTODY:raise Refused('hash search directory changed')
        def membership():
            _bound(budget,deadline);os.lseek(fd,0,os.SEEK_SET);names=[];size=0
            with os.scandir(fd) as entries:
                for entry in entries:
                    _bound(budget,deadline);raw=os.fsencode(entry.name);size+=len(raw)
                    if not 1<=len(raw)<=255 or len(names)>=DIRECTORY_ENTRY_CAP or size>16384:
                        raise Refused('hash search membership bound unavailable')
                    names.append(raw)
            rows=[]
            for name in sorted(names):
                _bound(budget,deadline);a=os.stat(name,dir_fd=fd,follow_symlinks=False)
                if (not (stat.S_ISREG(a.st_mode) or stat.S_ISDIR(a.st_mode))
                        or a.st_uid!=0 or a.st_mode&0o6022 or not a.st_mode&0o004):
                    raise Refused('hash search public member unavailable')
                rows.append((name,_identity(a)))
            return tuple(rows)
        rows=membership()
        if (rows!=SEARCH_ENTRIES or membership()!=rows or _identity(os.fstat(fd))!=SEARCH_CUSTODY
                or _identity(path.lstat())!=SEARCH_CUSTODY or _search_parents(path,budget,deadline)!=parents):
            raise Refused('hash search membership changed')
        _bound(budget,deadline);return SEARCH_CUSTODY,parents,rows
    finally:os.close(fd)

class HashInstalledGraph:
    def __init__(self,*_args,**_kwargs):raise Refused('hash graph construction unavailable')
    @classmethod
    def native(cls,budget,deadline):
        _bound(budget,deadline);system=os.uname()
        if (sys.platform!='openbsd7' or system.sysname!='OpenBSD' or system.release!='7.9'
                or system.machine!='amd64' or sys.byteorder!='little'
                or socket.gethostname()!=AUTHORITY or os.getuid()!=0 or os.geteuid()!=0):
            raise Refused('hash graph authority unavailable')
        states=cls._observe(budget,deadline)
        value=object.__new__(cls);value._budget=budget;value._states=states;return value
    @staticmethod
    def _observe(budget,deadline):
        _bound(budget,deadline);directory=_modules(budget,deadline);search=_search_directory(budget,deadline);total=[0];states=[]
        for name,metadata,digest,parents in FILES:
            states.append(_read(Path(name),budget,deadline,total,FILE_CAP,(metadata,digest,parents)))
        if _modules(budget,deadline)!=directory:raise Refused('hash graph module directory changed')
        if _search_directory(budget,deadline)!=search:raise Refused('hash search directory changed')
        _bound(budget,deadline);return tuple(states),directory,search
    def recheck(self,budget,deadline):
        if type(self)is not HashInstalledGraph or budget is not self._budget:
            raise Refused('hash graph original budget unavailable')
        if type(self)._observe(budget,deadline)!=self._states:raise Refused('hash graph custody changed')
        _bound(budget,deadline)
    @staticmethod
    def rows():
        # Exact leaf/hash checks remain. One fixed loader search directory now
        # grants recursive public read to reachable siblings/descendants; ALL
        # immediate membership is pinned, recursive bytes/lifetime are not.
        # Existing ALL-five module gate remains. No directory write/create.
        return tuple((name,b'rx' if name=='/usr/local/bin/doveadm' else b'r')
            for name,*_ in FILES)+((MODULE_DIRECTORY,b'r'),(SEARCH_DIRECTORY,b'r'),('/dev/null',b'rwc'))

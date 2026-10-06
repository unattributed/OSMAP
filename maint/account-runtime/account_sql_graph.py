"""Fixed SQL role custody and readonly null candidate; native profile disabled.

No path/promise comes from a caller. Only admitted NativeMaterial fixed config
and endpoint join the exact observed13 ELF+hints leaves. Effective runtime
loader, credential/grant and kernel qualification remains separate.
"""
import hashlib,os,socket,stat,sys
from pathlib import Path
from authoritative_password import Refused,AuthoritativePasswordAdapter as Adapter
from account_hash_identity import _bound,_identity,_null,AUTHORITY
from account_sql_graph_pins import FILES
from account_native_material import NativeMaterial,_SqlEndpoint
import account_native_material as material_source
SQL_PROGRAM='/usr/local/bin/mariadb'
FILE_CAP=64*1024*1024;TOTAL_CAP=128*1024*1024
PROMISES=b'stdio rpath unix prot_exec exec'

def _material(value):
    if (Adapter.SQL_PROGRAM!=SQL_PROGRAM or Adapter.SQL_ARGS!=(
            '--defaults-file='+str(material_source.CONFIG),'-N','-B','--raw','--database=postfixadmin')
            or type(value)is not NativeMaterial or getattr(value,'_owner',None)!=0
            or getattr(value,'_plan',None)!=material_source.PLAN
            or getattr(value,'_config',None)!=material_source.CONFIG
            or type(getattr(value,'_endpoint',None))is not _SqlEndpoint
            or str(value._endpoint.path)not in material_source.SQL_SOCKETS
            or type(value._endpoint.uid)is not int or not 0<value._endpoint.uid<2**32-1
            or getattr(value,'_identity_source',None)is not NativeMaterial._server
            or type(getattr(value,'_states',None))is not tuple or len(value._states)!=4):
        raise Refused('SQL graph fixed material unavailable')

def _directory_identity(a):
    return (a.st_dev,a.st_ino,a.st_uid,a.st_gid,a.st_mode)

def _parents(path,budget,deadline):
    rows=[]
    for p in path.parents:
        _bound(budget,deadline);a=p.lstat()
        if not stat.S_ISDIR(a.st_mode) or a.st_uid!=0 or a.st_mode&0o022 or not a.st_mode&0o001:
            raise Refused('SQL graph ancestry unavailable')
        rows.append((str(p),)+_directory_identity(a))
    return tuple(rows)

def _read(path,budget,deadline,total,limit,expected=None):
    allowed={row[0] for row in FILES}
    if str(path)not in allowed:raise Refused('SQL graph fixed leaf unavailable')
    _bound(budget,deadline);parents=_parents(path,budget,deadline);before=path.lstat()
    # Only fixed public package objects. Owner
    # writes remain privileged; no immutable flag or privileged-race claim.
    executable=str(path)==SQL_PROGRAM
    link_cap=64 if '.so'in path.name and not executable else 1
    if (not stat.S_ISREG(before.st_mode) or before.st_uid!=0
            or not 1<=before.st_nlink<=link_cap or before.st_mode&0o6022
            or not before.st_mode&0o004 or not 0<before.st_size<=min(limit,FILE_CAP)
            or total[0]+before.st_size>TOTAL_CAP or (executable and not before.st_mode&0o111)):
        raise Refused('SQL graph public object unavailable')
    if expected is not None and (_identity(before)!=expected[0] or parents!=expected[2]):
        raise Refused('SQL graph measured custody unavailable')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        if _identity(os.fstat(fd))!=_identity(before):raise Refused('SQL graph public object changed')
        digest=hashlib.sha256();count=0
        while count<=limit:
            _bound(budget,deadline);part=os.read(fd,min(4096,limit+1-count))
            if not part:break
            count+=len(part);digest.update(part)
        result=(_identity(before),digest.hexdigest(),parents)
        if (count!=before.st_size or _identity(os.fstat(fd))!=_identity(before)
                or _identity(path.lstat())!=_identity(before) or _parents(path,budget,deadline)!=parents):
            raise Refused('SQL graph public object changed')
        if expected is not None and result!=expected:raise Refused('SQL graph public bytes changed')
        total[0]+=count;_bound(budget,deadline);return result
    finally:os.close(fd)

class SqlInstalledGraph:
    def __init__(self,*_args,**_kwargs):raise Refused('SQL graph construction unavailable')
    @classmethod
    def native(cls,budget,deadline,material):
        _bound(budget,deadline);_material(material);system=os.uname()
        if (sys.platform!='openbsd7' or system.sysname!='OpenBSD' or system.release!='7.9'
                or system.machine!='amd64' or sys.byteorder!='little'
                or socket.gethostname()!=AUTHORITY or os.getuid()!=0 or os.geteuid()!=0):
            raise Refused('SQL graph authority unavailable')
        states=cls._observe(budget,deadline,material)
        value=object.__new__(cls);value._budget=budget;value._material=material;value._states=states;return value
    @staticmethod
    def _observe(budget,deadline,material):
        _bound(budget,deadline);_material(material)
        # Closed original material parser/NOFOLLOW/hash/Unix kernel peer only;
        # no credential or SQL bytes are sent by this recheck.
        material.recheck(budget);_bound(budget,deadline);total=[0];states=[]
        for name,metadata,digest,parents in FILES:
            states.append(_read(Path(name),budget,deadline,total,FILE_CAP,(metadata,digest,parents)))
        null=_null(budget,deadline);_bound(budget,deadline);return tuple(states),null
    def recheck(self,budget,deadline):
        if type(self)is not SqlInstalledGraph or budget is not self._budget:
            raise Refused('SQL graph original budget unavailable')
        if type(self)._observe(budget,deadline,self._material)!=self._states:
            raise Refused('SQL graph custody changed')
        _bound(budget,deadline)
    @staticmethod
    def rows(material):
        _material(material)
        # Socket w grants connection only; no c permission anywhere, no wpath /
        # cpath promise, directory grants or null write authority. Root retained
        # only to read the source-fixed0600 client config; no UID choice exposed.
        return tuple((name,b'rx' if name==SQL_PROGRAM else b'r') for name,*_ in FILES)+(
            (str(material_source.CONFIG),b'r'),(str(material._endpoint.path),b'w'),('/dev/null',b'r'))

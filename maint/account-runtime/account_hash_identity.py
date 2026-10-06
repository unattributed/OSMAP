"""Fixed purpose-private hash child identity and existing-null DAC custody.

Source-only: no identity provisioning, profile activation, caller UID/path,
NSS/password database lookup, socket/SQL/auth access, or device mutation.
"""
import hashlib,math,os,re,socket,stat,sys,time
from pathlib import Path
from authoritative_password import Refused
from operation_budget import OperationBudget
NAME='_osmaphash';AUTHORITY='mail.blackbagsecurity.com'
PASSWD=Path('/etc/passwd');GROUP=Path('/etc/group')
NULL_DEVICE=Path('/dev/null');NULL_RDEV=514
PUBLIC_FILE_CAP=65536;PUBLIC_TOTAL_CAP=131072;RECORD_CAP=1024;LINE_CAP=1024

def _bound(budget,deadline):
    if (type(budget)is not OperationBudget or type(deadline)not in (int,float)
            or not math.isfinite(deadline) or deadline<=time.monotonic()
            or not budget.inherited_group()):raise Refused('hash identity original phase unavailable')
    budget.remaining()

def _identity(a):
    return (a.st_dev,a.st_ino,a.st_uid,a.st_gid,a.st_mode,a.st_nlink,a.st_size,a.st_mtime_ns,a.st_ctime_ns)

def _parents(path,budget,deadline):
    rows=[]
    for p in path.parents:
        _bound(budget,deadline);a=p.lstat()
        if not stat.S_ISDIR(a.st_mode) or a.st_uid!=0 or a.st_mode&0o022 or not a.st_mode&0o001:
            raise Refused('hash identity ancestry unavailable')
        rows.append((str(p),a.st_dev,a.st_ino,a.st_uid,a.st_gid,a.st_mode))
    return tuple(rows)

def _read(path,budget,deadline,total):
    # Only the source-owned publicly readable text files; never master.passwd,
    # spwd.db/getpwnam/NSS or arbitrary operator configuration/content.
    if path not in (PASSWD,GROUP):raise Refused('hash identity public path unavailable')
    _bound(budget,deadline);parents=_parents(path,budget,deadline);a=path.lstat()
    if (not stat.S_ISREG(a.st_mode) or a.st_uid!=0 or a.st_nlink!=1
            or a.st_mode&0o6022 or not a.st_mode&0o004
            or not 0<a.st_size<=PUBLIC_FILE_CAP or total[0]+a.st_size>PUBLIC_TOTAL_CAP):
        raise Refused('hash identity public file unavailable')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        if _identity(os.fstat(fd))!=_identity(a):raise Refused('hash identity public file changed')
        raw=bytearray()
        while len(raw)<=PUBLIC_FILE_CAP:
            _bound(budget,deadline);part=os.read(fd,min(4096,PUBLIC_FILE_CAP+1-len(raw)))
            if not part:break
            raw.extend(part)
        if (len(raw)!=a.st_size or _identity(os.fstat(fd))!=_identity(a)
                or _identity(path.lstat())!=_identity(a) or _parents(path,budget,deadline)!=parents):
            raise Refused('hash identity public file changed')
        total[0]+=len(raw);return (_identity(a),hashlib.sha256(raw).digest(),parents),bytes(raw)
    finally:os.close(fd)

def _records(raw,fields):
    if type(raw)is not bytes or not 0<len(raw)<=PUBLIC_FILE_CAP or b'\0'in raw:
        raise Refused('hash identity record unavailable')
    lines=raw.split(b'\n')
    if lines[-1]==b'':lines.pop()
    if not lines or len(lines)>RECORD_CAP:raise Refused('hash identity record unavailable')
    result=[]
    for line in lines:
        if not line or line.startswith(b'#'):continue
        row=line.split(b':')
        # Public unrelated names/password/gecos/member bytes are opaque. No
        # private password-lock inference, ASCII normalization or NSS lookup.
        # Local numeric identities remain bounded; YP +/- directives refuse.
        if len(line)>LINE_CAP or len(row)!=fields or not row[0] or row[0][:1]in (b'+',b'-'):
            raise Refused('hash identity record unavailable')
        result.append(row)
    return result

def _number(text):
    if type(text)is not bytes or not re.fullmatch(rb'[0-9]{1,10}',text):raise Refused('hash identity number unavailable')
    value=int(text)
    if value>4294967295:raise Refused('hash identity number unavailable')
    return value

def _selected(passwd,group):
    users=_records(passwd,7);groups=_records(group,4)
    target=[u for u in users if u[0]==NAME.encode('ascii')];chosen=[g for g in groups if g[0]==NAME.encode('ascii')]
    if len(target)!=1 or len(chosen)!=1:raise Refused('hash purpose-private identity unavailable')
    user=target[0];entry=chosen[0];uid=_number(user[2]);gid=_number(user[3])
    if (not 0<uid<=2147483647 or not 0<gid<=2147483647 or uid in (32766,32767) or gid in (32766,32767) or _number(entry[2])!=gid
            or user[5:]!=[b'/var/empty',b'/sbin/nologin'] or entry[3]
            or sum(_number(u[2])==uid for u in users)!=1 or sum(_number(u[3])==gid for u in users)!=1
            or sum(_number(g[2])==gid for g in groups)!=1
            or any(NAME.encode('ascii') in (member.strip() for member in g[3].split(b',')) for g in groups)):
        raise Refused('hash purpose-private identity unavailable')
    return uid,gid

def _null(budget,deadline):
    parents=_parents(NULL_DEVICE,budget,deadline);_bound(budget,deadline);a=NULL_DEVICE.lstat()
    if (not stat.S_ISCHR(a.st_mode) or a.st_uid!=0 or a.st_gid!=0 or a.st_nlink!=1
            or stat.S_IMODE(a.st_mode)!=0o666 or a.st_rdev!=NULL_RDEV):
        raise Refused('hash existing null custody unavailable')
    # No open, chmod/chflags/chown/unlink/rename/mknod of the device occurs.
    return (_identity(a),a.st_rdev,parents)

class HashChildIdentity:
    def __init__(self,*_args,**_kwargs):raise Refused('hash identity construction unavailable')
    @classmethod
    def native(cls,budget,deadline):
        _bound(budget,deadline)
        platform=os.uname()
        if (sys.platform!='openbsd7' or os.getuid()!=0 or os.geteuid()!=0
                or platform.sysname!='OpenBSD' or platform.release!='7.9' or platform.machine!='amd64'
                or sys.byteorder!='little' or socket.gethostname()!=AUTHORITY):
            raise Refused('hash identity platform unavailable')
        required=('setgroups','getgroups','setresgid','getresgid','setresuid','getresuid')
        if any(not callable(getattr(os,n,None)) for n in required):raise Refused('hash identity ABI unavailable')
        total=[0];p,passwd=_read(PASSWD,budget,deadline,total);g,group=_read(GROUP,budget,deadline,total)
        uid,gid=_selected(passwd,group);null=_null(budget,deadline)
        value=object.__new__(cls);value._budget=budget;value._uid=uid;value._gid=gid
        value._public=(p,g);value._null=null;value.recheck(budget,deadline);return value
    def recheck(self,budget,deadline):
        if type(self)is not HashChildIdentity or budget is not self._budget:raise Refused('hash identity budget unavailable')
        total=[0];p,passwd=_read(PASSWD,budget,deadline,total);g,group=_read(GROUP,budget,deadline,total)
        if (self._public!=(p,g) or _selected(passwd,group)!=(self._uid,self._gid)
                or _null(budget,deadline)!=self._null):raise Refused('hash identity custody changed')
        _bound(budget,deadline)
    def drop(self,budget,deadline):
        # Child only, before final pledge/exec. Drop every saved/real/effective
        # identity and inherited supplemental group; never initgroups or id pledge.
        if os.getuid()!=0 or os.geteuid()!=0:raise Refused('hash identity privileged setup unavailable')
        self.recheck(budget,deadline);os.chdir('/');_bound(budget,deadline)
        os.setgroups(())
        if os.getgroups()!=[]:raise Refused('hash identity supplemental groups unavailable')
        _bound(budget,deadline);os.setresgid(self._gid,self._gid,self._gid)
        if os.getresgid()!=(self._gid,)*3:raise Refused('hash identity group drop unavailable')
        _bound(budget,deadline);os.setresuid(self._uid,self._uid,self._uid)
        if (os.getresuid()!=(self._uid,)*3 or os.getuid()!=self._uid or os.geteuid()!=self._uid
                or os.getgid()!=self._gid or os.getegid()!=self._gid or os.getgroups()!=[]):
            raise Refused('hash identity user drop unavailable')
        _bound(budget,deadline)

"""Fixed primary private-client/listener custody; native admission remains closed.

The ordinary auth-client0600 is never selected. The separate fixed listener
and reviewed dedicated client
identity + listener0660/private GID is required. No provision/config or credential
protocol occurs here, and metadata server UID alone never attests its peer.
"""
import os,socket,stat,sys,time
from pathlib import Path
import account_hash_identity as h
from account_mutation_supervisor import _peer
from authoritative_password import Refused
from operation_budget import _OriginalReceipt
NAME='_osmapprimary'
SOCKET=Path('/var/dovecot/osmap-account-auth-client')
SERVER_UID=518
# Authoritative metadata15October observes ordinary filesystem owner518.
# The selected private listener is absent; its kernel binder is not observed.
# Tagged kernel records bind identity, not chown owner/accepting process UID.
PEER_BIND_UID=None
PEER_SECONDS=1

def _original(budget,deadline):
    h._bound(budget,deadline)
    receipt=getattr(budget,'_original_receipt',None)
    if type(receipt)is not _OriginalReceipt:raise Refused('primary original receipt unavailable')
    budget.require_original(sent_millis=receipt.sent_millis,deadline_millis=receipt.deadline_millis,expires_at=receipt.expires_at)

def _selected(passwd,group):
    users=h._records(passwd,7);groups=h._records(group,4);name=NAME.encode('ascii')
    found=[u for u in users if u[0]==name];chosen=[g for g in groups if g[0]==name]
    if len(found)!=1 or len(chosen)!=1:raise Refused('primary private identity unavailable')
    user=found[0];entry=chosen[0];uid=h._number(user[2]);gid=h._number(user[3])
    if (not 0<uid<=2147483647 or not 0<gid<=2147483647
            or uid in (SERVER_UID,32766,32767) or gid in (32766,32767)
            or h._number(entry[2])!=gid or user[5:]!=[b'/var/empty',b'/sbin/nologin'] or entry[3]
            or sum(h._number(u[2])==uid for u in users)!=1
            or sum(h._number(u[3])==gid for u in users)!=1
            or sum(h._number(g[2])==gid for g in groups)!=1
            or any(name in (v.strip()for v in g[3].split(b','))for g in groups)):
        raise Refused('primary private identity unavailable')
    return uid,gid

def _socket(uid,gid,budget,deadline):
    # UID/GID only arrive from the source-fixed selected public record; no
    # public class accepts them. Parent is privileged, sends zero auth bytes.
    _original(budget,deadline)
    if type(PEER_BIND_UID)is not int or not 0<=PEER_BIND_UID<2**32-1:
        raise Refused('primary fixed kernel peer admission unavailable')
    parents=h._parents(SOCKET,budget,deadline);before=SOCKET.lstat()
    if (uid==SERVER_UID or gid==0 or not stat.S_ISSOCK(before.st_mode)
            or before.st_uid!=SERVER_UID or before.st_gid!=gid or before.st_nlink!=1
            or stat.S_IMODE(before.st_mode)!=0o660):
        raise Refused('primary private listener DAC unavailable')
    _original(budget,deadline)
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)as stream:
        seconds=min(PEER_SECONDS,budget.remaining(),deadline-time.monotonic())
        if seconds<=0:raise Refused('primary peer deadline unavailable')
        stream.settimeout(seconds);stream.connect(str(SOCKET))
        _original(budget,deadline)
        if (_peer(stream)!=PEER_BIND_UID or h._identity(SOCKET.lstat())!=h._identity(before)
                or h._parents(SOCKET,budget,deadline)!=parents):
            raise Refused('primary listener peer/custody unavailable')
        _original(budget,deadline)
    return h._identity(before),parents

class PrimaryChildIdentity:
    def __init__(self,*_args,**_kwargs):raise Refused('primary identity construction unavailable')
    @classmethod
    def native(cls,budget,deadline):
        _original(budget,deadline)
        if type(PEER_BIND_UID)is not int or not 0<=PEER_BIND_UID<2**32-1:
            raise Refused('primary fixed kernel peer admission unavailable')
        platform=os.uname()
        if (sys.platform!='openbsd7' or os.getuid()!=0 or os.geteuid()!=0
                or platform.sysname!='OpenBSD' or platform.release!='7.9' or platform.machine!='amd64'
                or sys.byteorder!='little' or socket.gethostname()!=h.AUTHORITY):
            raise Refused('primary identity platform unavailable')
        if any(not callable(getattr(os,n,None))for n in ('setgroups','getgroups','setresgid','getresgid','setresuid','getresuid')):
            raise Refused('primary identity ABI unavailable')
        total=[0];p,passwd=h._read(h.PASSWD,budget,deadline,total);g,group=h._read(h.GROUP,budget,deadline,total)
        uid,gid=_selected(passwd,group);null=h._null(budget,deadline);endpoint=_socket(uid,gid,budget,deadline)
        value=object.__new__(cls);value._budget=budget;value._uid=uid;value._gid=gid
        value._public=(p,g);value._null=null;value._socket=endpoint;value.recheck(budget,deadline);return value
    def recheck(self,budget,deadline):
        if type(self)is not PrimaryChildIdentity or budget is not self._budget:raise Refused('primary identity budget unavailable')
        _original(budget,deadline);total=[0]
        p,passwd=h._read(h.PASSWD,budget,deadline,total);g,group=h._read(h.GROUP,budget,deadline,total)
        if (self._public!=(p,g) or _selected(passwd,group)!=(self._uid,self._gid)
                or h._null(budget,deadline)!=self._null
                or _socket(self._uid,self._gid,budget,deadline)!=self._socket):
            raise Refused('primary identity custody changed')
        _original(budget,deadline)
    def drop(self,budget,deadline):
        # Child only before final pledge/exec. Dedicated primary GID is the
        # listener group; supplementary membership and saved root are removed.
        if os.getuid()!=0 or os.geteuid()!=0:raise Refused('primary privileged setup unavailable')
        self.recheck(budget,deadline);os.chdir('/');_original(budget,deadline);os.setgroups(())
        if os.getgroups()!=[]:raise Refused('primary supplemental groups unavailable')
        _original(budget,deadline);os.setresgid(self._gid,self._gid,self._gid)
        if os.getresgid()!=(self._gid,)*3:raise Refused('primary group drop unavailable')
        _original(budget,deadline);os.setresuid(self._uid,self._uid,self._uid)
        if (os.getresuid()!=(self._uid,)*3 or os.getuid()!=self._uid or os.geteuid()!=self._uid
                or os.getgid()!=self._gid or os.getegid()!=self._gid or os.getgroups()!=[]):
            raise Refused('primary user drop unavailable')
        _original(budget,deadline)

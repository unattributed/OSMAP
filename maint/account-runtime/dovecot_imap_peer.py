"""Fixed OpenBSD IMAP peer custody; native admission remains disabled.

SO_PEERCRED is connect-time kernel authority, never a submitted PID or socket
inode owner. Exact installed ABI, process layout and actual race remain required.
"""
import ctypes
from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
import selectors
import socket
import stat
import subprocess
import sys
import time

from authoritative_password import Refused
from operation_budget import OperationBudget
from mail_session_containment import MailSessionContainment
from smtp_native_peer import NativeSmtpPeerInspector, _MetadataExecutor, PS, FSTAT, PS_FIELDS

NATIVE_IMAP_PEER_QUALIFIED=False
IMAP=Path('/usr/local/libexec/dovecot/imap')
MASTER=Path('/usr/local/sbin/dovecot')
PLUGIN=Path('/usr/local/lib/dovecot/lib90_osmap_imap_epoch_plugin.so')
RUNTIME=Path('/usr/local/libexec/osmap/account-runtime')
_SOURCE_NAMES=('dovecot_auth_epoch.py','dovecot_imap_peer.py','dovecot_imap_publication.py',
               'dovecot_imap_service.py','account_epoch.py','operation_budget.py',
               'smtp_native_peer.py','mail_session_containment.py')


def _require(value):
    if not value:raise Refused('IMAP native peer unavailable')


def bounded_who(account,deadline):
    """One exact read-only command, original cap and retained child on doubt."""
    left=deadline-time.monotonic();_require(0<left<=.5)
    budget=OperationBudget(math.ceil(time.time()+left),maximum_seconds=left)
    budget.attach_owned_process_group()
    _require(not _MetadataExecutor._retained and not _MetadataExecutor._quarantined)
    child=None;selector=None;uncertain=False;output=bytearray();error=bytearray()
    work=deadline-.01
    try:
        budget.remaining();_require(time.monotonic()<work)
        child=subprocess.Popen((MailSessionContainment.PROGRAM,)+MailSessionContainment.commands(account)['who'],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            shell=False,close_fds=True,start_new_session=False,
            env={'PATH':'/usr/bin:/usr/local/bin','LC_ALL':'C'})
        selector=selectors.DefaultSelector()
        for pipe,kind in ((child.stdout,'out'),(child.stderr,'err')):
            os.set_blocking(pipe.fileno(),False);selector.register(pipe,selectors.EVENT_READ,kind)
        while selector.get_map():
            remaining=min(work-time.monotonic(),budget.remaining());_require(remaining>0)
            for key,_ in selector.select(min(remaining,.01)):
                try:data=os.read(key.fd,4096)
                except BlockingIOError:continue
                if not data:selector.unregister(key.fileobj);key.fileobj.close();continue
                dest=output if key.data=='out'else error;dest.extend(data)
                _require(len(dest)<=4096)
        remaining=min(work-time.monotonic(),budget.remaining());_require(remaining>0)
        code=child.wait(timeout=remaining);budget.remaining();_require(time.monotonic()<work)
        return code,bytes(output),bytes(error)
    finally:
        if selector is not None:
            try:selector.close()
            except BaseException:uncertain=True
        if child is not None:
            try:
                if child.poll()is None:
                    child.kill()
                    child.wait(timeout=max(0,min(deadline-time.monotonic(),budget.remaining())))
            except BaseException:
                if child not in _MetadataExecutor._retained:_MetadataExecutor._retained.append(child)
                uncertain=True
            finally:
                for pipe in (child.stdout,child.stderr):
                    try:
                        if not pipe.closed:pipe.close()
                    except BaseException:uncertain=True
        if uncertain:
            _MetadataExecutor._quarantined=True
            raise Refused('IMAP metadata cleanup unconfirmed')from None


class _SockPeerCred(ctypes.Structure):
    # Root-retained installed socket.h confirms order/constants; public _types.h
    # 1.10 supplies widths. Installed compiled sizeof/offset proof remains open.
    _fields_=[('uid',ctypes.c_uint32),('gid',ctypes.c_uint32),('pid',ctypes.c_int32)]


def kernel_peer(stream):
    """No recv/send. Refuse unknown OS/ABI instead of another OS's option."""
    _require(sys.platform.startswith('openbsd')and os.uname().sysname=='OpenBSD'
             and os.uname().machine=='amd64'
             and type(stream)is socket.socket and stream.family==socket.AF_UNIX
             and stream.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)==socket.SOCK_STREAM
             and ctypes.sizeof(_SockPeerCred)==12
             and tuple(getattr(_SockPeerCred,k).offset for k in ('uid','gid','pid'))==(0,4,8)
             and ctypes.sizeof(ctypes.c_uint32)==4 and ctypes.sizeof(ctypes.c_int)==4)
    fd=stream.fileno();before=NativeSmtpPeerInspector._identity(os.fstat(fd))
    _require(stat.S_ISSOCK(before[4])and fd>=0)
    libc=ctypes.CDLL(None,use_errno=True)
    call=libc.getsockopt
    call.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_void_p,
                   ctypes.POINTER(ctypes.c_uint32)]
    call.restype=ctypes.c_int
    credentials=_SockPeerCred();size=ctypes.c_uint32(ctypes.sizeof(credentials))
    _require(call(fd,0xffff,0x1022,ctypes.byref(credentials),ctypes.byref(size))==0
             and size.value==12 and stream.fileno()==fd
             and NativeSmtpPeerInspector._identity(os.fstat(fd))==before
             and 1<credentials.pid<2**31 and credentials.uid<2**32-1
             and credentials.gid<2**32-1)
    return credentials.pid,credentials.uid,credentials.gid


@dataclass(frozen=True,repr=False)
class _PeerBinding:
    inspector: object
    stream: object
    descriptor: int
    descriptor_identity: tuple
    credentials: tuple
    rows: tuple
    pcbs: tuple
    budget: OperationBudget
    deadline: float


class NativeImapPeerInspector:
    """Trusted startup fixes account scope/master and root file identities.

    No wire account can select a binary, command, principal or ancestor. The
    native factory is deliberately unavailable pending installed ABI/custody.
    """
    def __init__(self,master_pid,accounts):
        _require(type(master_pid)is int and 1<master_pid<2**31
                 and type(accounts)is frozenset and 1<=len(accounts)<=64)
        from authoritative_password import AuthoritativePasswordAdapter
        for account in accounts:AuthoritativePasswordAdapter._account(account)
        self._master_pid=master_pid;self._accounts=accounts
        self._own_pid=os.getpid();self._helper=Path(sys.executable).resolve(strict=True)
        self._custody=self._files();self._native=False
        self._startup_master=None;self._startup_own=None

    def _files(self):
        programs=(Path(PS),Path(FSTAT),Path(MailSessionContainment.PROGRAM),IMAP,MASTER,self._helper)
        files=programs+(PLUGIN,)+tuple(RUNTIME/name for name in _SOURCE_NAMES)
        return tuple((str(p),NativeSmtpPeerInspector._file(p,program=p in programs))for p in files)

    def _anchor(self,budget):
        # Operator observations supply no standing PID/birth authority. Native
        # startup freshly binds master and our own process BEFORE listening.
        _require(type(budget)is OperationBudget and budget.inherited_group())
        deadline=time.monotonic()+budget.cap_seconds(.5)
        pids=(self._master_pid,self._own_pid);executor=_MetadataExecutor(budget,pids)
        def rows():
            values=executor.pair(PS,tuple(('-p',str(pid),'-o',PS_FIELDS)for pid in pids),deadline)
            return tuple(NativeSmtpPeerInspector._rows(NativeSmtpPeerInspector._checked(v,budget,deadline),(pid,))[pid]
                         for pid,v in zip(pids,values))
        master,own=rows()
        _require(master[1]==1 and master[2]==master[0]and master[3:5]==(0,0)
                 and master[-1]=='dovecot'and own[0]==own[2]==os.getpid()
                 and own[3:5]==(0,0))
        values=executor.pair(FSTAT,tuple(('-n','-p',str(pid))for pid in pids),deadline)
        programs=dict(self._custody)
        for row,program,value in zip((master,own),(MASTER,self._helper),values):
            self._descriptors(NativeSmtpPeerInspector._checked(value,budget,deadline),
                              row[0],row[-1],programs[str(program)][0])
        _require(rows()==(master,own)and self._files()==self._custody)
        budget.remaining();self._startup_master=master;self._startup_own=own

    @staticmethod
    def _descriptors(raw,pid,comm,binary):
        """Read-only fstat grammar: exact text inode and connected Unix PCBs."""
        _require(type(raw)is bytes and 0<len(raw)<=65536 and b'\0'not in raw)
        try:lines=raw.decode('ascii').splitlines()
        except UnicodeError:raise Refused('IMAP descriptor metadata unavailable')from None
        _require(1<=len(lines)<=256 and lines[0].split()==
                 ['USER','CMD','PID','FD','DEV','INUM','MODE','R/W','SZ|DV'])
        texts=[];connections={}
        for line in lines[1:]:
            fields=line.split()
            _require(len(fields)>=4 and fields[1:3]==[comm,str(pid)])
            if fields[3]=='text':
                match=re.fullmatch(r'\S+\s+'+re.escape(comm)+r'\s+'+str(pid)+
                    r'\s+text\s+(\d+),\s*(\d+)\s+(\d+)\s+([0-7]+)\s+.*',line)
                _require(match is not None)
                texts.append((int(match[1]),int(match[2]),int(match[3]),int(match[4],8)))
            elif len(fields)>=6 and fields[4:6]==['unix','stream']:
                # Only a fully open connected socket can bind this request.
                if len(fields)<9 or fields[7]!='<->':continue
                _require(len(fields)in (9,10)and re.fullmatch(r'[0-9]{1,10}\*',fields[3])
                         and all(re.fullmatch(r'0x[0-9a-fA-F]{1,16}',v)and int(v,16)>0
                                 for v in (fields[6],fields[8])))
                fd=int(fields[3][:-1]);_require(fd not in connections and fd<2**31)
                connections[fd]=(int(fields[6],16),int(fields[8],16))
        _require(texts==[(os.major(binary[0]),os.minor(binary[0]),binary[1],binary[4])])
        return connections

    def _snapshot(self,stream,credentials,budget,deadline):
        _require(os.getpid()==self._own_pid and self._files()==self._custody
                 and kernel_peer(stream)==credentials and deadline>time.monotonic())
        peer,uid,gid=credentials;pids=(self._master_pid,peer,self._own_pid)
        _require(len(set(pids))==3)
        executor=_MetadataExecutor(budget,pids)
        def rows():
            result={}
            # Reuse the bounded retained-handle pair executor, never the base
            # transport's exceptional two-second cleanup wait in this daemon.
            for pair in ((pids[0],pids[1]),(pids[0],pids[2])):
                values=executor.pair(PS,tuple(('-p',str(pid),'-o',PS_FIELDS)for pid in pair),deadline)
                for pid,value in zip(pair,values):
                    parsed=NativeSmtpPeerInspector._rows(NativeSmtpPeerInspector._checked(value,budget,deadline),(pid,))[pid]
                    _require(pid not in result or result[pid]==parsed);result[pid]=parsed
            return result
        before=rows();master=before[self._master_pid];child=before[peer];own=before[self._own_pid]
        _require(master[1]==1 and master[3:5]==(0,0)and master[-1]=='dovecot'
                 and child[1]==self._master_pid and child[3:5]==(uid,gid)and child[-1]=='imap'
                 and own[3:5]==(0,0)and own[0]==own[2]
                 and (self._startup_master is None or master==self._startup_master)
                 and (self._startup_own is None or own==self._startup_own))
        programs=dict(self._custody);connections={}
        binaries={self._master_pid:MASTER,peer:IMAP,self._own_pid:self._helper}
        for pair in ((peer,self._own_pid),(self._master_pid,self._own_pid)):
            values=executor.pair(FSTAT,tuple(('-n','-p',str(pid))for pid in pair),deadline)
            for pid,value in zip(pair,values):
                parsed=self._descriptors(NativeSmtpPeerInspector._checked(value,budget,deadline),
                    pid,before[pid][-1],programs[str(binaries[pid])][0])
                _require(pid not in connections or connections[pid]==parsed);connections[pid]=parsed
        fd=stream.fileno();pair=connections[self._own_pid].get(fd)
        _require(pair is not None and pair[0]!=pair[1]
                 and sum(value==(pair[1],pair[0])for value in connections[peer].values())==1
                 and rows()==before and self._files()==self._custody
                 and kernel_peer(stream)==credentials and time.monotonic()<deadline)
        budget.remaining()
        return tuple((pid,before[pid])for pid in pids),pair

    def admit(self,stream,deadline):
        # Everything before reading the first frame: kernel peer, nonroot kernel
        # identity, live executable/parent/birth and reciprocal accepted fd.
        _require(type(deadline)in (int,float)and math.isfinite(deadline)
                 and 0<deadline-time.monotonic()<=.5)
        credentials=kernel_peer(stream)
        _require(0<credentials[1]<2**32-1 and 0<=credentials[2]<2**32-1)
        left=deadline-time.monotonic();_require(left>0)
        budget=OperationBudget(math.ceil(time.time()+left),maximum_seconds=left)
        budget.attach_owned_process_group()
        fd=stream.fileno();identity=NativeSmtpPeerInspector._identity(os.fstat(fd))
        rows,pcbs=self._snapshot(stream,credentials,budget,deadline)
        if self._startup_master is None:
            self._startup_master=dict(rows)[self._master_pid]
            self._startup_own=dict(rows)[self._own_pid]
        _require(stream.fileno()==fd and NativeSmtpPeerInspector._identity(os.fstat(fd))==identity)
        return _PeerBinding(self,stream,fd,identity,credentials,rows,pcbs,budget,deadline)

    def validate(self,binding,stream,pid,account,deadline,*,fresh=True):
        try:
            _require(type(binding)is _PeerBinding and binding.inspector is self
                     and binding.stream is stream and binding.deadline==deadline
                     and type(pid)is int and pid==binding.credentials[0]
                     and account in self._accounts
                     and stream.fileno()==binding.descriptor
                     and NativeSmtpPeerInspector._identity(os.fstat(stream.fileno()))==binding.descriptor_identity
                     and kernel_peer(stream)==binding.credentials and time.monotonic()<deadline
                     and type(fresh)is bool)
            if fresh:
                _require(self._snapshot(stream,binding.credentials,binding.budget,deadline)==(binding.rows,binding.pcbs))
            return True
        except Exception:return False

    @classmethod
    def native(cls,master_pid,accounts,budget=None):
        from account_mutation_supervisor import AUTHORITY
        _require(NATIVE_IMAP_PEER_QUALIFIED and os.geteuid()==0 and os.getegid()==0
                 and sys.platform.startswith('openbsd')and os.uname().sysname=='OpenBSD'
                 and os.uname().machine=='amd64'
                 and socket.gethostname()==AUTHORITY and os.getpid()==os.getpgrp()
                 and type(budget)is OperationBudget)
        value=cls(master_pid,accounts);value._anchor(budget);value._native=True
        return value

"""Managed fixed IMAP policy/publication daemon; native qualification closed."""
import json
import math
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

if __name__=='__main__':
    sys.path.insert(0,'/usr/local/libexec/osmap/account-runtime')

from account_epoch import EpochStore
from account_mutation_supervisor import _Bootstrap,ROOT,AUTHORITY,_directory,_private
from account_mutation_grant import _ConnectorGrant
from authoritative_password import Refused
from dovecot_auth_epoch import EpochPolicyFence
from dovecot_imap_peer import NativeImapPeerInspector,_MetadataExecutor
from dovecot_imap_publication import FixedPublicationEndpoint,FINAL_SOCKET
from operation_budget import OperationBudget

NATIVE_IMAP_SERVICE_QUALIFIED=False
PURPOSE='osmap-imap-publication'
POLICY_ADDRESS=('127.0.0.1',10058)
EPOCH_ROOT=Path('/var/db/osmap-account/epoch')
_FILES=('config.json','mutation.key','session-proof.key','imap-publication.json','imap-policy.key')


def _require(value):
    if not value:raise Refused('IMAP publication service unavailable')


def _identity(info):
    return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _reap_retained():
    """Quarantined ownership outlives admission, including graceful stop.

    The failed request already ended at its original deadline. No command,
    timeout, kill or numeric PID/group authority is renewed here. Keep this
    owning process/actual Popen handles alive until nonblocking kernel reap
    confirms disposition. An unconfirmed child cannot become a clean exit.
    """
    while _MetadataExecutor._retained:
        for child in tuple(_MetadataExecutor._retained):
            try:
                if type(child)is not subprocess.Popen or child.poll()is None:continue
                for pipe in (child.stdin,child.stdout,child.stderr):
                    if pipe is not None and not pipe.closed:pipe.close()
                _MetadataExecutor._retained[:]=[p for p in _MetadataExecutor._retained if p is not child]
            except Exception:
                # Retain this exact handle, including a failed pipe disposition.
                # No retry of the operation or stale PID signal follows.
                continue
        if _MetadataExecutor._retained:time.sleep(.05)


@dataclass(frozen=True,repr=False)
class _Startup:
    bootstrap: _Bootstrap
    key: bytes
    master_pid: int
    connector_gid: int
    custody: tuple

    @classmethod
    def _read(cls,root,owner,budget):
        # Existing private-directory/regular-file nonblocking readers. The two
        # new purpose files do not duplicate mutation keys or account scope.
        fd=None
        try:
            _require(type(budget)is OperationBudget);budget.remaining()
            fd=_directory(root,owner)
            directory=_identity(os.fstat(fd))[:5]
            before=tuple(_identity(os.stat(name,dir_fd=fd,follow_symlinks=False))for name in _FILES)
            bootstrap=_Bootstrap._read(root,owner)
            value=json.loads(_private(fd,'imap-publication.json',owner,16384),object_pairs_hook=EpochStore._unique)
            key=_private(fd,'imap-policy.key',owner,64)
            _require(type(value)is dict and set(value)=={'version','authority','purpose','master_pid','connector_gid'}
                     and type(value['version'])is int and value['version']==1
                     and value['authority']==AUTHORITY and value['purpose']==PURPOSE
                     and re.fullmatch(rb'[a-f0-9]{64}',key)
                     and key not in (bootstrap.mutation_key,bootstrap.session_key)
                     and 1<=len(bootstrap.accounts)<=64
                     and type(value['master_pid'])is int and 1<value['master_pid']<2**31
                     and type(value['connector_gid'])is int and 0<value['connector_gid']<2**32-1)
            after=tuple(_identity(os.stat(name,dir_fd=fd,follow_symlinks=False))for name in _FILES)
            _require(before==after and _identity(os.fstat(fd))[:5]==directory
                     and _identity(root.lstat())[:5]==directory)
            budget.remaining()
            return cls(bootstrap,key,value['master_pid'],value['connector_gid'],
                       (root,owner,directory,before))
        except Exception:raise Refused('IMAP publication startup unavailable')from None
        finally:
            if fd is not None:os.close(fd)

    def recheck(self,budget):
        _require(type(self)._read(self.custody[0],self.custody[1],budget)==self)


class _FinalGrant(_ConnectorGrant):
    # Reuse protected namespace ancestry, FD continuity, owner:group0710 and
    # inode-bound0660 publication/cleanup checks. No configured caller UID supplies
    # identity: the inherited unused connector_uid field is fixed to zero.
    def __post_init__(self):
        _require(self.path==Path(FINAL_SOCKET)and self.owner==0
                 and type(self.connector_uid)is int and self.connector_uid==0
                 and type(self.connector_gid)is int and 0<self.connector_gid<2**32-1)


class PublicationService:
    def __init__(self,startup,endpoint,grant):
        _require(type(startup)is _Startup and type(endpoint)is FixedPublicationEndpoint
                 and type(grant)is _FinalGrant and endpoint._fence._accounts==startup.bootstrap.accounts
                 and endpoint._api_key==startup.key
                 and type(endpoint._inspect_peer)is NativeImapPeerInspector
                 and endpoint._inspect_peer._accounts==startup.bootstrap.accounts
                 and endpoint._inspect_peer._master_pid==startup.master_pid
                 and grant.connector_gid==startup.connector_gid)
        self.startup=startup;self.endpoint=endpoint;self.grant=grant

    @classmethod
    def native(cls,budget):
        # Refusal BEFORE reading any configuration, creating sockets or files.
        import dovecot_imap_publication as publication
        _require(NATIVE_IMAP_SERVICE_QUALIFIED and publication.NATIVE_IMAP_PUBLICATION_QUALIFIED
                 and os.getuid()==os.geteuid()==0 and os.getegid()==0
                 and sys.platform.startswith('openbsd')and os.uname().release=='7.9'
                 and socket.gethostname()==AUTHORITY)
        startup=_Startup._read(ROOT,0,budget)
        inspector=NativeImapPeerInspector.native(startup.master_pid,startup.bootstrap.accounts,budget)
        store=EpochStore(EPOCH_ROOT,0)
        fence=EpochPolicyFence(store,startup.bootstrap.accounts)
        endpoint=FixedPublicationEndpoint(fence,startup.key,inspector)
        grant=_FinalGrant(Path(FINAL_SOCKET),0,0,startup.connector_gid)
        return cls(startup,endpoint,grant)

    def serve(self,stop,startup_budget):
        _require(type(stop)is threading.Event and type(startup_budget)is OperationBudget
                 and self.endpoint._inspect_peer._native)
        parent=self.grant.open_namespace();final=None;policy=None;inode=None
        try:
            startup_budget.remaining();self.startup.recheck(startup_budget)
            _require(not self.grant.path.exists()and not self.grant.path.is_symlink())
            final=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            final.bind(FINAL_SOCKET);info=self.grant.path.lstat();inode=(info.st_dev,info.st_ino)
            self.grant.publish(parent,inode);final.listen(4)
            # Fixed loopback HTTP purpose. No generic routes, TLS proxy, dynamic
            # ports or provider access; a preexisting owner/port fails startup.
            policy=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            policy.bind(POLICY_ADDRESS);policy.listen(4)
            _require(policy.getsockname()==POLICY_ADDRESS)
            self.grant.verify(parent,inode);startup_budget.remaining()
            with selectors.DefaultSelector()as selector:
                selector.register(final,selectors.EVENT_READ,'final')
                selector.register(policy,selectors.EVENT_READ,'policy')
                while not stop.is_set():
                    self.grant.verify(parent,inode)
                    _require(not _MetadataExecutor._retained and not _MetadataExecutor._quarantined)
                    for item,_ in selector.select(.1):
                        if stop.is_set():return
                        stream,_=item.fileobj.accept();end=time.monotonic()+.5
                        try:
                            # File/listener custody and all frame/metadata work
                            # are deducted from this accepted request's one cap.
                            budget=OperationBudget(math.ceil(time.time()+.5),maximum_seconds=.5)
                            budget.attach_owned_process_group()
                            self.startup.recheck(budget);self.grant.verify(parent,inode)
                            _require(item.data!='policy'or stream.getpeername()[0]=='127.0.0.1')
                            self.endpoint.connection(stream,item.data,original_deadline=end)
                        except Exception:stream.close()
                        _require(not _MetadataExecutor._retained and not _MetadataExecutor._quarantined)
        finally:
            if policy is not None:policy.close()
            if final is not None:final.close()
            try:
                if inode is not None:
                    self.grant.verify(parent,inode);self.grant.path.unlink()
            finally:os.close(parent)


def main():
    _require(len(sys.argv)==1 and os.getuid()==os.geteuid()==0
             and signal.getsignal(signal.SIGCHLD)==signal.SIG_DFL)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    if os.getpid()!=os.getpgrp():os.setsid()
    _require(os.getpid()==os.getpgrp()==os.getsid(0))
    budget=OperationBudget(int(time.time())+5,maximum_seconds=5)
    budget.attach_owned_process_group();stop=threading.Event();previous={}
    try:
        for sig in (signal.SIGTERM,signal.SIGINT):
            previous[sig]=signal.signal(sig,lambda *_:stop.set())
        service=PublicationService.native(budget)
        return service.serve(stop,budget)
    finally:
        stop.set()
        try:_reap_retained()
        finally:
            for sig,handler in previous.items():signal.signal(sig,handler)


if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit(1)from None

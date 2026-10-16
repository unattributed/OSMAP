"""Fixed private SMTP broker composition and bounded accepted-channel handler.

No native activation: the new purpose-private backend kernel binder is UNKNOWN
and all existing broker/routing/control gates remain closed. This source never
substitutes the ordinary Postfix auth socket or discovers authority from its
filesystem owner. A native front acceptor/complete ingress qualification remains
required. Only actual backend OK can publish under the shared epoch registry.
"""
import os
import base64
import re
from pathlib import Path
import socket
import select
import threading
import time
import stat
import sys
import signal
import resource

if __name__=='__main__':
    sys.path.insert(0,'/usr/local/libexec/osmap/account-runtime')

from account_epoch import EpochStore
from account_mutation_supervisor import _Bootstrap,AUTHORITY,_directory
from authoritative_password import Refused,Unconfirmed
from operation_budget import OperationBudget
import smtp_auth_control_service as control
import smtp_auth_lifecycle as lifecycle
from smtp_control_startup import ControlStartup
from smtp_native_peer import NativeSmtpOwnership
from smtp_topology import FixedSmtpRouting
import smtp_topology as routing_bootstrap
import mail_session_containment as containment

# NEW purpose contract, not an existing provision. Dovecot must bind this exact
# root-private directory/socket for the broker only; Postfix receives a separate
# broker front socket. Native admission requires actual same-endpoint kernel
# getpeereid proof before this source-owned constant can be completed.
BACKEND_SOCKET=Path('/var/dovecot/osmap-account-smtp/auth.sock')
BACKEND_BIND_PEER=None
EPOCH_ROOT=Path('/var/db/osmap-account/epoch')
# NEW purpose root, never the actual _postfix-owned private/ directory.
# Root provisions root:derived-postfix0710; chroot-relative client path is
# osmap-account-smtp/auth.sock. No existing path or chroot is inferred.
FRONT_SOCKET=Path('/var/spool/postfix/osmap-account-smtp/auth.sock')


def _require(value):
    if not value:raise Refused('SMTP broker unavailable')


class PrivateSmtpBackend:
    def __init__(self,path,owner,peer):
        _require(isinstance(path,Path)and path.name=='auth.sock'and type(owner)is int and owner>=0
                 and type(peer)is tuple and len(peer)==2
                 and all(type(v)is int and 0<=v<2**32-1 for v in peer))
        self.path=path;self.owner=owner;self.peer=peer
        fd=_directory(path.parent,owner)
        try:self._parent=self._directory_identity(os.fstat(fd))
        finally:os.close(fd)
        self._socket=self._current()

    @staticmethod
    def _identity(info):
        return info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink

    @staticmethod
    def _directory_identity(info):
        # A new protected child changes directory linkcount, not its custody.
        # Exact socket identity and its single-link guard remain independent.
        return info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode

    def _current(self):
        _require(self.path.resolve()==self.path)
        fd=_directory(self.path.parent,self.owner)
        try:_require(self._directory_identity(os.fstat(fd))==self._parent)
        finally:os.close(fd)
        info=self.path.lstat()
        _require(stat.S_ISSOCK(info.st_mode)and info.st_uid==self.owner and info.st_nlink==1
                 and stat.S_IMODE(info.st_mode)==0o600)
        return self._identity(info)

    def recheck(self,budget):
        _require(type(budget)is OperationBudget);budget.remaining()
        _require(self._current()==self._socket);budget.remaining()

    def connect(self,budget):
        self.recheck(budget);stream=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            stream.settimeout(budget.cap_seconds(1));stream.connect(str(self.path))
            _require(lifecycle._kernel_peer(stream)==self.peer)
            self.recheck(budget)
            return stream
        except BaseException:stream.close();raise

    @classmethod
    def native(cls,budget):
        # UNKNOWN refuses BEFORE any file/socket operation, even if another
        # qualification flag is accidentally set. No caller selects this peer.
        _require(BACKEND_BIND_PEER is not None and os.geteuid()==0
                 and sys.platform.startswith('openbsd')and socket.gethostname()==AUTHORITY)
        value=cls(BACKEND_SOCKET,0,BACKEND_BIND_PEER);value.recheck(budget);return value


class AuthBroker:
    FRAME_LIMIT=4096
    HANDSHAKE_LIMIT=16

    def __init__(self,startup,registry,ownership,backend,supervisor):
        _require(type(startup)is ControlStartup and type(registry)is lifecycle.SmtpAuthLifecycle
                 and type(ownership)is NativeSmtpOwnership and type(backend)is PrivateSmtpBackend
                 and type(supervisor)is control.GuardedControlSupervisor
                 and supervisor._registry is registry and supervisor._authority==startup.authority
                 and supervisor._routing is ownership._routing
                 and registry._accounts==startup.authority.accounts
                 and registry._authority._inspect is ownership
                 and registry._authority._postfix==ownership._startup_custody[1]
                 and registry._authority._backend==backend.peer
                 and registry._authority._port==ownership._startup_custody[4][-1])
        self.startup=startup;self.registry=registry;self.ownership=ownership
        self.backend=backend;self.supervisor=supervisor
        self.control_listener=None;self._serving=threading.Lock()

    @classmethod
    def _compose(cls,startup,store,journal,routing,ownership,backend,*,ok_profile=None):
        _require(type(startup)is ControlStartup and type(store)is EpochStore
                 and type(journal)is control.ControlGrantStore
                 and type(routing)is control.ControlTopologyAdmission
                 and type(ownership)is NativeSmtpOwnership and ownership._routing is routing
                 and type(backend)is PrivateSmtpBackend)
        authority=lifecycle.OwnedSmtpPeerAuthority(ownership._startup_custody[1],backend.peer,
            ownership._startup_custody[4][-1],ownership,ok_profile=ok_profile)
        registry=lifecycle.SmtpAuthLifecycle(store,startup.authority.accounts,authority)
        supervisor=control.GuardedControlSupervisor(startup.authority,registry,journal,routing)
        return cls(startup,registry,ownership,backend,supervisor)

    @staticmethod
    def _line(stream,budget):
        result=bytearray()
        while not result.endswith(b'\n'):
            stream.settimeout(budget.cap_seconds(1));raw=stream.recv(1)
            _require(raw and len(result)<AuthBroker.FRAME_LIMIT);result.extend(raw)
        value=bytes(result)
        _require(b'\0'not in value and b'\r'not in value)
        return value

    @staticmethod
    def _send(stream,line,budget):
        stream.settimeout(budget.cap_seconds(1));stream.sendall(line);budget.remaining()

    @staticmethod
    def _server_version(fields):
        # Dovecot2.3.21.1 auth-client-interface.h declares1.2 and explicitly
        # allows ignoring minor versions. Keep the client1.0 wire unchanged;
        # a compatible server minor does not grant any new protocol feature.
        _require(type(fields)is list and len(fields)==3 and all(type(v)is bytes for v in fields)
                 and fields[:2]==[b'VERSION',b'1']
                 and re.fullmatch(rb'0|[1-9][0-9]{0,9}',fields[2])is not None
                 and int(fields[2])<2**32)

    def connection(self,client,budget):
        """One accepted descriptor, one AUTH; no credentials are retained.

        A published channel remains in the SAME registry for later control
        cancellation. Returning it does not close SASL ends or erase the epoch
        capture. The native acceptor must own EOF/stop cleanup through close().
        """
        _require(type(budget)is OperationBudget and type(client)is socket.socket)
        upstream=None;channel=None;published=False
        try:
            budget.remaining()
            _require(not getattr(self.registry,'_control_uncertain',False)
                     and lifecycle._kernel_peer(client)==self.registry._authority._postfix)
            self.startup.recheck(budget)
            self.ownership.prepare(budget)  # Exactly once before credential dispatch.
            upstream=self.backend.connect(budget)
            _require(self._line(client,budget)==b'VERSION\t1\t0\n')
            self._send(upstream,b'VERSION\t1\t0\n',budget)
            cpid=self._line(client,budget)
            fields=lifecycle.SmtpAuthLifecycle._fields(cpid)
            _require(len(fields)==2 and fields[0]==b'CPID')
            self._send(upstream,cpid,budget)
            seen=set()
            for _ in range(self.HANDSHAKE_LIMIT):
                line=self._line(upstream,budget);fields=lifecycle.SmtpAuthLifecycle._fields(line)
                _require(fields[0]in (b'VERSION',b'MECH',b'SPID',b'CUID',b'COOKIE',b'DONE'))
                if fields[0]in (b'VERSION',b'SPID',b'CUID',b'COOKIE',b'DONE'):
                    _require(fields[0]not in seen);seen.add(fields[0])
                if fields[0]==b'VERSION':self._server_version(fields)
                if fields[0]==b'DONE':_require(fields==[b'DONE']and b'VERSION'in seen)
                self._send(client,line,budget)
                if fields[0]==b'DONE':break
            else:raise Refused('SMTP broker handshake unavailable')
            auth=self._line(client,budget)
            fields=lifecycle.SmtpAuthLifecycle._fields(auth)
            _require(len(fields)>=3)
            if fields[2]==b'LOGIN':
                channel,line=self._login(client,upstream,cpid,auth,budget)
                del auth
            else:
                # Preserve the existing one-frame PLAIN capture/dispatch path.
                channel=self.registry.begin(client,upstream,cpid,auth,budget)
                self.backend.recheck(budget)
                self._send(upstream,auth,budget);del auth
                line=self._line(upstream,budget)
            fields=lifecycle.SmtpAuthLifecycle._fields(line)
            if fields[:2]==[b'FAIL',channel.request]:
                self._send(client,line,budget);raise Refused('SMTP backend authentication refused')
            receipt=self.registry.verified(channel,line)
            self.startup.recheck(budget);self.backend.recheck(budget)
            self.registry.publish(channel,receipt);published=True
            return channel
        finally:
            if not published and channel is not None:self.registry.close(channel)
            # Lifecycle.begin owns duplicated descriptors. Close the handler
            # originals on EVERY exit without shutting down a published channel.
            client.close()
            if upstream is not None:upstream.close()

    def _login(self,client,upstream,cpid,auth,budget):
        channel=None;returned=False
        def challenge(prompt,request):
            line=self._line(upstream,budget)
            fields=lifecycle.SmtpAuthLifecycle._fields(line)
            if fields[:2]==[b'FAIL',request]:
                self._send(client,line,budget)
                raise Refused('SMTP LOGIN backend authentication refused')
            _require(fields==[b'CONT',request,base64.b64encode(prompt)])
            self._send(client,line,budget)
        try:
            _pid,request,initial=self.registry.login_initial(cpid,auth)
            if initial:
                channel=self.registry.begin_login(client,upstream,cpid,auth,None,budget)
            self.backend.recheck(budget)
            self._send(upstream,auth,budget)
            if not initial:
                challenge(b'Username:',request)
                username=self._line(client,budget)
                # Register before forwarding username or receiving password.
                channel=self.registry.begin_login(client,upstream,cpid,auth,username,budget)
                self.backend.recheck(budget)
                self._send(upstream,username,budget);del username
            challenge(b'Password:',request)
            password=self._line(client,budget)
            self.backend.recheck(budget)
            self.registry.forward_login_password(channel,password);del password
            line=self._line(upstream,budget)
            returned=True
            return channel,line
        finally:
            if not returned and channel is not None:self.registry.close(channel)

    @staticmethod
    def _front_parent(path,owner):
        _require(isinstance(path,Path)and path.is_absolute()and path.parent.resolve(strict=True)==path.parent)
        captured=[]
        for parent in (path.parent,*path.parent.parents):
            info=parent.lstat()
            _require(stat.S_ISDIR(info.st_mode)and info.st_uid in (0,owner)and not info.st_mode&0o022
                     and (parent!=path.parent or info.st_uid==owner))
            captured.append((str(parent),PrivateSmtpBackend._directory_identity(info)))
        return tuple(captured)

    @staticmethod
    def _authentication_budget():
        # Trusted accepted-descriptor entry captures ONE original local AUTH
        # receipt. Neither protocol fields nor retries can choose/reset it.
        value=OperationBudget(int(time.time())+3,maximum_seconds=3)
        value.attach_owned_process_group();return value

    def _sweep(self):
        with self.registry._mutex:channels=tuple(self.registry._channels)
        for channel in channels:
            if channel.closed:continue
            try:
                ready,_,_=select.select((channel.client,channel.upstream),(),(),0)
                if ready:
                    # EOF or any unexpected post-publication byte closes the
                    # exact owned duplicates. Never parse/forward another AUTH.
                    for stream in ready:stream.recv(1,socket.MSG_PEEK)
                    self.registry.close(channel)
            except (OSError,ValueError):self.registry.close(channel)

    def serve(self,stop):
        _require(hasattr(self,'_startup_budget')and self.control_listener is not None)
        # Actual standard private/ is _postfix-owned and is not root custody.
        # This separate NEW purpose parent must be explicitly provisioned.
        parent=FRONT_SOCKET.parent.lstat()
        _require(parent.st_uid==0 and parent.st_gid==self.registry._authority._postfix[1]
                 and stat.S_IMODE(parent.st_mode)==0o710)
        return self._serve(FRONT_SOCKET,0,stop,self._startup_budget)

    def _serve(self,path,owner,stop,startup_budget):
        _require(type(stop)is threading.Event and type(startup_budget)is OperationBudget
                 and startup_budget.inherited_group()
                 and type(self.control_listener)is control.PrivateControlListener
                 and self.control_listener._supervisor is self.supervisor)
        if stop.is_set():return 0
        captured=self._front_parent(path,owner)
        _require(self._serving.acquire(blocking=False))
        server=None;inode=None;thread=None;errors=[];ready=threading.Event();completed=0
        def control_run():
            try:self.control_listener.serve(stop,_ready=ready)
            except BaseException:errors.append(True)
        def current():
            _require(self._front_parent(path,owner)==captured)
            info=path.lstat()
            _require(stat.S_ISSOCK(info.st_mode)and info.st_uid==self.registry._authority._postfix[0]
                     and info.st_gid==self.registry._authority._postfix[1]
                     and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1
                     and (info.st_dev,info.st_ino)==inode)
        try:
            startup_budget.remaining();_require(not path.exists()and not path.is_symlink())
            thread=threading.Thread(target=control_run);thread.start()
            while not ready.wait(min(.05,startup_budget.remaining())):
                _require(thread.is_alive()and not errors and not stop.is_set())
            self.control_listener.recheck()
            _require(thread.is_alive()and not errors and self.control_listener._supervisor._registry is self.registry)
            startup_budget.remaining();server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            server.bind(str(path));info=path.lstat();inode=(info.st_dev,info.st_ino)
            os.chmod(path,0o600);os.chown(path,*self.registry._authority._postfix)
            current();server.listen(4);server.settimeout(.1);startup_budget.remaining()
            while not stop.is_set():
                current();self.control_listener.recheck()
                _require(thread.is_alive()and not errors and not getattr(self.registry,'_control_uncertain',False))
                self._sweep()
                try:client,_=server.accept()
                except socket.timeout:continue
                try:
                    current();self.control_listener.recheck()
                    _require(not stop.is_set()and thread.is_alive()and not errors
                             and not getattr(self.registry,'_control_uncertain',False)
                             and len(self.registry._channels)<min(128,self.registry.MAX_CHANNELS))
                    self.connection(client,self._authentication_budget());completed+=1
                except (Refused,OSError):client.close()  # This descriptor is never retried.
            return completed
        finally:
            stop.set()
            if server is not None:server.close()
            with self.registry._mutex:channels=tuple(self.registry._channels)
            for channel in channels:self.registry.close(channel)
            cleanup_ok=not errors
            try:
                if inode is not None:current();path.unlink()
            except Exception:cleanup_ok=False  # Retain a replaced/unconfirmed path.
            if thread is not None:
                # Active control keeps its original budget; this finite grace
                # does not renew it or force a receipt/reset. A live thread is
                # retained and explicitly unconfirmed for outer supervision.
                thread.join(.5)
                if thread.is_alive():cleanup_ok=False;self.registry._control_uncertain=True
            self._serving.release()
            if not cleanup_ok:raise Unconfirmed('SMTP broker cleanup unconfirmed')

    @classmethod
    def native(cls,budget):
        # No Boolean/config/browser opt-in. These existing qualification gates
        # and the UNKNOWN dedicated backend admission remain independently shut.
        _require(lifecycle.NATIVE_AUTH_BROKER_QUALIFIED and control.NATIVE_CONTROL_SERVICE_QUALIFIED
                 and routing_bootstrap.NATIVE_ROUTING_BOOTSTRAP_QUALIFIED
                 and containment.NATIVE_SMTP_TOPOLOGY_QUALIFIED
                 and BACKEND_BIND_PEER is not None and type(budget)is OperationBudget)
        budget.remaining()
        backend=PrivateSmtpBackend.native(budget)
        bootstrap=_Bootstrap.native();startup=ControlStartup.native(bootstrap,budget)
        store=EpochStore(EPOCH_ROOT,0);journal=control.ControlGrantStore(control.REPLAY_ROOT,0)
        for account in startup.authority.accounts:
            store._read(store._paths(account)[1]);journal._record(journal._paths(account)[1])
        # Publish/verify the existing fixed routing certificate before its
        # consumer, spending this same original startup budget throughout.
        FixedSmtpRouting.native(budget)
        routing=control.ControlTopologyAdmission(FixedSmtpRouting.ROOT,0)
        namespace,topology=routing.admit(budget)
        # The producer is imported locally to avoid circular startup imports.
        from smtp_native_peer import NativeSmtpPeerInspector
        inspector=NativeSmtpPeerInspector.native(namespace,topology,budget)
        ownership=NativeSmtpOwnership._read(inspector,routing)
        value=cls._compose(startup,store,journal,routing,ownership,backend,
            ok_profile=lifecycle.DovecotProxyOkProfile(namespace._backend_port))
        value.control_listener=control.PrivateControlListener.native(value.supervisor)
        value._startup_budget=budget
        return value


# Fixed pre-listen startup cap, matching the existing guarded binding startup.
# It never becomes an AUTH budget; each accepted channel retains its original3s.
SERVICE_STARTUP_SECONDS=5


def main():
    """Managed fixed-purpose entry; closed native factory remains authoritative."""
    _require(len(sys.argv)==1 and os.getuid()==os.geteuid()==0
             and sys.platform.startswith('openbsd')and socket.gethostname()==AUTHORITY)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    # rc backgrounds a child that may inherit its caller's group. Establish our
    # own session before any listener/credential input; never signal that caller.
    if os.getpid()!=os.getpgrp():os.setsid()
    _require(os.getpid()==os.getpgrp()==os.getsid(0))
    budget=OperationBudget(int(time.time())+SERVICE_STARTUP_SECONDS,
                           maximum_seconds=SERVICE_STARTUP_SECONDS)
    budget.attach_owned_process_group();budget.remaining()
    stop=threading.Event();previous={}
    try:
        for sig in (signal.SIGTERM,signal.SIGINT):
            previous[sig]=signal.signal(sig,lambda *_args:stop.set())
        service=AuthBroker.native(budget)
        budget.remaining()
        return service.serve(stop)
    finally:
        for sig,handler in previous.items():signal.signal(sig,handler)


if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit(1)from None

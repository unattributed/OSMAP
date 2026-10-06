"""Disabled guarded original-budget admission and private control listener.

Only fixed startup dependencies choose keys, accounts, replay store, routing
plan and accepted descriptor. No native entry constructs them yet. A source
fixture cannot qualify unique worker/flock ownership, ingress or TCP absence.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import socket
import stat
import threading
import time

from account_epoch import EpochStore
from smtp_control_authorization import (LIMIT, ControlAuthority, VerifiedControlAuthorization, verify_authorization)
from account_mutation_budget import wall_millis
from account_mutation_codec import uint
from account_mutation_supervisor import _directory
from account_mutation_worker import IntentStore
from authoritative_password import Refused, Unconfirmed
from mail_session_containment import (OperatorOwnedProxyNamespace, OperatorOwnedSmtpTopology,
                                     RoutingMetadataExecutor)
from operation_budget import OperationBudget
from smtp_auth_control import LifecycleControlOperation, _send
from smtp_auth_lifecycle import SmtpAuthLifecycle, _kernel_peer, _socket_identity
from smtp_topology import FixedSmtpRouting, PrivateRoutingPlan

NATIVE_CONTROL_SERVICE_QUALIFIED = False
SOCKET = Path('/var/run/osmap-account-smtp-control/control.sock')
REPLAY_ROOT = Path('/var/db/osmap-account/smtp-control-intents')
ROUTING_ROOT = Path('/etc/osmap/account-runtime')


class ControlGrantStore(IntentStore):
    """Separately provisioned durable control purpose; no credential/outcome data.

    Claimed grants never expire into reusable authority. A pending/uncertain
    entry requires reconciliation. Completed grants retire only after their
    signed original deadlines under a durable time high-water mark. Closed
    journal version2 refuses old/malformed records rather than recreating them.
    Lock order is mutation account -> this
    purpose journal -> registry; this server never acquires the account flock.
    """
    RECORD_LIMIT = 8192
    MAX_ENTRIES = 32

    def _paths(self, account):
        from authoritative_password import AuthoritativePasswordAdapter
        AuthoritativePasswordAdapter._account(account)
        name=hashlib.sha256(b'osmap-smtp-control-grants-v1\0'+account.encode('ascii')).hexdigest()
        return self.root/(name+'.lock'),self.root/(name+'.json')

    def provision(self, account):
        # Explicit source/operator preparation only, never a runtime fallback.
        with EpochStore.locked(self,account)as path:
            if path.exists()or path.is_symlink():raise Refused('SMTP control grant already exists')
            self._publish(path,{'version':2,'high_water_millis':0,'entries':[]})

    def _record(self,path):
        import json
        try:
            fd=self._private(path,os.O_RDONLY)
            with os.fdopen(fd,'rb')as handle:raw=handle.read(self.RECORD_LIMIT+1)
            if len(raw)>self.RECORD_LIMIT:raise ValueError
            value=json.loads(raw,object_pairs_hook=EpochStore._unique)
            if (type(value)is not dict or set(value)!={'version','high_water_millis','entries'}
                    or type(value['version'])is not int or value['version']!=2 or not uint(value['high_water_millis'])
                    or type(value['entries'])is not list or len(value['entries'])>self.MAX_ENTRIES):raise ValueError
            seen=set()
            for row in value['entries']:
                if (type(row)is not dict or set(row)!={'intent','authorization_sha256','state','deadline_millis'}
                        or not self._reference(row['intent'])or not self._reference(row['authorization_sha256'])
                        or row['intent']in seen or row['state']not in ('claimed','complete','uncertain')
                        or not uint(row['deadline_millis'])or row['deadline_millis']<=0):raise ValueError
                seen.add(row['intent'])
            return value
        except Exception:raise Refused('SMTP control grant unavailable')from None

    @staticmethod
    def _now(budget):
        budget.remaining()
        # Use the exact existing budget wall sample; no fresh clock/deadline.
        millis=int(budget._last_wall*1000)
        if not uint(millis):raise Refused('SMTP control grant time unavailable')
        return millis

    @contextmanager
    def claim(self,action,authorization_digest,budget):
        if (type(action)is not VerifiedControlAuthorization or type(budget)is not OperationBudget
                or not self._reference(authorization_digest)):raise Refused('SMTP control grant authority unavailable')
        budget.require_original(sent_millis=action.sent_millis,
            deadline_millis=action.deadline_millis,expires_at=action.expires)
        lock,path=self._paths(action.account);fd=self._private(lock,os.O_RDWR|os.O_CREAT)
        try:
            end=time.monotonic()+budget.cap_seconds(2)
            while True:
                budget.remaining()
                try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                except BlockingIOError:
                    remaining=min(end-time.monotonic(),budget.remaining())
                    if remaining<=0:raise Refused('SMTP control grant lock unavailable')
                    time.sleep(min(.01,remaining))
            value=self._record(path)
            now=self._now(budget)
            if now<value['high_water_millis']or any(e['state']!='complete'for e in value['entries']):
                raise Refused('SMTP control grant spent or uncertain')
            # Only completed grants past their independently signed original
            # deadline can retire. Unresolved state never expires or resets.
            entries=[e for e in value['entries']if e['deadline_millis']>now]
            if (any(e['intent']==action.intent_reference for e in entries)
                    or len(entries)>=self.MAX_ENTRIES):raise Refused('SMTP control grant spent or uncertain')
            row={'intent':action.intent_reference,'authorization_sha256':authorization_digest,
                 'deadline_millis':action.deadline_millis,'state':'claimed'}
            value.update(high_water_millis=now,entries=entries+[row]);self._publish(path,value);budget.remaining()
            try:
                yield row
                now=self._now(budget)
                if now<value['high_water_millis']:raise Refused('SMTP control grant time changed')
                value['high_water_millis']=now;row['state']='complete';self._publish(path,value);budget.remaining()
            except BaseException:
                row['state']='uncertain'
                try:self._publish(path,value)
                except Exception:pass  # Claimed durable state still refuses admission.
                raise
        finally:
            fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)


class ControlTopologyAdmission:
    """Consumes an existing v2 certificate; no request provisioning/producer."""
    def __init__(self,root,owner,executor=None):
        self.root=Path(root);self.owner=owner;self._executor=executor
        fd=_directory(self.root,owner)
        try:self._root_identity=self._identity(os.fstat(fd))
        finally:os.close(fd)

    @staticmethod
    def _identity(info):return info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode

    def recheck(self):
        fd=_directory(self.root,self.owner)
        try:
            if self._identity(os.fstat(fd))!=self._root_identity:raise Refused('SMTP control routing root changed')
        finally:os.close(fd)

    def admit(self,budget):
        self.recheck()
        captured,plan=FixedSmtpRouting._private_read(self.root,self.owner,budget)
        root=FixedSmtpRouting._plan(plan)
        namespace=OperatorOwnedProxyNamespace(root,self.owner,plan['backend_address'],plan['backend_port'])
        routing=PrivateRoutingPlan(self.root,self.owner,budget,namespace,captured)
        execute=self._executor or RoutingMetadataExecutor(namespace,budget)
        topology=OperatorOwnedSmtpTopology(namespace,execute,budget,routing_plan=routing)
        self.recheck();budget.remaining()
        return namespace,topology


class GuardedControlSupervisor:
    """Authenticates password-free original-budget delegation before source cutoff."""
    def __init__(self,authority,registry,journal,routing,*,monotonic=time.monotonic,clock_millis=wall_millis):
        if (type(authority)is not ControlAuthority or type(registry)is not SmtpAuthLifecycle
                or type(journal)is not ControlGrantStore or type(routing)is not ControlTopologyAdmission
                or registry._accounts!=authority.accounts or registry._store.uid!=journal.uid
                or routing.owner!=journal.uid or journal.root==registry._store.root
                or journal.root==routing.root or registry._store.root==routing.root
                or not callable(monotonic)or not callable(clock_millis)):
            raise Refused('SMTP control supervisor startup unavailable')
        self._authority=authority;self._registry=registry;self._journal=journal;self._routing=routing
        self._monotonic=monotonic;self._clock_millis=clock_millis;self._busy=threading.Lock()

    @classmethod
    def native(cls,*_args):
        raise Refused('native SMTP control service composition unavailable')

    def _frame(self,stream,end):
        def exact(size):
            value=bytearray()
            while len(value)<size:
                remaining=end-self._monotonic()
                if remaining<=0:raise Refused('SMTP control initial frame deadline')
                stream.settimeout(remaining);part=stream.recv(size-len(value))
                if not part:raise Refused('SMTP control initial frame unavailable')
                value.extend(part)
            return bytes(value)
        size=int.from_bytes(exact(4),'big')
        if not 0<size<=LIMIT:raise Refused('SMTP control initial frame cap')
        return exact(size)

    def connection(self,stream,*,_listener=None):
        if not self._busy.acquire(blocking=False):
            stream.close();raise Refused('SMTP control supervisor busy')
        operation=None
        try:
            if _listener is not None and type(_listener)is not PrivateControlListener:
                raise Refused('SMTP control source listener unavailable')
            if _listener is not None:_listener.recheck()
            identity=_socket_identity(stream)
            if _kernel_peer(stream)[0]!=self._journal.uid:raise Refused('SMTP control supervisor peer refused')
            received_mono=self._monotonic();received_millis=self._clock_millis()
            raw=self._frame(stream,received_mono+1)
            action=verify_authorization(raw,self._authority,self._clock_millis())
            budget=action.budget(received_mono=received_mono,received_millis=received_millis,
                                    monotonic=self._monotonic,clock_millis=self._clock_millis)
            if _socket_identity(stream)!=identity or _kernel_peer(stream)[0]!=self._journal.uid:
                raise Refused('SMTP control supervisor peer changed')
            # Original signed action binds account/epoch/intent independently of
            # the later capture frame. The mutation owner already holds flock;
            # kernel UID is not interpreted as proof of worker PID/flock.
            pending=self._registry._record(action.account)
            if (pending['state']not in ('pending','contained')or pending['epoch']!=action.epoch
                    or pending['intent']!=action.intent_reference):raise Refused('SMTP control guarded pending mismatch')
            namespace,topology=self._routing.admit(budget)
            operation=LifecycleControlOperation(self._registry,namespace,topology,budget,
                                                admitted_account=action.account,admitted_authorization=action,
                                                listener_recheck=None if _listener is None else _listener.recheck)
            with self._journal.claim(action,hashlib.sha256(raw).hexdigest(),budget):
                # This disabled source composition supplies independently authenticated
                # original budget and admitted account; no caller budget selector.
                terminal=[]
                result=operation._serve(stream,lambda value,_budget: terminal.append(value))
            # Only durable grant completion permits terminal publication. A
            # consumed cutoff need not remain live after a late send failure.
            try:
                self._routing.recheck();operation._authority(stream,identity)
                if len(terminal)!=1:raise Unconfirmed('SMTP control terminal unavailable')
                _send(stream,terminal[0],budget)
            except Exception:
                self._registry._control_uncertain=True
                raise
            return result
        except Exception:
            if operation is not None and operation._state in ('complete','unconfirmed'):
                self._registry._control_uncertain=True
            raise Unconfirmed('SMTP guarded control unavailable')from None
        finally:
            stream.close();self._busy.release()


class PrivateControlListener:
    """Source-owned private namespace and serial accepted control descriptor."""
    def __init__(self,path,owner,supervisor):
        if (type(supervisor)is not GuardedControlSupervisor or not isinstance(path,Path)
                or path.name!='control.sock'or owner!=supervisor._journal.uid or owner!=os.geteuid()):
            raise Refused('SMTP control listener startup unavailable')
        self.path=path;self.owner=owner;self._supervisor=supervisor

    @classmethod
    def native(cls,*_args):raise Refused('native SMTP control listener unavailable')

    def recheck(self):
        if not callable(getattr(self,'_current_recheck',None)):
            raise Refused('SMTP control listener current custody unavailable')
        self._current_recheck()

    def one(self):
        parent=_directory(self.path.parent,self.owner);server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        inode=None
        def directory_identity(info):return info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode
        original=directory_identity(os.fstat(parent))
        def recheck():
            if directory_identity(self.path.parent.lstat())!=original or directory_identity(os.fstat(parent))!=original:
                raise Refused('SMTP control listener namespace changed')
            info=self.path.lstat()
            if (not stat.S_ISSOCK(info.st_mode)or info.st_uid!=self.owner or stat.S_IMODE(info.st_mode)!=0o600
                    or (info.st_dev,info.st_ino)!=inode):raise Refused('SMTP control listener inode changed')
        self._current_recheck=recheck
        try:
            if self.path.exists()or self.path.is_symlink()or len(os.fsencode(self.path))>=100:
                raise Refused('SMTP control listener preexisting path')
            server.bind(str(self.path));info=self.path.lstat();inode=(info.st_dev,info.st_ino)
            os.chmod(self.path,0o600);recheck();server.listen(1);server.settimeout(1)
            stream,_=server.accept()
            with stream:recheck();return self._supervisor.connection(stream,_listener=self)
        finally:
            server.close()
            try:
                if inode is not None:
                    recheck();self.path.unlink()
            finally:
                self._current_recheck=None
                os.close(parent)

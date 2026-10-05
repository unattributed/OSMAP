"""Durable own-account password admission and interruption containment.

Operator provisioning is explicit. Runtime never recreates a missing account
record, silently clears pending/contained state, or retries a password write.
The web integration must bind issued sessions to the returned epoch and recheck
on validation; this store does not claim that integration is installed.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import pathlib
import stat
import tempfile
import time
from authoritative_password import AuthoritativePasswordAdapter, Refused, Unconfirmed


# u64::MAX is reserved/refused by the durable store and Rust session protocol.
# The final readable epoch remains valid for authentication, but cannot advance.
MAX_EPOCH = 2**64 - 2


def valid_epoch(value):
    return type(value) is int and 0 <= value <= MAX_EPOCH


class EpochStore:
    LOCK_WAIT_SECONDS=2.0
    def __init__(self,root,expected_uid=0):
        self.root=pathlib.Path(root); self.uid=expected_uid
        info=self.root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=self.uid or
                info.st_mode&0o077 or self.root.resolve()!=self.root):
            raise Refused('account admission store unavailable')
    def _paths(self,account):
        AuthoritativePasswordAdapter._account(account)
        name=hashlib.sha256(b'osmap-account-epoch-v1\0'+account.encode()).hexdigest()
        return self.root/(name+'.lock'),self.root/(name+'.json')
    def _private(self,path,flags):
        descriptor=os.open(path,flags|os.O_NOFOLLOW,0o600)
        info=os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=self.uid or
                info.st_mode&0o077 or info.st_nlink!=1):
            os.close(descriptor);raise Refused('account admission store unavailable')
        return descriptor
    @contextmanager
    def locked(self,account):
        lock,path=self._paths(account)
        descriptor=self._private(lock,os.O_RDWR|os.O_CREAT)
        try:
            deadline=time.monotonic()+self.LOCK_WAIT_SECONDS
            while True:
                try:fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                except BlockingIOError:
                    remaining=deadline-time.monotonic()
                    if remaining<=0:raise Refused('account admission lock busy')
                    time.sleep(min(remaining,0.01))
            yield path
        finally:
            fcntl.flock(descriptor,fcntl.LOCK_UN);os.close(descriptor)
    def _read(self,path):
        try:
            descriptor=self._private(path,os.O_RDONLY)
            with os.fdopen(descriptor,'rb') as handle:data=handle.read(4097)
            if len(data)>4096:raise ValueError
            value=json.loads(data,object_pairs_hook=self._unique)
            if set(value)!=set(('epoch','state','changed_at','intent','used_intents')):raise ValueError
            if not valid_epoch(value['epoch']):raise ValueError
            if value['state'] not in ('active','pending','contained'):raise ValueError
            if value['changed_at'] is not None:AuthoritativePasswordAdapter._stamp(value['changed_at'])
            if value['intent'] is not None and not self._reference(value['intent']):raise ValueError
            if not isinstance(value['used_intents'],list) or len(value['used_intents'])>32:raise ValueError
            for item in value['used_intents']:
                if (not isinstance(item,list) or len(item)!=2 or not self._reference(item[0]) or
                        type(item[1]) is not int or item[1]<=0):raise ValueError
            if (value['state']!='active' and value['intent'] is None) or (value['state']=='active' and value['intent'] is not None):raise ValueError
            return value
        except (OSError,ValueError,TypeError,Refused):
            raise Refused('account admission record unavailable') from None
    @staticmethod
    def _unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError
            result[key]=value
        return result
    @staticmethod
    def _reference(value):
        return isinstance(value,str) and len(value)==64 and all(c in '0123456789abcdef' for c in value)
    def _write(self,path,value):
        if not isinstance(value,dict) or not valid_epoch(value.get('epoch')):
            raise Refused('account epoch unavailable')
        descriptor,name=tempfile.mkstemp(prefix='.epoch-',dir=self.root)
        try:
            os.fchmod(descriptor,0o600)
            with os.fdopen(descriptor,'wb') as handle:
                handle.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
                handle.flush();os.fsync(handle.fileno())
            os.replace(name,path)
            directory=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(directory)
            finally:os.close(directory)
        finally:
            try:os.unlink(name)
            except FileNotFoundError:pass
    def provision(self,account):
        """Explicit operator-only preparation; never called by a browser RPC."""
        with self.locked(account) as path:
            if path.exists() or path.is_symlink():raise Refused('account record already exists')
            self._write(path,{'epoch':0,'state':'active','changed_at':None,'intent':None,'used_intents':[]})
    def admission(self,account,expected_epoch=None):
        if expected_epoch is not None and not valid_epoch(expected_epoch):
            raise Refused('account epoch unavailable')
        with self.locked(account) as path:
            value=self._read(path)
            if value['state']!='active' or (expected_epoch is not None and value['epoch']!=expected_epoch):
                raise Refused('account authentication admission refused')
            return value['epoch'],value['changed_at']


class PasswordCoordinator:
    """Serializes qualified step-up, conditional write and containment.

    Callbacks are independently qualified helper dependencies, never request
    fields: fresh verifier binds account/current/TOTP; containment preflight
    checks actual native session scope; finish returns true only after actual
    configured Dovecot cache/connection containment. A database receipt alone
    cannot produce a successful return. Real browser session epoch validation is
    an additional required runtime integration, not supplied by these callbacks.
    """
    def __init__(self,store,adapter,verify_fresh,verify_changed,containment_ready,finish_containment,
                 invalidate_changed_auth=None):
        self.store=store;self.adapter=adapter;self.verify_fresh=verify_fresh
        self.verify_changed=verify_changed;self.containment_ready=containment_ready
        self.finish_containment=finish_containment
        self.invalidate_changed_auth=invalidate_changed_auth
    def change(self,account,expected_epoch,intent_reference,current,new,confirmation,totp,now):
        return self._change(account,expected_epoch,intent_reference,current,new,
                            confirmation,now,
                            lambda:self.verify_fresh(account,current,totp))

    def _change(self,account,expected_epoch,intent_reference,current,new,confirmation,
                now,verify_action,fresh_before_write=None,pending_confirmation=None):
        """Private shared transaction; verifiers are helper dependencies, not fields."""
        self.adapter._account(account);self.adapter.validate_new(current,new,confirmation)
        if (not self.store._reference(intent_reference) or not valid_epoch(expected_epoch) or type(now) is not int or now<=0):raise Refused('change admission refused')
        with self.store.locked(account) as path:
            value=self.store._read(path)
            if value['state']!='active' or value['epoch']!=expected_epoch:raise Refused('account admission refused')
            # Refuse exhaustion before callbacks, credential dispatch or pending writes.
            if value['epoch']>=MAX_EPOCH:raise Refused('account credential epoch exhausted')
            used=[item for item in value['used_intents'] if item[1]>now]
            if any(item[0]==intent_reference for item in used) or len(used)>=32:raise Refused('change replay refused')
            # Current primary credential and fresh replay-protected factor are
            # verified while holding the same durable account mutation lock.
            try:
                if (not callable(self.invalidate_changed_auth) or
                        self.containment_ready(account) is not True or verify_action() is not True):
                    raise Refused('fresh verification or containment unavailable')
                snapshot=self.adapter.read(account)
                if fresh_before_write is not None and fresh_before_write() is not True:
                    raise Refused('prepared action expired before credential write')
            except Exception:
                raise Refused('fresh verification or authoritative backend unavailable') from None
            pending=dict(value,state='pending',intent=intent_reference,
                         used_intents=used+[[intent_reference,now+300]])
            self.store._write(path,pending)
            # Only a fixed authenticated helper dependency supplies this
            # guarded-flow hook. Durable account pending precedes issuer ACK;
            # disappearance/uncertainty before SQL cannot reopen old authority.
            if pending_confirmation is not None:
                try:
                    if not callable(pending_confirmation) or pending_confirmation() is not True:
                        raise ValueError
                except BaseException:
                    self.store._write(path,dict(pending,state='contained'))
                    raise Unconfirmed('pending authority requires reconciliation') from None
            try:
                receipt=self.adapter.replace(snapshot,account,current,new,confirmation)
            except Refused:
                # Verified pre-write/hash refusal or exact zero-row CAS preserves
                # the credential epoch. The fresh intent is still consumed once.
                self.store._write(path,dict(pending,state='active',intent=None))
                raise
            except BaseException:
                self.store._write(path,dict(pending,state='contained'))
                raise Unconfirmed('account contained; inspect before retrying') from None
            try:
                # Invalidate only this account's old authentication cache BEFORE
                # testing the changed credential. Invalidation is not termination;
                # the independent finish dependency must kick and reconcile.
                if (self.invalidate_changed_auth(account) is not True or
                        self.verify_changed(account,new) is not True or
                        self.finish_containment(account) is not True):
                    raise ValueError
                final=dict(pending,state='active',intent=None,epoch=value['epoch']+1,
                           changed_at=receipt.changed_at)
                self.store._write(path,final)
            except BaseException:
                self.store._write(path,dict(pending,state='contained'))
                raise Unconfirmed('changed credential requires contained reconciliation') from None
            return final['epoch'],final['changed_at']

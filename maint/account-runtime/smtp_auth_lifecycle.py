"""Disabled broker-owned SMTP SASL lifecycle and shared-epoch publication seam.

An after-policy ALLOW is not final authentication publication. This component
registers owned channels before credential dispatch and publishes an actual
parsed backend OK under the same account lock used by password mutation.
Cancellation must be called by the mutation owner while that lock is held; it
never reacquires it. A pending record supplies the generation cutoff, not RPC
fields. Shutdown here proves SASL-channel closure only, never smtpd TCP absence.

No listener, native ownership loader, mutation control transport, configuration
or factory is supplied. The inspector is a trusted startup dependency that must
independently prove exact owned CPID/TCP identity within the passed deadline.
Source fixtures do not qualify that authority or complete ingress coverage.
"""
import base64
from contextlib import contextmanager, nullcontext
import ctypes
from dataclasses import dataclass
import fcntl
import os
import re
import socket
import stat
import struct
import sys
import threading
import time

from account_epoch import EpochStore
from authoritative_password import AuthoritativePasswordAdapter, Refused, Unconfirmed
from operation_budget import OperationBudget

NATIVE_AUTH_BROKER_QUALIFIED = False


def _kernel_peer(stream):
    try:
        if hasattr(stream, 'getpeereid'):
            uid, gid = stream.getpeereid()
        elif sys.platform.startswith('openbsd'):
            fd = stream.fileno()
            if type(fd) is not int or not 0 <= fd <= 2**31 - 1:
                raise ValueError
            function = ctypes.CDLL(None, use_errno=True).getpeereid
            function.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
            function.restype = ctypes.c_int
            uid, gid = ctypes.c_uint(), ctypes.c_uint()
            if function(fd, ctypes.byref(uid), ctypes.byref(gid)) != 0:
                raise ValueError
            uid, gid = uid.value, gid.value
        elif sys.platform.startswith('linux'):
            _, uid, gid = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        else:
            raise ValueError
        if any(type(v) is not int or not 0 <= v < 2**32 - 1 for v in (uid, gid)):
            raise ValueError
        return uid, gid
    except Exception:
        raise Refused('SMTP authentication kernel peer unavailable') from None


def _socket_identity(stream):
    if type(stream) is not socket.socket or stream.family != socket.AF_UNIX or stream.type != socket.SOCK_STREAM:
        raise Refused('SMTP authentication socket unavailable')
    info = os.fstat(stream.fileno())
    if not stat.S_ISSOCK(info.st_mode):
        raise Refused('SMTP authentication socket unavailable')
    return info.st_dev, info.st_ino


@dataclass(frozen=True, repr=False)
class DovecotProxyOkProfile:
    """Closed supported passdb metadata, bound by trusted broker startup.

    The loopback topology and TLS requirement are fixed. Metadata never chooses
    the backend connection, process identity, account, epoch or operation budget.
    """
    backend_port: int

    def __post_init__(self):
        if type(self.backend_port) is not int or not 1024 <= self.backend_port <= 65535:
            raise Refused('SMTP authentication OK profile refused')


class OwnedSmtpPeerAuthority:
    """Fixed broker startup dependencies; no request can choose principals."""
    def __init__(self, postfix_peer, backend_peer, backend_port, inspector, *, ok_profile=None):
        if (any(type(p) is not tuple or len(p) != 2 or
                any(type(v) is not int or not 0 <= v < 2**32 - 1 for v in p)
                for p in (postfix_peer, backend_peer))
                or type(backend_port) is not int or not 1024 <= backend_port <= 65535
                or not callable(inspector)):
            raise Refused('SMTP authentication ownership unavailable')
        self._postfix = postfix_peer
        self._backend = backend_peer
        self._port = backend_port
        self._inspect = inspector
        if ok_profile is None:
            self._ok_fields = ()
        elif type(ok_profile) is DovecotProxyOkProfile and ok_profile.backend_port == backend_port:
            self._ok_fields = (b'proxy', b'host=127.0.0.1',
                               b'port=' + str(backend_port).encode('ascii'), b'ssl=yes')
        else:
            raise Refused('SMTP authentication OK profile refused')

    def check_ok(self, fields, request, account):
        if self.canonical_ok(fields,request)!=account:
            raise Refused('SMTP authentication backend success refused')

    def canonical_ok(self, fields, request, original=None):
        users=[value for value in fields[2:] if value.startswith(b'user=')]
        if len(users)!=1:
            raise Refused('SMTP authentication backend success refused')
        try:
            account=AuthoritativePasswordAdapter._account(users[0][5:].decode('ascii'))
        except Exception:
            raise Refused('SMTP authentication backend success refused')from None
        expected = (b'user=' + account.encode('ascii'),) + self._ok_fields
        originals=[value for value in fields[2:] if value.startswith(b'original_user=')]
        if originals:
            if (original is None or account==original or len(originals)!=1
                    or originals[0]!=b'original_user='+original.encode('ascii')):
                raise Refused('SMTP authentication original identity refused')
            expected+=(originals[0],)
        # Dovecot serializes fields in insertion order. Only their closed set
        # matters; cardinality plus equality also rejects every duplicate.
        if (len(fields) != 2 + len(expected) or fields[:2] != [b'OK', request]
                or len(set(fields[2:])) != len(expected)
                or set(fields[2:]) != set(expected)):
            raise Refused('SMTP authentication backend success refused')
        return account

    def check(self, client, upstream, pid, budget):
        if type(budget) is not OperationBudget or type(pid) is not int or not 1 < pid <= 2**31 - 1:
            raise Refused('SMTP authentication ownership unavailable')
        budget.remaining()
        if _kernel_peer(client) != self._postfix or _kernel_peer(upstream) != self._backend:
            raise Refused('SMTP authentication peer refused')
        deadline = time.monotonic() + budget.cap_seconds(0.5)
        from smtp_native_peer import NativeSmtpPeerInspector, NativeSmtpIdentity, NativeSmtpOwnership
        inspector = self._inspect.prepared(budget) if type(self._inspect) is NativeSmtpOwnership else self._inspect
        if type(inspector) is NativeSmtpPeerInspector:
            identity = inspector.inspect(pid, deadline, budget)
            if type(identity) is not NativeSmtpIdentity:
                raise Refused('SMTP authentication native process refused')
            projection = identity.projection()
        else:
            # Existing explicitly synthetic startup fixtures retain their tuple
            # seam; the native producer supplies no caller-selected callback.
            identity = self._inspect(pid, deadline)
            projection = identity
        budget.remaining()
        if (time.monotonic() >= deadline or type(projection) is not tuple or len(projection) != 4
                or projection[:3] != (pid, '127.0.0.1', self._port)
                or type(projection[3]) is not int or not 1024 <= projection[3] <= 65535):
            raise Refused('SMTP authentication process refused')
        return identity


@dataclass(eq=False, repr=False)
class _Channel:
    registry: object
    client: socket.socket
    upstream: socket.socket
    socket_ids: tuple
    pid: int
    identity: tuple
    account: str
    request: bytes
    epoch: int | None
    budget: OperationBudget
    capture_expires: float
    auth_account: str
    mechanism: bytes = b'PLAIN'
    password_forwarded: bool = False
    verified: bool = False
    published: bool = False
    closed: bool = False


@dataclass(eq=False, repr=False)
class _Verified:
    channel: _Channel
    line: bytes
    used: bool = False


@dataclass(eq=False, repr=False)
class _Cutoff:
    registry: object
    account: str
    epoch: int
    intent: str


class SmtpAuthLifecycle:
    MAX_CHANNELS = 256
    MAX_CUTOFFS = 64
    FRAME_LIMIT = 4096

    def __init__(self, store, accounts, authority):
        if (type(store) is not EpochStore or type(accounts) is not frozenset
                or not 1 <= len(accounts) <= 64 or type(authority) is not OwnedSmtpPeerAuthority):
            raise Refused('SMTP authentication lifecycle unavailable')
        for account in accounts:
            AuthoritativePasswordAdapter._account(account)
        self._store = store
        self._accounts = accounts
        self._authority = authority
        self._root = self._root_identity()
        self._channels = set()
        self._cutoffs = set()
        self._mutex = threading.RLock()

    def _root_identity(self):
        info = self._store.root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self._store.uid
                or info.st_mode & 0o077 or self._store.root.resolve() != self._store.root):
            raise Refused('SMTP authentication epoch root unavailable')
        return info.st_dev, info.st_ino

    def _record(self, account):
        if account not in self._accounts or self._root_identity() != self._root:
            raise Refused('SMTP authentication epoch authority refused')
        value = self._store._read(self._store._paths(account)[1])
        if self._root_identity() != self._root:
            raise Refused('SMTP authentication epoch root changed')
        return value

    @contextmanager
    def _locked(self, account):
        # Nonblocking: the mutation owner already holding this flock wins.
        lock, _ = self._store._paths(account)
        fd = self._store._private(lock, os.O_RDWR | os.O_CREAT)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refused('SMTP authentication epoch lock busy') from None
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    @contextmanager
    def _guard(self, budget, cap=0.5):
        if type(budget) is not OperationBudget or not self._mutex.acquire(timeout=budget.cap_seconds(cap)):
            raise Refused('SMTP authentication lifecycle busy')
        try:
            budget.remaining()
            yield
            budget.remaining()
        finally:
            self._mutex.release()

    @classmethod
    def _fields(cls, line):
        if (type(line) is not bytes or not 1 <= len(line) <= cls.FRAME_LIMIT
                or not line.endswith(b'\n') or line.count(b'\n') != 1
                or b'\0' in line or b'\r' in line):
            raise Refused('SMTP authentication frame refused')
        return line[:-1].split(b'\t')

    def _auth_fields(self, cpid, auth, mechanism):
        peer = self._fields(cpid)
        fields = self._fields(auth)
        if (len(peer) != 2 or peer[0] != b'CPID' or not re.fullmatch(rb'[1-9][0-9]{0,9}', peer[1])
                or not 1 < int(peer[1]) <= 2**31 - 1 or len(fields) < 4
                or fields[0] != b'AUTH' or not re.fullmatch(rb'[1-9][0-9]{0,9}', fields[1])
                or int(fields[1]) > 2**32 - 1 or fields[2] != mechanism
                or [p for p in fields[3:] if p.startswith(b'service=')] != [b'service=smtp']):
            raise Refused('SMTP authentication identity refused')
        return int(peer[1]),fields

    def _begin_fields(self, cpid, auth):
        pid,fields=self._auth_fields(cpid,auth,b'PLAIN')
        responses = [p[5:] for p in fields[3:] if p.startswith(b'resp=')]
        if len(responses) != 1:
            raise Refused('SMTP authentication identity refused')
        try:
            value = base64.b64decode(responses[0], validate=True).split(b'\0')
            if len(value) != 3 or value[0] not in (b'', value[1]) or not value[2]:
                raise ValueError
            account = value[1].decode('ascii')
            AuthoritativePasswordAdapter._account(account)
            return pid, fields[1], account
        except Exception:
            raise Refused('SMTP authentication identity refused') from None
        finally:
            # Credentials are neither attached to a receipt nor logged.
            del responses

    def begin(self, client, upstream, cpid, auth, budget):
        pid, request, account = self._begin_fields(cpid, auth)
        return self._register(client,upstream,pid,request,account,budget)

    def login_initial(self,cpid,auth):
        pid,fields=self._auth_fields(cpid,auth,b'LOGIN')
        responses=[value[5:] for value in fields[3:] if value.startswith(b'resp=')]
        if len(responses)>1 or (responses and not fields[-1].startswith(b'resp=')):
            raise Refused('SMTP LOGIN initial response refused')
        try:
            initial=base64.b64decode(responses[0],validate=True) if responses else b''
            if initial:
                AuthoritativePasswordAdapter._account(initial.decode('ascii'))
            return pid,fields[1],initial
        except Exception:
            raise Refused('SMTP LOGIN initial response refused')from None

    def begin_login(self,client,upstream,cpid,auth,username,budget):
        pid,request,initial=self.login_initial(cpid,auth)
        try:
            if initial:
                if username is not None:raise ValueError
                account=initial.decode('ascii')
            else:
                fields=self._fields(username)
                if len(fields)!=3 or fields[:2]!=[b'CONT',request]:raise ValueError
                account=base64.b64decode(fields[2],validate=True).decode('ascii')
            AuthoritativePasswordAdapter._account(account)
        except Exception:
            raise Refused('SMTP LOGIN username refused')from None
        channel=self._register(client,upstream,pid,request,account,budget)
        channel.mechanism=b'LOGIN'
        return channel

    def _register(self,client,upstream,pid,request,original,budget):
        # Source-owned installed profile is auth_username_format=%Lu. Keep the
        # submitted spelling solely to bind Dovecot's original_user metadata.
        account=AuthoritativePasswordAdapter._account(original).lower()
        socket_ids = (_socket_identity(client), _socket_identity(upstream))
        if socket_ids[0] == socket_ids[1]:
            raise Refused('SMTP authentication socket pair refused')
        identity = self._authority.check(client, upstream, pid, budget)
        managed=account in self._accounts
        with self._locked(account) if managed else nullcontext(), self._guard(budget):
            value = self._record(account) if managed else None
            if ((managed and value['state'] != 'active')
                    or len(self._channels) >= self.MAX_CHANNELS):
                raise Refused('SMTP authentication admission refused')
            if any(set(socket_ids).intersection(c.socket_ids) for c in self._channels):
                # Cross-account multiplexing cannot supply exact cancellation.
                raise Refused('SMTP authentication multiplexing refused')
            owned_client = client.dup()
            try:
                owned_upstream = upstream.dup()
            except Exception:
                owned_client.close()
                raise
            channel = _Channel(self, owned_client, owned_upstream, socket_ids, pid,
                               identity, account, request, value['epoch'] if managed else None, budget,
                               time.monotonic() + budget.cap_seconds(30),original)
            self._channels.add(channel)
            return channel

    def forward_login_password(self,channel,raw):
        try:
            fields=self._fields(raw)
            if (len(fields)!=3 or fields[:2]!=[b'CONT',channel.request]
                    or channel.mechanism!=b'LOGIN' or channel.password_forwarded):
                raise Refused('SMTP LOGIN password continuation refused')
            password=base64.b64decode(fields[2],validate=True)
            if not password or b'\0'in password:
                raise Refused('SMTP LOGIN password continuation refused')
            del password
            managed=channel.account in self._accounts
            with self._locked(channel.account) if managed else nullcontext(),self._guard(channel.budget):
                self._owned(channel)
                if managed:
                    value=self._record(channel.account)
                    if value['state']!='active' or value['epoch']!=channel.epoch:
                        raise Refused('SMTP LOGIN credential epoch changed')
                # Consume before IO; a partial/late send is never repeated.
                channel.password_forwarded=True
                channel.upstream.settimeout(channel.budget.cap_seconds(1))
                channel.upstream.sendall(raw)
                self._owned(channel)
        except Exception:
            self.close(channel)
            raise Refused('SMTP LOGIN password dispatch refused')from None

    def _owned(self, channel):
        if type(channel) is not _Channel or channel.registry is not self or channel not in self._channels or channel.closed:
            raise Refused('SMTP authentication channel refused')
        if (channel.account in self._accounts)!=(channel.epoch is not None):
            raise Refused('SMTP authentication scope changed')
        if (_socket_identity(channel.client), _socket_identity(channel.upstream)) != channel.socket_ids:
            raise Refused('SMTP authentication descriptor changed')
        channel.budget.remaining()
        if time.monotonic() >= channel.capture_expires:
            raise Refused('SMTP authentication capture expired')

    def verified(self, channel, line):
        try:
            with self._guard(channel.budget):
                self._owned(channel)
                fields = self._fields(line)
                if (channel.verified or channel.published
                        or (channel.mechanism==b'LOGIN' and not channel.password_forwarded)):
                    raise Refused('SMTP authentication backend success refused')
                canonical=self._authority.canonical_ok(fields,channel.request,channel.auth_account)
                if channel.epoch is None:
                    # Backend identity may resolve an ordinary alias, but can
                    # never promote that unfenced request into selected scope.
                    if canonical in self._accounts:
                        raise Refused('SMTP authentication selected alias refused')
                    channel.account=canonical
                elif canonical!=channel.account:
                    raise Refused('SMTP authentication backend success refused')
                channel.verified = True
                receipt = _Verified(channel, line)
                channel._receipt = receipt
                return receipt
        except Exception:
            self.close(channel)
            raise Refused('SMTP authentication backend success refused') from None

    def publish(self, channel, receipt):
        try:
            managed=channel.account in self._accounts
            with self._locked(channel.account) if managed else nullcontext(), self._guard(channel.budget):
                self._owned(channel)
                if (type(receipt) is not _Verified or receipt is not getattr(channel, '_receipt', None)
                        or receipt.channel is not channel or receipt.used or channel.published):
                    raise Refused('SMTP authentication success authority refused')
                receipt.used = True
                if managed:
                    value = self._record(channel.account)
                    if value['state'] != 'active' or value['epoch'] != channel.epoch:
                        raise Refused('SMTP authentication epoch changed')
                if self._authority.check(channel.client, channel.upstream, channel.pid,
                                         channel.budget) != channel.identity:
                    raise Refused('SMTP authentication process changed')
                # Registration precedes bytes. Selected publication holds its
                # account flock; unrelated backend authentication has no epoch.
                # Exact ownership and one-use proof are required in both paths.
                channel.client.settimeout(min(channel.budget.cap_seconds(0.5),
                                              channel.capture_expires - time.monotonic()))
                channel.client.sendall(receipt.line)
                self._owned(channel)
                channel.published = True
                return True
        except Exception:
            # A partial/late write is never retried. Registration is closed.
            self.close(channel)
            raise Refused('SMTP authentication publication refused') from None

    def pending_cutoff_locked(self, account, budget):
        # Only the trusted mutation owner may call this under its existing
        # account flock. No request epoch, state, Boolean or socket is accepted.
        with self._guard(budget):
            value = self._record(account)
            if value['state'] not in ('pending', 'contained') or len(self._cutoffs) >= self.MAX_CUTOFFS:
                raise Refused('SMTP authentication cancellation authority refused')
            cutoff = _Cutoff(self, account, value['epoch'], value['intent'])
            self._cutoffs.add(cutoff)
            return cutoff

    def cancel_cutoff_locked(self, cutoff, budget):
        # Lock order remains account -> registry. The caller owns the account
        # lock; reacquiring it here would deadlock the actual coordinator.
        with self._guard(budget, 3):
            if type(cutoff) is not _Cutoff or cutoff.registry is not self or cutoff not in self._cutoffs:
                raise Refused('SMTP authentication cancellation authority refused')
            self._cutoffs.remove(cutoff)
            value = self._record(cutoff.account)
            if (value['epoch'] < cutoff.epoch or (value['epoch'] == cutoff.epoch and
                    (value['state'] not in ('pending', 'contained') or value['intent'] != cutoff.intent))):
                raise Refused('SMTP authentication cancellation state changed')
            count = 0
            for channel in tuple(self._channels):
                if (channel.account == cutoff.account and channel.epoch is not None
                        and channel.epoch <= cutoff.epoch):
                    budget.remaining()
                    if self.close(channel) is not True:
                        raise Unconfirmed('SMTP authentication channel closure unconfirmed')
                    count += 1
            return count

    def cancel_pending_locked(self, account, budget):
        return self.cancel_cutoff_locked(self.pending_cutoff_locked(account, budget), budget)

    def close(self, channel):
        with self._mutex:
            if type(channel) is not _Channel or channel.registry is not self:
                raise Refused('SMTP authentication channel refused')
            if channel.closed:
                return channel._closure_confirmed
            channel.closed = True
            self._channels.discard(channel)
            confirmed = True
            for peer in (channel.client, channel.upstream):
                try:
                    peer.shutdown(socket.SHUT_RDWR)
                except OSError:
                    confirmed = False
                peer.close()
            channel._closure_confirmed = confirmed
            return confirmed

"""Fixed private guarded-worker supervisor prerequisite; native activation off.

The authoritative endpoint belongs on mail.blackbagsecurity.com. The obsd1
issuer needs a separate pinned SSH forced-command relay to this exact socket;
existing auth/mailbox relays do not supply that purpose. This module qualifies
neither native dependencies nor current Postfix SMTP containment. The native
factory refuses before reading operator files or accepting connections.
"""
from dataclasses import dataclass
import json
import ctypes
import os
from pathlib import Path
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import threading

from account_epoch import EpochStore
from account_guarded_mutation import LIMIT, verify_guarded
from account_mutation_budget import operation_budget, wall_millis
from account_mutation_codec import key_valid
from account_mutation_worker import Unavailable
from authoritative_password import AuthoritativePasswordAdapter

NATIVE_CONFINEMENT_QUALIFIED = False
AUTHORITY = 'mail.blackbagsecurity.com'
PURPOSE = 'osmap-account-mutation'
ROOT = Path('/etc/osmap/account-runtime')
SOCKET = '/var/run/osmap-account-mutation/mutation.sock'
ENGINE = '/usr/local/bin/python3'
WORKER = '/usr/local/libexec/osmap/account-runtime/account_mutation_entry.py'
COMPLETE = b'osmap-guarded-worker-complete-v1\n'
RESERVE = .1


def _directory(path, owner):
    if not path.is_absolute() or path.resolve() != path:
        raise Unavailable('mutation bootstrap unavailable')
    # No writable ancestor may substitute an independently helper-owned root.
    for parent in (path, *path.parents):
        m = parent.lstat()
        if (not stat.S_ISDIR(m.st_mode) or m.st_uid not in (0, owner)
                or m.st_mode & (0o077 if parent == path else 0o022)):
            raise Unavailable('mutation bootstrap unavailable')
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    m = os.fstat(fd)
    if m.st_uid != owner or m.st_mode & 0o077:
        os.close(fd)
        raise Unavailable('mutation bootstrap unavailable')
    return fd


def _private(root_fd, name, owner, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root_fd)
    try:
        m = os.fstat(fd)
        if (not stat.S_ISREG(m.st_mode) or m.st_uid != owner or m.st_nlink != 1
                or m.st_mode & 0o077 or not 0 < m.st_size <= limit):
            raise Unavailable('mutation bootstrap unavailable')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            value = handle.read(limit + 1)
        if len(value) > limit:
            raise Unavailable('mutation bootstrap unavailable')
        return value
    finally:
        os.close(fd)


@dataclass(frozen=True, repr=False)
class _Bootstrap:
    mutation_key: bytes
    session_key: bytes
    accounts: frozenset
    trusted_relay_uid: int

    @classmethod
    def _read(cls, root, owner):
        fd = _directory(root, owner)
        try:
            raw = _private(fd, 'config.json', owner, 16384)
            value = json.loads(raw, object_pairs_hook=EpochStore._unique)
            if (type(value) is not dict or set(value) !=
                    {'version', 'authority', 'purpose', 'accounts', 'trusted_relay_uid'}
                    or type(value['version']) is not int or value['version'] != 1
                    or value['authority'] != AUTHORITY or value['purpose'] != PURPOSE
                    or type(value['trusted_relay_uid']) is not int
                    or not 0 < value['trusted_relay_uid'] <= 2**32 - 1
                    or type(value['accounts']) is not list
                    or not 1 <= len(value['accounts']) <= 128):
                raise ValueError
            for account in value['accounts']:
                AuthoritativePasswordAdapter._account(account)
            accounts = frozenset(value['accounts'])
            if len(accounts) != len(value['accounts']):
                raise ValueError
            mutation = _private(fd, 'mutation.key', owner, 1024)
            session = _private(fd, 'session-proof.key', owner, 1024)
            key_valid(mutation); key_valid(session)
            if mutation == session:
                raise ValueError
            return cls(mutation, session, accounts, value['trusted_relay_uid'])
        except Exception:
            raise Unavailable('mutation bootstrap unavailable') from None
        finally:
            os.close(fd)

    @classmethod
    def native(cls):
        if not NATIVE_CONFINEMENT_QUALIFIED:
            raise Unavailable('native mutation bootstrap unavailable')
        if os.geteuid() != 0 or socket.gethostname() != AUTHORITY:
            raise Unavailable('authoritative mutation bootstrap unavailable')
        return cls._read(ROOT, 0)


def _peer(stream):
    try:
        if hasattr(stream,'getpeereid'):
            uid,gid=stream.getpeereid()
        elif sys.platform.startswith('openbsd'):
            # Match the already reviewed ordinary relay's native ABI. OpenBSD
            # Python need not expose a socket.getpeereid method; the kernel
            # credential boundary remains mandatory, never a mode/UID waiver.
            fd=stream.fileno()
            if type(fd) is not int or not 0<=fd<=2**31-1:
                raise Unavailable('mutation native peer descriptor unavailable')
            libc=ctypes.CDLL(None,use_errno=True)
            function=getattr(libc,'getpeereid',None)
            if function is None:
                raise Unavailable('mutation native peer symbol unavailable')
            function.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_uint),ctypes.POINTER(ctypes.c_uint)]
            function.restype=ctypes.c_int
            native_uid=ctypes.c_uint();native_gid=ctypes.c_uint()
            ctypes.set_errno(0)
            if function(fd,ctypes.byref(native_uid),ctypes.byref(native_gid))!=0:
                number=ctypes.get_errno()
                raise Unavailable(f'mutation native peer failed errno {number}')
            uid,gid=native_uid.value,native_gid.value
        elif sys.platform.startswith('linux'):
            _pid,uid,gid=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        else:
            raise Unavailable('mutation peer platform unavailable')
        if any(type(v) is not int or not 0<=v<2**32-1 for v in (uid,gid)):
            raise Unavailable('mutation peer identity unavailable')
        return uid
    except Unavailable:raise
    except Exception:raise Unavailable('mutation peer unavailable') from None



class _Supervisor:
    """Source component; dependency construction is private, not a wire choice.

    One authenticated frame precedes fixed worker spawn. The child inherits only
    the accepted duplex socket on stdout and the frame on stdin. No credentials
    appear in argv/env/stderr. The supervised leader remains unreaped until the
    owned group is signalled; stale numeric PIDs are never signalled after reap.
    An unconfirmed cleanup latches this supervisor, with no retry/reset API.
    """
    def __init__(self, bootstrap):
        if type(bootstrap) is not _Bootstrap:
            raise Unavailable('mutation bootstrap unavailable')
        self._bootstrap = bootstrap
        self._uncertain = False
        self._busy = threading.Lock()
        self._retained = []

    @staticmethod
    def _command():
        return (ENGINE, '-I', WORKER)

    def connection(self, stream):
        if not self._busy.acquire(blocking=False):
            raise Unavailable('mutation supervisor busy')
        child = None
        remote = worker_end = None
        budget = None
        try:
            if self._uncertain or _peer(stream) != self._bootstrap.trusted_relay_uid:
                raise ValueError
            initial = time.monotonic() + 60
            def exact(n):
                result = bytearray()
                while len(result) < n:
                    remaining = initial - time.monotonic()
                    if remaining <= RESERVE:
                        raise ValueError
                    stream.settimeout(remaining - RESERVE)
                    part = stream.recv(n - len(result))
                    if not part:
                        raise ValueError
                    result.extend(part)
                return bytes(result)
            size = int.from_bytes(exact(4), 'big')
            if not 0 < size <= LIMIT:
                raise ValueError
            raw = exact(size)
            received_mono, received_millis = time.monotonic(), wall_millis()
            checked = verify_guarded(raw, self._bootstrap.mutation_key,
                                     self._bootstrap.session_key, received_millis)
            if checked.budget.request.action.account not in self._bootstrap.accounts:
                raise ValueError
            budget = operation_budget(checked.budget, received_mono=received_mono,
                                      received_millis=received_millis)
            if budget.remaining() <= RESERVE:
                raise ValueError
            if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
                # An auto-reaping/custom handler would invalidate owned PID
                # lifetime. No group signal may rely on an already reaped leader.
                raise Unavailable('guarded worker reap ownership unavailable')
            remote, worker_end = socket.socketpair()
            child = subprocess.Popen(self._command(), stdin=subprocess.PIPE,
                stdout=worker_end, stderr=subprocess.PIPE, close_fds=True,
                start_new_session=True, env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            worker_end.close(); worker_end = None
            reply = self._exchange(child, raw, budget, stream, remote)
            try:
                exit_code = self._cleanup(child, budget)
            except Exception:
                self._uncertain = True
                self._retained.append(child)
                for handle in (child.stdin,child.stderr):
                    if handle is not None and not handle.closed:handle.close()
                child = None
                raise
            child.stderr.close()
            child = None
            if exit_code != 0:
                raise Unavailable('guarded worker exit unavailable')
            # Terminal publication follows confirmed owned-group cleanup, never
            # a pipe receipt or child-authenticated claim alone.
            stream.settimeout(budget.remaining())
            stream.sendall(len(reply).to_bytes(4, 'big') + reply)
            budget.remaining()
        except Exception:
            raise Unavailable('guarded mutation supervisor unavailable') from None
        finally:
            cleanup_failed = False
            if child is not None:
                try:
                    self._cleanup(child, budget)
                except Exception:
                    self._uncertain = True
                    self._retained.append(child)
                    cleanup_failed = True
                for handle in (child.stdin, child.stderr):
                    if handle is not None and not handle.closed:
                        handle.close()
            for stream_end in (remote, worker_end):
                if stream_end is not None:
                    stream_end.close()
            self._busy.release()
            if cleanup_failed:
                raise Unavailable('guarded mutation cleanup unconfirmed') from None

    @staticmethod
    def _exact(stream, n, budget):
        result = bytearray()
        while len(result) < n:
            remaining = budget.remaining() - RESERVE
            if remaining <= 0:
                raise Unavailable('guarded worker deadline unavailable')
            stream.settimeout(remaining)
            part = stream.recv(n - len(result))
            if not part:
                raise Unavailable('guarded worker frame unavailable')
            result.extend(part)
        budget.remaining()
        return bytes(result)

    @classmethod
    def _frame(cls, stream, limit, budget):
        size = int.from_bytes(cls._exact(stream, 4, budget), 'big')
        if not 0 < size <= limit:
            raise Unavailable('guarded worker frame unavailable')
        return cls._exact(stream, size, budget)

    @staticmethod
    def _send(stream, raw, budget):
        remaining = budget.remaining() - RESERVE
        if remaining <= 0:
            raise Unavailable('guarded worker deadline unavailable')
        stream.settimeout(remaining)
        stream.sendall(len(raw).to_bytes(4,'big') + raw)
        budget.remaining()

    @classmethod
    def _exchange(cls, child, raw, budget, issuer, remote):
        os.set_blocking(child.stdin.fileno(), False)
        pending = len(raw).to_bytes(4, 'big') + raw
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdin, selectors.EVENT_WRITE)
            while pending:
                remaining = budget.remaining() - RESERVE
                if remaining <= 0:
                    raise Unavailable('guarded worker deadline unavailable')
                if selector.select(min(remaining,.01)):
                    written = os.write(child.stdin.fileno(),pending)
                    pending = pending[written:]
        child.stdin.close()
        first = cls._frame(remote,4096,budget)
        value = json.loads(first,object_pairs_hook=EpochStore._unique)
        if type(value) is dict and value.get('schema') == 'osmap-account-mutation-continuity-v1':
            # End-to-end MAC/nonce/request verification remains in the real Rust
            # issuer and worker. The supervisor transports only one bounded ACK.
            cls._send(issuer,first,budget)
            ack = cls._frame(issuer,2048,budget)
            issuer.settimeout(budget.remaining()-RESERVE)
            if issuer.recv(1) != b'':
                raise Unavailable('guarded issuer framing unavailable')
            cls._send(remote,ack,budget)
            remote.shutdown(socket.SHUT_WR)
            reply = cls._frame(remote,4096,budget)
        else:
            reply = first
        # No terminal response leaves this process until cleanup is confirmed.
        remaining = budget.remaining()-RESERVE
        if remaining <= 0:
            raise Unavailable('guarded worker deadline unavailable')
        remote.settimeout(remaining)
        if remote.recv(1) != b'':
            raise Unavailable('guarded worker trailing response unavailable')
        os.set_blocking(child.stderr.fileno(),False)
        marker = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(child.stderr,selectors.EVENT_READ)
            while selector.get_map():
                remaining = budget.remaining()-RESERVE
                if remaining <= 0:
                    raise Unavailable('guarded worker deadline unavailable')
                if selector.select(min(remaining,.01)):
                    part = os.read(child.stderr.fileno(),64)
                    if not part:
                        selector.unregister(child.stderr)
                    else:
                        marker.extend(part)
                        if not COMPLETE.startswith(marker):
                            raise Unavailable('guarded worker completion unavailable')
        if marker != COMPLETE:
            raise Unavailable('guarded worker completion unavailable')
        budget.remaining()
        return reply

    @staticmethod
    def _cleanup(child, budget):
        # There is no wait/poll before this signal: leader PID cannot be reused.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        remaining = budget.remaining()
        exit_code = child.wait(timeout=remaining)
        # Never signal the numeric PID after reap, even if absence is unknown.
        try:
            os.killpg(child.pid, 0)
        except ProcessLookupError:
            budget.remaining()
            return exit_code
        raise Unavailable('guarded worker group absence unconfirmed')


class _Listener:
    """Private single-connection listener; native factory remains unavailable.

    Native startup requires a separately qualified dedicated group grant. The
    root-owned purpose namespace is searchable, never writable by the connector;
    bootstrap keys/config stay owner-private. Old isolated private fixtures remain
    mode600. One synchronous connection avoids authority races.
    """
    def __init__(self, bootstrap, grant=None):
        from account_mutation_grant import _ConnectorGrant
        if grant is not None and (type(grant) is not _ConnectorGrant
                or grant.connector_uid!=bootstrap.trusted_relay_uid
                or grant.owner!=os.geteuid()):
            raise Unavailable('mutation listener grant unavailable')
        self._supervisor = _Supervisor(bootstrap)
        self._grant=grant

    @classmethod
    def native(cls):
        from account_mutation_native import NativeDependencies
        dependencies=NativeDependencies.native()
        from account_mutation_grant import _ConnectorGrant
        grant=_ConnectorGrant.native(dependencies.bootstrap)
        return cls(dependencies.bootstrap,grant)

    def _one(self, path):
        # Native entry supplies SOCKET only; isolated tests supply an owned path.
        path = Path(path)
        if self._grant is not None:
            if path!=self._grant.path:
                raise Unavailable('mutation listener purpose unavailable')
            parent=self._grant.open_namespace()
        else:
            # Existing private fixtures remain owner-only; native always requires
            # the separately qualified dedicated connector grant.
            parent=_directory(path.parent,os.geteuid())
        listener = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        inode = None
        try:
            if path.exists() or path.is_symlink() or len(os.fsencode(path)) >= 100:
                raise Unavailable('mutation listener unavailable')
            listener.bind(str(path))
            m = path.lstat(); inode = (m.st_dev,m.st_ino)
            if self._grant is None:os.chmod(path,0o600)
            else:self._grant.publish(parent,inode)
            listener.listen(1);listener.settimeout(1)
            stream,_ = listener.accept()
            with stream:
                if self._grant is not None:self._grant.verify(parent,inode)
                self._supervisor.connection(stream)
        except Exception:
            raise Unavailable('mutation listener unavailable') from None
        finally:
            listener.close();os.close(parent)
            if inode is not None:
                try:
                    m = path.lstat()
                    if stat.S_ISSOCK(m.st_mode) and (m.st_dev,m.st_ino) == inode:
                        path.unlink()
                except FileNotFoundError:
                    pass


    def _serve(self,path,_stop=None):
        """Serial service: no idle exit, no retry of a failed operation.

        A continuation means a new accepted request, never a reconnect/resend of
        the previous frame. Uncertain owned-worker cleanup terminates admission.
        The optional private stop predicate only removes admission; it supplies
        no action authority and is absent from all request/config inputs.
        """
        path=Path(path)
        if self._grant is None or path!=self._grant.path:
            raise Unavailable('mutation persistent grant unavailable')
        parent=self._grant.open_namespace()
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);inode=None
        try:
            if path.exists() or path.is_symlink() or len(os.fsencode(path))>=100:
                raise Unavailable('mutation listener unavailable')
            listener.bind(str(path));m=path.lstat();inode=(m.st_dev,m.st_ino)
            self._grant.publish(parent,inode)
            listener.listen(1);listener.settimeout(.1)
            while not self._supervisor._uncertain:
                if _stop is not None and _stop():return
                self._grant.verify(parent,inode)
                try:stream,_=listener.accept()
                except socket.timeout:continue
                with stream:
                    self._grant.verify(parent,inode)
                    # Stop may arrive while accept blocks. Recheck at this
                    # admission boundary before reading or dispatching a frame;
                    # already-dispatched work keeps its original deadline.
                    if _stop is not None and _stop():return
                    try:self._supervisor.connection(stream)
                    except Unavailable:
                        if self._supervisor._uncertain:raise
                        # A refused connection supplies no automatic resend.
                        # Only a new separately authenticated peer may proceed.
            raise Unavailable('mutation service cleanup unconfirmed')
        except Exception:
            raise Unavailable('mutation persistent listener unavailable') from None
        finally:
            listener.close();os.close(parent)
            if inode is not None:
                try:
                    m=path.lstat()
                    if stat.S_ISSOCK(m.st_mode) and (m.st_dev,m.st_ino)==inode:path.unlink()
                except FileNotFoundError:pass


def serve_native(_stop=None):
    listener = _Listener.native()
    # Native qualification still false. Exact native dependency construction,
    # relay grant and privilege/confinement are required before this is reachable.
    listener._serve(SOCKET,_stop)

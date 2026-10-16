"""Disabled fixed admission Unix/SSH transport; no request-MAC key custody.

The fixed Toronto helper source shares mutation's authoritative epoch store.
The relay preserves opaque bytes; only the helper and Rust client authenticate
requests/replies. Unverified issued/expires can only shorten the initial30s cap.
No ordinary auth/mailbox/mutation SSH identity is reused. Local SSH cleanup is
not remote worker termination proof; native confinement/route stay unqualified.
"""
import json
import ctypes
import math
import os
from pathlib import Path
import pwd
import resource
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time

NATIVE_RELAY_QUALIFIED=False
REMOTE='216.128.179.75'
PEER_UID=1001
PURPOSE='osmap-account-admission'
LISTEN=Path('/var/lib/osmap-bridge/run/admission.sock')
IDENTITY=Path('/var/lib/osmap-bridge/keys/admission')
KNOWN_HOSTS=Path('/var/lib/osmap-bridge/known_hosts')
SSH='/usr/bin/ssh'
LIMIT=4096
RESPONSE_LIMIT=4096
ORIGINAL_SECONDS=30
RESERVE=.1

class Unavailable(Exception):
    """No no-write assurance, no reconnect/retry/reset or raw diagnostics."""

def _unique(pairs):
    value={}
    for k,v in pairs:
        if k in value:raise ValueError
        value[k]=v
    return value

def _json(raw):
    return json.loads(raw.decode('utf-8'),object_pairs_hook=_unique,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError()))

def _uint(value):return type(value) is int and 0<=value<=2**64-1

def _millis():
    value=time.time()
    if not math.isfinite(value) or value<=0:raise Unavailable('admission clock unavailable')
    return math.ceil(value*1000)

class _Deadline:
    def __init__(self,raw,received_mono,received_millis,initial_deadline,stop):
        # These public fields supply resource limits only. Their MAC is not
        # verified here; all original request bytes go unchanged to the helper.
        try:
            value=_json(raw)
            if(type(value)is not dict or set(value)!={'schema','account','operation','issued','expires','nonce','signature'}
                or value['schema']!='osmap-account-admission-v1'
                or not all(_uint(value[k])for k in('issued','expires'))
                or value['expires']-value['issued']!=35
                or not value['issued']*1000<=received_millis<value['expires']*1000):raise ValueError
            self.wall_deadline=value['expires']*1000
            self.mono_deadline=min(initial_deadline,
                received_mono+(self.wall_deadline-received_millis)/1000)
            self.last_wall=received_millis;self.last_mono=received_mono;self.stop=stop
            self.remaining()
        except Exception:raise Unavailable('admission deadline unavailable')from None
    def resource_remaining(self):
        # Cleanup uses the same original deadline even after cancellation.
        mono=time.monotonic();wall=_millis()
        if mono<self.last_mono or wall<self.last_wall:raise Unavailable('admission clock changed')
        self.last_wall=wall;self.last_mono=mono
        remaining=min(self.mono_deadline-mono,(self.wall_deadline-wall)/1000)
        if remaining<=0:raise Unavailable('admission deadline expired')
        return remaining
    def remaining(self):
        if self.stop.is_set():raise Unavailable('admission cancelled')
        return self.resource_remaining()
    def io(self):
        remaining=self.remaining()-RESERVE
        if remaining<=0:raise Unavailable('admission IO deadline expired')
        return remaining

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
                raise Unavailable('admission native peer descriptor unavailable')
            libc=ctypes.CDLL(None,use_errno=True)
            function=getattr(libc,'getpeereid',None)
            if function is None:
                raise Unavailable('admission native peer symbol unavailable')
            function.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_uint),ctypes.POINTER(ctypes.c_uint)]
            function.restype=ctypes.c_int
            native_uid=ctypes.c_uint();native_gid=ctypes.c_uint()
            ctypes.set_errno(0)
            if function(fd,ctypes.byref(native_uid),ctypes.byref(native_gid))!=0:
                number=ctypes.get_errno()
                raise Unavailable(f'admission native peer failed errno {number}')
            uid,gid=native_uid.value,native_gid.value
        elif sys.platform.startswith('linux'):
            _pid,uid,gid=struct.unpack('3i',stream.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        else:
            raise Unavailable('admission peer platform unavailable')
        if any(type(v) is not int or not 0<=v<2**32-1 for v in (uid,gid)):
            raise Unavailable('admission peer identity unavailable')
        return uid
    except Unavailable:raise
    except Exception:raise Unavailable('admission peer unavailable') from None


def ssh_argv():
    return (SSH,'-F','/dev/null','-T','-a','-x','-i',str(IDENTITY),
        '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
        '-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no',
        '-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no',
        '-o',f'UserKnownHostsFile={KNOWN_HOSTS}',
        # A daemonized multiplex master could outlive the owned workflow group;
        # do not reuse auth/mailbox authority or create a admission master.
        '-o','ControlMaster=no','-o','ControlPersist=no','-o','ControlPath=none',
        '-o','ClearAllForwardings=yes','-o','ForwardAgent=no',
        '-o','ConnectTimeout=5','-o','ConnectionAttempts=1',
        '-o','ServerAliveInterval=5','-o','ServerAliveCountMax=1',
        f'_osmap@{REMOTE}',PURPOSE)

def _material():
    owner=os.geteuid()
    if owner==0 or pwd.getpwuid(owner).pw_name!='_osmapbridge':
        raise Unavailable('admission bridge principal unavailable')
    for path,private in ((IDENTITY,True),(KNOWN_HOSTS,False)):
        for parent in path.parents:
            m=parent.lstat()
            if (not stat.S_ISDIR(m.st_mode) or m.st_uid not in (0,owner)
                    or m.st_mode&0o022 or parent.resolve()!=parent):
                raise Unavailable('admission bridge ancestry unavailable')
        m=path.lstat()
        if (not stat.S_ISREG(m.st_mode) or m.st_nlink!=1 or m.st_size<=0
                or m.st_uid!=(owner if private else 0)
                or m.st_mode&(0o077 if private else 0o022)):
            raise Unavailable('admission SSH material unavailable')
    m=LISTEN.parent.lstat()
    if (not stat.S_ISDIR(m.st_mode) or m.st_uid!=owner or m.st_mode&0o027
            or LISTEN.parent.resolve()!=LISTEN.parent
            or LISTEN.exists() or LISTEN.is_symlink()):
        raise Unavailable('admission listener unavailable')

class _Relay:
    def __init__(self,trusted_uid):
        if type(trusted_uid) is not int or not 0<trusted_uid<=2**32-1:raise Unavailable('admission peer unavailable')
        self._trusted_uid=trusted_uid;self._contained=False
        self._busy=threading.Lock();self._retained=[];self._stop=threading.Event()
    @classmethod
    def native(cls):
        if not NATIVE_RELAY_QUALIFIED:raise Unavailable('native admission relay unavailable')
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        _material()
        return cls(PEER_UID)
    @staticmethod
    def _command():return ssh_argv()
    @staticmethod
    def _socket_exact(stream,size,seconds):
        data=bytearray()
        while len(data)<size:
            stream.settimeout(seconds());part=stream.recv(size-len(data))
            if not part:raise Unavailable('admission framing unavailable')
            data.extend(part)
        return bytes(data)
    @classmethod
    def _socket_frame(cls,stream,limit,seconds):
        n=int.from_bytes(cls._socket_exact(stream,4,seconds),'big')
        if not 0<n<=limit:raise Unavailable('admission framing unavailable')
        return cls._socket_exact(stream,n,seconds)
    @staticmethod
    def _pipe_read(pipe,size,deadline):
        result=bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(pipe,selectors.EVENT_READ)
            while len(result)<size:
                if selector.select(min(deadline.io(),.01)):
                    try:part=os.read(pipe.fileno(),size-len(result))
                    except BlockingIOError:continue
                    if not part:raise Unavailable('admission remote framing unavailable')
                    result.extend(part)
        deadline.remaining();return bytes(result)
    @classmethod
    def _pipe_frame(cls,pipe,limit,deadline):
        n=int.from_bytes(cls._pipe_read(pipe,4,deadline),'big')
        if not 0<n<=limit:raise Unavailable('admission remote framing unavailable')
        return cls._pipe_read(pipe,n,deadline)
    @staticmethod
    def _pipe_write(pipe,raw,deadline):
        data=len(raw).to_bytes(4,'big')+raw
        with selectors.DefaultSelector() as selector:
            selector.register(pipe,selectors.EVENT_WRITE)
            while data:
                if selector.select(min(deadline.io(),.01)):
                    try:n=os.write(pipe.fileno(),data)
                    except BlockingIOError:continue
                    if not n:raise Unavailable('admission SSH input unavailable')
                    data=data[n:]
        deadline.remaining()
    @staticmethod
    def _send(stream,raw,deadline):
        stream.settimeout(deadline.io());stream.sendall(len(raw).to_bytes(4,'big')+raw)
        deadline.remaining()
    @staticmethod
    def _success(child,deadline):
        # EOF does not mean the SSH process has exited. Permit its clean exit
        # inside the SAME original I/O budget, reserving failure cleanup time.
        while True:
            seconds=min(.01,deadline.io())
            try:code=child.wait(timeout=seconds);break
            except subprocess.TimeoutExpired:continue
        # wait may have reaped the direct child. Only read-only group probing
        # is safe now; no later failure grants a signal to this numeric group.
        deadline.remaining()
        try:os.killpg(child.pid,0)
        except ProcessLookupError:
            deadline.remaining();return code
        raise Unavailable('admission SSH descendant disposition unconfirmed')
    @staticmethod
    def _cleanup(child,deadline):
        # A success wait may already have reaped before a later check failed.
        # Never signal that numerical group after reap, even for descendants.
        if child.returncode is not None:
            deadline.resource_remaining()
            try:os.killpg(child.pid,0)
            except ProcessLookupError:
                deadline.resource_remaining();return child.returncode
            raise Unavailable('admission SSH descendant disposition unconfirmed')
        # Failure/cancellation retains the exact unreaped leader: stop-before-
        # reap remains valid and consumes only the original cleanup reserve.
        try:os.killpg(child.pid,signal.SIGKILL)
        except ProcessLookupError:pass
        code=child.wait(timeout=deadline.resource_remaining())
        try:os.killpg(child.pid,0)
        except ProcessLookupError:
            deadline.resource_remaining();return code
        raise Unavailable('admission SSH cleanup unconfirmed')
    def connection(self,stream):
        if not self._busy.acquire(blocking=False):raise Unavailable('admission relay busy')
        child=None;deadline=None
        try:
            # One captured resource bound precedes peer/framing/spawn. It can
            # never be restarted by a slow client or public signed-window data.
            initial=time.monotonic()+ORIGINAL_SECONDS
            if self._contained or self._stop.is_set()or _peer(stream)!=self._trusted_uid:raise ValueError
            def initial_remaining():
                left=initial-time.monotonic()-RESERVE
                if self._stop.is_set()or left<=0:raise Unavailable('admission initial framing expired')
                return left
            raw=self._socket_frame(stream,LIMIT,initial_remaining)
            received_mono,received_millis=time.monotonic(),_millis()
            deadline=_Deadline(raw,received_mono,received_millis,initial,self._stop)
            deadline.io()
            if signal.getsignal(signal.SIGCHLD)!=signal.SIG_DFL:raise ValueError
            child=subprocess.Popen(self._command(),stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,start_new_session=True,close_fds=True,
                env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            os.set_blocking(child.stdin.fileno(),False);os.set_blocking(child.stdout.fileno(),False)
            self._pipe_write(child.stdin,raw,deadline)
            # Rust sends one frame then reads; local EOF is not its protocol.
            # SSH stdin EOF half-closes the fixed connector after that frame.
            child.stdin.close()
            reply=self._pipe_frame(child.stdout,RESPONSE_LIMIT,deadline)
            with selectors.DefaultSelector()as selector:
                selector.register(child.stdout,selectors.EVENT_READ)
                while True:
                    if selector.select(min(deadline.io(),.01)):
                        try:part=os.read(child.stdout.fileno(),1)
                        except BlockingIOError:continue
                        if part:raise Unavailable('admission remote trailing data')
                        break
            code=self._success(child,deadline)
            child.stdout.close();child=None
            if code!=0:raise Unavailable('admission SSH exit unconfirmed')
            self._send(stream,reply,deadline)
        except Exception:raise Unavailable('admission relay unavailable')from None
        finally:
            failed=False
            if child is not None:
                try:self._cleanup(child,deadline)
                except Exception:self._contained=True;self._retained.append(child);failed=True
                for pipe in(child.stdin,child.stdout):
                    if not pipe.closed:pipe.close()
            self._busy.release()
            if failed:raise Unavailable('admission SSH cleanup unconfirmed')from None


def serve_native():
    relay=_Relay.native() # false before principal/material/listener access
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);inode=None;previous={}
    try:
        for number in(signal.SIGTERM,signal.SIGINT):
            previous[number]=signal.signal(number,lambda *_args:relay._stop.set())
        listener.bind(str(LISTEN));m=LISTEN.lstat();inode=(m.st_dev,m.st_ino)
        os.chmod(LISTEN,0o660);listener.listen(1);listener.settimeout(.1)
        while not relay._contained and not relay._stop.is_set():
            try:stream,_=listener.accept()
            except socket.timeout:continue
            with stream:
                try:relay.connection(stream)
                except Unavailable:pass
    finally:
        listener.close()
        for number,handler in previous.items():signal.signal(number,handler)
        if inode is not None:
            try:
                m=LISTEN.lstat()
                if stat.S_ISSOCK(m.st_mode)and(m.st_dev,m.st_ino)==inode:LISTEN.unlink()
            except FileNotFoundError:pass

if __name__=='__main__':
    try:serve_native()
    except Exception:raise SystemExit(1)from None
